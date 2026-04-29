//! In-process byte-channel primitives for wiring a `Transport`
//! directly to a same-process server loop - no sockets, no
//! subprocess, no network.
//!
//! The typical use case is running an in-process implementation of
//! `git-receive-pack` or `git-upload-pack` against a local
//! `Repository` without shelling out. Pair [`pipe`] twice to build a
//! duplex channel, spawn a worker thread that runs the server loop
//! against one pair, and hand the other pair to
//! [`git::blocking_io::Connection::new`](super::super::git::blocking_io::Connection::new)
//! as the client transport.
//!
//! The channels are backed by a blocking `mpsc::channel<Vec<u8>>`
//! plus a leftover buffer on the reader, so a reader blocks until
//! more data is produced by the writer and returns `Ok(0)` once the
//! writer is dropped. That's the same semantics a stateless-RPC
//! subprocess transport has when the child closes its stdout.

use std::io::{self, Read, Write};
use std::sync::mpsc::{self, Receiver, Sender};

/// The writing half of an in-process byte channel.
///
/// Every `write` enqueues a `Vec<u8>` chunk on the channel. `flush`
/// is a no-op because the channel is unbounded and drops carry
/// through to the reader as EOF.
pub struct ChannelWriter(Sender<Vec<u8>>);

impl Write for ChannelWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        self.0
            .send(buf.to_vec())
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "in-process channel closed"))?;
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// The reading half of an in-process byte channel.
///
/// Reads block until the other end enqueues a chunk. Partial reads
/// are handled via a local leftover buffer so callers can pull one
/// byte at a time without losing data.
pub struct ChannelReader {
    rx: Receiver<Vec<u8>>,
    buf: Vec<u8>,
    pos: usize,
}

impl Read for ChannelReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        if self.pos == self.buf.len() {
            match self.rx.recv() {
                Ok(chunk) => {
                    self.buf = chunk;
                    self.pos = 0;
                }
                Err(_) => return Ok(0),
            }
        }
        let n = (self.buf.len() - self.pos).min(out.len());
        out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

/// Create one half of a duplex: a [`ChannelReader`] + matching
/// [`ChannelWriter`]. Call twice to build a full duplex (one
/// direction each way) between a client and an in-process server.
pub fn pipe() -> (ChannelReader, ChannelWriter) {
    let (tx, rx) = mpsc::channel();
    (
        ChannelReader {
            rx,
            buf: Vec::new(),
            pos: 0,
        },
        ChannelWriter(tx),
    )
}

/// Spawn a worker thread that runs `server` against the server-side
/// halves of a freshly-created duplex, and return the client-side
/// halves.
///
/// The returned `(ChannelReader, ChannelWriter)` pair is what the
/// client transport reads from and writes to: the reader yields
/// bytes the server wrote, the writer sends bytes to the server.
/// The worker thread is detached; the server function owns both
/// halves of its end for the duration of the exchange.
pub fn spawn_server<F>(server: F) -> (ChannelReader, ChannelWriter)
where
    F: FnOnce(ChannelReader, ChannelWriter) -> io::Result<()> + Send + 'static,
{
    let (client_reader, server_writer) = pipe();
    let (server_reader, client_writer) = pipe();
    std::thread::spawn(move || {
        let _ = server(server_reader, server_writer);
    });
    (client_reader, client_writer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_request_and_response() {
        let (mut client_reader, mut client_writer) = spawn_server(|mut server_reader, mut server_writer| {
            let mut req = Vec::new();
            server_reader.read_to_end(&mut req)?;
            assert_eq!(req, b"hello");
            server_writer.write_all(b"world")?;
            Ok(())
        });
        client_writer.write_all(b"hello").unwrap();
        drop(client_writer); // signal EOF so the server's read_to_end returns
        let mut resp = Vec::new();
        client_reader.read_to_end(&mut resp).unwrap();
        assert_eq!(resp, b"world");
    }

    #[test]
    fn reader_reports_eof_after_writer_drop() {
        let (_reader, writer) = pipe();
        drop(writer);
        let mut reader = _reader;
        let mut buf = [0u8; 4];
        assert_eq!(reader.read(&mut buf).unwrap(), 0);
    }

    #[test]
    fn partial_reads_preserve_leftovers() {
        let (mut reader, mut writer) = pipe();
        writer.write_all(b"abcdef").unwrap();
        drop(writer);
        let mut buf = [0u8; 3];
        assert_eq!(reader.read(&mut buf).unwrap(), 3);
        assert_eq!(&buf, b"abc");
        assert_eq!(reader.read(&mut buf).unwrap(), 3);
        assert_eq!(&buf, b"def");
        assert_eq!(reader.read(&mut buf).unwrap(), 0);
    }
}
