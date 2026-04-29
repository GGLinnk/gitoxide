//! Blocking state machine for server-side v0/v1 `git-upload-pack`
//! under stateless-RPC (smart-HTTP) framing.
//!
//! The v0/v1 wire loop accepted here is:
//!
//! 1. Client sends the want-list (first line carries capabilities), optional
//!    shallow/deepen/filter directives, a flush-pkt, then the have-list
//!    terminated by `done`.
//! 2. Server parses the request and calls the caller-supplied `negotiate`
//!    closure to decide whether to acknowledge common objects.
//! 3. Server writes the acknowledgement line(s) - just `NAK` for the
//!    simplest stateless-RPC case - followed by the pack bytes produced
//!    by the `write_pack` closure. When the client negotiated
//!    `side-band` or `side-band-64k`, the pack bytes are pkt-line
//!    framed with a band-1 prefix here and the section is closed with
//!    a flush-pkt; without either capability the pack is streamed raw.
//!
//! The stateless variant above handles the single-round smart-HTTP
//! case. For stateful sessions (git:// / SSH) the client interleaves
//! multiple `have <oid>` batches with flush-pkts and expects the
//! server to emit ACK/NAK lines per batch; see [`serve_v1_stateful`].

use std::io::{Read, Write};

use super::fetch_request_v1;
use super::FetchRequestV1;

/// Response a caller's negotiation closure produces for v0/v1.
///
/// The wire grammar dictates exactly one of `NAK` or `ACK <oid>` per
/// stateless round, followed by the pack when `send_pack` is true.
#[derive(Debug, Default, Clone)]
pub struct ServeResponseV1 {
    /// When `Some`, emit `ACK <oid>` indicating a common ancestor.
    /// `None` emits `NAK`.
    pub ack: Option<gix_hash::ObjectId>,
    /// When `true`, invoke the pack-writer closure after the ack line.
    /// A `false` value produces a bodiless response (just `NAK` + flush).
    pub send_pack: bool,
}

/// Outcome of a completed [`serve_v1`] call.
#[derive(Debug)]
#[must_use = "inspect `pack_sent` to tell whether a pack was actually streamed"]
pub struct ServeOutcomeV1 {
    /// The parsed upload-request.
    pub request: FetchRequestV1,
    /// Whether a pack was streamed to the writer.
    pub pack_sent: bool,
}

/// Errors raised while driving the v0/v1 upload-pack state machine.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum ServeV1Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("malformed packet line in request: {message}")]
    PacketLine { message: String },
    #[error(transparent)]
    Parse(#[from] fetch_request_v1::Error),
    #[error("negotiation handler failed")]
    Negotiate(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error("pack generation handler failed")]
    PackGenerate(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
}

/// Drive one stateless-RPC v0/v1 upload-pack interaction.
///
/// `reader` yields the raw client bytes - the framed `want` / `have` /
/// `done` pkt-lines that form the upload-request. `writer` receives
/// the server's response: one `ACK` or `NAK` pkt-line followed by the
/// pack bytes produced by `write_pack`.
///
/// The two closures plug the concrete object-graph walker into the
/// state machine:
///
/// - `negotiate` receives the parsed [`FetchRequestV1`] and returns a
///   [`ServeResponseV1`] describing whether to emit `ACK <oid>` or
///   `NAK`, and whether the pack should follow.
/// - `write_pack` runs when `send_pack` is true and is responsible for
///   streaming a valid git pack onto the writer. When the client
///   negotiated `side-band` or `side-band-64k`, the byte stream from
///   `write_pack` is pkt-line framed with a band-1 prefix inside
///   `serve_v1` and the section is terminated with a flush-pkt;
///   without either capability the pack bytes are emitted verbatim.
#[doc(alias = "git upload-pack")]
pub fn serve_v1<R, W, N, P>(
    reader: R,
    writer: &mut W,
    negotiate: N,
    write_pack: P,
) -> Result<ServeOutcomeV1, ServeV1Error>
where
    R: Read,
    W: Write,
    N: FnOnce(&FetchRequestV1) -> Result<ServeResponseV1, Box<dyn std::error::Error + Send + Sync + 'static>>,
    P: FnOnce(&mut dyn Write) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>>,
{
    use gix_packetline::blocking_io::{encode, StreamingPeekableIter};
    use gix_packetline::PacketLineRef;

    // The v0/v1 upload-request consists of pkt-lines terminated by a
    // `done` pkt-line; flush-pkts inside separate the want-list from
    // the have-list. We read all pkt-lines through a single stream
    // without stopping at the first flush.
    let mut stream = StreamingPeekableIter::new(reader, &[], false);
    let mut payloads: Vec<Option<Vec<u8>>> = Vec::new();
    loop {
        match stream.read_line() {
            Some(Ok(Ok(line))) => match line {
                PacketLineRef::Data(data) => payloads.push(Some(data.to_vec())),
                PacketLineRef::Flush => payloads.push(None),
                PacketLineRef::Delimiter | PacketLineRef::ResponseEnd => {
                    // v0/v1 does not use delim-pkt; response-end belongs to
                    // stateless fetch, not upload-request. Ignore.
                }
            },
            Some(Ok(Err(err))) => {
                return Err(ServeV1Error::PacketLine {
                    message: err.to_string(),
                });
            }
            Some(Err(err)) => {
                // The v1 upload-request is not required to end with a
                // flush-pkt; the client terminates with `done\n` and
                // may close the stream immediately. Treat an
                // UnexpectedEof at the pkt-line boundary as a graceful
                // end-of-input.
                if err.kind() == std::io::ErrorKind::UnexpectedEof {
                    break;
                }
                return Err(ServeV1Error::Io(err));
            }
            None => break,
        }
    }

    let request = fetch_request_v1::parse_request(payloads.iter().map(|p| p.as_deref()))?;
    let response = negotiate(&request).map_err(ServeV1Error::Negotiate)?;

    // Emit the ACK/NAK line. v1 stateless-RPC uses at most one line.
    match &response.ack {
        Some(oid) => {
            let mut line = Vec::with_capacity(4 + 1 + 40 + 1);
            line.extend_from_slice(b"ACK ");
            oid.write_hex_to(&mut line)?;
            line.push(b'\n');
            encode::data_to_write(&line, &mut *writer)?;
        }
        None => {
            encode::data_to_write(b"NAK\n", &mut *writer)?;
        }
    }

    let pack_sent = response.send_pack;
    if pack_sent {
        let mode = crate::sideband::detect_v1_sideband_mode_from_caps(&request.capabilities);
        match crate::sideband::SidebandWriter::new(&mut *writer, mode) {
            None => {
                write_pack(writer).map_err(ServeV1Error::PackGenerate)?;
            }
            Some(mut sideband) => {
                write_pack(&mut sideband).map_err(ServeV1Error::PackGenerate)?;
                encode::flush_to_write(writer)?;
            }
        }
    }

    Ok(ServeOutcomeV1 { request, pack_sent })
}

/// Negotiated multi-ack mode for [`serve_v1_stateful`].
///
/// Picks which ACK wording the server emits per common oid. The mode
/// must match what the client requested on the first want line
/// (`multi_ack_detailed` → `ACK <oid> common` / `ready`,
/// `multi_ack` → `ACK <oid> continue`, legacy → single `ACK <oid>`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MultiAck {
    /// Single-ack flavour: emit at most one `ACK <oid>\n` line when a
    /// common commit is found. No `continue` or `ready` wording.
    #[default]
    None,
    /// Classic multi-ack: every common oid emits `ACK <oid> continue\n`.
    /// Used by git when the client sent just `multi_ack`.
    MultiAck,
    /// Detailed multi-ack: emits `ACK <oid> common\n` per common and a
    /// single `ACK <oid> ready\n` when the server has decided to ship.
    MultiAckDetailed,
}

/// How the caller classifies a client-announced `have <oid>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HaveClassification {
    /// The oid is reachable from the server's advertised tips; the
    /// server has it. Emits an ACK per the negotiated multi-ack mode.
    Common,
    /// The oid is not present or not reachable; the server does not
    /// have it. Emits no ACK.
    NotOurs,
}

/// Per-round decision produced by the caller after a flush-pkt closes
/// a batch of `have` lines.
///
/// Four states are meaningful:
///
/// - `continue_rounds = true, emit_ready = false` → send `NAK\n` and
///   wait for the next batch.
/// - `continue_rounds = true, emit_ready = true` → send
///   `ACK <last-common> ready\n` (detailed multi-ack only) and keep
///   waiting for the client's `done`.
/// - `continue_rounds = false` → the serve loop exits without
///   shipping a pack (used when negotiation failed hard).
///
/// The pack is shipped only after the client sends `done`; the
/// state machine owns that transition and calls the pack writer.
#[derive(Debug, Default, Clone, Copy)]
pub struct FlushDecision {
    /// Keep reading more `have` batches from the client.
    pub continue_rounds: bool,
    /// Emit `ACK <last-common> ready` on this flush.
    pub emit_ready: bool,
}

/// Drive a stateful v0/v1 upload-pack exchange against an
/// interactive transport (`git://` or SSH).
///
/// Unlike [`serve_v1`], this variant reads the client's want-list +
/// initial flush, then loops over as many `have`-batch/flush rounds
/// as the client needs, asking the caller to classify each oid and
/// to decide per-flush whether to keep rounds going or emit a
/// `ready` ack. The server ships the pack only after the client
/// sends `done`.
///
/// The caller owns the negotiator state entirely. The serve loop
/// is pure framing: pkt-line in, pkt-line out, ACK/NAK wording
/// chosen from [`MultiAck`].
///
/// ## Callbacks
///
/// - `parse_request` runs once on the want-list + shallow/deepen/
///   filter body. Same shape as [`serve_v1`]'s own parser output.
/// - `classify_have` is called per `have <oid>` and returns
///   `HaveClassification::Common` when the server has the oid, else
///   `NotOurs`.
/// - `on_flush` is called when the client closes a `have`-batch with
///   a flush-pkt; the returned [`FlushDecision`] drives the loop.
///   `emit_ready` is honoured only when the multi-ack mode is
///   `MultiAckDetailed` (legacy and plain multi-ack cannot express
///   `ready`).
/// - `write_pack` runs after the client sends `done` and there is at
///   least one common oid or the caller signalled ready.
#[doc(alias = "git upload-pack")]
pub fn serve_v1_stateful<R, W, Classify, Flush, Pack>(
    reader: R,
    writer: &mut W,
    multi_ack: MultiAck,
    mut classify_have: Classify,
    mut on_flush: Flush,
    write_pack: Pack,
) -> Result<ServeOutcomeV1, ServeV1Error>
where
    R: Read,
    W: Write,
    Classify: FnMut(&gix_hash::ObjectId) -> HaveClassification,
    Flush: FnMut() -> FlushDecision,
    Pack: FnOnce(&mut dyn Write) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>>,
{
    use gix_packetline::blocking_io::{encode, StreamingPeekableIter};
    use gix_packetline::PacketLineRef;

    let mut stream = StreamingPeekableIter::new(reader, &[], false);

    // 1. Drain the want-list up to and including the first flush.
    //    Shallow / deepen / filter directives are preserved in the
    //    request payload and parsed once at the end - same as
    //    `serve_v1`.
    let mut want_payloads: Vec<Option<Vec<u8>>> = Vec::new();
    loop {
        match stream.read_line() {
            Some(Ok(Ok(PacketLineRef::Data(d)))) => want_payloads.push(Some(d.to_vec())),
            Some(Ok(Ok(PacketLineRef::Flush))) => {
                want_payloads.push(None);
                break;
            }
            Some(Ok(Ok(PacketLineRef::Delimiter | PacketLineRef::ResponseEnd))) => {}
            Some(Ok(Err(err))) => {
                return Err(ServeV1Error::PacketLine {
                    message: err.to_string(),
                });
            }
            Some(Err(err)) if err.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Some(Err(err)) => return Err(ServeV1Error::Io(err)),
            None => break,
        }
    }

    let request = fetch_request_v1::parse_request(want_payloads.iter().map(|p| p.as_deref()))?;

    // 2. Loop over have-batches until we see `done` or the caller
    //    bails. Each flush between batches drives `on_flush`.
    let mut last_common_hex: Option<[u8; 64]> = None;
    let mut last_common_len: usize = 0;
    let mut got_any_common = false;
    let mut saw_done = false;
    let mut haves: Vec<gix_hash::ObjectId> = Vec::new();
    'outer: loop {
        let line = match stream.read_line() {
            Some(Ok(Ok(l))) => l,
            Some(Ok(Err(err))) => {
                return Err(ServeV1Error::PacketLine {
                    message: err.to_string(),
                });
            }
            Some(Err(err)) if err.kind() == std::io::ErrorKind::UnexpectedEof => break 'outer,
            Some(Err(err)) => return Err(ServeV1Error::Io(err)),
            None => break 'outer,
        };
        match line {
            PacketLineRef::Data(d) => {
                let text = trim_lf(d);
                if text == b"done" {
                    saw_done = true;
                    break 'outer;
                }
                if let Some(rest) = text.strip_prefix(b"have ") {
                    let oid = gix_hash::ObjectId::from_hex(rest).map_err(fetch_request_v1::Error::from)?;
                    haves.push(oid);
                    match classify_have(&oid) {
                        HaveClassification::Common => {
                            got_any_common = true;
                            let hex = oid.to_hex().to_string();
                            let bytes = hex.as_bytes();
                            let mut buf = [0u8; 64];
                            buf[..bytes.len()].copy_from_slice(bytes);
                            last_common_hex = Some(buf);
                            last_common_len = bytes.len();
                            emit_ack_for_common(writer, multi_ack, bytes)?;
                        }
                        HaveClassification::NotOurs => {}
                    }
                }
                // Any other line shape in the have-section is ignored
                // for forward-compat - git itself `die`s on unknown
                // lines but tolerating them here keeps unknown
                // trailer extensions from killing the connection.
            }
            PacketLineRef::Flush => {
                let decision = on_flush();
                if !decision.continue_rounds {
                    // Caller is abandoning. Emit NAK and stop.
                    encode::data_to_write(b"NAK\n", &mut *writer)?;
                    break 'outer;
                }
                // `multi_ack_detailed` with a `ready` trailer ends the
                // flush round with just the `ACK <oid> ready` line — the
                // `ready` IS the terminator. A plain (non-ready) flush
                // round still ends with `NAK\n` so the client knows the
                // batch was processed and more haves are welcome, which
                // matches upstream `upload-pack.c`.
                let emit_ready =
                    decision.emit_ready && matches!(multi_ack, MultiAck::MultiAckDetailed) && last_common_hex.is_some();
                if emit_ready {
                    let buf = last_common_hex.as_ref().expect("guarded above");
                    let mut line = Vec::with_capacity(4 + last_common_len + 8);
                    line.extend_from_slice(b"ACK ");
                    line.extend_from_slice(&buf[..last_common_len]);
                    line.extend_from_slice(b" ready\n");
                    encode::data_to_write(&line, &mut *writer)?;
                } else {
                    encode::data_to_write(b"NAK\n", &mut *writer)?;
                }
            }
            PacketLineRef::Delimiter | PacketLineRef::ResponseEnd => {}
        }
    }

    // 3. Final response after `done`. Spec: if any commons were
    //    acknowledged, emit a last `ACK <last-common>` (wording
    //    depends on multi-ack mode) then ship the pack. Else emit
    //    `NAK` and ship the pack anyway - the client sent `done`, so
    //    it wants the pack regardless of negotiation outcome.
    if saw_done {
        if got_any_common {
            if let Some(buf) = &last_common_hex {
                let bytes = &buf[..last_common_len];
                match multi_ack {
                    MultiAck::None => {
                        let mut line = Vec::with_capacity(4 + bytes.len() + 1);
                        line.extend_from_slice(b"ACK ");
                        line.extend_from_slice(bytes);
                        line.push(b'\n');
                        encode::data_to_write(&line, &mut *writer)?;
                    }
                    MultiAck::MultiAck | MultiAck::MultiAckDetailed => {
                        let mut line = Vec::with_capacity(4 + bytes.len() + 1);
                        line.extend_from_slice(b"ACK ");
                        line.extend_from_slice(bytes);
                        line.push(b'\n');
                        encode::data_to_write(&line, &mut *writer)?;
                    }
                }
            }
        } else {
            encode::data_to_write(b"NAK\n", &mut *writer)?;
        }
        write_pack(writer).map_err(ServeV1Error::PackGenerate)?;
        return Ok(ServeOutcomeV1 {
            request: FetchRequestV1 { haves, ..request },
            pack_sent: true,
        });
    }

    Ok(ServeOutcomeV1 {
        request: FetchRequestV1 { haves, ..request },
        pack_sent: false,
    })
}

fn emit_ack_for_common(writer: &mut (impl Write + ?Sized), multi_ack: MultiAck, hex: &[u8]) -> std::io::Result<()> {
    use gix_packetline::blocking_io::encode;
    match multi_ack {
        MultiAck::None => Ok(()), // legacy: emit the single ACK only at final `done`
        MultiAck::MultiAck => {
            let mut line = Vec::with_capacity(4 + hex.len() + 11);
            line.extend_from_slice(b"ACK ");
            line.extend_from_slice(hex);
            line.extend_from_slice(b" continue\n");
            encode::data_to_write(&line, writer).map(|_| ())
        }
        MultiAck::MultiAckDetailed => {
            let mut line = Vec::with_capacity(4 + hex.len() + 9);
            line.extend_from_slice(b"ACK ");
            line.extend_from_slice(hex);
            line.extend_from_slice(b" common\n");
            encode::data_to_write(&line, writer).map(|_| ())
        }
    }
}

fn trim_lf(bytes: &[u8]) -> &[u8] {
    match bytes.last() {
        Some(b'\n') => &bytes[..bytes.len() - 1],
        _ => bytes,
    }
}

#[cfg(all(test, feature = "sha1"))]
mod tests {
    use super::*;
    use gix_packetline::blocking_io::encode;

    fn oid(hex: &str) -> gix_hash::ObjectId {
        gix_hash::ObjectId::from_hex(hex.as_bytes()).expect("valid hex fixture")
    }

    fn build_request(wants: &[gix_hash::ObjectId], haves: &[gix_hash::ObjectId], caps: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for (i, w) in wants.iter().enumerate() {
            let mut line = Vec::new();
            line.extend_from_slice(b"want ");
            w.write_hex_to(&mut line).unwrap();
            if i == 0 && !caps.is_empty() {
                line.push(b' ');
                line.extend_from_slice(caps.as_bytes());
            }
            line.push(b'\n');
            encode::data_to_write(&line, &mut out).unwrap();
        }
        encode::flush_to_write(&mut out).unwrap();
        for h in haves {
            let mut line = Vec::new();
            line.extend_from_slice(b"have ");
            h.write_hex_to(&mut line).unwrap();
            line.push(b'\n');
            encode::data_to_write(&line, &mut out).unwrap();
        }
        encode::data_to_write(b"done\n", &mut out).unwrap();
        out
    }

    #[test]
    fn stateless_clone_emits_nak_and_pack() {
        let want = oid("1111111111111111111111111111111111111111");
        // NOTE(2026-04-18): no side-band capabilities means the
        // pack bytes are streamed raw after NAK, which this test
        // asserts; the sidebanded variants live in the two tests below.
        let request = build_request(&[want], &[], "multi_ack ofs-delta");

        let mut response: Vec<u8> = Vec::new();
        let outcome = serve_v1(
            request.as_slice(),
            &mut response,
            |req| {
                assert_eq!(req.wants, vec![want]);
                assert!(req.done);
                Ok(ServeResponseV1 {
                    ack: None,
                    send_pack: true,
                })
            },
            |writer| {
                writer.write_all(b"PACK-BYTES")?;
                Ok(())
            },
        )
        .expect("serve ok");

        assert!(outcome.pack_sent);
        assert_eq!(outcome.request.wants, vec![want]);
        // Response begins with "0008NAK\n" (4-byte length prefix + "NAK\n") then the raw pack bytes.
        let nak_frame = b"0008NAK\n";
        assert!(
            response.starts_with(nak_frame),
            "expected NAK pkt-line prefix, got {response:?}"
        );
        assert!(
            response.ends_with(b"PACK-BYTES"),
            "expected pack bytes at the end of the response, got {response:?}"
        );
    }

    #[test]
    fn stateless_clone_with_side_band_64k_wraps_pack_in_band_1() {
        let want = oid("1111111111111111111111111111111111111111");
        let request = build_request(&[want], &[], "side-band-64k");

        let mut response: Vec<u8> = Vec::new();
        let _ = serve_v1(
            request.as_slice(),
            &mut response,
            |_req| {
                Ok(ServeResponseV1 {
                    ack: None,
                    send_pack: true,
                })
            },
            |writer| {
                writer.write_all(b"PACK-BYTES")?;
                Ok(())
            },
        )
        .expect("serve ok");

        // Response layout: `0008NAK\n` + pkt-line band-1 frame + `0000` flush.
        // The frame is: ASCII-hex length (4 bytes) + band byte 0x01 + payload.
        let nak_frame = b"0008NAK\n";
        assert!(response.starts_with(nak_frame), "missing NAK prefix: {response:?}");
        let after_nak = &response[nak_frame.len()..];
        // "PACK-BYTES" = 10 bytes, plus 1 band byte = 11 bytes of data,
        // plus the 4-byte length header = 15 bytes total = 0x000f.
        assert!(
            after_nak.starts_with(b"000f\x01PACK-BYTES"),
            "expected band-1 framed pack, got {after_nak:?}"
        );
        assert!(
            response.ends_with(b"0000"),
            "expected flush-pkt terminator after sidebanded pack, got {response:?}"
        );
    }

    #[test]
    fn stateless_clone_with_side_band_wraps_pack_in_band_1() {
        let want = oid("1111111111111111111111111111111111111111");
        let request = build_request(&[want], &[], "side-band");

        let mut response: Vec<u8> = Vec::new();
        let _ = serve_v1(
            request.as_slice(),
            &mut response,
            |_req| {
                Ok(ServeResponseV1 {
                    ack: None,
                    send_pack: true,
                })
            },
            |writer| {
                writer.write_all(b"PACK-BYTES")?;
                Ok(())
            },
        )
        .expect("serve ok");

        // Same shape as the 64k variant: framing uses band 1; the
        // small-frame mode only differs in max chunk size, not layout.
        let nak_frame = b"0008NAK\n";
        assert!(response.starts_with(nak_frame));
        let after_nak = &response[nak_frame.len()..];
        assert!(
            after_nak.starts_with(b"000f\x01PACK-BYTES"),
            "expected band-1 framed pack, got {after_nak:?}"
        );
        assert!(response.ends_with(b"0000"));
    }

    #[test]
    fn ack_common_oid_is_serialised() {
        let want = oid("1111111111111111111111111111111111111111");
        let common = oid("2222222222222222222222222222222222222222");
        let request = build_request(&[want], &[common], "");
        let mut response: Vec<u8> = Vec::new();
        let outcome = serve_v1(
            request.as_slice(),
            &mut response,
            |_req| {
                Ok(ServeResponseV1 {
                    ack: Some(common),
                    send_pack: false,
                })
            },
            |_writer| Ok(()),
        )
        .expect("serve ok");
        assert!(!outcome.pack_sent);
        // The response must contain "ACK 2222...".
        let expected_fragment = b"ACK 2222222222222222222222222222222222222222";
        assert!(
            response
                .windows(expected_fragment.len())
                .any(|w| w == expected_fragment),
            "expected ACK line with common oid, got {response:?}"
        );
    }

    fn build_stateful_request(
        wants: &[gix_hash::ObjectId],
        caps: &str,
        have_batches: &[&[gix_hash::ObjectId]],
        with_done: bool,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        for (i, w) in wants.iter().enumerate() {
            let mut line = Vec::new();
            line.extend_from_slice(b"want ");
            w.write_hex_to(&mut line).unwrap();
            if i == 0 && !caps.is_empty() {
                line.push(b' ');
                line.extend_from_slice(caps.as_bytes());
            }
            line.push(b'\n');
            encode::data_to_write(&line, &mut out).unwrap();
        }
        encode::flush_to_write(&mut out).unwrap();
        for batch in have_batches.iter() {
            for h in *batch {
                let mut line = Vec::new();
                line.extend_from_slice(b"have ");
                h.write_hex_to(&mut line).unwrap();
                line.push(b'\n');
                encode::data_to_write(&line, &mut out).unwrap();
            }
            encode::flush_to_write(&mut out).unwrap();
        }
        if with_done {
            encode::data_to_write(b"done\n", &mut out).unwrap();
        }
        out
    }

    #[test]
    fn stateful_multi_ack_detailed_emits_common_then_ready_then_pack() {
        let want = oid("1111111111111111111111111111111111111111");
        let have1 = oid("2222222222222222222222222222222222222222");
        let have2 = oid("3333333333333333333333333333333333333333");
        let request = build_stateful_request(&[want], "multi_ack_detailed side-band-64k", &[&[have1, have2]], true);
        let mut response: Vec<u8> = Vec::new();

        // Classify first have as common, second as not-ours.
        let mut calls = 0;
        let outcome = serve_v1_stateful(
            request.as_slice(),
            &mut response,
            MultiAck::MultiAckDetailed,
            |h| {
                calls += 1;
                if *h == have1 {
                    HaveClassification::Common
                } else {
                    HaveClassification::NotOurs
                }
            },
            || FlushDecision {
                continue_rounds: true,
                emit_ready: true,
            },
            |w| {
                w.write_all(b"PACK-BYTES")?;
                Ok(())
            },
        )
        .expect("stateful serve ok");
        assert_eq!(calls, 2);
        assert!(outcome.pack_sent);

        let expect_common = b"ACK 2222222222222222222222222222222222222222 common";
        let expect_ready = b"ACK 2222222222222222222222222222222222222222 ready";
        let expect_final = b"ACK 2222222222222222222222222222222222222222\n";
        assert!(response.windows(expect_common.len()).any(|w| w == expect_common));
        assert!(response.windows(expect_ready.len()).any(|w| w == expect_ready));
        assert!(response.windows(expect_final.len()).any(|w| w == expect_final));
        assert!(response.ends_with(b"PACK-BYTES"));
    }

    /// Upstream `upload-pack.c` ends a `multi_ack_detailed` flush round
    /// whose negotiator decided "we have enough commons" with just the
    /// `ACK <oid> ready` line — no trailing `NAK\n` in that round, and
    /// no intermediate `NAK\n` before the post-`done` final `ACK`.
    /// Strict clients treat the extra `NAK` as a protocol error.
    #[test]
    fn stateful_multi_ack_detailed_does_not_emit_nak_after_ack_ready() {
        let want = oid("1111111111111111111111111111111111111111");
        let have = oid("2222222222222222222222222222222222222222");
        let request = build_stateful_request(&[want], "multi_ack_detailed side-band-64k", &[&[have]], true);
        let mut response: Vec<u8> = Vec::new();

        let _outcome = serve_v1_stateful(
            request.as_slice(),
            &mut response,
            MultiAck::MultiAckDetailed,
            |_h| HaveClassification::Common,
            || FlushDecision {
                continue_rounds: true,
                emit_ready: true,
            },
            |w| {
                w.write_all(b"PACK-BYTES")?;
                Ok(())
            },
        )
        .expect("stateful serve ok");

        let ready = b"ACK 2222222222222222222222222222222222222222 ready";
        assert!(
            response.windows(ready.len()).any(|w| w == ready),
            "ready trailer must be emitted"
        );
        // The inter-round NAK after ready is the bug — it must be gone.
        // A pre-pack `NAK\n` (when no commons ever matched) is fine, but
        // here the negotiator DID yield a common, so NAK has no place.
        assert!(
            !response.windows(b"NAK\n".len()).any(|w| w == b"NAK\n"),
            "no NAK should appear when the round emits ACK ready: {:?}",
            bstr::BStr::new(&response)
        );
    }

    #[test]
    fn stateful_legacy_emits_nak_when_nothing_common_then_ships_pack_on_done() {
        let want = oid("1111111111111111111111111111111111111111");
        let have = oid("2222222222222222222222222222222222222222");
        let request = build_stateful_request(&[want], "side-band-64k", &[&[have]], true);
        let mut response: Vec<u8> = Vec::new();
        let outcome = serve_v1_stateful(
            request.as_slice(),
            &mut response,
            MultiAck::None,
            |_| HaveClassification::NotOurs,
            || FlushDecision {
                continue_rounds: true,
                emit_ready: false,
            },
            |w| {
                w.write_all(b"PACK-BYTES")?;
                Ok(())
            },
        )
        .expect("stateful serve ok");
        assert!(outcome.pack_sent);
        // Final NAK appears just before the pack.
        assert!(
            response.windows(b"NAK\n".len()).any(|w| w == b"NAK\n"),
            "expected NAK somewhere in the response"
        );
        assert!(response.ends_with(b"PACK-BYTES"));
    }
}
