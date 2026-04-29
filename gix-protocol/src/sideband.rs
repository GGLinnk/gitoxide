//! Sideband pkt-line framing shared by `upload-pack` (pack bytes) and
//! `receive-pack` (`report-status` text).
//!
//! Under git's `side-band` / `side-band-64k` capabilities a byte stream
//! is transmitted as a sequence of pkt-lines whose first data byte is
//! the channel identifier: `1` for primary data, `2` for progress, `3`
//! for fatal errors. This module provides the small surface both
//! servers need: a per-capability [`SidebandMode`] selector,
//! a channel-1 [`SidebandWriter`] that chunks writes at the spec cap,
//! and [`detect_v1_sideband_mode_from_caps`] that maps an advertised
//! capability set to the negotiated mode.
//!
//! Both `side-band` (v1, 1000-byte pkt-line cap) and `side-band-64k`
//! (v1/v2, 65520-byte pkt-line cap) describe the *pkt-line* max,
//! inclusive of the 4-byte ASCII length header and the 1-byte channel
//! id. The per-call data caps exposed below are `pkt-line-max - 5`.

use bstr::BString;
use gix_packetline::blocking_io::encode;
use gix_packetline::Channel;
use std::io;

/// Per-frame payload cap negotiated from the client's capabilities.
///
/// [`SidebandMode::Disabled`] is the "no wrapping" case: the peer did
/// not advertise `side-band` or `side-band-64k`, so callers must write
/// raw pkt-lines directly on the underlying stream. The two active
/// variants select between the two pkt-line size classes spelled out
/// in `gitprotocol-capabilities`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SidebandMode {
    /// No sideband wrapping; write raw pkt-lines on the underlying stream.
    Disabled,
    /// Band 1 prefix, up to 995 data bytes per pkt-line (v1 `side-band`).
    Band1Small,
    /// Band 1 prefix, up to 65515 data bytes per pkt-line
    /// (v1 `side-band-64k`, v2 packfile / sideband-all).
    Band1Large,
}

impl SidebandMode {
    /// Maximum number of data bytes that fit in a single band-1
    /// pkt-line under this mode. Returns `None` for [`Self::Disabled`].
    pub(crate) fn chunk_cap(self) -> Option<usize> {
        match self {
            // NOTE: v1 `side-band` pins total pkt-line length at 1000
            // bytes (4 length + 1 band + 995 data).
            SidebandMode::Band1Small => Some(995),
            // NOTE: `gix-packetline` caps pkt-line data at 65516;
            // `band_to_write` counts the band byte against that cap,
            // leaving 65515 bytes for the caller's payload.
            SidebandMode::Band1Large => Some(65515),
            SidebandMode::Disabled => None,
        }
    }
}

/// `io::Write` adapter that re-emits every `write` call as one or more
/// band-1 pkt-lines on `inner`.
///
/// Each [`io::Write::write`] call writes at most
/// [`SidebandMode::chunk_cap`] bytes and reports how many were
/// consumed; [`io::Write::write_all`] drives the remaining bytes via
/// the default loop. No buffering is performed: a source that emits in
/// small chunks produces correspondingly small pkt-lines, which is
/// legal but wastes framing overhead. Callers that care should buffer
/// upstream.
///
/// Channel 2 (progress) and channel 3 (fatal error) are out of scope
/// here — those channels are one-shot status emissions, not
/// `io::Write` streams.
pub(crate) struct SidebandWriter<'inner> {
    inner: &'inner mut dyn io::Write,
    cap: usize,
}

impl<'inner> SidebandWriter<'inner> {
    /// Wrap `inner` so writes are re-framed with a band-1 prefix.
    ///
    /// Returns `None` when `mode` is [`SidebandMode::Disabled`] — the
    /// caller should write raw pkt-lines on the underlying stream in
    /// that case.
    pub(crate) fn new(inner: &'inner mut dyn io::Write, mode: SidebandMode) -> Option<Self> {
        mode.chunk_cap().map(|cap| Self { inner, cap })
    }
}

impl io::Write for SidebandWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let take = buf.len().min(self.cap);
        encode::band_to_write(Channel::Data, &buf[..take], &mut *self.inner)?;
        Ok(take)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Map a client-advertised v0/v1 capability list to the negotiated
/// sideband mode.
///
/// `side-band-64k` takes precedence over `side-band` when both are
/// present, matching the real-git preference; absence of either yields
/// [`SidebandMode::Disabled`].
pub(crate) fn detect_v1_sideband_mode_from_caps(capabilities: &[BString]) -> SidebandMode {
    if capabilities.iter().any(|c| c.as_slice() == b"side-band-64k") {
        SidebandMode::Band1Large
    } else if capabilities.iter().any(|c| c.as_slice() == b"side-band") {
        SidebandMode::Band1Small
    } else {
        SidebandMode::Disabled
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gix_packetline::blocking_io::StreamingPeekableIter;
    use gix_packetline::PacketLineRef;
    use std::io::Write;

    #[test]
    fn chunk_cap_matches_spec_per_mode() {
        assert_eq!(SidebandMode::Disabled.chunk_cap(), None);
        assert_eq!(SidebandMode::Band1Small.chunk_cap(), Some(995));
        assert_eq!(SidebandMode::Band1Large.chunk_cap(), Some(65515));
    }

    #[test]
    fn detect_prefers_64k_then_side_band_then_disabled() {
        let none: Vec<BString> = vec![];
        assert_eq!(detect_v1_sideband_mode_from_caps(&none), SidebandMode::Disabled);

        let small = vec![BString::from("side-band")];
        assert_eq!(detect_v1_sideband_mode_from_caps(&small), SidebandMode::Band1Small);

        let large = vec![BString::from("side-band-64k")];
        assert_eq!(detect_v1_sideband_mode_from_caps(&large), SidebandMode::Band1Large);

        let both = vec![BString::from("side-band"), BString::from("side-band-64k")];
        assert_eq!(detect_v1_sideband_mode_from_caps(&both), SidebandMode::Band1Large);
    }

    #[test]
    fn writer_returns_none_on_disabled_mode() {
        let mut sink: Vec<u8> = Vec::new();
        assert!(SidebandWriter::new(&mut sink, SidebandMode::Disabled).is_none());
        assert!(sink.is_empty());
    }

    #[test]
    fn writer_chunks_payload_at_cap_and_frames_each_chunk_as_band_1() {
        let payload: Vec<u8> = (0..2_500u32).map(|i| (i % 251) as u8).collect();
        let mut on_wire: Vec<u8> = Vec::new();

        {
            let mut w =
                SidebandWriter::new(&mut on_wire, SidebandMode::Band1Small).expect("Band1Small is an active mode");
            w.write_all(&payload).expect("write succeeds into in-memory buffer");
            w.flush().expect("flush succeeds");
        }

        // Decode every pkt-line, stripping the band byte; reassembled
        // payload must equal the input, and every frame's data segment
        // must fit the per-mode cap.
        let mut reader = StreamingPeekableIter::new(on_wire.as_slice(), &[PacketLineRef::Flush], false);
        let mut reassembled: Vec<u8> = Vec::new();
        let mut frame_count = 0usize;
        while let Some(Ok(Ok(line))) = reader.read_line() {
            let data = line.as_slice().expect("band frames carry data");
            assert_eq!(data[0], 1, "every frame must be channel 1");
            let body = &data[1..];
            assert!(
                body.len() <= 995,
                "Band1Small body must fit in 995 bytes, got {}",
                body.len()
            );
            reassembled.extend_from_slice(body);
            frame_count += 1;
        }
        assert_eq!(reassembled, payload, "round-trip preserves every byte");
        assert!(frame_count >= 3, "2500 bytes with 995-byte cap → ≥ 3 frames");
    }

    #[test]
    fn writer_64k_mode_uses_65515_cap() {
        let payload: Vec<u8> = (0..70_000u32).map(|i| (i % 241) as u8).collect();
        let mut on_wire: Vec<u8> = Vec::new();

        {
            let mut w =
                SidebandWriter::new(&mut on_wire, SidebandMode::Band1Large).expect("Band1Large is an active mode");
            w.write_all(&payload).expect("write succeeds");
        }

        let mut reader = StreamingPeekableIter::new(on_wire.as_slice(), &[PacketLineRef::Flush], false);
        let mut reassembled: Vec<u8> = Vec::new();
        let mut saw_large_frame = false;
        while let Some(Ok(Ok(line))) = reader.read_line() {
            let data = line.as_slice().expect("band frame");
            assert_eq!(data[0], 1, "every frame must be channel 1");
            let body = &data[1..];
            assert!(
                body.len() <= 65515,
                "Band1Large body must fit in 65515 bytes, got {}",
                body.len()
            );
            if body.len() > 995 {
                saw_large_frame = true;
            }
            reassembled.extend_from_slice(body);
        }
        assert_eq!(reassembled, payload);
        assert!(saw_large_frame, "at least one frame should exceed the Band1Small cap");
    }
}
