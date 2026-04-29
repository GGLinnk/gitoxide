//! Consume the server's `report-status` response after a push.
//!
//! The response stream is a sequence of pkt-lines terminated by a flush-pkt.
//! When `side-band` or `side-band-64k` was negotiated on the push
//! [`Arguments`](super::Arguments), the payloads are sideband frames carrying
//! a leading band byte (1 = data, 2 = progress, 3 = fatal error); otherwise
//! each payload *is* the report-status content.
//!
//! This module provides a reader that walks the response until flush-pkt,
//! accumulates the `report-status` / `report-status-v2` lines on band 1,
//! collects band-2 messages as progress, and converts band-3 messages into
//! a typed fatal error. The collected report-status lines are then fed to
//! [`super::report_status::parse_report_v1`] or
//! [`super::report_status::parse_report_v2`] depending on which variant was
//! selected on the capability list.

use bstr::{BStr, BString, ByteSlice};

use super::report_status;

/// Whether the response stream uses side-band framing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SideBandMode {
    /// No side-band negotiation; each pkt-line payload is the report-status
    /// content directly.
    Disabled,
    /// Side-band was negotiated; each payload begins with a band byte
    /// (`\x01` = data, `\x02` = progress, `\x03` = fatal).
    Enabled,
}

/// The parsed report-status, preserving which variant the server emitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportKind {
    /// A `report-status` (v1) response.
    V1(report_status::Report),
    /// A `report-status-v2` response with optional per-command annotations.
    V2(report_status::ReportV2),
}

/// Successful outcome of consuming a push response.
///
/// Consuming this value without at least checking [`Self::is_success`]
/// or [`Self::command_statuses`] silently ignores per-command
/// rejections and unpack failures; the `#[must_use]` annotation makes
/// that accidental drop a compile-time warning.
#[must_use = "a push response Outcome should be inspected for rejections / unpack status"]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// Parsed report-status (v1 or v2, matching the advertised capability).
    pub report: ReportKind,
    /// Messages received on side-band channel 2 (server progress), in order.
    ///
    /// Empty when [`SideBandMode::Disabled`] was requested or when the
    /// server sent no progress.
    pub progress: Vec<BString>,
}

impl Outcome {
    /// Return `true` if the unpack phase succeeded.
    ///
    /// A failed unpack means the pack never landed on the server even
    /// though individual commands may still appear as `ok` (git's
    /// current behaviour mirrors this: unpack status is reported
    /// separately from per-command status).
    pub fn unpack_ok(&self) -> bool {
        match &self.report {
            ReportKind::V1(r) => matches!(r.unpack, report_status::UnpackStatus::Ok),
            ReportKind::V2(r) => matches!(r.unpack, report_status::UnpackStatus::Ok),
        }
    }

    /// Return the number of commands that were accepted by the server.
    pub fn accepted_count(&self) -> usize {
        match &self.report {
            ReportKind::V1(r) => r
                .commands
                .iter()
                .filter(|c| matches!(c, report_status::CommandStatus::Ok { .. }))
                .count(),
            ReportKind::V2(r) => r
                .commands
                .iter()
                .filter(|c| matches!(c, report_status::CommandStatusV2::Ok { .. }))
                .count(),
        }
    }

    /// Return the number of commands that were rejected by the server.
    pub fn rejected_count(&self) -> usize {
        match &self.report {
            ReportKind::V1(r) => r
                .commands
                .iter()
                .filter(|c| matches!(c, report_status::CommandStatus::Rejected { .. }))
                .count(),
            ReportKind::V2(r) => r
                .commands
                .iter()
                .filter(|c| matches!(c, report_status::CommandStatusV2::Rejected { .. }))
                .count(),
        }
    }

    /// Return `true` when the push was fully successful: unpack ok and
    /// every command accepted.
    pub fn is_success(&self) -> bool {
        self.unpack_ok() && self.rejected_count() == 0
    }

    /// Iterate the per-command outcomes uniformly across v1 and v2
    /// reports.
    ///
    /// Yields `(refname, Ok(options))` for accepted commands (options
    /// are always the default for v1 reports, since v1 carries no
    /// trailer metadata) and `(refname, Err(reason))` for rejections.
    pub fn command_statuses(
        &self,
    ) -> Box<dyn Iterator<Item = (&BStr, Result<report_status::CommandOptions, &BStr>)> + '_> {
        match &self.report {
            ReportKind::V1(r) => Box::new(r.commands.iter().map(|cmd| match cmd {
                report_status::CommandStatus::Ok { refname } => {
                    (refname.as_bstr(), Ok(report_status::CommandOptions::default()))
                }
                report_status::CommandStatus::Rejected { refname, reason } => {
                    (refname.as_bstr(), Err(reason.as_bstr()))
                }
            })),
            ReportKind::V2(r) => Box::new(r.commands.iter().map(|cmd| match cmd {
                report_status::CommandStatusV2::Ok { refname, options } => (refname.as_bstr(), Ok(options.clone())),
                report_status::CommandStatusV2::Rejected { refname, reason } => {
                    (refname.as_bstr(), Err(reason.as_bstr()))
                }
            })),
        }
    }
}

#[cfg(all(test, feature = "sha1"))]
mod outcome_tests {
    use super::*;
    use crate::push::report_status;

    fn oid(hex: &str) -> gix_hash::ObjectId {
        gix_hash::ObjectId::from_hex(hex.as_bytes()).expect("valid hex fixture")
    }

    #[test]
    fn is_success_requires_unpack_ok_and_no_rejections() {
        let ok_report = ReportKind::V1(report_status::Report {
            unpack: report_status::UnpackStatus::Ok,
            commands: vec![report_status::CommandStatus::Ok {
                refname: BString::from("refs/heads/main"),
            }],
        });
        let outcome = Outcome {
            report: ok_report,
            progress: Vec::new(),
        };
        assert!(outcome.unpack_ok());
        assert_eq!(outcome.accepted_count(), 1);
        assert_eq!(outcome.rejected_count(), 0);
        assert!(outcome.is_success());
    }

    #[test]
    fn rejection_flips_is_success_off() {
        let report = ReportKind::V2(report_status::ReportV2 {
            unpack: report_status::UnpackStatus::Ok,
            commands: vec![
                report_status::CommandStatusV2::Ok {
                    refname: BString::from("refs/heads/a"),
                    options: report_status::CommandOptions {
                        old_oid: Some(oid("1111111111111111111111111111111111111111")),
                        new_oid: Some(oid("2222222222222222222222222222222222222222")),
                        ..Default::default()
                    },
                },
                report_status::CommandStatusV2::Rejected {
                    refname: BString::from("refs/heads/b"),
                    reason: BString::from("policy"),
                },
            ],
        });
        let outcome = Outcome {
            report,
            progress: Vec::new(),
        };
        assert!(outcome.unpack_ok());
        assert_eq!(outcome.accepted_count(), 1);
        assert_eq!(outcome.rejected_count(), 1);
        assert!(!outcome.is_success(), "any rejection must flip is_success off");
    }

    #[test]
    fn command_statuses_yields_refname_and_options_uniformly() {
        let ok_oid = oid("1111111111111111111111111111111111111111");
        let new_oid = oid("2222222222222222222222222222222222222222");
        let report = ReportKind::V2(report_status::ReportV2 {
            unpack: report_status::UnpackStatus::Ok,
            commands: vec![
                report_status::CommandStatusV2::Ok {
                    refname: BString::from("refs/heads/a"),
                    options: report_status::CommandOptions {
                        old_oid: Some(ok_oid),
                        new_oid: Some(new_oid),
                        ..Default::default()
                    },
                },
                report_status::CommandStatusV2::Rejected {
                    refname: BString::from("refs/heads/b"),
                    reason: BString::from("bad policy"),
                },
            ],
        });
        let outcome = Outcome {
            report,
            progress: Vec::new(),
        };
        let collected: Vec<(BString, Result<report_status::CommandOptions, Vec<u8>>)> = outcome
            .command_statuses()
            .map(|(name, result)| (name.to_owned(), result.map_err(|r| r.to_vec())))
            .collect();
        assert_eq!(collected.len(), 2);
        let (name0, res0) = &collected[0];
        assert_eq!(name0, "refs/heads/a");
        match res0 {
            Ok(opts) => {
                assert_eq!(opts.old_oid, Some(ok_oid));
                assert_eq!(opts.new_oid, Some(new_oid));
            }
            Err(reason) => panic!("expected Ok for refs/heads/a, got Err({reason:?})"),
        }
        let (name1, res1) = &collected[1];
        assert_eq!(name1, "refs/heads/b");
        match res1 {
            Err(reason) => assert_eq!(reason.as_slice(), b"bad policy"),
            Ok(opts) => panic!("expected Err for refs/heads/b, got Ok({opts:?})"),
        }
    }

    #[test]
    fn unpack_failure_flips_is_success_off() {
        let report = ReportKind::V1(report_status::Report {
            unpack: report_status::UnpackStatus::Failed(BString::from("bad checksum")),
            commands: vec![report_status::CommandStatus::Ok {
                refname: BString::from("refs/heads/whatever"),
            }],
        });
        let outcome = Outcome {
            report,
            progress: Vec::new(),
        };
        assert!(!outcome.unpack_ok());
        assert!(!outcome.is_success());
    }
}

/// Errors raised while reading the push response.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("malformed packet line from server: {message}")]
    PacketLine { message: String },
    #[error(transparent)]
    Report(#[from] report_status::Error),
    #[error("response ended without a flush-pkt")]
    UnexpectedEof,
    #[error("server reported a fatal error on side-band channel 3: {message:?}")]
    ServerError { message: BString },
    #[error("unknown side-band byte `{band}` in push response")]
    UnknownBand { band: u8 },
}

/// Classification of a single response-stream payload.
///
/// Flush-pkts are handled by the reader loop itself and never surface as a
/// `Classified` value.
#[derive(Debug)]
#[cfg_attr(not(any(feature = "blocking-client", feature = "async-client")), allow(dead_code))]
pub(super) enum Classified<'a> {
    /// A report-status content line (post-sideband if enabled, direct otherwise).
    Data(&'a BStr),
    /// A progress message from band 2.
    Progress(BString),
}

/// Classify a single pkt-line payload according to side-band mode. Returns
/// `Err(Error::ServerError)` on band 3.
///
/// Callers typically use [`blocking_io::from_reader`] / [`async_io::from_reader`];
/// this helper is exposed for custom transports that read pkt-lines through
/// a different path.
pub(super) fn classify(payload: &[u8], side_band: SideBandMode) -> Result<Classified<'_>, Error> {
    match side_band {
        SideBandMode::Disabled => Ok(Classified::Data(payload.as_bstr())),
        SideBandMode::Enabled => {
            let (band, rest) = payload.split_first().ok_or(Error::UnexpectedEof)?;
            match band {
                1 => Ok(Classified::Data(rest.as_bstr())),
                2 => Ok(Classified::Progress(rest.to_owned().into())),
                3 => Err(Error::ServerError {
                    message: rest.to_owned().into(),
                }),
                other => Err(Error::UnknownBand { band: *other }),
            }
        }
    }
}

#[cfg(feature = "blocking-client")]
pub mod blocking_io {
    //! Blocking consumer for push responses.
    use bstr::BString;
    use gix_transport::client::blocking_io::ExtendedBufRead;

    use super::{classify, Classified, Error, Outcome, ReportKind, SideBandMode};
    use crate::push::report_status;

    /// Read the response from `reader` and parse it as a `report-status` or
    /// `report-status-v2`, depending on `expects_v2`.
    ///
    /// `side_band` must match the capability actually negotiated on the push
    /// [`Arguments`](crate::push::Arguments); use
    /// [`Arguments::can_use_side_band`](crate::push::Arguments::can_use_side_band)
    /// to decide.
    pub fn from_reader(
        reader: &mut (dyn ExtendedBufRead<'_> + Unpin),
        expects_v2: bool,
        side_band: SideBandMode,
    ) -> Result<Outcome, Error> {
        // The transport's reader is typically latched at the flush-pkt
        // that terminated the previous section (the handshake's ref
        // advertisement or a push-options drain). Push uses v0/v1
        // framing on the wire regardless of whether the client asked
        // for `report-status-v2`, so the reset bounds are v1.
        reader.reset(gix_transport::Protocol::V1);
        // When side-band is enabled git wraps the `report-status`
        // response in *two* layers: the outer pkt-lines carry one-byte
        // band prefixes, and the bytes inside band 1 are themselves
        // pkt-line framed so a single band-1 packet can carry several
        // status lines. Accumulate band-1 bytes into `inner_band_data`
        // and decode pkt-lines from that buffer at the end. With
        // side-band disabled each outer pkt-line already is a bare
        // status line and goes straight into `report_lines`.
        let mut report_lines: Vec<BString> = Vec::new();
        let mut inner_band_data: Vec<u8> = Vec::new();
        let mut progress: Vec<BString> = Vec::new();
        loop {
            let payload = match reader.readline() {
                // The transport returns `None` both for a stop-delimiter
                // (our flush-pkt terminator) and for genuine EOF;
                // `stopped_at()` disambiguates. `Some(MessageKind::Flush)`
                // is the clean end of section.
                None => match reader.stopped_at() {
                    Some(_) => break,
                    None => return Err(Error::UnexpectedEof),
                },
                Some(Err(err)) => return Err(err.into()),
                Some(Ok(Err(err))) => {
                    return Err(Error::PacketLine {
                        message: err.to_string(),
                    })
                }
                Some(Ok(Ok(line))) => match line.as_slice() {
                    Some(data) => data.to_owned(),
                    None => break,
                },
            };
            match classify(&payload, side_band)? {
                Classified::Data(content) => match side_band {
                    SideBandMode::Enabled => inner_band_data.extend_from_slice(content),
                    SideBandMode::Disabled => report_lines.push(content.to_owned()),
                },
                Classified::Progress(msg) => progress.push(msg),
            }
        }
        if matches!(side_band, SideBandMode::Enabled) && !inner_band_data.is_empty() {
            let mut cursor: &[u8] = &inner_band_data;
            while !cursor.is_empty() {
                match gix_transport::packetline::decode::streaming(cursor).map_err(|err| Error::PacketLine {
                    message: err.to_string(),
                })? {
                    gix_transport::packetline::decode::Stream::Complete { line, bytes_consumed } => {
                        if let Some(data) = line.as_slice() {
                            report_lines.push(BString::from(data));
                        }
                        cursor = &cursor[bytes_consumed..];
                    }
                    gix_transport::packetline::decode::Stream::Incomplete { .. } => {
                        return Err(Error::PacketLine {
                            message: "incomplete pkt-line in side-band report-status payload".into(),
                        });
                    }
                }
            }
        }
        let report = if expects_v2 {
            ReportKind::V2(report_status::parse_report_v2(
                report_lines.iter().map(|b| b.as_slice()),
            )?)
        } else {
            ReportKind::V1(report_status::parse_report_v1(
                report_lines.iter().map(|b| b.as_slice()),
            )?)
        };
        Ok(Outcome { report, progress })
    }
}

#[cfg(feature = "async-client")]
pub mod async_io {
    //! Async consumer for push responses.
    use bstr::BString;
    use gix_transport::client::async_io::ExtendedBufRead;

    use super::{classify, Classified, Error, Outcome, ReportKind, SideBandMode};
    use crate::push::report_status;

    /// Async counterpart of [`super::blocking_io::from_reader`].
    pub async fn from_reader(
        reader: &mut (dyn ExtendedBufRead<'_> + Unpin),
        expects_v2: bool,
        side_band: SideBandMode,
    ) -> Result<Outcome, Error> {
        // See the blocking counterpart for rationale: reset the reader
        // so it can read past the latched flush-pkt of the previous
        // section (handshake or push-options drain).
        reader.reset(gix_transport::Protocol::V1);
        // See the blocking counterpart for the two-layer side-band
        // decoding rationale.
        let mut report_lines: Vec<BString> = Vec::new();
        let mut inner_band_data: Vec<u8> = Vec::new();
        let mut progress: Vec<BString> = Vec::new();
        loop {
            let payload = match reader.readline().await {
                // `stopped_at()` distinguishes a clean stop-delimiter
                // (our flush-pkt terminator) from genuine EOF.
                None => match reader.stopped_at() {
                    Some(_) => break,
                    None => return Err(Error::UnexpectedEof),
                },
                Some(Err(err)) => return Err(err.into()),
                Some(Ok(Err(err))) => {
                    return Err(Error::PacketLine {
                        message: err.to_string(),
                    })
                }
                Some(Ok(Ok(line))) => match line.as_slice() {
                    Some(data) => data.to_owned(),
                    None => break,
                },
            };
            match classify(&payload, side_band)? {
                Classified::Data(content) => match side_band {
                    SideBandMode::Enabled => inner_band_data.extend_from_slice(content),
                    SideBandMode::Disabled => report_lines.push(content.to_owned()),
                },
                Classified::Progress(msg) => progress.push(msg),
            }
        }
        if matches!(side_band, SideBandMode::Enabled) && !inner_band_data.is_empty() {
            let mut cursor: &[u8] = &inner_band_data;
            while !cursor.is_empty() {
                match gix_transport::packetline::decode::streaming(cursor).map_err(|err| Error::PacketLine {
                    message: err.to_string(),
                })? {
                    gix_transport::packetline::decode::Stream::Complete { line, bytes_consumed } => {
                        if let Some(data) = line.as_slice() {
                            report_lines.push(BString::from(data));
                        }
                        cursor = &cursor[bytes_consumed..];
                    }
                    gix_transport::packetline::decode::Stream::Incomplete { .. } => {
                        return Err(Error::PacketLine {
                            message: "incomplete pkt-line in side-band report-status payload".into(),
                        });
                    }
                }
            }
        }
        let report = if expects_v2 {
            ReportKind::V2(report_status::parse_report_v2(
                report_lines.iter().map(|b| b.as_slice()),
            )?)
        } else {
            ReportKind::V1(report_status::parse_report_v1(
                report_lines.iter().map(|b| b.as_slice()),
            )?)
        };
        Ok(Outcome { report, progress })
    }
}

#[cfg(all(test, feature = "sha1"))]
mod tests {
    use super::*;

    #[test]
    fn classify_direct_data_passes_through_unchanged() {
        let payload = b"unpack ok\n".as_slice();
        match classify(payload, SideBandMode::Disabled).expect("direct data is never an error") {
            Classified::Data(b) => assert_eq!(b, payload.as_bstr()),
            other => panic!("expected Data, got {other:?}"),
        }
    }

    #[test]
    fn classify_band_1_strips_prefix() {
        let payload = [1, b'u', b'n', b'p', b'a', b'c', b'k', b' ', b'o', b'k'];
        match classify(&payload, SideBandMode::Enabled).expect("band 1 is not an error") {
            Classified::Data(b) => assert_eq!(b, b"unpack ok".as_bstr()),
            other => panic!("expected Data, got {other:?}"),
        }
    }

    #[test]
    fn classify_band_2_produces_progress() {
        let payload = [2, b'h', b'e', b'l', b'l', b'o'];
        match classify(&payload, SideBandMode::Enabled).expect("band 2 is not an error") {
            Classified::Progress(m) => assert_eq!(m.as_slice(), b"hello"),
            _ => panic!("expected Progress"),
        }
    }

    #[test]
    fn classify_band_3_returns_server_error() {
        let payload = [3, b'f', b'a', b't', b'a', b'l'];
        match classify(&payload, SideBandMode::Enabled) {
            Err(Error::ServerError { message }) => assert_eq!(message.as_slice(), b"fatal"),
            other => panic!("expected ServerError, got {other:?}"),
        }
    }

    #[test]
    fn classify_unknown_band_returns_decode_error() {
        let payload = [9, b'x'];
        match classify(&payload, SideBandMode::Enabled) {
            Err(Error::UnknownBand { band }) => assert_eq!(band, 9),
            other => panic!("expected UnknownBand, got {other:?}"),
        }
    }

    #[cfg(feature = "blocking-client")]
    mod blocking_from_reader {
        use std::io::Cursor;

        use bstr::ByteSlice;

        use super::super::{blocking_io, SideBandMode};
        use crate::push::{report_status::CommandStatus, ReportKind, UnpackStatus};

        fn build_band_one(inner: &[u8]) -> Vec<u8> {
            // One outer pkt-line carrying `band 1 || inner`, followed
            // by an outer flush-pkt that terminates the section.
            let mut band_and_inner = Vec::with_capacity(1 + inner.len());
            band_and_inner.push(1);
            band_and_inner.extend_from_slice(inner);
            let mut out = Vec::new();
            gix_transport::packetline::blocking_io::encode::data_to_write(&band_and_inner, &mut out)
                .expect("write to Vec never fails");
            gix_transport::packetline::blocking_io::encode::flush_to_write(&mut out)
                .expect("write to Vec never fails");
            out
        }

        fn build_inner_pkt_lines(lines: &[&[u8]]) -> Vec<u8> {
            let mut out = Vec::new();
            for line in lines {
                gix_transport::packetline::blocking_io::encode::data_to_write(line, &mut out)
                    .expect("write to Vec never fails");
            }
            out
        }

        fn read_from(bytes: Vec<u8>, expects_v2: bool) -> super::super::Outcome {
            let mut provider = gix_transport::packetline::blocking_io::StreamingPeekableIter::new(
                Cursor::new(bytes),
                &[gix_transport::packetline::PacketLineRef::Flush],
                false,
            );
            let mut reader = provider.as_read_without_sidebands::<gix_transport::client::blocking_io::HandleProgress<'_>>();
            blocking_io::from_reader(&mut reader, expects_v2, SideBandMode::Enabled).expect("valid report")
        }

        /// Regression: the server wraps the `report-status` response in
        /// *two* layers of pkt-line framing when `side-band-64k` is
        /// negotiated — an outer pkt-line carrying the band byte, and
        /// inside band 1 another pkt-line-framed stream. The parser
        /// must decode both layers; feeding the inner framed bytes to
        /// `parse_report_v1` directly yields `MalformedUnpack` because
        /// the inner length header reaches the line parser as text.
        #[test]
        fn side_band_nested_report_status_v1_parses_success() {
            let inner = build_inner_pkt_lines(&[b"unpack ok\n", b"ok refs/heads/main\n"]);
            let framed = build_band_one(&inner);
            let outcome = read_from(framed, false);
            assert!(outcome.unpack_ok());
            assert_eq!(outcome.accepted_count(), 1);
            assert_eq!(outcome.rejected_count(), 0);
            assert!(outcome.is_success());
            match &outcome.report {
                ReportKind::V1(r) => {
                    assert_eq!(r.unpack, UnpackStatus::Ok);
                    assert!(matches!(r.commands.first(), Some(CommandStatus::Ok { refname }) if refname == "refs/heads/main"));
                }
                other => panic!("expected V1 report, got {other:?}"),
            }
        }

        /// Regression: the `unpack index-pack failed` failure message
        /// surfaces inside band 1 exactly like a success, so the inner
        /// pkt-line decoder must run on failure responses too —
        /// otherwise the length prefix leaks into `MalformedUnpack`.
        #[test]
        fn side_band_nested_report_status_v1_parses_unpack_failure() {
            let inner = build_inner_pkt_lines(&[b"unpack index-pack failed\n"]);
            let framed = build_band_one(&inner);
            let outcome = read_from(framed, false);
            assert!(!outcome.unpack_ok());
            assert_eq!(outcome.rejected_count(), 0);
            assert!(!outcome.is_success());
            match &outcome.report {
                ReportKind::V1(r) => match &r.unpack {
                    UnpackStatus::Failed(reason) => {
                        assert_eq!(reason.as_bstr(), "index-pack failed");
                    }
                    other => panic!("expected failure, got {other:?}"),
                },
                other => panic!("expected V1 report, got {other:?}"),
            }
        }
    }
}
