//! Blocking state machine for server-side `git-upload-pack` (v2).
//!
//! Reads a `command=fetch` request, delegates negotiation and pack
//! generation to a caller-supplied closure, and writes the framed
//! response per the protocol-v2 `output` grammar:
//!
//! ```text
//! output = acknowledgements flush-pkt |                 # AcknowledgmentsOnly
//!          [acknowledgments delim-pkt]
//!          [shallow-info delim-pkt]
//!          [wanted-refs delim-pkt]
//!          [packfile-uris delim-pkt]
//!          packfile flush-pkt                           # WithPack
//! ```
//!
//! The two top-level alternatives map to the two variants of
//! [`ServeResponse`]. Illegal combinations (e.g. a `ready` trailer
//! on a mid-negotiation response) are type-unrepresentable: Branch A
//! has no `trailer` field.
//!
//! Like `receive_pack::serve`, the heavy lifting - walking the object
//! graph, writing the pack bytes - is delegated through a closure so
//! `gix-protocol` stays decoupled from `gix-odb` / `gix-pack`.

use std::io::{Read, Write};

use super::ack;
use super::fetch_request;
use super::ls_refs_request;
use super::ls_refs_response;
use super::sections;
use super::{FetchRequest, LsRefsRequest};
use crate::wire_types::{Acknowledgments, PackfileUri, ShallowUpdate, WantedRef};

/// Response a caller's negotiation closure produces for a v2 fetch.
///
/// Variants map 1-to-1 onto the two top-level alternatives of the
/// protocol-v2 `output` grammar (see module doc). No illegal-on-wire
/// combinations are representable in the type system.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum ServeResponse {
    /// Branch A - mid-negotiation response. Server emits the
    /// `acknowledgments` section followed by flush-pkt; no pack, no
    /// other sections. The `ready` trailer slot is deliberately
    /// absent here: mid-negotiation cannot carry the `ready` marker
    /// because no pack follows, so the grammar production `(ready)`
    /// has no counterpart on this variant.
    #[non_exhaustive]
    AcknowledgmentsOnly {
        /// Grammar: `(nak | *ack)`. Empty emits `NAK` on the wire;
        /// non-empty emits one `ACK <oid>` per entry.
        common_oids: Vec<gix_hash::ObjectId>,
    },
    /// Branch B - final response. Zero or more optional sections
    /// followed by the mandatory `packfile` section. The caller's
    /// `write_pack` closure is invoked to emit the pack bytes.
    #[non_exhaustive]
    WithPack {
        /// Optional `acknowledgments` section. `None` omits the
        /// section header entirely; `Some(_)` emits the full
        /// section body including any `ready` trailer.
        acknowledgments: Option<Acknowledgments>,
        /// Optional `shallow-info` section. `None` omits the section
        /// header; `Some(vec![])` emits header + zero lines (both
        /// grammar-legal and distinct on the wire);
        /// `Some(vec![...])` emits header + each line.
        shallow_info: Option<Vec<ShallowUpdate>>,
        /// Optional `wanted-refs` section. Same three-state
        /// semantics as `shallow_info`.
        wanted_refs: Option<Vec<WantedRef>>,
        /// Optional `packfile-uris` section. Same three-state
        /// semantics. Non-`None` requires the client to have
        /// advertised the `packfile-uris` capability.
        packfile_uris: Option<Vec<PackfileUri>>,
    },
}

impl ServeResponse {
    /// Construct the acks-only (mid-negotiation, no pack) response.
    /// Empty `common_oids` emits `NAK`.
    pub fn acknowledgments_only(common_oids: Vec<gix_hash::ObjectId>) -> Self {
        ServeResponse::AcknowledgmentsOnly { common_oids }
    }

    /// Construct the pack-bearing response.
    pub fn with_pack(
        acknowledgments: Option<Acknowledgments>,
        shallow_info: Option<Vec<ShallowUpdate>>,
        wanted_refs: Option<Vec<WantedRef>>,
        packfile_uris: Option<Vec<PackfileUri>>,
    ) -> Self {
        ServeResponse::WithPack {
            acknowledgments,
            shallow_info,
            wanted_refs,
            packfile_uris,
        }
    }
}

/// Errors raised while driving the upload-pack state machine.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum ServeError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("malformed packet line in request: {message}")]
    PacketLine { message: String },
    #[error(transparent)]
    ParseFetch(#[from] fetch_request::Error),
    #[error(transparent)]
    ParseLsRefs(#[from] ls_refs_request::Error),
    #[error("unknown v2 command {command:?}; expected `command=fetch` or `command=ls-refs`")]
    UnknownCommand { command: bstr::BString },
    #[error("pack generation handler failed")]
    PackGenerate(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error("negotiation handler failed")]
    Negotiate(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error("ls-refs handler failed")]
    LsRefs(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
}

/// Outcome of a completed serve call.
#[derive(Debug)]
#[must_use = "inspect `pack_sent` to tell whether a pack was actually streamed"]
pub struct ServeOutcome {
    /// The parsed request that was answered.
    pub request: FetchRequest,
    /// Whether a pack was streamed in the response.
    pub pack_sent: bool,
}

/// Outcome of a completed [`dispatch_v2`] call, mirroring the union of
/// commands the dispatcher handles.
#[derive(Debug)]
#[must_use = "match on the variant to tell ls-refs from fetch"]
pub enum DispatchOutcome {
    /// The client invoked `command=ls-refs`.
    LsRefs {
        /// The parsed ls-refs request.
        request: LsRefsRequest,
        /// Number of refs emitted by the handler.
        refs_sent: usize,
    },
    /// The client invoked `command=fetch`.
    Fetch(ServeOutcome),
}

/// Drive one v2 upload-pack interaction.
///
/// `reader` yields the raw client bytes (a pkt-line framed
/// `command=fetch` request bounded by flush-pkts). `writer` receives
/// the server's framed response.
///
/// The caller supplies two closures:
///
/// - `negotiate` receives the parsed [`FetchRequest`] and returns a
///   [`ServeResponse`] describing the response shape. Implementations
///   walk their object graph to decide common ancestry and which
///   optional sections to include.
/// - `write_pack` is invoked with a mutable writer only when the
///   response is `WithPack`. The closure is responsible for streaming
///   a complete git pack. The pack byte stream is pkt-line framed
///   with a band-1 prefix inside `serve_v2`, matching the
///   protocol-v2 packfile-section spec; callers write raw pack bytes
///   and framing happens here.
///
/// On success, the full response has been written to `writer`.
#[doc(alias = "git upload-pack")]
pub fn serve_v2<R, W, N, P>(reader: R, writer: &mut W, negotiate: N, write_pack: P) -> Result<ServeOutcome, ServeError>
where
    R: Read,
    W: Write,
    N: FnOnce(&FetchRequest) -> Result<ServeResponse, Box<dyn std::error::Error + Send + Sync + 'static>>,
    P: FnOnce(&mut dyn Write) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>>,
{
    use gix_packetline::blocking_io::StreamingPeekableIter;
    use gix_packetline::PacketLineRef;

    // The v2 request is bounded by a flush-pkt; the header/body
    // sections are separated by a delim-pkt, which surfaces through
    // `read_line` as `PacketLineRef::Delimiter` and is captured as a
    // `None` entry by `read_until_flush` below.
    let mut stream = StreamingPeekableIter::new(reader, &[PacketLineRef::Flush], false);

    let payloads = read_until_flush(&mut stream)?;
    let request = parse_payloads(&payloads)?;

    let response = negotiate(&request).map_err(ServeError::Negotiate)?;

    let pack_sent = emit_response(writer, response, write_pack, request.sideband_all)?;

    Ok(ServeOutcome { request, pack_sent })
}

/// Read pkt-line payloads until a flush-pkt. Delim-pkts are encoded as
/// `None` entries so the caller can tell them apart from payloads.
fn read_until_flush<R: Read>(
    stream: &mut gix_packetline::blocking_io::StreamingPeekableIter<R>,
) -> Result<Vec<Option<Vec<u8>>>, ServeError> {
    use gix_packetline::PacketLineRef;

    let mut out = Vec::new();
    loop {
        match stream.read_line() {
            None => break,
            Some(Err(err)) => return Err(ServeError::Io(err)),
            Some(Ok(Err(err))) => {
                return Err(ServeError::PacketLine {
                    message: err.to_string(),
                })
            }
            Some(Ok(Ok(line))) => match line {
                PacketLineRef::Data(d) => out.push(Some(d.to_vec())),
                PacketLineRef::Delimiter => out.push(None),
                PacketLineRef::Flush | PacketLineRef::ResponseEnd => break,
            },
        }
    }
    Ok(out)
}

fn parse_payloads(payloads: &[Option<Vec<u8>>]) -> Result<FetchRequest, ServeError> {
    let items: Vec<Option<&[u8]>> = payloads.iter().map(|o| o.as_deref()).collect();
    Ok(fetch_request::parse_request(items.into_iter())?)
}

fn parse_ls_refs_payloads(payloads: &[Option<Vec<u8>>]) -> Result<LsRefsRequest, ServeError> {
    let items: Vec<Option<&[u8]>> = payloads.iter().map(|o| o.as_deref()).collect();
    Ok(ls_refs_request::parse_request(items.into_iter())?)
}

/// Peek the first `command=<name>` token from a payload sequence.
fn peek_command(payloads: &[Option<Vec<u8>>]) -> Option<bstr::BString> {
    use bstr::ByteSlice;
    for payload in payloads {
        let line = match payload {
            Some(data) => data.as_slice(),
            None => return None, // delim before command is invalid
        };
        let trimmed = match line.last() {
            Some(b'\n') => &line[..line.len() - 1],
            _ => line,
        };
        if let Some(rest) = trimmed.strip_prefix(b"command=") {
            return Some(rest.to_vec().into());
        }
        // Other lines before `command=` (e.g. capability filters) are
        // allowed; keep scanning.
        let _ = trimmed.as_bstr();
    }
    None
}

/// Emit one data pkt-line, adding a band-1 prefix when the v2
/// `sideband-all` capability was negotiated. Flush-pkts and
/// delim-pkts are NOT routed through here - per spec they stay
/// unbanded regardless of sideband-all.
fn emit_data_pkt<W: Write>(writer: &mut W, data: &[u8], sideband_all: bool) -> Result<usize, std::io::Error> {
    use gix_packetline::blocking_io::encode;
    use gix_packetline::Channel;
    if sideband_all {
        encode::band_to_write(Channel::Data, data, writer)
    } else {
        encode::data_to_write(data, writer)
    }
}

/// Walk the `ServeResponse` grammar variants and emit the matching
/// pkt-lines onto `writer`. Returns `true` when a pack was streamed.
///
/// When `sideband_all` is `true` the client negotiated the
/// `sideband-all` v2 capability, which requires every non-flush,
/// non-delim pkt-line to carry a band byte (stock git enters
/// sideband demux mode for the whole response and fails with
/// `bad band #<ascii-of-first-byte>` otherwise). Flush-pkts and
/// delim-pkts stay unbanded per spec.
fn emit_response<W, P>(
    writer: &mut W,
    response: ServeResponse,
    write_pack: P,
    sideband_all: bool,
) -> Result<bool, ServeError>
where
    W: Write,
    P: FnOnce(&mut dyn Write) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>>,
{
    use gix_packetline::blocking_io::encode;

    match response {
        ServeResponse::AcknowledgmentsOnly { common_oids } => {
            let lines = ack::emit_section_from_oids(&common_oids);
            for line in &lines {
                emit_data_pkt(&mut *writer, line.as_slice(), sideband_all)?;
            }
            encode::flush_to_write(writer)?;
            Ok(false)
        }
        ServeResponse::WithPack {
            acknowledgments,
            shallow_info,
            wanted_refs,
            packfile_uris,
        } => {
            if let Some(acks) = acknowledgments {
                for line in &ack::emit_section_from_acks(&acks) {
                    emit_data_pkt(&mut *writer, line.as_slice(), sideband_all)?;
                }
                encode::delim_to_write(&mut *writer)?;
            }
            if let Some(shallow) = shallow_info {
                for line in &sections::emit_shallow_info(&shallow) {
                    emit_data_pkt(&mut *writer, line.as_slice(), sideband_all)?;
                }
                encode::delim_to_write(&mut *writer)?;
            }
            if let Some(wanted) = wanted_refs {
                for line in &sections::emit_wanted_refs(&wanted) {
                    emit_data_pkt(&mut *writer, line.as_slice(), sideband_all)?;
                }
                encode::delim_to_write(&mut *writer)?;
            }
            if let Some(uris) = packfile_uris {
                for line in &sections::emit_packfile_uris(&uris) {
                    emit_data_pkt(&mut *writer, line.as_slice(), sideband_all)?;
                }
                encode::delim_to_write(&mut *writer)?;
            }

            // Packfile section: the `packfile\n` header is a regular
            // data pkt-line (banded iff sideband-all); the pack bytes
            // that follow are always band-1 framed, whether or not
            // sideband-all was negotiated - that framing is the
            // packfile section's own spec-mandated wrapping.
            let header = ack::emit_packfile_header();
            emit_data_pkt(&mut *writer, header.as_slice(), sideband_all)?;
            let mut sideband =
                crate::sideband::SidebandWriter::new(&mut *writer, crate::sideband::SidebandMode::Band1Large)
                    .expect("Band1Large is an active sideband mode");
            write_pack(&mut sideband).map_err(ServeError::PackGenerate)?;
            encode::flush_to_write(writer)?;
            Ok(true)
        }
    }
}

/// Drive one v2 upload-pack interaction dispatching between
/// `command=ls-refs` and `command=fetch`.
///
/// This is the recommended entry point for a full v2 upload-pack
/// service. A real v2 client sends `ls-refs` before `fetch`, so a
/// server that only implements `fetch` (via the narrower
/// [`serve_v2`]) will fail the first exchange of a typical session.
///
/// The caller supplies three closures:
///
/// - `ls_refs`: invoked on a `command=ls-refs` request; returns the
///   ordered list of refs to emit in the response.
/// - `fetch_negotiate`: invoked on a `command=fetch` request; returns
///   the server's [`ServeResponse`] choosing response shape.
/// - `fetch_write_pack`: invoked only when `fetch_negotiate` returned
///   the `WithPack` variant; streams the pack bytes.
///
/// Exactly one of `ls_refs` or the fetch closure pair is invoked per
/// call, depending on the request's `command=` header.
pub fn dispatch_v2<R, W, L, N, P>(
    reader: R,
    writer: &mut W,
    ls_refs: L,
    fetch_negotiate: N,
    fetch_write_pack: P,
) -> Result<DispatchOutcome, ServeError>
where
    R: Read,
    W: Write,
    L: FnOnce(
        &LsRefsRequest,
    ) -> Result<Vec<ls_refs_response::RefEntry>, Box<dyn std::error::Error + Send + Sync + 'static>>,
    N: FnOnce(&FetchRequest) -> Result<ServeResponse, Box<dyn std::error::Error + Send + Sync + 'static>>,
    P: FnOnce(&mut dyn Write) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>>,
{
    use gix_packetline::blocking_io::{encode, StreamingPeekableIter};
    use gix_packetline::PacketLineRef;

    let mut stream = StreamingPeekableIter::new(reader, &[PacketLineRef::Flush], false);
    let payloads = read_until_flush(&mut stream)?;

    let command = peek_command(&payloads).ok_or(ServeError::UnknownCommand {
        command: bstr::BString::default(),
    })?;

    if command == "ls-refs" {
        let request = parse_ls_refs_payloads(&payloads)?;
        let refs = ls_refs(&request).map_err(ServeError::LsRefs)?;
        let lines = ls_refs_response::emit(&refs);
        for line in &lines {
            encode::data_to_write(line.as_slice(), &mut *writer)?;
        }
        encode::flush_to_write(writer)?;
        Ok(DispatchOutcome::LsRefs {
            request,
            refs_sent: refs.len(),
        })
    } else if command == "fetch" {
        let request = parse_payloads(&payloads)?;
        let response = fetch_negotiate(&request).map_err(ServeError::Negotiate)?;
        let pack_sent = emit_response(writer, response, fetch_write_pack, request.sideband_all)?;
        Ok(DispatchOutcome::Fetch(ServeOutcome { request, pack_sent }))
    } else {
        Err(ServeError::UnknownCommand { command })
    }
}

#[cfg(all(test, feature = "sha1"))]
mod tests {
    use super::*;
    use crate::wire_types::AckTrailer;

    fn oid(hex: &str) -> gix_hash::ObjectId {
        gix_hash::ObjectId::from_hex(hex.as_bytes()).expect("valid hex fixture")
    }

    /// Framed v2 request: header with command=fetch, delim, body, flush.
    fn framed_v2_fetch(header: &[&[u8]], body: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        for line in header {
            gix_packetline::blocking_io::encode::data_to_write(line, &mut out).unwrap();
        }
        gix_packetline::blocking_io::encode::delim_to_write(&mut out).unwrap();
        for line in body {
            gix_packetline::blocking_io::encode::data_to_write(line, &mut out).unwrap();
        }
        gix_packetline::blocking_io::encode::flush_to_write(&mut out).unwrap();
        out
    }

    #[test]
    fn serve_emits_nak_and_no_pack_when_negotiation_declines() {
        let req = framed_v2_fetch(
            &[b"command=fetch\n"],
            &[b"want 1111111111111111111111111111111111111111\n", b"done\n"],
        );
        let mut resp = Vec::new();
        let outcome = serve_v2(
            req.as_slice(),
            &mut resp,
            |_request| Ok(ServeResponse::AcknowledgmentsOnly { common_oids: Vec::new() }),
            |_w| panic!("write_pack should not be invoked for AcknowledgmentsOnly"),
        )
        .expect("serve ok");

        assert!(!outcome.pack_sent);
        assert!(resp.windows(b"acknowledgments".len()).any(|w| w == b"acknowledgments"));
        assert!(resp.windows(b"NAK".len()).any(|w| w == b"NAK"));
        assert!(!resp.windows(b"packfile".len()).any(|w| w == b"packfile"));
    }

    #[test]
    fn serve_emits_pack_when_ready() {
        let req = framed_v2_fetch(
            &[b"command=fetch\n"],
            &[b"want 1111111111111111111111111111111111111111\n", b"done\n"],
        );
        let mut resp = Vec::new();
        let pack_payload = b"PACK\x00\x00\x00\x02\x00\x00\x00\x00".to_vec();
        let pack_payload_copy = pack_payload.clone();
        let outcome = serve_v2(
            req.as_slice(),
            &mut resp,
            |_request| {
                Ok(ServeResponse::WithPack {
                    acknowledgments: Some(Acknowledgments {
                        common_oids: Vec::new(),
                        trailer: Some(AckTrailer::Ready),
                    }),
                    shallow_info: None,
                    wanted_refs: None,
                    packfile_uris: None,
                })
            },
            move |w| w.write_all(&pack_payload_copy).map_err(Into::into),
        )
        .expect("serve ok");

        assert!(outcome.pack_sent);
        assert!(resp.windows(b"ready".len()).any(|w| w == b"ready"));
        assert!(resp.windows(b"packfile".len()).any(|w| w == b"packfile"));
        // The pack bytes are band-1 pkt-line framed by `serve_v2`; the
        // contiguous payload still appears verbatim as a subsequence
        // inside the frame (between the length prefix + band byte and
        // the next frame boundary), so a substring match still holds.
        assert!(resp.windows(pack_payload.len()).any(|w| w == pack_payload.as_slice()));
    }

    #[test]
    fn serve_v2_wraps_pack_bytes_in_band_1() {
        let req = framed_v2_fetch(
            &[b"command=fetch\n"],
            &[b"want 1111111111111111111111111111111111111111\n", b"done\n"],
        );
        let mut resp = Vec::new();
        let _ = serve_v2(
            req.as_slice(),
            &mut resp,
            |_request| {
                Ok(ServeResponse::WithPack {
                    acknowledgments: Some(Acknowledgments {
                        common_oids: Vec::new(),
                        trailer: Some(AckTrailer::Ready),
                    }),
                    shallow_info: None,
                    wanted_refs: None,
                    packfile_uris: None,
                })
            },
            |w| w.write_all(b"PACK-BYTES").map_err(Into::into),
        )
        .expect("serve ok");

        // Walk pkt-lines from the first `packfile` header forward and
        // assert every subsequent data pkt-line in the packfile
        // section carries a band-1 prefix, and the section ends with a
        // flush-pkt `0000`.
        assert!(
            frames_after_packfile_header_are_band_1(&resp),
            "expected every post-header pkt-line to start with band 1: {resp:?}"
        );
        assert!(resp.ends_with(b"0000"), "expected flush-pkt terminator: {resp:?}");
    }

    #[test]
    fn dispatch_v2_fetch_wraps_pack_bytes_in_band_1() {
        let req = framed_v2_fetch(
            &[b"command=fetch\n"],
            &[b"want 1111111111111111111111111111111111111111\n", b"done\n"],
        );
        let mut resp = Vec::new();
        let outcome = dispatch_v2(
            req.as_slice(),
            &mut resp,
            |_req| panic!("ls-refs must not be called for fetch"),
            |_request| {
                Ok(ServeResponse::WithPack {
                    acknowledgments: Some(Acknowledgments {
                        common_oids: Vec::new(),
                        trailer: Some(AckTrailer::Ready),
                    }),
                    shallow_info: None,
                    wanted_refs: None,
                    packfile_uris: None,
                })
            },
            |w| w.write_all(b"PACK-BYTES").map_err(Into::into),
        )
        .expect("dispatch ok");
        match outcome {
            DispatchOutcome::Fetch(serve_outcome) => assert!(serve_outcome.pack_sent),
            other => panic!("expected Fetch, got {other:?}"),
        }
        assert!(
            frames_after_packfile_header_are_band_1(&resp),
            "expected dispatched fetch pack to be band-1 framed: {resp:?}"
        );
        assert!(resp.ends_with(b"0000"));
    }

    /// Walk `resp` as a pkt-line stream. Find the first pkt-line whose
    /// payload is exactly `packfile\n`, then assert every subsequent
    /// data pkt-line (up to the next flush-pkt) has a first payload
    /// byte equal to 0x01 (band 1). Returns false on any deviation.
    fn frames_after_packfile_header_are_band_1(resp: &[u8]) -> bool {
        let marker = b"packfile\n";
        let Some(mut cursor) = find_pkt_line_with_payload(resp, marker) else {
            return false;
        };
        // Skip the packfile header pkt-line itself.
        cursor += 4 + marker.len();
        loop {
            if cursor + 4 > resp.len() {
                return false;
            }
            let len_bytes = &resp[cursor..cursor + 4];
            if len_bytes == b"0000" {
                return true; // clean flush-pkt termination
            }
            let len = u16::from_str_radix(std::str::from_utf8(len_bytes).ok().unwrap_or(""), 16)
                .ok()
                .map(usize::from);
            let Some(len) = len else {
                return false;
            };
            if len < 5 {
                return false;
            }
            let band_byte_idx = cursor + 4;
            if band_byte_idx >= resp.len() || resp[band_byte_idx] != 0x01 {
                return false;
            }
            cursor += len;
        }
    }

    fn find_pkt_line_with_payload(resp: &[u8], payload: &[u8]) -> Option<usize> {
        let mut cursor = 0;
        while cursor + 4 <= resp.len() {
            let len_bytes = &resp[cursor..cursor + 4];
            if len_bytes == b"0000" || len_bytes == b"0001" || len_bytes == b"0002" {
                cursor += 4;
                continue;
            }
            let len = u16::from_str_radix(std::str::from_utf8(len_bytes).ok()?, 16).ok()? as usize;
            if len < 4 || cursor + len > resp.len() {
                return None;
            }
            let body = &resp[cursor + 4..cursor + len];
            if body == payload {
                return Some(cursor);
            }
            cursor += len;
        }
        None
    }

    #[test]
    fn dispatch_v2_routes_ls_refs_to_the_ls_refs_handler() {
        let req = framed_v2_fetch(&[b"command=ls-refs\n"], &[b"peel\n", b"ref-prefix refs/heads/\n"]);
        let mut resp = Vec::new();
        let outcome = dispatch_v2(
            req.as_slice(),
            &mut resp,
            |req| {
                assert!(req.peel);
                assert_eq!(req.prefixes.len(), 1);
                Ok(vec![super::ls_refs_response::RefEntry {
                    object: Some(oid("1111111111111111111111111111111111111111")),
                    name: "refs/heads/main".into(),
                    symref_target: None,
                    peeled: None,
                }])
            },
            |_req| panic!("fetch negotiator must not be called for ls-refs"),
            |_w| panic!("fetch pack writer must not be called for ls-refs"),
        )
        .expect("ls-refs ok");

        match outcome {
            DispatchOutcome::LsRefs { refs_sent, .. } => assert_eq!(refs_sent, 1),
            other => panic!("expected LsRefs, got {other:?}"),
        }
        assert!(resp
            .windows(b"1111111111111111111111111111111111111111 refs/heads/main".len())
            .any(|w| w == b"1111111111111111111111111111111111111111 refs/heads/main"));
    }

    #[test]
    fn dispatch_v2_routes_fetch_to_the_fetch_handler() {
        let req = framed_v2_fetch(
            &[b"command=fetch\n"],
            &[b"want 1111111111111111111111111111111111111111\n", b"done\n"],
        );
        let mut resp = Vec::new();
        let outcome = dispatch_v2(
            req.as_slice(),
            &mut resp,
            |_req| panic!("ls-refs must not be called for fetch"),
            |_request| Ok(ServeResponse::AcknowledgmentsOnly { common_oids: Vec::new() }),
            |_w| panic!("pack writer must not run for AcknowledgmentsOnly"),
        )
        .expect("fetch ok");

        match outcome {
            DispatchOutcome::Fetch(serve_outcome) => assert!(!serve_outcome.pack_sent),
            other => panic!("expected Fetch, got {other:?}"),
        }
        assert!(resp.windows(b"NAK".len()).any(|w| w == b"NAK"));
    }

    #[test]
    fn dispatch_v2_rejects_unknown_command_with_typed_error() {
        let req = framed_v2_fetch(&[b"command=wat\n"], &[]);
        let mut resp = Vec::new();
        let err = dispatch_v2(
            req.as_slice(),
            &mut resp,
            |_req| panic!("must not route ls-refs"),
            |_req| panic!("must not route fetch"),
            |_w| panic!("no pack"),
        )
        .expect_err("unknown command");
        assert!(matches!(err, ServeError::UnknownCommand { .. }));
    }

    /// Stock-git clone fix: no `acknowledgments` section before
    /// `packfile` when the caller doesn't want one.
    #[test]
    fn serve_v2_bare_packfile_response_when_no_acknowledgments() {
        let req = framed_v2_fetch(
            &[b"command=fetch\n"],
            &[b"want 1111111111111111111111111111111111111111\n", b"done\n"],
        );
        let mut resp = Vec::new();
        let _ = serve_v2(
            req.as_slice(),
            &mut resp,
            |_request| {
                Ok(ServeResponse::WithPack {
                    acknowledgments: None,
                    shallow_info: None,
                    wanted_refs: None,
                    packfile_uris: None,
                })
            },
            |w| w.write_all(b"PACK-BYTES").map_err(Into::into),
        )
        .expect("serve ok");

        // Response must NOT contain `acknowledgments` as a pkt-line
        // payload. It MUST contain `packfile` as the first section
        // header.
        assert!(
            find_pkt_line_with_payload(&resp, b"acknowledgments\n").is_none(),
            "bare-packfile response must omit the acknowledgments section entirely: {resp:?}"
        );
        assert!(
            find_pkt_line_with_payload(&resp, b"packfile\n").is_some(),
            "bare-packfile response must still emit the packfile header: {resp:?}"
        );
        assert!(
            frames_after_packfile_header_are_band_1(&resp),
            "pack bytes must be band-1 framed: {resp:?}"
        );
    }

    #[test]
    fn serve_v2_emits_acknowledgments_only_mid_negotiation() {
        let req = framed_v2_fetch(
            &[b"command=fetch\n"],
            &[b"want 1111111111111111111111111111111111111111\n"],
        );
        let mut resp = Vec::new();
        let outcome = serve_v2(
            req.as_slice(),
            &mut resp,
            |_request| Ok(ServeResponse::AcknowledgmentsOnly { common_oids: Vec::new() }),
            |_w| panic!("no pack in Branch A"),
        )
        .expect("serve ok");

        assert!(!outcome.pack_sent);
        assert!(find_pkt_line_with_payload(&resp, b"acknowledgments\n").is_some());
        assert!(find_pkt_line_with_payload(&resp, b"NAK\n").is_some());
        assert!(find_pkt_line_with_payload(&resp, b"packfile\n").is_none());
        assert!(resp.ends_with(b"0000"), "must end with flush-pkt: {resp:?}");
    }

    #[test]
    fn serve_v2_emits_acknowledgments_only_with_common_oid() {
        let req = framed_v2_fetch(
            &[b"command=fetch\n"],
            &[b"want 1111111111111111111111111111111111111111\n"],
        );
        let mut resp = Vec::new();
        let common = oid("2222222222222222222222222222222222222222");
        let _ = serve_v2(
            req.as_slice(),
            &mut resp,
            |_request| Ok(ServeResponse::AcknowledgmentsOnly { common_oids: vec![common] }),
            |_w| panic!("no pack"),
        )
        .expect("serve ok");

        assert!(find_pkt_line_with_payload(
            &resp,
            b"ACK 2222222222222222222222222222222222222222\n"
        )
        .is_some());
        // No NAK when there's an ACK.
        assert!(find_pkt_line_with_payload(&resp, b"NAK\n").is_none());
    }

    #[test]
    fn serve_v2_emits_acknowledgments_then_delim_then_packfile() {
        let req = framed_v2_fetch(
            &[b"command=fetch\n"],
            &[b"want 1111111111111111111111111111111111111111\n", b"done\n"],
        );
        let mut resp = Vec::new();
        let common = oid("2222222222222222222222222222222222222222");
        let _ = serve_v2(
            req.as_slice(),
            &mut resp,
            |_request| {
                Ok(ServeResponse::WithPack {
                    acknowledgments: Some(Acknowledgments::new(vec![common], None)),
                    shallow_info: None,
                    wanted_refs: None,
                    packfile_uris: None,
                })
            },
            |w| w.write_all(b"PACK-BYTES").map_err(Into::into),
        )
        .expect("serve ok");

        assert!(find_pkt_line_with_payload(&resp, b"acknowledgments\n").is_some());
        assert!(find_pkt_line_with_payload(
            &resp,
            b"ACK 2222222222222222222222222222222222222222\n"
        )
        .is_some());
        // No `ready` trailer since trailer is None.
        assert!(find_pkt_line_with_payload(&resp, b"ready\n").is_none());
        assert!(find_pkt_line_with_payload(&resp, b"packfile\n").is_some());
    }

    #[test]
    fn serve_v2_emits_acknowledgments_with_ready_trailer_before_packfile() {
        let req = framed_v2_fetch(
            &[b"command=fetch\n"],
            &[b"want 1111111111111111111111111111111111111111\n", b"done\n"],
        );
        let mut resp = Vec::new();
        let common = oid("2222222222222222222222222222222222222222");
        let _ = serve_v2(
            req.as_slice(),
            &mut resp,
            |_request| {
                Ok(ServeResponse::WithPack {
                    acknowledgments: Some(Acknowledgments::new(vec![common], Some(AckTrailer::Ready))),
                    shallow_info: None,
                    wanted_refs: None,
                    packfile_uris: None,
                })
            },
            |w| w.write_all(b"PACK-BYTES").map_err(Into::into),
        )
        .expect("serve ok");

        assert!(find_pkt_line_with_payload(&resp, b"ready\n").is_some());
        assert!(find_pkt_line_with_payload(&resp, b"packfile\n").is_some());
    }

    #[test]
    fn serve_v2_emits_shallow_info_with_lines_before_packfile() {
        use crate::wire_types::ShallowUpdate;
        let req = framed_v2_fetch(
            &[b"command=fetch\n"],
            &[b"want 1111111111111111111111111111111111111111\n", b"done\n"],
        );
        let mut resp = Vec::new();
        let shallow_oid = oid("3333333333333333333333333333333333333333");
        let _ = serve_v2(
            req.as_slice(),
            &mut resp,
            |_request| {
                Ok(ServeResponse::WithPack {
                    acknowledgments: None,
                    shallow_info: Some(vec![ShallowUpdate::Shallow(shallow_oid)]),
                    wanted_refs: None,
                    packfile_uris: None,
                })
            },
            |w| w.write_all(b"PACK-BYTES").map_err(Into::into),
        )
        .expect("serve ok");

        assert!(find_pkt_line_with_payload(&resp, b"shallow-info\n").is_some());
        assert!(find_pkt_line_with_payload(
            &resp,
            b"shallow 3333333333333333333333333333333333333333\n"
        )
        .is_some());
        assert!(find_pkt_line_with_payload(&resp, b"packfile\n").is_some());
        // shallow-info must appear BEFORE packfile in the pkt-line stream.
        let shallow_pos = find_pkt_line_with_payload(&resp, b"shallow-info\n").unwrap();
        let packfile_pos = find_pkt_line_with_payload(&resp, b"packfile\n").unwrap();
        assert!(shallow_pos < packfile_pos);
    }

    /// `Some(vec![])` is wire-distinct from `None`: header-only
    /// section vs omitted section.
    #[test]
    fn serve_v2_emits_empty_shallow_info_section_when_some_empty() {
        let req = framed_v2_fetch(
            &[b"command=fetch\n"],
            &[b"want 1111111111111111111111111111111111111111\n", b"done\n"],
        );
        let mut resp = Vec::new();
        let _ = serve_v2(
            req.as_slice(),
            &mut resp,
            |_request| {
                Ok(ServeResponse::WithPack {
                    acknowledgments: None,
                    shallow_info: Some(Vec::new()),
                    wanted_refs: None,
                    packfile_uris: None,
                })
            },
            |w| w.write_all(b"PACK-BYTES").map_err(Into::into),
        )
        .expect("serve ok");

        // The `shallow-info` header IS emitted even though the Vec is
        // empty - this distinguishes `Some(vec![])` from `None`.
        assert!(find_pkt_line_with_payload(&resp, b"shallow-info\n").is_some());
        // No body lines (no `shallow <oid>` or `unshallow <oid>`).
        assert!(find_pkt_line_with_payload(&resp, b"shallow 3333333333333333333333333333333333333333\n")
            .is_none());
    }

    #[test]
    fn serve_v2_emits_wanted_refs_before_packfile() {
        use crate::wire_types::WantedRef;
        let req = framed_v2_fetch(
            &[b"command=fetch\n"],
            &[b"want-ref refs/heads/main\n", b"done\n"],
        );
        let mut resp = Vec::new();
        let resolved_oid = oid("4444444444444444444444444444444444444444");
        let _ = serve_v2(
            req.as_slice(),
            &mut resp,
            |_request| {
                Ok(ServeResponse::WithPack {
                    acknowledgments: None,
                    shallow_info: None,
                    wanted_refs: Some(vec![WantedRef {
                        id: resolved_oid,
                        path: bstr::BString::from("refs/heads/main"),
                    }]),
                    packfile_uris: None,
                })
            },
            |w| w.write_all(b"PACK-BYTES").map_err(Into::into),
        )
        .expect("serve ok");

        assert!(find_pkt_line_with_payload(&resp, b"wanted-refs\n").is_some());
        assert!(find_pkt_line_with_payload(
            &resp,
            b"4444444444444444444444444444444444444444 refs/heads/main\n"
        )
        .is_some());
        // Order: wanted-refs BEFORE packfile.
        let wanted_pos = find_pkt_line_with_payload(&resp, b"wanted-refs\n").unwrap();
        let packfile_pos = find_pkt_line_with_payload(&resp, b"packfile\n").unwrap();
        assert!(wanted_pos < packfile_pos);
    }

    #[test]
    fn dispatch_v2_fetch_bare_packfile_response() {
        let req = framed_v2_fetch(
            &[b"command=fetch\n"],
            &[b"want 1111111111111111111111111111111111111111\n", b"done\n"],
        );
        let mut resp = Vec::new();
        let outcome = dispatch_v2(
            req.as_slice(),
            &mut resp,
            |_req| panic!("ls-refs not routed"),
            |_request| {
                Ok(ServeResponse::WithPack {
                    acknowledgments: None,
                    shallow_info: None,
                    wanted_refs: None,
                    packfile_uris: None,
                })
            },
            |w| w.write_all(b"PACK-BYTES").map_err(Into::into),
        )
        .expect("dispatch ok");

        match outcome {
            DispatchOutcome::Fetch(so) => assert!(so.pack_sent),
            other => panic!("expected Fetch, got {other:?}"),
        }
        assert!(
            find_pkt_line_with_payload(&resp, b"acknowledgments\n").is_none(),
            "dispatch_v2 bare-packfile must omit acknowledgments too"
        );
    }

    /// sideband-all: when the client negotiated `sideband-all`, every
    /// non-flush/non-delim pkt-line in the response carries a band-1
    /// prefix - including the `wanted-refs` section header that stock
    /// git would otherwise mis-read as band byte 119 ('w') once it
    /// entered sideband demux mode.
    #[test]
    fn serve_v2_wraps_every_section_in_band_1_when_sideband_all() {
        use crate::wire_types::WantedRef;
        let req = framed_v2_fetch(
            &[b"command=fetch\n"],
            &[
                b"want 1111111111111111111111111111111111111111\n",
                b"sideband-all\n",
                b"done\n",
            ],
        );
        let mut resp = Vec::new();
        let _ = serve_v2(
            req.as_slice(),
            &mut resp,
            |request| {
                assert!(request.sideband_all, "request must carry sideband-all");
                Ok(ServeResponse::WithPack {
                    acknowledgments: None,
                    shallow_info: None,
                    wanted_refs: Some(vec![WantedRef {
                        id: oid("4444444444444444444444444444444444444444"),
                        path: bstr::BString::from("refs/heads/main"),
                    }]),
                    packfile_uris: None,
                })
            },
            |w| w.write_all(b"PACK-BYTES").map_err(Into::into),
        )
        .expect("serve ok");

        // Walk the pkt-line stream: every data pkt-line (non-flush,
        // non-delim) must start with byte 0x01.
        assert!(
            every_data_pkt_line_starts_with_band_1(&resp),
            "with sideband-all, every data pkt-line must carry band 1 prefix; got {resp:?}"
        );
        assert!(resp.ends_with(b"0000"), "must end with flush-pkt: {resp:?}");
    }

    /// Check every data pkt-line in `resp` has its first payload byte
    /// equal to 0x01 (band 1). Skip flush-pkt (`0000`) and delim-pkt
    /// (`0001`) as they're unbanded per spec.
    fn every_data_pkt_line_starts_with_band_1(resp: &[u8]) -> bool {
        let mut cursor = 0;
        while cursor + 4 <= resp.len() {
            let len_bytes = &resp[cursor..cursor + 4];
            if len_bytes == b"0000" || len_bytes == b"0001" || len_bytes == b"0002" {
                cursor += 4;
                continue;
            }
            let Some(len) = std::str::from_utf8(len_bytes)
                .ok()
                .and_then(|s| u16::from_str_radix(s, 16).ok())
                .map(usize::from)
            else {
                return false;
            };
            if len < 5 || cursor + len > resp.len() {
                return false;
            }
            if resp[cursor + 4] != 0x01 {
                return false;
            }
            cursor += len;
        }
        true
    }

    #[test]
    fn dispatch_v2_fetch_full_grammar_with_acks_shallow_wanted_and_pack() {
        use crate::wire_types::{ShallowUpdate, WantedRef};
        let req = framed_v2_fetch(
            &[b"command=fetch\n"],
            &[b"want 1111111111111111111111111111111111111111\n", b"done\n"],
        );
        let mut resp = Vec::new();
        let common = oid("2222222222222222222222222222222222222222");
        let shallow_oid = oid("3333333333333333333333333333333333333333");
        let wanted_oid = oid("4444444444444444444444444444444444444444");
        let _ = dispatch_v2(
            req.as_slice(),
            &mut resp,
            |_req| panic!("ls-refs not routed"),
            |_request| {
                Ok(ServeResponse::WithPack {
                    acknowledgments: Some(Acknowledgments::new(vec![common], Some(AckTrailer::Ready))),
                    shallow_info: Some(vec![ShallowUpdate::Unshallow(shallow_oid)]),
                    wanted_refs: Some(vec![WantedRef {
                        id: wanted_oid,
                        path: bstr::BString::from("refs/heads/main"),
                    }]),
                    packfile_uris: None,
                })
            },
            |w| w.write_all(b"PACK-BYTES").map_err(Into::into),
        )
        .expect("dispatch ok");

        // All four sections appear in grammar order, each followed by
        // a delim-pkt, then `packfile`.
        let acks_pos = find_pkt_line_with_payload(&resp, b"acknowledgments\n").unwrap();
        let shallow_pos = find_pkt_line_with_payload(&resp, b"shallow-info\n").unwrap();
        let wanted_pos = find_pkt_line_with_payload(&resp, b"wanted-refs\n").unwrap();
        let packfile_pos = find_pkt_line_with_payload(&resp, b"packfile\n").unwrap();
        assert!(acks_pos < shallow_pos);
        assert!(shallow_pos < wanted_pos);
        assert!(wanted_pos < packfile_pos);
    }

    #[test]
    fn serve_surfaces_wants_to_the_negotiator() {
        let req = framed_v2_fetch(
            &[b"command=fetch\n"],
            &[
                b"want 1111111111111111111111111111111111111111\n",
                b"want 2222222222222222222222222222222222222222\n",
                b"have 3333333333333333333333333333333333333333\n",
                b"done\n",
            ],
        );
        let mut resp = Vec::new();
        let mut wants_seen: Vec<gix_hash::ObjectId> = Vec::new();
        let mut haves_seen: Vec<gix_hash::ObjectId> = Vec::new();
        let _ = serve_v2(
            req.as_slice(),
            &mut resp,
            |request| {
                for w in &request.wants {
                    if let super::super::Want::ByOid(id) = w {
                        wants_seen.push(*id);
                    }
                }
                haves_seen.extend(request.haves.iter().copied());
                Ok(ServeResponse::AcknowledgmentsOnly {
                    common_oids: vec![request.haves[0]],
                })
            },
            |_w| panic!("write_pack should not be invoked for AcknowledgmentsOnly"),
        )
        .expect("serve ok");

        assert_eq!(wants_seen.len(), 2);
        assert_eq!(wants_seen[0], oid("1111111111111111111111111111111111111111"));
        assert_eq!(haves_seen, vec![oid("3333333333333333333333333333333333333333")]);
        assert!(resp
            .windows(b"ACK 3333333333333333333333333333333333333333".len())
            .any(|w| w == b"ACK 3333333333333333333333333333333333333333"));
    }
}
