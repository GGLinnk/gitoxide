//! Parse a v0/v1 `git-upload-pack` upload-request.
//!
//! The v0/v1 wire format (prescribed by `Documentation/gitprotocol-pack.txt`) is:
//!
//! ```text
//! upload-request  =  want-list [shallow-list | depth-request | filter-request] flush-pkt
//!                    haves
//! want-list       =  first-want *additional-want
//! first-want      =  PKT-LINE("want" SP obj-id SP capability-list)
//! additional-want =  PKT-LINE("want" SP obj-id)
//! have            =  PKT-LINE("have" SP obj-id)
//! done            =  PKT-LINE("done")
//! ```
//!
//! This parser targets the stateless-RPC shape used over smart-HTTP: the
//! client sends the entire want-list plus have-list plus `done` in a single
//! request, and the server replies once. Stateful git:// / SSH sessions use
//! the same grammar but interleave ACK/NAK responses; `serve_v1` drives
//! only the stateless-RPC variant.

use bstr::{BString, ByteSlice};

/// Parsed v0/v1 upload-request.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FetchRequestV1 {
    /// Capability tokens advertised by the client on the first `want` line
    /// (after the OID).
    pub capabilities: Vec<BString>,
    /// `want <oid>` lines, in order.
    pub wants: Vec<gix_hash::ObjectId>,
    /// `have <oid>` lines, in order.
    pub haves: Vec<gix_hash::ObjectId>,
    /// `shallow <oid>` lines the client announced.
    pub shallow: Vec<gix_hash::ObjectId>,
    /// `deepen <n>` directive, if present.
    pub deepen: Option<u32>,
    /// `deepen-since <ts>` directive (unix timestamp), if present.
    pub deepen_since: Option<BString>,
    /// `deepen-not <ref>` directives — collected in order. The spec
    /// grammar permits repetition, so all refs are retained; a single
    /// value is the common case but never enforced.
    pub deepen_not: Vec<BString>,
    /// Whether the client sent `deepen-relative`.
    pub deepen_relative: bool,
    /// `filter <spec>` for partial clone, if present.
    pub filter: Option<BString>,
    /// Whether the client sent `done` to close the request.
    pub done: bool,
    /// Unknown lines preserved verbatim so the caller can decide what to
    /// reject.
    pub unknown: Vec<BString>,
}

/// Errors raised while parsing a v0/v1 upload-request.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum Error {
    #[error("expected `want <oid>` as the first line, got {line:?}")]
    MissingFirstWant { line: BString },
    #[error("malformed `want` line: {line:?}")]
    MalformedWant { line: BString },
    #[error("malformed `have` line: {line:?}")]
    MalformedHave { line: BString },
    #[error("malformed `shallow` line: {line:?}")]
    MalformedShallow { line: BString },
    #[error("malformed `deepen` line: {line:?}")]
    MalformedDeepen { line: BString },
    #[error(transparent)]
    Hash(#[from] gix_hash::decode::Error),
}

/// Parse a v0/v1 upload-request from its already-deframed pkt-line payloads.
///
/// Input is a sequence of `Option<&[u8]>` where `None` marks a flush-pkt.
/// The request starts with the want-list, a flush-pkt, then the have-list
/// terminated by `done`. Only the stateless-RPC variant is supported.
#[doc(alias = "upload-request")]
pub fn parse_request<'a, I>(lines: I) -> Result<FetchRequestV1, Error>
where
    I: IntoIterator<Item = Option<&'a [u8]>>,
{
    let mut req = FetchRequestV1::default();
    let mut seen_first_want = false;
    let mut in_haves = false;
    for payload in lines {
        match payload {
            None => {
                // Flush between want-list / shallow directives and haves.
                if !in_haves {
                    in_haves = true;
                }
                continue;
            }
            Some(line) => {
                let line = line.trim_end_with(|c| c == '\n');
                if !in_haves {
                    if let Some(rest) = line.strip_prefix(b"want ") {
                        let (oid_bytes, caps) = match rest.iter().position(|b| *b == b' ') {
                            Some(idx) => (&rest[..idx], Some(&rest[idx + 1..])),
                            None => (rest, None),
                        };
                        if oid_bytes.is_empty() {
                            return Err(Error::MalformedWant { line: line.into() });
                        }
                        let oid = gix_hash::ObjectId::from_hex(oid_bytes)?;
                        req.wants.push(oid);
                        if !seen_first_want {
                            seen_first_want = true;
                            if let Some(caps) = caps {
                                for tok in caps.split(|b| *b == b' ').filter(|s| !s.is_empty()) {
                                    req.capabilities.push(tok.into());
                                }
                            }
                        } else if caps.is_some() {
                            // Additional wants must not carry capabilities.
                            return Err(Error::MalformedWant { line: line.into() });
                        }
                    } else if let Some(rest) = line.strip_prefix(b"shallow ") {
                        let oid = gix_hash::ObjectId::from_hex(rest)
                            .map_err(|_| Error::MalformedShallow { line: line.into() })?;
                        req.shallow.push(oid);
                    } else if let Some(rest) = line.strip_prefix(b"deepen ") {
                        let depth: u32 = std::str::from_utf8(rest)
                            .ok()
                            .and_then(|s| s.parse().ok())
                            .ok_or_else(|| Error::MalformedDeepen { line: line.into() })?;
                        req.deepen = Some(depth);
                    } else if let Some(rest) = line.strip_prefix(b"deepen-since ") {
                        req.deepen_since = Some(rest.into());
                    } else if let Some(rest) = line.strip_prefix(b"deepen-not ") {
                        req.deepen_not.push(rest.into());
                    } else if line == b"deepen-relative" {
                        req.deepen_relative = true;
                    } else if let Some(rest) = line.strip_prefix(b"filter ") {
                        req.filter = Some(rest.into());
                    } else if line.is_empty() {
                        // Tolerate blank lines.
                    } else {
                        req.unknown.push(line.into());
                    }
                    if !seen_first_want && line.starts_with(b"want ") {
                        // Already handled above; noop.
                    }
                } else if let Some(rest) = line.strip_prefix(b"have ") {
                    let oid =
                        gix_hash::ObjectId::from_hex(rest).map_err(|_| Error::MalformedHave { line: line.into() })?;
                    req.haves.push(oid);
                } else if line == b"done" {
                    req.done = true;
                } else if line.is_empty() {
                    // tolerate
                } else {
                    req.unknown.push(line.into());
                }
            }
        }
    }
    if !seen_first_want {
        return Err(Error::MissingFirstWant {
            line: BString::default(),
        });
    }
    Ok(req)
}

#[cfg(all(test, feature = "sha1"))]
mod tests {
    use super::*;

    fn oid(hex: &str) -> gix_hash::ObjectId {
        gix_hash::ObjectId::from_hex(hex.as_bytes()).expect("valid hex fixture")
    }

    #[test]
    fn parse_clone_without_haves() {
        let want = b"want 1111111111111111111111111111111111111111 multi_ack side-band-64k ofs-delta\n";
        let lines: Vec<Option<&[u8]>> = vec![Some(want), None, Some(b"done\n")];
        let req = parse_request(lines).expect("valid request");
        assert_eq!(req.wants, vec![oid("1111111111111111111111111111111111111111")]);
        assert_eq!(
            req.capabilities,
            vec![
                BString::from("multi_ack"),
                BString::from("side-band-64k"),
                BString::from("ofs-delta")
            ]
        );
        assert!(req.haves.is_empty());
        assert!(req.done);
    }

    #[test]
    fn parse_fetch_with_haves_and_done() {
        let first_want = b"want 1111111111111111111111111111111111111111 multi_ack\n";
        let second_want = b"want 2222222222222222222222222222222222222222\n";
        let have = b"have 3333333333333333333333333333333333333333\n";
        let lines: Vec<Option<&[u8]>> = vec![Some(first_want), Some(second_want), None, Some(have), Some(b"done\n")];
        let req = parse_request(lines).expect("valid request");
        assert_eq!(req.wants.len(), 2);
        assert_eq!(req.haves, vec![oid("3333333333333333333333333333333333333333")]);
        assert!(req.done);
    }

    #[test]
    fn capabilities_only_on_first_want() {
        let first_want = b"want 1111111111111111111111111111111111111111 multi_ack\n";
        let second_want_with_caps = b"want 2222222222222222222222222222222222222222 side-band\n";
        let lines: Vec<Option<&[u8]>> = vec![Some(first_want), Some(second_want_with_caps), None];
        match parse_request(lines) {
            Err(Error::MalformedWant { .. }) => (),
            other => panic!("expected MalformedWant, got {other:?}"),
        }
    }

    #[test]
    fn missing_first_want_is_an_error() {
        let lines: Vec<Option<&[u8]>> = vec![None, Some(b"done\n")];
        match parse_request(lines) {
            Err(Error::MissingFirstWant { .. }) => (),
            other => panic!("expected MissingFirstWant, got {other:?}"),
        }
    }

    /// `gitprotocol-pack`'s `depth-request` grammar allows `deepen-not`
    /// to repeat. Collect every ref instead of silently keeping only
    /// the last one, matching the v2 parser shape in `fetch_request.rs`.
    #[test]
    fn deepen_not_collects_multiple_values_in_order() {
        let want = b"want 1111111111111111111111111111111111111111 multi_ack\n";
        let lines: Vec<Option<&[u8]>> = vec![
            Some(want),
            Some(b"deepen-not refs/tags/v1.0\n"),
            Some(b"deepen-not refs/tags/v2.0\n"),
            None,
            Some(b"done\n"),
        ];
        let req = parse_request(lines).expect("valid request");
        assert_eq!(
            req.deepen_not,
            vec![BString::from("refs/tags/v1.0"), BString::from("refs/tags/v2.0"),]
        );
    }
}
