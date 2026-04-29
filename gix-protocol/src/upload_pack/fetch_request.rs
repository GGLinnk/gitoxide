//! Parse the client's v2 `command=fetch` request.
//!
//! A v2 fetch command is a sequence of pkt-lines between two flush-pkts:
//! a leading capability section (`command=fetch`, `object-format=...`,
//! optional feature tokens), then a delimiter, then a body of
//! `want <oid>`, `have <oid>`, and terminator lines like `done`,
//! `no-done`, `thin-pack`, `ofs-delta`, etc.
//!
//! This module ingests already-de-framed pkt-line payloads and returns
//! a typed [`FetchRequest`] describing what the client asked for. No
//! transport I/O is performed; the caller strips pkt-line framing.

use bstr::{BString, ByteSlice};

/// One client-side `want` or `want-ref` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Want {
    /// The client wants an object identified by its OID.
    ByOid(gix_hash::ObjectId),
    /// The client wants the tip of a ref (v2 `ref-in-want` feature).
    ByRef(BString),
}

/// Parsed v2 `command=fetch` request.
///
/// `features` collects every non-`command=` capability token from the
/// header; `wants`, `haves`, and `options` are populated from the body
/// section that follows the v2 `delim-pkt`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FetchRequest {
    /// Raw capability tokens from the header section (minus
    /// `command=fetch`). Includes `object-format=...` and any per-fetch
    /// features the client announced.
    pub features: Vec<BString>,
    /// `want <oid>` / `want-ref <refname>` lines.
    pub wants: Vec<Want>,
    /// `have <oid>` lines.
    pub haves: Vec<gix_hash::ObjectId>,
    /// Whether the client sent `done`.
    pub done: bool,
    /// Whether the client sent `thin-pack`.
    pub thin_pack: bool,
    /// Whether the client sent `ofs-delta`.
    pub ofs_delta: bool,
    /// Whether the client sent `no-progress`.
    pub no_progress: bool,
    /// Whether the client sent `include-tag`.
    pub include_tag: bool,
    /// Whether the client sent `wait-for-done`.
    pub wait_for_done: bool,
    /// Whether the client sent `sideband-all`.
    pub sideband_all: bool,
    /// `filter <spec>` for partial clone, when present.
    pub filter: Option<BString>,
    /// `deepen <depth>` for shallow clones, when present.
    pub deepen: Option<u32>,
    /// `deepen-since <ts>` (unix timestamp) when present.
    pub deepen_since: Option<BString>,
    /// `deepen-not <ref>` boundary refs the client wants to exclude.
    pub deepen_not: Vec<BString>,
    /// Whether the client sent `deepen-relative`.
    pub deepen_relative: bool,
    /// `shallow <oid>` tips announced by the client.
    pub shallow: Vec<gix_hash::ObjectId>,
    /// `packfile-uris <proto1,proto2,...>` — protocols the client is
    /// willing to resolve pack bytes from, when the server advertised
    /// the `packfile-uris` capability.
    pub packfile_uris: Option<BString>,
    /// Unknown lines preserved verbatim in the body section so the
    /// caller can decide whether to accept or reject them.
    pub unknown: Vec<BString>,
}

/// Errors raised while parsing a fetch request.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum Error {
    #[error("expected `command=fetch` header, got {line:?}")]
    MissingCommand { line: BString },
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

/// Parse a v2 `command=fetch` request.
///
/// The input is the ordered pkt-line payloads between the caller's two
/// flush-pkts, with the v2 delimiter (`delim-pkt`) represented as
/// `None` in an `Option<&[u8]>` sentinel so the parser can distinguish
/// the header / body split from a trailing flush.
///
/// For callers that have already split the sections, use
/// [`parse_sections`] instead.
#[doc(alias = "command=fetch")]
pub fn parse_request<'a, I>(lines: I) -> Result<FetchRequest, Error>
where
    I: IntoIterator<Item = Option<&'a [u8]>>,
{
    let mut header = Vec::<&[u8]>::new();
    let mut body = Vec::<&[u8]>::new();
    let mut seen_delim = false;
    for payload in lines {
        match payload {
            None => {
                // delim-pkt separates header from body in v2
                if seen_delim {
                    break;
                }
                seen_delim = true;
            }
            Some(line) if !seen_delim => header.push(line),
            Some(line) => body.push(line),
        }
    }
    parse_sections(&header, &body)
}

/// Parse a v2 fetch request from pre-split header and body sections.
pub fn parse_sections(header: &[&[u8]], body: &[&[u8]]) -> Result<FetchRequest, Error> {
    let mut req = FetchRequest::default();
    let mut saw_command = false;
    for line in header {
        let trimmed = trim_lf(line).as_bstr();
        if trimmed == "command=fetch" {
            saw_command = true;
            continue;
        }
        req.features.push(trimmed.to_owned());
    }
    if !saw_command {
        return Err(Error::MissingCommand {
            line: header.first().map(|l| l.to_vec().into()).unwrap_or_default(),
        });
    }

    for line in body {
        let trimmed = trim_lf(line).as_bstr();
        if let Some(rest) = trimmed.strip_prefix(b"want-ref ") {
            if rest.is_empty() {
                return Err(Error::MalformedWant {
                    line: trimmed.to_owned(),
                });
            }
            req.wants.push(Want::ByRef(rest.to_owned().into()));
        } else if let Some(rest) = trimmed.strip_prefix(b"want ") {
            req.wants.push(Want::ByOid(gix_hash::ObjectId::from_hex(rest)?));
        } else if let Some(rest) = trimmed.strip_prefix(b"have ") {
            req.haves.push(gix_hash::ObjectId::from_hex(rest)?);
        } else if let Some(rest) = trimmed.strip_prefix(b"shallow ") {
            req.shallow.push(gix_hash::ObjectId::from_hex(rest)?);
        } else if let Some(rest) = trimmed.strip_prefix(b"deepen ") {
            req.deepen = Some(
                std::str::from_utf8(rest)
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .ok_or_else(|| Error::MalformedDeepen {
                        line: trimmed.to_owned(),
                    })?,
            );
        } else if let Some(rest) = trimmed.strip_prefix(b"deepen-since ") {
            req.deepen_since = Some(rest.to_owned().into());
        } else if let Some(rest) = trimmed.strip_prefix(b"deepen-not ") {
            req.deepen_not.push(rest.to_owned().into());
        } else if trimmed == "deepen-relative" {
            req.deepen_relative = true;
        } else if let Some(rest) = trimmed.strip_prefix(b"packfile-uris ") {
            req.packfile_uris = Some(rest.to_owned().into());
        } else if let Some(rest) = trimmed.strip_prefix(b"filter ") {
            req.filter = Some(rest.to_owned().into());
        } else if trimmed == "done" {
            req.done = true;
        } else if trimmed == "thin-pack" {
            req.thin_pack = true;
        } else if trimmed == "ofs-delta" {
            req.ofs_delta = true;
        } else if trimmed == "no-progress" {
            req.no_progress = true;
        } else if trimmed == "include-tag" {
            req.include_tag = true;
        } else if trimmed == "wait-for-done" {
            req.wait_for_done = true;
        } else if trimmed == "sideband-all" {
            req.sideband_all = true;
        } else {
            req.unknown.push(trimmed.to_owned());
        }
    }
    Ok(req)
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

    fn oid(hex: &str) -> gix_hash::ObjectId {
        gix_hash::ObjectId::from_hex(hex.as_bytes()).expect("valid hex fixture")
    }

    #[test]
    fn parse_deepen_variants_and_packfile_uris() {
        let header: &[&[u8]] = &[b"command=fetch\n"];
        let body: &[&[u8]] = &[
            b"want 1111111111111111111111111111111111111111\n",
            b"shallow 2222222222222222222222222222222222222222\n",
            b"deepen 1\n",
            b"deepen-since 1700000000\n",
            b"deepen-not refs/tags/v1.0\n",
            b"deepen-not refs/tags/v2.0\n",
            b"deepen-relative\n",
            b"packfile-uris https,http\n",
            b"done\n",
        ];
        let req = parse_sections(header, body).expect("valid");
        assert_eq!(req.deepen, Some(1));
        assert_eq!(
            req.deepen_since.as_ref().map(AsRef::<[u8]>::as_ref),
            Some(&b"1700000000"[..])
        );
        assert_eq!(req.deepen_not.len(), 2);
        assert_eq!(req.deepen_not[0], "refs/tags/v1.0");
        assert_eq!(req.deepen_not[1], "refs/tags/v2.0");
        assert!(req.deepen_relative);
        assert_eq!(
            req.packfile_uris.as_ref().map(AsRef::<[u8]>::as_ref),
            Some(&b"https,http"[..])
        );
        assert_eq!(req.shallow.len(), 1);
        assert!(req.done);
        // None of the parsed keys should leak into `unknown`.
        assert!(req.unknown.is_empty());
    }

    #[test]
    fn parse_minimal_fetch_with_one_want_and_done() {
        let header: &[&[u8]] = &[b"command=fetch\n", b"object-format=sha1\n"];
        let body: &[&[u8]] = &[b"want 1111111111111111111111111111111111111111\n", b"done\n"];
        let req = parse_sections(header, body).expect("valid");
        assert!(req.features.iter().any(|f| f == "object-format=sha1"));
        assert_eq!(
            req.wants,
            vec![Want::ByOid(oid("1111111111111111111111111111111111111111"))],
        );
        assert!(req.done);
        assert!(req.haves.is_empty());
    }

    #[test]
    fn parse_wants_haves_and_feature_tokens() {
        let header: &[&[u8]] = &[b"command=fetch\n"];
        let body: &[&[u8]] = &[
            b"thin-pack\n",
            b"ofs-delta\n",
            b"want 1111111111111111111111111111111111111111\n",
            b"want-ref refs/heads/main\n",
            b"have 2222222222222222222222222222222222222222\n",
            b"filter blob:none\n",
            b"deepen 5\n",
            b"shallow 3333333333333333333333333333333333333333\n",
            b"done\n",
        ];
        let req = parse_sections(header, body).expect("valid");
        assert!(req.thin_pack);
        assert!(req.ofs_delta);
        assert_eq!(req.wants.len(), 2);
        assert_eq!(req.wants[1], Want::ByRef(BString::from("refs/heads/main")),);
        assert_eq!(req.haves, vec![oid("2222222222222222222222222222222222222222")],);
        assert_eq!(req.filter, Some(BString::from("blob:none")));
        assert_eq!(req.deepen, Some(5));
        assert_eq!(req.shallow, vec![oid("3333333333333333333333333333333333333333")],);
        assert!(req.done);
    }

    #[test]
    fn unknown_body_lines_are_preserved() {
        let header: &[&[u8]] = &[b"command=fetch\n"];
        let body: &[&[u8]] = &[b"want 1111111111111111111111111111111111111111\n", b"custom-opt\n"];
        let req = parse_sections(header, body).expect("valid");
        assert_eq!(req.unknown, vec![BString::from("custom-opt")]);
    }

    #[test]
    fn missing_command_header_errors() {
        let header: &[&[u8]] = &[b"object-format=sha1\n"];
        let body: &[&[u8]] = &[];
        match parse_sections(header, body) {
            Err(Error::MissingCommand { .. }) => (),
            other => panic!("expected MissingCommand, got {other:?}"),
        }
    }

    #[test]
    fn malformed_oid_errors() {
        let header: &[&[u8]] = &[b"command=fetch\n"];
        let body: &[&[u8]] = &[b"want not-a-hex-oid\n"];
        match parse_sections(header, body) {
            Err(Error::Hash(_)) => (),
            other => panic!("expected Hash, got {other:?}"),
        }
    }

    #[test]
    fn parse_request_respects_delim_pkt() {
        let lines: &[Option<&[u8]>] = &[
            Some(b"command=fetch\n"),
            Some(b"object-format=sha1\n"),
            None, // delim-pkt
            Some(b"want 1111111111111111111111111111111111111111\n"),
            Some(b"done\n"),
        ];
        let req = parse_request(lines.iter().copied()).expect("valid");
        assert!(req.done);
        assert_eq!(req.wants.len(), 1);
    }
}
