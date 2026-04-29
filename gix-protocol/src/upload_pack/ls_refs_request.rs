//! Parse the client's v2 `command=ls-refs` request.
//!
//! v2 clients send `ls-refs` to enumerate the server's refs after the
//! capability advertisement. The request has the familiar v2 shape: a
//! capability-style header terminated by a delim-pkt, then a body of
//! feature toggles and `ref-prefix <prefix>` filters, terminated by a
//! flush-pkt.
//!
//! This module mirrors [`super::fetch_request`]: pure-data parser, no
//! transport I/O. The [`LsRefsRequest`] output feeds the serve dispatch
//! that chooses the handler (ls-refs vs fetch) based on the command
//! token. Emission of the ref list (the response) lives in
//! [`super::ls_refs_response`].

use bstr::{BString, ByteSlice};

/// Parsed `command=ls-refs` request body.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct LsRefsRequest {
    /// Raw capability tokens from the header section (minus
    /// `command=ls-refs`). Typically `object-format=<kind>`.
    pub features: Vec<BString>,
    /// Whether the client asked for annotated tag peels
    /// (`peel` body token).
    pub peel: bool,
    /// Whether the client asked for symref targets (`symrefs` body
    /// token).
    pub symrefs: bool,
    /// Whether the client asked to include unborn refs (`unborn`
    /// body token).
    pub unborn: bool,
    /// Ref-name prefixes the server should filter by, collected from
    /// `ref-prefix <prefix>` lines. An empty vector means "no filter"
    /// (emit all refs).
    pub prefixes: Vec<BString>,
    /// Unknown body lines preserved verbatim so the server can decide
    /// whether to reject them.
    pub unknown: Vec<BString>,
}

/// Errors raised while parsing an ls-refs request.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum Error {
    #[error("expected `command=ls-refs` header, got {line:?}")]
    MissingCommand { line: BString },
}

/// Parse a v2 `command=ls-refs` request. See
/// [`super::fetch_request::parse_request`] for the shape of the
/// `Option<&[u8]>` iterator (delim-pkts as `None`).
#[doc(alias = "command=ls-refs")]
pub fn parse_request<'a, I>(lines: I) -> Result<LsRefsRequest, Error>
where
    I: IntoIterator<Item = Option<&'a [u8]>>,
{
    let mut header = Vec::<&[u8]>::new();
    let mut body = Vec::<&[u8]>::new();
    let mut seen_delim = false;
    for payload in lines {
        match payload {
            None => {
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

/// Parse from pre-split header / body sections (e.g. when the caller
/// already demultiplexed the delim-pkt split).
pub fn parse_sections(header: &[&[u8]], body: &[&[u8]]) -> Result<LsRefsRequest, Error> {
    let mut req = LsRefsRequest::default();
    let mut saw_command = false;
    for line in header {
        let trimmed = trim_lf(line).as_bstr();
        if trimmed == "command=ls-refs" {
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
        if trimmed == "peel" {
            req.peel = true;
        } else if trimmed == "symrefs" {
            req.symrefs = true;
        } else if trimmed == "unborn" {
            req.unborn = true;
        } else if let Some(rest) = trimmed.strip_prefix(b"ref-prefix ") {
            if !rest.is_empty() {
                req.prefixes.push(rest.to_owned().into());
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_ls_refs_with_no_body() {
        let header: &[&[u8]] = &[b"command=ls-refs\n"];
        let body: &[&[u8]] = &[];
        let req = parse_sections(header, body).expect("valid");
        assert!(req.features.is_empty());
        assert!(!req.peel);
        assert!(!req.symrefs);
        assert!(!req.unborn);
        assert!(req.prefixes.is_empty());
    }

    #[test]
    fn parse_full_body_feature_tokens_and_prefixes() {
        let header: &[&[u8]] = &[b"command=ls-refs\n", b"object-format=sha1\n"];
        let body: &[&[u8]] = &[
            b"peel\n",
            b"symrefs\n",
            b"unborn\n",
            b"ref-prefix refs/heads/\n",
            b"ref-prefix refs/tags/\n",
        ];
        let req = parse_sections(header, body).expect("valid");
        assert!(req.peel);
        assert!(req.symrefs);
        assert!(req.unborn);
        assert_eq!(
            req.prefixes,
            vec![BString::from("refs/heads/"), BString::from("refs/tags/")],
        );
        assert!(req.features.iter().any(|f| f == "object-format=sha1"));
    }

    #[test]
    fn missing_command_header_errors() {
        let header: &[&[u8]] = &[b"object-format=sha1\n"];
        let body: &[&[u8]] = &[];
        match parse_sections(header, body) {
            Err(Error::MissingCommand { .. }) => (),
            Ok(req) => panic!("expected MissingCommand, got {req:?}"),
        }
    }

    #[test]
    fn unknown_body_lines_are_preserved() {
        let header: &[&[u8]] = &[b"command=ls-refs\n"];
        let body: &[&[u8]] = &[b"peel\n", b"custom-opt\n"];
        let req = parse_sections(header, body).expect("valid");
        assert!(req.peel);
        assert_eq!(req.unknown, vec![BString::from("custom-opt")]);
    }

    #[test]
    fn parse_request_respects_delim_pkt() {
        let lines: &[Option<&[u8]>] = &[
            Some(b"command=ls-refs\n"),
            None, // delim
            Some(b"peel\n"),
            Some(b"ref-prefix refs/\n"),
        ];
        let req = parse_request(lines.iter().copied()).expect("valid");
        assert!(req.peel);
        assert_eq!(req.prefixes, vec![BString::from("refs/")]);
    }
}
