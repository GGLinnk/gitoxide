//! Parse the client's update-request block.
//!
//! The client sends one or more pkt-lines of the form
//!
//! ```text
//! <old-oid> SP <new-oid> SP <refname> [NUL capability-list] LF
//! ```
//!
//! terminated by a flush-pkt. This module consumes already-de-framed
//! pkt-line payloads and returns a [`ParsedRequest`] containing the ref
//! updates and the set of capabilities the client requested.

use bstr::{BStr, BString, ByteSlice};

use crate::push::Command;

/// Capabilities the client has requested on the first command line.
///
/// The server is free to ignore any capability it does not support; this
/// type simply surfaces what the client asked for so the serve loop can
/// decide how to respond (side-band framing, v2 report, etc.).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RequestedCapabilities {
    /// Raw capability tokens as sent by the client, in order.
    pub raw: Vec<BString>,
}

impl RequestedCapabilities {
    /// Return true if the client requested the given capability (exact
    /// match, case-sensitive).
    pub fn has(&self, name: &str) -> bool {
        self.raw.iter().any(|c| c == name)
    }

    /// Return the first value of a keyed capability (e.g. `agent=<value>`),
    /// if present.
    pub fn value_of(&self, name: &str) -> Option<&BStr> {
        let prefix = format!("{name}=");
        for entry in &self.raw {
            if let Some(rest) = entry.strip_prefix(prefix.as_bytes()) {
                return Some(rest.as_bstr());
            }
        }
        None
    }
}

/// Outcome of [`parse_request`]: the client's ref-update [`Command`]s
/// and the capabilities attached to the first line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedRequest {
    /// Ref-update commands, in send order.
    pub commands: Vec<Command>,
    /// Capabilities requested by the client.
    pub capabilities: RequestedCapabilities,
    /// `shallow <oid>` lines the client announced before (or interleaved
    /// with) the command list. Matches the behaviour of
    /// `git-receive-pack` which accepts a shallow-tip snapshot alongside
    /// the command-list so the server knows the client's effective
    /// history boundary. The list is preserved verbatim; the built-in
    /// `serve_pack_receive` path does not act on shallow tips today but
    /// accepting them keeps a shallow-aware client unblocked.
    pub shallow: Vec<gix_hash::ObjectId>,
    /// Raw `push-cert` block when the client signed its push. The
    /// payload is every payload byte between the `push-cert\0<caps>\n`
    /// opener and the `push-cert-end\n` terminator, preserved verbatim
    /// so an embedder can pipe it through a signature verifier of
    /// their choice. The built-in `serve_pack_receive` does not verify
    /// the cert; it only surfaces it.
    pub push_cert: Option<BString>,
}

/// Errors raised while parsing a client update-request.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum Error {
    #[error("empty update-request (no command lines before flush-pkt)")]
    Empty,
    #[error("command line is malformed: {line:?}")]
    MalformedCommand { line: BString },
    #[error("expected a capability list after NUL on the first command line, got {line:?}")]
    MissingCapabilities { line: BString },
    #[error("push-cert block not terminated by `push-cert-end`")]
    MissingPushCertEnd,
    #[error("command {refname:?} has both zero old-oid and zero new-oid — neither create nor delete")]
    ZeroZeroCommand { refname: BString },
    #[error(transparent)]
    Hash(#[from] gix_hash::decode::Error),
}

/// Parse an ordered sequence of already-de-framed pkt-line payloads as a
/// client update-request.
///
/// The caller is responsible for the pkt-line framing: strip flush-pkts
/// and pass only the payload bytes of each command line. Trailing LF on
/// each payload is tolerated and stripped.
#[doc(alias = "update-request")]
pub fn parse_request<I, L>(lines: I) -> Result<ParsedRequest, Error>
where
    I: IntoIterator<Item = L>,
    L: AsRef<[u8]>,
{
    let mut iter = lines.into_iter();
    let mut shallow = Vec::new();
    let mut push_cert: Option<BString> = None;
    // Git's receive-pack accepts shallow lines before the command list,
    // so drain them off the head of the iterator first and then treat
    // the first non-shallow payload as the capabilities carrier.
    let first_non_shallow = loop {
        let payload = iter.next().ok_or(Error::Empty)?;
        let trimmed = trim_lf(payload.as_ref());
        match trimmed.strip_prefix(b"shallow ") {
            Some(oid) => shallow.push(gix_hash::ObjectId::from_hex(oid)?),
            None => break trimmed.to_owned(),
        }
    };

    // Detect a signed push. git-send-pack emits `push-cert\0<caps>`
    // as the first line carrying the capability list, followed by
    // cert body + PGP signature, terminated by `push-cert-end`. Then
    // the normal command lines begin. See send-pack.c:398-404.
    let (first_command_line, caps) = if let Some(caps_bytes) = detect_push_cert_header(&first_non_shallow) {
        let caps = parse_capabilities_bytes(caps_bytes.as_bstr());
        let mut cert_body: BString = first_non_shallow.clone().into();
        cert_body.push(b'\n');
        let mut found_end = false;
        let mut first_command_line: Option<BString> = None;
        for line in iter.by_ref() {
            let trimmed = trim_lf(line.as_ref());
            if trimmed == b"push-cert-end" {
                cert_body.extend_from_slice(b"push-cert-end\n");
                found_end = true;
                break;
            }
            if !found_end {
                cert_body.extend_from_slice(trimmed);
                cert_body.push(b'\n');
            }
        }
        if !found_end {
            return Err(Error::MissingPushCertEnd);
        }
        // The first real command line is the next payload after the
        // cert terminator. Additional shallow lines may still be
        // interleaved here too.
        for line in iter.by_ref() {
            let trimmed = trim_lf(line.as_ref());
            if let Some(oid) = trimmed.strip_prefix(b"shallow ") {
                shallow.push(gix_hash::ObjectId::from_hex(oid)?);
                continue;
            }
            first_command_line = Some(trimmed.to_owned().into());
            break;
        }
        push_cert = Some(cert_body);
        (first_command_line, caps)
    } else {
        let (first_command, caps) = parse_first_line(first_non_shallow.as_bstr())?;
        let mut commands = Vec::with_capacity(4);
        commands.push(first_command);
        for line in iter {
            let trimmed = trim_lf(line.as_ref());
            if let Some(oid) = trimmed.strip_prefix(b"shallow ") {
                shallow.push(gix_hash::ObjectId::from_hex(oid)?);
                continue;
            }
            commands.push(parse_plain_line(trimmed.as_bstr())?);
        }
        return Ok(ParsedRequest {
            commands,
            capabilities: caps,
            shallow,
            push_cert,
        });
    };

    let mut commands = Vec::with_capacity(4);
    if let Some(first) = first_command_line {
        commands.push(parse_plain_line(first.as_bstr())?);
    }
    for line in iter {
        let trimmed = trim_lf(line.as_ref());
        if let Some(oid) = trimmed.strip_prefix(b"shallow ") {
            shallow.push(gix_hash::ObjectId::from_hex(oid)?);
            continue;
        }
        commands.push(parse_plain_line(trimmed.as_bstr())?);
    }

    Ok(ParsedRequest {
        commands,
        capabilities: caps,
        shallow,
        push_cert,
    })
}

/// Return the capability bytes when `line` is a `push-cert\0<caps>`
/// header, else `None`. Used to branch the parser onto the signed-push
/// path before attempting to read `<oid> <oid> <refname>`.
fn detect_push_cert_header(line: &[u8]) -> Option<&[u8]> {
    let nul = line.iter().position(|b| *b == 0)?;
    if &line[..nul] == b"push-cert" {
        Some(&line[nul + 1..])
    } else {
        None
    }
}

fn parse_capabilities_bytes(caps_bytes: &BStr) -> RequestedCapabilities {
    let raw: Vec<BString> = if caps_bytes.is_empty() {
        Vec::new()
    } else {
        caps_bytes.split(|b| *b == b' ').map(|s| s.to_owned().into()).collect()
    };
    RequestedCapabilities { raw }
}

fn parse_first_line(line: &BStr) -> Result<(Command, RequestedCapabilities), Error> {
    let nul_pos = line
        .find_byte(0)
        .ok_or_else(|| Error::MissingCapabilities { line: line.to_owned() })?;
    let head = &line[..nul_pos];
    let caps_bytes = &line[nul_pos + 1..];

    let command = parse_plain_line(head.as_bstr())?;

    let raw: Vec<BString> = if caps_bytes.is_empty() {
        Vec::new()
    } else {
        caps_bytes.split(|b| *b == b' ').map(|s| s.to_owned().into()).collect()
    };

    Ok((command, RequestedCapabilities { raw }))
}

fn parse_plain_line(line: &BStr) -> Result<Command, Error> {
    let mut parts = line.splitn(3, |b| *b == b' ');
    let old = parts
        .next()
        .ok_or_else(|| Error::MalformedCommand { line: line.to_owned() })?;
    let new = parts
        .next()
        .ok_or_else(|| Error::MalformedCommand { line: line.to_owned() })?;
    let name = parts
        .next()
        .ok_or_else(|| Error::MalformedCommand { line: line.to_owned() })?;
    if name.is_empty() {
        return Err(Error::MalformedCommand { line: line.to_owned() });
    }
    let old_id = gix_hash::ObjectId::from_hex(old)?;
    let new_id = gix_hash::ObjectId::from_hex(new)?;
    // zero/zero command is semantically a no-op — neither create nor
    // delete nor update. Upstream `receive-pack` rejects it; we match.
    if old_id.is_null() && new_id.is_null() {
        return Err(Error::ZeroZeroCommand {
            refname: name.to_owned().into(),
        });
    }
    Ok(Command {
        old_id,
        new_id,
        refname: name.to_owned().into(),
    })
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
    fn single_update_with_capabilities() {
        let line = b"1111111111111111111111111111111111111111 2222222222222222222222222222222222222222 refs/heads/main\0report-status side-band-64k\n";
        let lines: &[&[u8]] = &[line];
        let parsed = parse_request(lines.iter().copied()).expect("valid");
        assert_eq!(parsed.commands.len(), 1);
        assert_eq!(parsed.commands[0].refname, "refs/heads/main");
        assert_eq!(
            parsed.commands[0].old_id,
            oid("1111111111111111111111111111111111111111")
        );
        assert_eq!(
            parsed.commands[0].new_id,
            oid("2222222222222222222222222222222222222222")
        );
        assert!(parsed.capabilities.has("report-status"));
        assert!(parsed.capabilities.has("side-band-64k"));
        assert!(!parsed.capabilities.has("atomic"));
    }

    #[test]
    fn push_cert_block_is_consumed_and_surfaced_raw() {
        let lines: &[&[u8]] = &[
            b"push-cert\0report-status atomic\n",
            b"certificate version 0.1\n",
            b"pusher Test <test@example.com> 1700000000 +0000\n",
            b"pushee git://example.com/repo\n",
            b"nonce deadbeef\n",
            b"\n",
            b"1111111111111111111111111111111111111111 2222222222222222222222222222222222222222 refs/heads/main\n",
            b"\n",
            b"-----BEGIN PGP SIGNATURE-----\n",
            b"fake-signature\n",
            b"-----END PGP SIGNATURE-----\n",
            b"push-cert-end\n",
            b"1111111111111111111111111111111111111111 2222222222222222222222222222222222222222 refs/heads/main\n",
        ];
        let parsed = parse_request(lines.iter().copied()).expect("valid");
        assert_eq!(parsed.commands.len(), 1);
        assert_eq!(parsed.commands[0].refname, "refs/heads/main");
        assert!(parsed.capabilities.has("report-status"));
        assert!(parsed.capabilities.has("atomic"));
        let cert = parsed.push_cert.expect("cert surfaced");
        assert!(cert.starts_with(b"push-cert\0report-status atomic\n"));
        assert!(cert
            .windows(b"certificate version 0.1".len())
            .any(|w| w == b"certificate version 0.1"));
        assert!(cert.ends_with(b"push-cert-end\n"));
    }

    #[test]
    fn push_cert_missing_terminator_is_rejected() {
        let lines: &[&[u8]] = &[
            b"push-cert\0report-status\n",
            b"certificate version 0.1\n",
            b"nonce deadbeef\n",
            // no push-cert-end
        ];
        match parse_request(lines.iter().copied()) {
            Err(Error::MissingPushCertEnd) => {}
            other => panic!("expected MissingPushCertEnd, got {other:?}"),
        }
    }

    #[test]
    fn shallow_lines_are_accepted_before_and_between_commands() {
        let lines: &[&[u8]] = &[
            b"shallow aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
            b"1111111111111111111111111111111111111111 2222222222222222222222222222222222222222 refs/heads/main\0report-status\n",
            b"shallow bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n",
            b"3333333333333333333333333333333333333333 4444444444444444444444444444444444444444 refs/heads/feature\n",
        ];
        let parsed = parse_request(lines.iter().copied()).expect("valid");
        assert_eq!(parsed.commands.len(), 2);
        assert_eq!(parsed.shallow.len(), 2);
        assert_eq!(parsed.shallow[0], oid("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
        assert_eq!(parsed.shallow[1], oid("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"));
        assert!(parsed.capabilities.has("report-status"));
    }

    #[test]
    fn multiple_commands_only_first_has_capabilities() {
        let lines: &[&[u8]] = &[
            b"1111111111111111111111111111111111111111 2222222222222222222222222222222222222222 refs/heads/main\0report-status\n",
            b"3333333333333333333333333333333333333333 4444444444444444444444444444444444444444 refs/heads/feature\n",
        ];
        let parsed = parse_request(lines.iter().copied()).expect("valid");
        assert_eq!(parsed.commands.len(), 2);
        assert_eq!(parsed.commands[1].refname, "refs/heads/feature");
    }

    #[test]
    fn empty_input_errors() {
        let empty: &[&[u8]] = &[];
        match parse_request(empty.iter().copied()) {
            Err(Error::Empty) => (),
            other => panic!("expected Empty, got {other:?}"),
        }
    }

    #[test]
    fn missing_capabilities_nul_errors() {
        let lines: &[&[u8]] =
            &[b"1111111111111111111111111111111111111111 2222222222222222222222222222222222222222 refs/heads/main\n"];
        match parse_request(lines.iter().copied()) {
            Err(Error::MissingCapabilities { .. }) => (),
            other => panic!("expected MissingCapabilities, got {other:?}"),
        }
    }

    #[test]
    fn malformed_subsequent_line_errors() {
        let lines: &[&[u8]] = &[
            b"1111111111111111111111111111111111111111 2222222222222222222222222222222222222222 refs/heads/main\0report-status\n",
            b"not a real line\n",
        ];
        match parse_request(lines.iter().copied()) {
            Err(Error::Hash(_) | Error::MalformedCommand { .. }) => (),
            other => panic!("expected Hash or MalformedCommand, got {other:?}"),
        }
    }

    #[test]
    fn value_of_agent_capability() {
        let lines: &[&[u8]] = &[
            b"1111111111111111111111111111111111111111 2222222222222222222222222222222222222222 refs/heads/main\0report-status agent=git/2.42\n",
        ];
        let parsed = parse_request(lines.iter().copied()).expect("valid");
        assert_eq!(parsed.capabilities.value_of("agent"), Some(b"git/2.42".as_bstr()));
    }

    /// Both-zero-OID commands are semantically nonsensical (neither a
    /// create, delete, nor update) and rejected by upstream
    /// `receive-pack`. The parser must surface a typed error instead of
    /// handing a no-op command to the serve loop.
    #[test]
    fn both_zero_oid_command_is_rejected() {
        let lines: &[&[u8]] = &[
            b"0000000000000000000000000000000000000000 0000000000000000000000000000000000000000 refs/heads/ghost\0report-status\n",
        ];
        match parse_request(lines.iter().copied()) {
            Err(Error::ZeroZeroCommand { refname }) => assert_eq!(refname, "refs/heads/ghost"),
            other => panic!("expected ZeroZeroCommand, got {other:?}"),
        }
    }

    /// Zero/zero on a subsequent (non-first) command line is caught in
    /// the same branch — `parse_first_line` delegates to
    /// `parse_plain_line`, so a single check covers both shapes.
    #[test]
    fn both_zero_oid_on_subsequent_line_is_rejected() {
        let lines: &[&[u8]] = &[
            b"1111111111111111111111111111111111111111 2222222222222222222222222222222222222222 refs/heads/main\0report-status\n",
            b"0000000000000000000000000000000000000000 0000000000000000000000000000000000000000 refs/heads/ghost\n",
        ];
        match parse_request(lines.iter().copied()) {
            Err(Error::ZeroZeroCommand { refname }) => assert_eq!(refname, "refs/heads/ghost"),
            other => panic!("expected ZeroZeroCommand, got {other:?}"),
        }
    }
}
