//! Parsers for the `report-status` and `report-status-v2` server responses
//! that follow a push.
//!
//! The input is an ordered sequence of pkt-line payloads *with framing and
//! flush packets already stripped by the transport layer*. The parsers do not
//! perform pkt-line deframing themselves; they take opaque byte lines and
//! interpret them semantically.
//!
//! See the [pack protocol reference][v1] and [protocol v2][v2] for the
//! grammar.
//!
//! [v1]: https://git-scm.com/docs/pack-protocol#_report_status
//! [v2]: https://git-scm.com/docs/protocol-v2#_push

use bstr::{BStr, BString, ByteSlice};

/// Outcome of the pack-unpack phase reported by the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnpackStatus {
    /// The server successfully unpacked the received pack.
    Ok,
    /// The server rejected the pack; the contained message is the reason
    /// verbatim from the wire (no trailing LF).
    Failed(BString),
}

/// Per-ref outcome in a `report-status` (v1) response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandStatus {
    /// The server accepted and applied the ref update.
    Ok {
        /// The fully-qualified ref name the server acknowledged.
        refname: BString,
    },
    /// The server rejected the ref update with the given reason.
    Rejected {
        /// The fully-qualified ref name the server rejected.
        refname: BString,
        /// Reason message verbatim from the wire (no trailing LF).
        reason: BString,
    },
}

/// A parsed `report-status` (v1) response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// Outcome of the unpack phase.
    pub unpack: UnpackStatus,
    /// Per-ref command outcomes, in the order reported by the server.
    pub commands: Vec<CommandStatus>,
}

/// Optional per-command metadata sent only in `report-status-v2`.
///
/// All fields default to `None` / `false` if the server did not send the
/// corresponding option line.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CommandOptions {
    /// Value of the `option refname <new-refname>` line, when sent.
    pub refname: Option<BString>,
    /// Value of the `option old-oid <oid>` line, when sent.
    pub old_oid: Option<gix_hash::ObjectId>,
    /// Value of the `option new-oid <oid>` line, when sent.
    pub new_oid: Option<gix_hash::ObjectId>,
    /// `true` if the server sent `option forced-update`.
    pub forced_update: bool,
}

/// Per-ref outcome in a `report-status-v2` response.
///
/// The `Ok` variant carries optional metadata via [`CommandOptions`]. The
/// `Rejected` variant is identical to [`CommandStatus::Rejected`]: option
/// lines must not follow a rejection per the v2 spec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandStatusV2 {
    /// The server accepted and applied the ref update, possibly with metadata.
    Ok {
        /// The fully-qualified ref name the server acknowledged.
        refname: BString,
        /// Metadata attached via `option` lines. Defaults to empty.
        options: CommandOptions,
    },
    /// The server rejected the ref update with the given reason.
    Rejected {
        /// The fully-qualified ref name the server rejected.
        refname: BString,
        /// Reason message verbatim from the wire (no trailing LF).
        reason: BString,
    },
}

/// A parsed `report-status-v2` response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportV2 {
    /// Outcome of the unpack phase.
    pub unpack: UnpackStatus,
    /// Per-ref command outcomes, in the order reported by the server.
    pub commands: Vec<CommandStatusV2>,
}

/// Errors raised while parsing a push report.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum Error {
    #[error("expected an `unpack` status line, got {line:?}")]
    MalformedUnpack { line: BString },
    #[error("expected an `ok`/`ng` command status line, got {line:?}")]
    MalformedCommand { line: BString },
    #[error("`option` line appeared before any `ok` command: {line:?}")]
    OptionWithoutCommand { line: BString },
    #[error("`option` line appeared after an `ng` (rejected) command: {line:?}")]
    OptionAfterRejection { line: BString },
    #[error("unknown `option` line: {line:?}")]
    UnknownOption { line: BString },
    #[error("report ended before the `unpack` status line was seen")]
    MissingUnpack,
    #[error(transparent)]
    Hash(#[from] gix_hash::decode::Error),
}

/// Parse a `report-status` (v1) response from an ordered sequence of
/// already-de-framed pkt-line payloads.
///
/// The input must be the payload bytes of each non-flush line, one item per
/// line, in the order received. Trailing LF is tolerated and stripped.
#[doc(alias = "report-status")]
pub fn parse_report_v1<I, L>(lines: I) -> Result<Report, Error>
where
    I: IntoIterator<Item = L>,
    L: AsRef<[u8]>,
{
    let mut iter = lines.into_iter();
    let first = iter.next().ok_or(Error::MissingUnpack)?;
    let unpack = parse_unpack(trim_lf(first.as_ref()).as_bstr())?;
    let mut commands = Vec::new();
    for line in iter {
        let trimmed = trim_lf(line.as_ref()).as_bstr();
        commands.push(parse_command_status(trimmed)?);
    }
    Ok(Report { unpack, commands })
}

/// Parse a `report-status-v2` response.
///
/// The input must be the payload bytes of each non-flush line, one item per
/// line, in the order received. Trailing LF is tolerated and stripped.
///
/// `option` lines are attached to the most recently parsed `ok` command per
/// the v2 spec; an `option` line that appears before any command, or after an
/// `ng` command, is rejected.
#[doc(alias = "report-status-v2")]
pub fn parse_report_v2<I, L>(lines: I) -> Result<ReportV2, Error>
where
    I: IntoIterator<Item = L>,
    L: AsRef<[u8]>,
{
    let mut iter = lines.into_iter();
    let first = iter.next().ok_or(Error::MissingUnpack)?;
    let unpack = parse_unpack(trim_lf(first.as_ref()).as_bstr())?;
    let mut commands: Vec<CommandStatusV2> = Vec::new();
    for line in iter {
        let trimmed = trim_lf(line.as_ref()).as_bstr();
        if let Some(rest) = trimmed.strip_prefix(b"option ") {
            let target = commands.last_mut().ok_or_else(|| Error::OptionWithoutCommand {
                line: trimmed.to_owned(),
            })?;
            let options = match target {
                CommandStatusV2::Ok { options, .. } => options,
                CommandStatusV2::Rejected { .. } => {
                    return Err(Error::OptionAfterRejection {
                        line: trimmed.to_owned(),
                    })
                }
            };
            apply_option(options, rest.as_bstr(), trimmed)?;
        } else {
            commands.push(command_status_to_v2(parse_command_status(trimmed)?));
        }
    }
    Ok(ReportV2 { unpack, commands })
}

fn parse_unpack(line: &BStr) -> Result<UnpackStatus, Error> {
    let rest = line
        .strip_prefix(b"unpack ")
        .ok_or_else(|| Error::MalformedUnpack { line: line.to_owned() })?;
    if rest == b"ok" {
        Ok(UnpackStatus::Ok)
    } else if rest.is_empty() {
        Err(Error::MalformedUnpack { line: line.to_owned() })
    } else {
        Ok(UnpackStatus::Failed(rest.to_owned().into()))
    }
}

fn parse_command_status(line: &BStr) -> Result<CommandStatus, Error> {
    if let Some(rest) = line.strip_prefix(b"ok ") {
        if rest.is_empty() {
            return Err(Error::MalformedCommand { line: line.to_owned() });
        }
        Ok(CommandStatus::Ok {
            refname: rest.to_owned().into(),
        })
    } else if let Some(rest) = line.strip_prefix(b"ng ") {
        let sp = rest
            .find_byte(b' ')
            .ok_or_else(|| Error::MalformedCommand { line: line.to_owned() })?;
        let refname = rest[..sp].to_owned();
        let reason = rest[sp + 1..].to_owned();
        if refname.is_empty() || reason.is_empty() {
            return Err(Error::MalformedCommand { line: line.to_owned() });
        }
        Ok(CommandStatus::Rejected {
            refname: refname.into(),
            reason: reason.into(),
        })
    } else {
        Err(Error::MalformedCommand { line: line.to_owned() })
    }
}

fn command_status_to_v2(status: CommandStatus) -> CommandStatusV2 {
    match status {
        CommandStatus::Ok { refname } => CommandStatusV2::Ok {
            refname,
            options: CommandOptions::default(),
        },
        CommandStatus::Rejected { refname, reason } => CommandStatusV2::Rejected { refname, reason },
    }
}

fn apply_option(options: &mut CommandOptions, rest: &BStr, full_line: &BStr) -> Result<(), Error> {
    if let Some(value) = rest.strip_prefix(b"refname ") {
        if value.is_empty() {
            return Err(Error::UnknownOption {
                line: full_line.to_owned(),
            });
        }
        options.refname = Some(value.to_owned().into());
    } else if let Some(value) = rest.strip_prefix(b"old-oid ") {
        options.old_oid = Some(gix_hash::ObjectId::from_hex(value)?);
    } else if let Some(value) = rest.strip_prefix(b"new-oid ") {
        options.new_oid = Some(gix_hash::ObjectId::from_hex(value)?);
    } else if rest == b"forced-update" {
        options.forced_update = true;
    } else {
        return Err(Error::UnknownOption {
            line: full_line.to_owned(),
        });
    }
    Ok(())
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

    // ---- v1 -----------------------------------------------------------------

    #[test]
    fn v1_unpack_ok_single_command() {
        let lines: &[&[u8]] = &[b"unpack ok\n", b"ok refs/heads/main\n"];
        let report = parse_report_v1(lines.iter().copied()).expect("valid report");
        assert_eq!(report.unpack, UnpackStatus::Ok);
        assert_eq!(
            report.commands,
            vec![CommandStatus::Ok {
                refname: "refs/heads/main".into(),
            }],
        );
    }

    #[test]
    fn v1_unpack_failure_carries_verbatim_reason() {
        let lines: &[&[u8]] = &[b"unpack missing object abc\n"];
        let report = parse_report_v1(lines.iter().copied()).expect("valid report");
        assert_eq!(report.unpack, UnpackStatus::Failed("missing object abc".into()));
        assert!(report.commands.is_empty());
    }

    #[test]
    fn v1_rejection_carries_reason() {
        let lines: &[&[u8]] = &[b"unpack ok\n", b"ng refs/heads/other pre-receive hook declined\n"];
        let report = parse_report_v1(lines.iter().copied()).expect("valid report");
        assert_eq!(
            report.commands,
            vec![CommandStatus::Rejected {
                refname: "refs/heads/other".into(),
                reason: "pre-receive hook declined".into(),
            }],
        );
    }

    #[test]
    fn v1_tolerates_missing_trailing_lf() {
        let lines: &[&[u8]] = &[b"unpack ok", b"ok refs/heads/main"];
        let report = parse_report_v1(lines.iter().copied()).expect("valid report");
        assert_eq!(report.unpack, UnpackStatus::Ok);
        assert_eq!(
            report.commands,
            vec![CommandStatus::Ok {
                refname: "refs/heads/main".into(),
            }],
        );
    }

    #[test]
    fn v1_missing_unpack_errors() {
        let empty: &[&[u8]] = &[];
        match parse_report_v1(empty.iter().copied()) {
            Err(Error::MissingUnpack) => (),
            other => panic!("expected MissingUnpack, got {other:?}"),
        }
    }

    #[test]
    fn v1_malformed_unpack_errors() {
        let lines: &[&[u8]] = &[b"not-unpack ok\n"];
        match parse_report_v1(lines.iter().copied()) {
            Err(Error::MalformedUnpack { .. }) => (),
            other => panic!("expected MalformedUnpack, got {other:?}"),
        }
    }

    #[test]
    fn v1_unknown_command_verb_errors() {
        let lines: &[&[u8]] = &[b"unpack ok\n", b"maybe refs/heads/main\n"];
        match parse_report_v1(lines.iter().copied()) {
            Err(Error::MalformedCommand { .. }) => (),
            other => panic!("expected MalformedCommand, got {other:?}"),
        }
    }

    #[test]
    fn v1_empty_ok_refname_errors() {
        let lines: &[&[u8]] = &[b"unpack ok\n", b"ok \n"];
        match parse_report_v1(lines.iter().copied()) {
            Err(Error::MalformedCommand { .. }) => (),
            other => panic!("expected MalformedCommand, got {other:?}"),
        }
    }

    // ---- v2 -----------------------------------------------------------------

    #[test]
    fn v2_accepts_option_lines_for_preceding_ok_command() {
        let lines: &[&[u8]] = &[
            b"unpack ok\n",
            b"ok refs/heads/main\n",
            b"option refname refs/heads/renamed\n",
            b"option old-oid 1111111111111111111111111111111111111111\n",
            b"option new-oid 2222222222222222222222222222222222222222\n",
            b"option forced-update\n",
            b"ng refs/heads/other non-fast-forward\n",
        ];
        let report = parse_report_v2(lines.iter().copied()).expect("valid v2 report");
        assert_eq!(report.unpack, UnpackStatus::Ok);
        assert_eq!(report.commands.len(), 2);
        match &report.commands[0] {
            CommandStatusV2::Ok { refname, options } => {
                assert_eq!(refname, "refs/heads/main");
                assert_eq!(options.refname, Some(BString::from("refs/heads/renamed")));
                assert_eq!(options.old_oid, Some(oid("1111111111111111111111111111111111111111")),);
                assert_eq!(options.new_oid, Some(oid("2222222222222222222222222222222222222222")),);
                assert!(options.forced_update);
            }
            other => panic!("expected Ok, got {other:?}"),
        }
        match &report.commands[1] {
            CommandStatusV2::Rejected { refname, reason } => {
                assert_eq!(refname, "refs/heads/other");
                assert_eq!(reason, "non-fast-forward");
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    #[test]
    fn v2_option_before_any_command_errors() {
        let lines: &[&[u8]] = &[b"unpack ok\n", b"option forced-update\n"];
        match parse_report_v2(lines.iter().copied()) {
            Err(Error::OptionWithoutCommand { .. }) => (),
            other => panic!("expected OptionWithoutCommand, got {other:?}"),
        }
    }

    #[test]
    fn v2_option_after_rejection_errors() {
        let lines: &[&[u8]] = &[
            b"unpack ok\n",
            b"ng refs/heads/main fast-forward\n",
            b"option forced-update\n",
        ];
        match parse_report_v2(lines.iter().copied()) {
            Err(Error::OptionAfterRejection { .. }) => (),
            other => panic!("expected OptionAfterRejection, got {other:?}"),
        }
    }

    #[test]
    fn v2_unknown_option_errors() {
        let lines: &[&[u8]] = &[
            b"unpack ok\n",
            b"ok refs/heads/main\n",
            b"option something-weird value\n",
        ];
        match parse_report_v2(lines.iter().copied()) {
            Err(Error::UnknownOption { .. }) => (),
            other => panic!("expected UnknownOption, got {other:?}"),
        }
    }

    #[test]
    fn v2_invalid_oid_in_option_errors() {
        let lines: &[&[u8]] = &[
            b"unpack ok\n",
            b"ok refs/heads/main\n",
            b"option old-oid not-a-hex-oid\n",
        ];
        match parse_report_v2(lines.iter().copied()) {
            Err(Error::Hash(_)) => (),
            other => panic!("expected Hash error, got {other:?}"),
        }
    }
}
