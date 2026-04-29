//! Emit the server's `report-status` / `report-status-v2` response.
//!
//! Both emitters produce a sequence of LF-terminated byte payloads that
//! the transport wraps in pkt-lines and terminates with a flush-pkt:
//!
//! ```text
//! unpack ok|<err> LF
//! ok <refname> LF          (per accepted command)
//! ng <refname> <reason> LF (per rejected command)
//! flush-pkt
//! ```
//!
//! The v2 variant additionally supports `option refname|old-oid|new-oid|
//! forced-update` annotations following each `ok` command.

use bstr::{BString, ByteVec};

use crate::push::{CommandOptions, CommandStatus, CommandStatusV2, Report, ReportV2, UnpackStatus};

/// Emit a v1 `report-status` response as ordered pkt-line payloads.
///
/// Returns a vector of LF-terminated byte payloads (without pkt-line
/// framing).
#[doc(alias = "report-status")]
pub fn emit_v1(report: &Report) -> Vec<BString> {
    let mut lines = Vec::with_capacity(1 + report.commands.len());
    lines.push(unpack_line(&report.unpack));
    for status in &report.commands {
        lines.push(command_line(status));
    }
    lines
}

/// Emit a v2 `report-status-v2` response.
///
/// Returns a vector of LF-terminated byte payloads. `Ok` commands are
/// followed by any populated `option` lines in the canonical order
/// (`refname`, `old-oid`, `new-oid`, `forced-update`).
#[doc(alias = "report-status-v2")]
pub fn emit_v2(report: &ReportV2) -> Vec<BString> {
    let mut lines = Vec::with_capacity(1 + report.commands.len() * 2);
    lines.push(unpack_line(&report.unpack));
    for status in &report.commands {
        match status {
            CommandStatusV2::Ok { refname, options } => {
                lines.push(ok_line(refname));
                push_option_lines(&mut lines, options);
            }
            CommandStatusV2::Rejected { refname, reason } => {
                lines.push(ng_line(refname, reason));
            }
        }
    }
    lines
}

fn unpack_line(status: &UnpackStatus) -> BString {
    let mut out = BString::from("unpack ");
    match status {
        UnpackStatus::Ok => out.extend_from_slice(b"ok"),
        UnpackStatus::Failed(msg) => out.extend_from_slice(msg),
    }
    out.push(b'\n');
    out
}

fn command_line(status: &CommandStatus) -> BString {
    match status {
        CommandStatus::Ok { refname } => ok_line(refname),
        CommandStatus::Rejected { refname, reason } => ng_line(refname, reason),
    }
}

fn ok_line(refname: &BString) -> BString {
    let mut out = BString::from("ok ");
    out.extend_from_slice(refname);
    out.push(b'\n');
    out
}

fn ng_line(refname: &BString, reason: &BString) -> BString {
    let mut out = BString::from("ng ");
    out.extend_from_slice(refname);
    out.push(b' ');
    out.extend_from_slice(reason);
    out.push(b'\n');
    out
}

fn push_option_lines(out: &mut Vec<BString>, options: &CommandOptions) {
    if let Some(refname) = &options.refname {
        let mut line = BString::from("option refname ");
        line.extend_from_slice(refname);
        line.push(b'\n');
        out.push(line);
    }
    if let Some(old_oid) = options.old_oid {
        let mut line = BString::from("option old-oid ");
        line.push_str(old_oid.to_hex().to_string());
        line.push(b'\n');
        out.push(line);
    }
    if let Some(new_oid) = options.new_oid {
        let mut line = BString::from("option new-oid ");
        line.push_str(new_oid.to_hex().to_string());
        line.push(b'\n');
        out.push(line);
    }
    if options.forced_update {
        out.push(BString::from("option forced-update\n"));
    }
}

#[cfg(all(test, feature = "sha1"))]
mod tests {
    use super::*;

    fn oid(hex: &str) -> gix_hash::ObjectId {
        gix_hash::ObjectId::from_hex(hex.as_bytes()).expect("valid hex fixture")
    }

    #[test]
    fn v1_round_trip_ok_and_rejected() {
        let report = Report {
            unpack: UnpackStatus::Ok,
            commands: vec![
                CommandStatus::Ok {
                    refname: "refs/heads/main".into(),
                },
                CommandStatus::Rejected {
                    refname: "refs/heads/other".into(),
                    reason: "non-fast-forward".into(),
                },
            ],
        };
        let lines = emit_v1(&report);
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], "unpack ok\n");
        assert_eq!(lines[1], "ok refs/heads/main\n");
        assert_eq!(lines[2], "ng refs/heads/other non-fast-forward\n");
    }

    #[test]
    fn v1_unpack_failure_is_written_verbatim() {
        let report = Report {
            unpack: UnpackStatus::Failed("missing blob abc".into()),
            commands: vec![],
        };
        let lines = emit_v1(&report);
        assert_eq!(lines, vec![BString::from("unpack missing blob abc\n")]);
    }

    #[test]
    fn v2_emits_option_lines_after_ok_in_canonical_order() {
        let report = ReportV2 {
            unpack: UnpackStatus::Ok,
            commands: vec![CommandStatusV2::Ok {
                refname: "refs/heads/main".into(),
                options: CommandOptions {
                    refname: Some("refs/heads/renamed".into()),
                    old_oid: Some(oid("1111111111111111111111111111111111111111")),
                    new_oid: Some(oid("2222222222222222222222222222222222222222")),
                    forced_update: true,
                },
            }],
        };
        let lines = emit_v2(&report);
        let joined: Vec<&[u8]> = lines.iter().map(|l| l.as_slice()).collect();
        assert_eq!(joined[0], b"unpack ok\n");
        assert_eq!(joined[1], b"ok refs/heads/main\n");
        assert_eq!(joined[2], b"option refname refs/heads/renamed\n");
        assert_eq!(joined[3], b"option old-oid 1111111111111111111111111111111111111111\n",);
        assert_eq!(joined[4], b"option new-oid 2222222222222222222222222222222222222222\n",);
        assert_eq!(joined[5], b"option forced-update\n");
    }

    #[test]
    fn v2_rejection_has_no_options() {
        let report = ReportV2 {
            unpack: UnpackStatus::Ok,
            commands: vec![CommandStatusV2::Rejected {
                refname: "refs/heads/main".into(),
                reason: "hook declined".into(),
            }],
        };
        let lines = emit_v2(&report);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[1], "ng refs/heads/main hook declined\n");
    }

    /// Round-trip with the parser in `push::report_status` proves emit and
    /// parse are mutual inverses - fixing one without the other would
    /// surface as a failing round-trip.
    #[test]
    fn round_trip_v1_through_parser() {
        let report = Report {
            unpack: UnpackStatus::Ok,
            commands: vec![
                CommandStatus::Ok {
                    refname: "refs/heads/main".into(),
                },
                CommandStatus::Rejected {
                    refname: "refs/heads/other".into(),
                    reason: "non-fast-forward".into(),
                },
            ],
        };
        let lines = emit_v1(&report);
        let byte_slices: Vec<&[u8]> = lines.iter().map(|l| l.as_slice()).collect();
        let parsed =
            crate::push::report_status::parse_report_v1(byte_slices.iter().copied()).expect("round trip parses");
        assert_eq!(parsed, report);
    }
}
