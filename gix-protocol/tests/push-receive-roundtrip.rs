//! Integration test that proves the client-side `push` and server-side
//! `receive_pack` wire types are mutual inverses. A message constructed
//! by the client and consumed by the server (and vice versa) round-trips
//! with no loss.

use bstr::BString;
use gix_protocol::{push, receive_pack};

fn oid(hex: &str) -> gix_hash::ObjectId {
    gix_hash::ObjectId::from_hex(hex.as_bytes()).expect("valid hex fixture")
}

/// Client emits commands -> server parses them -> commands match.
#[test]
fn commands_round_trip_client_to_server() {
    let mut args = push::Arguments::new(
        &gix_transport::client::Capabilities::from_bytes(
            b"\0report-status-v2 side-band-64k delete-refs atomic ofs-delta",
        )
        .expect("valid capabilities")
        .0,
    );
    args.use_atomic().expect("atomic is advertised");
    args.add_command(push::Command {
        old_id: oid("1111111111111111111111111111111111111111"),
        new_id: oid("2222222222222222222222222222222222222222"),
        refname: BString::from("refs/heads/main"),
    })
    .expect("update command accepted");
    args.add_command(push::Command {
        old_id: oid("3333333333333333333333333333333333333333"),
        new_id: oid("0000000000000000000000000000000000000000"),
        refname: BString::from("refs/heads/deleted"),
    })
    .expect("delete-refs is advertised");

    // Client side: serialise command lines.
    let lines: Vec<BString> = args.emit_command_lines();
    let byte_slices: Vec<&[u8]> = lines.iter().map(|l| l.as_slice()).collect();

    // Server side: parse them back.
    let parsed = receive_pack::commands::parse_request(byte_slices.iter().copied()).expect("parses");

    assert_eq!(parsed.commands.len(), 2);
    assert_eq!(parsed.commands[0].refname, "refs/heads/main");
    assert_eq!(parsed.commands[1].refname, "refs/heads/deleted");
    assert!(parsed.commands[1].is_delete());
    assert!(parsed.capabilities.has("report-status-v2"));
    assert!(parsed.capabilities.has("atomic"));
    assert!(parsed.capabilities.has("side-band-64k"));
    assert!(parsed.capabilities.has("ofs-delta"));
}

/// Server emits a v1 report -> client parses it -> report matches.
#[test]
fn report_v1_round_trip_server_to_client() {
    let original = push::Report {
        unpack: push::UnpackStatus::Ok,
        commands: vec![
            push::CommandStatus::Ok {
                refname: BString::from("refs/heads/main"),
            },
            push::CommandStatus::Rejected {
                refname: BString::from("refs/heads/other"),
                reason: BString::from("non-fast-forward"),
            },
        ],
    };
    let emitted: Vec<BString> = receive_pack::report::emit_v1(&original);
    let slices: Vec<&[u8]> = emitted.iter().map(|l| l.as_slice()).collect();

    let parsed = push::report_status::parse_report_v1(slices.iter().copied()).expect("parses");
    assert_eq!(parsed, original);
}

/// Server emits a v2 report with options -> client parses it -> options preserved.
#[test]
fn report_v2_round_trip_with_options() {
    let original = push::ReportV2 {
        unpack: push::UnpackStatus::Ok,
        commands: vec![push::CommandStatusV2::Ok {
            refname: BString::from("refs/heads/main"),
            options: push::CommandOptions {
                refname: Some(BString::from("refs/heads/renamed")),
                old_oid: Some(oid("1111111111111111111111111111111111111111")),
                new_oid: Some(oid("2222222222222222222222222222222222222222")),
                forced_update: true,
            },
        }],
    };
    let emitted: Vec<BString> = receive_pack::report::emit_v2(&original);
    let slices: Vec<&[u8]> = emitted.iter().map(|l| l.as_slice()).collect();

    let parsed = push::report_status::parse_report_v2(slices.iter().copied()).expect("parses");
    assert_eq!(parsed, original);
}

/// Unpack-failure reports survive a round-trip with the reason verbatim.
#[test]
fn unpack_failure_reason_is_preserved() {
    let original = push::Report {
        unpack: push::UnpackStatus::Failed(BString::from("missing blob abcdef")),
        commands: vec![],
    };
    let emitted = receive_pack::report::emit_v1(&original);
    let slices: Vec<&[u8]> = emitted.iter().map(|l| l.as_slice()).collect();
    let parsed = push::report_status::parse_report_v1(slices.iter().copied()).expect("parses");
    assert_eq!(parsed, original);
}
