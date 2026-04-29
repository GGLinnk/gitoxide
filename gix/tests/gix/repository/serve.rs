//! Integration tests for the serve-side endpoints on `Repository`.
//!
//! Validates that the wiring from `gix-protocol::receive_pack::serve_blocking`
//! through `Repository::edit_references` down to `gix-lock` / `gix-ref`
//! produces a spec-conformant `report-status` response, even when the
//! refs being acted on do not exist in the reference store.

use bstr::{BString, ByteSlice};
use gix_testtools::tempfile;

fn line_as_slice(line: gix_packetline::PacketLineRef<'_>) -> Option<Vec<u8>> {
    line.as_slice().map(<[u8]>::to_vec)
}

fn oid(hex: &str) -> gix_hash::ObjectId {
    gix_hash::ObjectId::from_hex(hex.as_bytes()).expect("valid hex fixture")
}

fn build_request(commands: Vec<gix_protocol::push::Command>, capabilities: &[&str]) -> Vec<u8> {
    let mut caps_bytes = vec![0u8];
    for (i, c) in capabilities.iter().enumerate() {
        if i > 0 {
            caps_bytes.push(b' ');
        }
        caps_bytes.extend_from_slice(c.as_bytes());
    }
    let caps = gix_transport::client::Capabilities::from_bytes(Box::leak(caps_bytes.into_boxed_slice()))
        .expect("valid capabilities")
        .0;
    let mut args = gix_protocol::push::Arguments::new(&caps);
    for cmd in commands {
        args.add_command(cmd).expect("add command");
    }
    let mut out = Vec::new();
    for line in args.emit_command_lines() {
        gix_packetline::blocking_io::encode::data_to_write(&line, &mut out).expect("write");
    }
    gix_packetline::blocking_io::encode::flush_to_write(&mut out).expect("flush");
    out
}

fn parse_report(body: &[u8]) -> gix_protocol::push::Report {
    let mut payloads: Vec<Vec<u8>> = Vec::new();
    let mut stream =
        gix_packetline::blocking_io::StreamingPeekableIter::new(body, &[gix_packetline::PacketLineRef::Flush], false);
    while let Some(Ok(Ok(line))) = stream.read_line() {
        match line_as_slice(line) {
            Some(data) => payloads.push(data),
            None => break,
        }
    }
    gix_protocol::push::report_status::parse_report_v1(payloads.iter().map(Vec::as_slice)).expect("parses")
}

/// When the client asks to delete a ref that does not exist, the
/// serve path must respond with a well-formed v1 `report-status` whose
/// single command entry carries an `ng` verdict referencing the
/// MustExistAndMatch failure - not a generic transport error.
#[test]
fn serve_pack_receive_delete_only_rejects_nonexistent_ref() -> crate::Result {
    let tmp = tempfile::tempdir()?;
    let repo = gix::init_bare(tmp.path())?;

    let request = build_request(
        vec![gix_protocol::push::Command {
            old_id: oid("1111111111111111111111111111111111111111"),
            new_id: oid("0000000000000000000000000000000000000000"),
            refname: BString::from("refs/heads/nonexistent"),
        }],
        &["report-status", "delete-refs"],
    );

    let mut response = Vec::new();
    let outcome = repo.serve_pack_receive_delete_only(request.as_slice(), &mut response)?;

    assert_eq!(outcome.parsed_commands.len(), 1);
    assert_eq!(outcome.parsed_commands[0].refname, "refs/heads/nonexistent");

    let report = parse_report(&response);
    assert_eq!(report.unpack, gix_protocol::push::UnpackStatus::Ok);
    assert_eq!(report.commands.len(), 1);
    match &report.commands[0] {
        gix_protocol::push::CommandStatus::Rejected { refname, reason } => {
            assert_eq!(refname, "refs/heads/nonexistent");
            // The reason carries the transaction error message from
            // gix-ref's MustExistAndMatch guard. We don't pin the exact
            // phrasing, just that *some* non-empty reason is present.
            assert!(!reason.is_empty(), "rejection should carry a non-empty reason");
        }
        other => panic!("expected Rejected verdict, got {other:?}"),
    }

    Ok(())
}

/// Non-deletion commands should be rejected with the explanatory
/// "pack ingestion not implemented" reason, rather than silently
/// accepted or causing a transport error.
#[test]
fn serve_pack_receive_delete_only_rejects_non_deletion_commands() -> crate::Result {
    let tmp = tempfile::tempdir()?;
    let repo = gix::init_bare(tmp.path())?;

    let request = build_request(
        vec![gix_protocol::push::Command {
            old_id: oid("1111111111111111111111111111111111111111"),
            new_id: oid("2222222222222222222222222222222222222222"),
            refname: BString::from("refs/heads/main"),
        }],
        &["report-status"],
    );

    let mut response = Vec::new();
    let _outcome = repo.serve_pack_receive_delete_only(request.as_slice(), &mut response)?;

    let report = parse_report(&response);
    assert_eq!(report.unpack, gix_protocol::push::UnpackStatus::Ok);
    assert_eq!(report.commands.len(), 1);
    match &report.commands[0] {
        gix_protocol::push::CommandStatus::Rejected { refname, reason } => {
            assert_eq!(refname, "refs/heads/main");
            assert!(
                reason.as_bstr().contains_str("pack ingestion not implemented"),
                "reason should explain the delete-only limitation, got: {reason:?}"
            );
        }
        other => panic!("expected Rejected verdict, got {other:?}"),
    }

    Ok(())
}

/// The pre-receive hook returning `Err(reason)` must short-circuit
/// the whole batch: every command surfaces as `ng <refname> <reason>`,
/// and no ref-update is attempted.
#[cfg(feature = "blocking-network-client")]
#[test]
fn serve_pack_receive_with_hooks_pre_receive_rejects_whole_batch() -> crate::Result {
    let tmp = tempfile::tempdir()?;
    let repo = gix::init_bare(tmp.path())?;

    let request = build_request(
        vec![gix_protocol::push::Command {
            old_id: oid("1111111111111111111111111111111111111111"),
            new_id: oid("0000000000000000000000000000000000000000"),
            refname: BString::from("refs/heads/whatever"),
        }],
        &["report-status", "delete-refs"],
    );

    let mut response = Vec::new();
    let mut progress = gix_features::progress::Discard;
    let should_interrupt = std::sync::atomic::AtomicBool::new(false);
    let hooks = gix_protocol::receive_pack::ServeHooks {
        pre_receive: Some(Box::new(|_cmds, _opts| Err(BString::from("policy says no")))),
        update: None,
        post_receive: None,
    };
    let outcome = repo.serve_pack_receive_with_hooks(
        request.as_slice(),
        &mut response,
        &mut progress,
        &should_interrupt,
        hooks,
    )?;

    assert_eq!(outcome.serve.parsed_commands.len(), 1);
    let report = parse_report(&response);
    assert_eq!(report.commands.len(), 1);
    match &report.commands[0] {
        gix_protocol::push::CommandStatus::Rejected { refname, reason } => {
            assert_eq!(refname, "refs/heads/whatever");
            assert_eq!(reason, "policy says no");
        }
        other => panic!("expected pre-receive rejection, got {other:?}"),
    }
    Ok(())
}

/// When the `update` hook rejects one command and accepts another,
/// only the rejected one should be reported as `ng`; the others run
/// through the normal ref-update path.
#[cfg(feature = "blocking-network-client")]
#[test]
fn serve_pack_receive_with_hooks_update_rejects_individually() -> crate::Result {
    use std::cell::RefCell;
    use std::rc::Rc;

    let tmp = tempfile::tempdir()?;
    let repo = gix::init_bare(tmp.path())?;

    // Two delete-only commands targeting refs that do not exist on the
    // server. One will be rejected by the update hook; the other would
    // be rejected by the ref-update layer (MustExistAndMatch) but we
    // assert on the hook's decision first.
    let request = build_request(
        vec![
            gix_protocol::push::Command {
                old_id: oid("1111111111111111111111111111111111111111"),
                new_id: oid("0000000000000000000000000000000000000000"),
                refname: BString::from("refs/heads/allowed"),
            },
            gix_protocol::push::Command {
                old_id: oid("2222222222222222222222222222222222222222"),
                new_id: oid("0000000000000000000000000000000000000000"),
                refname: BString::from("refs/heads/blocked"),
            },
        ],
        &["report-status", "delete-refs"],
    );

    let update_invocations: Rc<RefCell<Vec<BString>>> = Rc::new(RefCell::new(Vec::new()));
    let update_invocations_for_hook = update_invocations.clone();

    let post_receive_fired: Rc<RefCell<bool>> = Rc::new(RefCell::new(false));
    let post_receive_for_hook = post_receive_fired.clone();

    let mut response = Vec::new();
    let mut progress = gix_features::progress::Discard;
    let should_interrupt = std::sync::atomic::AtomicBool::new(false);
    let hooks = gix_protocol::receive_pack::ServeHooks {
        pre_receive: None,
        update: Some(Box::new(move |cmd, _opts| {
            update_invocations_for_hook.borrow_mut().push(cmd.refname.clone());
            if cmd.refname == "refs/heads/blocked" {
                Err(BString::from("update hook blocked"))
            } else {
                Ok(())
            }
        })),
        post_receive: Some(Box::new(move |_cmds, _outcomes, _opts| {
            *post_receive_for_hook.borrow_mut() = true;
        })),
    };
    let _ = repo.serve_pack_receive_with_hooks(
        request.as_slice(),
        &mut response,
        &mut progress,
        &should_interrupt,
        hooks,
    )?;

    // The update hook should have been called once per command.
    assert_eq!(update_invocations.borrow().len(), 2);
    // post_receive is informational; it must fire regardless of per-command outcomes.
    assert!(*post_receive_fired.borrow(), "post_receive must fire after the batch");

    let report = parse_report(&response);
    assert_eq!(report.commands.len(), 2);
    let blocked_report = report
        .commands
        .iter()
        .find(|c| match c {
            gix_protocol::push::CommandStatus::Ok { refname } => refname == "refs/heads/blocked",
            gix_protocol::push::CommandStatus::Rejected { refname, .. } => refname == "refs/heads/blocked",
        })
        .expect("blocked ref must surface in report");
    match blocked_report {
        gix_protocol::push::CommandStatus::Rejected { reason, .. } => {
            assert_eq!(reason, "update hook blocked");
        }
        other => panic!("expected Rejected for blocked ref, got {other:?}"),
    }
    Ok(())
}

/// The pre-receive hook must also observe push-options so an
/// embedder can reject the whole batch based on a policy token
/// without involving per-command state.
#[cfg(feature = "blocking-network-client")]
#[test]
fn serve_pack_receive_with_hooks_pre_receive_sees_push_options() -> crate::Result {
    use gix_packetline::blocking_io::encode;

    let tmp = tempfile::tempdir()?;
    let repo = gix::init_bare(tmp.path())?;

    let mut request: Vec<u8> = Vec::new();
    let first_line = "1111111111111111111111111111111111111111 \
        0000000000000000000000000000000000000000 \
        refs/heads/whatever\0report-status push-options delete-refs\n";
    encode::data_to_write(first_line.as_bytes(), &mut request)?;
    encode::flush_to_write(&mut request)?;
    encode::data_to_write(b"deploy=production", &mut request)?;
    encode::flush_to_write(&mut request)?;

    let hooks = gix_protocol::receive_pack::ServeHooks {
        pre_receive: Some(Box::new(|_cmds, opts| {
            if opts.iter().any(|o| o.as_slice() == b"deploy=production") {
                Err(BString::from("deploy=production requires reviewer approval"))
            } else {
                Ok(())
            }
        })),
        update: None,
        post_receive: None,
    };

    let mut response = Vec::new();
    let mut progress = gix_features::progress::Discard;
    let should_interrupt = std::sync::atomic::AtomicBool::new(false);
    let _ = repo.serve_pack_receive_with_hooks(
        request.as_slice(),
        &mut response,
        &mut progress,
        &should_interrupt,
        hooks,
    )?;

    let report = parse_report(&response);
    assert_eq!(report.commands.len(), 1);
    match &report.commands[0] {
        gix_protocol::push::CommandStatus::Rejected { reason, .. } => {
            assert_eq!(reason, "deploy=production requires reviewer approval");
        }
        other => panic!("expected pre-receive rejection, got {other:?}"),
    }
    Ok(())
}

/// When the client sends push-options, the update hook must receive
/// them as its second argument so embedders can gate per-command
/// policy on the option values.
#[cfg(feature = "blocking-network-client")]
#[test]
fn serve_pack_receive_with_hooks_passes_push_options_to_update_hook() -> crate::Result {
    use gix_packetline::blocking_io::encode;
    use std::cell::RefCell;
    use std::rc::Rc;

    let tmp = tempfile::tempdir()?;
    let repo = gix::init_bare(tmp.path())?;

    let mut request: Vec<u8> = Vec::new();
    let first_line = "1111111111111111111111111111111111111111 \
        0000000000000000000000000000000000000000 \
        refs/heads/whatever\0report-status push-options delete-refs\n";
    encode::data_to_write(first_line.as_bytes(), &mut request)?;
    encode::flush_to_write(&mut request)?;
    encode::data_to_write(b"ci.skip", &mut request)?;
    encode::flush_to_write(&mut request)?;

    let captured: Rc<RefCell<Vec<gix::bstr::BString>>> = Rc::new(RefCell::new(Vec::new()));
    let captured_for_hook = captured.clone();
    let hooks = gix_protocol::receive_pack::ServeHooks {
        pre_receive: None,
        update: Some(Box::new(move |_cmd, opts| {
            captured_for_hook.borrow_mut().extend_from_slice(opts);
            Ok(())
        })),
        post_receive: None,
    };

    let mut response = Vec::new();
    let mut progress = gix_features::progress::Discard;
    let should_interrupt = std::sync::atomic::AtomicBool::new(false);
    let _ = repo.serve_pack_receive_with_hooks(
        request.as_slice(),
        &mut response,
        &mut progress,
        &should_interrupt,
        hooks,
    )?;

    assert_eq!(
        *captured.borrow(),
        vec![gix::bstr::BString::from("ci.skip")],
        "update hook must receive the push-options the client sent",
    );
    Ok(())
}

/// When the client advertises `push-options`, the gix-level
/// `serve_pack_receive` must surface the parsed options on the
/// outcome so hooks can inspect them.
#[cfg(feature = "blocking-network-client")]
#[test]
fn serve_pack_receive_surfaces_push_options() -> crate::Result {
    use gix_packetline::blocking_io::encode;

    let tmp = tempfile::tempdir()?;
    let repo = gix::init_bare(tmp.path())?;

    // Hand-build a request that exercises the push-options pkt-line
    // section. The command itself is a delete of a nonexistent ref,
    // which the ref-updater will reject with ng; that is fine - we
    // only care that push_options round-trip onto the outcome.
    let mut request: Vec<u8> = Vec::new();
    let first_line = "1111111111111111111111111111111111111111 \
        0000000000000000000000000000000000000000 \
        refs/heads/whatever\0report-status push-options delete-refs\n";
    encode::data_to_write(first_line.as_bytes(), &mut request)?;
    encode::flush_to_write(&mut request)?;
    encode::data_to_write(b"ci.skip", &mut request)?;
    encode::data_to_write(b"merge-request-title=WIP", &mut request)?;
    encode::flush_to_write(&mut request)?;

    let mut response = Vec::new();
    let mut progress = gix_features::progress::Discard;
    let should_interrupt = std::sync::atomic::AtomicBool::new(false);
    let outcome = repo.serve_pack_receive(request.as_slice(), &mut response, &mut progress, &should_interrupt)?;

    assert_eq!(
        outcome.serve.push_options,
        vec![
            gix::bstr::BString::from("ci.skip"),
            gix::bstr::BString::from("merge-request-title=WIP"),
        ],
        "push-options must propagate to the gix-level outcome"
    );
    Ok(())
}

/// When the caller passes `ServeOptions { allow_deletes: false }`
/// — i.e. the server's own policy does not advertise `delete-refs` —
/// a deletion command must be rejected at the protocol layer before
/// reaching the ref store.
#[test]
fn serve_pack_receive_rejects_deletion_when_delete_refs_disallowed() -> crate::Result {
    let tmp = tempfile::tempdir()?;
    let repo = gix::init_bare(tmp.path())?;

    let request = build_request(
        vec![gix_protocol::push::Command {
            old_id: oid("1111111111111111111111111111111111111111"),
            new_id: oid("0000000000000000000000000000000000000000"),
            refname: BString::from("refs/heads/stale"),
        }],
        &["report-status", "delete-refs"],
    );

    let mut response = Vec::new();
    let mut progress = gix_features::progress::Discard;
    let should_interrupt = std::sync::atomic::AtomicBool::new(false);
    let _ = repo.serve_pack_receive_with_options_and_hooks(
        request.as_slice(),
        &mut response,
        &mut progress,
        &should_interrupt,
        gix_protocol::receive_pack::ServeHooks::default(),
        gix_protocol::receive_pack::ServeOptions { allow_deletes: false },
    )?;

    let report = parse_report(&response);
    assert_eq!(report.unpack, gix_protocol::push::UnpackStatus::Ok);
    assert_eq!(report.commands.len(), 1);
    match &report.commands[0] {
        gix_protocol::push::CommandStatus::Rejected { refname, reason } => {
            assert_eq!(refname, "refs/heads/stale");
            assert!(
                reason.as_bstr().starts_with_str("deletion prohibited"),
                "expected the policy reason, got {reason:?}"
            );
        }
        other => panic!("expected Rejected verdict, got {other:?}"),
    }
    Ok(())
}

/// The delete-only endpoint must accept deletions unconditionally —
/// it is delete-only by contract. `serve_pack_receive_delete_only`
/// therefore hardcodes `allow_deletes: true` in the policy struct it
/// forwards to the protocol layer, regardless of how any wider server
/// policy would be configured.
#[test]
fn serve_pack_receive_delete_only_ignores_wider_policy() -> crate::Result {
    let tmp = tempfile::tempdir()?;
    let repo = gix::init_bare(tmp.path())?;

    let request = build_request(
        vec![gix_protocol::push::Command {
            old_id: oid("1111111111111111111111111111111111111111"),
            new_id: oid("0000000000000000000000000000000000000000"),
            refname: BString::from("refs/heads/stale"),
        }],
        &["report-status", "delete-refs"],
    );

    let mut response = Vec::new();
    let outcome = repo.serve_pack_receive_delete_only(request.as_slice(), &mut response)?;

    assert_eq!(outcome.parsed_commands.len(), 1);
    let report = parse_report(&response);
    // The ref doesn't exist so the ref-store still rejects it, but the
    // rejection must NOT cite the delete-refs policy. Accept either a
    // MustExistAndMatch-style rejection or any other transaction error,
    // as long as it's not the protocol-layer "deletion prohibited".
    assert_eq!(report.commands.len(), 1);
    if let gix_protocol::push::CommandStatus::Rejected { reason, .. } = &report.commands[0] {
        assert!(
            !reason.as_bstr().starts_with_str("deletion prohibited"),
            "delete-only endpoint must bypass the delete-refs policy, got {reason:?}"
        );
    }
    Ok(())
}
