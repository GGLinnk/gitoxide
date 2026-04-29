//! Blocking state machine for server-side `git-receive-pack`.
//!
//! Reads the client's update-request, hands the trailing pack bytes to
//! a caller-supplied ingester, asks a caller-supplied updater to apply
//! each ref-update, and finally writes the `report-status` response.
//!
//! This keeps the protocol-layer crate decoupled from concrete object
//! storage and ref storage. An embedder wiring this into
//! `gix::Repository` provides the two closures that plug in
//! `gix_pack::data::input::BytesToEntriesIter` / `gix-odb` for the
//! pack and `gix-lock` / `gix-ref` for the updates.

use std::io::{Read, Write};

use bstr::BString;

use super::commands;
use super::report;
use super::RequestedCapabilities;
use crate::push::{Command, CommandOptions, CommandStatus, CommandStatusV2, Report, ReportV2, UnpackStatus};

/// Outcome of a completed serve call.
#[derive(Debug)]
#[must_use = "inspect the parsed commands / push-options to surface what the client negotiated"]
pub struct ServeOutcome {
    /// The commands the client asked for, in send order.
    pub parsed_commands: Vec<Command>,
    /// Capabilities the client requested on the first command line.
    pub requested_capabilities: RequestedCapabilities,
    /// Whether the client requested `atomic` application.
    pub atomic: bool,
    /// Push-options the client sent after the command-list, when the
    /// `push-options` capability was negotiated. Empty otherwise (either
    /// the capability was not advertised or the client sent none).
    pub push_options: Vec<BString>,
    /// Raw `push-cert` block when the client signed its push. `None`
    /// if the client did not send a cert. The body is the verbatim
    /// wire bytes from the `push-cert\0<caps>` header through the
    /// `push-cert-end` terminator; verification against GPG/SSH is
    /// the embedder's responsibility - gix-protocol does not validate.
    pub push_cert: Option<BString>,
}

/// Per-command outcome fed back from the caller's ref-updater.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateOutcome {
    /// The ref was updated as requested, optionally with v2 trailer
    /// metadata that the server wants to surface (`old-oid`,
    /// `new-oid`, `forced-update`, ...). v1 reports silently discard
    /// the options; v2 reports emit them as `option` lines.
    Ok(CommandOptions),
    /// The ref update was rejected with the given reason.
    Rejected(BString),
}

impl UpdateOutcome {
    /// Shorthand for an `Ok` outcome with no v2 trailer metadata.
    ///
    /// Equivalent to `UpdateOutcome::Ok(CommandOptions::default())` and
    /// exists so call sites that do not populate trailer metadata stay
    /// terse.
    pub fn accepted() -> Self {
        Self::Ok(CommandOptions::default())
    }
}

/// Optional hook callbacks invoked by [`serve_with_hooks`].
///
/// These follow the pre-receive / update / post-receive shape of
/// server-side hooks in `git` but are plain closures rather than
/// spawned subprocesses, so the host crate decides what runs inside.
///
/// The second `&[BString]` argument on each hook is the push-options
/// section the client sent after the command-list, when the
/// `push-options` capability was negotiated. Empty otherwise.
/// Closure type for the `pre-receive` hook (`Err(reason)` rejects the whole batch).
pub type PreReceiveHook<'a> = Box<dyn FnOnce(&[Command], &[BString]) -> Result<(), BString> + 'a>;
/// Closure type for the per-command `update` hook.
pub type UpdateHook<'a> = Box<dyn FnMut(&Command, &[BString]) -> Result<(), BString> + 'a>;
/// Closure type for the informational `post-receive` hook.
pub type PostReceiveHook<'a> = Box<dyn FnOnce(&[Command], &[UpdateOutcome], &[BString]) + 'a>;

/// Server-side policy knobs consulted by [`serve_with_options_and_hooks`].
///
/// Defaults match the permissive behavior of [`serve`] /
/// [`serve_with_hooks`] (everything allowed). Adjust fields to enforce
/// tighter server-side policy that must stay in sync with the
/// advertisement emitted by [`super::advertisement::Options`].
#[derive(Debug, Clone, Copy)]
pub struct ServeOptions {
    /// Accept deletion commands (`<old> SP <zero-oid> SP <ref>`).
    ///
    /// Must be aligned with the `delete-refs` capability advertised by
    /// [`super::advertisement::Options::delete_refs`]: the spec wording
    /// is that the server honours only capabilities it advertised, so
    /// advertising `delete-refs` without enforcement — or the reverse —
    /// breaks the capability contract.
    ///
    /// When `false`, every deletion command in the batch is reported
    /// back to the client as `ng <refname> deletion prohibited:
    /// delete-refs capability not advertised`, non-deletion commands
    /// flow through the normal pipeline, and `unpack` still reports
    /// `ok` when the pack (if any) ingested cleanly.
    pub allow_deletes: bool,
}

impl Default for ServeOptions {
    fn default() -> Self {
        Self { allow_deletes: true }
    }
}

/// Hook callbacks invoked at the standard receive-pack checkpoints.
///
/// Every field is `Option`: passing `ServeHooks::default()` makes
/// [`serve_with_hooks`] behave identically to [`serve`]. See the
/// per-field docs for the rejection semantics.
#[derive(Default)]
pub struct ServeHooks<'a> {
    /// Run after the commands are parsed but before the pack has been
    /// ingested. Return `Err(reason)` to reject the entire batch:
    /// every command will surface in the report as
    /// `ng <refname> <reason>`, the pack ingester and ref-updater are
    /// never invoked, and the response is emitted as if the batch had
    /// been rejected atomically.
    pub pre_receive: Option<PreReceiveHook<'a>>,
    /// Run per-command after pack ingest but before ref-update. A
    /// return of `Err(reason)` marks just that command as rejected;
    /// other commands continue. When `atomic` was negotiated, any
    /// rejection should cause the updater to reject *all* commands;
    /// callers that honour `atomic` wire that up themselves.
    pub update: Option<UpdateHook<'a>>,
    /// Run after ref-update with the final outcomes. Purely
    /// informational; the return value is discarded.
    pub post_receive: Option<PostReceiveHook<'a>>,
}

/// Errors raised while driving the receive-pack state machine.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum ServeError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("malformed packet line in request: {message}")]
    PacketLine { message: String },
    #[error(transparent)]
    Parse(#[from] commands::Error),
    #[error("pack ingestion failed")]
    PackIngest(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error("ref update handler failed")]
    RefUpdate(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error("ref-updater returned {returned} outcomes for {expected} commands")]
    UpdaterMismatch { expected: usize, returned: usize },
}

/// Drive one receive-pack interaction.
///
/// `reader` yields the raw client bytes (pkt-line framed update-request
/// followed by an optional pack). `writer` receives the server's framed
/// `report-status` response. The two closures plug concrete object /
/// ref storage into the state machine:
///
/// - `pack_ingester` consumes the pack bytes that follow the command
///   list's terminating flush-pkt. For delete-only pushes (no pack on
///   the wire), implementations may simply read zero bytes and return
///   `Ok(())`. The passed reader is positioned at the first post-flush
///   byte.
/// - `apply_updates` receives the parsed commands plus the value of the
///   client's `atomic` capability. It returns one [`UpdateOutcome`] per
///   command, in the same order, reflecting whether each ref was
///   actually updated (`Ok`) or rejected (`Rejected(reason)`).
///
/// On success, the `report-status` response has been fully written to
/// `writer` and flushed. v2 `report-status-v2` is emitted automatically
/// when the client advertised it on the first command line; otherwise
/// v1 `report-status` is emitted.
#[doc(alias = "git receive-pack")]
pub fn serve<R, W, PI, RU>(
    reader: R,
    writer: &mut W,
    pack_ingester: PI,
    apply_updates: RU,
) -> Result<ServeOutcome, ServeError>
where
    R: Read,
    W: Write,
    PI: FnOnce(&mut dyn Read) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>>,
    RU: FnOnce(&[Command], bool) -> Result<Vec<UpdateOutcome>, Box<dyn std::error::Error + Send + Sync + 'static>>,
{
    serve_with_hooks(reader, writer, pack_ingester, apply_updates, ServeHooks::default())
}

/// Variant of [`serve`] that additionally runs caller-supplied hooks
/// at the standard receive-pack checkpoints (`pre-receive`, `update`,
/// `post-receive`).
///
/// See [`ServeHooks`] for the shape of each callback. Hooks are
/// invoked inline from the serve loop on whatever thread drives it;
/// they must not block indefinitely if the transport has a timeout.
#[doc(alias = "git receive-pack")]
pub fn serve_with_hooks<R, W, PI, RU>(
    reader: R,
    writer: &mut W,
    pack_ingester: PI,
    apply_updates: RU,
    hooks: ServeHooks<'_>,
) -> Result<ServeOutcome, ServeError>
where
    R: Read,
    W: Write,
    PI: FnOnce(&mut dyn Read) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>>,
    RU: FnOnce(&[Command], bool) -> Result<Vec<UpdateOutcome>, Box<dyn std::error::Error + Send + Sync + 'static>>,
{
    serve_with_options_and_hooks(reader, writer, pack_ingester, apply_updates, hooks, ServeOptions::default())
}

/// Variant of [`serve_with_hooks`] that additionally takes a
/// [`ServeOptions`] policy struct.
///
/// Today the only policy knob is `allow_deletes`, which must stay in
/// sync with the `delete-refs` capability advertisement on
/// [`super::advertisement::Options::delete_refs`]. When `false`,
/// deletion commands surface to the client as
/// `ng <refname> deletion prohibited: delete-refs capability not advertised`,
/// the update hook is bypassed for those commands, and `apply_updates`
/// is invoked only with the non-forbidden subset so a misbehaving
/// updater cannot quietly apply a policy-rejected deletion.
#[doc(alias = "git receive-pack")]
pub fn serve_with_options_and_hooks<R, W, PI, RU>(
    reader: R,
    writer: &mut W,
    pack_ingester: PI,
    apply_updates: RU,
    mut hooks: ServeHooks<'_>,
    options: ServeOptions,
) -> Result<ServeOutcome, ServeError>
where
    R: Read,
    W: Write,
    PI: FnOnce(&mut dyn Read) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>>,
    RU: FnOnce(&[Command], bool) -> Result<Vec<UpdateOutcome>, Box<dyn std::error::Error + Send + Sync + 'static>>,
{
    use gix_packetline::blocking_io::{encode, StreamingPeekableIter};
    use gix_packetline::PacketLineRef;

    let mut stream = StreamingPeekableIter::new(reader, &[PacketLineRef::Flush], false);

    // 1. Read command-list pkt-lines until the terminating flush-pkt.
    let mut payloads: Vec<Vec<u8>> = Vec::new();
    loop {
        match stream.read_line() {
            None => break,
            Some(Err(err)) => return Err(ServeError::Io(err)),
            Some(Ok(Err(err))) => {
                return Err(ServeError::PacketLine {
                    message: err.to_string(),
                });
            }
            Some(Ok(Ok(line))) => match line.as_slice() {
                Some(data) => payloads.push(data.to_vec()),
                None => break,
            },
        }
    }

    // 2. Parse the command-list.
    let parsed = commands::parse_request(payloads.iter().map(Vec::as_slice))?;
    let atomic = parsed.capabilities.has("atomic");

    // 3. When the client advertised `push-options`, a second pkt-line
    //    section follows the command-list flush, terminated by another
    //    flush-pkt. Drain it into a Vec<BString> before the pack. When
    //    the capability is NOT advertised, no such section exists and
    //    we go straight to the pack.
    //
    //    `StreamingPeekableIter` latches to `None` after it hits its
    //    first stop delimiter (the command-list flush above), so we
    //    reset it before reading the options section.
    let mut push_options: Vec<BString> = Vec::new();
    if parsed.capabilities.has("push-options") {
        stream.reset();
        loop {
            match stream.read_line() {
                None => break,
                Some(Err(err)) => return Err(ServeError::Io(err)),
                Some(Ok(Err(err))) => {
                    return Err(ServeError::PacketLine {
                        message: err.to_string(),
                    });
                }
                Some(Ok(Ok(line))) => match line.as_slice() {
                    Some(data) => {
                        let trimmed = match data.last() {
                            Some(b'\n') => &data[..data.len() - 1],
                            _ => data,
                        };
                        push_options.push(BString::from(trimmed));
                    }
                    None => break,
                },
            }
        }
    }

    // 4. Policy gate: when delete-refs was not negotiated, every
    //    deletion command is rejected at the protocol layer and
    //    removed from every downstream step (pack ingestion skipped
    //    if the whole batch is forbidden; update hook bypassed for
    //    forbidden slots; updater called only with allowed commands).
    let forbidden_deletion: Vec<bool> = parsed
        .commands
        .iter()
        .map(|cmd| !options.allow_deletes && cmd.is_delete())
        .collect();
    let every_command_forbidden = !parsed.commands.is_empty() && forbidden_deletion.iter().all(|&f| f);

    // 5. pre-receive hook: short-circuit before touching the ODB.
    let pre_receive_rejection = match hooks.pre_receive.take() {
        Some(hook) => hook(&parsed.commands, &push_options).err(),
        None => None,
    };

    // 6. Transition to raw-byte mode so the pack ingester can read
    //    unframed bytes from the same transport stream.
    let mut raw_reader = stream.into_inner();

    // 7. Hand the pack (if any) to the ingester. A delete-only batch
    //    never carries a pack on the wire, so when every command is
    //    forbidden deletions the ingester is bypassed entirely — a
    //    spec-compliant client would never send pack bytes we should
    //    attempt to read.
    if !every_command_forbidden {
        pack_ingester(&mut raw_reader).map_err(ServeError::PackIngest)?;
    }

    // 8. Collect outcomes. pre-receive rejection short-circuits the
    //    updater entirely. Otherwise: forbidden-deletion slots are
    //    pre-rejected; the update hook runs only on allowed slots;
    //    the updater receives only allowed commands and its outcomes
    //    are re-interleaved with the forbidden slots at the end.
    let forbidden_reason: BString = "deletion prohibited: delete-refs capability not advertised".into();
    let outcomes = if let Some(reason) = pre_receive_rejection {
        parsed
            .commands
            .iter()
            .map(|_| UpdateOutcome::Rejected(reason.clone()))
            .collect()
    } else {
        let mut per_command_rejections: Vec<Option<BString>> = forbidden_deletion
            .iter()
            .map(|&forbidden| forbidden.then(|| forbidden_reason.clone()))
            .collect();
        if let Some(hook) = hooks.update.as_mut() {
            for (idx, cmd) in parsed.commands.iter().enumerate() {
                if per_command_rejections[idx].is_some() {
                    continue;
                }
                if let Err(reason) = hook(cmd, &push_options) {
                    per_command_rejections[idx] = Some(reason);
                }
            }
        }
        // Atomic push: if the update hook rejected any command, we
        // must not touch the ref store at all. Short-circuit by
        // synthesizing rejections for every command - the sibling
        // rejections carry the hook's reason, the rest cite the
        // sibling failure so the report makes the atomicity visible.
        let hook_rejected_atomic = atomic && per_command_rejections.iter().any(Option::is_some);
        if hook_rejected_atomic {
            per_command_rejections
                .into_iter()
                .map(|rej| match rej {
                    Some(reason) => UpdateOutcome::Rejected(reason),
                    None => UpdateOutcome::Rejected(
                        "atomic push: another ref in this batch was rejected by the update hook".into(),
                    ),
                })
                .collect()
        } else {
            let allowed_commands: Vec<Command> = parsed
                .commands
                .iter()
                .zip(forbidden_deletion.iter().copied())
                .filter(|(_, forbidden)| !*forbidden)
                .map(|(cmd, _)| cmd.clone())
                .collect();
            let allowed_outcomes = if allowed_commands.is_empty() {
                Vec::new()
            } else {
                let outs = apply_updates(&allowed_commands, atomic).map_err(ServeError::RefUpdate)?;
                if outs.len() != allowed_commands.len() {
                    return Err(ServeError::UpdaterMismatch {
                        expected: allowed_commands.len(),
                        returned: outs.len(),
                    });
                }
                outs
            };
            // Re-interleave: forbidden slots get the pre-computed
            // rejection; allowed slots take the updater's verdict,
            // with any update-hook rejection overlaid on top (hook
            // rejection always wins, matching the pre-B4 behavior).
            let mut outcomes: Vec<UpdateOutcome> = Vec::with_capacity(parsed.commands.len());
            let mut allowed_iter = allowed_outcomes.into_iter();
            for (idx, rejection) in per_command_rejections.into_iter().enumerate() {
                let outcome = if let Some(reason) = rejection {
                    UpdateOutcome::Rejected(reason)
                } else {
                    debug_assert!(!forbidden_deletion[idx], "forbidden slots always carry a rejection");
                    allowed_iter.next().expect("allowed count matches allowed commands")
                };
                outcomes.push(outcome);
            }
            outcomes
        }
    };

    // 7. post-receive hook (informational).
    if let Some(hook) = hooks.post_receive.take() {
        hook(&parsed.commands, &outcomes, &push_options);
    }

    // 6. Build and emit the report-status response, picking v1 / v2
    //    based on the client's advertised capability set (v2 is
    //    preferred whenever the client requested it). When the client
    //    selected `side-band` / `side-band-64k` the report rides on
    //    channel 1; the terminating flush-pkt is emitted on the raw
    //    stream, matching upstream `builtin/receive-pack.c`.
    let use_v2 = parsed.capabilities.has("report-status-v2");
    let lines: Vec<bstr::BString> = if use_v2 {
        report::emit_v2(&build_report_v2(&parsed.commands, &outcomes))
    } else {
        report::emit_v1(&build_report(&parsed.commands, &outcomes))
    };
    let sideband_mode = crate::sideband::detect_v1_sideband_mode_from_caps(&parsed.capabilities.raw);
    match crate::sideband::SidebandWriter::new(&mut *writer, sideband_mode) {
        None => {
            for line in &lines {
                encode::data_to_write(line.as_slice(), &mut *writer)?;
            }
        }
        Some(mut sideband) => {
            for line in &lines {
                encode::data_to_write(line.as_slice(), &mut sideband)?;
            }
        }
    }
    encode::flush_to_write(writer)?;

    Ok(ServeOutcome {
        parsed_commands: parsed.commands,
        requested_capabilities: parsed.capabilities,
        atomic,
        push_options,
        push_cert: parsed.push_cert,
    })
}

fn build_report(commands: &[Command], outcomes: &[UpdateOutcome]) -> Report {
    let mut report = Report {
        unpack: UnpackStatus::Ok,
        commands: Vec::with_capacity(commands.len()),
    };
    for (cmd, outcome) in commands.iter().zip(outcomes.iter()) {
        let status = match outcome {
            UpdateOutcome::Ok(_) => CommandStatus::Ok {
                refname: cmd.refname.clone(),
            },
            UpdateOutcome::Rejected(reason) => CommandStatus::Rejected {
                refname: cmd.refname.clone(),
                reason: reason.clone(),
            },
        };
        report.commands.push(status);
    }
    report
}

fn build_report_v2(commands: &[Command], outcomes: &[UpdateOutcome]) -> ReportV2 {
    let mut report = ReportV2 {
        unpack: UnpackStatus::Ok,
        commands: Vec::with_capacity(commands.len()),
    };
    for (cmd, outcome) in commands.iter().zip(outcomes.iter()) {
        let status = match outcome {
            UpdateOutcome::Ok(options) => CommandStatusV2::Ok {
                refname: cmd.refname.clone(),
                options: options.clone(),
            },
            UpdateOutcome::Rejected(reason) => CommandStatusV2::Rejected {
                refname: cmd.refname.clone(),
                reason: reason.clone(),
            },
        };
        report.commands.push(status);
    }
    report
}

#[cfg(all(test, feature = "sha1"))]
mod tests {
    use super::*;
    use crate::push;

    fn oid(hex: &str) -> gix_hash::ObjectId {
        gix_hash::ObjectId::from_hex(hex.as_bytes()).expect("valid hex fixture")
    }

    /// Build a pkt-line framed request matching what a real client emits.
    fn build_request(commands: Vec<Command>, capabilities: &[&str]) -> Vec<u8> {
        let mut args = push::Arguments::new(
            &gix_transport::client::Capabilities::from_bytes({
                let mut buf = vec![0];
                for (i, c) in capabilities.iter().enumerate() {
                    if i > 0 {
                        buf.push(b' ');
                    }
                    buf.extend_from_slice(c.as_bytes());
                }
                Box::leak(buf.into_boxed_slice())
            })
            .expect("valid capability bytes")
            .0,
        );
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

    #[test]
    fn delete_only_push_emits_matching_report() {
        let req = build_request(
            vec![Command {
                old_id: oid("1111111111111111111111111111111111111111"),
                new_id: oid("0000000000000000000000000000000000000000"),
                refname: "refs/heads/stale".into(),
            }],
            &["report-status", "delete-refs"],
        );
        let mut resp = Vec::new();
        let outcome = serve(
            req.as_slice(),
            &mut resp,
            |_r| Ok(()), // delete-only: no pack expected
            |cmds, _atomic| Ok(cmds.iter().map(|_| UpdateOutcome::accepted()).collect()),
        )
        .expect("serve ok");
        assert_eq!(outcome.parsed_commands.len(), 1);
        assert!(outcome.requested_capabilities.has("report-status"));

        // Response should parse as an Ok v1 report with one command accepted.
        let mut payloads: Vec<Vec<u8>> = Vec::new();
        let mut stream = gix_packetline::blocking_io::StreamingPeekableIter::new(
            resp.as_slice(),
            &[gix_packetline::PacketLineRef::Flush],
            false,
        );
        while let Some(Ok(Ok(line))) = stream.read_line() {
            if let Some(data) = line.as_slice() {
                payloads.push(data.to_vec());
            } else {
                break;
            }
        }
        let parsed = push::report_status::parse_report_v1(payloads.iter().map(Vec::as_slice)).expect("parses");
        assert_eq!(parsed.unpack, push::UnpackStatus::Ok);
        assert_eq!(parsed.commands.len(), 1);
        assert!(matches!(parsed.commands[0], push::CommandStatus::Ok { .. }));
    }

    #[test]
    fn rejected_commands_propagate_into_the_report() {
        let req = build_request(
            vec![Command {
                old_id: oid("1111111111111111111111111111111111111111"),
                new_id: oid("2222222222222222222222222222222222222222"),
                refname: "refs/heads/main".into(),
            }],
            &["report-status"],
        );
        let mut resp = Vec::new();
        let _ = serve(
            req.as_slice(),
            &mut resp,
            |_r| Ok(()),
            |_cmds, _atomic| Ok(vec![UpdateOutcome::Rejected("hook declined".into())]),
        )
        .expect("serve ok");

        // Response payload should contain the ng line with the reason.
        assert!(resp
            .windows(b"ng refs/heads/main hook declined".len())
            .any(|w| w == b"ng refs/heads/main hook declined"));
    }

    #[test]
    fn serve_emits_v2_report_when_client_advertises_report_status_v2() {
        let req = build_request(
            vec![Command {
                old_id: oid("1111111111111111111111111111111111111111"),
                new_id: oid("0000000000000000000000000000000000000000"),
                refname: "refs/heads/stale".into(),
            }],
            &["report-status-v2", "delete-refs"],
        );
        let mut resp = Vec::new();
        let _ = serve(
            req.as_slice(),
            &mut resp,
            |_r| Ok(()),
            |cmds, _atomic| Ok(cmds.iter().map(|_| UpdateOutcome::accepted()).collect()),
        )
        .expect("serve ok");

        // v2 emission is a superset of v1's `ok <refname>` shape, so
        // the v1 parser still reads it, but the extra point we assert
        // here is that the emitted response was built with the v2
        // emitter path. The divergent parts (option lines) are
        // exercised by the option-carrying tests in report.rs; here we
        // verify that the response still parses and that the client
        // sees the same accepted-refname shape.
        let mut payloads: Vec<Vec<u8>> = Vec::new();
        let mut stream = gix_packetline::blocking_io::StreamingPeekableIter::new(
            resp.as_slice(),
            &[gix_packetline::PacketLineRef::Flush],
            false,
        );
        while let Some(Ok(Ok(line))) = stream.read_line() {
            if let Some(data) = line.as_slice() {
                payloads.push(data.to_vec());
            } else {
                break;
            }
        }
        let parsed_v2 = push::report_status::parse_report_v2(payloads.iter().map(Vec::as_slice)).expect("parses as v2");
        assert_eq!(parsed_v2.unpack, push::UnpackStatus::Ok);
        match &parsed_v2.commands[0] {
            push::CommandStatusV2::Ok { refname, .. } => assert_eq!(refname, "refs/heads/stale"),
            other => panic!("expected v2 Ok, got {other:?}"),
        }
    }

    #[test]
    fn pre_receive_hook_rejects_whole_batch_and_short_circuits_updater() {
        let req = build_request(
            vec![
                Command {
                    old_id: oid("1111111111111111111111111111111111111111"),
                    new_id: oid("2222222222222222222222222222222222222222"),
                    refname: "refs/heads/a".into(),
                },
                Command {
                    old_id: oid("3333333333333333333333333333333333333333"),
                    new_id: oid("4444444444444444444444444444444444444444"),
                    refname: "refs/heads/b".into(),
                },
            ],
            &["report-status"],
        );
        let mut resp = Vec::new();
        let hooks = ServeHooks {
            pre_receive: Some(Box::new(|_cmds, _opts| Err(BString::from("policy denied")))),
            update: None,
            post_receive: None,
        };
        let _ = serve_with_hooks(
            req.as_slice(),
            &mut resp,
            |_r| Ok(()),
            |_cmds, _atomic| panic!("updater must be short-circuited by pre-receive rejection"),
            hooks,
        )
        .expect("serve ok");
        assert!(resp
            .windows(b"ng refs/heads/a policy denied".len())
            .any(|w| w == b"ng refs/heads/a policy denied"));
        assert!(resp
            .windows(b"ng refs/heads/b policy denied".len())
            .any(|w| w == b"ng refs/heads/b policy denied"));
    }

    fn build_atomic_request(commands: Vec<Command>) -> Vec<u8> {
        let mut args = push::Arguments::new(
            &gix_transport::client::Capabilities::from_bytes(b"\0report-status delete-refs atomic")
                .expect("valid capability bytes")
                .0,
        );
        args.use_atomic().expect("server advertised atomic");
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

    #[test]
    fn atomic_push_with_update_hook_rejection_blocks_updater_entirely() {
        let req = build_atomic_request(vec![
            Command {
                old_id: oid("1111111111111111111111111111111111111111"),
                new_id: oid("0000000000000000000000000000000000000000"),
                refname: "refs/heads/a".into(),
            },
            Command {
                old_id: oid("3333333333333333333333333333333333333333"),
                new_id: oid("0000000000000000000000000000000000000000"),
                refname: "refs/heads/b".into(),
            },
        ]);
        let mut resp = Vec::new();
        let hooks = ServeHooks {
            pre_receive: None,
            update: Some(Box::new(|cmd, _opts| {
                if cmd.refname == "refs/heads/b" {
                    Err(BString::from("b is protected"))
                } else {
                    Ok(())
                }
            })),
            post_receive: None,
        };
        let updater_calls = std::cell::Cell::new(0u32);
        let _ = serve_with_hooks(
            req.as_slice(),
            &mut resp,
            |_r| Ok(()),
            |cmds, _| {
                updater_calls.set(updater_calls.get() + 1);
                Ok(cmds.iter().map(|_| UpdateOutcome::accepted()).collect())
            },
            hooks,
        )
        .expect("serve ok");
        assert_eq!(
            updater_calls.get(),
            0,
            "atomic push with hook rejection must not invoke the ref updater"
        );
        assert!(resp
            .windows(b"ng refs/heads/b b is protected".len())
            .any(|w| w == b"ng refs/heads/b b is protected"));
        assert!(
            resp.windows(b"ng refs/heads/a".len()).any(|w| w == b"ng refs/heads/a"),
            "sibling command must also be rejected under atomic push"
        );
        assert!(
            resp.windows(b"atomic push".len()).any(|w| w == b"atomic push"),
            "sibling rejection reason must cite the atomic policy"
        );
    }

    #[test]
    fn non_atomic_push_with_update_hook_rejection_still_runs_updater() {
        let req = build_request(
            vec![
                Command {
                    old_id: oid("1111111111111111111111111111111111111111"),
                    new_id: oid("0000000000000000000000000000000000000000"),
                    refname: "refs/heads/a".into(),
                },
                Command {
                    old_id: oid("3333333333333333333333333333333333333333"),
                    new_id: oid("0000000000000000000000000000000000000000"),
                    refname: "refs/heads/b".into(),
                },
            ],
            &["report-status", "delete-refs"],
        );
        let mut resp = Vec::new();
        let hooks = ServeHooks {
            pre_receive: None,
            update: Some(Box::new(|cmd, _opts| {
                if cmd.refname == "refs/heads/b" {
                    Err(BString::from("b is protected"))
                } else {
                    Ok(())
                }
            })),
            post_receive: None,
        };
        let updater_calls = std::cell::Cell::new(0u32);
        let _ = serve_with_hooks(
            req.as_slice(),
            &mut resp,
            |_r| Ok(()),
            |cmds, _| {
                updater_calls.set(updater_calls.get() + 1);
                Ok(cmds.iter().map(|_| UpdateOutcome::accepted()).collect())
            },
            hooks,
        )
        .expect("serve ok");
        assert_eq!(
            updater_calls.get(),
            1,
            "non-atomic push runs the updater even when a sibling is rejected"
        );
        assert!(resp.windows(b"ok refs/heads/a".len()).any(|w| w == b"ok refs/heads/a"));
        assert!(resp
            .windows(b"ng refs/heads/b b is protected".len())
            .any(|w| w == b"ng refs/heads/b b is protected"));
    }

    #[test]
    fn update_hook_overlays_rejection_over_updater_outcome() {
        let req = build_request(
            vec![
                Command {
                    old_id: oid("1111111111111111111111111111111111111111"),
                    new_id: oid("0000000000000000000000000000000000000000"),
                    refname: "refs/heads/a".into(),
                },
                Command {
                    old_id: oid("3333333333333333333333333333333333333333"),
                    new_id: oid("0000000000000000000000000000000000000000"),
                    refname: "refs/heads/b".into(),
                },
            ],
            &["report-status", "delete-refs"],
        );
        let mut resp = Vec::new();
        let hooks = ServeHooks {
            pre_receive: None,
            update: Some(Box::new(|cmd, _opts| {
                if cmd.refname == "refs/heads/b" {
                    Err(BString::from("b is protected"))
                } else {
                    Ok(())
                }
            })),
            post_receive: None,
        };
        let _ = serve_with_hooks(
            req.as_slice(),
            &mut resp,
            |_r| Ok(()),
            |cmds, _| Ok(cmds.iter().map(|_| UpdateOutcome::accepted()).collect()),
            hooks,
        )
        .expect("serve ok");
        // a was accepted by both hook and updater, b rejected by hook.
        assert!(resp.windows(b"ok refs/heads/a".len()).any(|w| w == b"ok refs/heads/a"));
        assert!(resp
            .windows(b"ng refs/heads/b b is protected".len())
            .any(|w| w == b"ng refs/heads/b b is protected"));
    }

    #[test]
    fn post_receive_hook_sees_final_outcomes() {
        let req = build_request(
            vec![Command {
                old_id: oid("1111111111111111111111111111111111111111"),
                new_id: oid("2222222222222222222222222222222222222222"),
                refname: "refs/heads/main".into(),
            }],
            &["report-status"],
        );
        let mut resp = Vec::new();
        let observed = std::rc::Rc::new(std::cell::RefCell::new((
            Vec::<Command>::new(),
            Vec::<UpdateOutcome>::new(),
        )));
        let observed_hook = observed.clone();
        let hooks = ServeHooks {
            pre_receive: None,
            update: None,
            post_receive: Some(Box::new(move |cmds, outs, _opts| {
                let mut slot = observed_hook.borrow_mut();
                slot.0 = cmds.to_vec();
                slot.1 = outs.to_vec();
            })),
        };
        let _ = serve_with_hooks(
            req.as_slice(),
            &mut resp,
            |_r| Ok(()),
            |cmds, _| Ok(cmds.iter().map(|_| UpdateOutcome::accepted()).collect()),
            hooks,
        )
        .expect("serve ok");
        let observed = observed.borrow();
        assert_eq!(observed.0.len(), 1);
        assert_eq!(observed.1, vec![UpdateOutcome::accepted()]);
    }

    #[test]
    fn updater_mismatch_returns_typed_error() {
        let req = build_request(
            vec![
                Command {
                    old_id: oid("1111111111111111111111111111111111111111"),
                    new_id: oid("2222222222222222222222222222222222222222"),
                    refname: "refs/heads/a".into(),
                },
                Command {
                    old_id: oid("3333333333333333333333333333333333333333"),
                    new_id: oid("4444444444444444444444444444444444444444"),
                    refname: "refs/heads/b".into(),
                },
            ],
            &["report-status"],
        );
        let mut resp = Vec::new();
        let err = serve(
            req.as_slice(),
            &mut resp,
            |_r| Ok(()),
            |_cmds, _atomic| Ok(vec![UpdateOutcome::accepted()]), // only 1 for 2 commands
        )
        .expect_err("mismatch");
        assert!(matches!(
            err,
            ServeError::UpdaterMismatch {
                expected: 2,
                returned: 1
            }
        ));
    }

    /// When the client advertises `push-options`, the serve loop must
    /// drain the pkt-line section that follows the command-list and
    /// surface the parsed options on `ServeOutcome`. The trailing
    /// flush-pkt before the (empty) pack must be consumed so the pack
    /// ingester sees a clean stream boundary.
    #[test]
    fn serve_parses_push_options_when_negotiated() {
        use gix_packetline::blocking_io::encode;
        // Build the request by hand to put `push-options` directly in
        // the first-line capability list. Going through Arguments
        // would require a reciprocal advertisement, which isn't the
        // shape the server cares about here.
        let mut req: Vec<u8> = Vec::new();
        let old = "1111111111111111111111111111111111111111";
        let new = "0000000000000000000000000000000000000000";
        let first_line = format!("{old} {new} refs/heads/stale\0report-status push-options delete-refs\n");
        encode::data_to_write(first_line.as_bytes(), &mut req).unwrap();
        encode::flush_to_write(&mut req).unwrap();
        // Push-options section: two option lines + flush-pkt.
        encode::data_to_write(b"ci.skip", &mut req).unwrap();
        encode::data_to_write(b"merge-request-title=WIP", &mut req).unwrap();
        encode::flush_to_write(&mut req).unwrap();

        let mut resp = Vec::new();
        let outcome = serve(
            req.as_slice(),
            &mut resp,
            |_r| Ok(()),
            |cmds, _atomic| Ok(cmds.iter().map(|_| UpdateOutcome::accepted()).collect()),
        )
        .expect("serve ok");

        assert!(outcome.requested_capabilities.has("push-options"));
        assert_eq!(
            outcome.push_options,
            vec![BString::from("ci.skip"), BString::from("merge-request-title=WIP")],
            "both push-option lines must round-trip into the outcome"
        );
    }

    /// When the client selects `side-band-64k`, every report pkt-line
    /// must ride on channel 1, and the outer stream is terminated by a
    /// raw (unbanded) flush-pkt. Matches the wire shape upstream
    /// `git receive-pack` produces.
    #[test]
    fn report_rides_channel_one_when_side_band_64k_selected() {
        let req = build_request(
            vec![Command {
                old_id: oid("1111111111111111111111111111111111111111"),
                new_id: oid("2222222222222222222222222222222222222222"),
                refname: "refs/heads/main".into(),
            }],
            &["report-status", "side-band-64k"],
        );
        let mut resp = Vec::new();
        let _ = serve(
            req.as_slice(),
            &mut resp,
            |_r| Ok(()),
            |cmds, _atomic| Ok(cmds.iter().map(|_| UpdateOutcome::accepted()).collect()),
        )
        .expect("serve ok");

        // Walk the outer pkt-line stream. Every data pkt-line must be a
        // band-1 frame; reassemble the band-1 payloads and parse them
        // as an inner pkt-line stream carrying the report lines.
        let mut outer = gix_packetline::blocking_io::StreamingPeekableIter::new(
            resp.as_slice(),
            &[gix_packetline::PacketLineRef::Flush],
            false,
        );
        let mut inner_bytes: Vec<u8> = Vec::new();
        let mut saw_any_band_frame = false;
        while let Some(Ok(Ok(line))) = outer.read_line() {
            let data = line.as_slice().expect("every data pkt-line is a band frame");
            assert_eq!(data[0], 1, "every report frame must be on channel 1");
            inner_bytes.extend_from_slice(&data[1..]);
            saw_any_band_frame = true;
        }
        assert!(
            saw_any_band_frame,
            "at least one band-1 frame is expected for a non-empty report"
        );

        let mut inner = gix_packetline::blocking_io::StreamingPeekableIter::new(
            inner_bytes.as_slice(),
            &[gix_packetline::PacketLineRef::Flush],
            false,
        );
        let mut report_payloads: Vec<Vec<u8>> = Vec::new();
        while let Some(Ok(Ok(line))) = inner.read_line() {
            if let Some(body) = line.as_slice() {
                report_payloads.push(body.to_vec());
            } else {
                break;
            }
        }
        let parsed = push::report_status::parse_report_v1(report_payloads.iter().map(Vec::as_slice))
            .expect("report parses out of the reassembled band-1 payload");
        assert_eq!(parsed.unpack, push::UnpackStatus::Ok);
        assert_eq!(parsed.commands.len(), 1);
        assert!(matches!(parsed.commands[0], push::CommandStatus::Ok { .. }));
    }

    /// Deletion commands are rejected with `deletion prohibited`
    /// when `allow_deletes: false` is set, while non-deletion commands
    /// in the same batch flow through the updater untouched.
    #[test]
    fn mixed_batch_rejects_deletions_when_allow_deletes_is_false() {
        let req = build_request(
            vec![
                Command {
                    old_id: oid("1111111111111111111111111111111111111111"),
                    new_id: oid("0000000000000000000000000000000000000000"),
                    refname: "refs/heads/stale".into(),
                },
                Command {
                    old_id: oid("2222222222222222222222222222222222222222"),
                    new_id: oid("3333333333333333333333333333333333333333"),
                    refname: "refs/heads/main".into(),
                },
            ],
            &["report-status", "delete-refs"],
        );

        let mut resp = Vec::new();
        let updater_saw = std::cell::RefCell::new(Vec::<BString>::new());
        let pack_ingester_ran = std::cell::Cell::new(false);
        let _ = serve_with_options_and_hooks(
            req.as_slice(),
            &mut resp,
            |_r| {
                pack_ingester_ran.set(true);
                Ok(())
            },
            |cmds, _atomic| {
                for c in cmds {
                    updater_saw.borrow_mut().push(c.refname.clone());
                }
                Ok(cmds.iter().map(|_| UpdateOutcome::accepted()).collect())
            },
            ServeHooks::default(),
            ServeOptions { allow_deletes: false },
        )
        .expect("serve ok");

        assert!(
            pack_ingester_ran.get(),
            "mixed batch still carries a pack — the ingester must run"
        );
        let saw = updater_saw.into_inner();
        assert_eq!(
            saw,
            vec![BString::from("refs/heads/main")],
            "updater must receive only the non-deletion command"
        );

        // Parse the report: unpack ok; refs/heads/stale is ng, refs/heads/main is ok.
        let mut stream = gix_packetline::blocking_io::StreamingPeekableIter::new(
            resp.as_slice(),
            &[gix_packetline::PacketLineRef::Flush],
            false,
        );
        let mut payloads: Vec<Vec<u8>> = Vec::new();
        while let Some(Ok(Ok(line))) = stream.read_line() {
            if let Some(body) = line.as_slice() {
                payloads.push(body.to_vec());
            } else {
                break;
            }
        }
        let parsed = push::report_status::parse_report_v1(payloads.iter().map(Vec::as_slice)).expect("parses");
        assert_eq!(parsed.unpack, push::UnpackStatus::Ok);
        assert_eq!(parsed.commands.len(), 2);
        match &parsed.commands[0] {
            push::CommandStatus::Rejected { refname, reason } => {
                assert_eq!(refname.as_slice(), b"refs/heads/stale");
                assert!(
                    reason.as_slice().starts_with(b"deletion prohibited"),
                    "forbidden-deletion reason must cite the policy"
                );
            }
            other => panic!("expected ng on refs/heads/stale, got {other:?}"),
        }
        assert!(matches!(&parsed.commands[1], push::CommandStatus::Ok { refname } if refname == "refs/heads/main"));
    }

    /// All-deletion batch with `allow_deletes: false` skips pack
    /// ingestion entirely — a spec-compliant client never sends a pack
    /// for a delete-only push — and reports `ng deletion prohibited`
    /// for every command.
    #[test]
    fn all_deletion_batch_skips_pack_ingestion_when_allow_deletes_is_false() {
        let req = build_request(
            vec![
                Command {
                    old_id: oid("1111111111111111111111111111111111111111"),
                    new_id: oid("0000000000000000000000000000000000000000"),
                    refname: "refs/heads/stale-one".into(),
                },
                Command {
                    old_id: oid("2222222222222222222222222222222222222222"),
                    new_id: oid("0000000000000000000000000000000000000000"),
                    refname: "refs/heads/stale-two".into(),
                },
            ],
            &["report-status", "delete-refs"],
        );

        let mut resp = Vec::new();
        let pack_ingester_ran = std::cell::Cell::new(false);
        let updater_ran = std::cell::Cell::new(false);
        let _ = serve_with_options_and_hooks(
            req.as_slice(),
            &mut resp,
            |_r| {
                pack_ingester_ran.set(true);
                Ok(())
            },
            |_cmds, _atomic| {
                updater_ran.set(true);
                Ok(Vec::new())
            },
            ServeHooks::default(),
            ServeOptions { allow_deletes: false },
        )
        .expect("serve ok");

        assert!(!pack_ingester_ran.get(), "all-forbidden batch must skip pack ingestion");
        assert!(!updater_ran.get(), "all-forbidden batch must not invoke the updater");

        let mut stream = gix_packetline::blocking_io::StreamingPeekableIter::new(
            resp.as_slice(),
            &[gix_packetline::PacketLineRef::Flush],
            false,
        );
        let mut payloads: Vec<Vec<u8>> = Vec::new();
        while let Some(Ok(Ok(line))) = stream.read_line() {
            if let Some(body) = line.as_slice() {
                payloads.push(body.to_vec());
            } else {
                break;
            }
        }
        let parsed = push::report_status::parse_report_v1(payloads.iter().map(Vec::as_slice)).expect("parses");
        assert_eq!(parsed.unpack, push::UnpackStatus::Ok);
        assert_eq!(parsed.commands.len(), 2);
        for status in &parsed.commands {
            match status {
                push::CommandStatus::Rejected { reason, .. } => assert!(
                    reason.as_slice().starts_with(b"deletion prohibited"),
                    "every forbidden slot cites the policy"
                ),
                other => panic!("expected ng, got {other:?}"),
            }
        }
    }
}
