use gix::bstr::BString;

use crate::OutputFormat;

pub struct Options {
    pub format: OutputFormat,
    pub dry_run: bool,
    pub atomic: bool,
    /// Allow non-fast-forward updates on every refspec
    /// (`git push --force`). Per-refspec `+` prefixes are always
    /// honoured; this flag only widens what is allowed.
    pub force: bool,
    /// After a successful push, write `branch.<name>.{remote,merge}`
    /// for every local branch that was pushed, matching git's
    /// `-u` / `--set-upstream`.
    pub set_upstream: bool,
    pub quiet: bool,
    pub remote: Option<String>,
    /// If non-empty, override all ref-specs otherwise configured in the remote.
    pub ref_specs: Vec<BString>,
    /// Forwarded verbatim to the server's `push-options` section when
    /// the capability is advertised.
    pub push_options: Vec<BString>,
}

pub const PROGRESS_RANGE: std::ops::RangeInclusive<u8> = 1..=3;

pub(crate) mod function {
    use anyhow::{anyhow, bail, Context};
    use gix::bstr::ByteSlice;

    use super::Options;
    use crate::OutputFormat;

    pub fn push<P>(
        mut repo: gix::Repository,
        progress: P,
        mut out: impl std::io::Write,
        mut err: impl std::io::Write,
        Options {
            format,
            dry_run,
            atomic,
            force,
            set_upstream,
            quiet,
            remote,
            ref_specs,
            push_options,
        }: Options,
    ) -> anyhow::Result<()>
    where
        P: gix::NestedProgress,
        P::SubProgress: 'static,
    {
        if format != OutputFormat::Human {
            bail!("JSON output isn't yet supported for pushing.");
        }
        let remote = find_push_remote(&repo, remote.as_deref())?;
        // Always derive `remote_name_for_tracking`: `-u` needs it
        // explicitly, and `push.autoSetupRemote` may synthesise
        // tracking updates later whose write needs the same value.
        let remote_name_for_tracking = remote.name().map(|n| n.as_bstr().to_owned());
        if set_upstream && remote_name_for_tracking.is_none() {
            bail!("cannot --set-upstream: remote has no configured name");
        }
        let connection = remote.connect(gix::remote::Direction::Push)?;
        let tracking_pairs = push_with_connection(
            &remote,
            connection,
            progress,
            &mut out,
            &mut err,
            &gix::interrupt::IS_INTERRUPTED,
            PushParams {
                dry_run,
                atomic,
                force,
                set_upstream,
                quiet,
                ref_specs,
                push_options,
            },
        )?;
        drop(remote);
        if let (false, Some(remote_name)) = (tracking_pairs.is_empty(), remote_name_for_tracking) {
            let updates: Vec<gix::remote::push::TrackingUpdate> = tracking_pairs
                .into_iter()
                .map(|(local, remote_ref)| gix::remote::push::TrackingUpdate {
                    local_branch: local,
                    remote_ref,
                })
                .collect();
            match gix::remote::push::record_tracking(&mut repo, remote_name.as_ref(), &updates) {
                Ok(written) => {
                    for note in written {
                        writeln!(err, "{}", note.to_notice()).ok();
                    }
                }
                Err(error) => {
                    writeln!(err, "warning: could not record upstream tracking: {error}").ok();
                }
            }
        }
        Ok(())
    }

    /// Subset of [`Options`] that the post-`connect()` pipeline needs;
    /// the wire-time behaviours that [`push`] passes forward after the
    /// CLI-layer `format` and `remote` fields have done their job.
    pub(crate) struct PushParams {
        pub dry_run: bool,
        pub atomic: bool,
        pub force: bool,
        /// When `true`, the caller wants tracking config written for
        /// every local branch that was successfully pushed; the
        /// returned pairs are fed to [`gix::remote::push::record_tracking`].
        pub set_upstream: bool,
        pub quiet: bool,
        pub ref_specs: Vec<gix::bstr::BString>,
        pub push_options: Vec<gix::bstr::BString>,
    }

    /// Post-`connect()` body of [`push`], isolated so tests can drive a
    /// full CLI-layer push against an in-process receive-pack server
    /// without reaching for the subprocess transport that `connect()`
    /// would pick for a `file://` URL.
    ///
    /// The `should_interrupt` argument lets tests thread a local
    /// interrupt flag instead of the global `gix::interrupt::IS_INTERRUPTED`
    /// singleton — mandatory for reliable parallel test execution.
    pub(crate) fn push_with_connection<T, P>(
        remote: &gix::Remote<'_>,
        connection: gix::remote::Connection<'_, '_, T>,
        mut progress: P,
        mut out: impl std::io::Write,
        mut err: impl std::io::Write,
        should_interrupt: &std::sync::atomic::AtomicBool,
        PushParams {
            dry_run,
            atomic,
            force,
            set_upstream,
            quiet,
            ref_specs,
            push_options,
        }: PushParams,
    ) -> anyhow::Result<Vec<(gix::bstr::BString, gix::bstr::BString)>>
    where
        T: gix::protocol::transport::client::blocking_io::Transport,
        P: gix::NestedProgress,
        P::SubProgress: 'static,
    {
        let repo = remote.repo();
        let mut prepare = connection
            .prepare_push(&mut progress)?
            .with_atomic(atomic)
            .with_force(force)
            .with_quiet(quiet)
            .with_dry_run(dry_run);
        if !push_options.is_empty() {
            prepare = prepare.with_push_options(push_options);
        }
        let refspecs_were_explicit = !ref_specs.is_empty();
        prepare = if refspecs_were_explicit {
            prepare.with_refspecs(ref_specs.iter().map(AsRef::<gix::bstr::BStr>::as_ref))?
        } else {
            // Mirror `Remote::push`'s fallback chain: first try
            // `remote.<name>.push` from git-config, then fall back to
            // `push.default` via `branch_remote_ref_name(.., Push)`
            // which already encodes the nothing / current / matching /
            // upstream / simple semantics.
            let from_config = prepare.with_remote_push_specs(remote)?;
            if from_config.commands().is_empty() {
                match gix::remote::push::push_default_target(repo) {
                    Some(target) => {
                        let specs = [target];
                        from_config.with_refspecs(specs.iter().map(AsRef::<gix::bstr::BStr>::as_ref))?
                    }
                    None => from_config,
                }
            } else {
                from_config
            }
        };
        if prepare.commands().is_empty() && !refspecs_were_explicit {
            let branch = repo
                .head_name()
                .ok()
                .flatten()
                .map(|n| n.shorten().to_string())
                .unwrap_or_else(|| "HEAD".into());
            let remote_hint = remote
                .name()
                .map(|n| n.as_bstr().to_string())
                .unwrap_or_else(|| "<remote>".into());
            bail!(
                "current branch `{branch}` has no configured push refspec and no `push.default` target. \
                 Pass an explicit refspec, e.g. `gix push {remote_hint} {branch}`."
            );
        }
        // Compute the "effective" set-upstream bit: `-u` forces it
        // unconditionally, `push.autoSetupRemote=true` + valid
        // `push.default` triggers it for any local branch that has no
        // prior upstream (the git 2.37+ `simple|upstream|current`
        // carve-out).
        let auto_setup_active = !set_upstream && auto_setup_applies(repo);
        let want_tracking = set_upstream || auto_setup_active;
        let mut intended_tracking: Vec<(gix::bstr::BString, gix::bstr::BString)> = if want_tracking {
            intended_tracking_pairs(repo, &ref_specs, refspecs_were_explicit, prepare.commands())
        } else {
            Vec::new()
        };
        if auto_setup_active {
            intended_tracking.retain(|(local, _)| !branch_has_upstream(repo, local.as_ref()));
        }
        // Short-circuit when every resolved command is a no-op: local
        // and remote refs already match. See `commands_are_all_noop`
        // for the predicate and `git push`'s `Everything up-to-date`
        // parity rationale.
        if commands_are_all_noop(prepare.commands()) {
            writeln!(out, "Everything up-to-date")?;
            return Ok(intended_tracking);
        }
        let outcome = prepare.send_with_generated_pack(&mut progress, should_interrupt)?;

        let report = &outcome.report;
        let unpack_status = match &report.report {
            gix::protocol::push::ReportKind::V1(r) => &r.unpack,
            gix::protocol::push::ReportKind::V2(r) => &r.unpack,
        };
        match unpack_status {
            gix::protocol::push::UnpackStatus::Ok => writeln!(out, "unpack: ok")?,
            gix::protocol::push::UnpackStatus::Failed(reason) => writeln!(err, "unpack: failed ({reason})")?,
        }
        writeln!(
            out,
            "accepted: {accepted}, rejected: {rejected}",
            accepted = report.accepted_count(),
            rejected = report.rejected_count(),
        )?;
        for (refname, status) in report.command_statuses() {
            match status {
                Ok(_options) => writeln!(out, "\t{refname} ok")?,
                Err(reason) => writeln!(err, "\t{refname} ng {reason}")?,
            }
        }
        // Server-side progress arrives as side-band channel-2 pkt-lines
        // the transport collected while we waited for `report-status`.
        // See `should_skip_server_progress_tick` for the filter
        // rationale — summary: collapse the 100+ `Resolving deltas:
        // N%` ticks a big push emits into just their `done.` line, so
        // they stop fighting the TUI for terminal rows.
        for line in &outcome.report.progress {
            let text = line.to_string();
            if should_skip_server_progress_tick(&text) {
                continue;
            }
            writeln!(err, "remote: {text}")?;
        }
        if dry_run {
            writeln!(out, "DRY-RUN: No pack was sent and no ref was updated on the remote.").ok();
        }
        if !report.is_success() {
            match unpack_status {
                gix::protocol::push::UnpackStatus::Failed(reason) => {
                    bail!("push failed: server could not unpack the pack ({reason})");
                }
                gix::protocol::push::UnpackStatus::Ok => {
                    bail!("push failed: {} rejected ref(s)", report.rejected_count());
                }
            }
        }
        let tracking_pairs = if want_tracking {
            let succeeded: Vec<&gix::bstr::BStr> = report
                .command_statuses()
                .filter_map(|(refname, status)| status.as_ref().ok().map(|_| refname))
                .collect();
            intended_tracking
                .into_iter()
                .filter(|(_, remote_ref)| {
                    let needle: &gix::bstr::BStr = remote_ref.as_ref();
                    succeeded.iter().any(|ok| *ok == needle)
                })
                .collect()
        } else {
            Vec::new()
        };
        Ok(tracking_pairs)
    }

    /// Return `true` when `push.autoSetupRemote=true` and
    /// `push.default ∈ {simple, upstream, current}`, i.e. the git 2.37+
    /// carve-out where a successful push auto-configures tracking for
    /// branches that have no prior upstream.
    fn auto_setup_applies(repo: &gix::Repository) -> bool {
        let snapshot = repo.config_snapshot();
        if !snapshot.boolean("push.autoSetupRemote").unwrap_or(false) {
            return false;
        }
        let default_raw = match snapshot.string("push.default") {
            Some(v) => v,
            None => return true, // git's default is `simple`
        };
        let bytes: &[u8] = default_raw.as_ref().as_ref();
        matches!(bytes, b"simple" | b"upstream" | b"current")
    }

    /// Return `true` when `branch.<local>.merge` is already set; the
    /// `autoSetupRemote` path must not overwrite an existing upstream
    /// per git's behaviour.
    fn branch_has_upstream(repo: &gix::Repository, local: &gix::bstr::BStr) -> bool {
        use gix::bstr::ByteSlice;
        let key = match local.to_str() {
            Ok(s) if !s.is_empty() => format!("branch.{s}.merge"),
            _ => return false,
        };
        repo.config_snapshot().string(&key).is_some()
    }

    /// Derive `(local_branch_short, remote_full_ref)` pairs from the
    /// raw refspec strings the user passed, so the CLI can write
    /// `branch.<local>.{remote,merge}` for every local branch pushed
    /// under `-u`. Entries whose source is not a local branch
    /// (`refs/heads/<name>`) are filtered out: git's `--set-upstream`
    /// only configures tracking for local-branch sources.
    fn intended_tracking_pairs(
        repo: &gix::Repository,
        ref_specs: &[gix::bstr::BString],
        refspecs_were_explicit: bool,
        commands: &[gix::protocol::push::Command],
    ) -> Vec<(gix::bstr::BString, gix::bstr::BString)> {
        use gix::bstr::{BStr, BString, ByteSlice};
        let local_short = |src: &BStr| -> Option<BString> {
            if let Some(rest) = src.strip_prefix(b"refs/heads/") {
                return Some(rest.as_bstr().to_owned());
            }
            if src.contains(&b'/') || src.is_empty() {
                return None;
            }
            Some(src.to_owned())
        };
        let to_full_remote_ref = |dst: &BStr| -> BString {
            if dst.starts_with(b"refs/") {
                dst.to_owned()
            } else {
                let mut full = BString::from("refs/heads/");
                full.extend_from_slice(dst);
                full
            }
        };
        if !refspecs_were_explicit {
            let Some(head) = repo.head_name().ok().flatten() else {
                return Vec::new();
            };
            let head_short = head.shorten().to_owned();
            return commands
                .iter()
                .map(|cmd| (head_short.clone(), cmd.refname.clone()))
                .collect();
        }
        let mut pairs = Vec::new();
        for raw in ref_specs {
            let Ok(parsed) = gix::refspec::parse(raw.as_ref(), gix::refspec::parse::Operation::Push) else {
                continue;
            };
            let Some(src) = parsed.source() else { continue };
            let Some(dst) = parsed.destination() else { continue };
            let Some(local) = local_short(src) else { continue };
            let remote_ref = to_full_remote_ref(dst);
            if commands.iter().any(|cmd| cmd.refname == remote_ref) {
                pairs.push((local, remote_ref));
            }
        }
        pairs
    }

    /// Resolve a [`gix::Remote`] for `Direction::Push`.
    ///
    /// Mirrors the shape of `Repository::find_fetch_remote` but consults the
    /// push-direction config chain (`branch.<name>.pushRemote` →
    /// `remote.pushDefault` → fetch remote) so that repositories which
    /// configure push and fetch against different hosts — a common pattern
    /// for read-only mirrors and deploy keys — pick the right endpoint
    /// automatically when the user runs `gix push` with no explicit remote.
    fn find_push_remote<'repo>(
        repo: &'repo gix::Repository,
        name_or_url: Option<&str>,
    ) -> anyhow::Result<gix::Remote<'repo>> {
        if let Some(name) = name_or_url {
            let bytes: &gix::bstr::BStr = name.as_bytes().as_bstr();
            if let Some(result) = repo.try_find_remote(bytes) {
                return result.map_err(Into::into);
            }
            let url = gix::url::parse(bytes).with_context(|| format!("not a known remote name or URL: `{name}`"))?;
            return Ok(repo.remote_at(url)?);
        }
        if let Some(head) = repo.head().ok().and_then(|h| h.into_remote(gix::remote::Direction::Push).transpose().ok().flatten())
        {
            return Ok(head);
        }
        match repo.find_default_remote(gix::remote::Direction::Push) {
            Some(result) => Ok(result?),
            None => Err(anyhow!(
                "no remote is configured for the current branch; pass one as `gix push <remote> [<refspec>...]`"
            )),
        }
    }

    /// Return `true` when every resolved push command has matching
    /// `old_id` and `new_id` — i.e. the local branch already points
    /// at the OID the remote advertised during the handshake.
    ///
    /// Matches `git push`'s `Everything up-to-date` client-side
    /// short-circuit. Rationale for mirroring the behaviour:
    ///
    /// 1. Round-trip avoidance: pack generation, upload, server-side
    ///    `index-pack`, and the ref transaction all happen against a
    ///    nothing-to-do push. The server accepts silently and closes;
    ///    the user waits for a no-op.
    /// 2. HTTP 403 / 401 avoidance: some hosts reject even no-op
    ///    pushes when the caller lacks write access, which surfaces
    ///    as a confusing `Received HTTP status 403` when the intent
    ///    was "nothing to push anyway".
    ///
    /// Returns `false` for the empty command list so callers still
    /// reach the "nothing to push — did you mean `<remote> <branch>`?"
    /// diagnostic path (no commands is a refspec-resolution problem,
    /// not a no-op). Create (old zero) and delete (new zero) commands
    /// are never considered no-ops even when OIDs happen to match.
    pub(crate) fn commands_are_all_noop(commands: &[gix::protocol::push::Command]) -> bool {
        !commands.is_empty()
            && commands
                .iter()
                .all(|cmd| !cmd.is_create() && !cmd.is_delete() && cmd.old_id == cmd.new_id)
    }

    /// Return `true` when `line` is an intermediate server-side
    /// progress-tick that should be dropped from the output.
    ///
    /// Side-band channel-2 from a remote receive-pack carries pkt-line
    /// frames like `Resolving deltas:  47% (121/258)` (one per percent
    /// step the server crosses). A single real-world push surfaces
    /// ~100 of these, and the transport replays them *en masse* after
    /// the client-side progress TUI has drawn its final frame — they
    /// fight for terminal rows and scroll everything else off screen.
    ///
    /// We keep the corresponding `... done.` line for each phase so
    /// users still see completion, and we pass through every other
    /// `remote:` line verbatim (post-receive banners like GitHub's
    /// "Create a pull request for ...", GitLab's merge-request hint,
    /// hook output, server errors).
    pub(crate) fn should_skip_server_progress_tick(line: &str) -> bool {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return true;
        }
        const PROGRESS_VERBS: &[&str] = &[
            "Resolving deltas:",
            "Counting objects:",
            "Compressing objects:",
            "Writing objects:",
        ];
        let is_tick = PROGRESS_VERBS.iter().any(|verb| trimmed.starts_with(verb));
        is_tick && !trimmed.contains("done.")
    }

    #[cfg(test)]
    mod tests {
        use super::{commands_are_all_noop, push, should_skip_server_progress_tick};
        use crate::OutputFormat;

        /// Build a default `Options` value for the given `format`, with
        /// no remote, no refspecs, and every boolean cleared. Lets each
        /// test name only the field it actually wants to vary.
        fn opts(format: OutputFormat) -> super::Options {
            super::Options {
                format,
                dry_run: false,
                atomic: false,
                force: false,
                set_upstream: false,
                quiet: false,
                remote: None,
                ref_specs: Vec::new(),
                push_options: Vec::new(),
            }
        }

        #[cfg(feature = "serde")]
        #[test]
        fn push_rejects_json_output_format() -> anyhow::Result<()> {
            // JSON output isn't wired up for push yet; the CLI must
            // surface a clear "not yet supported" error instead of
            // falling through to a partial push with a wrong format.
            let tmp = tempfile::tempdir()?;
            let repo = gix::open_opts(gix::init_bare(tmp.path())?.path(), gix::open::Options::isolated())?;
            let err = push(
                repo,
                gix::progress::Discard,
                std::io::sink(),
                std::io::sink(),
                opts(OutputFormat::Json),
            )
            .expect_err("Json output must bail before any network I/O");
            assert!(
                err.to_string().contains("JSON output"),
                "wrong error surface for Json format: {err}",
            );
            Ok(())
        }

        #[test]
        fn push_bails_when_no_remote_is_configured() -> anyhow::Result<()> {
            // A fresh bare repo with no remotes configured and no
            // explicit `--remote` arg must yield a clean "no remote is
            // configured" diagnostic from `find_push_remote` rather
            // than an opaque downstream error.
            let tmp = tempfile::tempdir()?;
            let repo = gix::open_opts(gix::init_bare(tmp.path())?.path(), gix::open::Options::isolated())?;
            let err = push(
                repo,
                gix::progress::Discard,
                std::io::sink(),
                std::io::sink(),
                opts(OutputFormat::Human),
            )
            .expect_err("missing remote config must bail before any network I/O");
            assert!(
                err.to_string().contains("no remote is configured"),
                "wrong error surface for missing remote config: {err}",
            );
            Ok(())
        }

        /// End-to-end flow tests that exercise `push_with_connection`
        /// against an in-process receive-pack, letting us cover the
        /// report-formatting branches (dry-run notice, "Everything
        /// up-to-date" short-circuit, rejected-refs bail, empty-refspec
        /// fallback) without spawning a subprocess or opening a
        /// network socket.
        #[cfg(all(feature = "blocking-client"))]
        mod flow {
            use std::sync::atomic::AtomicBool;

            use super::super::{push_with_connection, PushParams};

            /// Build a bare repo on `path` with deterministic committer
            /// fields and a single commit on `refs/heads/main` whose
            /// message is `message`. Distinct `message` values guarantee
            /// distinct commit OIDs across otherwise-identical repos,
            /// which is how tests stage scenarios like non-fast-forward.
            ///
            /// Also pins `push.autoSetupRemote=false` and
            /// `push.default=nothing` on the repo's own config so tests
            /// are hermetic against a host git-config that may set
            /// either to `true` / non-default. Without these overrides
            /// `push_default_target` can synthesise a refspec from the
            /// current branch name and mask the "no configured
            /// refspec" bail we want to test.
            fn seeded_bare_repo(
                path: &std::path::Path,
                message: &str,
            ) -> anyhow::Result<(gix::Repository, gix::hash::ObjectId)> {
                let mut repo = gix::init_bare(path)?;
                let mut cfg = repo.config_snapshot_mut();
                cfg.set_raw_value(gix::config::tree::Author::NAME, "Test Author")?;
                cfg.set_raw_value(gix::config::tree::Author::EMAIL, "test@example.com")?;
                cfg.set_raw_value(gix::config::tree::Committer::NAME, "Test Author")?;
                cfg.set_raw_value(gix::config::tree::Committer::EMAIL, "test@example.com")?;
                cfg.set_raw_value("push.autoSetupRemote", "false")?;
                cfg.set_raw_value("push.default", "nothing")?;
                cfg.commit()?;
                let tree = gix::objs::Tree { entries: vec![] };
                let tree_id = repo.write_object(&tree)?.detach();
                let commit = repo
                    .commit("refs/heads/main", message, tree_id, gix::commit::NO_PARENT_IDS)?
                    .detach();
                Ok((repo, commit))
            }

            fn push_params(ref_specs: &[&str], dry_run: bool, atomic: bool) -> PushParams {
                PushParams {
                    dry_run,
                    atomic,
                    force: false,
                    set_upstream: false,
                    quiet: true,
                    ref_specs: ref_specs.iter().map(|s| gix::bstr::BString::from(*s)).collect(),
                    push_options: Vec::new(),
                }
            }

            /// Drive `push_with_connection` from `src` against `dst`'s
            /// in-process receive-pack, returning captured stdout and
            /// stderr. The placeholder URL is never dereferenced: the
            /// transport is pre-built and attached via
            /// `to_connection_with_transport`.
            fn run_push(
                src: &gix::Repository,
                dst: &gix::Repository,
                params: PushParams,
            ) -> anyhow::Result<(String, String)> {
                let transport = dst.in_process_receive_pack_transport();
                let remote = src.remote_at("file:///in-process-placeholder")?;
                let connection = remote.to_connection_with_transport(transport);
                let should_interrupt = AtomicBool::new(false);
                let mut out = Vec::<u8>::new();
                let mut err = Vec::<u8>::new();
                push_with_connection(
                    &remote,
                    connection,
                    gix::progress::Discard,
                    &mut out,
                    &mut err,
                    &should_interrupt,
                    params,
                )?;
                Ok((String::from_utf8(out)?, String::from_utf8(err)?))
            }

            #[test]
            fn everything_up_to_date_short_circuits_before_pack_generation() -> anyhow::Result<()> {
                let src_tmp = tempfile::tempdir()?;
                let dst_tmp = tempfile::tempdir()?;
                let (src, _) = seeded_bare_repo(src_tmp.path(), "shared seed")?;
                let dst = gix::init_bare(dst_tmp.path())?;
                // First push populates dst so its `refs/heads/main`
                // matches src's OID.
                run_push(&src, &dst, push_params(&["refs/heads/main:refs/heads/main"], false, false))?;
                // Second push: server's advertised OID matches local,
                // so every resolved command is a no-op.
                let (out, _err) =
                    run_push(&src, &dst, push_params(&["refs/heads/main:refs/heads/main"], false, false))?;
                assert!(
                    out.contains("Everything up-to-date"),
                    "expected short-circuit notice, got stdout: {out:?}",
                );
                // Short-circuit fires BEFORE `send_with_generated_pack`,
                // so no unpack/accepted lines should appear.
                assert!(
                    !out.contains("unpack:"),
                    "short-circuit must skip the report path, got stdout: {out:?}",
                );
                Ok(())
            }

            #[test]
            fn dry_run_synthesises_success_and_appends_dry_run_notice() -> anyhow::Result<()> {
                let src_tmp = tempfile::tempdir()?;
                let dst_tmp = tempfile::tempdir()?;
                let (src, _) = seeded_bare_repo(src_tmp.path(), "dry-run seed")?;
                let dst = gix::init_bare(dst_tmp.path())?;
                let (out, _err) =
                    run_push(&src, &dst, push_params(&["refs/heads/main:refs/heads/main"], true, false))?;
                assert!(
                    out.contains("unpack: ok"),
                    "dry-run synthesises an ok report, got stdout: {out:?}",
                );
                assert!(
                    out.contains("DRY-RUN: No pack was sent"),
                    "dry-run notice missing from stdout: {out:?}",
                );
                // The ref must NOT actually land on dst - dry_run=true
                // short-circuits BEFORE send_with_generated_pack does
                // any network I/O.
                let dst_reopened = gix::open(dst.git_dir())?;
                assert!(
                    dst_reopened.try_find_reference("refs/heads/main")?.is_none(),
                    "dry-run must not update refs on dst",
                );
                Ok(())
            }

            /// Spawn an in-process receive-pack that unconditionally
            /// rejects every incoming command via its `pre_receive`
            /// hook. Lets tests exercise the CLI-layer rejected-refs
            /// bail path without relying on server-side non-ff
            /// semantics that gix's built-in receive-pack does not
            /// enforce by default.
            fn rejecting_in_process_transport(
                dst: &gix::Repository,
            ) -> gix::protocol::transport::client::git::blocking_io::Connection<
                gix::protocol::transport::client::blocking_io::in_process::ChannelReader,
                gix::protocol::transport::client::blocking_io::in_process::ChannelWriter,
            > {
                use gix::protocol::transport::{client::git, Protocol};
                let repo_sync = dst.clone().into_sync();
                let hash_name = dst.object_hash().to_string();
                let (client_reader, client_writer) =
                    gix::protocol::transport::client::blocking_io::in_process::spawn_server(
                        move |reader, mut writer| {
                            let repo = repo_sync.to_thread_local();
                            let options = gix::protocol::receive_pack::Options {
                                side_band_64k: false,
                                side_band: false,
                                object_format: Some(gix::bstr::BString::from(hash_name.as_str())),
                                ..Default::default()
                            };
                            repo.serve_receive_pack_info_refs(&mut writer, &options)
                                .map_err(|e| std::io::Error::other(e.to_string()))?;
                            let should_interrupt = std::sync::atomic::AtomicBool::new(false);
                            let mut progress = gix::features::progress::Discard;
                            let hooks = gix::protocol::receive_pack::ServeHooks {
                                pre_receive: Some(Box::new(|_commands, _options| {
                                    Err(gix::bstr::BString::from("policy rejects all"))
                                })),
                                ..Default::default()
                            };
                            let _ = repo
                                .serve_pack_receive_with_hooks(
                                    reader,
                                    &mut writer,
                                    &mut progress,
                                    &should_interrupt,
                                    hooks,
                                )
                                .map_err(|e| std::io::Error::other(e.to_string()))?;
                            Ok(())
                        },
                    );
                git::blocking_io::Connection::new(
                    client_reader,
                    client_writer,
                    Protocol::V1,
                    "in-process",
                    None::<(&str, _)>,
                    git::ConnectMode::Process,
                    false,
                )
            }

            #[test]
            fn rejected_refs_surface_as_push_failed_bail_with_count() -> anyhow::Result<()> {
                let src_tmp = tempfile::tempdir()?;
                let dst_tmp = tempfile::tempdir()?;
                let (src, _) = seeded_bare_repo(src_tmp.path(), "src seed")?;
                let (dst, _) = seeded_bare_repo(dst_tmp.path(), "dst seed")?;
                // A rejecting pre_receive hook on dst forces the server
                // to emit `ng` for every command regardless of pack
                // content, which is exactly the report shape the CLI's
                // "push failed: N rejected ref(s)" bail path handles.
                let transport = rejecting_in_process_transport(&dst);
                let remote = src.remote_at("file:///in-process-placeholder")?;
                let connection = remote.to_connection_with_transport(transport);
                let should_interrupt = AtomicBool::new(false);
                let mut out = Vec::<u8>::new();
                let mut err_buf = Vec::<u8>::new();
                let result = push_with_connection(
                    &remote,
                    connection,
                    gix::progress::Discard,
                    &mut out,
                    &mut err_buf,
                    &should_interrupt,
                    push_params(&["refs/heads/main:refs/heads/main"], false, false),
                );
                let err = result.expect_err("rejected commands must bail");
                let msg = err.to_string();
                assert!(
                    msg.contains("push failed") && msg.contains("rejected"),
                    "expected rejected-refs bail, got: {msg}",
                );
                // The per-command `ng` line lands on stderr.
                let err_out = String::from_utf8(err_buf)?;
                assert!(
                    err_out.contains("refs/heads/main ng"),
                    "expected per-command ng line on stderr, got: {err_out:?}",
                );
                Ok(())
            }

            #[test]
            fn empty_refspecs_with_no_config_fall_back_to_diagnostic() -> anyhow::Result<()> {
                let src_tmp = tempfile::tempdir()?;
                let dst_tmp = tempfile::tempdir()?;
                let (src, _) = seeded_bare_repo(src_tmp.path(), "fallback seed")?;
                let dst = gix::init_bare(dst_tmp.path())?;
                // Empty refspecs, no `remote.<name>.push` config, no
                // `push.default` and no `branch.<name>.{remote,merge}`
                // => commands resolve to empty => "no configured push
                // refspec" bail fires before any network work.
                let transport = dst.in_process_receive_pack_transport();
                let remote = src.remote_at("file:///in-process-placeholder")?;
                let connection = remote.to_connection_with_transport(transport);
                let should_interrupt = AtomicBool::new(false);
                let mut out = Vec::<u8>::new();
                let mut err_buf = Vec::<u8>::new();
                let result = push_with_connection(
                    &remote,
                    connection,
                    gix::progress::Discard,
                    &mut out,
                    &mut err_buf,
                    &should_interrupt,
                    push_params(&[], false, false),
                );
                let err = result.expect_err("missing refspec config must bail");
                assert!(
                    err.to_string().contains("has no configured push refspec"),
                    "wrong error surface, got: {err}",
                );
                Ok(())
            }
        }

        /// Construct a `push::Command` with the low byte of its two
        /// OIDs set to `old` and `new` respectively. `0u8` both
        /// legitimately and intentionally means the null OID — a create
        /// has `old == 0`, a delete has `new == 0`.
        fn cmd(old: u8, new: u8, refname: &str) -> gix::protocol::push::Command {
            let mut buf = [0u8; 20];
            buf[19] = old;
            let old_id = gix::hash::ObjectId::from_bytes_or_panic(&buf);
            buf[19] = new;
            let new_id = gix::hash::ObjectId::from_bytes_or_panic(&buf);
            gix::protocol::push::Command {
                old_id,
                new_id,
                refname: refname.into(),
            }
        }

        #[test]
        fn all_noop_is_false_for_an_empty_command_list() {
            // Empty → let the caller reach the diagnostic path.
            assert!(!commands_are_all_noop(&[]));
        }

        #[test]
        fn all_noop_detects_matching_old_and_new_ids() {
            assert!(commands_are_all_noop(&[cmd(1, 1, "refs/heads/main")]));
            assert!(commands_are_all_noop(&[
                cmd(1, 1, "refs/heads/main"),
                cmd(7, 7, "refs/heads/side"),
            ]));
        }

        #[test]
        fn all_noop_is_false_when_any_command_moves_a_ref() {
            assert!(!commands_are_all_noop(&[
                cmd(1, 1, "refs/heads/a"),
                cmd(2, 3, "refs/heads/b"),
            ]));
        }

        #[test]
        fn creates_are_never_noops_even_with_matching_raw_ids() {
            // Creates have a zero `old_id` by definition; they're not no-ops.
            assert!(!commands_are_all_noop(&[cmd(0, 5, "refs/heads/new")]));
        }

        #[test]
        fn deletes_are_never_noops() {
            // Deletes have a zero `new_id` by definition; they move work.
            assert!(!commands_are_all_noop(&[cmd(5, 0, "refs/heads/gone")]));
        }

        #[test]
        fn progress_tick_mid_phase_is_skipped() {
            assert!(should_skip_server_progress_tick("Resolving deltas:  47% (121/258)"));
            assert!(should_skip_server_progress_tick(
                "Counting objects:  10% (22/220)"
            ));
            assert!(should_skip_server_progress_tick(
                "Compressing objects:  50% (100/200)"
            ));
            assert!(should_skip_server_progress_tick(
                "Writing objects:  30% (60/200)"
            ));
        }

        #[test]
        fn progress_tick_terminal_done_line_is_kept() {
            // The trailing `done.` is the only tick a user cares
            // about — it confirms the phase finished.
            assert!(!should_skip_server_progress_tick(
                "Resolving deltas: 100% (258/258), done."
            ));
        }

        #[test]
        fn non_tick_remote_messages_are_kept() {
            // Post-receive banners from forges must survive.
            assert!(!should_skip_server_progress_tick(
                "Create a pull request for 'branch' on GitHub by visiting:"
            ));
            assert!(!should_skip_server_progress_tick(
                "    https://github.com/owner/repo/pull/new/branch"
            ));
            // Hook output should survive too.
            assert!(!should_skip_server_progress_tick(
                "pre-receive hook accepted"
            ));
        }

        #[test]
        fn empty_and_whitespace_only_lines_are_dropped() {
            assert!(should_skip_server_progress_tick(""));
            assert!(should_skip_server_progress_tick("   "));
            assert!(should_skip_server_progress_tick("\n"));
        }
    }
}
