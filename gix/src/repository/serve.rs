//! Serve-side endpoints for running `git-upload-pack` /
//! `git-receive-pack` out of a [`Repository`](crate::Repository).
//!
//! This module wires the `gix-protocol` state machines into a live
//! repository. Three surfaces are exposed:
//!
//! - **`info/refs` advertisements.**
//!   [`Repository::serve_upload_pack_info_refs`],
//!   [`Repository::serve_upload_pack_info_refs_v2`], and
//!   [`Repository::serve_receive_pack_info_refs`] walk the ref store
//!   and emit the framed pkt-line sequence an HTTP smart-protocol
//!   endpoint should return.
//!
//! - **Upload-pack (fetch) service.**
//!   [`Repository::serve_pack_upload_v2_auto`] and
//!   [`Repository::serve_pack_upload_v1_auto`] drive the full v2 and
//!   v0/v1 state machines respectively, generating the pack
//!   automatically from the local object database via
//!   [`Repository::write_pack_for_push`]'s pipeline.
//!   [`Repository::serve_pack_upload_v2_dispatch_auto`] routes both
//!   `command=ls-refs` and `command=fetch` through a single entry
//!   point. All three auto paths honour `include-tag`: annotated tags
//!   whose peeled target lands in the pack are appended automatically.
//!   [`Repository::serve_pack_upload_v2`] is the lower-level variant
//!   for callers that want to plug in their own negotiator.
//!
//! - **Receive-pack (push) service.**
//!   [`Repository::serve_pack_receive`] ingests the pack via
//!   [`gix_pack::Bundle::write_to_directory`], walks the full object
//!   graph reachable from each new tip to catch partial packs,
//!   applies the ref updates with `MustExistAndMatch`, and emits the
//!   report-status response (v1 or v2 based on negotiation).
//!   [`Repository::serve_pack_receive_with_hooks`] adds the
//!   pre-receive / update / post-receive callbacks and exposes the
//!   parsed push-options to each.
//!   [`Repository::serve_pack_receive_delete_only`] is a feature-
//!   minimal variant for builds that do not need pack generation.
//!   Callers who need server-side ref-rewriting (`option refname`
//!   trailers) can drop down to
//!   [`gix_protocol::receive_pack::serve_with_hooks`] with their own
//!   `apply_updates` closure; the public
//!   [`Repository::walk_reachable_for_connectivity`] and
//!   [`Repository::is_forced_update`] helpers expose the same
//!   ancestry walk and connectivity check the built-in path uses.

use std::io::Write;

use crate::Repository;

/// Errors raised while serving an `info/refs` advertisement.
///
/// Reference-store errors vary by backend (loose, packed, reftable,
/// etc.) and by operation (iteration vs. peel); they are boxed as a
/// uniform `dyn Error` to keep the surface small while still surfacing
/// the root cause via `source()`.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum InfoRefsError {
    #[error("reference store traversal failed")]
    References(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl Repository {
    /// Write a v0 / v1 `git-upload-pack` advertisement to `out`.
    ///
    /// Walks this repository's reference store, collects each ref along
    /// with its peeled target (when it points to an annotated tag), and
    /// emits the framed pkt-line advertisement that a smart-HTTP
    /// `info/refs?service=git-upload-pack` endpoint should stream after
    /// the service banner.
    ///
    /// This method does *not* write the smart-HTTP banner itself
    /// (`# service=git-upload-pack\n` followed by a flush-pkt); the
    /// caller controls whether it is a stateful git:// session (no
    /// banner) or an HTTP response body (banner required).
    #[cfg(feature = "serve-upload-pack")]
    #[doc(alias = "info/refs")]
    pub fn serve_upload_pack_info_refs<W: Write>(
        &self,
        out: &mut W,
        options: &gix_protocol::upload_pack::Options,
    ) -> Result<(), InfoRefsError> {
        let refs: Vec<_> = self
            .collect_refs_with_peels()?
            .into_iter()
            .map(
                |RefEntry { object, name, peeled }| gix_protocol::upload_pack::advertisement::AdvertisedRef {
                    object,
                    name,
                    peeled,
                },
            )
            .collect();
        gix_protocol::upload_pack::serve_info_refs::write_v1(out, &refs, options)?;
        Ok(())
    }

    /// Write a v2 `git-upload-pack` advertisement to `out`.
    ///
    /// v2 advertisements do not carry refs - the client follows up with
    /// an explicit `ls-refs` command - so this is a pure pass-through
    /// to the `gix-protocol` emitter.
    #[cfg(feature = "serve-upload-pack")]
    #[doc(alias = "info/refs")]
    pub fn serve_upload_pack_info_refs_v2<W: Write>(
        &self,
        out: &mut W,
        options: &gix_protocol::upload_pack::OptionsV2,
    ) -> std::io::Result<()> {
        gix_protocol::upload_pack::serve_info_refs::write_v2(out, options)
    }

    /// Write a v0 / v1 `git-receive-pack` advertisement to `out`.
    ///
    /// The ref walk is identical to
    /// [`Self::serve_upload_pack_info_refs`]; only the capability list
    /// emitted on the first line differs, reflecting the push-side
    /// capability set the `gix_protocol::receive_pack::Options` type
    /// describes.
    #[cfg(feature = "serve-receive-pack")]
    #[doc(alias = "info/refs")]
    pub fn serve_receive_pack_info_refs<W: Write>(
        &self,
        out: &mut W,
        options: &gix_protocol::receive_pack::Options,
    ) -> Result<(), InfoRefsError> {
        let refs: Vec<_> = self
            .collect_refs_with_peels()?
            .into_iter()
            .map(|RefEntry { object, name, peeled }| gix_protocol::receive_pack::AdvertisedRef { object, name, peeled })
            .collect();
        gix_protocol::receive_pack::serve_info_refs::write_v1(out, &refs, options)?;
        Ok(())
    }

    fn collect_refs_with_peels(&self) -> Result<Vec<RefEntry>, InfoRefsError> {
        let mut out = Vec::new();
        let platform = self.references().map_err(|e| InfoRefsError::References(Box::new(e)))?;
        let all = platform.all().map_err(|e| InfoRefsError::References(Box::new(e)))?;
        for r in all {
            let r = r.map_err(InfoRefsError::References)?;
            let name = r.name().as_bstr().to_owned();
            // Snapshot the direct target oid (for an annotated tag, this
            // is the tag object's id; for a direct ref, the commit id).
            let direct = match r.target().try_id() {
                Some(id) => id.to_owned(),
                None => continue, // symbolic ref that couldn't be resolved
            };
            // Peel the ref to its underlying commit. If peeling lands
            // somewhere different from the direct target, the ref points
            // through a tag object and we emit a `^{}` peeled entry.
            let mut cloned = r;
            let peeled = cloned
                .peel_to_id()
                .map_err(|e| InfoRefsError::References(Box::new(e)))?
                .detach();
            let peeled_opt = if peeled == direct { None } else { Some(peeled) };
            out.push(RefEntry {
                object: direct,
                name,
                peeled: peeled_opt,
            });
        }
        Ok(out)
    }
}

struct RefEntry {
    object: gix_hash::ObjectId,
    name: crate::bstr::BString,
    peeled: Option<gix_hash::ObjectId>,
}

/// Errors raised by [`Repository::serve_pack_receive_delete_only`].
#[cfg(feature = "serve-receive-pack")]
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum ServePackReceiveError {
    #[error(transparent)]
    Serve(#[from] gix_protocol::receive_pack::ServeError),
}

/// Errors raised by [`Repository::serve_pack_upload_v2`].
#[cfg(feature = "serve-upload-pack")]
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum ServePackUploadError {
    #[error(transparent)]
    Serve(#[from] gix_protocol::upload_pack::ServeV2Error),
}

/// Outcome of a successful [`Repository::serve_pack_receive`] call.
#[cfg(all(feature = "serve-receive-pack", feature = "blocking-network-client"))]
#[derive(Debug)]
#[must_use = "inspect `serve` for the parsed commands and push-options, and `pack_write` for the pack-ingest outcome"]
pub struct ServePackReceiveOutcome {
    /// Details from the receive-pack state machine (commands parsed, atomic flag, etc.).
    pub serve: gix_protocol::receive_pack::ServeOutcome,
    /// If the client sent a pack, the outcome of writing it into the
    /// repository's pack directory. `None` for delete-only pushes where
    /// no pack was required.
    pub pack_write: Option<gix_pack::bundle::write::Outcome>,
}

#[cfg(all(feature = "serve-receive-pack", feature = "blocking-network-client"))]
impl Repository {
    /// Drive a full server-side `git-receive-pack` interaction, ingesting
    /// any pack the client sends into this repository's object database
    /// and applying the requested ref updates.
    ///
    /// Promotes [`Self::serve_pack_receive_delete_only`] to the general
    /// case: updates and creates are honored, backed by
    /// [`gix_pack::Bundle::write_to_directory`] for pack persistence and
    /// by this repository's ref-update transaction for the applied
    /// changes.
    ///
    /// `progress` and `should_interrupt` follow the same conventions as
    /// the fetch side of this crate: pass `&mut gix_features::progress::
    /// Discard` when no progress reporting is wanted, and a shared
    /// `AtomicBool` when the caller needs to interrupt in-flight I/O.
    ///
    /// # Invariants honored
    ///
    /// - The pack is written to the repository's standard pack
    ///   directory (`objects/pack/`), matching the layout `git` expects.
    /// - Ref updates use `MustExistAndMatch` on the old OID the client
    ///   announced, so a concurrent writer cannot race the server into
    ///   clobbering a newly-diverged tip.
    /// - A failure from the ref-update transaction is mapped onto per-
    ///   command `ng <reason>` entries in the response; the protocol
    ///   stays valid even when the update is rejected.
    ///
    /// Graph reachability from each `new_id` is verified after pack
    /// ingestion: every commit, tree, and blob reachable from the tip
    /// must be present in the ODB, otherwise the command is rejected
    /// with `ng <refname> missing object <oid>`. Embedders that need
    /// `pre-receive` / `update` / `post-receive` hook callbacks should
    /// use [`Self::serve_pack_receive_with_hooks`] instead.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # fn demo(repo: &gix::Repository, request: &[u8]) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    /// let should_interrupt = std::sync::atomic::AtomicBool::new(false);
    /// let mut response: Vec<u8> = Vec::new();
    /// let mut progress = gix::progress::Discard;
    /// let outcome = repo.serve_pack_receive(request, &mut response, &mut progress, &should_interrupt)?;
    /// println!("parsed {} commands", outcome.serve.parsed_commands.len());
    /// # Ok(()) }
    /// ```
    #[doc(alias = "git receive-pack")]
    pub fn serve_pack_receive<R, W>(
        &self,
        reader: R,
        writer: &mut W,
        progress: &mut dyn gix_features::progress::DynNestedProgress,
        should_interrupt: &std::sync::atomic::AtomicBool,
    ) -> Result<ServePackReceiveOutcome, ServePackReceiveError>
    where
        R: std::io::Read,
        W: std::io::Write,
    {
        self.serve_pack_receive_with_hooks(
            reader,
            writer,
            progress,
            should_interrupt,
            gix_protocol::receive_pack::ServeHooks::default(),
        )
    }

    /// Like [`Self::serve_pack_receive`], but runs the caller-provided
    /// [`ServeHooks`](gix_protocol::receive_pack::ServeHooks) at the
    /// standard receive-pack checkpoints.
    ///
    /// The hook semantics follow the reference implementation:
    ///
    /// - `pre_receive` runs after the commands are parsed but before
    ///   the pack is ingested. A `Err(reason)` rejects the whole
    ///   batch and every command is reported back as
    ///   `ng <refname> <reason>`.
    /// - `update` runs per-command after the pack has been ingested
    ///   but before the ref update is attempted. A `Err(reason)`
    ///   rejects just that one command; others proceed.
    /// - `post_receive` runs after the ref updates have been applied
    ///   with the final outcomes. Its return value is discarded; it
    ///   is purely informational (logging, notifications, analytics).
    ///
    /// This is the entry point embedders should use when they need
    /// authorisation checks, audit trails, or side-effects triggered
    /// by a push. Embedders that do not need any of that can call
    /// [`Self::serve_pack_receive`] directly.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # fn demo(repo: &gix::Repository, request: &[u8]) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    /// use gix_protocol::receive_pack::ServeHooks;
    /// let mut response: Vec<u8> = Vec::new();
    /// let mut progress = gix::progress::Discard;
    /// let should_interrupt = std::sync::atomic::AtomicBool::new(false);
    /// let hooks = ServeHooks {
    ///     pre_receive: Some(Box::new(|_cmds, _opts| Ok(()))),
    ///     update: Some(Box::new(|_cmd, _opts| Ok(()))),
    ///     post_receive: Some(Box::new(|_cmds, _outcomes, _opts| { /* audit */ })),
    /// };
    /// repo.serve_pack_receive_with_hooks(request, &mut response, &mut progress, &should_interrupt, hooks)?;
    /// # Ok(()) }
    /// ```
    #[doc(alias = "git receive-pack")]
    pub fn serve_pack_receive_with_hooks<R, W>(
        &self,
        reader: R,
        writer: &mut W,
        progress: &mut dyn gix_features::progress::DynNestedProgress,
        should_interrupt: &std::sync::atomic::AtomicBool,
        hooks: gix_protocol::receive_pack::ServeHooks<'_>,
    ) -> Result<ServePackReceiveOutcome, ServePackReceiveError>
    where
        R: std::io::Read,
        W: std::io::Write,
    {
        self.serve_pack_receive_with_options_and_hooks(
            reader,
            writer,
            progress,
            should_interrupt,
            hooks,
            gix_protocol::receive_pack::ServeOptions::default(),
        )
    }

    /// Like [`Self::serve_pack_receive_with_hooks`], but also takes a
    /// [`ServeOptions`](gix_protocol::receive_pack::ServeOptions)
    /// policy struct.
    ///
    /// Today the only knob is `allow_deletes`, which must stay aligned
    /// with the `delete-refs` capability advertised by the matching
    /// [`gix_protocol::receive_pack::advertisement::Options`]. When
    /// `false`, deletion commands surface to the client as
    /// `ng <refname> deletion prohibited: delete-refs capability not
    /// advertised`, and the ref-updater is invoked only with the
    /// non-forbidden subset.
    #[doc(alias = "git receive-pack")]
    pub fn serve_pack_receive_with_options_and_hooks<R, W>(
        &self,
        reader: R,
        writer: &mut W,
        progress: &mut dyn gix_features::progress::DynNestedProgress,
        should_interrupt: &std::sync::atomic::AtomicBool,
        hooks: gix_protocol::receive_pack::ServeHooks<'_>,
        options: gix_protocol::receive_pack::ServeOptions,
    ) -> Result<ServePackReceiveOutcome, ServePackReceiveError>
    where
        R: std::io::Read,
        W: std::io::Write,
    {
        use gix_protocol::receive_pack::{serve_with_options_and_hooks, UpdateOutcome};
        use gix_ref::transaction::{Change, LogChange, PreviousValue, RefEdit, RefLog};

        let pack_options = gix_pack::bundle::write::Options {
            thread_limit: None,
            index_version: gix_pack::index::Version::default(),
            iteration_mode: gix_pack::data::input::Mode::Verify,
            object_hash: self.object_hash(),
        };
        let pack_dir = self.objects.store_ref().path().join("pack");
        let mut pack_write_outcome: Option<gix_pack::bundle::write::Outcome> = None;

        let serve_outcome = serve_with_options_and_hooks(
            reader,
            writer,
            |reader| {
                let mut buf = std::io::BufReader::new(reader);
                // Peek to tell apart a pack from an empty delete-only
                // push. Real packs start with the 4-byte magic "PACK".
                let peek = std::io::BufRead::fill_buf(&mut buf)
                    .map_err(|err| -> Box<dyn std::error::Error + Send + Sync + 'static> { Box::new(err) })?;
                if peek.is_empty() {
                    return Ok(());
                }
                if !peek.starts_with(b"PACK") {
                    return Ok(());
                }
                let outcome = gix_pack::Bundle::write_to_directory(
                    &mut buf,
                    Some(&pack_dir),
                    progress,
                    should_interrupt,
                    Some(Box::new(self.objects.clone())),
                    pack_options,
                )
                .map_err(|err| -> Box<dyn std::error::Error + Send + Sync + 'static> { Box::new(err) })?;
                pack_write_outcome = Some(outcome);
                Ok(())
            },
            |commands, atomic| {
                let mut outcomes = Vec::with_capacity(commands.len());
                let mut edits = Vec::with_capacity(commands.len());
                let mut edit_indices: Vec<usize> = Vec::with_capacity(commands.len());
                // Dedup state shared across all non-delete tips in this
                // push: if two commands share ancestors, we only walk
                // each reachable commit and tree once.
                let mut visited_commits: gix_hashtable::HashSet<gix_hash::ObjectId> = Default::default();
                let mut visited_trees: gix_hashtable::HashSet<gix_hash::ObjectId> = Default::default();
                for cmd in commands {
                    let name = match gix_ref::FullName::try_from(cmd.refname.clone()) {
                        Ok(n) => n,
                        Err(_) => {
                            outcomes.push(UpdateOutcome::Rejected("invalid refname".into()));
                            continue;
                        }
                    };
                    // Reachability connectivity check: walk the graph
                    // from `new_id` and verify every referenced commit,
                    // tree, and blob exists in the ODB after pack
                    // ingest. Deletes skip this because there is no new
                    // tip to validate.
                    if !cmd.is_delete() {
                        if !self.has_object(cmd.new_id) {
                            outcomes.push(UpdateOutcome::Rejected(
                                format!(
                                    "new tip {} not present in object database after pack ingest",
                                    cmd.new_id
                                )
                                .into(),
                            ));
                            continue;
                        }
                        if let Err(missing) =
                            self.walk_reachable_for_connectivity(cmd.new_id, &mut visited_commits, &mut visited_trees)
                        {
                            outcomes.push(UpdateOutcome::Rejected(
                                format!("missing object {missing} reachable from new tip {}", cmd.new_id).into(),
                            ));
                            continue;
                        }
                    }
                    let change = if cmd.is_delete() {
                        Change::Delete {
                            expected: PreviousValue::MustExistAndMatch(gix_ref::Target::Object(cmd.old_id)),
                            log: RefLog::AndReference,
                        }
                    } else if cmd.is_create() {
                        Change::Update {
                            log: LogChange::default(),
                            expected: PreviousValue::MustNotExist,
                            new: gix_ref::Target::Object(cmd.new_id),
                        }
                    } else {
                        Change::Update {
                            log: LogChange::default(),
                            expected: PreviousValue::MustExistAndMatch(gix_ref::Target::Object(cmd.old_id)),
                            new: gix_ref::Target::Object(cmd.new_id),
                        }
                    };
                    edits.push(RefEdit {
                        change,
                        name,
                        deref: false,
                    });
                    edit_indices.push(outcomes.len());
                    // v2 trailer: surface the client-announced old / new
                    // on accepted commands. `forced-update` follows
                    // from an ancestry walk: a non-fast-forward update
                    // is one where `old_id` is not reachable from
                    // `new_id` in this repo's commit graph.
                    let mut options = gix_protocol::push::CommandOptions::default();
                    if !cmd.is_create() && !cmd.is_delete() {
                        options.old_oid = Some(cmd.old_id);
                        if self.is_forced_update(cmd.old_id, cmd.new_id) {
                            options.forced_update = true;
                        }
                    }
                    if !cmd.is_delete() {
                        options.new_oid = Some(cmd.new_id);
                    }
                    outcomes.push(UpdateOutcome::Ok(options));
                }

                // Atomic push: if any command was rejected (by the
                // per-command checks above or, later, by a caller's
                // update hook) the remaining commands must not apply
                // either. Flip every accepted outcome to a rejection
                // citing the sibling failure so the report makes the
                // atomicity visible, and drop the queued edits so the
                // ref-store transaction stays a no-op.
                if atomic && outcomes.iter().any(|o| matches!(o, UpdateOutcome::Rejected(_))) {
                    for (idx, outcome) in outcomes.iter_mut().enumerate() {
                        if matches!(outcome, UpdateOutcome::Ok(_)) && edit_indices.contains(&idx) {
                            *outcome =
                                UpdateOutcome::Rejected("atomic push: another ref in this batch was rejected".into());
                        }
                    }
                    return Ok(outcomes);
                }

                if edits.is_empty() {
                    return Ok(outcomes);
                }

                match self.edit_references(edits) {
                    Ok(_) => (),
                    Err(err) => {
                        let reason: crate::bstr::BString = err.to_string().into();
                        for idx in &edit_indices {
                            outcomes[*idx] = UpdateOutcome::Rejected(reason.clone());
                        }
                    }
                }
                Ok(outcomes)
            },
            hooks,
            options,
        )?;

        Ok(ServePackReceiveOutcome {
            serve: serve_outcome,
            pack_write: pack_write_outcome,
        })
    }

    /// Decide whether updating from `old_id` to `new_id` would be a
    /// non-fast-forward ("forced") update.
    ///
    /// A forced update is one where `old_id` is not reachable from
    /// `new_id`: the client rewrote history (rebased, reset, or
    /// replaced commits) rather than appending onto the existing
    /// tip. Walks ancestors of `new_id` looking for `old_id`; treats
    /// a traversal failure (e.g. `old_id` not in the ODB, corrupt
    /// commit) as "forced" since the server cannot prove it is a
    /// fast-forward.
    ///
    /// Exposed so callers who write their own `apply_updates` closure
    /// for [`gix_protocol::receive_pack::serve_with_hooks`] can
    /// populate the `forced-update` trailer on accepted commands
    /// without duplicating the ancestry walk.
    pub fn is_forced_update(&self, old_id: gix_hash::ObjectId, new_id: gix_hash::ObjectId) -> bool {
        if old_id == new_id {
            return false;
        }
        let walker = gix_traverse::commit::Simple::new(std::iter::once(new_id), &self.objects);
        for info in walker {
            match info {
                Ok(info) if info.id == old_id => return false,
                Ok(_) => continue,
                Err(_) => return true,
            }
        }
        true
    }

    /// Walk the object graph reachable from `tip` and verify every
    /// referenced commit, tree, and blob is present in this
    /// repository's ODB.
    ///
    /// Returns `Err(oid)` with the first missing object encountered;
    /// the caller turns that into an `ng <refname> missing object
    /// <oid>` verdict. `visited_commits` and `visited_trees` carry
    /// dedup state across tips so a multi-ref push whose commands
    /// share ancestry does linear work rather than quadratic.
    ///
    /// Exposed so callers who write their own `apply_updates` closure
    /// for [`gix_protocol::receive_pack::serve_with_hooks`] (for
    /// example to implement ref-rewriting and emit `option refname`
    /// trailers) can reuse the same connectivity check
    /// [`Self::serve_pack_receive`] performs internally.
    pub fn walk_reachable_for_connectivity(
        &self,
        tip: gix_hash::ObjectId,
        visited_commits: &mut gix_hashtable::HashSet<gix_hash::ObjectId>,
        visited_trees: &mut gix_hashtable::HashSet<gix_hash::ObjectId>,
    ) -> Result<(), gix_hash::ObjectId> {
        use gix_object::FindExt;

        let commit_iter = gix_traverse::commit::Simple::new(std::iter::once(tip), &self.objects);
        let mut commits_to_walk: Vec<gix_hash::ObjectId> = Vec::new();
        for info in commit_iter {
            let info = info.map_err(|_| tip)?;
            if visited_commits.insert(info.id) {
                commits_to_walk.push(info.id);
            }
        }

        let mut tree_state = gix_traverse::tree::breadthfirst::State::default();
        let mut commit_buf: Vec<u8> = Vec::new();
        let mut tree_buf: Vec<u8> = Vec::new();
        for commit_id in commits_to_walk {
            let commit = self
                .objects
                .find_commit(&commit_id, &mut commit_buf)
                .map_err(|_| commit_id)?;
            let tree_oid = commit.tree();
            if !visited_trees.insert(tree_oid) {
                continue;
            }
            let root_tree = self
                .objects
                .find_tree_iter(&tree_oid, &mut tree_buf)
                .map_err(|_| tree_oid)?;
            let mut visit = ConnectivityVisit {
                repo: self,
                visited_trees,
                missing: None,
            };
            let walk = gix_traverse::tree::breadthfirst(root_tree, &mut tree_state, &self.objects, &mut visit);
            if let Some(missing) = visit.missing {
                return Err(missing);
            }
            if walk.is_err() {
                // The tree walker bails on Find errors (missing
                // sub-tree) and on Cancelled (we never cancel unless we
                // already set `missing`). Surface the root tree as the
                // approximate missing oid - the actual missing sub-tree
                // couldn't be pinpointed without threading the error
                // oid through the breadthfirst API.
                return Err(tree_oid);
            }
        }

        Ok(())
    }
}

#[cfg(all(feature = "serve-receive-pack", feature = "blocking-network-client"))]
struct ConnectivityVisit<'a> {
    repo: &'a Repository,
    visited_trees: &'a mut gix_hashtable::HashSet<gix_hash::ObjectId>,
    missing: Option<gix_hash::ObjectId>,
}

#[cfg(all(feature = "serve-receive-pack", feature = "blocking-network-client"))]
impl gix_traverse::tree::Visit for ConnectivityVisit<'_> {
    fn pop_back_tracked_path_and_set_current(&mut self) {}
    fn pop_front_tracked_path_and_set_current(&mut self) {}
    fn push_back_tracked_path_component(&mut self, _component: &gix_object::bstr::BStr) {}
    fn push_path_component(&mut self, _component: &gix_object::bstr::BStr) {}
    fn pop_path_component(&mut self) {}

    fn visit_tree(&mut self, entry: &gix_object::tree::EntryRef<'_>) -> gix_traverse::tree::visit::Action {
        if self.missing.is_some() {
            return std::ops::ControlFlow::Break(());
        }
        let oid = entry.oid.to_owned();
        if !self.visited_trees.insert(oid) {
            // Already walked via another tip / subtree in this push.
            return std::ops::ControlFlow::Continue(false);
        }
        if !self.repo.has_object(oid) {
            self.missing = Some(oid);
            return std::ops::ControlFlow::Break(());
        }
        std::ops::ControlFlow::Continue(true)
    }

    fn visit_nontree(&mut self, entry: &gix_object::tree::EntryRef<'_>) -> gix_traverse::tree::visit::Action {
        if self.missing.is_some() {
            return std::ops::ControlFlow::Break(());
        }
        let oid = entry.oid.to_owned();
        // Gitlinks (submodule commits) reference repositories outside
        // this one; treat them as always present so an otherwise-valid
        // superproject push is not rejected because the submodule's
        // commit is not in *this* repo's ODB.
        if entry.mode.is_commit() {
            return std::ops::ControlFlow::Continue(false);
        }
        if !self.repo.has_object(oid) {
            self.missing = Some(oid);
            return std::ops::ControlFlow::Break(());
        }
        std::ops::ControlFlow::Continue(false)
    }
}

#[cfg(all(feature = "serve-upload-pack", feature = "blocking-network-client"))]
impl Repository {
    /// Drive a complete server-side v2 `git-upload-pack` interaction
    /// with automatic pack generation.
    ///
    /// Reads the client's `command=fetch` request, collects the
    /// requested wants plus announced haves, walks the local object
    /// graph via [`Self::write_pack_for_push`]'s pipeline to produce
    /// the pack, and streams the framed response on `writer`.
    ///
    /// Both `want <oid>` and `want-ref <refname>` entries are honored
    /// as wants: `want-ref` is resolved by looking up the refname in
    /// this repository's ref store and peeling it to a commit. Refs
    /// that cannot be found or cannot be peeled are silently skipped,
    /// matching the "best-effort" policy the upstream spec describes
    /// for missing want-refs.
    ///
    /// `include-tag` is honoured by walking the ref store for annotated
    /// tags whose peeled target is one of the commits that ship, and
    /// appending their tag-object oids to the pack input.
    ///
    /// `filter=blob:none` and `filter=blob:limit=<n>` are honoured:
    /// the former drops every blob from the pack, the latter drops
    /// blobs whose decoded size is at least the byte limit. `<n>` is a
    /// decimal byte count optionally followed by a single
    /// case-insensitive `k` / `m` / `g` suffix (powers of 1024).
    /// Other filter specs (`tree:N`, `sparse:*`, `object:type=*`)
    /// fall back to a full pack.
    ///
    /// `shallow` / `deepen` are ignored - callers that need them can
    /// use [`Self::serve_pack_upload_v2`] and plug in their own
    /// negotiator that does the ref-store walks themselves.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # fn demo(repo: &gix::Repository, request: &[u8]) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    /// let should_interrupt = std::sync::atomic::AtomicBool::new(false);
    /// let mut response: Vec<u8> = Vec::new();
    /// let outcome = repo.serve_pack_upload_v2_auto(request, &mut response, &should_interrupt)?;
    /// if outcome.pack_sent {
    ///     println!("streamed a pack for {} wants", outcome.request.wants.len());
    /// }
    /// # Ok(()) }
    /// ```
    #[doc(alias = "git upload-pack")]
    pub fn serve_pack_upload_v2_auto<R: std::io::Read, W: std::io::Write>(
        &self,
        reader: R,
        writer: &mut W,
        should_interrupt: &std::sync::atomic::AtomicBool,
    ) -> Result<gix_protocol::upload_pack::ServeV2Outcome, ServePackUploadError> {
        let object_hash = self.object_hash();
        let repo_objects = (*self.objects).clone();
        // Shared state: the negotiator fills it from the request, the
        // pack-writer closure reads it. `annotated_tags` is populated
        // only when the client advertised `include-tag`; each entry is
        // `(tag_object_oid, peeled_commit_oid)` for every annotated tag
        // ref the server knows about. `filter` is the object filter
        // derived from `req.filter` (currently only `blob:none` is
        // interpreted; other specs fall back to `None`).
        type CollectedRequest = std::rc::Rc<
            std::cell::RefCell<
                Option<(
                    Vec<gix_hash::ObjectId>,
                    Vec<gix_hash::ObjectId>,
                    Vec<(gix_hash::ObjectId, gix_hash::ObjectId)>,
                    gix_pack::data::output::count::push::ObjectFilter,
                )>,
            >,
        >;
        let collected: CollectedRequest = std::rc::Rc::new(std::cell::RefCell::new(None));
        let collected_for_neg = collected.clone();
        let collected_for_pack = collected.clone();
        let repo_for_neg: &Repository = self;
        let outcome = gix_protocol::upload_pack::serve_v2(
            reader,
            writer,
            move |req| -> Result<
                gix_protocol::upload_pack::ServeResponse,
                Box<dyn std::error::Error + Send + Sync + 'static>,
            > {
                let mut wants: Vec<gix_hash::ObjectId> = Vec::with_capacity(req.wants.len());
                let mut resolved_wanted_refs: Vec<gix_protocol::wire_types::WantedRef> = Vec::new();
                for w in &req.wants {
                    match w {
                        gix_protocol::upload_pack::Want::ByOid(id) => wants.push(*id),
                        gix_protocol::upload_pack::Want::ByRef(name) => {
                            if let Some(id) = repo_for_neg.resolve_want_ref(name.as_ref()) {
                                wants.push(id);
                                resolved_wanted_refs.push(gix_protocol::wire_types::WantedRef {
                                    id,
                                    path: name.clone(),
                                });
                            }
                        }
                    }
                }
                let haves = req.haves.clone();
                let annotated_tags = if req.include_tag {
                    repo_for_neg.collect_annotated_tag_targets()?
                } else {
                    Vec::new()
                };
                let filter = parse_object_filter(req.filter.as_ref().map(AsRef::<[u8]>::as_ref));
                let send_pack = !wants.is_empty();
                let client_done = req.done;
                *collected_for_neg.borrow_mut() = Some((wants, haves, annotated_tags, filter));
                Ok(response_for_auto_fetch(send_pack, client_done, resolved_wanted_refs))
            },
            move |pack_writer| -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
                let (wants, haves, annotated_tags, filter) = collected_for_pack.borrow_mut().take().unwrap_or_default();
                let mut db = repo_objects;
                db.prevent_pack_unload();
                let mut already_present: gix_hashtable::HashSet<gix_hash::ObjectId> = Default::default();
                for h in &haves {
                    already_present.insert(*h);
                }
                if !haves.is_empty() {
                    let iter = gix_traverse::commit::Simple::new(haves.iter().copied(), &db);
                    for info in iter.flatten() {
                        already_present.insert(info.id);
                    }
                }
                if wants.is_empty() {
                    let bytes_iter = gix_pack::data::output::bytes::FromEntriesIter::new(
                        std::iter::empty::<
                            Result<
                                Vec<gix_pack::data::output::Entry>,
                                gix_pack::data::output::entry::iter_from_counts::Error,
                            >,
                        >(),
                        pack_writer,
                        0,
                        gix_pack::data::Version::V2,
                        object_hash,
                    );
                    for chunk in bytes_iter {
                        chunk?;
                    }
                    return Ok(());
                }
                let commits_to_pack: Vec<gix_hash::ObjectId> =
                    match gix_traverse::commit::Simple::new(wants.iter().copied(), &db).hide(haves.iter().copied()) {
                        Ok(walker) => walker.filter_map(Result::ok).map(|info| info.id).collect(),
                        Err(err) => return Err(Box::new(err)),
                    };
                let inputs_with_tags = if annotated_tags.is_empty() {
                    commits_to_pack
                } else {
                    let shipped: gix_hashtable::HashSet<gix_hash::ObjectId> = commits_to_pack.iter().copied().collect();
                    let mut extra: Vec<gix_hash::ObjectId> = annotated_tags
                        .into_iter()
                        .filter_map(|(tag_oid, peeled)| shipped.contains(&peeled).then_some(tag_oid))
                        .collect();
                    extra.extend(commits_to_pack);
                    extra
                };
                let progress = gix_features::progress::Discard;
                let (counts, _) = gix_pack::data::output::count::push::objects_for_push_with_filter(
                    &db,
                    inputs_with_tags,
                    already_present,
                    filter,
                    &progress,
                    should_interrupt,
                )?;
                let num_entries = counts.len() as u32;
                let db_for_entries = db.clone();
                let nested_progress: Box<dyn gix_features::progress::DynNestedProgress + 'static> =
                    Box::new(gix_features::progress::Discard);
                let entries = gix_pack::data::output::entry::iter_from_counts(
                    counts,
                    db_for_entries,
                    nested_progress,
                    gix_pack::data::output::entry::iter_from_counts::Options::default(),
                );
                let mapped = entries.map(|res| res.map(|(_seq, entries)| entries));
                let bytes_iter = gix_pack::data::output::bytes::FromEntriesIter::new(
                    mapped,
                    pack_writer,
                    num_entries,
                    gix_pack::data::Version::V2,
                    object_hash,
                );
                for chunk in bytes_iter {
                    chunk?;
                }
                Ok(())
            },
        )?;
        Ok(outcome)
    }

    /// Drive a v2 upload-pack interaction that auto-handles both
    /// `command=ls-refs` and `command=fetch` in the same entry point.
    ///
    /// Real v2 clients always send `ls-refs` first to discover the
    /// remote's tips, then follow up with `fetch` for the wanted
    /// commits. [`Self::serve_pack_upload_v2_auto`] only handles
    /// `fetch` - this method routes both commands through
    /// [`gix_protocol::upload_pack::dispatch_v2`] and answers each with
    /// the repository's state automatically:
    ///
    /// - `ls-refs` walks the local ref store, peels annotated tags
    ///   when the client asked for `peel`, and surfaces symref targets
    ///   when `symrefs` was requested.
    /// - `fetch` reuses the same wants/haves pipeline as
    ///   [`Self::serve_pack_upload_v2_auto`], including `want-ref`
    ///   resolution, `include-tag` shipping, and `filter=blob:none`.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # fn demo(repo: &gix::Repository, request: &[u8]) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    /// let should_interrupt = std::sync::atomic::AtomicBool::new(false);
    /// let mut response: Vec<u8> = Vec::new();
    /// let outcome = repo.serve_pack_upload_v2_dispatch_auto(request, &mut response, &should_interrupt)?;
    /// match outcome {
    ///     gix_protocol::upload_pack::serve::DispatchOutcome::LsRefs { refs_sent, .. } => {
    ///         println!("answered ls-refs with {refs_sent} refs");
    ///     }
    ///     gix_protocol::upload_pack::serve::DispatchOutcome::Fetch(fetch_outcome) => {
    ///         println!("answered fetch, pack_sent = {}", fetch_outcome.pack_sent);
    ///     }
    /// }
    /// # Ok(()) }
    /// ```
    #[doc(alias = "git upload-pack")]
    pub fn serve_pack_upload_v2_dispatch_auto<R: std::io::Read, W: std::io::Write>(
        &self,
        reader: R,
        writer: &mut W,
        should_interrupt: &std::sync::atomic::AtomicBool,
    ) -> Result<gix_protocol::upload_pack::serve::DispatchOutcome, ServePackUploadError> {
        let object_hash = self.object_hash();
        let repo_objects = (*self.objects).clone();
        type CollectedRequestDispatch = std::rc::Rc<
            std::cell::RefCell<
                Option<(
                    Vec<gix_hash::ObjectId>,
                    Vec<gix_hash::ObjectId>,
                    Vec<(gix_hash::ObjectId, gix_hash::ObjectId)>,
                    gix_pack::data::output::count::push::ObjectFilter,
                )>,
            >,
        >;
        let collected: CollectedRequestDispatch = std::rc::Rc::new(std::cell::RefCell::new(None));
        let collected_for_neg = collected.clone();
        let collected_for_pack = collected.clone();
        let repo_for_ls_refs: &Repository = self;
        let repo_for_neg: &Repository = self;
        let outcome = gix_protocol::upload_pack::serve::dispatch_v2(
            reader,
            writer,
            move |req| -> Result<
                Vec<gix_protocol::upload_pack::LsRefsRefEntry>,
                Box<dyn std::error::Error + Send + Sync + 'static>,
            > { ls_refs_from_repo(repo_for_ls_refs, req) },
            move |req| -> Result<
                gix_protocol::upload_pack::ServeResponse,
                Box<dyn std::error::Error + Send + Sync + 'static>,
            > {
                let mut wants: Vec<gix_hash::ObjectId> = Vec::with_capacity(req.wants.len());
                let mut resolved_wanted_refs: Vec<gix_protocol::wire_types::WantedRef> = Vec::new();
                for w in &req.wants {
                    match w {
                        gix_protocol::upload_pack::Want::ByOid(id) => wants.push(*id),
                        gix_protocol::upload_pack::Want::ByRef(name) => {
                            if let Some(id) = repo_for_neg.resolve_want_ref(name.as_ref()) {
                                wants.push(id);
                                resolved_wanted_refs.push(gix_protocol::wire_types::WantedRef {
                                    id,
                                    path: name.clone(),
                                });
                            }
                        }
                    }
                }
                let haves = req.haves.clone();
                let annotated_tags = if req.include_tag {
                    repo_for_neg.collect_annotated_tag_targets()?
                } else {
                    Vec::new()
                };
                let filter = parse_object_filter(req.filter.as_ref().map(AsRef::<[u8]>::as_ref));
                let send_pack = !wants.is_empty();
                let client_done = req.done;
                *collected_for_neg.borrow_mut() = Some((wants, haves, annotated_tags, filter));
                Ok(response_for_auto_fetch(send_pack, client_done, resolved_wanted_refs))
            },
            move |pack_writer| -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
                let (wants, haves, annotated_tags, filter) = collected_for_pack.borrow_mut().take().unwrap_or_default();
                let mut db = repo_objects;
                db.prevent_pack_unload();
                let mut already_present: gix_hashtable::HashSet<gix_hash::ObjectId> = Default::default();
                for h in &haves {
                    already_present.insert(*h);
                }
                if !haves.is_empty() {
                    let iter = gix_traverse::commit::Simple::new(haves.iter().copied(), &db);
                    for info in iter.flatten() {
                        already_present.insert(info.id);
                    }
                }
                if wants.is_empty() {
                    return Ok(());
                }
                let commits_to_pack: Vec<gix_hash::ObjectId> =
                    match gix_traverse::commit::Simple::new(wants.iter().copied(), &db).hide(haves.iter().copied()) {
                        Ok(walker) => walker.filter_map(Result::ok).map(|info| info.id).collect(),
                        Err(err) => return Err(Box::new(err)),
                    };
                let inputs_with_tags = if annotated_tags.is_empty() {
                    commits_to_pack
                } else {
                    let shipped: gix_hashtable::HashSet<gix_hash::ObjectId> = commits_to_pack.iter().copied().collect();
                    let mut extra: Vec<gix_hash::ObjectId> = annotated_tags
                        .into_iter()
                        .filter_map(|(tag_oid, peeled)| shipped.contains(&peeled).then_some(tag_oid))
                        .collect();
                    extra.extend(commits_to_pack);
                    extra
                };
                let progress = gix_features::progress::Discard;
                let (counts, _) = gix_pack::data::output::count::push::objects_for_push_with_filter(
                    &db,
                    inputs_with_tags,
                    already_present,
                    filter,
                    &progress,
                    should_interrupt,
                )?;
                let num_entries = counts.len() as u32;
                let db_for_entries = db.clone();
                let nested_progress: Box<dyn gix_features::progress::DynNestedProgress + 'static> =
                    Box::new(gix_features::progress::Discard);
                let entries = gix_pack::data::output::entry::iter_from_counts(
                    counts,
                    db_for_entries,
                    nested_progress,
                    gix_pack::data::output::entry::iter_from_counts::Options::default(),
                );
                let mapped = entries.map(|res| res.map(|(_seq, entries)| entries));
                let bytes_iter = gix_pack::data::output::bytes::FromEntriesIter::new(
                    mapped,
                    pack_writer,
                    num_entries,
                    gix_pack::data::Version::V2,
                    object_hash,
                );
                for chunk in bytes_iter {
                    chunk?;
                }
                Ok(())
            },
        )?;
        Ok(outcome)
    }

    /// Resolve a `want-ref <refname>` entry into its peeled commit
    /// OID, returning `None` when the refname cannot be located or
    /// cannot be peeled to an object.
    ///
    /// Used by [`Self::serve_pack_upload_v2_auto`] to turn a client's
    /// ref-based want into the OID the pack generator expects.
    fn resolve_want_ref(&self, refname: &crate::bstr::BStr) -> Option<gix_hash::ObjectId> {
        let partial: &gix_ref::PartialNameRef = refname.try_into().ok()?;
        let mut reference = self.try_find_reference(partial).ok().flatten()?;
        reference.peel_to_id().ok().map(crate::Id::detach)
    }

    /// Walk the ref store and return `(tag_object_oid, peeled_commit_oid)`
    /// for every annotated tag the caller can discover.
    ///
    /// Used by the auto upload-pack paths to honour the client's
    /// `include-tag` capability: if any of the returned peeled commits
    /// ends up in the pack, the matching tag object is appended so the
    /// tag survives the transfer. Lightweight tags (refs whose direct
    /// target is already the commit, with no intervening tag object) are
    /// skipped because there is no separate tag object to ship.
    fn collect_annotated_tag_targets(
        &self,
    ) -> Result<Vec<(gix_hash::ObjectId, gix_hash::ObjectId)>, Box<dyn std::error::Error + Send + Sync + 'static>> {
        let mut out = Vec::new();
        let entries = self
            .collect_refs_with_peels()
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync + 'static>)?;
        for RefEntry {
            object,
            name: _,
            peeled,
        } in entries
        {
            if let Some(peeled) = peeled {
                out.push((object, peeled));
            }
        }
        Ok(out)
    }
}

/// Convert a wire-level `filter=<spec>` value into the matching
/// [`gix_pack::data::output::count::push::ObjectFilter`].
///
/// Recognised today:
/// - `blob:none` → [`BlobsNone`](gix_pack::data::output::count::push::ObjectFilter::BlobsNone)
/// - `blob:limit=<n>` → [`BlobsAtLeast`](gix_pack::data::output::count::push::ObjectFilter::BlobsAtLeast)
///   where `<n>` is a decimal byte count optionally followed by a
///   single case-insensitive `k`, `m`, or `g` suffix (powers of 1024
///   to match what `git clone --filter=blob:limit=1m` expects).
///
/// Every other spec (including absent) falls back to
/// [`ObjectFilter::None`](gix_pack::data::output::count::push::ObjectFilter::None),
/// which means the server ships a full pack and the client downgrades
/// its partial-clone expectation.
/// Shape a v2 `ServeResponse` for the auto-fetch entry points.
///
/// The v2 spec requires the `acknowledgments` section to be omitted
/// when the client sent `done`.
#[cfg(all(feature = "serve-upload-pack", feature = "blocking-network-client"))]
fn response_for_auto_fetch(
    pack_incoming: bool,
    client_done: bool,
    wanted_refs: Vec<gix_protocol::wire_types::WantedRef>,
) -> gix_protocol::upload_pack::ServeResponse {
    use gix_protocol::upload_pack::ServeResponse;
    use gix_protocol::wire_types::{AckTrailer, Acknowledgments};
    if !pack_incoming {
        return ServeResponse::acknowledgments_only(Vec::new());
    }
    let acknowledgments = if client_done {
        None
    } else {
        Some(Acknowledgments::new(Vec::new(), Some(AckTrailer::Ready)))
    };
    let wanted_refs = if wanted_refs.is_empty() { None } else { Some(wanted_refs) };
    ServeResponse::with_pack(acknowledgments, None, wanted_refs, None)
}

#[cfg(all(feature = "serve-upload-pack", feature = "blocking-network-client"))]
fn parse_object_filter(filter: Option<&[u8]>) -> gix_pack::data::output::count::push::ObjectFilter {
    use gix_pack::data::output::count::push::ObjectFilter;
    match filter {
        Some(b"blob:none") => ObjectFilter::BlobsNone,
        // `tree:0` and `object:type=commit` both request a
        // commits-only clone. The latter also covers
        // `object:type=blob` / `tag` in git, but commits-only is by
        // far the common case downstream clients ask for.
        Some(b"tree:0") | Some(b"object:type=commit") => ObjectFilter::TreesNone,
        Some(spec) => {
            if let Some(rest) = spec.strip_prefix(b"blob:limit=") {
                if let Some(limit) = parse_blob_size_limit(rest) {
                    return ObjectFilter::BlobsAtLeast(limit);
                }
            }
            ObjectFilter::None
        }
        None => ObjectFilter::None,
    }
}

/// Parse the byte-count used by `filter=blob:limit=<n>`.
///
/// Accepts a plain decimal (`1048576`) or a decimal followed by a
/// single `k`, `m`, or `g` (case-insensitive) suffix interpreted as
/// powers of 1024 so `1m` means exactly 1 MiB. Returns `None` for
/// anything that doesn't parse cleanly so the caller can fall back to
/// `ObjectFilter::None` rather than guess.
#[cfg(all(feature = "serve-upload-pack", feature = "blocking-network-client"))]
fn parse_blob_size_limit(spec: &[u8]) -> Option<u64> {
    if spec.is_empty() {
        return None;
    }
    let (digits, multiplier) = match spec.last().copied()? {
        b'k' | b'K' => (&spec[..spec.len() - 1], 1024_u64),
        b'm' | b'M' => (&spec[..spec.len() - 1], 1024 * 1024),
        b'g' | b'G' => (&spec[..spec.len() - 1], 1024 * 1024 * 1024),
        _ => (spec, 1),
    };
    let s = std::str::from_utf8(digits).ok()?;
    let value: u64 = s.parse().ok()?;
    value.checked_mul(multiplier)
}

#[cfg(all(test, feature = "serve-upload-pack", feature = "blocking-network-client"))]
mod parse_blob_size_limit_tests {
    use super::parse_blob_size_limit;

    #[test]
    fn plain_decimal() {
        assert_eq!(parse_blob_size_limit(b"0"), Some(0));
        assert_eq!(parse_blob_size_limit(b"128"), Some(128));
        assert_eq!(parse_blob_size_limit(b"1048576"), Some(1024 * 1024));
    }

    #[test]
    fn accepts_k_m_g_suffix_case_insensitive() {
        assert_eq!(parse_blob_size_limit(b"1k"), Some(1024));
        assert_eq!(parse_blob_size_limit(b"1K"), Some(1024));
        assert_eq!(parse_blob_size_limit(b"2m"), Some(2 * 1024 * 1024));
        assert_eq!(parse_blob_size_limit(b"3G"), Some(3 * 1024 * 1024 * 1024));
    }

    #[test]
    fn rejects_bad_inputs() {
        assert_eq!(parse_blob_size_limit(b""), None);
        assert_eq!(parse_blob_size_limit(b"abc"), None);
        assert_eq!(parse_blob_size_limit(b"1t"), None); // unknown suffix
        assert_eq!(parse_blob_size_limit(b"-5"), None);
    }

    #[test]
    fn overflow_yields_none() {
        // u64::MAX * 1024 overflows.
        assert_eq!(parse_blob_size_limit(b"18446744073709551615k"), None);
    }
}

#[cfg(all(test, feature = "serve-upload-pack", feature = "blocking-network-client"))]
mod parse_object_filter_tests {
    use gix_pack::data::output::count::push::ObjectFilter;

    use super::parse_object_filter;

    #[test]
    fn none_spec_yields_none_filter() {
        assert!(matches!(parse_object_filter(None), ObjectFilter::None));
    }

    #[test]
    fn blob_none_is_recognised() {
        assert!(matches!(
            parse_object_filter(Some(b"blob:none")),
            ObjectFilter::BlobsNone,
        ));
    }

    #[test]
    fn tree_zero_and_object_type_commit_both_request_trees_none() {
        // Two distinct wire-level spellings of "ship commits only".
        assert!(matches!(
            parse_object_filter(Some(b"tree:0")),
            ObjectFilter::TreesNone,
        ));
        assert!(matches!(
            parse_object_filter(Some(b"object:type=commit")),
            ObjectFilter::TreesNone,
        ));
    }

    #[test]
    fn blob_limit_routes_through_size_parser() {
        match parse_object_filter(Some(b"blob:limit=1048576")) {
            ObjectFilter::BlobsAtLeast(n) => assert_eq!(n, 1024 * 1024),
            other => panic!("expected BlobsAtLeast(1MiB), got {other:?}"),
        }
        match parse_object_filter(Some(b"blob:limit=2m")) {
            ObjectFilter::BlobsAtLeast(n) => assert_eq!(n, 2 * 1024 * 1024),
            other => panic!("expected BlobsAtLeast(2MiB), got {other:?}"),
        }
    }

    #[test]
    fn blob_limit_with_unparseable_size_falls_back_to_none() {
        // Reviewer-level safety: a malformed size must NOT be silently
        // treated as zero — otherwise the server would ship an empty
        // pack while the client thought it asked for a real filter.
        assert!(matches!(
            parse_object_filter(Some(b"blob:limit=not-a-number")),
            ObjectFilter::None,
        ));
        assert!(matches!(
            parse_object_filter(Some(b"blob:limit=")),
            ObjectFilter::None,
        ));
    }

    #[test]
    fn unknown_spec_falls_back_to_none() {
        // Unknown filter specs must degrade to "no filter" rather than
        // silently altering server behaviour.
        assert!(matches!(
            parse_object_filter(Some(b"sparse:oid=abcdef")),
            ObjectFilter::None,
        ));
        assert!(matches!(
            parse_object_filter(Some(b"object:type=blob")),
            ObjectFilter::None,
        ));
        assert!(matches!(parse_object_filter(Some(b"")), ObjectFilter::None));
    }
}

#[cfg(all(feature = "serve-upload-pack", feature = "blocking-network-client"))]
impl Repository {
    /// Drive a complete server-side v0/v1 `git-upload-pack` interaction
    /// with automatic pack generation, for stateless-RPC (smart-HTTP)
    /// clients.
    ///
    /// This is the legacy counterpart to [`Self::serve_pack_upload_v2_auto`].
    /// It reads the upload-request, walks the local object graph via
    /// the same [`objects_for_push`](gix_pack::data::output::count::objects_for_push)
    /// pipeline used for push, and streams the resulting pack after a
    /// single `NAK` pkt-line. `ACK`-with-common-oid and multi-ack
    /// rounds are not emitted here: the `NAK` + pack shape covers the
    /// stateless-RPC case v0/v1 HTTP clients expect when no prior
    /// negotiation context exists.
    ///
    /// `include-tag` (advertised as a capability token on the first
    /// `want` line) is honoured the same way the v2 auto path does it:
    /// annotated tags whose peeled target lands in the pack are
    /// appended to the pack input.
    ///
    /// `filter=blob:none` (sent as a capability on the first `want`
    /// line) is honoured by stripping blobs from the resulting pack;
    /// other filter specs are ignored.
    ///
    /// `shallow` / `deepen` are ignored; embedders who need them
    /// should drop down to [`gix_protocol::upload_pack::serve_v1`] and
    /// supply their own walker.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # fn demo(repo: &gix::Repository, request: &[u8]) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    /// let should_interrupt = std::sync::atomic::AtomicBool::new(false);
    /// let mut response: Vec<u8> = Vec::new();
    /// let outcome = repo.serve_pack_upload_v1_auto(request, &mut response, &should_interrupt)?;
    /// if outcome.pack_sent {
    ///     println!("streamed a pack for {} wants", outcome.request.wants.len());
    /// }
    /// # Ok(()) }
    /// ```
    #[doc(alias = "git upload-pack")]
    pub fn serve_pack_upload_v1_auto<R: std::io::Read, W: std::io::Write>(
        &self,
        reader: R,
        writer: &mut W,
        should_interrupt: &std::sync::atomic::AtomicBool,
    ) -> Result<gix_protocol::upload_pack::ServeOutcomeV1, ServePackUploadV1Error> {
        let object_hash = self.object_hash();
        let repo_objects = (*self.objects).clone();
        type CollectedRequestV1 = std::rc::Rc<
            std::cell::RefCell<
                Option<(
                    Vec<gix_hash::ObjectId>,
                    Vec<gix_hash::ObjectId>,
                    Vec<(gix_hash::ObjectId, gix_hash::ObjectId)>,
                    gix_pack::data::output::count::push::ObjectFilter,
                )>,
            >,
        >;
        let collected: CollectedRequestV1 = std::rc::Rc::new(std::cell::RefCell::new(None));
        let collected_for_neg = collected.clone();
        let collected_for_pack = collected.clone();
        let repo_for_neg: &Repository = self;
        let outcome = gix_protocol::upload_pack::serve_v1(
            reader,
            writer,
            move |req| -> Result<
                gix_protocol::upload_pack::ServeResponseV1,
                Box<dyn std::error::Error + Send + Sync + 'static>,
            > {
                let wants = req.wants.clone();
                let haves = req.haves.clone();
                let include_tag = req.capabilities.iter().any(|c| c.as_slice() == b"include-tag");
                let annotated_tags = if include_tag {
                    repo_for_neg.collect_annotated_tag_targets()?
                } else {
                    Vec::new()
                };
                let filter = parse_object_filter(req.filter.as_ref().map(AsRef::<[u8]>::as_ref));
                let send_pack = !wants.is_empty();
                *collected_for_neg.borrow_mut() = Some((wants, haves, annotated_tags, filter));
                Ok(gix_protocol::upload_pack::ServeResponseV1 { ack: None, send_pack })
            },
            move |pack_writer| -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
                let (wants, haves, annotated_tags, filter) = collected_for_pack.borrow_mut().take().unwrap_or_default();
                let mut db = repo_objects;
                db.prevent_pack_unload();
                let mut already_present: gix_hashtable::HashSet<gix_hash::ObjectId> = Default::default();
                for h in &haves {
                    already_present.insert(*h);
                }
                if !haves.is_empty() {
                    let iter = gix_traverse::commit::Simple::new(haves.iter().copied(), &db);
                    for info in iter.flatten() {
                        already_present.insert(info.id);
                    }
                }
                if wants.is_empty() {
                    return Ok(());
                }
                let commits_to_pack: Vec<gix_hash::ObjectId> =
                    match gix_traverse::commit::Simple::new(wants.iter().copied(), &db).hide(haves.iter().copied()) {
                        Ok(walker) => walker.filter_map(Result::ok).map(|info| info.id).collect(),
                        Err(err) => return Err(Box::new(err)),
                    };
                let inputs_with_tags = if annotated_tags.is_empty() {
                    commits_to_pack
                } else {
                    let shipped: gix_hashtable::HashSet<gix_hash::ObjectId> = commits_to_pack.iter().copied().collect();
                    let mut extra: Vec<gix_hash::ObjectId> = annotated_tags
                        .into_iter()
                        .filter_map(|(tag_oid, peeled)| shipped.contains(&peeled).then_some(tag_oid))
                        .collect();
                    extra.extend(commits_to_pack);
                    extra
                };
                let progress = gix_features::progress::Discard;
                let (counts, _) = gix_pack::data::output::count::push::objects_for_push_with_filter(
                    &db,
                    inputs_with_tags,
                    already_present,
                    filter,
                    &progress,
                    should_interrupt,
                )?;
                let num_entries = counts.len() as u32;
                let db_for_entries = db.clone();
                let nested_progress: Box<dyn gix_features::progress::DynNestedProgress + 'static> =
                    Box::new(gix_features::progress::Discard);
                let entries = gix_pack::data::output::entry::iter_from_counts(
                    counts,
                    db_for_entries,
                    nested_progress,
                    gix_pack::data::output::entry::iter_from_counts::Options::default(),
                );
                let mapped = entries.map(|res| res.map(|(_seq, entries)| entries));
                let bytes_iter = gix_pack::data::output::bytes::FromEntriesIter::new(
                    mapped,
                    pack_writer,
                    num_entries,
                    gix_pack::data::Version::V2,
                    object_hash,
                );
                for chunk in bytes_iter {
                    chunk?;
                }
                Ok(())
            },
        )?;
        Ok(outcome)
    }
}

/// Errors raised by [`Repository::serve_pack_upload_v1_auto`].
#[cfg(all(feature = "serve-upload-pack", feature = "blocking-network-client"))]
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum ServePackUploadV1Error {
    #[error(transparent)]
    Serve(#[from] gix_protocol::upload_pack::ServeV1Error),
}

/// Build an `ls-refs` response for the given request from the live
/// repository's ref store. Used by
/// [`Repository::serve_pack_upload_v2_dispatch_auto`] to auto-answer
/// the v2 `command=ls-refs`.
///
/// Applies the request's `peel`, `symrefs`, and `prefixes` selectors:
/// - `prefixes` are matched as literal string prefixes against the
///   full ref name (empty list matches everything).
/// - `peel` on an annotated tag fills `peeled` with the underlying
///   commit.
/// - `symrefs` surfaces the target of symbolic refs as the
///   `symref-target`.
#[cfg(all(feature = "serve-upload-pack", feature = "blocking-network-client"))]
fn ls_refs_from_repo(
    repo: &Repository,
    request: &gix_protocol::upload_pack::LsRefsRequest,
) -> Result<Vec<gix_protocol::upload_pack::LsRefsRefEntry>, Box<dyn std::error::Error + Send + Sync + 'static>> {
    let platform = repo
        .references()
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync + 'static>)?;
    let all = platform
        .all()
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync + 'static>)?;
    let mut out: Vec<gix_protocol::upload_pack::LsRefsRefEntry> = Vec::new();
    for r in all {
        let mut r = r?;
        let full_name_bstr = r.name().as_bstr().to_owned();
        if !request.prefixes.is_empty() && !request.prefixes.iter().any(|p| full_name_bstr.starts_with(p.as_ref())) {
            continue;
        }
        let direct = r.target().try_id().map(ToOwned::to_owned);
        let peeled = if request.peel {
            r.peel_to_id().ok().map(crate::Id::detach)
        } else {
            None
        };
        // Include the peeled OID only when it differs from the direct
        // target (i.e. the ref is an annotated tag).
        let peeled_if_different = match (peeled, direct) {
            (Some(p), Some(d)) if p != d => Some(p),
            _ => None,
        };
        let symref_target = if request.symrefs {
            match r.target() {
                gix_ref::TargetRef::Symbolic(name) => Some(name.as_bstr().to_owned()),
                _ => None,
            }
        } else {
            None
        };
        out.push(gix_protocol::upload_pack::LsRefsRefEntry {
            object: direct,
            name: full_name_bstr,
            symref_target,
            peeled: peeled_if_different,
        });
    }
    Ok(out)
}

#[cfg(feature = "serve-upload-pack")]
impl Repository {
    /// Drive a server-side v2 `git-upload-pack` interaction using
    /// caller-supplied negotiation and pack-generation closures.
    ///
    /// The heavy lifting - walking the object graph to decide
    /// acknowledgements and streaming the pack itself - is delegated
    /// through the two closures because the underlying building blocks
    /// in `gix-pack` do not yet support server-side thin-pack
    /// generation. Until those ship, embedders that can bring their own
    /// pack generator (for example, one that shells out to a trusted
    /// git binary, or one backed by a future `gix-pack` API) can use
    /// this method to get the protocol framing for free.
    ///
    /// `negotiate` receives the parsed fetch request and returns a
    /// [`gix_protocol::upload_pack::ServeResponse`] describing which
    /// acknowledgements to emit and whether the pack should follow.
    /// `write_pack` streams the pack bytes when `ServeResponse::
    /// send_pack` is true.
    pub fn serve_pack_upload_v2<R, W, N, P>(
        &self,
        reader: R,
        writer: &mut W,
        negotiate: N,
        write_pack: P,
    ) -> Result<gix_protocol::upload_pack::ServeV2Outcome, ServePackUploadError>
    where
        R: std::io::Read,
        W: std::io::Write,
        N: FnOnce(
            &gix_protocol::upload_pack::FetchRequest,
        ) -> Result<
            gix_protocol::upload_pack::ServeResponse,
            Box<dyn std::error::Error + Send + Sync + 'static>,
        >,
        P: FnOnce(&mut dyn std::io::Write) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>>,
    {
        let outcome = gix_protocol::upload_pack::serve_v2(reader, writer, negotiate, write_pack)?;
        Ok(outcome)
    }
}

#[cfg(feature = "serve-receive-pack")]
impl Repository {
    /// Drive a server-side `git-receive-pack` interaction limited to
    /// delete-only pushes.
    ///
    /// Reads the client's update-request from `reader`, verifies that
    /// every command is a deletion (zero `new-id`), applies the
    /// deletions through this repository's reference store via
    /// [`Repository::edit_references`], and writes the framed
    /// `report-status` response to `writer`.
    ///
    /// Non-deletion commands are **rejected with an explanatory
    /// reason** in the response (`ng <refname> pack ingestion not
    /// implemented on this serve path`). This keeps the endpoint
    /// spec-conformant - the client sees a real `report-status` with
    /// per-ref outcomes - while limiting the scope to the subset that
    /// does not require integrating `gix-pack`'s streaming ingest.
    ///
    /// For the general case with actual pack ingest, use
    /// [`Self::serve_pack_receive`] (creates + updates + deletes via
    /// `gix_pack::Bundle::write_to_directory`) or
    /// [`Self::serve_pack_receive_with_hooks`] when hooks are needed.
    /// This entry point is kept because it requires no pack-generation
    /// features, making it useful for minimal server builds that only
    /// need to accept deletion pushes.
    pub fn serve_pack_receive_delete_only<R: std::io::Read, W: std::io::Write>(
        &self,
        reader: R,
        writer: &mut W,
    ) -> Result<gix_protocol::receive_pack::ServeOutcome, ServePackReceiveError> {
        use gix_protocol::receive_pack::{serve_with_options_and_hooks, ServeHooks, ServeOptions, UpdateOutcome};
        use gix_ref::transaction::{Change, PreviousValue, RefEdit, RefLog};

        // Delete-only endpoint is delete-only by contract; always
        // accept deletions regardless of any wider server policy —
        // any other posture would be self-inconsistent.
        let options = ServeOptions { allow_deletes: true };
        let outcome = serve_with_options_and_hooks(
            reader,
            writer,
            |_reader| {
                // Delete-only path: the client SHOULD NOT send a pack.
                // We do not drain trailing bytes here; the caller closes
                // the underlying stream once this function returns.
                Ok(())
            },
            |commands, _atomic| {
                let mut outcomes = Vec::with_capacity(commands.len());
                let mut deletions = Vec::with_capacity(commands.len());
                for cmd in commands {
                    if !cmd.is_delete() {
                        outcomes.push(UpdateOutcome::Rejected(
                            "pack ingestion not implemented on this serve path".into(),
                        ));
                        continue;
                    }
                    let name = match gix_ref::FullName::try_from(cmd.refname.clone()) {
                        Ok(n) => n,
                        Err(_) => {
                            outcomes.push(UpdateOutcome::Rejected("invalid refname".into()));
                            continue;
                        }
                    };
                    deletions.push((
                        outcomes.len(),
                        cmd,
                        RefEdit {
                            change: Change::Delete {
                                expected: PreviousValue::MustExistAndMatch(gix_ref::Target::Object(cmd.old_id)),
                                log: RefLog::AndReference,
                            },
                            name,
                            deref: false,
                        },
                    ));
                    outcomes.push(UpdateOutcome::accepted());
                }

                if deletions.is_empty() {
                    return Ok(outcomes);
                }

                let edits: Vec<RefEdit> = deletions.iter().map(|(_, _, edit)| edit.clone()).collect();
                match self.edit_references(edits) {
                    Ok(_) => (),
                    Err(err) => {
                        // Roll per-command outcomes back to a rejection
                        // using the transaction error as the reason.
                        let reason: crate::bstr::BString = err.to_string().into();
                        for (idx, _, _) in &deletions {
                            outcomes[*idx] = UpdateOutcome::Rejected(reason.clone());
                        }
                    }
                }
                Ok(outcomes)
            },
            ServeHooks::default(),
            options,
        )?;
        Ok(outcome)
    }
}
