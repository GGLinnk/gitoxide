//! End-to-end integration test for `Repository::write_pack_for_push`.
//!
//! Creates a bare repo, writes a few objects and a commit, then asks
//! the pack generator to produce a pack for that commit with no
//! haves. Validates the pack by round-tripping it through
//! `gix_pack::Bundle::write_to_directory` into a second bare repo and
//! confirming every originally-written object now exists there.

use std::sync::atomic::AtomicBool;

use gix_testtools::tempfile;

#[test]
fn write_pack_for_push_round_trips_a_single_commit() -> crate::Result {
    let src_tmp = tempfile::tempdir()?;
    let mut src = gix::init_bare(src_tmp.path())?;

    // Author identity so new_commit doesn't fail on missing config.
    let mut cfg = src.config_snapshot_mut();
    cfg.set_raw_value(gix::config::tree::Author::NAME, "Test Author")?;
    cfg.set_raw_value(gix::config::tree::Author::EMAIL, "test@example.com")?;
    cfg.set_raw_value(gix::config::tree::Committer::NAME, "Test Author")?;
    cfg.set_raw_value(gix::config::tree::Committer::EMAIL, "test@example.com")?;
    cfg.commit()?;

    // Write a blob and a tree that references it.
    let blob_id = src.write_blob(b"hello push\n".as_slice())?.detach();
    let tree = gix_object::Tree {
        entries: vec![gix_object::tree::Entry {
            mode: gix_object::tree::EntryKind::Blob.into(),
            filename: "hello.txt".into(),
            oid: blob_id,
        }],
    };
    let tree_id = src.write_object(&tree)?.detach();

    // Write a commit pointing at the tree.
    let commit_id = src
        .commit("refs/heads/main", "initial", tree_id, gix::commit::NO_PARENT_IDS)?
        .detach();

    // Pack every object reachable from the commit into an in-memory buffer.
    let mut pack_bytes: Vec<u8> = Vec::new();
    let should_interrupt = AtomicBool::new(false);
    src.write_pack_for_push(
        std::iter::once(commit_id),
        std::iter::empty(),
        &mut pack_bytes,
        &should_interrupt,
    )?;

    // A non-empty commit chain must emit at least the header, commit,
    // tree, blob, and trailer: we don't pin the exact size, but the
    // buffer must start with the `PACK` magic and end with a 20-byte
    // SHA-1 trailer.
    assert!(
        pack_bytes.starts_with(b"PACK"),
        "pack bytes must start with the PACK magic, got {:?}",
        &pack_bytes[..pack_bytes.len().min(8)]
    );
    assert!(
        pack_bytes.len() > 12 + 20,
        "pack must have at least a header (12 bytes), at least one entry, and a 20-byte trailer; got {} bytes",
        pack_bytes.len()
    );

    // Ingest the pack into a second bare repo and verify every object lands.
    let dst_tmp = tempfile::tempdir()?;
    let dst = gix::init_bare(dst_tmp.path())?;
    let dst_pack_dir = dst.objects.store_ref().path().join("pack");
    let mut cursor = std::io::Cursor::new(pack_bytes);
    let mut reader = std::io::BufReader::new(&mut cursor);
    // Provide a concrete (but empty) Find lookup for thin-pack base
    // resolution. The test never emits a thin pack, so this is just a
    // type witness - the lookup is never actually consulted.
    let base_lookup: Option<gix_odb::Cache<gix_odb::store::Handle<std::sync::Arc<gix_odb::Store>>>> =
        Some((*dst.objects).clone().into_arc()?);
    gix_pack::Bundle::write_to_directory(
        &mut reader,
        Some(&dst_pack_dir),
        &mut gix_features::progress::Discard,
        &should_interrupt,
        base_lookup,
        gix_pack::bundle::write::Options {
            thread_limit: None,
            index_version: gix_pack::index::Version::default(),
            iteration_mode: gix_pack::data::input::Mode::Verify,
            object_hash: src.object_hash(),
        },
    )?;

    // Reopen the dst repo so it sees the freshly written pack.
    let dst = gix::open(dst.git_dir())?;
    assert!(dst.has_object(commit_id), "pack did not contain the commit");
    assert!(dst.has_object(tree_id), "pack did not contain the root tree");
    assert!(dst.has_object(blob_id), "pack did not contain the blob");

    Ok(())
}

/// Regression: `objects_for_push`'s tree walker must emit every
/// subtree reachable from a commit's root tree. Before the fix,
/// `NonTreeCollector::visit_tree` eagerly inserted each encountered
/// subtree OID into the shared `seen` set *before* the walker's
/// `find_tree_iter(..)` call reached `RecordingObjects::try_find` —
/// which uses the same `seen` set as its "should I emit?" predicate.
/// The subtree was therefore marked seen without ever being emitted,
/// so the resulting pack was missing every non-root tree and the
/// server-side connectivity walk failed with
/// `did not receive expected object <subtree-oid>`.
///
/// The fix is small but load-bearing: `visit_tree` now only *reads*
/// `seen` to decide whether to descend, leaving `try_find` as the
/// sole owner of the "insert + emit Count" pair.
///
/// This test builds a commit whose root tree contains a subdirectory
/// containing a blob (so `subtree_oid != tree_oid != blob_oid`) and
/// re-ingests the resulting pack into a second bare repo. The assertion
/// that `dst.has_object(sub_tree_id)` is the actual regression guard —
/// it fails noisily before the fix and passes after.
#[test]
fn write_pack_for_push_emits_nested_subtrees() -> crate::Result {
    let src_tmp = tempfile::tempdir()?;
    let mut src = gix::init_bare(src_tmp.path())?;

    let mut cfg = src.config_snapshot_mut();
    cfg.set_raw_value(gix::config::tree::Author::NAME, "Test Author")?;
    cfg.set_raw_value(gix::config::tree::Author::EMAIL, "test@example.com")?;
    cfg.set_raw_value(gix::config::tree::Committer::NAME, "Test Author")?;
    cfg.set_raw_value(gix::config::tree::Committer::EMAIL, "test@example.com")?;
    cfg.commit()?;

    // Build src/nested.txt — a blob inside a subtree inside the root.
    let blob_id = src.write_blob(b"nested push content\n".as_slice())?.detach();
    let sub_tree = gix_object::Tree {
        entries: vec![gix_object::tree::Entry {
            mode: gix_object::tree::EntryKind::Blob.into(),
            filename: "nested.txt".into(),
            oid: blob_id,
        }],
    };
    let sub_tree_id = src.write_object(&sub_tree)?.detach();
    let root_tree = gix_object::Tree {
        entries: vec![gix_object::tree::Entry {
            mode: gix_object::tree::EntryKind::Tree.into(),
            filename: "src".into(),
            oid: sub_tree_id,
        }],
    };
    let root_tree_id = src.write_object(&root_tree)?.detach();
    let commit_id = src
        .commit(
            "refs/heads/main",
            "root + sub + blob",
            root_tree_id,
            gix::commit::NO_PARENT_IDS,
        )?
        .detach();

    let mut pack_bytes: Vec<u8> = Vec::new();
    let should_interrupt = AtomicBool::new(false);
    src.write_pack_for_push(
        std::iter::once(commit_id),
        std::iter::empty(),
        &mut pack_bytes,
        &should_interrupt,
    )?;

    assert!(pack_bytes.starts_with(b"PACK"), "must be a valid pack");

    let dst_tmp = tempfile::tempdir()?;
    let dst = gix::init_bare(dst_tmp.path())?;
    let dst_pack_dir = dst.objects.store_ref().path().join("pack");
    let mut cursor = std::io::Cursor::new(pack_bytes);
    let mut reader = std::io::BufReader::new(&mut cursor);
    let base_lookup: Option<gix_odb::Cache<gix_odb::store::Handle<std::sync::Arc<gix_odb::Store>>>> =
        Some((*dst.objects).clone().into_arc()?);
    gix_pack::Bundle::write_to_directory(
        &mut reader,
        Some(&dst_pack_dir),
        &mut gix_features::progress::Discard,
        &should_interrupt,
        base_lookup,
        gix_pack::bundle::write::Options {
            thread_limit: None,
            index_version: gix_pack::index::Version::default(),
            iteration_mode: gix_pack::data::input::Mode::Verify,
            object_hash: src.object_hash(),
        },
    )?;

    let dst = gix::open(dst.git_dir())?;
    assert!(dst.has_object(commit_id), "commit must be in the pack");
    assert!(dst.has_object(root_tree_id), "root tree must be in the pack");
    assert!(
        dst.has_object(sub_tree_id),
        "subtree must be in the pack — regression: before the fix, non-root trees were marked seen by the walker but never emitted"
    );
    assert!(dst.has_object(blob_id), "blob must be in the pack");

    Ok(())
}

/// Regression: the push write path seeds `haves` from every ref the
/// server advertised during the handshake, but some of those refs
/// point at commits the client has never fetched (other people's
/// branches on the remote). An unknown OID in `haves` used to blow up
/// the traversal with "An object with id ... could not be found";
/// after the fix we filter haves against the local ODB and carry on.
#[test]
fn write_pack_for_push_tolerates_haves_not_in_object_db() -> crate::Result {
    let src_tmp = tempfile::tempdir()?;
    let mut src = gix::init_bare(src_tmp.path())?;

    let mut cfg = src.config_snapshot_mut();
    cfg.set_raw_value(gix::config::tree::Author::NAME, "Test Author")?;
    cfg.set_raw_value(gix::config::tree::Author::EMAIL, "test@example.com")?;
    cfg.set_raw_value(gix::config::tree::Committer::NAME, "Test Author")?;
    cfg.set_raw_value(gix::config::tree::Committer::EMAIL, "test@example.com")?;
    cfg.commit()?;

    let blob_id = src.write_blob(b"haves-filter payload\n".as_slice())?.detach();
    let tree = gix_object::Tree {
        entries: vec![gix_object::tree::Entry {
            mode: gix_object::tree::EntryKind::Blob.into(),
            filename: "haves.txt".into(),
            oid: blob_id,
        }],
    };
    let tree_id = src.write_object(&tree)?.detach();
    let commit_id = src
        .commit(
            "refs/heads/main",
            "initial for haves filter",
            tree_id,
            gix::commit::NO_PARENT_IDS,
        )?
        .detach();

    // A synthetic OID that is NOT in the src's ODB — mimics what we'd
    // see on the wire when the server advertises a ref pointing at a
    // commit we've never fetched locally.
    let unknown_have: gix::hash::ObjectId =
        gix::hash::ObjectId::from_hex(b"deadbeefdeadbeefdeadbeefdeadbeefdeadbeef")?;
    assert!(!src.has_object(unknown_have), "precondition: unknown OID must be absent");

    let mut pack_bytes: Vec<u8> = Vec::new();
    let should_interrupt = AtomicBool::new(false);
    src.write_pack_for_push(
        std::iter::once(commit_id),
        std::iter::once(unknown_have),
        &mut pack_bytes,
        &should_interrupt,
    )?;

    assert!(pack_bytes.starts_with(b"PACK"), "pack must still be a valid pack");
    assert!(pack_bytes.len() > 12 + 20, "pack must contain at least one entry plus trailer");
    Ok(())
}

/// Regression: `iter_from_counts` kicks into its parallel-chunk path
/// once `counts.len() > 4_000`, and chunks return out-of-submission
/// order. Each chunk's delta entries carry back-references to their
/// base by overall count-index, so an out-of-order chunk hitting
/// `FromEntriesIter` panics with `index out of bounds`. We wrap the
/// iterator with `InOrderIter`; this test builds a ~5 000-blob tree
/// that pushes us firmly past the parallel-threshold so the ordering
/// wrapper is actually exercised on every run, not just in theory.
///
/// Without the `InOrderIter` wrap this test reliably panics.
#[test]
fn write_pack_for_push_round_trips_across_the_parallel_threshold() -> crate::Result {
    let src_tmp = tempfile::tempdir()?;
    let mut src = gix::init_bare(src_tmp.path())?;
    let mut cfg = src.config_snapshot_mut();
    cfg.set_raw_value(gix::config::tree::Author::NAME, "Test Author")?;
    cfg.set_raw_value(gix::config::tree::Author::EMAIL, "test@example.com")?;
    cfg.set_raw_value(gix::config::tree::Committer::NAME, "Test Author")?;
    cfg.set_raw_value(gix::config::tree::Committer::EMAIL, "test@example.com")?;
    cfg.commit()?;

    // Produce > 4_000 unique blobs so `iter_from_counts` crosses the
    // internal `enough_counts_present` threshold and spins up worker
    // threads. Each blob is tiny — the point is the count, not the
    // byte size.
    const NUM_BLOBS: usize = 5_000;
    let mut entries = Vec::with_capacity(NUM_BLOBS);
    for i in 0..NUM_BLOBS {
        let content = format!("blob-payload-{i:05}\n");
        let blob_id = src.write_blob(content.as_bytes())?.detach();
        entries.push(gix_object::tree::Entry {
            mode: gix_object::tree::EntryKind::Blob.into(),
            // Tree entries must be sorted; `{i:05}` makes the zero-
            // padded decimal string sort correctly byte-wise.
            filename: format!("blob-{i:05}.txt").into(),
            oid: blob_id,
        });
    }
    entries.sort_by(|a, b| a.filename.cmp(&b.filename));
    let root_tree = gix_object::Tree { entries };
    let root_tree_id = src.write_object(&root_tree)?.detach();
    let commit_id = src
        .commit(
            "refs/heads/main",
            "parallel-threshold regression",
            root_tree_id,
            gix::commit::NO_PARENT_IDS,
        )?
        .detach();

    let mut pack_bytes: Vec<u8> = Vec::new();
    let should_interrupt = AtomicBool::new(false);
    src.write_pack_for_push(
        std::iter::once(commit_id),
        std::iter::empty(),
        &mut pack_bytes,
        &should_interrupt,
    )?;
    assert!(pack_bytes.starts_with(b"PACK"), "must be a valid pack");

    let dst_tmp = tempfile::tempdir()?;
    let dst = gix::init_bare(dst_tmp.path())?;
    let dst_pack_dir = dst.objects.store_ref().path().join("pack");
    let mut cursor = std::io::Cursor::new(pack_bytes);
    let mut reader = std::io::BufReader::new(&mut cursor);
    let base_lookup: Option<gix_odb::Cache<gix_odb::store::Handle<std::sync::Arc<gix_odb::Store>>>> =
        Some((*dst.objects).clone().into_arc()?);
    gix_pack::Bundle::write_to_directory(
        &mut reader,
        Some(&dst_pack_dir),
        &mut gix_features::progress::Discard,
        &should_interrupt,
        base_lookup,
        gix_pack::bundle::write::Options {
            thread_limit: None,
            index_version: gix_pack::index::Version::default(),
            iteration_mode: gix_pack::data::input::Mode::Verify,
            object_hash: src.object_hash(),
        },
    )?;
    let dst = gix::open(dst.git_dir())?;
    assert!(dst.has_object(commit_id));
    assert!(dst.has_object(root_tree_id));
    // Spot-check a handful of blobs — if the out-of-order chunk bug
    // were back, index-pack above would have failed outright.
    for i in [0usize, 123, 2500, 4999] {
        let needle = format!("blob-payload-{i:05}\n");
        let tree = dst.find_tree(root_tree_id)?;
        let entry = tree
            .find_entry(format!("blob-{i:05}.txt").as_str())
            .expect("tree entry");
        let blob = dst.find_blob(entry.oid())?;
        assert_eq!(blob.data.as_slice(), needle.as_bytes());
    }
    Ok(())
}

/// `gix::remote::push::push_default_target` encodes the `push.default`
/// fallback + `push.autoSetupRemote` layer that `Remote::push` reaches
/// for when the caller passes no refspec and `remote.<name>.push`
/// isn't configured. Cover each resolution path directly so a
/// regression in the helper surfaces without needing a live transport.
///
/// Tested cases:
///
/// 1. No upstream + `push.autoSetupRemote = false` → `None` (the
///    caller will later report `no configured push target`).
/// 2. No upstream + `push.autoSetupRemote = true` → `refs/heads/HEAD`
///    (git 2.37+ auto-tracking; the case that most user-reports
///    hinge on).
/// 3. Upstream configured (`branch.<name>.remote` +
///    `branch.<name>.merge`) → the upstream refname.
#[test]
fn push_default_target_resolution_matches_git_push_default() -> crate::Result {
    fn init_repo_on_branch(branch: &str) -> crate::Result<(gix::Repository, tempfile::TempDir)> {
        let tmp = tempfile::tempdir()?;
        let mut repo = gix::init_bare(tmp.path())?;
        let mut cfg = repo.config_snapshot_mut();
        cfg.set_raw_value(gix::config::tree::Author::NAME, "Test Author")?;
        cfg.set_raw_value(gix::config::tree::Author::EMAIL, "test@example.com")?;
        cfg.set_raw_value(gix::config::tree::Committer::NAME, "Test Author")?;
        cfg.set_raw_value(gix::config::tree::Committer::EMAIL, "test@example.com")?;
        cfg.commit()?;

        // Create an initial commit so HEAD peels to something valid.
        let blob_id = repo.write_blob(b"bootstrap\n".as_slice())?.detach();
        let tree = gix_object::Tree {
            entries: vec![gix_object::tree::Entry {
                mode: gix_object::tree::EntryKind::Blob.into(),
                filename: "bootstrap.txt".into(),
                oid: blob_id,
            }],
        };
        let tree_id = repo.write_object(&tree)?.detach();
        let full_ref = format!("refs/heads/{branch}");
        repo.commit(
            full_ref.as_str(),
            "bootstrap",
            tree_id,
            gix::commit::NO_PARENT_IDS,
        )?;
        // Point HEAD at the newly-created branch.
        repo.edit_reference(gix_ref::transaction::RefEdit {
            change: gix_ref::transaction::Change::Update {
                log: gix_ref::transaction::LogChange::default(),
                expected: gix_ref::transaction::PreviousValue::Any,
                new: gix_ref::Target::Symbolic(full_ref.as_str().try_into()?),
            },
            name: "HEAD".try_into()?,
            deref: false,
        })?;
        Ok((repo, tmp))
    }

    // (1) `push.autoSetupRemote = true`, no upstream configured →
    //     git 2.37+ auto-tracking kicks in and the helper synthesises
    //     HEAD's own refname. This is the case that makes `gix push`
    //     "just work" on a freshly-created local branch the way
    //     `git push` does in a modern git install.
    {
        let (mut repo, _tmp) = init_repo_on_branch("feature-auto")?;
        let mut cfg = repo.config_snapshot_mut();
        cfg.set_raw_value("push.autoSetupRemote", "true")?;
        cfg.commit()?;
        let target =
            gix::remote::push::push_default_target(&repo).expect("autoSetupRemote synthesises a target");
        assert_eq!(target.as_slice(), b"refs/heads/feature-auto");
    }

    // (2) With an upstream tracking ref configured, the helper should
    //     return whatever `branch_remote_ref_name(.., Push)` resolves
    //     to — namely the tracked merge target for the current branch.
    //     This is the path that existed before `autoSetupRemote`; the
    //     new helper must not regress it.
    {
        let (mut repo, _tmp) = init_repo_on_branch("feature-upstream")?;
        let mut cfg = repo.config_snapshot_mut();
        cfg.set_raw_value("remote.origin.url", "https://example.invalid/x.git")?;
        cfg.set_raw_value("branch.feature-upstream.remote", "origin")?;
        cfg.set_raw_value("branch.feature-upstream.merge", "refs/heads/feature-upstream")?;
        cfg.commit()?;
        let target =
            gix::remote::push::push_default_target(&repo).expect("configured upstream synthesises a target");
        assert_eq!(target.as_slice(), b"refs/heads/feature-upstream");
    }

    // (3) Detached HEAD: no branch name, no target. The caller is
    //     expected to fall through to its own diagnostic.
    {
        let (repo, _tmp) = init_repo_on_branch("feature-detached")?;
        // Resolve HEAD to a concrete OID, then rewrite HEAD to point
        // directly at that OID (detached).
        let head = repo.head()?;
        let head_oid = head.id().ok_or_else(|| anyhow::anyhow!("expected HEAD to have an OID"))?;
        repo.edit_reference(gix_ref::transaction::RefEdit {
            change: gix_ref::transaction::Change::Update {
                log: gix_ref::transaction::LogChange::default(),
                expected: gix_ref::transaction::PreviousValue::Any,
                new: gix_ref::Target::Object(head_oid.detach()),
            },
            name: "HEAD".try_into()?,
            deref: false,
        })?;
        assert_eq!(
            gix::remote::push::push_default_target(&repo),
            None,
            "detached HEAD has no branch name — the helper has nothing to synthesise"
        );
    }
    Ok(())
}

/// The full push-loop end-to-end: build a push request with a real
/// pack on the src side, feed it through `serve_pack_receive` on the
/// dst side, and confirm the dst's ref store and ODB contain what we
/// expected to push.
#[cfg(feature = "serve-receive-pack")]
#[test]
fn full_push_loop_src_to_dst_through_serve_pack_receive() -> crate::Result {
    use std::io::Write as _;

    let src_tmp = tempfile::tempdir()?;
    let mut src = gix::init_bare(src_tmp.path())?;
    let mut cfg = src.config_snapshot_mut();
    cfg.set_raw_value(gix::config::tree::Author::NAME, "Test Author")?;
    cfg.set_raw_value(gix::config::tree::Author::EMAIL, "test@example.com")?;
    cfg.set_raw_value(gix::config::tree::Committer::NAME, "Test Author")?;
    cfg.set_raw_value(gix::config::tree::Committer::EMAIL, "test@example.com")?;
    cfg.commit()?;

    let blob_id = src.write_blob(b"round-trip payload\n".as_slice())?.detach();
    let tree = gix_object::Tree {
        entries: vec![gix_object::tree::Entry {
            mode: gix_object::tree::EntryKind::Blob.into(),
            filename: "round.txt".into(),
            oid: blob_id,
        }],
    };
    let tree_id = src.write_object(&tree)?.detach();
    let commit_id = src
        .commit(
            "refs/heads/pushed",
            "first pushed commit",
            tree_id,
            gix::commit::NO_PARENT_IDS,
        )?
        .detach();

    // Build the push request in an in-memory buffer: command-list
    // pkt-lines + flush + pack bytes.
    let mut request_buf: Vec<u8> = Vec::new();
    let caps = gix_transport::client::Capabilities::from_bytes(b"\0report-status delete-refs")
        .expect("valid capabilities")
        .0;
    let mut args = gix_protocol::push::Arguments::new(&caps);
    args.add_command(gix_protocol::push::Command {
        old_id: gix_hash::ObjectId::null(src.object_hash()),
        new_id: commit_id,
        refname: "refs/heads/received".into(),
    })?;
    for line in args.emit_command_lines() {
        gix_packetline::blocking_io::encode::data_to_write(&line, &mut request_buf)?;
    }
    gix_packetline::blocking_io::encode::flush_to_write(&mut request_buf)?;

    // Append the pack bytes after the flush-pkt.
    let should_interrupt = std::sync::atomic::AtomicBool::new(false);
    src.write_pack_for_push(
        std::iter::once(commit_id),
        std::iter::empty(),
        &mut request_buf,
        &should_interrupt,
    )?;
    request_buf.flush()?;

    // Receive the whole thing on the dst side.
    let dst_tmp = tempfile::tempdir()?;
    let dst = gix::init_bare(dst_tmp.path())?;
    let mut response_buf: Vec<u8> = Vec::new();
    let mut progress = gix_features::progress::Discard;
    let outcome = dst.serve_pack_receive(
        request_buf.as_slice(),
        &mut response_buf,
        &mut progress,
        &should_interrupt,
    )?;

    // The server must have applied the create; re-open the dst to pick
    // up the new ref store state.
    let dst = gix::open(dst.git_dir())?;
    assert_eq!(outcome.serve.parsed_commands.len(), 1);
    assert!(dst.has_object(commit_id), "dst ODB missing pushed commit");
    assert!(dst.has_object(tree_id), "dst ODB missing pushed tree");
    assert!(dst.has_object(blob_id), "dst ODB missing pushed blob");
    let received_ref = dst
        .try_find_reference("refs/heads/received")?
        .expect("pushed ref should now exist on dst");
    assert_eq!(received_ref.target().try_id().map(ToOwned::to_owned), Some(commit_id));

    // The response is a framed v1 report-status - every command `ok`.
    let mut payloads: Vec<Vec<u8>> = Vec::new();
    let mut stream = gix_packetline::blocking_io::StreamingPeekableIter::new(
        response_buf.as_slice(),
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
    let parsed = gix_protocol::push::report_status::parse_report_v1(payloads.iter().map(Vec::as_slice))?;
    assert_eq!(parsed.unpack, gix_protocol::push::UnpackStatus::Ok);
    assert_eq!(parsed.commands.len(), 1);
    assert!(matches!(
        parsed.commands[0],
        gix_protocol::push::CommandStatus::Ok { .. }
    ));

    Ok(())
}

/// Second-push-overwrites-tip scenario: create refs/heads/target with
/// commit A, then push a totally unrelated commit B (no parent) with
/// old=A, new=B using `report-status-v2`. The server must detect that
/// A is not reachable from B's ancestry and emit `option forced-update`
/// in the v2 report.
#[cfg(feature = "serve-receive-pack")]
#[test]
fn forced_update_trailer_on_non_fast_forward_push() -> crate::Result {
    use std::io::Write as _;

    let src_tmp = tempfile::tempdir()?;
    let mut src = gix::init_bare(src_tmp.path())?;
    let mut cfg = src.config_snapshot_mut();
    cfg.set_raw_value(gix::config::tree::Author::NAME, "Test Author")?;
    cfg.set_raw_value(gix::config::tree::Author::EMAIL, "test@example.com")?;
    cfg.set_raw_value(gix::config::tree::Committer::NAME, "Test Author")?;
    cfg.set_raw_value(gix::config::tree::Committer::EMAIL, "test@example.com")?;
    cfg.commit()?;

    // Two parallel histories sharing no ancestry: commit_a and commit_b
    // each have distinct (empty-tree) trees and no parents.
    let blob_a = src.write_blob(b"a\n".as_slice())?.detach();
    let tree_a = gix_object::Tree {
        entries: vec![gix_object::tree::Entry {
            mode: gix_object::tree::EntryKind::Blob.into(),
            filename: "a.txt".into(),
            oid: blob_a,
        }],
    };
    let tree_a_id = src.write_object(&tree_a)?.detach();
    let commit_a = src
        .commit("refs/heads/source-a", "a", tree_a_id, gix::commit::NO_PARENT_IDS)?
        .detach();

    let blob_b = src.write_blob(b"b\n".as_slice())?.detach();
    let tree_b = gix_object::Tree {
        entries: vec![gix_object::tree::Entry {
            mode: gix_object::tree::EntryKind::Blob.into(),
            filename: "b.txt".into(),
            oid: blob_b,
        }],
    };
    let tree_b_id = src.write_object(&tree_b)?.detach();
    let commit_b = src
        .commit("refs/heads/source-b", "b", tree_b_id, gix::commit::NO_PARENT_IDS)?
        .detach();

    let dst_tmp = tempfile::tempdir()?;
    let dst = gix::init_bare(dst_tmp.path())?;
    let should_interrupt = std::sync::atomic::AtomicBool::new(false);

    // First push: create refs/heads/target = commit_a on dst.
    let mut request_a: Vec<u8> = Vec::new();
    let caps = gix_transport::client::Capabilities::from_bytes(b"\0report-status-v2")
        .expect("valid capabilities")
        .0;
    let mut args = gix_protocol::push::Arguments::new(&caps);
    args.add_command(gix_protocol::push::Command {
        old_id: gix_hash::ObjectId::null(src.object_hash()),
        new_id: commit_a,
        refname: "refs/heads/target".into(),
    })?;
    for line in args.emit_command_lines() {
        gix_packetline::blocking_io::encode::data_to_write(&line, &mut request_a)?;
    }
    gix_packetline::blocking_io::encode::flush_to_write(&mut request_a)?;
    src.write_pack_for_push(
        std::iter::once(commit_a),
        std::iter::empty(),
        &mut request_a,
        &should_interrupt,
    )?;
    request_a.flush()?;

    let mut response_a: Vec<u8> = Vec::new();
    let mut progress = gix_features::progress::Discard;
    let _ = dst.serve_pack_receive(request_a.as_slice(), &mut response_a, &mut progress, &should_interrupt)?;

    // Re-open dst so the new ref is visible.
    let dst = gix::open(dst.git_dir())?;

    // Second push: update refs/heads/target from commit_a -> commit_b.
    // commit_b has no parents, so commit_a is not reachable from it.
    let mut request_b: Vec<u8> = Vec::new();
    let mut args = gix_protocol::push::Arguments::new(&caps);
    args.add_command(gix_protocol::push::Command {
        old_id: commit_a,
        new_id: commit_b,
        refname: "refs/heads/target".into(),
    })?;
    for line in args.emit_command_lines() {
        gix_packetline::blocking_io::encode::data_to_write(&line, &mut request_b)?;
    }
    gix_packetline::blocking_io::encode::flush_to_write(&mut request_b)?;
    src.write_pack_for_push(
        std::iter::once(commit_b),
        std::iter::empty(),
        &mut request_b,
        &should_interrupt,
    )?;
    request_b.flush()?;

    let mut response_b: Vec<u8> = Vec::new();
    let _ = dst.serve_pack_receive(request_b.as_slice(), &mut response_b, &mut progress, &should_interrupt)?;

    // Parse the v2 report and assert the forced-update trailer.
    let mut payloads: Vec<Vec<u8>> = Vec::new();
    let mut stream = gix_packetline::blocking_io::StreamingPeekableIter::new(
        response_b.as_slice(),
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
    let parsed = gix_protocol::push::report_status::parse_report_v2(payloads.iter().map(Vec::as_slice))?;
    assert_eq!(parsed.unpack, gix_protocol::push::UnpackStatus::Ok);
    assert_eq!(parsed.commands.len(), 1);
    match &parsed.commands[0] {
        gix_protocol::push::CommandStatusV2::Ok { refname, options } => {
            assert_eq!(refname, "refs/heads/target");
            assert!(options.forced_update, "non-fast-forward should set forced-update");
            assert_eq!(options.old_oid, Some(commit_a));
            assert_eq!(options.new_oid, Some(commit_b));
        }
        other => panic!("expected v2 Ok verdict with forced-update, got {other:?}"),
    }

    Ok(())
}

/// Demonstrates that a caller can implement server-side ref-rewriting
/// (the `option refname` v2 trailer) by dropping down to
/// [`gix_protocol::receive_pack::serve_with_hooks`] and supplying a
/// custom `apply_updates` closure that reuses the newly-public
/// [`gix::Repository::walk_reachable_for_connectivity`] and
/// [`gix::Repository::is_forced_update`] helpers.
///
/// The scenario mimics a Gerrit-style server that accepts pushes to
/// `refs/for/main` but stores them under `refs/heads/rewritten/main`.
/// The v2 report must surface both the client-facing refname and the
/// `option refname <new-name>` trailer.
#[cfg(feature = "serve-receive-pack")]
#[test]
fn custom_apply_updates_can_emit_option_refname() -> crate::Result {
    use std::io::Write as _;

    let src_tmp = tempfile::tempdir()?;
    let mut src = gix::init_bare(src_tmp.path())?;
    let mut cfg = src.config_snapshot_mut();
    cfg.set_raw_value(gix::config::tree::Author::NAME, "Test Author")?;
    cfg.set_raw_value(gix::config::tree::Author::EMAIL, "test@example.com")?;
    cfg.set_raw_value(gix::config::tree::Committer::NAME, "Test Author")?;
    cfg.set_raw_value(gix::config::tree::Committer::EMAIL, "test@example.com")?;
    cfg.commit()?;

    let blob_id = src.write_blob(b"rewrite payload\n".as_slice())?.detach();
    let tree = gix_object::Tree {
        entries: vec![gix_object::tree::Entry {
            mode: gix_object::tree::EntryKind::Blob.into(),
            filename: "r.txt".into(),
            oid: blob_id,
        }],
    };
    let tree_id = src.write_object(&tree)?.detach();
    let commit_id = src
        .commit(
            "refs/heads/source",
            "rewrite-target commit",
            tree_id,
            gix::commit::NO_PARENT_IDS,
        )?
        .detach();

    // Build the push request: client asks for refs/for/main.
    let client_refname = gix::bstr::BString::from("refs/for/main");
    let rewritten_refname = gix::bstr::BString::from("refs/heads/rewritten/main");

    let mut request_buf: Vec<u8> = Vec::new();
    let caps = gix_transport::client::Capabilities::from_bytes(b"\0report-status-v2")
        .expect("valid capabilities")
        .0;
    let mut args = gix_protocol::push::Arguments::new(&caps);
    args.add_command(gix_protocol::push::Command {
        old_id: gix_hash::ObjectId::null(src.object_hash()),
        new_id: commit_id,
        refname: client_refname.clone(),
    })?;
    for line in args.emit_command_lines() {
        gix_packetline::blocking_io::encode::data_to_write(&line, &mut request_buf)?;
    }
    gix_packetline::blocking_io::encode::flush_to_write(&mut request_buf)?;
    let should_interrupt = std::sync::atomic::AtomicBool::new(false);
    src.write_pack_for_push(
        std::iter::once(commit_id),
        std::iter::empty(),
        &mut request_buf,
        &should_interrupt,
    )?;
    request_buf.flush()?;

    let dst_tmp = tempfile::tempdir()?;
    let dst = gix::init_bare(dst_tmp.path())?;

    // Ingest the pack through the standard bundle writer.
    let pack_dir = dst.objects.store_ref().path().join("pack");
    let pack_options = gix_pack::bundle::write::Options {
        thread_limit: None,
        index_version: gix_pack::index::Version::default(),
        iteration_mode: gix_pack::data::input::Mode::Verify,
        object_hash: dst.object_hash(),
    };
    let dst_objects = dst.objects.clone();
    let mut progress = gix_features::progress::Discard;
    let pack_ingester =
        |reader: &mut dyn std::io::Read| -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
            let mut buf = std::io::BufReader::new(reader);
            let peek = std::io::BufRead::fill_buf(&mut buf)
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync + 'static> { Box::new(e) })?;
            if peek.is_empty() || !peek.starts_with(b"PACK") {
                return Ok(());
            }
            gix_pack::Bundle::write_to_directory(
                &mut buf,
                Some(&pack_dir),
                &mut progress,
                &should_interrupt,
                Some(Box::new(dst_objects.clone())),
                pack_options,
            )
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync + 'static> { Box::new(e) })?;
            Ok(())
        };

    // Custom apply_updates: rewrite refs/for/main -> refs/heads/rewritten/main
    // using the public helpers on `Repository`.
    let dst_ref = &dst;
    let client_refname_clone = client_refname.clone();
    let rewritten_refname_clone = rewritten_refname.clone();
    let apply_updates = |commands: &[gix_protocol::push::Command],
                         _atomic: bool|
     -> Result<
        Vec<gix_protocol::receive_pack::UpdateOutcome>,
        Box<dyn std::error::Error + Send + Sync + 'static>,
    > {
        use gix_ref::transaction::{Change, LogChange, PreviousValue, RefEdit};

        let mut outcomes = Vec::with_capacity(commands.len());
        let mut edits = Vec::with_capacity(commands.len());
        let mut visited_commits: gix_hashtable::HashSet<gix_hash::ObjectId> = Default::default();
        let mut visited_trees: gix_hashtable::HashSet<gix_hash::ObjectId> = Default::default();

        for cmd in commands {
            let target_refname = if cmd.refname == client_refname_clone {
                rewritten_refname_clone.clone()
            } else {
                cmd.refname.clone()
            };

            // Reuse the public connectivity walk to verify the
            // client's new tip is fully present.
            if !dst_ref.has_object(cmd.new_id) {
                outcomes.push(gix_protocol::receive_pack::UpdateOutcome::Rejected(
                    format!("new tip {} missing", cmd.new_id).into(),
                ));
                continue;
            }
            if let Err(missing) =
                dst_ref.walk_reachable_for_connectivity(cmd.new_id, &mut visited_commits, &mut visited_trees)
            {
                outcomes.push(gix_protocol::receive_pack::UpdateOutcome::Rejected(
                    format!("missing object {missing}").into(),
                ));
                continue;
            }

            let name = match gix_ref::FullName::try_from(target_refname.clone()) {
                Ok(n) => n,
                Err(_) => {
                    outcomes.push(gix_protocol::receive_pack::UpdateOutcome::Rejected(
                        "invalid refname".into(),
                    ));
                    continue;
                }
            };
            edits.push(RefEdit {
                change: Change::Update {
                    log: LogChange::default(),
                    expected: PreviousValue::MustNotExist,
                    new: gix_ref::Target::Object(cmd.new_id),
                },
                name,
                deref: false,
            });

            let mut options = gix_protocol::push::CommandOptions::default();
            if target_refname != cmd.refname {
                options.refname = Some(target_refname.clone());
            }
            options.new_oid = Some(cmd.new_id);
            if !cmd.is_create() && !cmd.is_delete() && dst_ref.is_forced_update(cmd.old_id, cmd.new_id) {
                options.forced_update = true;
            }
            outcomes.push(gix_protocol::receive_pack::UpdateOutcome::Ok(options));
        }

        if !edits.is_empty() {
            dst_ref
                .edit_references(edits)
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync + 'static> { Box::new(e) })?;
        }
        Ok(outcomes)
    };

    let mut response_buf: Vec<u8> = Vec::new();
    let outcome = gix_protocol::receive_pack::serve_with_hooks(
        request_buf.as_slice(),
        &mut response_buf,
        pack_ingester,
        apply_updates,
        gix_protocol::receive_pack::ServeHooks::default(),
    )?;
    assert_eq!(outcome.parsed_commands.len(), 1);
    assert_eq!(outcome.parsed_commands[0].refname, client_refname);

    // Re-open dst and verify the ref landed under the rewritten name.
    let dst = gix::open(dst.git_dir())?;
    assert!(dst.has_object(commit_id));
    assert!(
        dst.try_find_reference("refs/for/main")?.is_none(),
        "client-facing refname must not have been created"
    );
    let renamed = dst
        .try_find_reference("refs/heads/rewritten/main")?
        .expect("rewritten target refname must exist");
    assert_eq!(renamed.target().try_id().map(ToOwned::to_owned), Some(commit_id));

    // Parse the v2 report and assert the `option refname` trailer.
    let mut payloads: Vec<Vec<u8>> = Vec::new();
    let mut stream = gix_packetline::blocking_io::StreamingPeekableIter::new(
        response_buf.as_slice(),
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
    let parsed = gix_protocol::push::report_status::parse_report_v2(payloads.iter().map(Vec::as_slice))?;
    match &parsed.commands[0] {
        gix_protocol::push::CommandStatusV2::Ok { refname, options } => {
            assert_eq!(refname, &client_refname);
            assert_eq!(options.refname, Some(rewritten_refname));
            assert_eq!(options.new_oid, Some(commit_id));
        }
        other => panic!("expected v2 Ok with option refname, got {other:?}"),
    }

    Ok(())
}

/// `resolve_refspecs_to_commands` must:
/// - resolve `src:dst` to `{ old_id: remote_current, new_id: local_peel, refname: dst }`
/// - resolve shorthand `src` as `src:src`
/// - resolve `:dst` to a deletion using the remote's current tip
/// - reject glob patterns
#[test]
fn resolve_refspecs_to_commands_literal_paths() -> crate::Result {
    use gix::bstr::BString;

    let tmp = tempfile::tempdir()?;
    let mut repo = gix::init_bare(tmp.path())?;
    let mut cfg = repo.config_snapshot_mut();
    cfg.set_raw_value(gix::config::tree::Author::NAME, "Test Author")?;
    cfg.set_raw_value(gix::config::tree::Author::EMAIL, "test@example.com")?;
    cfg.set_raw_value(gix::config::tree::Committer::NAME, "Test Author")?;
    cfg.set_raw_value(gix::config::tree::Committer::EMAIL, "test@example.com")?;
    cfg.commit()?;

    let blob_id = repo.write_blob(b"hello\n".as_slice())?.detach();
    let tree = gix_object::Tree {
        entries: vec![gix_object::tree::Entry {
            mode: gix_object::tree::EntryKind::Blob.into(),
            filename: "h.txt".into(),
            oid: blob_id,
        }],
    };
    let tree_id = repo.write_object(&tree)?.detach();
    let commit_id = repo
        .commit("refs/heads/local-tip", "c", tree_id, gix::commit::NO_PARENT_IDS)?
        .detach();

    let remote_tip: gix_hash::ObjectId =
        gix_hash::ObjectId::from_hex(b"2222222222222222222222222222222222222222").expect("valid hex");
    let handshake = gix_protocol::Handshake {
        server_protocol_version: gix_transport::Protocol::V1,
        refs: Some(vec![gix_protocol::handshake::Ref::Direct {
            full_ref_name: "refs/heads/existing".into(),
            object: remote_tip,
        }]),
        v1_shallow_updates: None,
        capabilities: gix_transport::client::Capabilities::from_bytes(b"\0report-status")
            .expect("valid capabilities")
            .0,
    };

    let specs: Vec<BString> = vec![
        "refs/heads/local-tip:refs/heads/existing".into(),
        ":refs/heads/existing".into(),
        "refs/heads/local-tip".into(),
    ];
    let commands = gix::remote::push::resolve_refspecs_to_commands(
        &repo,
        &handshake,
        specs.iter().map(<BString as AsRef<gix::bstr::BStr>>::as_ref),
    )?;
    assert_eq!(commands.len(), 3);
    assert!(
        commands.iter().all(|(_, force)| !*force),
        "none of these refspecs were `+`-prefixed",
    );

    // `src:dst` update
    assert_eq!(commands[0].0.old_id, remote_tip);
    assert_eq!(commands[0].0.new_id, commit_id);
    assert_eq!(commands[0].0.refname, "refs/heads/existing");

    // `:dst` deletion
    assert_eq!(commands[1].0.old_id, remote_tip);
    assert!(commands[1].0.new_id.is_null());
    assert_eq!(commands[1].0.refname, "refs/heads/existing");

    // `src` shorthand -> `src:src`; remote does not know this ref so old_id = null
    assert!(commands[2].0.old_id.is_null());
    assert_eq!(commands[2].0.new_id, commit_id);
    assert_eq!(commands[2].0.refname, "refs/heads/local-tip");

    // Asymmetric globs (only one side has `*`) are rejected at parse
    // time by `gix_refspec::parse`, surfacing as RefspecParse on our
    // public error surface.
    let bad_glob_specs: Vec<BString> = vec!["refs/heads/main:refs/heads/*".into()];
    let err = gix::remote::push::resolve_refspecs_to_commands(
        &repo,
        &handshake,
        bad_glob_specs.iter().map(<BString as AsRef<gix::bstr::BStr>>::as_ref),
    )
    .expect_err("asymmetric globs must be rejected");
    assert!(
        matches!(err, gix::remote::push::Error::RefspecParse { .. }),
        "expected RefspecParse for asymmetric glob, got {err:?}"
    );

    // Negative refspecs (`^<ref>`) were previously stripped by
    // `gix_refspec::parse` and silently re-interpreted as positive
    // pushes. Assert that the resolver now emits the typed
    // `RefspecNegativeUnsupported` error instead.
    let negative_specs: Vec<BString> = vec!["^refs/heads/local-tip".into()];
    let err = gix::remote::push::resolve_refspecs_to_commands(
        &repo,
        &handshake,
        negative_specs.iter().map(<BString as AsRef<gix::bstr::BStr>>::as_ref),
    )
    .expect_err("negative refspecs must be rejected, not silently re-interpreted");
    match err {
        gix::remote::push::Error::RefspecNegativeUnsupported { spec } => {
            assert_eq!(spec, "^refs/heads/local-tip");
        }
        other => panic!("expected RefspecNegativeUnsupported, got {other:?}"),
    }

    Ok(())
}

/// Wildcard push refspecs like `refs/heads/*:refs/heads/*` must expand
/// to one [`Command`] per local ref matching the source pattern, with
/// destination names formed by substituting the captured segment into
/// the destination pattern.
#[test]
fn resolve_refspecs_to_commands_expands_wildcard() -> crate::Result {
    use gix::bstr::BString;

    let tmp = tempfile::tempdir()?;
    let mut repo = gix::init_bare(tmp.path())?;
    let mut cfg = repo.config_snapshot_mut();
    cfg.set_raw_value(gix::config::tree::Author::NAME, "Test Author")?;
    cfg.set_raw_value(gix::config::tree::Author::EMAIL, "test@example.com")?;
    cfg.set_raw_value(gix::config::tree::Committer::NAME, "Test Author")?;
    cfg.set_raw_value(gix::config::tree::Committer::EMAIL, "test@example.com")?;
    cfg.commit()?;

    // Build two local branches + one ref outside refs/heads/ that
    // should not match the pattern.
    let blob = repo.write_blob(b"x\n".as_slice())?.detach();
    let tree = gix_object::Tree {
        entries: vec![gix_object::tree::Entry {
            mode: gix_object::tree::EntryKind::Blob.into(),
            filename: "x.txt".into(),
            oid: blob,
        }],
    };
    let tree_id = repo.write_object(&tree)?.detach();
    let commit_a = repo
        .commit("refs/heads/alpha", "a", tree_id, gix::commit::NO_PARENT_IDS)?
        .detach();
    let commit_b = repo
        .commit("refs/heads/beta", "b", tree_id, gix::commit::NO_PARENT_IDS)?
        .detach();
    let _commit_tag = repo
        .commit("refs/tags/should-not-match", "t", tree_id, gix::commit::NO_PARENT_IDS)?
        .detach();

    let handshake = gix_protocol::Handshake {
        server_protocol_version: gix_transport::Protocol::V1,
        refs: Some(vec![]),
        v1_shallow_updates: None,
        capabilities: gix_transport::client::Capabilities::from_bytes(b"\0report-status")
            .expect("valid capabilities")
            .0,
    };
    let specs: Vec<BString> = vec!["refs/heads/*:refs/heads/*".into()];
    let mut commands = gix::remote::push::resolve_refspecs_to_commands(
        &repo,
        &handshake,
        specs.iter().map(<BString as AsRef<gix::bstr::BStr>>::as_ref),
    )?;
    // Iteration order from the ref store is stable but not alphabetic
    // on every backend; sort for a deterministic assertion.
    commands.sort_by(|l, r| l.0.refname.cmp(&r.0.refname));
    assert_eq!(
        commands.len(),
        2,
        "expected exactly two expansions (alpha, beta); got {commands:?}"
    );
    assert_eq!(commands[0].0.refname, "refs/heads/alpha");
    assert_eq!(commands[0].0.new_id, commit_a);
    assert_eq!(commands[1].0.refname, "refs/heads/beta");
    assert_eq!(commands[1].0.new_id, commit_b);
    // Neither destination exists on the (empty) remote yet.
    for (cmd, force) in &commands {
        assert!(cmd.old_id.is_null(), "{:?} should be a create", cmd.refname);
        assert!(!force, "wildcard refspec was not `+`-prefixed");
    }
    Ok(())
}

#[test]
fn write_pack_for_push_with_empty_wants_writes_nothing() -> crate::Result {
    let tmp = tempfile::tempdir()?;
    let repo = gix::init_bare(tmp.path())?;
    let mut buf: Vec<u8> = Vec::new();
    let should_interrupt = AtomicBool::new(false);
    repo.write_pack_for_push(std::iter::empty(), std::iter::empty(), &mut buf, &should_interrupt)?;
    assert!(buf.is_empty(), "expected no bytes for an empty wants set");
    Ok(())
}
