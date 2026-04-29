//! End-to-end tests for the in-process transport: drive the client-side
//! `Remote` chain through `gix_transport::client::blocking_io::in_process`
//! byte channels into an in-process server running against a sibling
//! Repository on a worker thread.

#[cfg(any(feature = "serve-receive-pack", feature = "serve-upload-pack"))]
use gix_testtools::tempfile;

/// Interop-compare a push driven by `Remote::push` against the
/// reference `git` binary: when `test-with-real-git` is enabled the
/// test drives push end-to-end through the in-process transport and
/// then validates the destination with `git log`, so any bit-level
/// divergence from what `git` produces surfaces as a test failure.
#[cfg(all(
    feature = "serve-receive-pack",
    feature = "test-with-real-git",
    not(target_os = "windows")
))]
#[test]
fn in_process_receive_pack_push_is_readable_by_real_git() -> crate::Result {
    use std::process::Command;

    // Skip gracefully if `git` is not on PATH rather than failing
    // builds that opt in without having the binary available.
    if Command::new("git").arg("--version").output().is_err() {
        eprintln!("skipping: `git` not available on PATH");
        return Ok(());
    }

    let src_tmp = tempfile::tempdir()?;
    let mut src = gix::init_bare(src_tmp.path())?;
    let mut cfg = src.config_snapshot_mut();
    cfg.set_raw_value(gix::config::tree::Author::NAME, "Test Author")?;
    cfg.set_raw_value(gix::config::tree::Author::EMAIL, "test@example.com")?;
    cfg.set_raw_value(gix::config::tree::Committer::NAME, "Test Author")?;
    cfg.set_raw_value(gix::config::tree::Committer::EMAIL, "test@example.com")?;
    cfg.commit()?;

    let blob_id = src.write_blob(b"interop payload\n".as_slice())?.detach();
    let tree = gix_object::Tree {
        entries: vec![gix_object::tree::Entry {
            mode: gix_object::tree::EntryKind::Blob.into(),
            filename: "interop.txt".into(),
            oid: blob_id,
        }],
    };
    let tree_id = src.write_object(&tree)?.detach();
    let commit_id = src
        .commit("refs/heads/pushed", "interop", tree_id, gix::commit::NO_PARENT_IDS)?
        .detach();

    // Use a bare repo init'd by `git init --bare` so the destination
    // is a vanilla reference-implementation repo.
    let dst_tmp = tempfile::tempdir()?;
    let status = Command::new("git")
        .args(["init", "--bare"])
        .arg(dst_tmp.path())
        .status()?;
    assert!(status.success(), "git init --bare must succeed");
    let dst = gix::open(dst_tmp.path())?;

    let transport = dst.in_process_receive_pack_transport();
    let remote = src.remote_at("file:///in-process-placeholder")?;
    let connection = remote.to_connection_with_transport(transport);
    let prepare = connection.prepare_push(gix_features::progress::Discard)?;
    let prepare = prepare.with_refspecs(
        [gix::bstr::BString::from("refs/heads/pushed:refs/heads/received")]
            .iter()
            .map(AsRef::<gix::bstr::BStr>::as_ref),
    )?;
    let should_interrupt = std::sync::atomic::AtomicBool::new(false);
    let outcome = prepare.send_with_generated_pack(gix::progress::Discard, &should_interrupt)?;
    assert!(outcome.report.is_success());

    // Ask real `git` to read back the ref we just pushed.
    let log = Command::new("git")
        .arg("--git-dir")
        .arg(dst_tmp.path())
        .args(["log", "--format=%H", "-n", "1", "refs/heads/received"])
        .output()?;
    assert!(log.status.success(), "git log on the pushed ref must succeed");
    let sha = String::from_utf8(log.stdout)?.trim().to_string();
    assert_eq!(
        sha,
        commit_id.to_string(),
        "real git must see the same commit we pushed"
    );

    Ok(())
}

#[cfg(feature = "serve-receive-pack")]
#[test]
fn in_process_receive_pack_transport_handshake_surfaces_refs() -> crate::Result {
    use gix_transport::client::blocking_io::Transport;

    // Setup: dst with one existing ref so handshake has something to advertise.
    let dst_tmp = tempfile::tempdir()?;
    let mut dst = gix::init_bare(dst_tmp.path())?;
    let mut cfg = dst.config_snapshot_mut();
    cfg.set_raw_value(gix::config::tree::Author::NAME, "Test Author")?;
    cfg.set_raw_value(gix::config::tree::Author::EMAIL, "test@example.com")?;
    cfg.set_raw_value(gix::config::tree::Committer::NAME, "Test Author")?;
    cfg.set_raw_value(gix::config::tree::Committer::EMAIL, "test@example.com")?;
    cfg.commit()?;

    let tree = gix_object::Tree { entries: vec![] };
    let tree_id = dst.write_object(&tree)?.detach();
    dst.commit("refs/heads/already-there", "seed", tree_id, gix::commit::NO_PARENT_IDS)?;

    let mut transport = dst.in_process_receive_pack_transport();
    let resp = transport.handshake(gix_transport::Service::ReceivePack, &[])?;
    assert!(resp.refs.is_some(), "v1 receive-pack handshake must yield refs");
    let mut buf = Vec::new();
    std::io::Read::read_to_end(&mut resp.refs.expect("some"), &mut buf)?;
    assert!(
        !buf.is_empty(),
        "server must have emitted at least one ref advertisement line"
    );

    Ok(())
}

#[cfg(feature = "serve-receive-pack")]
#[test]
fn in_process_receive_pack_transport_round_trips_a_full_push() -> crate::Result {
    // Populate src with a commit that we want to push to dst.
    let src_tmp = tempfile::tempdir()?;
    let mut src = gix::init_bare(src_tmp.path())?;
    let mut cfg = src.config_snapshot_mut();
    cfg.set_raw_value(gix::config::tree::Author::NAME, "Test Author")?;
    cfg.set_raw_value(gix::config::tree::Author::EMAIL, "test@example.com")?;
    cfg.set_raw_value(gix::config::tree::Committer::NAME, "Test Author")?;
    cfg.set_raw_value(gix::config::tree::Committer::EMAIL, "test@example.com")?;
    cfg.commit()?;

    let blob_id = src.write_blob(b"in-process\n".as_slice())?.detach();
    let tree = gix_object::Tree {
        entries: vec![gix_object::tree::Entry {
            mode: gix_object::tree::EntryKind::Blob.into(),
            filename: "ip.txt".into(),
            oid: blob_id,
        }],
    };
    let tree_id = src.write_object(&tree)?.detach();
    let commit_id = src
        .commit("refs/heads/pushed", "in-process", tree_id, gix::commit::NO_PARENT_IDS)?
        .detach();

    // Spin up dst with its in-process receive-pack transport.
    let dst_tmp = tempfile::tempdir()?;
    let dst = gix::init_bare(dst_tmp.path())?;
    let transport = dst.in_process_receive_pack_transport();

    // Wire the transport into an anonymous remote on the src side and
    // push. The URL is a placeholder - the transport is pre-built, so
    // no actual subprocess or network spawns.
    let remote = src.remote_at("file:///in-process-placeholder")?;
    let connection = remote.to_connection_with_transport(transport);
    let prepare = connection.prepare_push(gix_features::progress::Discard)?;
    let prepare = prepare.with_refspecs(
        [gix::bstr::BString::from("refs/heads/pushed:refs/heads/received")]
            .iter()
            .map(AsRef::<gix::bstr::BStr>::as_ref),
    )?;
    let should_interrupt = std::sync::atomic::AtomicBool::new(false);
    let outcome = prepare.send_with_generated_pack(gix::progress::Discard, &should_interrupt)?;

    assert!(outcome.report.is_success(), "push must be accepted end-to-end");
    assert_eq!(outcome.report.accepted_count(), 1);
    assert_eq!(outcome.report.rejected_count(), 0);

    // Re-open dst and verify the pushed refs + objects landed.
    let dst = gix::open(dst_tmp.path())?;
    assert!(dst.has_object(commit_id), "dst ODB missing the pushed commit");
    assert!(dst.has_object(tree_id), "dst ODB missing the pushed tree");
    assert!(dst.has_object(blob_id), "dst ODB missing the pushed blob");
    let received = dst
        .try_find_reference("refs/heads/received")?
        .expect("rewritten refname must exist on dst");
    assert_eq!(received.target().try_id().map(ToOwned::to_owned), Some(commit_id));

    Ok(())
}

#[cfg(feature = "serve-upload-pack")]
#[test]
fn in_process_upload_pack_transport_v1_handshake_surfaces_refs() -> crate::Result {
    use gix_transport::client::blocking_io::Transport;

    // Seed src with a single commit so the v1 advertisement has an oid + ref to emit.
    let src_tmp = tempfile::tempdir()?;
    let mut src = gix::init_bare(src_tmp.path())?;
    let mut cfg = src.config_snapshot_mut();
    cfg.set_raw_value(gix::config::tree::Author::NAME, "Test Author")?;
    cfg.set_raw_value(gix::config::tree::Author::EMAIL, "test@example.com")?;
    cfg.set_raw_value(gix::config::tree::Committer::NAME, "Test Author")?;
    cfg.set_raw_value(gix::config::tree::Committer::EMAIL, "test@example.com")?;
    cfg.commit()?;

    let tree = gix_object::Tree { entries: vec![] };
    let tree_id = src.write_object(&tree)?.detach();
    let commit_id = src
        .commit("refs/heads/main", "seed", tree_id, gix::commit::NO_PARENT_IDS)?
        .detach();

    let mut transport = src.in_process_upload_pack_transport_v1();
    let resp = transport.handshake(gix_transport::Service::UploadPack, &[])?;
    assert_eq!(
        resp.actual_protocol,
        gix_transport::Protocol::V1,
        "factory must pin the channel to v1",
    );
    let mut refs_reader = resp.refs.expect("v1 upload-pack handshake must yield a refs reader");
    let mut buf = Vec::new();
    std::io::Read::read_to_end(&mut refs_reader, &mut buf)?;
    // The commit OID we just wrote must appear in the v1 advertisement
    // body — proof the spawned server actually ran
    // `serve_upload_pack_info_refs` against our repo.
    let needle = commit_id.to_string();
    assert!(
        gix::bstr::ByteSlice::contains_str(buf.as_slice(), needle.as_bytes()),
        "advertisement body must include the seeded commit oid",
    );

    Ok(())
}

#[cfg(feature = "serve-upload-pack")]
#[test]
fn in_process_upload_pack_transport_v2_handshake_surfaces_capabilities() -> crate::Result {
    use gix_transport::client::blocking_io::Transport;

    let src_tmp = tempfile::tempdir()?;
    let mut src = gix::init_bare(src_tmp.path())?;
    let mut cfg = src.config_snapshot_mut();
    cfg.set_raw_value(gix::config::tree::Author::NAME, "Test Author")?;
    cfg.set_raw_value(gix::config::tree::Author::EMAIL, "test@example.com")?;
    cfg.set_raw_value(gix::config::tree::Committer::NAME, "Test Author")?;
    cfg.set_raw_value(gix::config::tree::Committer::EMAIL, "test@example.com")?;
    cfg.commit()?;

    let tree = gix_object::Tree { entries: vec![] };
    let tree_id = src.write_object(&tree)?.detach();
    src.commit("refs/heads/main", "seed", tree_id, gix::commit::NO_PARENT_IDS)?;

    let mut transport = src.in_process_upload_pack_transport_v2();
    let resp = transport.handshake(gix_transport::Service::UploadPack, &[])?;
    assert_eq!(
        resp.actual_protocol,
        gix_transport::Protocol::V2,
        "factory must pin the channel to v2",
    );
    // v2 advertises capabilities only — refs are discovered via a later
    // `command=ls-refs`, so the handshake's `refs` field is `None`.
    assert!(resp.refs.is_none(), "v2 handshake must not ship inline refs");
    assert!(
        resp.capabilities.capability("fetch").is_some(),
        "v2 upload-pack must advertise the `fetch` command capability",
    );
    assert!(
        resp.capabilities.capability("ls-refs").is_some(),
        "v2 upload-pack must advertise the `ls-refs` command capability",
    );

    Ok(())
}
