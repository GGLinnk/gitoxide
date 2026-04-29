//! End-to-end integration test for
//! [`gix::Repository::serve_pack_upload_v2_auto`].
//!
//! A bare src repo with a single commit is wrapped by the v2
//! upload-pack serve endpoint. A synthetic v2 `command=fetch` request
//! is fed in (one `want <oid>`, no haves), the server streams the
//! response, and the test extracts the raw pack bytes from the
//! `packfile` section and re-ingests them into a fresh dst repo via
//! [`gix_pack::Bundle::write_to_directory`]. The three objects written
//! on the src side (commit, tree, blob) must all appear on the dst.

use std::sync::atomic::AtomicBool;

use gix_testtools::tempfile;

fn build_v2_fetch_request(object_hash: gix_hash::Kind, want: gix_hash::ObjectId) -> crate::Result<Vec<u8>> {
    let want_line = format!("want {want}\n");
    build_v2_fetch_request_body(object_hash, &[want_line.as_bytes()])
}

fn build_v2_ls_refs_request(object_hash: gix_hash::Kind) -> crate::Result<Vec<u8>> {
    build_v2_ls_refs_request_with(object_hash, &[])
}

fn build_v2_ls_refs_request_with(object_hash: gix_hash::Kind, prefixes: &[&str]) -> crate::Result<Vec<u8>> {
    let mut out: Vec<u8> = Vec::new();
    gix_packetline::blocking_io::encode::data_to_write(b"command=ls-refs\n", &mut out)?;
    let obj_fmt = format!("object-format={object_hash}\n");
    gix_packetline::blocking_io::encode::data_to_write(obj_fmt.as_bytes(), &mut out)?;
    gix_packetline::blocking_io::encode::delim_to_write(&mut out)?;
    for prefix in prefixes {
        let line = format!("ref-prefix {prefix}\n");
        gix_packetline::blocking_io::encode::data_to_write(line.as_bytes(), &mut out)?;
    }
    gix_packetline::blocking_io::encode::flush_to_write(&mut out)?;
    Ok(out)
}

fn build_v1_fetch_request(want: gix_hash::ObjectId, caps: &str) -> crate::Result<Vec<u8>> {
    let mut out: Vec<u8> = Vec::new();
    let want_line = if caps.is_empty() {
        format!("want {want}\n")
    } else {
        format!("want {want} {caps}\n")
    };
    gix_packetline::blocking_io::encode::data_to_write(want_line.as_bytes(), &mut out)?;
    gix_packetline::blocking_io::encode::flush_to_write(&mut out)?;
    gix_packetline::blocking_io::encode::data_to_write(b"done\n", &mut out)?;
    Ok(out)
}

fn build_v2_fetch_request_with_ref(object_hash: gix_hash::Kind, refname: &str) -> crate::Result<Vec<u8>> {
    let want_line = format!("want-ref {refname}\n");
    build_v2_fetch_request_body(object_hash, &[want_line.as_bytes()])
}

fn build_v2_fetch_request_body(object_hash: gix_hash::Kind, body_lines: &[&[u8]]) -> crate::Result<Vec<u8>> {
    let mut out: Vec<u8> = Vec::new();
    gix_packetline::blocking_io::encode::data_to_write(b"command=fetch\n", &mut out)?;
    let obj_fmt = format!("object-format={object_hash}\n");
    gix_packetline::blocking_io::encode::data_to_write(obj_fmt.as_bytes(), &mut out)?;
    gix_packetline::blocking_io::encode::delim_to_write(&mut out)?;
    for line in body_lines {
        gix_packetline::blocking_io::encode::data_to_write(line, &mut out)?;
    }
    gix_packetline::blocking_io::encode::data_to_write(b"done\n", &mut out)?;
    gix_packetline::blocking_io::encode::flush_to_write(&mut out)?;
    Ok(out)
}

// NOTE(2026-04-18): v2 upload-pack always pkt-line wraps the
// pack with a band-1 prefix per spec. Walk the response, locate the
// `packfile\n` section header, then concatenate every subsequent
// band-1 data pkt-line's payload (stripping the band byte) until the
// flush-pkt. Returns the de-sidebanded raw pack bytes.
fn extract_pack_from_response(response: &[u8]) -> Vec<u8> {
    let packfile_marker = b"packfile\n";
    let header_off = find_pkt_line_payload_offset(response, packfile_marker)
        .expect("response must contain a `packfile\\n` section header");
    let mut cursor = header_off + 4 + packfile_marker.len();
    let mut out = Vec::new();
    loop {
        assert!(cursor + 4 <= response.len(), "truncated pkt-line in pack section");
        let len_bytes = &response[cursor..cursor + 4];
        if len_bytes == b"0000" {
            break;
        }
        let len = usize::from(
            u16::from_str_radix(
                std::str::from_utf8(len_bytes).expect("pkt-line length must be ASCII hex"),
                16,
            )
            .expect("pkt-line length must parse as u16 hex"),
        );
        assert!(len >= 5, "band-1 pkt-line too short to hold band byte");
        assert!(
            response[cursor + 4] == 0x01,
            "expected band-1 pack pkt-line, got band {}",
            response[cursor + 4]
        );
        out.extend_from_slice(&response[cursor + 5..cursor + len]);
        cursor += len;
    }
    out
}

fn find_pkt_line_payload_offset(response: &[u8], payload: &[u8]) -> Option<usize> {
    let mut cursor = 0;
    while cursor + 4 <= response.len() {
        let len_bytes = &response[cursor..cursor + 4];
        if len_bytes == b"0000" || len_bytes == b"0001" || len_bytes == b"0002" {
            cursor += 4;
            continue;
        }
        let len = usize::from(u16::from_str_radix(std::str::from_utf8(len_bytes).ok()?, 16).ok()?);
        if len < 4 || cursor + len > response.len() {
            return None;
        }
        if &response[cursor + 4..cursor + len] == payload {
            return Some(cursor);
        }
        cursor += len;
    }
    None
}

#[test]
fn serve_pack_upload_v2_auto_round_trips_a_single_commit() -> crate::Result {
    let src_tmp = tempfile::tempdir()?;
    let mut src = gix::init_bare(src_tmp.path())?;

    let mut cfg = src.config_snapshot_mut();
    cfg.set_raw_value(gix::config::tree::Author::NAME, "Test Author")?;
    cfg.set_raw_value(gix::config::tree::Author::EMAIL, "test@example.com")?;
    cfg.set_raw_value(gix::config::tree::Committer::NAME, "Test Author")?;
    cfg.set_raw_value(gix::config::tree::Committer::EMAIL, "test@example.com")?;
    cfg.commit()?;

    let blob_id = src.write_blob(b"upload-pack payload\n".as_slice())?.detach();
    let tree = gix_object::Tree {
        entries: vec![gix_object::tree::Entry {
            mode: gix_object::tree::EntryKind::Blob.into(),
            filename: "served.txt".into(),
            oid: blob_id,
        }],
    };
    let tree_id = src.write_object(&tree)?.detach();
    let commit_id = src
        .commit("refs/heads/main", "initial", tree_id, gix::commit::NO_PARENT_IDS)?
        .detach();

    let request = build_v2_fetch_request(src.object_hash(), commit_id)?;
    let mut response: Vec<u8> = Vec::new();
    let should_interrupt = AtomicBool::new(false);
    let outcome = src.serve_pack_upload_v2_auto(request.as_slice(), &mut response, &should_interrupt)?;

    assert!(outcome.pack_sent, "server should have emitted a pack");
    assert_eq!(outcome.request.wants.len(), 1, "the request parsed exactly one want");

    let pack_bytes = extract_pack_from_response(&response);
    assert!(pack_bytes.starts_with(b"PACK"), "extracted bytes must start with PACK");
    assert!(
        pack_bytes.len() > 12 + 20,
        "pack must carry at least header + one entry + trailer, got {} bytes",
        pack_bytes.len()
    );

    let dst_tmp = tempfile::tempdir()?;
    let dst = gix::init_bare(dst_tmp.path())?;
    let dst_pack_dir = dst.objects.store_ref().path().join("pack");
    let mut cursor = std::io::Cursor::new(pack_bytes.to_vec());
    let mut reader = std::io::BufReader::new(&mut cursor);
    let base_lookup: Option<gix_odb::Cache<gix_odb::store::Handle<std::sync::Arc<gix_odb::Store>>>> =
        Some((*dst.objects).clone());
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
    assert!(dst.has_object(commit_id), "pack did not contain the commit");
    assert!(dst.has_object(tree_id), "pack did not contain the root tree");
    assert!(dst.has_object(blob_id), "pack did not contain the blob");

    Ok(())
}

#[test]
fn serve_pack_upload_v2_auto_resolves_want_ref() -> crate::Result {
    let src_tmp = tempfile::tempdir()?;
    let mut src = gix::init_bare(src_tmp.path())?;

    let mut cfg = src.config_snapshot_mut();
    cfg.set_raw_value(gix::config::tree::Author::NAME, "Test Author")?;
    cfg.set_raw_value(gix::config::tree::Author::EMAIL, "test@example.com")?;
    cfg.set_raw_value(gix::config::tree::Committer::NAME, "Test Author")?;
    cfg.set_raw_value(gix::config::tree::Committer::EMAIL, "test@example.com")?;
    cfg.commit()?;

    let blob_id = src.write_blob(b"want-ref payload\n".as_slice())?.detach();
    let tree = gix_object::Tree {
        entries: vec![gix_object::tree::Entry {
            mode: gix_object::tree::EntryKind::Blob.into(),
            filename: "byref.txt".into(),
            oid: blob_id,
        }],
    };
    let tree_id = src.write_object(&tree)?.detach();
    let commit_id = src
        .commit(
            "refs/heads/served",
            "served commit",
            tree_id,
            gix::commit::NO_PARENT_IDS,
        )?
        .detach();

    // Ask via want-ref, not want <oid>. The server must resolve
    // refs/heads/served to `commit_id` before the pack is generated.
    let request = build_v2_fetch_request_with_ref(src.object_hash(), "refs/heads/served")?;
    let mut response: Vec<u8> = Vec::new();
    let should_interrupt = AtomicBool::new(false);
    let outcome = src.serve_pack_upload_v2_auto(request.as_slice(), &mut response, &should_interrupt)?;

    assert!(
        outcome.pack_sent,
        "server should have emitted a pack for a resolvable want-ref"
    );
    assert_eq!(outcome.request.wants.len(), 1);

    let pack_bytes = extract_pack_from_response(&response);
    assert!(pack_bytes.starts_with(b"PACK"));

    let dst_tmp = tempfile::tempdir()?;
    let dst = gix::init_bare(dst_tmp.path())?;
    let dst_pack_dir = dst.objects.store_ref().path().join("pack");
    let mut cursor = std::io::Cursor::new(pack_bytes.to_vec());
    let mut reader = std::io::BufReader::new(&mut cursor);
    let base_lookup: Option<gix_odb::Cache<gix_odb::store::Handle<std::sync::Arc<gix_odb::Store>>>> =
        Some((*dst.objects).clone());
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
    assert!(dst.has_object(commit_id), "want-ref pack did not contain the commit");
    assert!(dst.has_object(tree_id));
    assert!(dst.has_object(blob_id));

    Ok(())
}

#[test]
fn serve_pack_upload_v2_auto_include_tag_ships_annotated_tag() -> crate::Result {
    let src_tmp = tempfile::tempdir()?;
    let mut src = gix::init_bare(src_tmp.path())?;

    let mut cfg = src.config_snapshot_mut();
    cfg.set_raw_value(gix::config::tree::Author::NAME, "Test Author")?;
    cfg.set_raw_value(gix::config::tree::Author::EMAIL, "test@example.com")?;
    cfg.set_raw_value(gix::config::tree::Committer::NAME, "Test Author")?;
    cfg.set_raw_value(gix::config::tree::Committer::EMAIL, "test@example.com")?;
    cfg.commit()?;

    let blob_id = src.write_blob(b"include-tag payload\n".as_slice())?.detach();
    let tree = gix_object::Tree {
        entries: vec![gix_object::tree::Entry {
            mode: gix_object::tree::EntryKind::Blob.into(),
            filename: "tagged.txt".into(),
            oid: blob_id,
        }],
    };
    let tree_id = src.write_object(&tree)?.detach();
    let commit_id = src
        .commit("refs/heads/main", "initial", tree_id, gix::commit::NO_PARENT_IDS)?
        .detach();

    let tagger = gix_actor::SignatureRef {
        name: "Test Author".into(),
        email: "test@example.com".into(),
        time: "0 +0000".into(),
    };
    let tag_ref = src.tag(
        "v1.0",
        commit_id,
        gix_object::Kind::Commit,
        Some(tagger),
        "tagging v1.0",
        gix::refs::transaction::PreviousValue::MustNotExist,
    )?;
    let tag_oid = tag_ref.target().try_id().expect("tag ref is direct").to_owned();
    assert_ne!(tag_oid, commit_id, "tag must be annotated, not lightweight");

    let want_line = format!("want {commit_id}\n");
    let request = build_v2_fetch_request_body(src.object_hash(), &[want_line.as_bytes(), b"include-tag\n"])?;
    let mut response: Vec<u8> = Vec::new();
    let should_interrupt = AtomicBool::new(false);
    let outcome = src.serve_pack_upload_v2_auto(request.as_slice(), &mut response, &should_interrupt)?;

    assert!(outcome.pack_sent);
    assert!(outcome.request.include_tag, "parser surfaced include-tag");

    let pack_bytes = extract_pack_from_response(&response);
    let dst_tmp = tempfile::tempdir()?;
    let dst = gix::init_bare(dst_tmp.path())?;
    let dst_pack_dir = dst.objects.store_ref().path().join("pack");
    let mut cursor = std::io::Cursor::new(pack_bytes.to_vec());
    let mut reader = std::io::BufReader::new(&mut cursor);
    let base_lookup: Option<gix_odb::Cache<gix_odb::store::Handle<std::sync::Arc<gix_odb::Store>>>> =
        Some((*dst.objects).clone());
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
    assert!(dst.has_object(commit_id), "commit shipped");
    assert!(dst.has_object(tree_id), "tree shipped");
    assert!(dst.has_object(blob_id), "blob shipped");
    assert!(
        dst.has_object(tag_oid),
        "include-tag must ship the annotated tag object"
    );

    Ok(())
}

#[test]
fn serve_pack_upload_v2_auto_without_include_tag_skips_annotated_tag() -> crate::Result {
    let src_tmp = tempfile::tempdir()?;
    let mut src = gix::init_bare(src_tmp.path())?;

    let mut cfg = src.config_snapshot_mut();
    cfg.set_raw_value(gix::config::tree::Author::NAME, "Test Author")?;
    cfg.set_raw_value(gix::config::tree::Author::EMAIL, "test@example.com")?;
    cfg.set_raw_value(gix::config::tree::Committer::NAME, "Test Author")?;
    cfg.set_raw_value(gix::config::tree::Committer::EMAIL, "test@example.com")?;
    cfg.commit()?;

    let blob_id = src.write_blob(b"no include-tag\n".as_slice())?.detach();
    let tree = gix_object::Tree {
        entries: vec![gix_object::tree::Entry {
            mode: gix_object::tree::EntryKind::Blob.into(),
            filename: "plain.txt".into(),
            oid: blob_id,
        }],
    };
    let tree_id = src.write_object(&tree)?.detach();
    let commit_id = src
        .commit("refs/heads/main", "initial", tree_id, gix::commit::NO_PARENT_IDS)?
        .detach();

    let tagger = gix_actor::SignatureRef {
        name: "Test Author".into(),
        email: "test@example.com".into(),
        time: "0 +0000".into(),
    };
    let tag_ref = src.tag(
        "v0.9",
        commit_id,
        gix_object::Kind::Commit,
        Some(tagger),
        "un-shipped tag",
        gix::refs::transaction::PreviousValue::MustNotExist,
    )?;
    let tag_oid = tag_ref.target().try_id().expect("tag ref is direct").to_owned();

    let request = build_v2_fetch_request(src.object_hash(), commit_id)?;
    let mut response: Vec<u8> = Vec::new();
    let should_interrupt = AtomicBool::new(false);
    let _ = src.serve_pack_upload_v2_auto(request.as_slice(), &mut response, &should_interrupt)?;

    let pack_bytes = extract_pack_from_response(&response);
    let dst_tmp = tempfile::tempdir()?;
    let dst = gix::init_bare(dst_tmp.path())?;
    let dst_pack_dir = dst.objects.store_ref().path().join("pack");
    let mut cursor = std::io::Cursor::new(pack_bytes.to_vec());
    let mut reader = std::io::BufReader::new(&mut cursor);
    let base_lookup: Option<gix_odb::Cache<gix_odb::store::Handle<std::sync::Arc<gix_odb::Store>>>> =
        Some((*dst.objects).clone());
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
    assert!(
        !dst.has_object(tag_oid),
        "without include-tag the annotated tag must not be shipped"
    );

    Ok(())
}

#[test]
fn serve_pack_upload_v1_auto_round_trips_a_single_commit() -> crate::Result {
    let src_tmp = tempfile::tempdir()?;
    let mut src = gix::init_bare(src_tmp.path())?;

    let mut cfg = src.config_snapshot_mut();
    cfg.set_raw_value(gix::config::tree::Author::NAME, "Test Author")?;
    cfg.set_raw_value(gix::config::tree::Author::EMAIL, "test@example.com")?;
    cfg.set_raw_value(gix::config::tree::Committer::NAME, "Test Author")?;
    cfg.set_raw_value(gix::config::tree::Committer::EMAIL, "test@example.com")?;
    cfg.commit()?;

    let blob_id = src.write_blob(b"v1 upload payload\n".as_slice())?.detach();
    let tree = gix_object::Tree {
        entries: vec![gix_object::tree::Entry {
            mode: gix_object::tree::EntryKind::Blob.into(),
            filename: "v1.txt".into(),
            oid: blob_id,
        }],
    };
    let tree_id = src.write_object(&tree)?.detach();
    let commit_id = src
        .commit("refs/heads/main", "initial", tree_id, gix::commit::NO_PARENT_IDS)?
        .detach();

    let request = build_v1_fetch_request(commit_id, "multi_ack ofs-delta")?;
    let mut response: Vec<u8> = Vec::new();
    let should_interrupt = AtomicBool::new(false);
    let outcome = src.serve_pack_upload_v1_auto(request.as_slice(), &mut response, &should_interrupt)?;

    assert!(outcome.pack_sent, "server should have emitted a pack");
    assert_eq!(outcome.request.wants, vec![commit_id]);
    assert!(outcome.request.done);

    // Response begins with "0008NAK\n" (v0/v1 stateless ack) then pack bytes.
    assert!(
        response.starts_with(b"0008NAK\n"),
        "v1 response must start with a NAK pkt-line, got {response:?}"
    );
    let pack_start = response
        .windows(4)
        .position(|w| w == b"PACK")
        .expect("response must contain a PACK section");
    let pack_bytes = &response[pack_start..];
    assert!(pack_bytes.len() > 12 + 20, "pack too short: {}", pack_bytes.len());

    let dst_tmp = tempfile::tempdir()?;
    let dst = gix::init_bare(dst_tmp.path())?;
    let dst_pack_dir = dst.objects.store_ref().path().join("pack");
    let mut cursor = std::io::Cursor::new(pack_bytes.to_vec());
    let mut reader = std::io::BufReader::new(&mut cursor);
    let base_lookup: Option<gix_odb::Cache<gix_odb::store::Handle<std::sync::Arc<gix_odb::Store>>>> =
        Some((*dst.objects).clone());
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
    assert!(dst.has_object(tree_id));
    assert!(dst.has_object(blob_id));
    Ok(())
}

#[test]
fn serve_pack_upload_v2_auto_filter_tree_zero_ships_commits_only() -> crate::Result {
    let src_tmp = tempfile::tempdir()?;
    let mut src = gix::init_bare(src_tmp.path())?;

    let mut cfg = src.config_snapshot_mut();
    cfg.set_raw_value(gix::config::tree::Author::NAME, "Test Author")?;
    cfg.set_raw_value(gix::config::tree::Author::EMAIL, "test@example.com")?;
    cfg.set_raw_value(gix::config::tree::Committer::NAME, "Test Author")?;
    cfg.set_raw_value(gix::config::tree::Committer::EMAIL, "test@example.com")?;
    cfg.commit()?;

    let blob_id = src.write_blob(b"filter tree:0\n".as_slice())?.detach();
    let tree = gix_object::Tree {
        entries: vec![gix_object::tree::Entry {
            mode: gix_object::tree::EntryKind::Blob.into(),
            filename: "t.txt".into(),
            oid: blob_id,
        }],
    };
    let tree_id = src.write_object(&tree)?.detach();
    let commit_id = src
        .commit("refs/heads/main", "tree-zero", tree_id, gix::commit::NO_PARENT_IDS)?
        .detach();

    let want_line = format!("want {commit_id}\n");
    let request = build_v2_fetch_request_body(src.object_hash(), &[want_line.as_bytes(), b"filter tree:0\n"])?;
    let mut response: Vec<u8> = Vec::new();
    let should_interrupt = AtomicBool::new(false);
    let _ = src.serve_pack_upload_v2_auto(request.as_slice(), &mut response, &should_interrupt)?;

    let pack_bytes = extract_pack_from_response(&response);
    let dst_tmp = tempfile::tempdir()?;
    let dst = gix::init_bare(dst_tmp.path())?;
    let dst_pack_dir = dst.objects.store_ref().path().join("pack");
    let mut cursor = std::io::Cursor::new(pack_bytes.to_vec());
    let mut reader = std::io::BufReader::new(&mut cursor);
    let base_lookup: Option<gix_odb::Cache<gix_odb::store::Handle<std::sync::Arc<gix_odb::Store>>>> =
        Some((*dst.objects).clone());
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
    assert!(dst.has_object(commit_id), "commit ships under tree:0");
    assert!(!dst.has_object(tree_id), "tree:0 strips the root tree");
    assert!(!dst.has_object(blob_id), "tree:0 strips all blobs");

    Ok(())
}

#[test]
fn serve_pack_upload_v2_auto_filter_blob_none_omits_blobs() -> crate::Result {
    let src_tmp = tempfile::tempdir()?;
    let mut src = gix::init_bare(src_tmp.path())?;

    let mut cfg = src.config_snapshot_mut();
    cfg.set_raw_value(gix::config::tree::Author::NAME, "Test Author")?;
    cfg.set_raw_value(gix::config::tree::Author::EMAIL, "test@example.com")?;
    cfg.set_raw_value(gix::config::tree::Committer::NAME, "Test Author")?;
    cfg.set_raw_value(gix::config::tree::Committer::EMAIL, "test@example.com")?;
    cfg.commit()?;

    let blob_id = src.write_blob(b"filter blob:none\n".as_slice())?.detach();
    let tree = gix_object::Tree {
        entries: vec![gix_object::tree::Entry {
            mode: gix_object::tree::EntryKind::Blob.into(),
            filename: "f.txt".into(),
            oid: blob_id,
        }],
    };
    let tree_id = src.write_object(&tree)?.detach();
    let commit_id = src
        .commit("refs/heads/main", "initial", tree_id, gix::commit::NO_PARENT_IDS)?
        .detach();

    let want_line = format!("want {commit_id}\n");
    let request = build_v2_fetch_request_body(src.object_hash(), &[want_line.as_bytes(), b"filter blob:none\n"])?;
    let mut response: Vec<u8> = Vec::new();
    let should_interrupt = AtomicBool::new(false);
    let outcome = src.serve_pack_upload_v2_auto(request.as_slice(), &mut response, &should_interrupt)?;
    assert!(outcome.pack_sent);
    assert_eq!(
        outcome.request.filter.as_ref().map(AsRef::<[u8]>::as_ref),
        Some(b"blob:none".as_slice())
    );

    let pack_bytes = extract_pack_from_response(&response);
    let dst_tmp = tempfile::tempdir()?;
    let dst = gix::init_bare(dst_tmp.path())?;
    let dst_pack_dir = dst.objects.store_ref().path().join("pack");
    let mut cursor = std::io::Cursor::new(pack_bytes.to_vec());
    let mut reader = std::io::BufReader::new(&mut cursor);
    let base_lookup: Option<gix_odb::Cache<gix_odb::store::Handle<std::sync::Arc<gix_odb::Store>>>> =
        Some((*dst.objects).clone());
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
    assert!(dst.has_object(commit_id), "commit still ships");
    assert!(dst.has_object(tree_id), "root tree still ships");
    assert!(!dst.has_object(blob_id), "blob:none must strip the blob from the pack");

    Ok(())
}

#[test]
fn serve_pack_upload_v1_auto_include_tag_ships_annotated_tag() -> crate::Result {
    let src_tmp = tempfile::tempdir()?;
    let mut src = gix::init_bare(src_tmp.path())?;

    let mut cfg = src.config_snapshot_mut();
    cfg.set_raw_value(gix::config::tree::Author::NAME, "Test Author")?;
    cfg.set_raw_value(gix::config::tree::Author::EMAIL, "test@example.com")?;
    cfg.set_raw_value(gix::config::tree::Committer::NAME, "Test Author")?;
    cfg.set_raw_value(gix::config::tree::Committer::EMAIL, "test@example.com")?;
    cfg.commit()?;

    let blob_id = src.write_blob(b"v1 include-tag payload\n".as_slice())?.detach();
    let tree = gix_object::Tree {
        entries: vec![gix_object::tree::Entry {
            mode: gix_object::tree::EntryKind::Blob.into(),
            filename: "v1tag.txt".into(),
            oid: blob_id,
        }],
    };
    let tree_id = src.write_object(&tree)?.detach();
    let commit_id = src
        .commit("refs/heads/main", "initial", tree_id, gix::commit::NO_PARENT_IDS)?
        .detach();

    let tagger = gix_actor::SignatureRef {
        name: "Test Author".into(),
        email: "test@example.com".into(),
        time: "0 +0000".into(),
    };
    let tag_ref = src.tag(
        "v1-included",
        commit_id,
        gix_object::Kind::Commit,
        Some(tagger),
        "v1 include-tag",
        gix::refs::transaction::PreviousValue::MustNotExist,
    )?;
    let tag_oid = tag_ref.target().try_id().expect("direct tag ref").to_owned();
    assert_ne!(tag_oid, commit_id);

    // include-tag rides on the first want line as a capability token
    // on the v0/v1 wire.
    let request = build_v1_fetch_request(commit_id, "multi_ack ofs-delta include-tag")?;
    let mut response: Vec<u8> = Vec::new();
    let should_interrupt = AtomicBool::new(false);
    let _ = src.serve_pack_upload_v1_auto(request.as_slice(), &mut response, &should_interrupt)?;

    let pack_start = response
        .windows(4)
        .position(|w| w == b"PACK")
        .expect("response must contain a PACK section");
    let pack_bytes = &response[pack_start..];

    let dst_tmp = tempfile::tempdir()?;
    let dst = gix::init_bare(dst_tmp.path())?;
    let dst_pack_dir = dst.objects.store_ref().path().join("pack");
    let mut cursor = std::io::Cursor::new(pack_bytes.to_vec());
    let mut reader = std::io::BufReader::new(&mut cursor);
    let base_lookup: Option<gix_odb::Cache<gix_odb::store::Handle<std::sync::Arc<gix_odb::Store>>>> =
        Some((*dst.objects).clone());
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
    assert!(
        dst.has_object(tag_oid),
        "v1 include-tag must ship the annotated tag object"
    );

    Ok(())
}

#[test]
fn serve_pack_upload_v2_auto_unresolvable_want_ref_sends_no_pack() -> crate::Result {
    let tmp = tempfile::tempdir()?;
    let repo = gix::init_bare(tmp.path())?;
    let request = build_v2_fetch_request_with_ref(repo.object_hash(), "refs/heads/does-not-exist")?;
    let mut response: Vec<u8> = Vec::new();
    let should_interrupt = AtomicBool::new(false);
    let outcome = repo.serve_pack_upload_v2_auto(request.as_slice(), &mut response, &should_interrupt)?;

    assert!(
        !outcome.pack_sent,
        "an unresolvable want-ref should yield an empty response, not a pack"
    );
    // The response still has framing overhead (acknowledgments section + flush-pkt)
    // but must NOT carry a PACK marker.
    assert!(
        !response.windows(4).any(|w| w == b"PACK"),
        "response must not contain any pack bytes"
    );

    Ok(())
}

/// When the dispatcher receives a v2 `command=fetch` request it
/// must take the fetch branch and stream a pack (verified by
/// finding the PACK magic in the response and the matching
/// `DispatchOutcome::Fetch` variant).
#[test]
fn serve_pack_upload_v2_dispatch_auto_answers_fetch() -> crate::Result {
    let src_tmp = tempfile::tempdir()?;
    let mut src = gix::init_bare(src_tmp.path())?;
    let mut cfg = src.config_snapshot_mut();
    cfg.set_raw_value(gix::config::tree::Author::NAME, "Test Author")?;
    cfg.set_raw_value(gix::config::tree::Author::EMAIL, "test@example.com")?;
    cfg.set_raw_value(gix::config::tree::Committer::NAME, "Test Author")?;
    cfg.set_raw_value(gix::config::tree::Committer::EMAIL, "test@example.com")?;
    cfg.commit()?;

    let blob_id = src.write_blob(b"dispatch fetch\n".as_slice())?.detach();
    let tree = gix_object::Tree {
        entries: vec![gix_object::tree::Entry {
            mode: gix_object::tree::EntryKind::Blob.into(),
            filename: "d.txt".into(),
            oid: blob_id,
        }],
    };
    let tree_id = src.write_object(&tree)?.detach();
    let commit_id = src
        .commit("refs/heads/d", "c", tree_id, gix::commit::NO_PARENT_IDS)?
        .detach();

    let request = build_v2_fetch_request(src.object_hash(), commit_id)?;
    let mut response: Vec<u8> = Vec::new();
    let should_interrupt = AtomicBool::new(false);
    let outcome = src.serve_pack_upload_v2_dispatch_auto(request.as_slice(), &mut response, &should_interrupt)?;

    match outcome {
        gix_protocol::upload_pack::serve::DispatchOutcome::Fetch(fetch) => {
            assert!(fetch.pack_sent);
            assert_eq!(fetch.request.wants.len(), 1);
        }
        other => panic!("expected Fetch outcome, got {other:?}"),
    }
    assert!(
        response.windows(4).any(|w| w == b"PACK"),
        "dispatch fetch must stream a PACK in the response"
    );
    Ok(())
}

#[test]
fn serve_pack_upload_v2_auto_filter_blob_limit_drops_large_blobs() -> crate::Result {
    let src_tmp = tempfile::tempdir()?;
    let mut src = gix::init_bare(src_tmp.path())?;

    let mut cfg = src.config_snapshot_mut();
    cfg.set_raw_value(gix::config::tree::Author::NAME, "Test Author")?;
    cfg.set_raw_value(gix::config::tree::Author::EMAIL, "test@example.com")?;
    cfg.set_raw_value(gix::config::tree::Committer::NAME, "Test Author")?;
    cfg.set_raw_value(gix::config::tree::Committer::EMAIL, "test@example.com")?;
    cfg.commit()?;

    // "small" ships (4 bytes), "big" does not (1024 bytes) when
    // filter=blob:limit=128.
    let small_blob = src.write_blob(b"tiny".as_slice())?.detach();
    let big_blob = src.write_blob(vec![b'x'; 1024].as_slice())?.detach();
    let tree = gix_object::Tree {
        entries: vec![
            gix_object::tree::Entry {
                mode: gix_object::tree::EntryKind::Blob.into(),
                filename: "big.bin".into(),
                oid: big_blob,
            },
            gix_object::tree::Entry {
                mode: gix_object::tree::EntryKind::Blob.into(),
                filename: "small.txt".into(),
                oid: small_blob,
            },
        ],
    };
    let tree_id = src.write_object(&tree)?.detach();
    let commit_id = src
        .commit("refs/heads/main", "initial", tree_id, gix::commit::NO_PARENT_IDS)?
        .detach();

    let want_line = format!("want {commit_id}\n");
    let request = build_v2_fetch_request_body(src.object_hash(), &[want_line.as_bytes(), b"filter blob:limit=128\n"])?;
    let mut response: Vec<u8> = Vec::new();
    let should_interrupt = AtomicBool::new(false);
    let _ = src.serve_pack_upload_v2_auto(request.as_slice(), &mut response, &should_interrupt)?;

    let pack_bytes = extract_pack_from_response(&response);
    let dst_tmp = tempfile::tempdir()?;
    let dst = gix::init_bare(dst_tmp.path())?;
    let dst_pack_dir = dst.objects.store_ref().path().join("pack");
    let mut cursor = std::io::Cursor::new(pack_bytes.to_vec());
    let mut reader = std::io::BufReader::new(&mut cursor);
    let base_lookup: Option<gix_odb::Cache<gix_odb::store::Handle<std::sync::Arc<gix_odb::Store>>>> =
        Some((*dst.objects).clone());
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
    assert!(dst.has_object(tree_id));
    assert!(dst.has_object(small_blob), "blob:limit keeps small blobs");
    assert!(!dst.has_object(big_blob), "blob:limit drops large blobs");

    Ok(())
}

#[test]
fn serve_pack_upload_v1_auto_filter_blob_none_omits_blobs() -> crate::Result {
    let src_tmp = tempfile::tempdir()?;
    let mut src = gix::init_bare(src_tmp.path())?;

    let mut cfg = src.config_snapshot_mut();
    cfg.set_raw_value(gix::config::tree::Author::NAME, "Test Author")?;
    cfg.set_raw_value(gix::config::tree::Author::EMAIL, "test@example.com")?;
    cfg.set_raw_value(gix::config::tree::Committer::NAME, "Test Author")?;
    cfg.set_raw_value(gix::config::tree::Committer::EMAIL, "test@example.com")?;
    cfg.commit()?;

    let blob_id = src.write_blob(b"v1 blob:none\n".as_slice())?.detach();
    let tree = gix_object::Tree {
        entries: vec![gix_object::tree::Entry {
            mode: gix_object::tree::EntryKind::Blob.into(),
            filename: "f.txt".into(),
            oid: blob_id,
        }],
    };
    let tree_id = src.write_object(&tree)?.detach();
    let commit_id = src
        .commit("refs/heads/main", "initial", tree_id, gix::commit::NO_PARENT_IDS)?
        .detach();

    // build_v1_fetch_request emits a want + flush + done without a
    // filter line, so inline the request shape here and insert the
    // filter directive right after the want list.
    let mut request: Vec<u8> = Vec::new();
    let want_line = format!("want {commit_id} multi_ack filter\n");
    gix_packetline::blocking_io::encode::data_to_write(want_line.as_bytes(), &mut request)?;
    gix_packetline::blocking_io::encode::data_to_write(b"filter blob:none\n", &mut request)?;
    gix_packetline::blocking_io::encode::flush_to_write(&mut request)?;
    gix_packetline::blocking_io::encode::data_to_write(b"done\n", &mut request)?;

    let mut response: Vec<u8> = Vec::new();
    let should_interrupt = AtomicBool::new(false);
    let _ = src.serve_pack_upload_v1_auto(request.as_slice(), &mut response, &should_interrupt)?;

    let pack_start = response
        .windows(4)
        .position(|w| w == b"PACK")
        .expect("response must contain a PACK section");
    let pack_bytes = &response[pack_start..];

    let dst_tmp = tempfile::tempdir()?;
    let dst = gix::init_bare(dst_tmp.path())?;
    let dst_pack_dir = dst.objects.store_ref().path().join("pack");
    let mut cursor = std::io::Cursor::new(pack_bytes.to_vec());
    let mut reader = std::io::BufReader::new(&mut cursor);
    let base_lookup: Option<gix_odb::Cache<gix_odb::store::Handle<std::sync::Arc<gix_odb::Store>>>> =
        Some((*dst.objects).clone());
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
    assert!(dst.has_object(tree_id));
    assert!(!dst.has_object(blob_id), "v1 blob:none must strip blobs");

    Ok(())
}

#[test]
fn serve_pack_upload_v1_auto_filter_blob_limit_drops_large_blobs() -> crate::Result {
    let src_tmp = tempfile::tempdir()?;
    let mut src = gix::init_bare(src_tmp.path())?;

    let mut cfg = src.config_snapshot_mut();
    cfg.set_raw_value(gix::config::tree::Author::NAME, "Test Author")?;
    cfg.set_raw_value(gix::config::tree::Author::EMAIL, "test@example.com")?;
    cfg.set_raw_value(gix::config::tree::Committer::NAME, "Test Author")?;
    cfg.set_raw_value(gix::config::tree::Committer::EMAIL, "test@example.com")?;
    cfg.commit()?;

    let small_blob = src.write_blob(b"tiny".as_slice())?.detach();
    let big_blob = src.write_blob(vec![b'x'; 4096].as_slice())?.detach();
    let tree = gix_object::Tree {
        entries: vec![
            gix_object::tree::Entry {
                mode: gix_object::tree::EntryKind::Blob.into(),
                filename: "big.bin".into(),
                oid: big_blob,
            },
            gix_object::tree::Entry {
                mode: gix_object::tree::EntryKind::Blob.into(),
                filename: "small.txt".into(),
                oid: small_blob,
            },
        ],
    };
    let tree_id = src.write_object(&tree)?.detach();
    let commit_id = src
        .commit("refs/heads/main", "initial", tree_id, gix::commit::NO_PARENT_IDS)?
        .detach();

    // Inline the request: want + filter directive + flush + done.
    let mut request: Vec<u8> = Vec::new();
    let want_line = format!("want {commit_id} multi_ack filter\n");
    gix_packetline::blocking_io::encode::data_to_write(want_line.as_bytes(), &mut request)?;
    gix_packetline::blocking_io::encode::data_to_write(b"filter blob:limit=1k\n", &mut request)?;
    gix_packetline::blocking_io::encode::flush_to_write(&mut request)?;
    gix_packetline::blocking_io::encode::data_to_write(b"done\n", &mut request)?;

    let mut response: Vec<u8> = Vec::new();
    let should_interrupt = AtomicBool::new(false);
    let _ = src.serve_pack_upload_v1_auto(request.as_slice(), &mut response, &should_interrupt)?;

    let pack_start = response
        .windows(4)
        .position(|w| w == b"PACK")
        .expect("response must contain a PACK section");
    let pack_bytes = &response[pack_start..];

    let dst_tmp = tempfile::tempdir()?;
    let dst = gix::init_bare(dst_tmp.path())?;
    let dst_pack_dir = dst.objects.store_ref().path().join("pack");
    let mut cursor = std::io::Cursor::new(pack_bytes.to_vec());
    let mut reader = std::io::BufReader::new(&mut cursor);
    let base_lookup: Option<gix_odb::Cache<gix_odb::store::Handle<std::sync::Arc<gix_odb::Store>>>> =
        Some((*dst.objects).clone());
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
    assert!(dst.has_object(tree_id));
    assert!(dst.has_object(small_blob));
    assert!(!dst.has_object(big_blob), "v1 blob:limit drops the large blob");

    Ok(())
}

#[test]
fn serve_pack_upload_v2_dispatch_auto_honours_include_tag() -> crate::Result {
    let src_tmp = tempfile::tempdir()?;
    let mut src = gix::init_bare(src_tmp.path())?;

    let mut cfg = src.config_snapshot_mut();
    cfg.set_raw_value(gix::config::tree::Author::NAME, "Test Author")?;
    cfg.set_raw_value(gix::config::tree::Author::EMAIL, "test@example.com")?;
    cfg.set_raw_value(gix::config::tree::Committer::NAME, "Test Author")?;
    cfg.set_raw_value(gix::config::tree::Committer::EMAIL, "test@example.com")?;
    cfg.commit()?;

    let blob_id = src.write_blob(b"dispatch include-tag\n".as_slice())?.detach();
    let tree = gix_object::Tree {
        entries: vec![gix_object::tree::Entry {
            mode: gix_object::tree::EntryKind::Blob.into(),
            filename: "dispatch.txt".into(),
            oid: blob_id,
        }],
    };
    let tree_id = src.write_object(&tree)?.detach();
    let commit_id = src
        .commit("refs/heads/dispatch", "c", tree_id, gix::commit::NO_PARENT_IDS)?
        .detach();

    let tagger = gix_actor::SignatureRef {
        name: "Test Author".into(),
        email: "test@example.com".into(),
        time: "0 +0000".into(),
    };
    let tag_ref = src.tag(
        "v-dispatch",
        commit_id,
        gix_object::Kind::Commit,
        Some(tagger),
        "dispatch tag",
        gix::refs::transaction::PreviousValue::MustNotExist,
    )?;
    let tag_oid = tag_ref.target().try_id().expect("direct tag ref").to_owned();

    let want_line = format!("want {commit_id}\n");
    let request = build_v2_fetch_request_body(src.object_hash(), &[want_line.as_bytes(), b"include-tag\n"])?;
    let mut response: Vec<u8> = Vec::new();
    let should_interrupt = AtomicBool::new(false);
    let _ = src.serve_pack_upload_v2_dispatch_auto(request.as_slice(), &mut response, &should_interrupt)?;

    let pack_bytes = extract_pack_from_response(&response);
    let dst_tmp = tempfile::tempdir()?;
    let dst = gix::init_bare(dst_tmp.path())?;
    let dst_pack_dir = dst.objects.store_ref().path().join("pack");
    let mut cursor = std::io::Cursor::new(pack_bytes.to_vec());
    let mut reader = std::io::BufReader::new(&mut cursor);
    let base_lookup: Option<gix_odb::Cache<gix_odb::store::Handle<std::sync::Arc<gix_odb::Store>>>> =
        Some((*dst.objects).clone());
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
    assert!(dst.has_object(tag_oid), "dispatch path must ship include-tag");

    Ok(())
}

#[test]
fn serve_pack_upload_v2_dispatch_auto_honours_filter_blob_limit() -> crate::Result {
    let src_tmp = tempfile::tempdir()?;
    let mut src = gix::init_bare(src_tmp.path())?;

    let mut cfg = src.config_snapshot_mut();
    cfg.set_raw_value(gix::config::tree::Author::NAME, "Test Author")?;
    cfg.set_raw_value(gix::config::tree::Author::EMAIL, "test@example.com")?;
    cfg.set_raw_value(gix::config::tree::Committer::NAME, "Test Author")?;
    cfg.set_raw_value(gix::config::tree::Committer::EMAIL, "test@example.com")?;
    cfg.commit()?;

    let small_blob = src.write_blob(b"tiny".as_slice())?.detach();
    let big_blob = src.write_blob(vec![b'x'; 4096].as_slice())?.detach();
    let tree = gix_object::Tree {
        entries: vec![
            gix_object::tree::Entry {
                mode: gix_object::tree::EntryKind::Blob.into(),
                filename: "big.bin".into(),
                oid: big_blob,
            },
            gix_object::tree::Entry {
                mode: gix_object::tree::EntryKind::Blob.into(),
                filename: "small.txt".into(),
                oid: small_blob,
            },
        ],
    };
    let tree_id = src.write_object(&tree)?.detach();
    let commit_id = src
        .commit("refs/heads/dispatch", "c", tree_id, gix::commit::NO_PARENT_IDS)?
        .detach();

    // Use the k-suffix on the wire so the test also exercises the
    // suffix parser inside the dispatch path.
    let want_line = format!("want {commit_id}\n");
    let request = build_v2_fetch_request_body(src.object_hash(), &[want_line.as_bytes(), b"filter blob:limit=1k\n"])?;
    let mut response: Vec<u8> = Vec::new();
    let should_interrupt = AtomicBool::new(false);
    let _ = src.serve_pack_upload_v2_dispatch_auto(request.as_slice(), &mut response, &should_interrupt)?;

    let pack_bytes = extract_pack_from_response(&response);
    let dst_tmp = tempfile::tempdir()?;
    let dst = gix::init_bare(dst_tmp.path())?;
    let dst_pack_dir = dst.objects.store_ref().path().join("pack");
    let mut cursor = std::io::Cursor::new(pack_bytes.to_vec());
    let mut reader = std::io::BufReader::new(&mut cursor);
    let base_lookup: Option<gix_odb::Cache<gix_odb::store::Handle<std::sync::Arc<gix_odb::Store>>>> =
        Some((*dst.objects).clone());
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
    assert!(dst.has_object(tree_id));
    assert!(dst.has_object(small_blob), "small blob fits under the 1k limit");
    assert!(!dst.has_object(big_blob), "4096-byte blob exceeds the 1k limit");

    Ok(())
}

#[test]
fn serve_pack_upload_v2_dispatch_auto_honours_filter_blob_none() -> crate::Result {
    let src_tmp = tempfile::tempdir()?;
    let mut src = gix::init_bare(src_tmp.path())?;

    let mut cfg = src.config_snapshot_mut();
    cfg.set_raw_value(gix::config::tree::Author::NAME, "Test Author")?;
    cfg.set_raw_value(gix::config::tree::Author::EMAIL, "test@example.com")?;
    cfg.set_raw_value(gix::config::tree::Committer::NAME, "Test Author")?;
    cfg.set_raw_value(gix::config::tree::Committer::EMAIL, "test@example.com")?;
    cfg.commit()?;

    let blob_id = src.write_blob(b"dispatch blob:none\n".as_slice())?.detach();
    let tree = gix_object::Tree {
        entries: vec![gix_object::tree::Entry {
            mode: gix_object::tree::EntryKind::Blob.into(),
            filename: "f.txt".into(),
            oid: blob_id,
        }],
    };
    let tree_id = src.write_object(&tree)?.detach();
    let commit_id = src
        .commit("refs/heads/dispatch", "c", tree_id, gix::commit::NO_PARENT_IDS)?
        .detach();

    let want_line = format!("want {commit_id}\n");
    let request = build_v2_fetch_request_body(src.object_hash(), &[want_line.as_bytes(), b"filter blob:none\n"])?;
    let mut response: Vec<u8> = Vec::new();
    let should_interrupt = AtomicBool::new(false);
    let _ = src.serve_pack_upload_v2_dispatch_auto(request.as_slice(), &mut response, &should_interrupt)?;

    let pack_bytes = extract_pack_from_response(&response);
    let dst_tmp = tempfile::tempdir()?;
    let dst = gix::init_bare(dst_tmp.path())?;
    let dst_pack_dir = dst.objects.store_ref().path().join("pack");
    let mut cursor = std::io::Cursor::new(pack_bytes.to_vec());
    let mut reader = std::io::BufReader::new(&mut cursor);
    let base_lookup: Option<gix_odb::Cache<gix_odb::store::Handle<std::sync::Arc<gix_odb::Store>>>> =
        Some((*dst.objects).clone());
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
    assert!(dst.has_object(tree_id));
    assert!(
        !dst.has_object(blob_id),
        "dispatch path must strip blobs under blob:none"
    );

    Ok(())
}

/// The v2 dispatcher must surface an unknown command as a typed
/// error rather than silently producing a malformed response, so
/// embedders can distinguish protocol-level client bugs from
/// I/O / ref-store failures.
#[test]
fn serve_pack_upload_v2_dispatch_auto_rejects_unknown_command() -> crate::Result {
    let tmp = tempfile::tempdir()?;
    let repo = gix::init_bare(tmp.path())?;

    let mut request: Vec<u8> = Vec::new();
    gix_packetline::blocking_io::encode::data_to_write(b"command=not-a-real-command\n", &mut request)?;
    gix_packetline::blocking_io::encode::data_to_write(b"object-format=sha1\n", &mut request)?;
    gix_packetline::blocking_io::encode::delim_to_write(&mut request)?;
    gix_packetline::blocking_io::encode::flush_to_write(&mut request)?;

    let mut response: Vec<u8> = Vec::new();
    let should_interrupt = AtomicBool::new(false);
    let err = repo
        .serve_pack_upload_v2_dispatch_auto(request.as_slice(), &mut response, &should_interrupt)
        .expect_err("unknown command must be rejected");

    // The error wraps the underlying ServeV2Error::UnknownCommand.
    let gix::repository::serve::ServePackUploadError::Serve(inner) = err;
    match inner {
        gix_protocol::upload_pack::ServeV2Error::UnknownCommand { .. } => {}
        other => panic!("expected UnknownCommand, got {other:?}"),
    }
    Ok(())
}

/// The `ref-prefix` body argument on an ls-refs request must filter
/// the advertised refs to names starting with one of the prefixes.
#[test]
fn serve_pack_upload_v2_dispatch_auto_ls_refs_honours_ref_prefix() -> crate::Result {
    let src_tmp = tempfile::tempdir()?;
    let mut src = gix::init_bare(src_tmp.path())?;
    let mut cfg = src.config_snapshot_mut();
    cfg.set_raw_value(gix::config::tree::Author::NAME, "Test Author")?;
    cfg.set_raw_value(gix::config::tree::Author::EMAIL, "test@example.com")?;
    cfg.set_raw_value(gix::config::tree::Committer::NAME, "Test Author")?;
    cfg.set_raw_value(gix::config::tree::Committer::EMAIL, "test@example.com")?;
    cfg.commit()?;

    let blob_id = src.write_blob(b"p\n".as_slice())?.detach();
    let tree = gix_object::Tree {
        entries: vec![gix_object::tree::Entry {
            mode: gix_object::tree::EntryKind::Blob.into(),
            filename: "p.txt".into(),
            oid: blob_id,
        }],
    };
    let tree_id = src.write_object(&tree)?.detach();
    // Two branches and one tag. The client will ask for refs/heads/
    // only; the tag must be filtered out.
    let head_commit = src
        .commit("refs/heads/main", "m", tree_id, gix::commit::NO_PARENT_IDS)?
        .detach();
    let _other = src
        .commit("refs/heads/other", "o", tree_id, gix::commit::NO_PARENT_IDS)?
        .detach();
    let _tag_commit = src
        .commit("refs/tags/v1", "t", tree_id, gix::commit::NO_PARENT_IDS)?
        .detach();

    let request = build_v2_ls_refs_request_with(src.object_hash(), &["refs/heads/"])?;
    let mut response: Vec<u8> = Vec::new();
    let should_interrupt = AtomicBool::new(false);
    let outcome = src.serve_pack_upload_v2_dispatch_auto(request.as_slice(), &mut response, &should_interrupt)?;

    match outcome {
        gix_protocol::upload_pack::serve::DispatchOutcome::LsRefs { refs_sent, .. } => {
            assert_eq!(refs_sent, 2, "only the two refs/heads/* entries should be returned");
        }
        other => panic!("expected LsRefs outcome, got {other:?}"),
    }
    // Response contains refs/heads/* but not refs/tags/v1.
    assert!(response
        .windows(b"refs/heads/main".len())
        .any(|w| w == b"refs/heads/main"));
    assert!(response
        .windows(b"refs/heads/other".len())
        .any(|w| w == b"refs/heads/other"));
    assert!(
        !response.windows(b"refs/tags/v1".len()).any(|w| w == b"refs/tags/v1"),
        "response must NOT advertise refs/tags/v1 when the prefix filter excludes it"
    );
    // The main commit oid should be present in the response since main is advertised.
    let hex = head_commit.to_hex().to_string();
    assert!(response.windows(hex.len()).any(|w| w == hex.as_bytes()));

    Ok(())
}

/// The dispatcher entry point must answer v2 `command=ls-refs`
/// requests by walking the live ref store, even though no fetch
/// follows.
#[test]
fn serve_pack_upload_v2_dispatch_auto_answers_ls_refs() -> crate::Result {
    let src_tmp = tempfile::tempdir()?;
    let mut src = gix::init_bare(src_tmp.path())?;
    let mut cfg = src.config_snapshot_mut();
    cfg.set_raw_value(gix::config::tree::Author::NAME, "Test Author")?;
    cfg.set_raw_value(gix::config::tree::Author::EMAIL, "test@example.com")?;
    cfg.set_raw_value(gix::config::tree::Committer::NAME, "Test Author")?;
    cfg.set_raw_value(gix::config::tree::Committer::EMAIL, "test@example.com")?;
    cfg.commit()?;

    let blob_id = src.write_blob(b"ls-refs\n".as_slice())?.detach();
    let tree = gix_object::Tree {
        entries: vec![gix_object::tree::Entry {
            mode: gix_object::tree::EntryKind::Blob.into(),
            filename: "l.txt".into(),
            oid: blob_id,
        }],
    };
    let tree_id = src.write_object(&tree)?.detach();
    let commit_id = src
        .commit("refs/heads/dispatch", "c", tree_id, gix::commit::NO_PARENT_IDS)?
        .detach();

    let request = build_v2_ls_refs_request(src.object_hash())?;
    let mut response: Vec<u8> = Vec::new();
    let should_interrupt = AtomicBool::new(false);
    let outcome = src.serve_pack_upload_v2_dispatch_auto(request.as_slice(), &mut response, &should_interrupt)?;

    match outcome {
        gix_protocol::upload_pack::serve::DispatchOutcome::LsRefs { refs_sent, .. } => {
            assert!(refs_sent >= 1, "at least refs/heads/dispatch should be advertised");
        }
        other => panic!("expected LsRefs outcome, got {other:?}"),
    }

    // The response must contain the ref's oid + refname somewhere.
    let hex = commit_id.to_hex().to_string();
    assert!(
        response.windows(hex.len()).any(|w| w == hex.as_bytes()),
        "response must include the commit oid from refs/heads/dispatch"
    );
    assert!(
        response
            .windows(b"refs/heads/dispatch".len())
            .any(|w| w == b"refs/heads/dispatch"),
        "response must include the ref name"
    );

    Ok(())
}

/// Fresh `git clone` (want + done, no haves) must get a response
/// with no `acknowledgments` section; otherwise stock git aborts
/// with `bad band #97`.
#[test]
fn serve_pack_upload_v2_auto_clone_without_haves_skips_acknowledgments() -> crate::Result {
    let src_tmp = tempfile::tempdir()?;
    let mut src = gix::init_bare(src_tmp.path())?;
    let mut cfg = src.config_snapshot_mut();
    cfg.set_raw_value(gix::config::tree::Author::NAME, "Test Author")?;
    cfg.set_raw_value(gix::config::tree::Author::EMAIL, "test@example.com")?;
    cfg.set_raw_value(gix::config::tree::Committer::NAME, "Test Author")?;
    cfg.set_raw_value(gix::config::tree::Committer::EMAIL, "test@example.com")?;
    cfg.commit()?;

    let blob_id = src.write_blob(b"clone-no-haves\n".as_slice())?.detach();
    let tree = gix_object::Tree {
        entries: vec![gix_object::tree::Entry {
            mode: gix_object::tree::EntryKind::Blob.into(),
            filename: "clone.txt".into(),
            oid: blob_id,
        }],
    };
    let tree_id = src.write_object(&tree)?.detach();
    let commit_id = src
        .commit("refs/heads/main", "initial", tree_id, gix::commit::NO_PARENT_IDS)?
        .detach();

    let request = build_v2_fetch_request(src.object_hash(), commit_id)?;
    let mut response: Vec<u8> = Vec::new();
    let should_interrupt = AtomicBool::new(false);
    let outcome = src.serve_pack_upload_v2_auto(request.as_slice(), &mut response, &should_interrupt)?;

    assert!(outcome.pack_sent, "pack must still ship for the clone");
    let acks_pos = find_pkt_line_payload_offset(&response, b"acknowledgments\n");
    let packfile_pos = find_pkt_line_payload_offset(&response, b"packfile\n");
    assert!(
        acks_pos.is_none(),
        "fresh clone response must omit the acknowledgments section entirely (v2 spec)"
    );
    assert!(packfile_pos.is_some(), "packfile section must still be present");
    Ok(())
}

/// A resolved `want-ref <refname>` must surface in a `wanted-refs`
/// section as `<oid> <refname>`.
#[test]
fn serve_pack_upload_v2_auto_resolved_want_ref_shows_in_wanted_refs_section() -> crate::Result {
    let src_tmp = tempfile::tempdir()?;
    let mut src = gix::init_bare(src_tmp.path())?;
    let mut cfg = src.config_snapshot_mut();
    cfg.set_raw_value(gix::config::tree::Author::NAME, "Test Author")?;
    cfg.set_raw_value(gix::config::tree::Author::EMAIL, "test@example.com")?;
    cfg.set_raw_value(gix::config::tree::Committer::NAME, "Test Author")?;
    cfg.set_raw_value(gix::config::tree::Committer::EMAIL, "test@example.com")?;
    cfg.commit()?;

    let blob_id = src.write_blob(b"wanted-refs payload\n".as_slice())?.detach();
    let tree = gix_object::Tree {
        entries: vec![gix_object::tree::Entry {
            mode: gix_object::tree::EntryKind::Blob.into(),
            filename: "wanted.txt".into(),
            oid: blob_id,
        }],
    };
    let tree_id = src.write_object(&tree)?.detach();
    let commit_id = src
        .commit("refs/heads/target", "wanted-ref target", tree_id, gix::commit::NO_PARENT_IDS)?
        .detach();

    let request = build_v2_fetch_request_with_ref(src.object_hash(), "refs/heads/target")?;
    let mut response: Vec<u8> = Vec::new();
    let should_interrupt = AtomicBool::new(false);
    let outcome = src.serve_pack_upload_v2_auto(request.as_slice(), &mut response, &should_interrupt)?;
    assert!(outcome.pack_sent);

    let wanted_pos = find_pkt_line_payload_offset(&response, b"wanted-refs\n")
        .expect("wanted-refs section must be emitted for resolved want-ref");
    let expected_body = format!("{commit_id} refs/heads/target\n");
    let body_pos = find_pkt_line_payload_offset(&response, expected_body.as_bytes())
        .expect("wanted-refs section must carry the oid + refname body line");
    let packfile_pos =
        find_pkt_line_payload_offset(&response, b"packfile\n").expect("packfile section must be present");
    assert!(wanted_pos < body_pos);
    assert!(body_pos < packfile_pos);
    Ok(())
}
