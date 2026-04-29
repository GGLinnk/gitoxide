//! Emit the server's v2 `ls-refs` response.
//!
//! The response is a sequence of pkt-lines, one per ref, terminated by
//! a flush-pkt. Each line has the form
//!
//! ```text
//! <oid> <refname>[SP symref-target:<target>][SP peeled:<oid>] LF
//! ```
//!
//! or, for unborn refs when the client advertised `unborn`:
//!
//! ```text
//! unborn <refname>[SP symref-target:<target>] LF
//! ```
//!
//! This module provides the ref model and an emitter that produces
//! ordered LF-terminated byte payloads, mirroring
//! [`super::advertisement::emit_v1`]'s shape.

use bstr::{BString, ByteVec};

/// A single ref in a v2 `ls-refs` response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefEntry {
    /// The object the ref points to. `None` for an unborn ref
    /// (emitted only when the client announced the `unborn` token).
    pub object: Option<gix_hash::ObjectId>,
    /// The fully-qualified ref name.
    pub name: BString,
    /// When the ref is a symref and the client asked for `symrefs`,
    /// the target ref-name to include as `symref-target:<target>`.
    pub symref_target: Option<BString>,
    /// When the ref is an annotated tag and the client asked for
    /// `peel`, the OID of the underlying commit to include as
    /// `peeled:<oid>`.
    pub peeled: Option<gix_hash::ObjectId>,
}

/// Emit a v2 `ls-refs` response as ordered LF-terminated payloads.
///
/// The caller frames each as a pkt-line and terminates the response
/// with a flush-pkt.
pub fn emit(refs: &[RefEntry]) -> Vec<BString> {
    let mut lines = Vec::with_capacity(refs.len());
    for entry in refs {
        lines.push(format_ref_line(entry));
    }
    lines
}

fn format_ref_line(entry: &RefEntry) -> BString {
    let mut out = BString::default();
    match entry.object {
        Some(oid) => {
            out.push_str(oid.to_hex().to_string());
        }
        None => {
            out.extend_from_slice(b"unborn");
        }
    }
    out.push(b' ');
    out.extend_from_slice(&entry.name);
    if let Some(target) = &entry.symref_target {
        out.extend_from_slice(b" symref-target:");
        out.extend_from_slice(target);
    }
    if let Some(peeled) = entry.peeled {
        out.extend_from_slice(b" peeled:");
        out.push_str(peeled.to_hex().to_string());
    }
    out.push(b'\n');
    out
}

#[cfg(all(test, feature = "sha1"))]
mod tests {
    use super::*;

    fn oid(hex: &str) -> gix_hash::ObjectId {
        gix_hash::ObjectId::from_hex(hex.as_bytes()).expect("valid hex fixture")
    }

    #[test]
    fn direct_ref_emits_hex_oid_and_refname() {
        let refs = vec![RefEntry {
            object: Some(oid("1111111111111111111111111111111111111111")),
            name: "refs/heads/main".into(),
            symref_target: None,
            peeled: None,
        }];
        let lines = emit(&refs);
        assert_eq!(lines[0], "1111111111111111111111111111111111111111 refs/heads/main\n",);
    }

    #[test]
    fn symref_annotation_appended_when_target_present() {
        let refs = vec![RefEntry {
            object: Some(oid("1111111111111111111111111111111111111111")),
            name: "HEAD".into(),
            symref_target: Some("refs/heads/main".into()),
            peeled: None,
        }];
        let lines = emit(&refs);
        assert_eq!(
            lines[0],
            "1111111111111111111111111111111111111111 HEAD symref-target:refs/heads/main\n",
        );
    }

    #[test]
    fn peeled_annotation_appended_for_annotated_tags() {
        let refs = vec![RefEntry {
            object: Some(oid("1111111111111111111111111111111111111111")),
            name: "refs/tags/v1".into(),
            symref_target: None,
            peeled: Some(oid("2222222222222222222222222222222222222222")),
        }];
        let lines = emit(&refs);
        assert_eq!(
            lines[0],
            "1111111111111111111111111111111111111111 refs/tags/v1 peeled:2222222222222222222222222222222222222222\n",
        );
    }

    #[test]
    fn unborn_ref_prefixes_with_unborn_token() {
        let refs = vec![RefEntry {
            object: None,
            name: "refs/heads/empty".into(),
            symref_target: Some("refs/heads/main".into()),
            peeled: None,
        }];
        let lines = emit(&refs);
        assert_eq!(lines[0], "unborn refs/heads/empty symref-target:refs/heads/main\n");
    }

    #[test]
    fn empty_refs_list_emits_no_lines() {
        let refs: Vec<RefEntry> = Vec::new();
        let lines = emit(&refs);
        assert!(lines.is_empty());
    }
}
