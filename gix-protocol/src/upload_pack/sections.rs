//! Emitters for the optional v2 fetch-response sections
//! `shallow-info`, `wanted-refs`, and `packfile-uris`.
//!
//! Each function emits the section header pkt-line + each body line
//! as ordered LF-terminated payloads. The caller frames each payload
//! as a pkt-line and is responsible for injecting the delim-pkt
//! between sections and the flush-pkt at end-of-response.

use bstr::{BString, ByteVec};

use crate::wire_types::{PackfileUri, ShallowUpdate, WantedRef};

/// Emit the `shallow-info` section.
///
/// Grammar:
///
/// ```text
/// shallow-info = PKT-LINE("shallow-info" LF)
///                *PKT-LINE((shallow | unshallow) LF)
/// shallow   = "shallow" SP obj-id
/// unshallow = "unshallow" SP obj-id
/// ```
///
/// Empty `updates` yields the header + zero body lines - this is
/// grammar-legal and distinct from section absence, which is modelled
/// one level up by `Option<Vec<ShallowUpdate>>`.
pub fn emit_shallow_info(updates: &[ShallowUpdate]) -> Vec<BString> {
    let mut lines = Vec::with_capacity(1 + updates.len());
    lines.push(BString::from("shallow-info\n"));
    for update in updates {
        let (prefix, oid) = match update {
            ShallowUpdate::Shallow(oid) => ("shallow", oid),
            ShallowUpdate::Unshallow(oid) => ("unshallow", oid),
        };
        let mut line = BString::from(prefix);
        line.push(b' ');
        line.push_str(oid.to_hex().to_string());
        line.push(b'\n');
        lines.push(line);
    }
    lines
}

/// Emit the `wanted-refs` section.
///
/// Grammar:
///
/// ```text
/// wanted-refs = PKT-LINE("wanted-refs" LF)
///               *PKT-LINE(wanted-ref LF)
/// wanted-ref  = obj-id SP refname
/// ```
pub fn emit_wanted_refs(refs: &[WantedRef]) -> Vec<BString> {
    let mut lines = Vec::with_capacity(1 + refs.len());
    lines.push(BString::from("wanted-refs\n"));
    for wanted in refs {
        let mut line = BString::new(Vec::new());
        line.push_str(wanted.id.to_hex().to_string());
        line.push(b' ');
        line.push_str(wanted.path.as_slice());
        line.push(b'\n');
        lines.push(line);
    }
    lines
}

/// Emit the `packfile-uris` section.
///
/// Grammar:
///
/// ```text
/// packfile-uris = PKT-LINE("packfile-uris" LF) *packfile-uri
/// packfile-uri  = PKT-LINE(40*(HEXDIG) SP *%x20-ff LF)
/// ```
pub fn emit_packfile_uris(uris: &[PackfileUri]) -> Vec<BString> {
    let mut lines = Vec::with_capacity(1 + uris.len());
    lines.push(BString::from("packfile-uris\n"));
    for uri in uris {
        let mut line = BString::new(Vec::new());
        line.push_str(uri.hash.to_hex().to_string());
        line.push(b' ');
        line.push_str(uri.uri.as_bytes());
        line.push(b'\n');
        lines.push(line);
    }
    lines
}

#[cfg(all(test, feature = "sha1"))]
mod tests {
    use super::*;

    fn oid(hex: &str) -> gix_hash::ObjectId {
        gix_hash::ObjectId::from_hex(hex.as_bytes()).expect("valid hex fixture")
    }

    #[test]
    fn shallow_info_empty_emits_header_only() {
        let lines = emit_shallow_info(&[]);
        assert_eq!(lines, vec![BString::from("shallow-info\n")]);
    }

    #[test]
    fn shallow_info_emits_one_line_per_update() {
        let lines = emit_shallow_info(&[
            ShallowUpdate::Shallow(oid("1111111111111111111111111111111111111111")),
            ShallowUpdate::Unshallow(oid("2222222222222222222222222222222222222222")),
        ]);
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], "shallow-info\n");
        assert_eq!(lines[1], "shallow 1111111111111111111111111111111111111111\n");
        assert_eq!(lines[2], "unshallow 2222222222222222222222222222222222222222\n");
    }

    #[test]
    fn wanted_refs_empty_emits_header_only() {
        let lines = emit_wanted_refs(&[]);
        assert_eq!(lines, vec![BString::from("wanted-refs\n")]);
    }

    #[test]
    fn wanted_refs_emits_oid_space_name() {
        let lines = emit_wanted_refs(&[WantedRef {
            id: oid("1111111111111111111111111111111111111111"),
            path: bstr::BString::from("refs/heads/main"),
        }]);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], "wanted-refs\n");
        assert_eq!(lines[1], "1111111111111111111111111111111111111111 refs/heads/main\n");
    }

    #[test]
    fn packfile_uris_empty_emits_header_only() {
        let lines = emit_packfile_uris(&[]);
        assert_eq!(lines, vec![BString::from("packfile-uris\n")]);
    }

    #[test]
    fn packfile_uris_emits_hash_space_uri() {
        let lines = emit_packfile_uris(&[PackfileUri {
            hash: oid("1111111111111111111111111111111111111111"),
            uri: "https://example.com/packs/abc.pack".into(),
        }]);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], "packfile-uris\n");
        assert_eq!(
            lines[1],
            "1111111111111111111111111111111111111111 https://example.com/packs/abc.pack\n"
        );
    }
}
