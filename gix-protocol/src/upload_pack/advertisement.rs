//! Emit the ref / capability advertisement at the start of an upload-pack
//! service response.
//!
//! Two wire formats are supported:
//!
//! - [`emit_v1`] produces the v0 / v1 advertisement - one pkt-line per ref
//!   with the capability list NUL-separated on the first line. Empty
//!   repositories are advertised as a single placeholder line carrying
//!   only the capability list.
//! - [`emit_v2`] produces the v2 advertisement - a `version 2` header
//!   followed by one pkt-line per capability token.
//!
//! Both emitters produce an ordered list of LF-terminated byte payloads
//! (without pkt-line framing); the transport layer is responsible for
//! wrapping each in a pkt-line and writing the terminating flush-pkt.

use bstr::{BString, ByteVec};

use super::options::{Options, OptionsV2};

/// A single ref to advertise in a v0 / v1 advertisement.
///
/// The [`peeled`] field is used to emit the classic `<refname>^{}` suffix
/// line for annotated tag peels. For non-tag refs, set it to `None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvertisedRef {
    /// The OID the ref currently points to.
    pub object: gix_hash::ObjectId,
    /// The fully-qualified ref name (e.g. `refs/heads/main`).
    pub name: BString,
    /// When the ref is an annotated tag, the peeled commit OID.
    pub peeled: Option<gix_hash::ObjectId>,
}

/// Emit a v0 / v1 ref + capability advertisement.
///
/// Returns a vector of LF-terminated pkt-line payloads in emit order. The
/// capability list is attached to the first line (via NUL). If `refs` is
/// empty, a single placeholder line with the all-zero OID and the ref name
/// `capabilities^{}` is emitted, per git's convention for empty
/// repositories.
pub fn emit_v1(refs: &[AdvertisedRef], options: &Options) -> Vec<BString> {
    let caps = options.advertised_capabilities();
    let mut lines = Vec::with_capacity(refs.len() * 2 + 1);

    if refs.is_empty() {
        // Empty-repository placeholder: git advertises a single ref-looking
        // line with the all-zero OID and the sentinel name `capabilities^{}`
        // carrying only the capability list. Derive the zero-OID width
        // from the advertised `object-format=<name>` capability so a
        // caller pointing us at a SHA-256 repo emits a 64-char zero
        // prefix; fall back to SHA-1 when the token is absent.
        let zero = gix_hash::ObjectId::null(kind_from_object_format(
            options.object_format.as_ref().map(|b| bstr::BStr::new(b.as_slice())),
        ));
        let mut line = BString::new(Vec::with_capacity(64));
        write_ref_first(&mut line, zero, b"capabilities^{}", &caps);
        lines.push(line);
        return lines;
    }

    let (first, rest) = refs.split_first().expect("non-empty");
    let mut first_line = BString::new(Vec::with_capacity(caps.iter().map(|c| c.len() + 1).sum::<usize>() + 64));
    write_ref_first(&mut first_line, first.object, &first.name, &caps);
    lines.push(first_line);
    if let Some(peeled) = first.peeled {
        lines.push(write_ref_peeled(peeled, &first.name));
    }
    for entry in rest {
        lines.push(write_ref_plain(entry.object, &entry.name));
        if let Some(peeled) = entry.peeled {
            lines.push(write_ref_peeled(peeled, &entry.name));
        }
    }
    lines
}

/// Emit a v2 capability advertisement.
///
/// Returns a vector of LF-terminated pkt-line payloads starting with
/// `version 2` and followed by each capability token. The caller frames
/// each as a pkt-line and terminates the advertisement with a flush-pkt.
pub fn emit_v2(options: &OptionsV2) -> Vec<BString> {
    let mut lines = Vec::with_capacity(8 + options.extra.len());
    lines.push(BString::from("version 2\n"));
    for cap in options.advertised_capabilities() {
        let mut line = cap;
        line.push(b'\n');
        lines.push(line);
    }
    lines
}

fn write_ref_first(out: &mut BString, oid: gix_hash::ObjectId, name: &[u8], caps: &[BString]) {
    out.push_str(oid.to_hex().to_string());
    out.push(b' ');
    out.extend_from_slice(name);
    out.push(0);
    for (i, cap) in caps.iter().enumerate() {
        if i > 0 {
            out.push(b' ');
        }
        out.extend_from_slice(cap);
    }
    out.push(b'\n');
}

fn write_ref_plain(oid: gix_hash::ObjectId, name: &[u8]) -> BString {
    let hex_len = oid.kind().len_in_hex();
    let mut out = BString::new(Vec::with_capacity(hex_len + name.len() + 2));
    out.push_str(oid.to_hex().to_string());
    out.push(b' ');
    out.extend_from_slice(name);
    out.push(b'\n');
    out
}

fn write_ref_peeled(peeled: gix_hash::ObjectId, name: &[u8]) -> BString {
    let hex_len = peeled.kind().len_in_hex();
    let mut out = BString::new(Vec::with_capacity(hex_len + name.len() + 5));
    out.push_str(peeled.to_hex().to_string());
    out.push(b' ');
    out.extend_from_slice(name);
    out.extend_from_slice(b"^{}\n");
    out
}

/// Map an `object-format=<name>` capability value to the matching
/// [`gix_hash::Kind`].
///
/// Unknown or absent values fall back to [`gix_hash::Kind::Sha1`].
/// `sha256` is recognised and mapped through [`gix_hash::Kind::all`]
/// so the lookup compiles against any feature set `gix-hash` was
/// built with - when the local `gix-hash` lacks SHA-256 support the
/// lookup gracefully degrades to SHA-1 rather than refusing to
/// compile.
pub(crate) fn kind_from_object_format(name: Option<&bstr::BStr>) -> gix_hash::Kind {
    use bstr::ByteSlice as _;
    if let Some(name) = name.map(|n| n.as_bytes()) {
        if name.eq_ignore_ascii_case(b"sha256") {
            // Walk the compile-time `Kind` list and pick the first
            // non-SHA1 entry - that's the SHA-256 slot when the
            // feature is on, and just SHA-1 otherwise.
            for &kind in gix_hash::Kind::all() {
                if !matches!(kind, gix_hash::Kind::Sha1) {
                    return kind;
                }
            }
        }
    }
    gix_hash::Kind::Sha1
}

#[cfg(all(test, feature = "sha1"))]
mod tests {
    use super::*;

    fn oid(hex: &str) -> gix_hash::ObjectId {
        gix_hash::ObjectId::from_hex(hex.as_bytes()).expect("valid hex fixture")
    }

    #[test]
    fn v1_first_line_carries_capabilities_after_nul() {
        let refs = vec![AdvertisedRef {
            object: oid("1111111111111111111111111111111111111111"),
            name: BString::from("refs/heads/main"),
            peeled: None,
        }];
        let lines = emit_v1(&refs, &Options::default());
        assert_eq!(lines.len(), 1);
        let first = &lines[0];
        let nul_pos = first.iter().position(|&b| b == 0).expect("NUL is present");
        assert!(first[..nul_pos].ends_with(b"refs/heads/main"));
        // capabilities follow the NUL and include side-band-64k by default
        let caps_part = &first[nul_pos + 1..];
        assert!(caps_part.windows(13).any(|w| w == b"side-band-64k"));
        assert!(first.last().copied() == Some(b'\n'));
    }

    #[test]
    fn v1_subsequent_lines_have_no_capabilities() {
        let refs = vec![
            AdvertisedRef {
                object: oid("1111111111111111111111111111111111111111"),
                name: BString::from("refs/heads/main"),
                peeled: None,
            },
            AdvertisedRef {
                object: oid("2222222222222222222222222222222222222222"),
                name: BString::from("refs/heads/feature"),
                peeled: None,
            },
        ];
        let lines = emit_v1(&refs, &Options::default());
        assert_eq!(lines.len(), 2);
        assert!(!lines[1].contains(&0));
        assert_eq!(
            &lines[1][..],
            b"2222222222222222222222222222222222222222 refs/heads/feature\n",
        );
    }

    #[test]
    fn v1_peeled_tag_emits_caret_curly_line() {
        let refs = vec![AdvertisedRef {
            object: oid("1111111111111111111111111111111111111111"),
            name: BString::from("refs/tags/v1"),
            peeled: Some(oid("2222222222222222222222222222222222222222")),
        }];
        let lines = emit_v1(&refs, &Options::default());
        assert_eq!(lines.len(), 2);
        assert!(lines[1].ends_with(b"refs/tags/v1^{}\n"));
    }

    #[test]
    fn v1_empty_repository_emits_capabilities_placeholder() {
        let lines = emit_v1(&[], &Options::default());
        assert_eq!(lines.len(), 1);
        let line = &lines[0];
        assert!(line.starts_with(b"0000000000000000000000000000000000000000 capabilities^{}"));
        assert!(line.contains(&0));
    }

    #[test]
    fn v2_starts_with_version_line() {
        let lines = emit_v2(&OptionsV2::default());
        assert!(lines.first().expect("at least one line") == "version 2\n");
    }

    #[test]
    fn v2_advertises_fetch_and_ls_refs() {
        let lines = emit_v2(&OptionsV2::default());
        assert!(lines.iter().any(|l| l.starts_with(b"ls-refs")));
        assert!(lines.iter().any(|l| l.starts_with(b"fetch")));
        assert!(lines.iter().all(|l| l.ends_with(b"\n")));
    }
}
