//! Capability options and advertisement emitter for `git-receive-pack`.
//!
//! Receive-pack advertises a different capability set than upload-pack:
//! the push-oriented `report-status`/`report-status-v2`, `delete-refs`,
//! `atomic`, `quiet`, and `push-options` instead of the fetch-side
//! `multi_ack_*` / `thin-pack` / `filter` / etc.
//!
//! The ref / version framing is otherwise shared with upload-pack.

use bstr::{BString, ByteVec};

/// A single ref to advertise in a v0 / v1 receive-pack advertisement.
///
/// This struct is intentionally identical in shape to
/// [`crate::upload_pack::advertisement::AdvertisedRef`] - the wire format
/// is the same across services, only the capability list differs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvertisedRef {
    /// The OID the ref currently points to.
    pub object: gix_hash::ObjectId,
    /// The fully-qualified ref name (e.g. `refs/heads/main`).
    pub name: BString,
    /// When the ref is an annotated tag, the peeled commit OID.
    pub peeled: Option<gix_hash::ObjectId>,
}

/// Options for a receive-pack v0 / v1 advertisement.
#[derive(Debug, Clone)]
pub struct Options {
    /// The `agent=<value>` capability. Defaults to `gix/<crate-version>`.
    pub agent: BString,
    /// Advertise `report-status` so the client expects a per-ref report.
    pub report_status: bool,
    /// Advertise `report-status-v2` (preferred over the legacy report).
    pub report_status_v2: bool,
    /// Advertise `delete-refs` so clients may send deletion commands.
    pub delete_refs: bool,
    /// Advertise `atomic` for all-or-nothing application.
    pub atomic: bool,
    /// Advertise `quiet` so clients may suppress server progress.
    pub quiet: bool,
    /// Advertise `side-band-64k` for multiplexed response framing.
    pub side_band_64k: bool,
    /// Advertise the legacy `side-band` (smaller frames).
    pub side_band: bool,
    /// Advertise `ofs-delta`.
    pub ofs_delta: bool,
    /// Advertise `push-options`.
    pub push_options: bool,
    /// Advertise `object-format=<name>` so clients negotiate the repo's
    /// hash algorithm explicitly. Always emitted by git-receive-pack
    /// from 2.28 onward; `None` suppresses it.
    pub object_format: Option<BString>,
    /// Advertise `session-id=<sid>` for server-supplied request
    /// tracing. `None` omits the token.
    pub session_id: Option<BString>,
    /// Extra capability strings appended verbatim.
    pub extra: Vec<BString>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            agent: BString::from(default_agent()),
            report_status: true,
            report_status_v2: true,
            delete_refs: true,
            atomic: true,
            quiet: true,
            side_band_64k: true,
            side_band: false,
            ofs_delta: true,
            push_options: false,
            object_format: Some(BString::from("sha1")),
            session_id: None,
            extra: Vec::new(),
        }
    }
}

impl Options {
    /// Return the advertised capability strings in emit order.
    pub fn advertised_capabilities(&self) -> Vec<BString> {
        let mut out = Vec::with_capacity(10 + self.extra.len());
        if self.report_status_v2 {
            out.push(BString::from("report-status-v2"));
        }
        if self.report_status {
            out.push(BString::from("report-status"));
        }
        if self.delete_refs {
            out.push(BString::from("delete-refs"));
        }
        if self.atomic {
            out.push(BString::from("atomic"));
        }
        if self.quiet {
            out.push(BString::from("quiet"));
        }
        if self.side_band_64k {
            out.push(BString::from("side-band-64k"));
        } else if self.side_band {
            out.push(BString::from("side-band"));
        }
        if self.ofs_delta {
            out.push(BString::from("ofs-delta"));
        }
        if self.push_options {
            out.push(BString::from("push-options"));
        }
        if let Some(fmt) = &self.object_format {
            let mut line = BString::from("object-format=");
            line.extend_from_slice(fmt);
            out.push(line);
        }
        if let Some(sid) = &self.session_id {
            let mut line = BString::from("session-id=");
            line.extend_from_slice(sid);
            out.push(line);
        }
        let mut agent = BString::from("agent=");
        agent.extend_from_slice(&self.agent);
        out.push(agent);
        for extra in &self.extra {
            out.push(extra.clone());
        }
        out
    }
}

/// Emit a receive-pack v0 / v1 ref + capability advertisement.
///
/// Returns a vector of LF-terminated pkt-line payloads. See
/// [`crate::upload_pack::advertisement::emit_v1`] for the format details;
/// this variant differs only in which capability set it emits.
pub fn emit_v1(refs: &[AdvertisedRef], options: &Options) -> Vec<BString> {
    let caps = options.advertised_capabilities();
    let mut lines = Vec::with_capacity(refs.len() * 2 + 1);

    if refs.is_empty() {
        // Derive the zero-OID width from the advertised
        // `object-format=<name>` so a SHA-256 empty repository emits
        // the correct 64-char zero prefix.
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

/// Map an `object-format=<name>` value to a [`gix_hash::Kind`].
///
/// Mirrors the upload-pack helper of the same name so the two
/// advertisement emitters stay independent of each other at the
/// module level. Unknown values fall back to SHA-1; `sha256` is
/// mapped through the compile-time `Kind::all` list so the lookup
/// degrades gracefully when `gix-hash` was built without SHA-256.
fn kind_from_object_format(name: Option<&bstr::BStr>) -> gix_hash::Kind {
    use bstr::ByteSlice as _;
    if let Some(name) = name.map(|n| n.as_bytes()) {
        if name.eq_ignore_ascii_case(b"sha256") {
            for &kind in gix_hash::Kind::all() {
                if !matches!(kind, gix_hash::Kind::Sha1) {
                    return kind;
                }
            }
        }
    }
    gix_hash::Kind::Sha1
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

fn default_agent() -> String {
    concat!("gix/", env!("CARGO_PKG_VERSION")).to_string()
}

#[cfg(all(test, feature = "sha1"))]
mod tests {
    use super::*;

    fn oid(hex: &str) -> gix_hash::ObjectId {
        gix_hash::ObjectId::from_hex(hex.as_bytes()).expect("valid hex fixture")
    }

    #[test]
    fn defaults_advertise_modern_push_capabilities() {
        let caps = Options::default().advertised_capabilities();
        let has = |name: &str| {
            caps.iter()
                .any(|c| c == name || c.starts_with(format!("{name}=").as_bytes()))
        };
        assert!(has("report-status-v2"));
        assert!(has("report-status"));
        assert!(has("delete-refs"));
        assert!(has("atomic"));
        assert!(has("quiet"));
        assert!(has("side-band-64k"));
        assert!(has("ofs-delta"));
        assert!(has("object-format=sha1"));
        assert!(has("agent"));
    }

    #[test]
    fn session_id_is_emitted_when_set() {
        let mut opts = Options::default();
        opts.session_id = Some(BString::from("sid-42"));
        assert!(opts.advertised_capabilities().iter().any(|c| c == "session-id=sid-42"));
    }

    #[test]
    fn push_options_is_opt_in() {
        let mut opts = Options::default();
        assert!(!opts.advertised_capabilities().iter().any(|c| c == "push-options"));
        opts.push_options = true;
        assert!(opts.advertised_capabilities().iter().any(|c| c == "push-options"));
    }

    #[test]
    fn v1_empty_repository_emits_capabilities_placeholder() {
        let lines = emit_v1(&[], &Options::default());
        assert_eq!(lines.len(), 1);
        assert!(lines[0].starts_with(b"0000000000000000000000000000000000000000 capabilities^{}"));
        assert!(lines[0].contains(&0));
    }

    #[test]
    fn v1_first_line_carries_push_capabilities_after_nul() {
        let refs = vec![AdvertisedRef {
            object: oid("1111111111111111111111111111111111111111"),
            name: BString::from("refs/heads/main"),
            peeled: None,
        }];
        let lines = emit_v1(&refs, &Options::default());
        let first = &lines[0];
        let nul = first.iter().position(|&b| b == 0).expect("NUL present");
        let caps_part = &first[nul + 1..];
        assert!(caps_part.windows(16).any(|w| w == b"report-status-v2"));
        assert!(caps_part.windows(11).any(|w| w == b"delete-refs"));
    }
}
