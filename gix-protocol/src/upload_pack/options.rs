//! Configuration for the server side of `git-upload-pack`.

use bstr::BString;

/// Options for a v0 / v1 advertisement.
///
/// Values here drive the capability list appended to the first pkt-line of
/// an `info/refs` (smart-HTTP) or stateful git:// session's advertisement.
/// Unknown capabilities added by the caller are preserved verbatim and
/// emitted after the built-in set.
#[derive(Debug, Clone)]
pub struct Options {
    /// The `agent=<value>` capability advertised to the client. Defaults to
    /// `gix/<crate-version>` when constructed via [`Options::default`].
    pub agent: BString,
    /// Advertise `multi_ack_detailed`. Recommended for modern clients.
    pub multi_ack_detailed: bool,
    /// Advertise the legacy `multi_ack` capability. Prefer
    /// `multi_ack_detailed` for new deployments.
    pub multi_ack: bool,
    /// Advertise `side-band-64k` for multiplexed pack streaming.
    pub side_band_64k: bool,
    /// Advertise the legacy `side-band` (smaller frames).
    pub side_band: bool,
    /// Advertise `thin-pack` - the client may request a pack containing
    /// deltas whose bases are on the server but not in the pack.
    pub thin_pack: bool,
    /// Advertise `ofs-delta` - offset-delta encoding in packs.
    pub ofs_delta: bool,
    /// Advertise `shallow` support (partial history clients).
    pub shallow: bool,
    /// Advertise the `filter` capability for partial clone.
    pub filter: bool,
    /// Advertise `no-done` so the client may skip an explicit `done` line.
    pub no_done: bool,
    /// Advertise `allow-tip-sha1-in-want` so clients may `want <oid>` any
    /// advertised tip directly by OID.
    pub allow_tip_sha1_in_want: bool,
    /// Advertise `allow-reachable-sha1-in-want` for OIDs reachable from any
    /// advertised tip.
    pub allow_reachable_sha1_in_want: bool,
    /// Advertise `include-tag` so annotated tag peels are included by
    /// default.
    pub include_tag: bool,
    /// Advertise `no-progress` so clients may suppress side-band
    /// progress lines. The auto serve paths emit no progress
    /// regardless, so this is passive advertisement.
    pub no_progress: bool,
    /// Advertise `deepen-since <ts>` support on the first want line.
    pub deepen_since: bool,
    /// Advertise `deepen-not <ref>` support on the first want line.
    pub deepen_not: bool,
    /// Advertise `deepen-relative` support on the first want line.
    pub deepen_relative: bool,
    /// Advertise `object-format=<name>` so clients negotiate the repo's
    /// hash algorithm explicitly. Absent for bug-for-bug compatibility
    /// with pre-2.28 servers.
    pub object_format: Option<BString>,
    /// Advertise `session-id=<sid>` for server-supplied request
    /// tracing. `None` omits the token.
    pub session_id: Option<BString>,
    /// `symref=<refname>:<target>` entries, emitted one per symref the
    /// caller wants to surface (classically `HEAD`). Clients use these
    /// to decide which branch to check out after a clone without a
    /// follow-up round trip.
    pub symrefs: Vec<BString>,
    /// Extra capability strings to append verbatim (e.g. for
    /// server-specific extensions). Each entry is emitted as-is after the
    /// built-in set.
    pub extra: Vec<BString>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            agent: BString::from(default_agent()),
            multi_ack_detailed: true,
            multi_ack: false,
            side_band_64k: true,
            side_band: false,
            thin_pack: true,
            ofs_delta: true,
            shallow: true,
            filter: false,
            no_done: true,
            allow_tip_sha1_in_want: true,
            allow_reachable_sha1_in_want: true,
            include_tag: true,
            no_progress: true,
            deepen_since: true,
            deepen_not: true,
            deepen_relative: true,
            object_format: Some(BString::from(default_object_format())),
            session_id: None,
            symrefs: Vec::new(),
            extra: Vec::new(),
        }
    }
}

impl Options {
    /// Return the advertised capability strings in the order they should be
    /// emitted on the wire (space-separated after the first ref line).
    pub fn advertised_capabilities(&self) -> Vec<BString> {
        let mut out = Vec::with_capacity(16 + self.extra.len());
        if self.multi_ack_detailed {
            out.push(BString::from("multi_ack_detailed"));
        }
        if self.multi_ack {
            out.push(BString::from("multi_ack"));
        }
        if self.side_band_64k {
            out.push(BString::from("side-band-64k"));
        } else if self.side_band {
            out.push(BString::from("side-band"));
        }
        if self.thin_pack {
            out.push(BString::from("thin-pack"));
        }
        if self.ofs_delta {
            out.push(BString::from("ofs-delta"));
        }
        if self.shallow {
            out.push(BString::from("shallow"));
        }
        if self.no_done {
            out.push(BString::from("no-done"));
        }
        if self.allow_tip_sha1_in_want {
            out.push(BString::from("allow-tip-sha1-in-want"));
        }
        if self.allow_reachable_sha1_in_want {
            out.push(BString::from("allow-reachable-sha1-in-want"));
        }
        if self.include_tag {
            out.push(BString::from("include-tag"));
        }
        if self.no_progress {
            out.push(BString::from("no-progress"));
        }
        if self.deepen_since {
            out.push(BString::from("deepen-since"));
        }
        if self.deepen_not {
            out.push(BString::from("deepen-not"));
        }
        if self.deepen_relative {
            out.push(BString::from("deepen-relative"));
        }
        if self.filter {
            out.push(BString::from("filter"));
        }
        for symref in &self.symrefs {
            let mut line = BString::from("symref=");
            line.extend_from_slice(symref);
            out.push(line);
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

/// Options for a v2 capability advertisement.
///
/// v2 emits a flat pkt-line list of capability tokens after a `version 2`
/// header; the per-command feature support is expressed as `command=<name>`
/// and `<command>=<feature>` entries.
#[derive(Debug, Clone)]
pub struct OptionsV2 {
    /// The `agent=<value>` capability.
    pub agent: BString,
    /// Advertise `ls-refs` (required in practice).
    pub ls_refs: bool,
    /// Features advertised as `ls-refs=<feature1> <feature2> ...`; pass an
    /// empty vector to omit the per-feature suffix.
    pub ls_refs_features: Vec<BString>,
    /// Advertise `fetch` (required for a usable upload-pack service).
    pub fetch: bool,
    /// Features advertised as `fetch=<feature1> <feature2> ...`.
    pub fetch_features: Vec<BString>,
    /// Advertise `server-option`.
    pub server_option: bool,
    /// Advertise `object-format=sha1` (today) or `sha256` (when built with
    /// the `sha256` feature).
    pub object_format: Option<BString>,
    /// Extra capability lines appended verbatim.
    pub extra: Vec<BString>,
}

impl Default for OptionsV2 {
    fn default() -> Self {
        Self {
            agent: BString::from(default_agent()),
            ls_refs: true,
            ls_refs_features: vec![BString::from("unborn"), BString::from("peel"), BString::from("symrefs")],
            fetch: true,
            fetch_features: vec![
                BString::from("shallow"),
                BString::from("filter"),
                BString::from("ref-in-want"),
                BString::from("sideband-all"),
                BString::from("wait-for-done"),
            ],
            server_option: true,
            object_format: Some(BString::from("sha1")),
            extra: Vec::new(),
        }
    }
}

impl OptionsV2 {
    /// Emit the advertised v2 capabilities as ordered pkt-line payloads
    /// (LF-terminated lines, without pkt-line framing).
    ///
    /// The caller frames each entry as a pkt-line and terminates the
    /// advertisement with a flush-pkt.
    pub fn advertised_capabilities(&self) -> Vec<BString> {
        let mut out = Vec::with_capacity(8 + self.extra.len());
        let mut agent = BString::from("agent=");
        agent.extend_from_slice(&self.agent);
        out.push(agent);
        if self.ls_refs {
            out.push(cap_with_features(b"ls-refs", &self.ls_refs_features));
        }
        if self.fetch {
            out.push(cap_with_features(b"fetch", &self.fetch_features));
        }
        if self.server_option {
            out.push(BString::from("server-option"));
        }
        if let Some(kind) = &self.object_format {
            let mut line = BString::from("object-format=");
            line.extend_from_slice(kind);
            out.push(line);
        }
        for extra in &self.extra {
            out.push(extra.clone());
        }
        out
    }
}

fn cap_with_features(name: &[u8], features: &[BString]) -> BString {
    if features.is_empty() {
        return BString::from(name);
    }
    let mut line = BString::from(name);
    line.push(b'=');
    for (i, feat) in features.iter().enumerate() {
        if i > 0 {
            line.push(b' ');
        }
        line.extend_from_slice(feat);
    }
    line
}

fn default_agent() -> String {
    concat!("gix/", env!("CARGO_PKG_VERSION")).to_string()
}

fn default_object_format() -> &'static str {
    // Only SHA-1 is actually wired through gix-hash today; SHA-256
    // would need selection logic downstream before we could truthfully
    // advertise it.
    "sha1"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v1_defaults_advertise_modern_capabilities() {
        let opts = Options::default();
        let caps = opts.advertised_capabilities();
        let has = |name: &str| {
            caps.iter()
                .any(|c| c == name || c.starts_with(format!("{name}=").as_bytes()))
        };
        assert!(has("multi_ack_detailed"));
        assert!(has("side-band-64k"));
        assert!(has("thin-pack"));
        assert!(has("ofs-delta"));
        assert!(has("no-done"));
        assert!(has("include-tag"));
        assert!(has("no-progress"));
        assert!(has("deepen-since"));
        assert!(has("deepen-not"));
        assert!(has("deepen-relative"));
        assert!(has("object-format=sha1"));
        assert!(has("agent"));
    }

    #[test]
    fn v1_symrefs_and_session_id_are_emitted_when_set() {
        let mut opts = Options::default();
        opts.symrefs.push(BString::from("HEAD:refs/heads/main"));
        opts.symrefs
            .push(BString::from("refs/remotes/origin/HEAD:refs/remotes/origin/main"));
        opts.session_id = Some(BString::from("abc123"));
        let caps = opts.advertised_capabilities();
        assert!(caps.iter().any(|c| c == "symref=HEAD:refs/heads/main"));
        assert!(caps
            .iter()
            .any(|c| c == "symref=refs/remotes/origin/HEAD:refs/remotes/origin/main"));
        assert!(caps.iter().any(|c| c == "session-id=abc123"));
    }

    #[test]
    fn v1_legacy_side_band_is_skipped_when_modern_is_on() {
        let opts = Options::default();
        let caps = opts.advertised_capabilities();
        assert!(!caps.iter().any(|c| c == "side-band"));
    }

    #[test]
    fn v1_extra_capabilities_are_appended() {
        let mut opts = Options::default();
        opts.extra.push(BString::from("custom-cap"));
        let caps = opts.advertised_capabilities();
        assert_eq!(caps.last().expect("non-empty"), "custom-cap");
    }

    #[test]
    fn v2_defaults_include_version_free_entries() {
        // `version 2` is part of the advertisement wrapper, not this list.
        let opts = OptionsV2::default();
        let caps = opts.advertised_capabilities();
        assert!(caps.iter().any(|c| c.starts_with(b"agent=")));
        assert!(caps.iter().any(|c| c.starts_with(b"ls-refs")));
        assert!(caps.iter().any(|c| c.starts_with(b"fetch")));
        assert!(caps.iter().any(|c| c == "object-format=sha1"));
    }

    #[test]
    fn v2_features_are_joined_with_space_after_equals() {
        let opts = OptionsV2::default();
        let caps = opts.advertised_capabilities();
        let fetch = caps
            .iter()
            .find(|c| c.starts_with(b"fetch"))
            .expect("fetch is advertised");
        assert!(fetch.as_slice().starts_with(b"fetch=shallow "));
    }

    #[test]
    fn v2_capabilities_without_features_omit_the_equals_suffix() {
        let mut opts = OptionsV2::default();
        opts.ls_refs_features.clear();
        let caps = opts.advertised_capabilities();
        assert!(caps.iter().any(|c| c == "ls-refs"));
    }
}
