//! Client-side `git push` orchestration.
//!
//! This module provides the high-level entry point for pushing to a remote
//! from an existing [`Connection`]. It handles the handshake (`git-receive-
//! pack` service), capability negotiation via
//! [`gix_protocol::push::Arguments`], request emission, and
//! [`report-status`](gix_protocol::push::report_status) parsing.
//!
//! ## Quick start
//!
//! The convenience path for the common `git push <remote> <refspecs>`
//! case is [`crate::Remote::push`], which bundles connect + handshake
//! + refspec resolution + pack generation + send into one call:
//!
//! ```no_run
//! # #[cfg(feature = "blocking-network-client")]
//! # fn demo(repo: &gix::Repository) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
//! let should_interrupt = std::sync::atomic::AtomicBool::new(false);
//! let remote = repo.find_remote("origin")?;
//! // Empty refspecs falls back to `remote.origin.push` in git-config.
//! let outcome = remote.push(
//!     std::iter::empty::<&str>(),
//!     gix::progress::Discard,
//!     &should_interrupt,
//! )?;
//! # let _ = outcome;
//! # Ok(()) }
//! ```
//!
//! ## Manual builder chain
//!
//! Use the explicit builder when you need hooks, push-options, atomic
//! application, quiet mode, or a dry run:
//!
//! ```no_run
//! # #[cfg(feature = "blocking-network-client")]
//! # fn demo(repo: &gix::Repository) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
//! let should_interrupt = std::sync::atomic::AtomicBool::new(false);
//! let remote = repo.find_remote("origin")?;
//! let connection = remote.connect(gix::remote::Direction::Push)?;
//! let outcome = connection
//!     .prepare_push(gix::progress::Discard)?
//!     .with_refspecs(["refs/heads/main:refs/heads/main"].iter().map(AsRef::<gix::bstr::BStr>::as_ref))?
//!     .with_atomic(true)
//!     .send_with_generated_pack(&should_interrupt)?;
//! if !outcome.report.is_success() {
//!     for (refname, result) in outcome.report.command_statuses() {
//!         if let Err(reason) = result {
//!             eprintln!("rejected {refname}: {reason}");
//!         }
//!     }
//! }
//! # Ok(()) }
//! ```
//!
//! ## Inspecting the outcome
//!
//! Both entry points return an [`Outcome`] whose `report` field
//! exposes helpers to decide success without pattern-matching the
//! v1/v2 ReportKind directly:
//!
//! - [`gix_protocol::push::response::Outcome::is_success`] - unpack
//!   ok AND no per-command rejections
//! - [`gix_protocol::push::response::Outcome::accepted_count`] /
//!   [`rejected_count`](gix_protocol::push::response::Outcome::rejected_count)
//! - [`command_statuses`](gix_protocol::push::response::Outcome::command_statuses)
//!   - iterator of `(refname, Result<CommandOptions, reason>)`

#[cfg(feature = "async-network-client")]
use gix_transport::client::async_io::Transport;
#[cfg(feature = "blocking-network-client")]
use gix_transport::client::blocking_io::Transport;

use crate::{remote::Connection, Progress};

mod error;
pub use error::Error;

#[cfg(any(feature = "blocking-network-client", feature = "async-network-client"))]
fn url_to_bstring(configured: Option<&gix_url::Url>, transport_url: &crate::bstr::BStr) -> crate::bstr::BString {
    match configured {
        Some(url) => url.to_bstring(),
        None => transport_url.to_owned(),
    }
}

/// Outcome of a completed push.
///
/// A push with no rejected commands and a successful unpack is NOT
/// automatically signalled as success; the caller must inspect
/// [`gix_protocol::push::response::Outcome::is_success`] (accessible
/// via `self.report.is_success()`) to find out. The value is
/// `#[must_use]` so accidentally dropping it without checking the
/// report emits a warning.
#[must_use = "a push Outcome should be inspected for per-ref acceptance / rejection status"]
#[derive(Debug, Clone)]
pub struct Outcome {
    /// The handshake performed against the remote's `git-receive-pack` service.
    pub handshake: gix_protocol::Handshake,
    /// The server's `report-status` (or `report-status-v2`) response, plus any
    /// progress messages received over side-band channel 2.
    pub report: gix_protocol::push::response::Outcome,
}

/// Prepared push state. Constructed via
/// [`Connection::prepare_push`] after the handshake has completed, then
/// populated with ref-update commands and optional capabilities, and
/// finally executed with [`Prepare::send`].
#[must_use = "a prepared push does nothing until `send` / `send_with_generated_pack` is called"]
pub struct Prepare<'remote, 'repo, T>
where
    T: Transport,
{
    con: Option<Connection<'remote, 'repo, T>>,
    handshake: gix_protocol::Handshake,
    commands: Vec<gix_protocol::push::Command>,
    /// Parallel to `commands`: `true` when the originating refspec was
    /// prefixed with `+`, explicitly allowing a non-fast-forward update.
    /// Always the same length as `commands`.
    force_allowed: Vec<bool>,
    /// When set, the fast-forward check is skipped for every command,
    /// mirroring `git push --force`.
    force_all: bool,
    push_options: Option<Vec<crate::bstr::BString>>,
    use_atomic: bool,
    use_quiet: bool,
    dry_run: bool,
}

#[cfg(feature = "blocking-network-client")]
impl crate::Remote<'_> {
    /// Connect to the remote, run the handshake, resolve the given push
    /// `refspecs` against this repository's refs and the handshake's
    /// advertised remote tips, and stream the resulting pack - all in
    /// one call.
    ///
    /// This is the counterpart to the `remote.connect(Direction::Push)`
    /// -> `prepare_push` -> `with_refspecs` -> `send_with_generated_pack`
    /// chain for callers that have no reason to interact with the
    /// intermediate builders. Use the chain explicitly when custom
    /// hooks, atomic/quiet flags, push-options, or dry-run are needed.
    ///
    /// When `refspecs` is empty, the method falls back in two steps:
    ///
    /// 1. The push refspecs configured on this remote via
    ///    [`Remote::refspecs(Direction::Push)`](Self::refspecs) -
    ///    typically `remote.<name>.push` in git-config - are tried
    ///    first.
    /// 2. If that list is also empty, the current branch's push
    ///    target is derived from `push.default`:
    ///    - `nothing` -> no refspec (error)
    ///    - `current` / `matching` -> push HEAD's ref to the same name
    ///    - `upstream` -> push HEAD's ref to its tracked branch
    ///      (`branch.<name>.merge`)
    ///    - `simple` (the git default) -> push HEAD's ref to its
    ///      tracked branch only when the names match; otherwise no
    ///      refspec
    ///
    /// If neither fallback yields a command (e.g. a detached HEAD, a
    /// `push.default = nothing` policy, or `simple` with a renamed
    /// upstream) the push will fail with [`Error::NoCommands`].
    #[allow(clippy::result_large_err)]
    #[gix_protocol::maybe_async::maybe_async]
    #[doc(alias = "git push")]
    pub async fn push<I, S, P>(
        &self,
        refspecs: I,
        mut progress: P,
        should_interrupt: &std::sync::atomic::AtomicBool,
    ) -> Result<Outcome, Error>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<crate::bstr::BStr>,
        P: gix_features::progress::NestedProgress,
        P::SubProgress: 'static,
    {
        use crate::remote::Direction;
        let spec_strs: Vec<crate::bstr::BString> = refspecs.into_iter().map(|s| s.as_ref().to_owned()).collect();
        let connection = self.connect(Direction::Push).await?;
        // Handshake gets its own sub-child so the progress tree looks
        // the same shape as `Remote::fetch`'s (handshake + transfer).
        let prepare = connection.prepare_push(progress.add_child("handshake")).await?;
        let prepare = if !spec_strs.is_empty() {
            prepare.with_refspecs(spec_strs.iter().map(AsRef::<crate::bstr::BStr>::as_ref))?
        } else {
            let from_config = prepare.with_remote_push_specs(self)?;
            if from_config.commands().is_empty() {
                match push_default_target(self.repo) {
                    Some(target) => {
                        let specs = [target];
                        from_config.with_refspecs(specs.iter().map(AsRef::<crate::bstr::BStr>::as_ref))?
                    }
                    None => from_config,
                }
            } else {
                from_config
            }
        };
        prepare.send_with_generated_pack(progress, should_interrupt)
    }
}

impl<'remote, 'repo, T> Connection<'remote, 'repo, T>
where
    T: Transport,
{
    /// Perform the handshake with the remote's `git-receive-pack` service
    /// and return a [`Prepare`] ready to accept commands.
    ///
    /// The connection is consumed by this call; on success it lives inside
    /// the returned [`Prepare`] and is released back to the caller via
    /// [`Prepare::send`] or dropped when [`Prepare`] is discarded.
    #[allow(clippy::result_large_err)]
    #[gix_protocol::maybe_async::maybe_async]
    pub async fn prepare_push(mut self, mut progress: impl Progress) -> Result<Prepare<'remote, 'repo, T>, Error> {
        use crate::remote::Direction;

        let repo = self.remote.repo;
        let transport_url = self.transport.inner.to_url();
        let url_bstring = url_to_bstring(self.remote.url(Direction::Push), transport_url.as_ref());
        let url = gix_url::parse(url_bstring.as_ref()).expect("valid URL provided by transport or remote");
        if self.transport_options.is_none() {
            let url_bstr: &crate::bstr::BStr = url_bstring.as_ref();
            self.transport_options = repo
                .transport_options(url_bstr, self.remote.name().map(crate::remote::Name::as_bstr))
                .map_err(Error::GatherTransportConfig)?;
        }
        if let Some(config) = self.transport_options.as_ref() {
            self.transport
                .inner
                .configure(&**config)
                .map_err(|err| Error::Transport(gix_transport::client::Error::Io(std::io::Error::other(err))))?;
        }

        let mut credentials_storage;
        let authenticate = match self.authenticate.as_mut() {
            Some(f) => f,
            None => {
                credentials_storage = self.configured_credentials(url)?;
                &mut credentials_storage
            }
        };

        let handshake = gix_protocol::handshake(
            &mut self.transport.inner,
            gix_transport::Service::ReceivePack,
            authenticate,
            Vec::new(),
            &mut progress,
        )
        .await
        .map_err(Error::Handshake)?;

        Ok(Prepare {
            con: Some(self),
            handshake,
            commands: Vec::new(),
            force_allowed: Vec::new(),
            force_all: false,
            push_options: None,
            use_atomic: false,
            use_quiet: false,
            dry_run: false,
        })
    }
}

/// Builder methods.
impl<T> Prepare<'_, '_, T>
where
    T: Transport,
{
    /// Return the handshake that was performed when creating this [`Prepare`].
    pub fn handshake(&self) -> &gix_protocol::Handshake {
        &self.handshake
    }

    /// Returns `true` if the remote advertised the named capability
    /// during the handshake.
    ///
    /// Typed wrappers [`Self::can_use_atomic`],
    /// [`Self::can_use_push_options`], and [`Self::can_delete_refs`]
    /// cover the capabilities the push builder exposes directly.
    pub fn has_capability(&self, name: &str) -> bool {
        self.handshake.capabilities.contains(name)
    }

    /// Returns `true` if the server advertised `atomic`.
    pub fn can_use_atomic(&self) -> bool {
        self.has_capability("atomic")
    }

    /// Returns `true` if the server advertised `push-options`.
    pub fn can_use_push_options(&self) -> bool {
        self.has_capability("push-options")
    }

    /// Returns `true` if the server advertised `delete-refs`.
    pub fn can_delete_refs(&self) -> bool {
        self.has_capability("delete-refs")
    }

    /// Returns `true` if the server advertised `report-status-v2`.
    pub fn can_report_status_v2(&self) -> bool {
        self.has_capability("report-status-v2")
    }

    /// Replace the list of ref-update commands to send.
    ///
    /// Each command is treated as non-force; [`Prepare::send`] will
    /// refuse it if `new_id` does not descend from `old_id`. Use
    /// [`Self::with_commands_forced`] to mark a whole replacement batch
    /// as force, or [`Self::with_force`] to bypass the check for every
    /// command regardless of origin.
    ///
    /// Returning an empty list will cause [`Prepare::send`] to fail
    /// with [`Error::NoCommands`].
    pub fn with_commands(mut self, commands: Vec<gix_protocol::push::Command>) -> Self {
        self.force_allowed = vec![false; commands.len()];
        self.commands = commands;
        self
    }

    /// Replace the list of ref-update commands with a parallel list of
    /// force flags. `true` in `force_allowed[i]` permits a
    /// non-fast-forward update for `commands[i]`, matching a `+`
    /// prefix on a refspec.
    ///
    /// Panics if the two slices have different lengths.
    pub fn with_commands_forced(
        mut self,
        commands: Vec<gix_protocol::push::Command>,
        force_allowed: Vec<bool>,
    ) -> Self {
        assert_eq!(
            commands.len(),
            force_allowed.len(),
            "commands and force_allowed must have matching length",
        );
        self.commands = commands;
        self.force_allowed = force_allowed;
        self
    }

    /// Append a single ref-update command, non-force.
    pub fn push_command(mut self, command: gix_protocol::push::Command) -> Self {
        self.commands.push(command);
        self.force_allowed.push(false);
        self
    }

    /// Append a single ref-update command, explicitly allowing a
    /// non-fast-forward update (equivalent to a `+src:dst` refspec).
    pub fn push_forced_command(mut self, command: gix_protocol::push::Command) -> Self {
        self.commands.push(command);
        self.force_allowed.push(true);
        self
    }

    /// Bypass the fast-forward check for every command in this push,
    /// matching `git push --force`. Individual `+`-prefixed refspecs
    /// remain honoured regardless of this flag; setting it to `true`
    /// only widens what is allowed.
    pub fn with_force(mut self, enabled: bool) -> Self {
        self.force_all = enabled;
        self
    }

    /// Request all-or-nothing application by advertising the `atomic`
    /// capability. Ignored (silently succeeds as a no-op) if the server did
    /// not advertise it; see [`Prepare::handshake`] and
    /// [`gix_protocol::push::Arguments::can_use_atomic`] to check
    /// availability ahead of time.
    pub fn with_atomic(mut self, enabled: bool) -> Self {
        self.use_atomic = enabled;
        self
    }

    /// Ask the server to suppress its progress output via the `quiet`
    /// capability.
    pub fn with_quiet(mut self, enabled: bool) -> Self {
        self.use_quiet = enabled;
        self
    }

    /// Attach push-options to the request. The options are sent after the
    /// command-list (and pack, if any) per the pack-protocol spec. Requires
    /// the server to advertise `push-options`.
    pub fn with_push_options(mut self, options: Vec<crate::bstr::BString>) -> Self {
        self.push_options = Some(options);
        self
    }

    /// When set, [`Prepare::send`] returns a synthetic [`Outcome`] without
    /// contacting the remote.
    pub fn with_dry_run(mut self, enabled: bool) -> Self {
        self.dry_run = enabled;
        self
    }

    /// Resolve each `refspecs` entry against this repository's refs and the
    /// remote tips advertised during the handshake, appending one
    /// [`Command`](gix_protocol::push::Command) per refspec.
    ///
    /// Supported shapes (literal refspecs only; globs are out of scope):
    ///
    /// - `<src>:<dst>` - update `dst` on the remote to whatever `src`
    ///   peels to locally.
    /// - `<src>` - shorthand for `<src>:<src>`.
    /// - `+<src>:<dst>` - force-push: allow a non-fast-forward update
    ///   for this single refspec. The `+` is a client-side policy; the
    ///   receive-pack wire format has no force bit, so the server
    ///   cannot tell a forced command from a regular one. The server
    ///   instead applies its own `receive.denyNonFastForwards` policy
    ///   to every command. To override the client-side check for every
    ///   command at once (`git push --force`), use
    ///   [`Self::with_force`].
    /// - `:<dst>` - delete `dst` on the remote.
    ///
    /// Each entry that would resolve to a no-op (e.g. local tip equals
    /// the remote tip) still produces a command; the server reports
    /// `ok` for same-value updates.
    ///
    /// `old_id` is populated from [`gix_protocol::Handshake::refs`] when
    /// the remote advertised `dst`, otherwise it is the null OID
    /// (creating a new ref). `new_id` comes from peeling the local
    /// `src` ref or - for deletions - is the null OID.
    ///
    /// Use [`with_commands`](Self::with_commands) directly when
    /// callers already resolved to [`Command`](gix_protocol::push::Command)
    /// values themselves, or need glob / pattern matching not covered
    /// here.
    #[allow(clippy::result_large_err)]
    pub fn with_refspecs<I, S>(mut self, refspecs: I) -> Result<Self, Error>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<crate::bstr::BStr>,
    {
        let repo = self.con.as_ref().expect("prepared").remote.repo;
        let resolved = resolve_refspecs_to_commands(repo, &self.handshake, refspecs)?;
        for (cmd, force) in resolved {
            self.commands.push(cmd);
            self.force_allowed.push(force);
        }
        Ok(self)
    }

    /// Resolve the push refspecs configured on a [`Remote`](crate::Remote)
    /// via `remote.<name>.push` in git-config, appending the resulting
    /// commands to this prepared push.
    ///
    /// Equivalent to calling [`Self::with_refspecs`] with the string
    /// form of each refspec returned by
    /// [`Remote::refspecs(Direction::Push)`](crate::Remote::refspecs).
    /// Returns `Error::NoCommands` at [`Prepare::send`] time if the
    /// remote has no push refspecs configured; inspect
    /// [`Self::commands`](Prepare::commands) after this call if the
    /// caller needs to know up-front.
    #[allow(clippy::result_large_err)]
    pub fn with_remote_push_specs(self, remote: &crate::Remote<'_>) -> Result<Self, Error> {
        let specs = remote
            .refspecs(crate::remote::Direction::Push)
            .iter()
            .map(|s| s.to_ref().to_bstring())
            .collect::<Vec<_>>();
        self.with_refspecs(specs.iter().map(AsRef::<crate::bstr::BStr>::as_ref))
    }

    /// Read-only view of the ref-update commands collected so far.
    pub fn commands(&self) -> &[gix_protocol::push::Command] {
        &self.commands
    }
}

/// Pure helper that turns a list of literal push refspecs into
/// [`Command`](gix_protocol::push::Command) entries paired with a
/// `force` flag (`true` when the refspec was prefixed with `+`). Uses
/// the handshake's advertised refs to fill `old_id` and the repo's ref
/// store to fill `new_id`. Factored out of [`Prepare::with_refspecs`]
/// so the logic can be unit-tested without standing up a real
/// `Connection<T>`.
#[cfg(any(feature = "blocking-network-client", feature = "async-network-client"))]
#[allow(clippy::result_large_err)]
#[doc(alias = "refspec")]
pub fn resolve_refspecs_to_commands<I, S>(
    repo: &crate::Repository,
    handshake: &gix_protocol::Handshake,
    refspecs: I,
) -> Result<Vec<(gix_protocol::push::Command, bool)>, Error>
where
    I: IntoIterator<Item = S>,
    S: AsRef<crate::bstr::BStr>,
{
    use crate::bstr::{BString, ByteSlice};

    let object_hash = repo.object_hash();
    let mut out = Vec::new();
    for spec in refspecs {
        let spec_bstr = spec.as_ref();
        let parsed =
            gix_refspec::parse(spec_bstr, gix_refspec::parse::Operation::Push).map_err(|err| Error::RefspecParse {
                spec: spec_bstr.to_owned(),
                err,
            })?;
        // Negative refspecs (`^<ref>`) name refs to EXCLUDE from the
        // push, typically paired with a wildcard that would otherwise
        // include them. The parser strips the `^` and surfaces the
        // shape as `Instruction::Push(Push::Exclude)`; we reject with
        // a typed error rather than silently re-interpreting the name
        // as a positive push (which would quietly push the ref the
        // user asked to exclude).
        if matches!(
            parsed.instruction(),
            gix_refspec::Instruction::Push(gix_refspec::instruction::Push::Exclude { .. })
        ) {
            return Err(Error::RefspecNegativeUnsupported {
                spec: spec_bstr.to_owned(),
            });
        }
        let force = gix_refspec::RefSpec::from(parsed).allow_non_fast_forward();
        let src = parsed.source();
        let dst = parsed.destination();
        let src_has_glob = src.is_some_and(|s| s.contains(&b'*'));
        let dst_has_glob = dst.is_some_and(|d| d.contains(&b'*'));
        if src_has_glob != dst_has_glob {
            // Git requires symmetric wildcards on both sides.
            return Err(Error::RefspecWildcardUnsupported {
                spec: spec_bstr.to_owned(),
            });
        }
        if src_has_glob && dst_has_glob {
            let src_pat = src.expect("src must exist for a wildcard spec");
            let dst_pat = dst.expect("dst must exist for a wildcard spec");
            expand_wildcard_refspec(repo, handshake, spec_bstr, src_pat, dst_pat, object_hash, force, &mut out)?;
            continue;
        }
        if src.is_none() {
            let dst_name = dst.ok_or_else(|| Error::RefspecNoDestination {
                spec: spec_bstr.to_owned(),
            })?;
            let old_id = remote_ref_oid(handshake, dst_name).unwrap_or_else(|| gix_hash::ObjectId::null(object_hash));
            out.push((
                gix_protocol::push::Command {
                    old_id,
                    new_id: gix_hash::ObjectId::null(object_hash),
                    refname: dst_name.to_owned(),
                },
                force,
            ));
            continue;
        }
        let src_name = src.expect("non-deletion always has a source");
        let partial: &gix_ref::PartialNameRef =
            src_name
                .try_into()
                .map_err(|err: gix_ref::name::Error| Error::RefspecSourceNotFound {
                    spec: spec_bstr.to_owned(),
                    src: src_name.to_owned(),
                    err: Box::new(err) as Box<dyn std::error::Error + Send + Sync + 'static>,
                })?;
        let mut reference = repo
            .try_find_reference(partial)
            .map_err(|err| Error::RefspecSourceNotFound {
                spec: spec_bstr.to_owned(),
                src: src_name.to_owned(),
                err: Box::new(err) as Box<dyn std::error::Error + Send + Sync + 'static>,
            })?
            .ok_or_else(|| Error::RefspecSourceNotFound {
                spec: spec_bstr.to_owned(),
                src: src_name.to_owned(),
                err: "ref not found in local store".into(),
            })?;
        let new_id = reference
            .peel_to_id()
            .map_err(|err| Error::RefspecSourceNotFound {
                spec: spec_bstr.to_owned(),
                src: src_name.to_owned(),
                err: Box::new(err) as Box<dyn std::error::Error + Send + Sync + 'static>,
            })?
            .detach();
        let dst_name: BString = match dst {
            Some(d) => d.to_owned(),
            None => src_name.to_owned(),
        };
        let old_id =
            remote_ref_oid(handshake, dst_name.as_bstr()).unwrap_or_else(|| gix_hash::ObjectId::null(object_hash));
        out.push((
            gix_protocol::push::Command {
                old_id,
                new_id,
                refname: dst_name,
            },
            force,
        ));
    }
    Ok(out)
}

#[cfg(any(feature = "blocking-network-client", feature = "async-network-client"))]
#[allow(clippy::too_many_arguments)]
fn expand_wildcard_refspec(
    repo: &crate::Repository,
    handshake: &gix_protocol::Handshake,
    spec_bstr: &crate::bstr::BStr,
    src_pat: &crate::bstr::BStr,
    dst_pat: &crate::bstr::BStr,
    object_hash: gix_hash::Kind,
    force: bool,
    out: &mut Vec<(gix_protocol::push::Command, bool)>,
) -> Result<(), Error> {
    use crate::bstr::{BString, ByteSlice};

    let src_star = src_pat.iter().filter(|b| **b == b'*').count();
    let dst_star = dst_pat.iter().filter(|b| **b == b'*').count();
    if src_star != 1 || dst_star != 1 {
        return Err(Error::RefspecWildcardUnsupported {
            spec: spec_bstr.to_owned(),
        });
    }
    let src_star_pos = src_pat
        .iter()
        .position(|b| *b == b'*')
        .expect("exactly one star was verified above");
    let src_prefix = &src_pat[..src_star_pos];
    let src_suffix = &src_pat[src_star_pos + 1..];
    let dst_star_pos = dst_pat
        .iter()
        .position(|b| *b == b'*')
        .expect("exactly one star was verified above");
    let dst_prefix = &dst_pat[..dst_star_pos];
    let dst_suffix = &dst_pat[dst_star_pos + 1..];

    // gix ref iteration wants a valid prefix path. The prefix must
    // contain at least "refs/" for most repositories; non-refs patterns
    // (e.g. "HEAD") are rejected here because push wildcards in the
    // wild are always anchored under refs/.
    if !src_prefix.starts_with(b"refs/") {
        return Err(Error::RefspecWildcardUnsupported {
            spec: spec_bstr.to_owned(),
        });
    }
    let prefix_str = std::str::from_utf8(src_prefix).map_err(|_| Error::RefspecWildcardUnsupported {
        spec: spec_bstr.to_owned(),
    })?;
    let platform = repo.references().map_err(|err| Error::RefspecSourceNotFound {
        spec: spec_bstr.to_owned(),
        src: src_pat.to_owned(),
        err: Box::new(err) as Box<dyn std::error::Error + Send + Sync + 'static>,
    })?;
    let iter = platform
        .prefixed(prefix_str)
        .map_err(|err| Error::RefspecSourceNotFound {
            spec: spec_bstr.to_owned(),
            src: src_pat.to_owned(),
            err: Box::new(err) as Box<dyn std::error::Error + Send + Sync + 'static>,
        })?;
    for reference in iter {
        let mut reference = reference.map_err(|err| Error::RefspecSourceNotFound {
            spec: spec_bstr.to_owned(),
            src: src_pat.to_owned(),
            err,
        })?;
        let full_name = reference.name().as_bstr().to_owned();
        if !full_name.ends_with(src_suffix) {
            continue;
        }
        // Extract the portion of the ref name captured by the `*`.
        let capture_start = src_prefix.len();
        let capture_end = full_name.len() - src_suffix.len();
        if capture_end < capture_start {
            continue;
        }
        let captured = &full_name[capture_start..capture_end];
        // Build the destination ref name by substituting `captured`
        // into `dst_pat` at the star position.
        let mut dst_name = BString::from(dst_prefix);
        dst_name.extend_from_slice(captured);
        dst_name.extend_from_slice(dst_suffix);
        // Peel local ref to a commit oid.
        let new_id = reference
            .peel_to_id()
            .map_err(|err| Error::RefspecSourceNotFound {
                spec: spec_bstr.to_owned(),
                src: full_name.clone(),
                err: Box::new(err) as Box<dyn std::error::Error + Send + Sync + 'static>,
            })?
            .detach();
        let old_id =
            remote_ref_oid(handshake, dst_name.as_bstr()).unwrap_or_else(|| gix_hash::ObjectId::null(object_hash));
        out.push((
            gix_protocol::push::Command {
                old_id,
                new_id,
                refname: dst_name,
            },
            force,
        ));
    }
    Ok(())
}

#[cfg(any(feature = "blocking-network-client", feature = "async-network-client"))]
/// Derive the default push target for `HEAD` when no explicit refspec
/// and no `remote.<name>.push` config is available.
///
/// This is the `push.default` fallback layer that shipped implementations
/// of `Remote::push` reach for after `with_remote_push_specs(..)` returns
/// an empty command list. It encodes, in this order:
///
/// 1. Whatever [`Repository::branch_remote_ref_name(.., Direction::Push)`]
///    returns, which already covers `push.default = { nothing | current |
///    matching | upstream | simple }` and the tracking-ref lookup their
///    semantics require.
/// 2. `push.autoSetupRemote` (git 2.37+): when set to `true` and `HEAD`
///    has no upstream, the default push is treated as if `-u` had been
///    passed on the command line, so `HEAD`'s short name is pushed to a
///    same-named ref on the remote.
///
/// Returns the full-form target refname (e.g. `refs/heads/main`) when
/// one is available, or `None` when neither layer produces a target —
/// which happens for detached `HEAD`, `push.default = nothing`, or
/// `simple` with a renamed upstream and no `autoSetupRemote`.
///
/// Exposed as a public helper so downstream CLIs and custom push
/// drivers can reuse the same fallback without duplicating the logic.
#[cfg(any(feature = "blocking-network-client", feature = "async-network-client"))]
pub fn push_default_target(repo: &crate::Repository) -> Option<crate::bstr::BString> {
    let head_name = repo.head_name().ok().flatten()?;
    if let Some(target) = repo
        .branch_remote_ref_name(head_name.as_ref(), crate::remote::Direction::Push)
        .and_then(Result::ok)
        .map(std::borrow::Cow::into_owned)
    {
        return Some(target.as_bstr().to_owned());
    }
    let auto_setup = repo
        .config_snapshot()
        .boolean("push.autoSetupRemote")
        .unwrap_or(false);
    if !auto_setup {
        return None;
    }
    Some(head_name.as_bstr().to_owned())
}

/// Verify that every non-forced, non-create, non-delete command is a
/// fast-forward by walking from `new_id` and requiring `old_id` to be
/// reachable. A walk error (typically a missing commit in the local
/// odb) is treated as non-fast-forward: the client cannot prove the
/// relationship, so the remote update is refused.
///
/// `force_all = true` or a `true` entry in `force_allowed` at the
/// matching index bypasses the check for that command.
#[cfg(feature = "blocking-network-client")]
#[allow(clippy::result_large_err)]
fn check_fast_forward(
    repo: &crate::Repository,
    commands: &[gix_protocol::push::Command],
    force_allowed: &[bool],
    force_all: bool,
) -> Result<(), Error> {
    if force_all {
        return Ok(());
    }
    debug_assert_eq!(commands.len(), force_allowed.len());
    for (cmd, forced) in commands.iter().zip(force_allowed.iter().copied()) {
        if forced || cmd.is_create() || cmd.is_delete() || cmd.old_id == cmd.new_id {
            continue;
        }
        let walker = gix_traverse::commit::Simple::new(std::iter::once(cmd.new_id), &repo.objects);
        let mut is_ancestor = false;
        for info in walker {
            match info {
                Ok(info) => {
                    if info.id == cmd.old_id {
                        is_ancestor = true;
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        if !is_ancestor {
            return Err(Error::NonFastForward {
                refname: cmd.refname.clone(),
                local: cmd.new_id,
                remote: cmd.old_id,
            });
        }
    }
    Ok(())
}

#[cfg(any(feature = "blocking-network-client", feature = "async-network-client"))]
fn remote_ref_oid(handshake: &gix_protocol::Handshake, dst_name: &crate::bstr::BStr) -> Option<gix_hash::ObjectId> {
    let refs = handshake.refs.as_ref()?;
    refs.iter().find_map(|r| match r {
        gix_protocol::handshake::Ref::Direct { full_ref_name, object } if full_ref_name == dst_name => Some(*object),
        gix_protocol::handshake::Ref::Peeled { full_ref_name, tag, .. } if full_ref_name == dst_name => Some(*tag),
        gix_protocol::handshake::Ref::Symbolic {
            full_ref_name, object, ..
        } if full_ref_name == dst_name => Some(*object),
        _ => None,
    })
}

/// Execution convenience wrapper that generates the pack from the
/// repository's object database automatically.
#[cfg(feature = "blocking-network-client")]
impl<T> Prepare<'_, '_, T>
where
    T: Transport,
{
    /// Run the push, generating the pack from the repository
    /// automatically.
    ///
    /// Equivalent to calling [`Self::send`] with a closure that invokes
    /// [`crate::Repository::write_pack_for_push`]. The wants are drawn
    /// from the prepared commands' `new_id` (non-deletions only). The
    /// haves are seeded from two sources:
    ///
    /// 1. Each command's `old_id` when non-create - what this push is
    ///    explicitly replacing.
    /// 2. Every ref the server advertised during the handshake - the
    ///    remote's full current state is guaranteed present, so using
    ///    these as additional exclusions avoids re-sending objects
    ///    that are reachable from some other branch on the remote.
    ///
    /// Pass `should_interrupt` to allow cooperative cancellation while
    /// walking the object graph.
    #[allow(clippy::result_large_err)]
    pub fn send_with_generated_pack<P>(
        self,
        mut progress: P,
        should_interrupt: &std::sync::atomic::AtomicBool,
    ) -> Result<Outcome, Error>
    where
        P: gix_features::progress::NestedProgress,
        P::SubProgress: 'static,
    {
        // One progress per meaningful phase, carved out up front so
        // they can move into the FnOnce closure passed to `send`.
        // `count_progress` covers the "how many objects ship?" walk
        // (user-visible "counting objects for push" bar). The delta-
        // resolution / byte-emission phase that `iter_from_counts`
        // drives in parallel gets a silent `Discard` — a visible
        // NestedProgress there would sprout one sub-bar per worker
        // thread, which on a 16-core machine pushes the rendered
        // progress tree off the bottom of the terminal and produces
        // a messy "fighting" display with the post-push `remote:`
        // output. The counting bar already tells the user the push
        // is making forward progress; the aggregate throughput isn't
        // worth the visual cost of per-thread bars. (Re-enabling the
        // nested progress is trivial should we later ship a tidier
        // renderer; see `gitoxide-core::pack::create` for the shape.)
        let count_progress = progress.add_child("counting objects for push");
        let entry_progress: Box<dyn gix_features::progress::DynNestedProgress + 'static> =
            Box::new(gix_features::progress::Discard);
        // Snapshot the wants / haves upfront; `Prepare::send` takes
        // ownership of `self`, and the closure must be `FnOnce` from
        // the outside but still closes over these vectors.
        let wants: Vec<gix_hash::ObjectId> = self
            .commands
            .iter()
            .filter(|c| !c.is_delete())
            .map(|c| c.new_id)
            .collect();
        // Haves start from the commands' old ids (what this push is
        // explicitly replacing). Then we widen them with every ref the
        // remote advertised during the handshake: any tip visible on
        // the server is guaranteed to be present, and excluding
        // commits reachable from those tips keeps creates from
        // re-sending objects the remote already has via some other
        // branch.
        let mut haves: Vec<gix_hash::ObjectId> = self
            .commands
            .iter()
            .filter(|c| !c.is_create())
            .map(|c| c.old_id)
            .collect();
        if let Some(refs) = self.handshake.refs.as_ref() {
            for r in refs {
                match r {
                    gix_protocol::handshake::Ref::Direct { object, .. } => haves.push(*object),
                    gix_protocol::handshake::Ref::Peeled { tag, .. } => haves.push(*tag),
                    gix_protocol::handshake::Ref::Symbolic { object, .. } => haves.push(*object),
                    gix_protocol::handshake::Ref::Unborn { .. } => {}
                }
            }
        }
        // `iter_from_counts` requires `Send + Clone + 'static` for its
        // `Find` type. The repo's odb handle is `Rc<Store>`-backed
        // without the `parallel` feature (and therefore `!Send`), so
        // convert to the `Arc<Store>` variant up front — cheap
        // passthrough when already `Arc`, a clean remap when `Rc`. This
        // materialises the fix the non-parallel build actively needs:
        // without it, `gix` refuses to compile on
        // `--features blocking-network-client` alone.
        let repo_objects_arc = (*self.con.as_ref().expect("prepared").remote.repo.objects)
            .clone()
            .into_arc()
            .map_err(|err| Error::Transport(gix_transport::client::Error::Io(err)))?;
        let object_hash = self.con.as_ref().expect("prepared").remote.repo.object_hash();
        self.send(move |writer| -> std::io::Result<()> {
            if wants.is_empty() {
                return Ok(());
            }
            let mut db = repo_objects_arc;
            db.prevent_pack_unload();
            // Drop haves whose target commit isn't in the local object
            // database. The handshake advertises every ref on the
            // server, many of which point at commits the client has
            // never fetched (other people's branches, tags on unseen
            // history); passing those to `hide(..)` below makes the
            // traversal fail with "object not found". Filtering here is
            // safe because a missing-from-client have can't possibly
            // gate which wants need packing — we'd just fail to exclude
            // objects reachable from it, at worst making the pack a
            // touch larger than strictly necessary.
            use gix_object::Exists;
            haves.retain(|oid| db.exists(oid));
            // `haves` bounds the commit walk (via `hide(..)` below) so
            // we don't re-send whole history that the server already
            // has, but we intentionally hand `objects_for_push` an
            // empty "already-present" set: a commit walk only yields
            // commit OIDs, so populating the set with haves' commits
            // doesn't help skip the matching trees and blobs anyway.
            // More importantly, if the commit walker silently stops
            // on an error (`.flatten()` drops `Err`s), `already_present`
            // ends up missing commits that `hide(..)` DID manage to
            // exclude — producing a pack whose tip references a parent
            // commit the server also doesn't have, and failing the
            // server-side connectivity check with "did not receive
            // expected object <OID>". Paying a slightly bigger pack
            // for correctness is the right tradeoff until we have a
            // proper tree-walking boundary set.
            let already_present: gix_hashtable::HashSet<gix_hash::ObjectId> = Default::default();
            let wants_walker =
                match gix_traverse::commit::Simple::new(wants.iter().copied(), &db).hide(haves.iter().copied()) {
                    Ok(w) => w,
                    Err(err) => return Err(std::io::Error::other(err)),
                };
            let mut commits_to_pack: Vec<gix_hash::ObjectId> = Vec::new();
            for info in wants_walker {
                match info {
                    Ok(info) => commits_to_pack.push(info.id),
                    Err(err) => return Err(std::io::Error::other(err)),
                }
            }
            if commits_to_pack.is_empty() {
                return Ok(());
            }
            let (counts, _) = gix_pack::data::output::count::objects_for_push(
                &db,
                commits_to_pack,
                already_present,
                &count_progress,
                should_interrupt,
            )
            .map_err(std::io::Error::other)?;
            if counts.is_empty() {
                return Ok(());
            }
            let num_entries = counts.len() as u32;
            let db_for_entries = db.clone();
            let entries = gix_pack::data::output::entry::iter_from_counts(
                counts,
                db_for_entries,
                entry_progress,
                gix_pack::data::output::entry::iter_from_counts::Options::default(),
            );
            // Parallel chunk processing inside `iter_from_counts` yields
            // results as they complete, not in submission order. Delta
            // entries carry back-references to their base by overall
            // count-index; that index is only valid when chunks are
            // emitted in order, so reorder with `InOrderIter` before
            // handing the stream to `FromEntriesIter`.
            let mapped = gix_features::parallel::InOrderIter::from(entries);
            let iter = gix_pack::data::output::bytes::FromEntriesIter::new(
                mapped,
                writer,
                num_entries,
                gix_pack::data::Version::V2,
                object_hash,
            );
            for chunk in iter {
                chunk.map_err(std::io::Error::other)?;
            }
            Ok(())
        })
    }
}

/// Execution.
impl<T> Prepare<'_, '_, T>
where
    T: Transport,
{
    /// Send the prepared push to the remote.
    ///
    /// `write_pack` receives a writer into the transport after the command
    /// list and its terminating flush-pkt (and the optional push-options
    /// trailer) have been emitted; it is responsible for streaming a
    /// complete git pack. A delete-only push may pass a no-op closure -
    /// the spec allows omitting the pack when no command requires it.
    ///
    /// Progress reporting of the push itself is not yet surfaced by this
    /// slice; progress messages the server emits on side-band channel 2 are
    /// returned inside [`Outcome::report`](gix_protocol::push::response::Outcome::progress).
    #[allow(clippy::result_large_err)]
    #[cfg(feature = "blocking-network-client")]
    pub fn send<W>(mut self, write_pack: W) -> Result<Outcome, Error>
    where
        W: FnOnce(&mut (dyn std::io::Write + '_)) -> std::io::Result<()>,
    {
        if self.commands.is_empty() {
            return Err(Error::NoCommands);
        }

        {
            let repo = self.con.as_ref().expect("prepared").remote.repo;
            check_fast_forward(repo, &self.commands, &self.force_allowed, self.force_all)?;
        }

        if self.dry_run {
            return Ok(Outcome {
                handshake: self.handshake,
                report: gix_protocol::push::response::Outcome {
                    report: gix_protocol::push::response::ReportKind::V1(gix_protocol::push::Report {
                        unpack: gix_protocol::push::UnpackStatus::Ok,
                        commands: self
                            .commands
                            .iter()
                            .map(|c| gix_protocol::push::CommandStatus::Ok {
                                refname: c.refname.clone(),
                            })
                            .collect(),
                    }),
                    progress: Vec::new(),
                },
            });
        }

        let mut con = self.con.take().ok_or(Error::AlreadyExecuted)?;

        let mut args = gix_protocol::push::Arguments::new(&self.handshake.capabilities);
        args.set_agent(concat!("gix/", env!("CARGO_PKG_VERSION")));
        // Echo the repo's object-format only when the server advertised
        // it, matching git-send-pack's behaviour; servers pre-2.28
        // neither send nor expect the token, so unconditional emission
        // would regress compatibility.
        if self
            .handshake
            .capabilities
            .iter()
            .any(|c| c.name() == "object-format".as_bytes())
        {
            let hash = con.remote.repo.object_hash();
            args.set_object_format(&hash.to_string());
        }
        if self.use_atomic && args.can_use_atomic() {
            args.use_atomic().map_err(Error::Argument)?;
        }
        if self.use_quiet && args.can_use_quiet() {
            args.use_quiet().map_err(Error::Argument)?;
        }
        if let Some(options) = self.push_options.take() {
            args.use_push_options(options).map_err(Error::Argument)?;
        }
        for command in std::mem::take(&mut self.commands) {
            args.add_command(command).map_err(Error::Argument)?;
        }

        let uses_side_band = args.can_use_side_band();
        let expects_v2 = args.expects_report_status_v2();

        let mut reader = args
            .send(&mut con.transport.inner, write_pack, con.trace)
            .map_err(Error::Send)?;

        let side_band = if uses_side_band {
            gix_protocol::push::response::SideBandMode::Enabled
        } else {
            gix_protocol::push::response::SideBandMode::Disabled
        };

        let report = gix_protocol::push::response::blocking_io::from_reader(&mut *reader, expects_v2, side_band)
            .map_err(Error::Response)?;

        Ok(Outcome {
            handshake: self.handshake,
            report,
        })
    }
}

/// One local-branch -> remote-ref tracking pair to (re)write into local config.
///
/// `local_branch` must be a short branch name (without `refs/heads/`),
/// and `remote_ref` the full-form ref on the remote (typically
/// `refs/heads/<name>`). Sources outside `refs/heads/` must be filtered
/// by the caller before reaching [`record_tracking`].
#[derive(Debug, Clone)]
pub struct TrackingUpdate {
    /// Short local branch name, e.g. `main`.
    pub local_branch: crate::bstr::BString,
    /// Full remote ref path, e.g. `refs/heads/main`.
    pub remote_ref: crate::bstr::BString,
}

/// Outcome of a single tracking-config write performed by [`record_tracking`].
#[derive(Debug, Clone)]
pub struct TrackingWritten {
    /// Short local branch name that was configured.
    pub local_branch: crate::bstr::BString,
    /// Short remote name set on `branch.<name>.remote`.
    pub remote_name: crate::bstr::BString,
    /// Full remote ref set on `branch.<name>.merge`.
    pub remote_ref: crate::bstr::BString,
}

impl TrackingWritten {
    /// Render the git 2.x-compatible notice shown after a successful
    /// `git push -u`, e.g. `branch 'main' set up to track 'origin/main'.`
    pub fn to_notice(&self) -> String {
        use crate::bstr::ByteSlice;
        let remote_short = self.remote_ref.strip_prefix(b"refs/heads/").unwrap_or(&self.remote_ref);
        format!(
            "branch '{}' set up to track '{}/{}'.",
            self.local_branch.as_bstr(),
            self.remote_name.as_bstr(),
            remote_short.as_bstr(),
        )
    }
}

/// Persist `branch.<local>.{remote,merge}` for every entry in `updates`,
/// mirroring what `git push --set-upstream` / `push.autoSetupRemote`
/// emit after a successful push.
///
/// Returns one [`TrackingWritten`] per entry whose config was actually
/// written; callers typically render [`TrackingWritten::to_notice`] to
/// match `git`'s `branch '...' set up to track '...'.` output.
///
/// The local config file is rewritten in place via
/// [`crate::config::SnapshotMut::commit`], so changes are visible to
/// subsequent loads of the same repository.
/// Error returned by [`record_tracking`].
#[cfg(any(feature = "blocking-network-client", feature = "async-network-client"))]
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum TrackingError {
    #[error("section header `branch.<name>` is invalid for `{0}`")]
    SectionHeader(crate::bstr::BString),
    #[error(transparent)]
    Commit(#[from] crate::config::Error),
    #[error("the repository has no local config path to write `branch.<name>.{{remote,merge}}` into")]
    NoLocalConfigPath,
    #[error("could not persist the local config file")]
    Io(#[source] std::io::Error),
}

/// Persist `branch.<local>.{remote,merge}` for every entry in `updates`,
/// matching git 2.x `--set-upstream` / `push.autoSetupRemote` behaviour.
///
/// Returns one [`TrackingWritten`] per entry whose config was written.
#[cfg(any(feature = "blocking-network-client", feature = "async-network-client"))]
pub fn record_tracking(
    repo: &mut crate::Repository,
    remote_name: &crate::bstr::BStr,
    updates: &[TrackingUpdate],
) -> Result<Vec<TrackingWritten>, TrackingError> {
    use std::borrow::Cow;
    if updates.is_empty() {
        return Ok(Vec::new());
    }
    let mut written = Vec::with_capacity(updates.len());
    let mut snapshot = repo.config_snapshot_mut();
    for update in updates {
        let local_str = match std::str::from_utf8(&update.local_branch) {
            Ok(s) if !s.is_empty() => s,
            _ => continue,
        };
        let mut section = snapshot
            .new_section("branch", Some(Cow::Owned(local_str.into())))
            .map_err(|_| TrackingError::SectionHeader(update.local_branch.clone()))?;
        section.push(
            "remote".try_into().expect("`remote` is a valid config key"),
            Some(remote_name),
        );
        section.push(
            "merge".try_into().expect("`merge` is a valid config key"),
            Some(update.remote_ref.as_ref()),
        );
        written.push(TrackingWritten {
            local_branch: update.local_branch.clone(),
            remote_name: remote_name.to_owned(),
            remote_ref: update.remote_ref.clone(),
        });
    }
    // `SnapshotMut::commit` only refreshes the in-memory view, so
    // rewrite the on-disk local config (Local-source sections only)
    // before committing. Mirrors `clone::fetch::util::setup_branch_config`.
    persist_local_config(&snapshot)?;
    snapshot.commit()?;
    Ok(written)
}

#[cfg(any(feature = "blocking-network-client", feature = "async-network-client"))]
fn persist_local_config(snapshot: &gix_config::File<'static>) -> Result<(), TrackingError> {
    use std::io::Write;
    let path = snapshot
        .meta()
        .path
        .as_deref()
        .ok_or(TrackingError::NoLocalConfigPath)?;
    let mut file = std::fs::OpenOptions::new()
        .create(false)
        .write(true)
        .truncate(true)
        .open(path)
        .map_err(TrackingError::Io)?;
    file.write_all(snapshot.detect_newline_style())
        .map_err(TrackingError::Io)?;
    snapshot
        .write_to_filter(&mut file, |section_meta| {
            section_meta.meta().source == gix_config::Source::Local
        })
        .map_err(TrackingError::Io)?;
    Ok(())
}
