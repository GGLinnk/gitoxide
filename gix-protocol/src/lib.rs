//! An abstraction over [fetching][fetch()] a pack from the server.
//!
//! Generally, there is the following order of operations.
//!
//! * create a `Transport`, either blocking or async
//! * perform a [`handshake()`]
//! * execute a [`Command`]
//!     - [list references](LsRefsCommand)
//!          - create a mapping between [refspecs and references](fetch::RefMap)
//!     - [receive a pack](fetch())
//!
//! ## Feature Flags
#![cfg_attr(
    all(doc, feature = "document-features"),
    doc = ::document_features::document_features!()
)]
#![cfg_attr(all(doc, feature = "document-features"), feature(doc_cfg))]
#![deny(missing_docs, rust_2018_idioms, unsafe_code)]

/// A function that performs a given credential action, trying to obtain credentials for an operation that needs it.
///
/// Useful for both `fetch` and `push`.
#[cfg(feature = "handshake")]
pub type AuthenticateFn<'a> = Box<dyn FnMut(gix_credentials::helper::Action) -> gix_credentials::protocol::Result + 'a>;

/// A selector for V2 commands to invoke on the server for purpose of pre-invocation validation.
#[derive(PartialEq, Eq, Debug, Hash, Ord, PartialOrd, Clone, Copy)]
pub enum Command {
    /// List references.
    LsRefs,
    /// Fetch a pack.
    Fetch,
}
pub mod command;

#[cfg(feature = "async-client")]
pub use async_trait;
#[cfg(feature = "async-client")]
pub use futures_io;
#[cfg(feature = "async-client")]
pub use futures_lite;
#[cfg(feature = "handshake")]
pub use gix_credentials as credentials;
/// A convenience export allowing users of gix-protocol to use the transport layer without their own cargo dependency.
pub use gix_transport as transport;
pub use maybe_async;

///
pub mod fetch;
#[cfg(any(feature = "blocking-client", feature = "async-client"))]
pub use fetch::function::fetch;

/// Neutral home for v2 fetch-response wire-payload types shared by
/// the client-side parser ([`fetch::response`]) and the server-side
/// emitter ([`upload_pack`]).
pub mod wire_types;

mod remote_progress;
pub use remote_progress::RemoteProgress;

/// Shared sideband pkt-line framing used by both the `upload-pack`
/// (pack bytes) and `receive-pack` (`report-status`) server surfaces.
///
/// Crate-private: the type surface is an implementation detail of the
/// two server state machines. Both `upload-pack-server` and
/// `receive-pack-server` pull in `gix-packetline` with the
/// `blocking-io` feature, so this module is available whenever either
/// server feature is on.
#[cfg(any(feature = "upload-pack-server", feature = "receive-pack-server"))]
mod sideband;

#[cfg(all(feature = "blocking-client", feature = "async-client"))]
compile_error!("Cannot set both 'blocking-client' and 'async-client' features as they are mutually exclusive");

///
pub mod handshake;
#[cfg(any(feature = "blocking-client", feature = "async-client"))]
#[cfg(feature = "handshake")]
pub use handshake::function::handshake;
#[cfg(feature = "handshake")]
pub use handshake::hero::Handshake;

///
pub mod ls_refs;
#[cfg(any(feature = "blocking-client", feature = "async-client"))]
pub use ls_refs::function::LsRefsCommand;

/// Client side of `git push`: ref-update `Command` serialisation,
/// `Arguments` capability negotiation, blocking + async `send` that
/// streams the framed update-request plus pack, `report-status` /
/// `report-status-v2` parsing, and side-band response demux with
/// typed `Outcome` inspection helpers.
///
/// Gated behind the `push` feature. Transport I/O (`send` /
/// `send_async` / response consumer) is additionally gated behind
/// `blocking-client` / `async-client`; the pure-data types work
/// without either.
#[cfg(feature = "push")]
pub mod push;

/// Server-side primitives for `git-upload-pack` — the service that
/// answers `git fetch` / `git clone` requests. Parses v2
/// `command=fetch` / `command=ls-refs` requests and the v0/v1
/// `want`/`have`/`done` stream, emits advertisements, `ack` /
/// `packfile` sections, and drives a `serve_v2` / `serve_v1` dispatch
/// on caller-supplied object storage and pack writing closures.
///
/// Gated behind the `upload-pack-server` feature.
#[cfg(feature = "upload-pack-server")]
pub mod upload_pack;

/// Server-side primitives for `git-receive-pack` — the service that
/// accepts `git push`. Advertises current refs + push capabilities,
/// parses the framed update-request (old/new-oid + refname + inline
/// caps, optional `shallow <oid>` and `push-cert` blocks), dispatches
/// each update through caller-supplied hooks with atomic all-or-nothing
/// semantics, and serialises `report-status` / `report-status-v2`.
///
/// Gated behind the `receive-pack-server` feature.
#[cfg(feature = "receive-pack-server")]
pub mod receive_pack;

mod util;
pub use util::*;
