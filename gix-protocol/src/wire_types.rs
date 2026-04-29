//! Neutral home for v2 fetch-response wire-payload types.
//!
//! The types here model the protocol-v2 `fetch` response grammar as
//! published in
//! [`gitprotocol-v2`](https://git-scm.com/docs/protocol-v2):
//!
//! ```text
//! output = acknowledgements flush-pkt |
//!          [acknowledgments delim-pkt]
//!          [shallow-info delim-pkt]
//!          [wanted-refs delim-pkt]
//!          [packfile-uris delim-pkt]
//!          packfile flush-pkt
//! ```
//!
//! Each section in the grammar has a Rust counterpart here:
//!
//! - `acknowledgments = header (nak | *ack) (ready)`
//!   -> [`Acknowledgments`] struct + [`AckTrailer`] enum.
//! - `shallow-info = header *(shallow | unshallow)`
//!   -> [`ShallowUpdate`] (re-exported from `gix-shallow`).
//! - `wanted-refs = header *wanted-ref`
//!   -> [`WantedRef`] (re-exported from [`crate::fetch::response`]).
//! - `packfile-uris = header *packfile-uri`
//!   -> [`PackfileUri`].
//!
//! The module is direction-neutral: both the client (parser) and the
//! server (emitter) consume these types so the same concept is
//! represented once in the crate (SSOT).

pub use crate::fetch::response::WantedRef;
pub use gix_shallow::Update as ShallowUpdate;

/// Body of the `acknowledgments` section in a v2 fetch response.
///
/// Grammar:
///
/// ```text
/// acknowledgments = PKT-LINE("acknowledgments" LF)
///                   (nak | *ack)
///                   (ready)
/// ```
///
/// - `(nak | *ack)` is modelled as [`Self::common_oids`]: an empty
///   vector emits a single `NAK` line on the wire; a non-empty
///   vector emits one `ACK <oid>` line per entry.
/// - `(ready)` is modelled as [`Self::trailer`], an open-ended slot
///   matching the grammar's parenthesised trailer group for future
///   spec extensions.
#[non_exhaustive]
#[derive(Debug, Clone, Default)]
pub struct Acknowledgments {
    /// Common object-ids the server acknowledges sharing with the
    /// client. Each entry emits one `ACK <oid>` line. When empty,
    /// the server emits a single `NAK` line instead.
    pub common_oids: Vec<gix_hash::ObjectId>,
    /// Optional trailer token appended after the body lines.
    ///
    /// Today the v2 spec defines only `ready`; `#[non_exhaustive]`
    /// on [`AckTrailer`] leaves room for future spec extensions to
    /// land as additional variants without API churn here.
    pub trailer: Option<AckTrailer>,
}

impl Acknowledgments {
    /// Construct an acknowledgments section body.
    pub fn new(common_oids: Vec<gix_hash::ObjectId>, trailer: Option<AckTrailer>) -> Self {
        Self { common_oids, trailer }
    }
}

/// Trailer slot for the `(ready)` group of the `acknowledgments`
/// section. Open-ended so future spec-defined trailers can land as
/// additional variants.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckTrailer {
    /// Emit the literal `ready` pkt-line; signals "pack follows".
    Ready,
}

impl AckTrailer {
    /// True when this trailer signals a `packfile` section follows.
    pub fn signals_pack_incoming(&self) -> bool {
        match self {
            AckTrailer::Ready => true,
        }
    }
}

/// One entry of the `packfile-uris` section: a pack hash plus the
/// URI the client should fetch out-of-band. Requires the client to
/// have advertised the `packfile-uris` capability.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct PackfileUri {
    /// Hash of the pack at `uri`.
    pub hash: gix_hash::ObjectId,
    /// URI the client fetches out-of-band.
    pub uri: String,
}

impl PackfileUri {
    /// Construct a `packfile-uris` entry.
    pub fn new(hash: gix_hash::ObjectId, uri: String) -> Self {
        Self { hash, uri }
    }
}
