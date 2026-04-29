//! Server-side implementation of `git-upload-pack`, the service that
//! answers `git fetch` / `git clone` requests.
//!
//! This module is the server counterpart to [`crate::fetch`]. It reads
//! the client's `want` / `have` / `done` negotiation stream and emits
//! `ACK` / `NAK` responses plus the resulting pack.
//!
//! ## Module layout
//!
//! - [`advertisement`] - emit the ref / capability advertisement that
//!   prefaces every smart-HTTP `info/refs` response.
//! - [`options`] - [`Options`] / [`options::OptionsV2`] value types
//!   describing which server capabilities to advertise.
//! - [`fetch_request`] - parse a v2 `command=fetch` request.
//! - [`fetch_request_v1`] - parse a v0/v1 upload-request.
//! - [`ls_refs_request`] / [`ls_refs_response`] - v2 `ls-refs`.
//! - [`ack`] - acknowledgement and `packfile` section emitters.
//! - [`serve`] - v2 state machine: `serve_v2` + `dispatch_v2` route
//!   `ls-refs` and `fetch` requests.
//! - [`serve_v1`] - v0/v1 stateless-RPC state machine for legacy
//!   smart-HTTP clients.
//! - [`serve_info_refs`] - pkt-line framing for the `info/refs` banner.
//!
//! ## Scope
//!
//! The server is expected to be embedded into a transport-agnostic
//! host: an HTTP smart-protocol endpoint, a `git://` daemon, or an
//! in-process "serve" call mirroring `gix::Repository::serve_pack_upload_v2_auto`
//! / `serve_pack_upload_v1_auto`. Object storage and pack generation
//! are accessed through caller-supplied closures so this crate stays
//! decoupled from `gix-odb` / `gix-pack`'s concrete types.

pub mod ack;
pub mod advertisement;
pub mod fetch_request;
pub mod fetch_request_v1;
pub mod ls_refs_request;
pub mod ls_refs_response;
pub mod options;
pub mod sections;
pub mod serve;
pub mod serve_info_refs;
pub mod serve_v1;

pub use fetch_request::{FetchRequest, Want};
pub use fetch_request_v1::FetchRequestV1;
pub use ls_refs_request::LsRefsRequest;
pub use ls_refs_response::RefEntry as LsRefsRefEntry;
pub use options::{Options, OptionsV2};
pub use serve::{serve_v2, ServeError as ServeV2Error, ServeOutcome as ServeV2Outcome, ServeResponse};
pub use serve_v1::{serve_v1, ServeOutcomeV1, ServeResponseV1, ServeV1Error};
