use bstr::BString;
use gix_transport::{client, Protocol};

use crate::wire_types::{AckTrailer, Acknowledgments};
use crate::{command::Feature, fetch::Response};

/// The error returned in the [response module][crate::fetch::response].
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum Error {
    #[error("Failed to read from line reader")]
    Io(#[source] std::io::Error),
    #[error(transparent)]
    UploadPack(#[from] gix_transport::packetline::read::Error),
    #[error(transparent)]
    Transport(#[from] client::Error),
    #[error("Currently we require feature {feature:?}, which is not supported by the server")]
    MissingServerCapability { feature: &'static str },
    #[error("Encountered an unknown line prefix in {line:?}")]
    UnknownLineType { line: String },
    #[error("Unknown or unsupported header: {header:?}")]
    UnknownSectionHeader { header: String },
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        if err.kind() == std::io::ErrorKind::Other {
            match err.into_inner() {
                Some(err) => match err.downcast::<gix_transport::packetline::read::Error>() {
                    Ok(err) => Error::UploadPack(*err),
                    Err(err) => Error::Io(std::io::Error::other(err)),
                },
                None => Error::Io(std::io::ErrorKind::Other.into()),
            }
        } else {
            Error::Io(err)
        }
    }
}

impl gix_transport::IsSpuriousError for Error {
    fn is_spurious(&self) -> bool {
        match self {
            Error::Io(err) => err.is_spurious(),
            Error::Transport(err) => err.is_spurious(),
            _ => false,
        }
    }
}

pub use gix_shallow::Update as ShallowUpdate;

/// A wanted-ref line received from the server.
#[derive(PartialEq, Eq, Debug, Hash, Ord, PartialOrd, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct WantedRef {
    /// The object id of the wanted ref, as seen by the server.
    pub id: gix_hash::ObjectId,
    /// The name of the ref, as requested by the client as a `want-ref` argument.
    pub path: BString,
}

/// Outcome of parsing one line of the server's acknowledgments
/// section: either a common oid to append to the section, a trailer
/// token to attach, or a marker that the section is explicitly
/// present with no commons yet (NAK on the wire).
enum AckLine {
    Common(gix_hash::ObjectId),
    Trailer(AckTrailer),
    Nak,
}

impl AckLine {
    /// Parse one pkt-line payload from the server's response as a
    /// line of the `acknowledgments` section.
    fn from_line(line: &str) -> Result<AckLine, Error> {
        let mut tokens = line.trim_end().splitn(3, ' ');
        match (tokens.next(), tokens.next(), tokens.next()) {
            (Some("ready"), _, _) => Ok(AckLine::Trailer(AckTrailer::Ready)),
            (Some("NAK"), _, _) => Ok(AckLine::Nak),
            (Some("ACK"), Some(id_str), description) => {
                let id = gix_hash::ObjectId::from_hex(id_str.as_bytes())
                    .map_err(|_| Error::UnknownLineType { line: line.to_owned() })?;
                // v1 multi_ack_detailed tags the line as
                // `ACK <oid> common` or `ACK <oid> ready`; the
                // `ready` case also sets the section trailer, which
                // the caller handles from the raw line text.
                match description {
                    Some("ready") | Some("common") | None => Ok(AckLine::Common(id)),
                    Some(_) => Err(Error::UnknownLineType { line: line.to_owned() }),
                }
            }
            _ => Err(Error::UnknownLineType { line: line.to_owned() }),
        }
    }
}

/// Parse a `ShallowUpdate` from a `line` as received to the server.
pub fn shallow_update_from_line(line: &str) -> Result<ShallowUpdate, Error> {
    match line.trim_end().split_once(' ') {
        Some((prefix, id)) => {
            let id = gix_hash::ObjectId::from_hex(id.as_bytes())
                .map_err(|_| Error::UnknownLineType { line: line.to_owned() })?;
            Ok(match prefix {
                "shallow" => ShallowUpdate::Shallow(id),
                "unshallow" => ShallowUpdate::Unshallow(id),
                _ => return Err(Error::UnknownLineType { line: line.to_owned() }),
            })
        }
        None => Err(Error::UnknownLineType { line: line.to_owned() }),
    }
}

/// Append the parsed line to `acks`, making the section present if
/// it wasn't. Dedupes common oids.
fn append_ack_line(acks: &mut Option<Acknowledgments>, line: &str) -> Result<(), Error> {
    let entry = acks.get_or_insert_with(Acknowledgments::default);
    match AckLine::from_line(line)? {
        AckLine::Common(id) => {
            if !entry.common_oids.contains(&id) {
                entry.common_oids.push(id);
            }
            // v1 multi_ack_detailed tags "ACK <oid> ready" in the same line.
            let trimmed = line.trim_end();
            if trimmed.ends_with(" ready") {
                entry.trailer = Some(AckTrailer::Ready);
            }
        }
        AckLine::Trailer(t) => {
            entry.trailer = Some(t);
        }
        AckLine::Nak => {
            // NAK is "section present, no commons". The
            // `get_or_insert_with` above already made the section
            // present; nothing else to record.
        }
    }
    Ok(())
}

impl WantedRef {
    /// Parse a `WantedRef` from a `line` as received from the server.
    pub fn from_line(line: &str) -> Result<WantedRef, Error> {
        match line.trim_end().split_once(' ') {
            Some((id, path)) => {
                let id = gix_hash::ObjectId::from_hex(id.as_bytes())
                    .map_err(|_| Error::UnknownLineType { line: line.to_owned() })?;
                Ok(WantedRef { id, path: path.into() })
            }
            None => Err(Error::UnknownLineType { line: line.to_owned() }),
        }
    }
}

impl Response {
    /// Return true if the response has a pack which can be read next.
    pub fn has_pack(&self) -> bool {
        self.has_pack
    }

    /// Return an error if the given `features` don't contain the required ones (the ones this implementation needs)
    /// for the given `version` of the protocol.
    ///
    /// Even though technically any set of features supported by the server could work, we only implement the ones that
    /// make it easy to maintain all versions with a single code base that aims to be and remain maintainable.
    pub fn check_required_features(version: Protocol, features: &[Feature]) -> Result<(), Error> {
        match version {
            Protocol::V0 | Protocol::V1 => {
                let has = |name: &str| features.iter().any(|f| f.0 == name);
                // Let's focus on V2 standards, and simply not support old servers to keep our code simpler
                if !has("multi_ack_detailed") {
                    return Err(Error::MissingServerCapability {
                        feature: "multi_ack_detailed",
                    });
                }
                // It's easy to NOT do sideband for us, but then again, everyone supports it.
                // CORRECTION: If sideband is off, it would send the packfile without packet line encoding,
                // which is nothing we ever want to deal with (despite it being more efficient). In V2, this
                // is not even an option anymore, sidebands are always present.
                if !has("side-band") && !has("side-band-64k") {
                    return Err(Error::MissingServerCapability {
                        feature: "side-band OR side-band-64k",
                    });
                }
            }
            Protocol::V2 => {}
        }
        Ok(())
    }

    /// Return the parsed `acknowledgments` section
    /// [parsed previously][Response::from_line_reader()], or `None`
    /// when the server's response omitted the section entirely
    /// (v2-legal when the client signalled `done` with no haves).
    pub fn acknowledgements(&self) -> Option<&Acknowledgments> {
        self.acknowledgments.as_ref()
    }

    /// Return all shallow update lines [parsed previously][Response::from_line_reader()].
    pub fn shallow_updates(&self) -> &[ShallowUpdate] {
        &self.shallows
    }

    /// Append the given `updates` which may have been obtained from a
    /// (handshake::Outcome)[crate::Handshake::v1_shallow_updates].
    ///
    /// In V2, these are received as part of the pack, but V1 sends them early, so we
    /// offer to re-integrate them here.
    pub fn append_v1_shallow_updates(&mut self, updates: Option<Vec<ShallowUpdate>>) {
        self.shallows.extend(updates.into_iter().flatten());
    }

    /// Return all wanted-refs [parsed previously][Response::from_line_reader()].
    pub fn wanted_refs(&self) -> &[WantedRef] {
        &self.wanted_refs
    }
}

/// Parse one peeked V1 response line into the `acks` / `shallows`
/// accumulators and report what kind of line it was.
///
/// Returns `(was_nak, set_ready, stop_as_pack)`. `stop_as_pack` is
/// `true` when the line is neither ack nor shallow and the caller
/// should treat what follows as the pack.
#[cfg(any(feature = "async-client", feature = "blocking-client"))]
fn categorize_v1_line(
    peeked_line: &str,
    acks: &mut Option<Acknowledgments>,
    shallows: &mut Vec<ShallowUpdate>,
) -> (bool, bool, bool) {
    let trimmed = peeked_line.trim_end();
    let mut tokens = trimmed.splitn(3, ' ');
    match (tokens.next(), tokens.next(), tokens.next()) {
        (Some("NAK"), _, _) => {
            acks.get_or_insert_with(Acknowledgments::default);
            (true, false, false)
        }
        (Some("ready"), _, _) => {
            let entry = acks.get_or_insert_with(Acknowledgments::default);
            entry.trailer = Some(AckTrailer::Ready);
            (false, true, false)
        }
        (Some("ACK"), Some(id_str), description) => match gix_hash::ObjectId::from_hex(id_str.as_bytes()) {
            Ok(id) => {
                let entry = acks.get_or_insert_with(Acknowledgments::default);
                if !entry.common_oids.contains(&id) {
                    entry.common_oids.push(id);
                }
                let set_ready = matches!(description, Some("ready"));
                if set_ready {
                    entry.trailer = Some(AckTrailer::Ready);
                }
                (false, set_ready, false)
            }
            Err(_) => try_shallow(peeked_line, shallows),
        },
        _ => try_shallow(peeked_line, shallows),
    }
}

#[cfg(any(feature = "async-client", feature = "blocking-client"))]
fn try_shallow(peeked_line: &str, shallows: &mut Vec<ShallowUpdate>) -> (bool, bool, bool) {
    match shallow_update_from_line(peeked_line) {
        Ok(s) => {
            shallows.push(s);
            (false, false, false)
        }
        Err(_) => (false, false, true),
    }
}

#[cfg(feature = "async-client")]
mod async_io;
#[cfg(feature = "blocking-client")]
mod blocking_io;
