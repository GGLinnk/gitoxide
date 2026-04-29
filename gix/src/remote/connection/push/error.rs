//! Errors raised by the high-level push path.

/// The error type returned by [`super::Prepare::send`] and
/// [`super::Connection::prepare_push`].
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum Error {
    #[error("failed to gather transport options from the repository configuration")]
    GatherTransportConfig(#[source] crate::config::transport::Error),
    #[error(transparent)]
    Transport(gix_transport::client::Error),
    #[error(transparent)]
    CredentialHelpers(#[from] crate::config::credential_helpers::Error),
    #[error(transparent)]
    Handshake(gix_protocol::handshake::Error),
    #[error("no ref-update commands were provided")]
    NoCommands,
    #[error("the prepared push has already been executed")]
    AlreadyExecuted,
    #[error(transparent)]
    Argument(gix_protocol::push::arguments::Error),
    #[error(transparent)]
    Send(gix_protocol::push::arguments::SendError),
    #[error(transparent)]
    Response(gix_protocol::push::response::Error),
    #[error(transparent)]
    Connect(#[from] crate::remote::connect::Error),
    #[error("failed to parse push refspec {spec:?}")]
    RefspecParse {
        spec: crate::bstr::BString,
        #[source]
        err: gix_refspec::parse::Error,
    },
    #[error("push refspec {spec:?} needs an explicit destination")]
    RefspecNoDestination { spec: crate::bstr::BString },
    #[error("push refspec {spec:?} uses an unsupported wildcard shape - only symmetric single-star patterns under refs/ are supported")]
    RefspecWildcardUnsupported { spec: crate::bstr::BString },
    #[error(
        "push refspec {spec:?} is negative (`^<ref>`); negative refspec semantics on push are not implemented"
    )]
    RefspecNegativeUnsupported { spec: crate::bstr::BString },
    /// Raised when the refspec's source ref name is syntactically
    /// valid but cannot be found in the local ref store, or cannot be
    /// peeled to an object (e.g. a symref pointing at a nonexistent
    /// target). The source name is included verbatim so callers can
    /// surface it in CLI diagnostics.
    #[error("local source ref {src:?} for refspec {spec:?} could not be resolved")]
    RefspecSourceNotFound {
        spec: crate::bstr::BString,
        src: crate::bstr::BString,
        #[source]
        err: Box<dyn std::error::Error + Send + Sync + 'static>,
    },
    /// Raised when a command would rewrite `refname` on the remote with
    /// a `new` tip that does not descend from the remote's advertised
    /// `old` tip. Prefix the refspec with `+`, pass `--force`
    /// (CLI-level), or call [`super::Prepare::with_force`] to bypass
    /// the check.
    #[error(
        "non-fast-forward update refused for {refname:?}\n  \
         local tip    {local}\n  \
         remote tip   {remote}\n  \
         the remote has commits your local ref does not; pushing would rewind or diverge from history.\n  \
         hint: integrate the remote first (`gix fetch` then merge or rebase), or re-run with `--force` / \
         prefix the refspec with `+` to overwrite the remote."
    )]
    NonFastForward {
        refname: crate::bstr::BString,
        local: gix_hash::ObjectId,
        remote: gix_hash::ObjectId,
    },
}

impl gix_transport::IsSpuriousError for Error {
    fn is_spurious(&self) -> bool {
        match self {
            Error::Transport(err) => err.is_spurious(),
            Error::Handshake(err) => err.is_spurious(),
            Error::Send(err) => err.is_spurious(),
            _ => false,
        }
    }
}
