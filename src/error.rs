use core::fmt;

/// All errors in blindforest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Signature verification failed.
    VerificationFailed,
    /// All one-time signing keys have been exhausted.
    KeyExhausted,
    /// Invalid parameter or input length.
    InvalidInput,
    /// Merkle auth path is invalid.
    InvalidAuthPath,
    /// Commitment does not match.
    CommitmentMismatch,
    /// Proof encoding/decoding error.
    ProofFormat,
    /// I/O error (only with std feature).
    #[cfg(feature = "std")]
    Io,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::VerificationFailed => write!(f, "signature verification failed"),
            Error::KeyExhausted => write!(f, "all one-time keys exhausted"),
            Error::InvalidInput => write!(f, "invalid parameter or input length"),
            Error::InvalidAuthPath => write!(f, "invalid merkle auth path"),
            Error::CommitmentMismatch => write!(f, "commitment mismatch"),
            Error::ProofFormat => write!(f, "proof encoding/decoding error"),
            #[cfg(feature = "std")]
            Error::Io => write!(f, "I/O error"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

#[cfg(feature = "std")]
impl From<std::io::Error> for Error {
    fn from(_: std::io::Error) -> Self {
        Error::Io
    }
}

/// Result type alias for blindforest operations.
pub type Result<T> = core::result::Result<T, Error>;
