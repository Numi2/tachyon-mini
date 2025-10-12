use thiserror::Error as ThisError;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, ThisError)]
pub enum Error {
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("replay detected")]
    Replay,
    #[error("timeout")]
    Timeout,
    #[error("serialization error: {0}")]
    Serialize(String),
    #[error("deserialization error: {0}")]
    Deserialize(String),
    #[error("io error: {0}")]
    Io(String),
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("other: {0}")]
    Other(String),
}

impl From<anyhow::Error> for Error {
    fn from(e: anyhow::Error) -> Self { Error::Other(e.to_string()) }
}


