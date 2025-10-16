#![forbid(unsafe_code)]
use thiserror::Error;

#[derive(Error, Debug)]
pub enum EngineError {
    #[error("rpc transport: {0}")]
    RpcTransport(String),
    #[error("rpc server: {0}")]
    RpcServer(String),
    #[error("invalid response")]
    InvalidResponse,
}

pub trait FinalizeEngine: Send + Sync {
    /// Broadcast a raw transaction (hex). Returns txid (hex).
    fn broadcast_raw_tx(&self, hex_tx: &str) -> Result<String, EngineError>;
}


