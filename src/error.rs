use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("parse ip address: {0}")]
    AddrParse(#[from] std::net::AddrParseError),
    #[error("ipnetwork: {0}")]
    IpNetwork(#[from] ipnetwork::IpNetworkError),
    #[error("rustables builder: {0}")]
    RustablesBuilder(#[from] rustables::error::BuilderError),
    #[error("rustables query: {0}")]
    RustablesQuery(#[from] rustables::error::QueryError),
    #[error("serde_json: {0}")]
    SerdeJson(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
