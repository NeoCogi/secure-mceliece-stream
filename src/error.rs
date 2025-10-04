use thiserror::Error;

#[derive(Error, Debug)]
pub enum SecureStreamError {
    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("Decryption error: {0}")]
    Decryption(String),

    #[error("Key exchange error: {0}")]
    KeyExchange(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Invalid state: {0}")]
    InvalidState(String),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Key storage error: {0}")]
    KeyStorage(String),
}