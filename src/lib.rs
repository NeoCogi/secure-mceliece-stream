//! # Secure McEliece Stream
//!
//! A production-ready Rust library providing post-quantum secure communication channels
//! using the Classic McEliece cryptosystem for key exchange and AES-256-GCM for
//! authenticated encryption.
//!
//! ## Overview
//!
//! This library implements a secure communication protocol that is resistant to attacks
//! from quantum computers. It uses the Classic McEliece cryptosystem (specifically the
//! mceliece460896 variant) for key exchange, which is one of the finalists in NIST's
//! Post-Quantum Cryptography standardization process.
//!
//! ## Features
//!
//! - **Post-Quantum Security**: Resistant to attacks from quantum computers
//! - **Authenticated Encryption**: Uses AES-256-GCM for fast, secure data transmission
//! - **Flexible Key Management**: Support for both ephemeral and persistent key pairs
//! - **Async/Await**: Full Tokio async runtime support
//! - **Generic Transport**: Works with any `AsyncRead + AsyncWrite` stream
//!
//! ## Quick Example
//!
//! ```no_run
//! use secure_mceliece_stream::{SecureStream, SecureStreamConfig, SecureStreamImpl};
//! use tokio::net::TcpStream;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Connect to a server
//!     let socket = TcpStream::connect("127.0.0.1:8080").await?;
//!     let config = SecureStreamConfig::default();
//!     let mut stream = SecureStreamImpl::new(socket, config);
//!
//!     // Establish secure connection
//!     stream.connect().await?;
//!
//!     // Send encrypted data
//!     stream.send(b"Hello, secure world!").await?;
//!
//!     // Receive encrypted data
//!     let data = stream.receive().await?;
//!
//!     stream.close().await?;
//!     Ok(())
//! }
//! ```
//!
//! ## Security Considerations
//!
//! - The McEliece public keys are large (~524 KB) which may impact network performance
//! - Key generation can take 30-60 seconds due to the computational requirements
//! - Always use secure channels (TLS) for the underlying transport when possible
//! - Implement proper key rotation policies for long-lived connections

pub mod error;
pub mod key_exchange;
pub mod key_storage;
pub mod secure_stream;

pub use error::SecureStreamError;
pub use key_exchange::{KeyExchange, KeyPair, PublicKeyMessage};
pub use secure_stream::{SecureStream, SecureStreamConfig, SecureStreamImpl};

/// Result type for secure stream operations
pub type Result<T> = std::result::Result<T, SecureStreamError>;