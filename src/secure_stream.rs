use crate::error::SecureStreamError;
use crate::key_exchange::{EncapsulatedKey, KeyExchange, KeyPair, PublicKeyMessage};
use crate::Result;
use aes_gcm::{
    aead::{Aead, KeyInit, generic_array::GenericArray},
    aead::rand_core::{OsRng, RngCore},
    Aes256Gcm,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Mutex;

type Nonce12 = GenericArray<u8, aes_gcm::aead::consts::U12>;

/// Protocol messages for secure stream communication
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum ProtocolMessage {
    /// Initial key exchange message from Alice
    PublicKey(PublicKeyMessage),
    /// Encapsulated key response from Bob
    EncapsulatedKey(EncapsulatedKey),
    /// Encrypted data message
    Data {
        nonce: Vec<u8>,
        ciphertext: Vec<u8>,
    },
    /// Handshake complete acknowledgment
    HandshakeComplete,
}

/// Configuration parameters for secure stream connections.
///
/// This struct allows customization of buffer sizes and message limits
/// for secure communication streams.
///
/// # Example
///
/// ```
/// use secure_mceliece_stream::SecureStreamConfig;
///
/// let config = SecureStreamConfig {
///     max_message_size: 32 * 1024 * 1024, // 32MB
///     buffer_size: 16384,                  // 16KB buffer
/// };
/// ```
#[derive(Clone)]
pub struct SecureStreamConfig {
    /// Maximum message size in bytes.
    /// Messages larger than this will be rejected to prevent memory exhaustion.
    /// Default: 16MB
    pub max_message_size: usize,

    /// Buffer size for reading data from the transport layer.
    /// Larger buffers may improve throughput but use more memory.
    /// Default: 8192 bytes
    pub buffer_size: usize,
}

impl Default for SecureStreamConfig {
    fn default() -> Self {
        Self {
            max_message_size: 16 * 1024 * 1024, // 16MB
            buffer_size: 8192,
        }
    }
}

/// Trait defining the interface for secure encrypted communication streams.
///
/// This trait provides methods for establishing secure connections,
/// sending and receiving encrypted data, and managing connection lifecycle.
///
/// # Implementation Notes
///
/// Implementations must ensure that all data is encrypted before transmission
/// and properly authenticated to prevent tampering.
#[async_trait::async_trait]
pub trait SecureStream: Send + Sync {
    /// Sends encrypted data over the secure channel.
    ///
    /// # Arguments
    ///
    /// * `data` - The plaintext data to encrypt and send
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The connection is not established
    /// - Encryption fails
    /// - The underlying transport fails
    async fn send(&mut self, data: &[u8]) -> Result<()>;

    /// Receives and decrypts data from the secure channel.
    ///
    /// # Returns
    ///
    /// Returns the decrypted plaintext data.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The connection is not established
    /// - Decryption fails
    /// - Authentication fails (tampering detected)
    /// - The underlying transport fails
    async fn receive(&mut self) -> Result<Vec<u8>>;

    /// Checks if the secure connection is established and ready for use.
    ///
    /// # Returns
    ///
    /// Returns `true` if the handshake is complete and the connection is ready
    /// for encrypted communication.
    fn is_connected(&self) -> bool;

    /// Closes the secure connection gracefully.
    ///
    /// This method should be called to properly terminate the connection
    /// and clean up resources.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying transport fails during closure.
    async fn close(&mut self) -> Result<()>;
}

/// Implementation of a secure communication stream using post-quantum cryptography.
///
/// This struct wraps any `AsyncRead + AsyncWrite` transport (such as `TcpStream`)
/// and provides encrypted, authenticated communication using the McEliece cryptosystem
/// for key exchange and AES-256-GCM for symmetric encryption.
///
/// # Type Parameters
///
/// * `T` - The underlying transport type, must implement `AsyncRead + AsyncWrite + Unpin + Send`
///
/// # Example
///
/// ```no_run
/// use secure_mceliece_stream::{SecureStream, SecureStreamImpl, SecureStreamConfig};
/// use tokio::net::TcpStream;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let socket = TcpStream::connect("127.0.0.1:8080").await?;
/// let config = SecureStreamConfig::default();
/// let mut stream = SecureStreamImpl::new(socket, config);
///
/// // As client
/// stream.connect().await?;
///
/// // Send and receive encrypted data
/// stream.send(b"Hello").await?;
/// let response = stream.receive().await?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct SecureStreamImpl<T> {
    transport: Arc<Mutex<T>>,
    cipher: Option<Arc<Aes256Gcm>>,
    config: SecureStreamConfig,
    is_connected: Arc<Mutex<bool>>,
    nonce_counter: Arc<Mutex<u64>>,
}

impl<T> SecureStreamImpl<T>
where
    T: AsyncRead + AsyncWrite + Unpin + Send,
{
    /// Creates a new secure stream instance.
    ///
    /// # Arguments
    ///
    /// * `transport` - The underlying transport (e.g., `TcpStream`)
    /// * `config` - Configuration parameters for the secure stream
    ///
    /// # Example
    ///
    /// ```no_run
    /// use secure_mceliece_stream::{SecureStreamImpl, SecureStreamConfig};
    /// use tokio::net::TcpStream;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let socket = TcpStream::connect("127.0.0.1:8080").await?;
    /// let config = SecureStreamConfig::default();
    /// let stream = SecureStreamImpl::new(socket, config);
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(transport: T, config: SecureStreamConfig) -> Self {
        Self {
            transport: Arc::new(Mutex::new(transport)),
            cipher: None,
            config,
            is_connected: Arc::new(Mutex::new(false)),
            nonce_counter: Arc::new(Mutex::new(0)),
        }
    }

    /// Establishes a secure connection as a client using a pre-generated key pair.
    ///
    /// This method performs the McEliece key exchange protocol as the initiator,
    /// using the provided key pair instead of generating a new one. This is useful
    /// for maintaining persistent identities and avoiding the 30-60 second key
    /// generation time.
    ///
    /// # Arguments
    ///
    /// * `key_pair` - The pre-generated McEliece key pair to use
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The key exchange protocol fails
    /// - The underlying transport fails
    /// - The server sends invalid protocol messages
    ///
    /// # Example
    ///
    /// ```no_run
    /// use secure_mceliece_stream::{SecureStreamImpl, key_storage};
    /// use std::path::Path;
    /// # use tokio::net::TcpStream;
    /// # use secure_mceliece_stream::SecureStreamConfig;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Load pre-generated key
    /// let (key_pair, _) = key_storage::load_keypair(Path::new("client.key"))?;
    ///
    /// # let socket = TcpStream::connect("127.0.0.1:8080").await?;
    /// # let config = SecureStreamConfig::default();
    /// let mut stream = SecureStreamImpl::new(socket, config);
    /// stream.connect_with_keypair(key_pair).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn connect_with_keypair(&mut self, key_pair: KeyPair) -> Result<()> {
        let mut key_exchange = KeyExchange::new();

        // Step 1: Send public key to server using pre-generated key
        let public_key_msg = key_exchange.init_client_with_keypair(key_pair);
        self.send_protocol_message(&ProtocolMessage::PublicKey(public_key_msg))
            .await?;

        // Continue with the rest of the handshake
        self.complete_client_handshake(&mut key_exchange).await
    }

    /// Establishes a secure connection as a client.
    ///
    /// This method performs the McEliece key exchange protocol as the initiator,
    /// generating a new ephemeral key pair. Note that key generation may take
    /// 30-60 seconds due to the computational requirements of McEliece.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Key generation fails
    /// - The key exchange protocol fails
    /// - The underlying transport fails
    /// - The server sends invalid protocol messages
    ///
    /// # Example
    ///
    /// ```no_run
    /// use secure_mceliece_stream::{SecureStreamImpl, SecureStreamConfig};
    /// use tokio::net::TcpStream;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let socket = TcpStream::connect("127.0.0.1:8080").await?;
    /// let config = SecureStreamConfig::default();
    /// let mut stream = SecureStreamImpl::new(socket, config);
    ///
    /// // Connect as client (generates new key pair)
    /// stream.connect().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn connect(&mut self) -> Result<()> {
        let mut key_exchange = KeyExchange::new();
        let mut rng = OsRng;

        // Step 1: Send public key to server
        let public_key_msg = key_exchange.init_client(&mut rng);
        self.send_protocol_message(&ProtocolMessage::PublicKey(public_key_msg))
            .await?;

        // Continue with the rest of the handshake
        self.complete_client_handshake(&mut key_exchange).await
    }

    /// Complete client handshake after sending public key
    async fn complete_client_handshake(&mut self, key_exchange: &mut KeyExchange) -> Result<()> {

        // Step 2: Receive encapsulated key from server
        let msg = self.receive_protocol_message().await?;
        let encapsulated = match msg {
            ProtocolMessage::EncapsulatedKey(enc) => enc,
            _ => {
                return Err(SecureStreamError::Protocol(
                    "Expected encapsulated key from server".to_string(),
                ))
            }
        };

        // Step 3: Complete key exchange
        key_exchange.complete_client(&encapsulated)?;

        // Step 4: Initialize cipher
        self.initialize_cipher(key_exchange.get_shared_secret()?)?;

        // Step 5: Send handshake complete
        self.send_protocol_message(&ProtocolMessage::HandshakeComplete)
            .await?;

        // Step 6: Wait for server's handshake complete
        let msg = self.receive_protocol_message().await?;
        match msg {
            ProtocolMessage::HandshakeComplete => {
                *self.is_connected.lock().await = true;
                Ok(())
            }
            _ => Err(SecureStreamError::Protocol(
                "Expected handshake complete from server".to_string(),
            )),
        }
    }

    /// Accept incoming secure connection as server with a pre-generated key pair
    pub async fn accept_with_keypair(&mut self, key_pair: KeyPair) -> Result<()> {
        let mut key_exchange = KeyExchange::new();
        key_exchange.set_keypair(key_pair);
        self.complete_server_handshake(&mut key_exchange).await
    }

    /// Accept incoming secure connection as server, generating a new key pair
    pub async fn accept(&mut self) -> Result<()> {
        let mut key_exchange = KeyExchange::new();
        let mut rng = OsRng;

        // Generate a new key pair for server
        key_exchange.generate_keypair(&mut rng);
        self.complete_server_handshake(&mut key_exchange).await
    }

    /// Complete server handshake
    async fn complete_server_handshake(&mut self, key_exchange: &mut KeyExchange) -> Result<()> {
        let mut rng = OsRng;

        // Step 1: Receive public key from client
        let msg = self.receive_protocol_message().await?;
        let public_key_msg = match msg {
            ProtocolMessage::PublicKey(pk) => pk,
            _ => {
                return Err(SecureStreamError::Protocol(
                    "Expected public key from client".to_string(),
                ))
            }
        };

        // Step 2: Generate and send encapsulated key
        let encapsulated = key_exchange.init_server(&public_key_msg, &mut rng)?;
        self.send_protocol_message(&ProtocolMessage::EncapsulatedKey(encapsulated))
            .await?;

        // Step 3: Initialize cipher
        self.initialize_cipher(key_exchange.get_shared_secret()?)?;

        // Step 4: Wait for client's handshake complete
        let msg = self.receive_protocol_message().await?;
        match msg {
            ProtocolMessage::HandshakeComplete => {}
            _ => {
                return Err(SecureStreamError::Protocol(
                    "Expected handshake complete from client".to_string(),
                ))
            }
        }

        // Step 5: Send our handshake complete
        self.send_protocol_message(&ProtocolMessage::HandshakeComplete)
            .await?;

        *self.is_connected.lock().await = true;
        Ok(())
    }

    /// Initialize the cipher with the shared secret
    fn initialize_cipher(&mut self, shared_secret: Vec<u8>) -> Result<()> {
        if shared_secret.len() != 32 {
            return Err(SecureStreamError::KeyExchange(
                "Invalid shared secret length".to_string(),
            ));
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&shared_secret);

        self.cipher = Some(Arc::new(Aes256Gcm::new(&key.into())));
        Ok(())
    }

    /// Send a protocol message
    async fn send_protocol_message(&mut self, msg: &ProtocolMessage) -> Result<()> {
        let config = bincode::config::standard();
        let data = bincode::serde::encode_to_vec(msg, config)
            .map_err(|e| SecureStreamError::Serialization(e.to_string()))?;
        let len = data.len() as u32;

        let mut transport = self.transport.lock().await;
        transport.write_all(&len.to_be_bytes()).await?;
        transport.write_all(&data).await?;
        transport.flush().await?;

        Ok(())
    }

    /// Receive a protocol message
    async fn receive_protocol_message(&mut self) -> Result<ProtocolMessage> {
        let mut len_buf = [0u8; 4];
        let mut transport = self.transport.lock().await;
        transport.read_exact(&mut len_buf).await?;

        let len = u32::from_be_bytes(len_buf) as usize;
        if len > self.config.max_message_size {
            return Err(SecureStreamError::Protocol(
                "Message size exceeds maximum".to_string(),
            ));
        }

        let mut data = vec![0u8; len];
        transport.read_exact(&mut data).await?;

        let config = bincode::config::standard();
        let (msg, _) = bincode::serde::decode_from_slice(&data, config)
            .map_err(|e| SecureStreamError::Serialization(e.to_string()))?;
        Ok(msg)
    }

    /// Generate a unique nonce
    async fn generate_nonce(&mut self) -> Nonce12 {
        let mut counter = self.nonce_counter.lock().await;
        let mut nonce = [0u8; 12];
        nonce[0..8].copy_from_slice(&counter.to_be_bytes());
        *counter += 1;

        // Add randomness to last 4 bytes for additional security
        let mut random_bytes = [0u8; 4];
        OsRng.fill_bytes(&mut random_bytes);
        nonce[8..12].copy_from_slice(&random_bytes);

        Nonce12::from(nonce)
    }
}

#[async_trait::async_trait]
impl<T> SecureStream for SecureStreamImpl<T>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + Sync,
{
    async fn send(&mut self, data: &[u8]) -> Result<()> {
        let nonce = self.generate_nonce().await;

        let cipher = self
            .cipher
            .as_ref()
            .ok_or_else(|| SecureStreamError::InvalidState("Cipher not initialized".to_string()))?;

        let ciphertext = cipher
            .encrypt(&nonce, data)
            .map_err(|e| SecureStreamError::Encryption(e.to_string()))?;

        let msg = ProtocolMessage::Data {
            nonce: nonce.to_vec(),
            ciphertext,
        };

        self.send_protocol_message(&msg).await
    }

    async fn receive(&mut self) -> Result<Vec<u8>> {
        let msg = self.receive_protocol_message().await?;

        match msg {
            ProtocolMessage::Data { nonce, ciphertext } => {
                let cipher = self.cipher.as_ref().ok_or_else(|| {
                    SecureStreamError::InvalidState("Cipher not initialized".to_string())
                })?;

                if nonce.len() != 12 {
                    return Err(SecureStreamError::Decryption("Invalid nonce size".to_string()));
                }

                let mut nonce_array = [0u8; 12];
                nonce_array.copy_from_slice(&nonce);
                let nonce = Nonce12::from(nonce_array);

                cipher
                    .decrypt(&nonce, ciphertext.as_ref())
                    .map_err(|e| SecureStreamError::Decryption(e.to_string()))
            }
            _ => Err(SecureStreamError::Protocol(
                "Expected data message".to_string(),
            )),
        }
    }

    fn is_connected(&self) -> bool {
        // We can't use async in a non-async trait method, so we'll use try_lock
        self.is_connected
            .try_lock()
            .map(|guard| *guard)
            .unwrap_or(false)
    }

    async fn close(&mut self) -> Result<()> {
        *self.is_connected.lock().await = false;
        self.cipher = None;
        Ok(())
    }
}