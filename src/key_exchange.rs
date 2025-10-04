//! Key exchange module implementing the McEliece cryptosystem protocol.
//!
//! This module provides the key exchange functionality for establishing
//! post-quantum secure communication channels using the Classic McEliece
//! key encapsulation mechanism (KEM).
//!
//! # Protocol Overview
//!
//! The key exchange follows a KEM-based protocol with the following steps:
//!
//! 1. **Client (Initiator)** generates a McEliece key pair (public/secret keys)
//! 2. **Client** sends its public key to the Server
//! 3. **Server (Responder)** encapsulates a shared secret using the Client's public key
//! 4. **Server** sends the encapsulated ciphertext back to the Client
//! 5. **Client** decapsulates the ciphertext using its secret key to derive the same shared secret
//! 6. Both parties derive an AES-256-GCM key from the shared secret using SHA3-256
//!
//! ![Key Exchange Protocol](../docs/key-exchange-protocol.svg)
//!
//! # State Machine
//!
//! The key exchange operates as a state machine with the following states:
//!
//! ```text
//! Client States:
//! ┌─────────┐    generate     ┌──────────────┐    send PK    ┌──────────────┐
//! │  Init   │ ──────────────→ │  HasKeyPair  │ ────────────→ │ WaitingForCT │
//! └─────────┘                 └──────────────┘               └──────────────┘
//!                                                                   │
//!                                                              receive CT
//!                                                                   ↓
//!                             ┌──────────────┐  derive key   ┌──────────────┐
//!                             │   Complete   │ ←──────────── │ HasSharedSec │
//!                             └──────────────┘               └──────────────┘
//!
//! Server States:
//! ┌─────────┐   receive PK    ┌──────────────┐  encapsulate  ┌──────────────┐
//! │  Init   │ ──────────────→ │   HasPubKey  │ ────────────→ │ HasSharedSec │
//! └─────────┘                 └──────────────┘               └──────────────┘
//!                                                                   │
//!                                                                 send CT
//!                                                                   ↓
//!                                                            ┌──────────────┐
//!                                                            │   Complete   │
//!                                                            └──────────────┘
//! ```
//!
//! # Security Considerations
//!
//! - The McEliece public keys are large (~524 KB) which provides strong security
//!   but requires significant bandwidth for transmission
//! - The encapsulated ciphertext is only 188 bytes
//! - The shared secret is derived using SHA3-256 for key derivation
//! - All random number generation must use cryptographically secure RNGs
//! - The protocol is resistant to quantum computer attacks

use crate::Result;
use crate::error::SecureStreamError;
use aes_gcm::aead::rand_core::{CryptoRng, RngCore};
use classic_mceliece_rust::{
    CRYPTO_CIPHERTEXTBYTES, CRYPTO_PUBLICKEYBYTES, Ciphertext, PublicKey, SecretKey, SharedSecret,
    decapsulate_boxed, encapsulate_boxed, keypair_boxed,
};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

/// A McEliece key pair containing both public and secret keys.
///
/// The key pair is used for the McEliece key encapsulation mechanism (KEM)
/// during the key exchange protocol.
///
/// # Size Considerations
///
/// - Public key: ~524 KB (mceliece460896 variant)
/// - Secret key: ~13 KB
///
/// Due to these large sizes, key generation may take 30-60 seconds.
pub struct KeyPair {
    /// The public key used for encryption/encapsulation
    pub public_key: Box<PublicKey<'static>>,
    /// The secret key used for decryption/decapsulation
    pub secret_key: Box<SecretKey<'static>>,
}

impl KeyPair {
    /// Generates a new McEliece key pair.
    ///
    /// # Arguments
    ///
    /// * `rng` - A cryptographically secure random number generator
    ///
    /// # Performance
    ///
    /// Key generation is computationally intensive and may take 30-60 seconds
    /// on typical hardware.
    ///
    /// # Example
    ///
    /// ```
    /// use secure_mceliece_stream::key_exchange::KeyPair;
    /// use aes_gcm::aead::rand_core::OsRng;
    ///
    /// let mut rng = OsRng;
    /// let key_pair = KeyPair::generate(&mut rng);
    /// ```
    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        let (public_key, secret_key) = keypair_boxed(rng);
        Self {
            public_key: Box::new(public_key),
            secret_key: Box::new(secret_key),
        }
    }
}

/// Message containing public key for exchange
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PublicKeyMessage {
    pub public_key: Vec<u8>,
}

impl PublicKeyMessage {
    pub fn from_public_key(public_key: &PublicKey) -> Self {
        Self {
            public_key: public_key.as_array().to_vec(),
        }
    }

    pub fn to_public_key(&self) -> Result<Box<PublicKey<'static>>> {
        // PublicKey size is very large and varies based on variant
        // We need to copy to a boxed array
        if self.public_key.len() != CRYPTO_PUBLICKEYBYTES {
            return Err(SecureStreamError::KeyExchange(format!(
                "Invalid public key size: {} (expected {})",
                self.public_key.len(),
                CRYPTO_PUBLICKEYBYTES
            )));
        }

        // Create a boxed array from the slice
        let mut key_bytes = vec![0u8; CRYPTO_PUBLICKEYBYTES].into_boxed_slice();
        key_bytes.copy_from_slice(&self.public_key);

        // Convert Box<[u8]> to Box<[u8; N]>
        let array_ptr = Box::into_raw(key_bytes) as *mut [u8; CRYPTO_PUBLICKEYBYTES];
        let array = unsafe { Box::from_raw(array_ptr) };

        Ok(Box::new(PublicKey::from(array)))
    }
}

/// Encapsulated key message containing the KEM ciphertext.
///
/// This message is sent from the server to the client and contains
/// the encapsulated shared secret that only the client can decapsulate
/// using its secret key.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EncapsulatedKey {
    /// The McEliece ciphertext (188 bytes for mceliece460896)
    pub ciphertext: Vec<u8>,
}

/// Key exchange protocol state machine implementation.
///
/// This struct manages the state transitions during the McEliece key exchange
/// protocol. It tracks the current state (via Option fields) and ensures
/// the protocol steps are executed in the correct order.
///
/// # State Tracking
///
/// - `key_pair: None` → Initial state
/// - `key_pair: Some(_)` → Has generated/loaded keys (client ready to send PK)
/// - `shared_secret: None` → No shared secret yet
/// - `shared_secret: Some(_)` → Key exchange complete
///
/// # Protocol Flow
///
/// ## Client Side:
/// ```text
/// 1. new() → Init state
/// 2. init_client() → Generate keypair, return PublicKeyMessage
/// 3. [Send PublicKeyMessage to server]
/// 4. [Receive EncapsulatedKey from server]
/// 5. complete_client() → Decapsulate and derive shared secret
/// 6. get_shared_secret() → Retrieve the shared secret for cipher init
/// ```
///
/// ## Server Side:
/// ```text
/// 1. new() → Init state
/// 2. [Receive PublicKeyMessage from client]
/// 3. init_server() → Encapsulate secret, return EncapsulatedKey
/// 4. [Send EncapsulatedKey to client]
/// 5. get_shared_secret() → Retrieve the shared secret for cipher init
/// ```
pub struct KeyExchange {
    /// The client's key pair (only used by client side)
    key_pair: Option<KeyPair>,
    /// The derived shared secret (available after key exchange completes)
    shared_secret: Option<Vec<u8>>,
}

impl KeyExchange {
    pub fn new() -> Self {
        Self {
            key_pair: None,
            shared_secret: None,
        }
    }

    /// Set a pre-generated key pair
    pub fn set_keypair(&mut self, key_pair: KeyPair) {
        self.key_pair = Some(key_pair);
    }

    /// Generate a new key pair
    pub fn generate_keypair<R: CryptoRng + RngCore>(&mut self, rng: &mut R) {
        self.key_pair = Some(KeyPair::generate(rng));
    }

    /// Initialize as client with a pre-generated key pair
    pub fn init_client_with_keypair(&mut self, key_pair: KeyPair) -> PublicKeyMessage {
        let msg = PublicKeyMessage::from_public_key(&key_pair.public_key);
        self.key_pair = Some(key_pair);
        msg
    }

    /// Initialize as client generating a new key pair
    pub fn init_client<R: CryptoRng + RngCore>(&mut self, rng: &mut R) -> PublicKeyMessage {
        let key_pair = KeyPair::generate(rng);
        let msg = PublicKeyMessage::from_public_key(&key_pair.public_key);
        self.key_pair = Some(key_pair);
        msg
    }

    /// Server-side: Process client's public key and generate encapsulated secret.
    ///
    /// This is the main server-side operation in the key exchange protocol.
    /// It takes the client's public key and uses the McEliece KEM to encapsulate
    /// a random shared secret that only the client can decapsulate.
    ///
    /// # Protocol Position
    ///
    /// This is step 3 in the protocol:
    /// 1. Client generates keypair
    /// 2. Client sends public key → Server
    /// 3. **Server encapsulates secret** (this method)
    /// 4. Server sends ciphertext → Client
    /// 5. Client decapsulates to get same secret
    ///
    /// # Arguments
    ///
    /// * `client_public_key` - The public key received from the client
    /// * `rng` - Cryptographically secure RNG for generating the shared secret
    ///
    /// # Returns
    ///
    /// Returns the `EncapsulatedKey` containing the ciphertext to send to the client.
    ///
    /// # Security
    ///
    /// The encapsulation operation generates a random shared secret and encrypts it
    /// such that only the holder of the corresponding secret key can decrypt it.
    pub fn init_server<R: CryptoRng + RngCore>(
        &mut self,
        client_public_key: &PublicKeyMessage,
        rng: &mut R,
    ) -> Result<EncapsulatedKey> {
        let public_key = client_public_key.to_public_key()?;
        let (ciphertext, shared_secret) = encapsulate_boxed(&public_key, rng);

        // Derive key material from shared secret
        let derived_key = Self::derive_key(&shared_secret);
        self.shared_secret = Some(derived_key);

        Ok(EncapsulatedKey {
            ciphertext: ciphertext.as_array().to_vec(),
        })
    }

    /// Client-side: Decapsulate the ciphertext to derive the shared secret.
    ///
    /// This completes the client side of the key exchange protocol by decapsulating
    /// the ciphertext received from the server to derive the same shared secret.
    ///
    /// # Protocol Position
    ///
    /// This is step 5 in the protocol:
    /// 1. Client generates keypair
    /// 2. Client sends public key → Server
    /// 3. Server encapsulates secret
    /// 4. Server sends ciphertext → Client
    /// 5. **Client decapsulates** (this method)
    ///
    /// # Arguments
    ///
    /// * `encapsulated` - The encapsulated key received from the server
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The key pair was not initialized (protocol violation)
    /// - The ciphertext size is invalid
    /// - Decapsulation fails (corrupted or tampered ciphertext)
    ///
    /// # Security
    ///
    /// Only the holder of the secret key corresponding to the public key
    /// used for encapsulation can successfully decapsulate the ciphertext
    /// to recover the shared secret.
    pub fn complete_client(&mut self, encapsulated: &EncapsulatedKey) -> Result<()> {
        let key_pair = self.key_pair.as_ref().ok_or_else(|| {
            SecureStreamError::InvalidState("Key pair not initialized".to_string())
        })?;

        if encapsulated.ciphertext.len() != CRYPTO_CIPHERTEXTBYTES {
            return Err(SecureStreamError::KeyExchange(format!(
                "Invalid ciphertext size: {} (expected {})",
                encapsulated.ciphertext.len(),
                CRYPTO_CIPHERTEXTBYTES
            )));
        }

        let mut ct_bytes = [0u8; CRYPTO_CIPHERTEXTBYTES];
        ct_bytes.copy_from_slice(&encapsulated.ciphertext);

        let ciphertext = Box::new(Ciphertext::from(ct_bytes));

        let shared_secret = decapsulate_boxed(&ciphertext, &key_pair.secret_key);

        // Derive key material from shared secret
        let derived_key = Self::derive_key(&shared_secret);
        self.shared_secret = Some(derived_key);

        Ok(())
    }

    /// Get the derived shared secret
    pub fn get_shared_secret(&self) -> Result<Vec<u8>> {
        self.shared_secret.clone().ok_or_else(|| {
            SecureStreamError::InvalidState("Shared secret not established".to_string())
        })
    }

    /// Derive encryption key from shared secret using KDF
    fn derive_key(shared_secret: &SharedSecret) -> Vec<u8> {
        let mut hasher = Sha3_256::new();
        hasher.update(shared_secret.as_array());
        hasher.update(b"secure-mceliece-stream-v1");
        hasher.finalize().to_vec()
    }
}
