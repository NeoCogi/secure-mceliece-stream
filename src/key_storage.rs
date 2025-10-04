//! Key storage and management utilities
//!
//! This module provides functionality to save and load McEliece keys to/from files,
//! allowing for persistent key storage and reuse.

use crate::error::SecureStreamError;
use crate::key_exchange::KeyPair;
use crate::Result;
use classic_mceliece_rust::{PublicKey, SecretKey, CRYPTO_PUBLICKEYBYTES, CRYPTO_SECRETKEYBYTES};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Stored key pair format
#[derive(Serialize, Deserialize)]
pub struct StoredKeyPair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
    pub metadata: KeyMetadata,
}

/// Metadata about the stored key
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KeyMetadata {
    pub created_at: String,
    pub key_id: String,
    pub comment: Option<String>,
}

impl KeyMetadata {
    pub fn new(key_id: String) -> Self {
        Self {
            created_at: chrono::Utc::now().to_rfc3339(),
            key_id,
            comment: None,
        }
    }

    pub fn with_comment(mut self, comment: String) -> Self {
        self.comment = Some(comment);
        self
    }
}

/// Save a key pair to files
pub fn save_keypair(
    key_pair: &KeyPair,
    public_key_path: &Path,
    secret_key_path: &Path,
    metadata: KeyMetadata,
) -> Result<()> {
    // Create stored format
    let stored = StoredKeyPair {
        public_key: key_pair.public_key.as_array().to_vec(),
        secret_key: key_pair.secret_key.as_array().to_vec(),
        metadata,
    };

    // Serialize to JSON (you could also use bincode for smaller files)
    let json = serde_json::to_string_pretty(&stored)
        .map_err(|e| SecureStreamError::KeyStorage(format!("Failed to serialize keys: {}", e)))?;

    // Save public key (only public key and metadata)
    let public_stored = serde_json::json!({
        "public_key": stored.public_key,
        "metadata": stored.metadata,
    });

    fs::write(public_key_path, serde_json::to_string_pretty(&public_stored)
        .map_err(|e| SecureStreamError::KeyStorage(format!("Failed to serialize public key: {}", e)))?)
        .map_err(|e| SecureStreamError::KeyStorage(format!("Failed to write public key file: {}", e)))?;

    // Save secret key (full keypair)
    fs::write(secret_key_path, json)
        .map_err(|e| SecureStreamError::KeyStorage(format!("Failed to write secret key file: {}", e)))?;

    // Set restrictive permissions on secret key file (Unix-like systems)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(secret_key_path)
            .map_err(|e| SecureStreamError::KeyStorage(format!("Failed to get file metadata: {}", e)))?
            .permissions();
        perms.set_mode(0o600); // Read/write for owner only
        fs::set_permissions(secret_key_path, perms)
            .map_err(|e| SecureStreamError::KeyStorage(format!("Failed to set file permissions: {}", e)))?;
    }

    Ok(())
}

/// Load a key pair from a secret key file
pub fn load_keypair(secret_key_path: &Path) -> Result<(KeyPair, KeyMetadata)> {
    let contents = fs::read_to_string(secret_key_path)
        .map_err(|e| SecureStreamError::KeyStorage(format!("Failed to read key file: {}", e)))?;

    let stored: StoredKeyPair = serde_json::from_str(&contents)
        .map_err(|e| SecureStreamError::KeyStorage(format!("Failed to parse key file: {}", e)))?;

    // Validate key sizes
    if stored.public_key.len() != CRYPTO_PUBLICKEYBYTES {
        return Err(SecureStreamError::KeyStorage(format!(
            "Invalid public key size: {} (expected {})",
            stored.public_key.len(),
            CRYPTO_PUBLICKEYBYTES
        )));
    }

    if stored.secret_key.len() != CRYPTO_SECRETKEYBYTES {
        return Err(SecureStreamError::KeyStorage(format!(
            "Invalid secret key size: {} (expected {})",
            stored.secret_key.len(),
            CRYPTO_SECRETKEYBYTES
        )));
    }

    // Reconstruct keys
    let mut public_key_array = Box::new([0u8; CRYPTO_PUBLICKEYBYTES]);
    public_key_array.copy_from_slice(&stored.public_key);
    let public_key = Box::new(PublicKey::from(public_key_array));

    let mut secret_key_array = Box::new([0u8; CRYPTO_SECRETKEYBYTES]);
    secret_key_array.copy_from_slice(&stored.secret_key);
    let secret_key = Box::new(SecretKey::from(secret_key_array));

    let key_pair = KeyPair {
        public_key,
        secret_key,
    };

    Ok((key_pair, stored.metadata))
}

/// Load only a public key from file
pub fn load_public_key(public_key_path: &Path) -> Result<(Box<PublicKey<'static>>, KeyMetadata)> {
    let contents = fs::read_to_string(public_key_path)
        .map_err(|e| SecureStreamError::KeyStorage(format!("Failed to read public key file: {}", e)))?;

    let value: serde_json::Value = serde_json::from_str(&contents)
        .map_err(|e| SecureStreamError::KeyStorage(format!("Failed to parse public key file: {}", e)))?;

    let public_key_data = value["public_key"]
        .as_array()
        .ok_or_else(|| SecureStreamError::KeyStorage("Invalid public key format".into()))?
        .iter()
        .map(|v| {
            v.as_u64()
                .ok_or_else(|| SecureStreamError::KeyStorage("Invalid byte value".into()))
                .map(|n| n as u8)
        })
        .collect::<Result<Vec<u8>>>()?;

    let metadata: KeyMetadata = serde_json::from_value(value["metadata"].clone())
        .map_err(|e| SecureStreamError::KeyStorage(format!("Failed to parse metadata: {}", e)))?;

    if public_key_data.len() != CRYPTO_PUBLICKEYBYTES {
        return Err(SecureStreamError::KeyStorage(format!(
            "Invalid public key size: {} (expected {})",
            public_key_data.len(),
            CRYPTO_PUBLICKEYBYTES
        )));
    }

    let mut public_key_array = Box::new([0u8; CRYPTO_PUBLICKEYBYTES]);
    public_key_array.copy_from_slice(&public_key_data);
    let public_key = Box::new(PublicKey::from(public_key_array));

    Ok((public_key, metadata))
}