//! Integration tests for key management functionality

use secure_mceliece_stream::key_exchange::KeyPair;
use secure_mceliece_stream::key_storage::{self, KeyMetadata};
use secure_mceliece_stream::secure_stream::{SecureStreamConfig, SecureStreamImpl};
use secure_mceliece_stream::SecureStream;
use tempfile::TempDir;
use tokio::net::{TcpListener, TcpStream};

#[tokio::test]
async fn test_key_generation_and_storage() {
    // Create temporary directory for keys
    let temp_dir = TempDir::new().unwrap();
    let public_key_path = temp_dir.path().join("test_public.key");
    let secret_key_path = temp_dir.path().join("test_secret.key");

    // Generate key pair
    let mut rng = aes_gcm::aead::rand_core::OsRng;
    let key_pair = KeyPair::generate(&mut rng);

    // Create metadata
    let metadata = KeyMetadata::new("test_key".to_string())
        .with_comment("Test key for unit testing".to_string());

    // Save keys
    key_storage::save_keypair(&key_pair, &public_key_path, &secret_key_path, metadata.clone())
        .expect("Failed to save key pair");

    // Verify files exist
    assert!(public_key_path.exists(), "Public key file should exist");
    assert!(secret_key_path.exists(), "Secret key file should exist");

    // Load keys back
    let (loaded_keypair, loaded_metadata) = key_storage::load_keypair(&secret_key_path)
        .expect("Failed to load key pair");

    // Verify metadata
    assert_eq!(loaded_metadata.key_id, "test_key");
    assert_eq!(loaded_metadata.comment, Some("Test key for unit testing".to_string()));

    // Verify keys match
    assert_eq!(
        loaded_keypair.public_key.as_array(),
        key_pair.public_key.as_array(),
        "Public keys should match"
    );
    assert_eq!(
        loaded_keypair.secret_key.as_array(),
        key_pair.secret_key.as_array(),
        "Secret keys should match"
    );

    // Test loading public key only
    let (loaded_public_key, pub_metadata) = key_storage::load_public_key(&public_key_path)
        .expect("Failed to load public key");

    assert_eq!(
        loaded_public_key.as_array(),
        key_pair.public_key.as_array(),
        "Loaded public key should match"
    );
    assert_eq!(pub_metadata.key_id, metadata.key_id);
}

#[tokio::test]
async fn test_secure_stream_with_pregenerated_keys() {
    // Generate two key pairs (Alice and Bob)
    let mut rng = aes_gcm::aead::rand_core::OsRng;
    let alice_keypair = KeyPair::generate(&mut rng);
    let bob_keypair = KeyPair::generate(&mut rng);

    // Start server with Bob's pre-generated key
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Clone the keypair for the server task
    // We need to manually clone the boxed keys
    let bob_public_clone = Box::new(classic_mceliece_rust::PublicKey::from(
        Box::new(bob_keypair.public_key.as_array().clone())
    ));
    let bob_secret_clone = Box::new(classic_mceliece_rust::SecretKey::from(
        Box::new(bob_keypair.secret_key.as_array().clone())
    ));
    let bob_keypair_clone = KeyPair {
        public_key: bob_public_clone,
        secret_key: bob_secret_clone,
    };

    let server_task = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let config = SecureStreamConfig::default();
        let mut secure_stream = SecureStreamImpl::new(socket, config);

        // Use pre-generated key
        secure_stream
            .accept_with_keypair(bob_keypair_clone)
            .await
            .expect("Bob handshake failed");

        // Echo test message
        let data = secure_stream.receive().await.expect("Failed to receive");
        secure_stream.send(&data).await.expect("Failed to send");
    });

    // Give server time to start
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Connect as Alice with pre-generated key
    let socket = TcpStream::connect(addr).await.unwrap();
    let config = SecureStreamConfig::default();
    let mut secure_stream = SecureStreamImpl::new(socket, config);

    secure_stream
        .connect_with_keypair(alice_keypair)
        .await
        .expect("Alice handshake failed");

    // Send test message
    let test_message = b"Test message with pre-generated keys";
    secure_stream.send(test_message).await.expect("Failed to send");

    // Receive echo
    let received = secure_stream.receive().await.expect("Failed to receive");
    assert_eq!(received, test_message, "Echoed message should match");

    // Clean up
    secure_stream.close().await.ok();
    server_task.await.ok();
}

#[tokio::test]
async fn test_key_persistence_across_sessions() {
    // Create temporary directory for keys
    let temp_dir = TempDir::new().unwrap();
    let key_path = temp_dir.path().join("persistent.key");
    let public_path = temp_dir.path().join("persistent.pub");

    // Generate and save a key pair
    let mut rng = aes_gcm::aead::rand_core::OsRng;
    let original_keypair = KeyPair::generate(&mut rng);
    let metadata = KeyMetadata::new("persistent_test".to_string());

    key_storage::save_keypair(&original_keypair, &public_path, &key_path, metadata)
        .expect("Failed to save key pair");

    // Simulate multiple sessions using the same key
    for session in 0..3 {
        let (loaded_keypair, loaded_metadata) = key_storage::load_keypair(&key_path)
            .expect("Failed to load key pair");

        assert_eq!(
            loaded_metadata.key_id, "persistent_test",
            "Key ID should be consistent in session {}", session
        );

        // Verify the key is the same
        assert_eq!(
            loaded_keypair.public_key.as_array(),
            original_keypair.public_key.as_array(),
            "Public key should be the same in session {}", session
        );
    }
}

#[test]
fn test_key_metadata() {
    let metadata = KeyMetadata::new("test_id".to_string())
        .with_comment("Test comment".to_string());

    assert_eq!(metadata.key_id, "test_id");
    assert_eq!(metadata.comment, Some("Test comment".to_string()));
    assert!(!metadata.created_at.is_empty());

    // Verify timestamp format
    assert!(metadata.created_at.contains('T'), "Should be RFC3339 format");
}