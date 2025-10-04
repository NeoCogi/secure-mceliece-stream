use secure_mceliece_stream::{SecureStream, SecureStreamConfig};
use secure_mceliece_stream::secure_stream::SecureStreamImpl;
use tokio::net::{TcpListener, TcpStream};

#[tokio::test]
async fn test_secure_stream_communication() {
    // Start a TCP server
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Server task
    let server_handle = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let config = SecureStreamConfig::default();
        let mut stream = SecureStreamImpl::new(socket, config);

        // Accept connection as server
        stream.accept().await.unwrap();

        // Receive a message
        let received = stream.receive().await.unwrap();
        assert_eq!(received, b"Hello from Alice");

        // Send a response
        stream.send(b"Hello from Bob").await.unwrap();

        stream.close().await.unwrap();
    });

    // Give server time to start
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Client connection
    let socket = TcpStream::connect(addr).await.unwrap();
    let config = SecureStreamConfig::default();
    let mut stream = SecureStreamImpl::new(socket, config);

    // Connect as client
    stream.connect().await.unwrap();

    // Send a message
    stream.send(b"Hello from Alice").await.unwrap();

    // Receive response
    let received = stream.receive().await.unwrap();
    assert_eq!(received, b"Hello from Bob");

    stream.close().await.unwrap();

    // Wait for server to finish
    server_handle.await.unwrap();
}

#[tokio::test]
async fn test_key_exchange() {
    use secure_mceliece_stream::key_exchange::KeyExchange;
    use aes_gcm::aead::rand_core::OsRng;

    let mut alice_kex = KeyExchange::new();
    let mut bob_kex = KeyExchange::new();

    // Client generates public key
    let client_public = alice_kex.init_client(&mut OsRng);

    // Server generates encapsulated key
    let encapsulated = bob_kex.init_server(&client_public, &mut OsRng).unwrap();

    // Client completes exchange
    alice_kex.complete_client(&encapsulated).unwrap();

    // Both should have the same shared secret
    let alice_secret = alice_kex.get_shared_secret().unwrap();
    let bob_secret = bob_kex.get_shared_secret().unwrap();

    assert_eq!(alice_secret, bob_secret);
    assert_eq!(alice_secret.len(), 32); // Should be 256 bits
}