//! Example demonstrating secure chat using pre-generated McEliece keys
//!
//! This example shows how to use pre-generated key pairs for secure communication,
//! allowing for persistent identities and faster connection establishment.

use secure_mceliece_stream::{SecureStream, SecureStreamConfig};
use secure_mceliece_stream::key_storage;
use secure_mceliece_stream::secure_stream::SecureStreamImpl;
use std::error::Error;
use std::path::Path;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use std::sync::Arc;
use tokio::sync::Mutex;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage:");
        eprintln!("  Server: {} server [keyfile]", args[0]);
        eprintln!("  Client: {} client <host:port> [keyfile]", args[0]);
        eprintln!();
        eprintln!("If keyfile is not provided, a new key pair will be generated.");
        eprintln!();
        eprintln!("Example:");
        eprintln!("  Generate keys first:");
        eprintln!("    cargo run --bin keygen -- generate -p alice.pub -s alice.key --id alice");
        eprintln!("    cargo run --bin keygen -- generate -p bob.pub -s bob.key --id bob");
        eprintln!();
        eprintln!("  Then run with pre-generated keys:");
        eprintln!("    {} server bob.key", args[0]);
        eprintln!("    {} client 127.0.0.1:8080 alice.key", args[0]);
        return Ok(());
    }

    match args[1].as_str() {
        "server" => {
            let key_file = args.get(2);
            run_server_with_keys(key_file).await?;
        }
        "client" => {
            if args.len() < 3 {
                eprintln!("Please specify host:port to connect to");
                return Ok(());
            }
            let key_file = args.get(3);
            run_client_with_keys(&args[2], key_file).await?;
        }
        _ => {
            eprintln!("Invalid mode. Use 'server' or 'client'");
        }
    }

    Ok(())
}

/// Run server with optional pre-generated key
async fn run_server_with_keys(key_file: Option<&String>) -> Result<(), Box<dyn Error>> {
    let addr = "127.0.0.1:8080";
    let listener = TcpListener::bind(&addr).await?;

    if let Some(key_path) = key_file {
        println!("Loading server key from: {}", key_path);
        let (key_pair, metadata) = key_storage::load_keypair(Path::new(key_path))?;
        println!("Using key ID: {} (created: {})", metadata.key_id, metadata.created_at);
        if let Some(comment) = &metadata.comment {
            println!("Key comment: {}", comment);
        }

        println!("Server listening on {} with pre-generated key", addr);

        // Accept connection
        let (socket, peer_addr) = listener.accept().await?;
        println!("Client connected from {}", peer_addr);

        // Create secure stream with pre-generated key
        let config = SecureStreamConfig::default();
        let mut secure_stream = SecureStreamImpl::new(socket, config);

        // Use the pre-generated key pair
        println!("Performing key exchange with pre-generated key...");
        secure_stream.accept_with_keypair(key_pair).await?;
        println!("✅ Secure channel established!");

        handle_chat(secure_stream, "Bob", "Alice").await?;
    } else {
        println!("Server listening on {} (generating new key pair)", addr);

        // Accept connection
        let (socket, peer_addr) = listener.accept().await?;
        println!("Client connected from {}", peer_addr);

        // Create secure stream
        let config = SecureStreamConfig::default();
        let mut secure_stream = SecureStreamImpl::new(socket, config);

        // Generate new key pair
        println!("Generating new key pair (this may take 30-60 seconds)...");
        secure_stream.accept().await?;
        println!("✅ Secure channel established!");

        handle_chat(secure_stream, "Bob", "Alice").await?;
    }

    Ok(())
}

/// Run client with optional pre-generated key
async fn run_client_with_keys(address: &str, key_file: Option<&String>) -> Result<(), Box<dyn Error>> {
    println!("Connecting to {}...", address);
    let socket = TcpStream::connect(address).await?;
    println!("Connected to server");

    // Create secure stream
    let config = SecureStreamConfig::default();
    let mut secure_stream = SecureStreamImpl::new(socket, config);

    if let Some(key_path) = key_file {
        println!("Loading client key from: {}", key_path);
        let (key_pair, metadata) = key_storage::load_keypair(Path::new(key_path))?;
        println!("Using key ID: {} (created: {})", metadata.key_id, metadata.created_at);
        if let Some(comment) = &metadata.comment {
            println!("Key comment: {}", comment);
        }

        // Use the pre-generated key pair
        println!("Performing key exchange with pre-generated key...");
        secure_stream.connect_with_keypair(key_pair).await?;
    } else {
        // Generate new key pair
        println!("Generating new key pair (this may take 30-60 seconds)...");
        secure_stream.connect().await?;
    }

    println!("✅ Secure channel established!");
    handle_chat(secure_stream, "Alice", "Bob").await?;

    Ok(())
}

/// Handle chat interaction
async fn handle_chat<T>(mut secure_stream: SecureStreamImpl<T>, my_name: &str, peer_name: &str) -> Result<(), Box<dyn Error>>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync + 'static,
{
    println!("\n=== Secure Chat Session ===");
    println!("You are: {}", my_name);
    println!("Chatting with: {}", peer_name);
    println!("Type messages and press Enter to send. Type 'quit' to exit.\n");

    // Setup stdin for reading user input
    let stdin = tokio::io::stdin();
    let reader = tokio::io::BufReader::new(stdin);
    let mut lines = reader.lines();

    let mut message_count = 0;

    loop {
        tokio::select! {
            // Check for incoming messages (non-blocking via select!)
            _ = tokio::time::sleep(tokio::time::Duration::from_millis(10)) => {
                // Try to receive a message if available
                let result = tokio::time::timeout(
                    tokio::time::Duration::from_millis(100),
                    secure_stream.receive()
                ).await;

                if let Ok(Ok(data)) = result {
                    let message = String::from_utf8_lossy(&data);
                    if message == "quit" {
                        println!("\n{} disconnected", peer_name);
                        break;
                    }
                    println!("{}: {}", peer_name, message);
                }
            }

            // Check for user input
            line = lines.next_line() => {
                if let Ok(Some(input)) = line {
                    if input.trim() == "quit" {
                        secure_stream.send(b"quit").await?;
                        break;
                    }
                    if !input.trim().is_empty() {
                        secure_stream.send(input.trim().as_bytes()).await?;
                        message_count += 1;
                    }
                }
            }
        }
    }

    secure_stream.close().await?;
    println!("Connection closed. Messages sent: {}", message_count);

    Ok(())
}