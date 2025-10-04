//! Example demonstrating secure chat using McEliece-based secure stream
//!
//! This example shows how two parties can establish
//! a quantum-resistant secure communication channel.

use secure_mceliece_stream::{SecureStream, SecureStreamConfig};
use secure_mceliece_stream::secure_stream::SecureStreamImpl;
use std::error::Error;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::select;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Parse command line arguments
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage:");
        eprintln!("  Server: {} server [port]", args[0]);
        eprintln!("  Client: {} client <host:port>", args[0]);
        return Ok(());
    }

    match args[1].as_str() {
        "server" => {
            let port = args.get(2).map(|s| s.as_str()).unwrap_or("8080");
            run_server(port).await?;
        }
        "client" => {
            if args.len() < 3 {
                eprintln!("Please specify host:port to connect to");
                return Ok(());
            }
            run_client(&args[2]).await?;
        }
        _ => {
            eprintln!("Invalid mode. Use 'server' or 'client'");
        }
    }

    Ok(())
}

/// Run as server
async fn run_server(port: &str) -> Result<(), Box<dyn Error>> {
    let addr = format!("127.0.0.1:{}", port);
    let listener = TcpListener::bind(&addr).await?;
    println!("Server listening on {}", addr);
    println!("Waiting for client connection...");

    // Accept connection
    let (socket, peer_addr) = listener.accept().await?;
    println!("Client connected from {}", peer_addr);

    // Create secure stream
    let config = SecureStreamConfig::default();
    let mut secure_stream = SecureStreamImpl::new(socket, config);

    // Perform key exchange as server
    println!("Performing post-quantum key exchange...");
    secure_stream.accept().await?;
    println!("✅ Secure channel established!");

    // Exchange messages
    println!("\nYou can now exchange secure messages. Type 'quit' to exit.\n");

    // Setup stdin for reading user input
    let stdin = tokio::io::stdin();
    let reader = tokio::io::BufReader::new(stdin);
    let mut lines = reader.lines();

    let mut message_count = 0;

    loop {
        select! {
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
                        println!("\nClient disconnected");
                        break;
                    }
                    println!("Client: {}", message);
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

/// Run as client
async fn run_client(address: &str) -> Result<(), Box<dyn Error>> {
    println!("Client connecting to {}...", address);
    let socket = TcpStream::connect(address).await?;
    println!("Connected to server");

    // Create secure stream
    let config = SecureStreamConfig::default();
    let mut secure_stream = SecureStreamImpl::new(socket, config);

    // Perform key exchange as client
    println!("Performing post-quantum key exchange...");
    secure_stream.connect().await?;
    println!("✅ Secure channel established!");

    // Exchange messages
    println!("\nYou can now exchange secure messages. Type 'quit' to exit.\n");

    // Setup stdin for reading user input
    let stdin = tokio::io::stdin();
    let reader = tokio::io::BufReader::new(stdin);
    let mut lines = reader.lines();

    let mut message_count = 0;

    loop {
        select! {
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
                        println!("\nServer disconnected");
                        break;
                    }
                    println!("Server: {}", message);
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