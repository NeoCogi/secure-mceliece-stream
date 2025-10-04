//! Simple echo server example demonstrating the secure stream
//!
//! This example shows a basic echo server that uses post-quantum
//! secure communication to echo messages back to the client.

use secure_mceliece_stream::{SecureStream, SecureStreamConfig};
use secure_mceliece_stream::secure_stream::SecureStreamImpl;
use std::error::Error;
use tokio::net::{TcpListener, TcpStream};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage:");
        eprintln!("  Server: {} server", args[0]);
        eprintln!("  Client: {} client", args[0]);
        return Ok(());
    }

    match args[1].as_str() {
        "server" => run_echo_server().await?,
        "client" => run_echo_client().await?,
        _ => eprintln!("Use 'server' or 'client'"),
    }

    Ok(())
}

async fn run_echo_server() -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:7777").await?;
    println!("Echo server listening on 127.0.0.1:7777");

    loop {
        let (socket, addr) = listener.accept().await?;
        println!("New connection from {}", addr);

        tokio::spawn(async move {
            if let Err(e) = handle_echo_client(socket).await {
                eprintln!("Error handling client: {}", e);
            }
        });
    }
}

async fn handle_echo_client(socket: TcpStream) -> Result<(), Box<dyn Error>> {
    let config = SecureStreamConfig::default();
    let mut secure_stream = SecureStreamImpl::new(socket, config);

    // Establish secure connection as server
    println!("Establishing secure connection...");
    secure_stream.accept().await?;
    println!("Secure connection established");

    // Echo loop
    loop {
        match secure_stream.receive().await {
            Ok(data) => {
                let message = String::from_utf8_lossy(&data);
                println!("Received: {}", message);

                if message == "quit" {
                    break;
                }

                // Echo back
                let response = format!("Echo: {}", message);
                secure_stream.send(response.as_bytes()).await?;
            }
            Err(e) => {
                eprintln!("Error receiving: {}", e);
                break;
            }
        }
    }

    secure_stream.close().await?;
    println!("Client disconnected");
    Ok(())
}

async fn run_echo_client() -> Result<(), Box<dyn Error>> {
    println!("Connecting to echo server...");
    let socket = TcpStream::connect("127.0.0.1:7777").await?;

    let config = SecureStreamConfig::default();
    let mut secure_stream = SecureStreamImpl::new(socket, config);

    // Establish secure connection as client
    println!("Establishing secure connection...");
    secure_stream.connect().await?;
    println!("Secure connection established");

    // Send test messages
    let messages = vec![
        "Hello, quantum-resistant world!",
        "This is a test message",
        "McEliece provides post-quantum security",
        "Final message before quit",
    ];

    for msg in messages {
        println!("Sending: {}", msg);
        secure_stream.send(msg.as_bytes()).await?;

        let response = secure_stream.receive().await?;
        let response_str = String::from_utf8_lossy(&response);
        println!("Received: {}", response_str);
        println!();

        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }

    // Send quit signal
    println!("Sending quit signal...");
    secure_stream.send(b"quit").await?;

    secure_stream.close().await?;
    println!("Connection closed");
    Ok(())
}