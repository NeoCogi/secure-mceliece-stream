# Secure McEliece Stream

A Rust library implementing post-quantum secure communication streams using the Classic McEliece cryptosystem for key exchange and AES-GCM for symmetric encryption.

## Features

- **Post-Quantum Security**: Uses Classic McEliece for quantum-resistant key exchange
- **Symmetric Encryption**: AES-256-GCM for fast data encryption after key exchange
- **Async/Await Support**: Built on Tokio for asynchronous I/O
- **Generic Transport**: Works with any `AsyncRead + AsyncWrite` stream

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
secure-mceliece-stream = "0.1.0"
```

## Example

```rust
use secure_mceliece_stream::{SecureStream, SecureStreamConfig};
use secure_mceliece_stream::secure_stream::SecureStreamImpl;
use tokio::net::TcpStream;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Connect to a server
    let socket = TcpStream::connect("127.0.0.1:8080").await?;
    let config = SecureStreamConfig::default();
    let mut stream = SecureStreamImpl::new(socket, config);

    // Establish secure connection as client
    stream.connect().await?;

    // Send encrypted data
    stream.send(b"Hello, secure world!").await?;

    // Receive encrypted data
    let data = stream.receive().await?;
    println!("Received: {}", String::from_utf8_lossy(&data));

    stream.close().await?;
    Ok(())
}
```

## Examples

The library includes two example applications:

### Simple Echo Server

A basic echo server demonstrating secure communication:

```bash
# Terminal 1 - Start server
cargo run --example simple_echo server

# Terminal 2 - Run client
cargo run --example simple_echo client
```

### Secure Chat

An interactive chat application with post-quantum encryption:

```bash
# Terminal 1 - Start server
cargo run --example secure_chat server

# Terminal 2 - Connect as client
cargo run --example secure_chat client localhost:8080
```

### Secure Chat with Pre-Generated Keys

Use persistent key pairs for faster connection establishment:

```bash
# Generate keys first
cargo run --bin keygen -- generate -p server.pub -s server.key --id server
cargo run --bin keygen -- generate -p client.pub -s client.key --id client

# Run with pre-generated keys
cargo run --example secure_chat_with_keys server server.key
cargo run --example secure_chat_with_keys client localhost:8080 client.key
```

## Performance Note

Classic McEliece uses very large keys (524KB for the public key in the mceliece460896 variant). Key generation and exchange can take 30+ seconds. This is normal and provides strong post-quantum security guarantees.

## Security Considerations

- The library uses Classic McEliece (mceliece460896 variant) for post-quantum key exchange
- Shared secrets are derived using SHA3-256
- Each message uses a unique nonce combining a counter and random bytes
- AES-256-GCM provides authenticated encryption for the data stream

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

Copyright (c) 2024 Raja Lehtihet & Wael El Oraiby