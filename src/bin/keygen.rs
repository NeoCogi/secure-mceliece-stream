//! McEliece Key Generation and Management CLI
//!
//! This tool allows generating, storing, and managing McEliece key pairs
//! for use with the secure-mceliece-stream library.

use clap::{Parser, Subcommand};
use secure_mceliece_stream::key_exchange::KeyPair;
use secure_mceliece_stream::key_storage::{self, KeyMetadata};
use std::path::PathBuf;
use aes_gcm::aead::rand_core::OsRng;

#[derive(Parser)]
#[command(name = "keygen")]
#[command(about = "McEliece key generation and management tool", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new McEliece key pair
    Generate {
        /// Output path for the public key
        #[arg(short, long, default_value = "public.key")]
        public: PathBuf,

        /// Output path for the secret key
        #[arg(short, long, default_value = "secret.key")]
        secret: PathBuf,

        /// Key identifier
        #[arg(short, long, default_value = "default")]
        id: String,

        /// Optional comment for the key
        #[arg(short, long)]
        comment: Option<String>,
    },

    /// Display information about a key
    Info {
        /// Path to the key file (public or secret)
        key: PathBuf,
    },

    /// Verify a key pair
    Verify {
        /// Path to the public key
        #[arg(short, long)]
        public: PathBuf,

        /// Path to the secret key
        #[arg(short, long)]
        secret: PathBuf,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Generate {
            public,
            secret,
            id,
            comment,
        } => {
            println!("Generating McEliece key pair...");
            println!("⚠️  Warning: Key generation may take 30-60 seconds due to the large key size.");

            // Generate key pair
            let mut rng = OsRng;
            let key_pair = KeyPair::generate(&mut rng);

            // Create metadata
            let mut metadata = KeyMetadata::new(id.clone());
            if let Some(comment) = comment {
                metadata = metadata.with_comment(comment);
            }

            // Save keys
            key_storage::save_keypair(&key_pair, &public, &secret, metadata)?;

            println!("✅ Key pair generated successfully!");
            println!("   Public key: {}", public.display());
            println!("   Secret key: {}", secret.display());
            println!("   Key ID: {}", id);
            println!("\n⚠️  Keep your secret key file safe and secure!");
            println!("   The secret key file has been set to owner-read-only permissions (600).");
        }

        Commands::Info { key } => {
            // Try to load as secret key first (contains full info)
            match key_storage::load_keypair(&key) {
                Ok((_, metadata)) => {
                    println!("Key Information (Full Keypair):");
                    println!("  ID: {}", metadata.key_id);
                    println!("  Created: {}", metadata.created_at);
                    if let Some(comment) = metadata.comment {
                        println!("  Comment: {}", comment);
                    }
                    println!("  Type: Secret key (contains both public and secret keys)");
                }
                Err(_) => {
                    // Try as public key
                    match key_storage::load_public_key(&key) {
                        Ok((_, metadata)) => {
                            println!("Key Information (Public Key Only):");
                            println!("  ID: {}", metadata.key_id);
                            println!("  Created: {}", metadata.created_at);
                            if let Some(comment) = metadata.comment {
                                println!("  Comment: {}", comment);
                            }
                            println!("  Type: Public key only");
                        }
                        Err(e) => {
                            eprintln!("Error reading key file: {}", e);
                            std::process::exit(1);
                        }
                    }
                }
            }
        }

        Commands::Verify { public, secret } => {
            println!("Verifying key pair...");

            // Load keys
            let (public_key, pub_meta) = key_storage::load_public_key(&public)?;
            let (key_pair, sec_meta) = key_storage::load_keypair(&secret)?;

            // Check if IDs match
            if pub_meta.key_id != sec_meta.key_id {
                println!("⚠️  Warning: Key IDs don't match!");
                println!("   Public key ID: {}", pub_meta.key_id);
                println!("   Secret key ID: {}", sec_meta.key_id);
            }

            // Verify that the public keys match
            if public_key.as_array() == key_pair.public_key.as_array() {
                println!("✅ Key pair verified successfully!");
                println!("   The public and secret keys are a valid pair.");
            } else {
                println!("❌ Key pair verification failed!");
                println!("   The public key does not match the secret key's public component.");
                std::process::exit(1);
            }
        }
    }

    Ok(())
}