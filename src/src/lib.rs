//! # Pubky Messenger
//!
//! A Rust library for secure private messaging using the Pubky protocol.
//!
//! ## Features
//!
//! - End-to-end encrypted messaging
//! - Authentication via pkarr recovery files
//! - Message signature verification
//! - Profile and contact management
//!
//! ## Example
//!
//! ```no_run
//! use pubky_messenger::PrivateMessengerClient;
//! use pkarr::PublicKey;
//!
//! # async fn example() -> anyhow::Result<()> {
//! // Load recovery file
//! let recovery_file = std::fs::read("recovery.pkarr")?;
//! 
//! // Create client
//! let client = PrivateMessengerClient::from_recovery_file(&recovery_file, "passphrase")?;
//!
//! // Sign in
//! client.sign_in().await?;
//!
//! // Send a message
//! let recipient = PublicKey::try_from("recipient_public_key")?;
//! client.send_message(&recipient, "Hello, world!").await?;
//!
//! // Get messages
//! let messages = client.get_messages(&recipient).await?;
//! # Ok(())
//! # }
//! ```

mod client;
mod crypto;
mod message;

pub use client::{FollowedUser, PrivateMessengerClient, PubkyProfile};
pub use message::{DecryptedMessage, PrivateMessage};

pub use pkarr::{Keypair, PublicKey};
