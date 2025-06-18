use anyhow::Result;
use pubky_messenger::{PrivateMessengerClient, PublicKey};
use std::env;
use std::io::{self, Write};

#[tokio::main]
async fn main() -> Result<()> {
    // Get command line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <recovery_file_path> [recipient_pubky]", args[0]);
        std::process::exit(1);
    }

    let recovery_file_path = &args[1];

    // Prompt for passphrase
    print!("Enter passphrase: ");
    io::stdout().flush()?;
    let passphrase = rpassword::read_password()?;

    // Load recovery file
    println!("Loading recovery file...");
    let recovery_file_bytes = std::fs::read(recovery_file_path)?;

    // Create client
    println!("Creating client and decrypting keypair...");
    let client = PrivateMessengerClient::from_recovery_file(&recovery_file_bytes, &passphrase)?;

    println!("Your public key: {}", client.public_key_string());

    // Sign in
    println!("Signing in to Pubky...");
    client.sign_in().await?;
    println!("Signed in successfully!");

    // Get own profile
    if let Some(profile) = client.get_own_profile().await? {
        println!("Your profile name: {}", profile.name);
        if let Some(bio) = profile.bio {
            println!("Bio: {}", bio);
        }
    }

    // Get followed users
    println!("\nFetching followed users...");
    let followed_users = client.get_followed_users().await?;
    println!("You are following {} users:", followed_users.len());
    for user in &followed_users {
        println!(
            "  - {} ({})",
            user.name.as_ref().unwrap_or(&"No name".to_string()),
            user.pubky
        );
    }

    // If recipient pubky provided, send a message and fetch conversation
    if args.len() > 2 {
        let recipient_pubky_str = &args[2];
        let recipient = PublicKey::try_from(recipient_pubky_str.as_str())?;

        // Send a test message
        println!("\nSending test message...");
        let message_id = client
            .send_message(&recipient, "Hello from pubky-private-messenger-lib!")
            .await?;
        println!("Message sent with ID: {}", message_id);

        // Get conversation messages
        println!("\nFetching conversation messages...");
        let messages = client.get_messages(&recipient).await?;
        println!("Found {} messages in conversation:", messages.len());

        for msg in messages {
            let is_own = msg.sender == client.public_key_string();
            println!(
                "\n[{}] {}: {}",
                chrono::DateTime::from_timestamp(msg.timestamp as i64, 0)
                    .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                    .unwrap_or_else(|| "Unknown time".to_string()),
                if is_own { "You" } else { &msg.sender[..8] },
                msg.content
            );
            println!("  Verified: {}", msg.verified);
        }
    }

    Ok(())
}
