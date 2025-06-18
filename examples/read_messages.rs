use anyhow::Result;
use pubky_messenger::{PrivateMessengerClient, PublicKey};
use std::env;
use std::io::{self, Write};

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} <recovery_file_path> <peer_pubkey>", args[0]);
        eprintln!(
            "Example: {} recovery.pkarr pk:q9x5sfjbpajdebk45b9jashgb86iem7rnwpmu16px3ens63xzwro",
            args[0]
        );
        std::process::exit(1);
    }

    let recovery_file_path = &args[1];
    let peer_pubkey_str = &args[2];

    print!("Enter passphrase: ");
    io::stdout().flush()?;
    let passphrase = rpassword::read_password()?;

    println!("Loading recovery file...");
    let recovery_file_bytes = std::fs::read(recovery_file_path)?;

    println!("Creating client...");
    let client = PrivateMessengerClient::from_recovery_file(&recovery_file_bytes, &passphrase)?;

    println!("Your public key: {}", client.public_key_string());

    println!("Signing in to Pubky...");
    client.sign_in().await?;
    println!("Signed in successfully!");

    let peer = PublicKey::try_from(peer_pubkey_str.as_str())?;

    println!("\nFetching conversation with {}...", peer_pubkey_str);
    let messages = client.get_messages(&peer).await?;

    if messages.is_empty() {
        println!("No messages found in this conversation.");
    } else {
        println!("Found {} message(s) in conversation:\n", messages.len());
        println!("{:-<80}", "");

        for (index, msg) in messages.iter().enumerate() {
            let is_own_message = msg.sender == client.public_key_string();
            let sender_display = if is_own_message {
                "You".to_string()
            } else {
                format!("{}...", &msg.sender[..16])
            };

            let timestamp = chrono::DateTime::from_timestamp(msg.timestamp as i64, 0)
                .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                .unwrap_or_else(|| "Unknown time".to_string());

            println!("[{}] {} - {}", index + 1, timestamp, sender_display);
            println!("Message: {}", msg.content);
            println!("Verified: {}", if msg.verified { "✓" } else { "✗" });

            if index < messages.len() - 1 {
                println!("{:-<80}", "");
            }
        }
        println!("{:-<80}", "");
    }

    Ok(())
}
