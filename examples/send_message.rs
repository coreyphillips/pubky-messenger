use anyhow::Result;
use pubky_messenger::{PrivateMessengerClient, PublicKey};
use std::env;
use std::io::{self, Write};

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 4 {
        eprintln!(
            "Usage: {} <recovery_file_path> <recipient_pubkey> <message>",
            args[0]
        );
        eprintln!("Example: {} recovery.pkarr pk:q9x5sfjbpajdebk45b9jashgb86iem7rnwpmu16px3ens63xzwro \"Hello there!\"", args[0]);
        std::process::exit(1);
    }

    let recovery_file_path = &args[1];
    let recipient_pubkey_str = &args[2];
    let message_content = &args[3];

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

    let recipient = PublicKey::try_from(recipient_pubkey_str.as_str())?;
    println!("\nSending message to {}...", recipient_pubkey_str);

    let message_id = client.send_message(&recipient, message_content).await?;
    println!("✓ Message sent successfully!");
    println!("Message ID: {}", message_id);
    println!("Content: {}", message_content);
    println!(
        "Timestamp: {}",
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
    );

    Ok(())
}
