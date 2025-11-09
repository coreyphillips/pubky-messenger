use anyhow::Result;
use pubky_messenger::{DecryptedMessage, PrivateMessengerClient, PublicKey};
use std::collections::HashSet;
use std::env;
use std::io::{self, Write};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::Duration;

struct ChatState {
    messages: Vec<DecryptedMessage>,
    seen_timestamps: HashSet<u64>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} <recovery_file_path> <peer_pubky>", args[0]);
        eprintln!(
            "Example: {} recovery.pkarr pk:q9x5sfjbpajdebk45b9jashgb86iem7rnwpmu16px3ens63xzwro",
            args[0]
        );
        std::process::exit(1);
    }

    let recovery_file_path = &args[1];
    let peer_pubky_str = &args[2];

    print!("Enter passphrase: ");
    io::stdout().flush()?;
    let passphrase = rpassword::read_password()?;

    println!("Loading recovery file...");
    let recovery_file_bytes = std::fs::read(recovery_file_path)?;

    println!("Creating client...");
    let client = Arc::new(PrivateMessengerClient::from_recovery_file(
        &recovery_file_bytes,
        Some(&passphrase),
    )?);

    println!("Your public key: {}", client.public_key_string());

    println!("Signing in to Pubky...");
    client.sign_in().await?;
    println!("Signed in successfully!");

    let peer = PublicKey::try_from(peer_pubky_str.as_str())?;

    // Clear the screen
    print!("\x1B[2J\x1B[1;1H");

    println!("=== Conversation with {} ===", peer_pubky_str);
    println!("Type your message and press Enter to send. Press Ctrl+C to exit.\n");

    // Fetch initial messages
    let initial_messages = client.get_messages(&peer).await?;
    let mut chat_state = ChatState {
        messages: initial_messages.clone(),
        seen_timestamps: initial_messages
            .iter()
            .map(|m| (m.timestamp, m.sender.clone()))
            .map(|(t, s)| t ^ s.bytes().fold(0u64, |acc, b| acc.rotate_left(7) ^ b as u64))
            .collect(),
    };

    // Display last 10 messages
    let recent_messages: Vec<_> = chat_state.messages.iter().rev().take(10).rev().collect();

    for msg in recent_messages {
        display_message(msg, &client.public_key_string());
    }

    println!("\n{:-<80}", "");

    // Create a channel for communication between tasks
    let (tx, mut rx) = mpsc::channel::<String>(100);

    // Spawn input handler
    let tx_clone = tx.clone();
    tokio::spawn(async move {
        let stdin = io::stdin();
        loop {
            let mut input = String::new();
            if stdin.read_line(&mut input).is_ok() {
                if tx_clone.send(input).await.is_err() {
                    break;
                }
            }
        }
    });

    // Main loop with automatic polling
    let mut poll_timer = tokio::time::interval(Duration::from_secs(3));

    print!("> ");
    io::stdout().flush()?;

    loop {
        tokio::select! {
            // Handle user input
            Some(input) = rx.recv() => {
                let input = input.trim();

                if input.is_empty() {
                    print!("> ");
                    io::stdout().flush()?;
                    continue;
                }

                // Send message
                match client.send_message(&peer, input).await {
                    Ok(_message_id) => {
                        // Create a local message to display immediately
                        let timestamp = chrono::Utc::now().timestamp() as u64;
                        let local_msg = DecryptedMessage {
                            sender: client.public_key_string(),
                            content: input.to_string(),
                            timestamp,
                            verified: true,
                        };

                        // Update state
                        let msg_hash = local_msg.timestamp ^ local_msg.sender.bytes().fold(0u64, |acc, b| acc.rotate_left(7) ^ b as u64);
                        chat_state.seen_timestamps.insert(msg_hash);
                        chat_state.messages.push(local_msg.clone());

                        // Display the sent message
                        print!("\x1B[1A\x1B[K"); // Move up and clear line
                        display_message(&local_msg, &client.public_key_string());
                        println!();
                    }
                    Err(e) => {
                        eprintln!("\nError sending message: {}", e);
                    }
                }

                print!("> ");
                io::stdout().flush()?;
            }

            // Poll for new messages
            _ = poll_timer.tick() => {
                match client.get_messages(&peer).await {
                    Ok(messages) => {
                        let mut new_messages = Vec::new();

                        for msg in messages {
                            let msg_hash = msg.timestamp ^ msg.sender.bytes().fold(0u64, |acc, b| acc.rotate_left(7) ^ b as u64);
                            if !chat_state.seen_timestamps.contains(&msg_hash) {
                                chat_state.seen_timestamps.insert(msg_hash);
                                chat_state.messages.push(msg.clone());

                                // Only display messages from the peer
                                if msg.sender != client.public_key_string() {
                                    new_messages.push(msg);
                                }
                            }
                        }

                        // Display new messages
                        if !new_messages.is_empty() {
                            print!("\r\x1B[K"); // Clear current line
                            for msg in new_messages {
                                display_message(&msg, &client.public_key_string());
                            }
                            print!("> ");
                            io::stdout().flush().ok();
                        }
                    }
                    Err(_) => {
                        // Silently ignore polling errors
                    }
                }
            }
        }
    }
}

fn display_message(msg: &DecryptedMessage, own_pubky: &str) {
    let is_own_message = msg.sender == own_pubky;
    let timestamp = chrono::DateTime::from_timestamp(msg.timestamp as i64, 0)
        .map(|dt| dt.format("%H:%M:%S").to_string())
        .unwrap_or_else(|| "??:??:??".to_string());

    if is_own_message {
        println!("[{}] You: {}", timestamp, msg.content);
    } else {
        let sender_short = if msg.sender.len() > 16 {
            format!("{}...", &msg.sender[..16])
        } else {
            msg.sender.clone()
        };
        println!("[{}] {}: {}", timestamp, sender_short, msg.content);
    }
}
