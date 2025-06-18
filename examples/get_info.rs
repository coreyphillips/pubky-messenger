use anyhow::Result;
use pubky_messenger::PrivateMessengerClient;
use std::env;
use std::io::{self, Write};

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <recovery_file_path>", args[0]);
        eprintln!("Example: {} recovery.pkarr", args[0]);
        std::process::exit(1);
    }

    let recovery_file_path = &args[1];

    print!("Enter passphrase: ");
    io::stdout().flush()?;
    let passphrase = rpassword::read_password()?;

    println!("Loading recovery file...");
    let recovery_file_bytes = std::fs::read(recovery_file_path)?;

    println!("Creating client...");
    let client = PrivateMessengerClient::from_recovery_file(&recovery_file_bytes, &passphrase)?;

    println!("Signing in to Pubky...");
    let session = client.sign_in().await?;
    println!("Signed in successfully!");
    println!("Session capabilities: {:?}", session.capabilities());

    // Get own public key
    let pubky = client.public_key_string();
    println!("\nMy Pubky ID: {}", pubky);

    // Get own profile information
    match client.get_own_profile().await? {
        Some(profile) => {
            println!("\nMy Profile:");
            println!("  Name: {}", profile.name);
            if let Some(bio) = profile.bio {
                println!("  Bio: {}", bio);
            }
            if let Some(image) = profile.image {
                println!("  Image: {}", image);
            }
            if let Some(status) = profile.status {
                println!("  Status: {}", status);
            }
        }
        None => {
            println!("\nNo profile found for this pubky");
        }
    }

    // Get followed users
    let followed_users = client.get_followed_users().await?;
    println!("\nFollowed Users: {}", followed_users.len());

    for user in followed_users {
        println!("\n  Pubky: {}", user.pubky);
        if let Some(name) = user.name {
            println!("  Name: {}", name);
        }
    }

    Ok(())
}
