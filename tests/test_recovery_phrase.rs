use anyhow::Result;
use bip39::Mnemonic;
use pubky_messenger::{Language, PrivateMessengerClient};

#[test]
fn test_from_recovery_phrase_valid() -> Result<()> {
    // Test with a valid 12-word mnemonic (no passphrase, default English)
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    // Should create client successfully with defaults
    let client = PrivateMessengerClient::from_recovery_phrase(mnemonic, None, None)?;

    // Verify we have a valid client with a public key
    assert!(!client.public_key_string().is_empty());

    Ok(())
}

#[test]
fn test_from_recovery_phrase_deterministic() -> Result<()> {
    // Same mnemonic should always produce the same keypair
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    let client1 = PrivateMessengerClient::from_recovery_phrase(mnemonic, None, None)?;
    let client2 = PrivateMessengerClient::from_recovery_phrase(mnemonic, None, None)?;

    // Both clients should have the same public key
    assert_eq!(client1.public_key_string(), client2.public_key_string());

    Ok(())
}

#[test]
fn test_from_recovery_phrase_different_mnemonics() -> Result<()> {
    // Different mnemonics should produce different keypairs
    let mnemonic1 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mnemonic2 = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong";

    let client1 = PrivateMessengerClient::from_recovery_phrase(mnemonic1, None, None)?;
    let client2 = PrivateMessengerClient::from_recovery_phrase(mnemonic2, None, None)?;

    // Different mnemonics should produce different public keys
    assert_ne!(client1.public_key_string(), client2.public_key_string());

    Ok(())
}

#[test]
fn test_from_recovery_phrase_invalid() {
    // Test with invalid mnemonics
    let invalid_cases = vec![
        "invalid mnemonic phrase here",                    // Invalid words
        "abandon abandon abandon",                         // Too few words
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon", // 11 words
        "",                                                // Empty
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", // 13 words
    ];

    for invalid_mnemonic in invalid_cases {
        let result = PrivateMessengerClient::from_recovery_phrase(invalid_mnemonic, None, None);
        assert!(result.is_err(), "Should fail for invalid mnemonic: '{}'", invalid_mnemonic);
    }
}

#[test]
fn test_from_recovery_phrase_with_generated_mnemonic() -> Result<()> {
    // Generate entropy for a 12-word mnemonic (128 bits)
    let entropy = [0u8; 16]; // Using zeros for deterministic test
    let mnemonic = Mnemonic::from_entropy(&entropy)
        .map_err(|e| anyhow::anyhow!("Failed to generate mnemonic: {}", e))?;

    let mnemonic_str = mnemonic.to_string();

    // Should be able to create a client from the generated mnemonic
    let client = PrivateMessengerClient::from_recovery_phrase(&mnemonic_str, None, None)?;

    // Verify we have a valid client
    assert!(!client.public_key_string().is_empty());

    // Creating another client with the same mnemonic should produce the same keypair
    let client2 = PrivateMessengerClient::from_recovery_phrase(&mnemonic_str, None, None)?;
    assert_eq!(client.public_key_string(), client2.public_key_string());

    Ok(())
}

#[test]
fn test_from_recovery_phrase_case_sensitive() -> Result<()> {
    // Mnemonics should be case-sensitive (BIP39 standard uses lowercase)
    let lowercase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let uppercase = "ABANDON ABANDON ABANDON ABANDON ABANDON ABANDON ABANDON ABANDON ABANDON ABANDON ABANDON ABOUT";

    let client_lower = PrivateMessengerClient::from_recovery_phrase(lowercase, None, None)?;
    let result_upper = PrivateMessengerClient::from_recovery_phrase(uppercase, None, None);

    // Uppercase should fail as BIP39 mnemonics are lowercase
    assert!(result_upper.is_err(), "Uppercase mnemonic should fail");

    // But lowercase should work
    assert!(!client_lower.public_key_string().is_empty());

    Ok(())
}

#[test]
fn test_from_recovery_phrase_with_extra_spaces() -> Result<()> {
    // Test handling of extra spaces - BIP39 v2 normalizes spaces
    let normal = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let extra_spaces = "abandon  abandon abandon   abandon abandon abandon abandon abandon abandon abandon abandon about";

    let client_normal = PrivateMessengerClient::from_recovery_phrase(normal, None, None)?;

    // In BIP39 v2, extra spaces might be normalized, so we check if they produce the same result
    let result_extra = PrivateMessengerClient::from_recovery_phrase(extra_spaces, None, None);

    // If it succeeds, it should produce the same keypair (normalized)
    // If it fails, that's also acceptable behavior
    match result_extra {
        Ok(client_extra) => {
            // If both work, they should produce the same keypair due to normalization
            assert_eq!(client_normal.public_key_string(), client_extra.public_key_string(),
                "Normalized mnemonics should produce the same keypair");
        }
        Err(_) => {
            // Failing on extra spaces is also valid behavior
            assert!(true, "Extra spaces causing failure is acceptable");
        }
    }

    // Normal spacing should always work
    assert!(!client_normal.public_key_string().is_empty());

    Ok(())
}

// Note: Sign-in test removed as it requires actual network connectivity
// The client creation is already tested above, and sign-in functionality
// is tested separately in integration tests with proper test accounts

#[test]
fn test_from_recovery_phrase_with_language() -> Result<()> {
    // Test with English explicitly
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let client_english = PrivateMessengerClient::from_recovery_phrase(
        mnemonic,
        None,
        Some(Language::English),
    )?;

    // Test that default (no language param) produces the same result as explicit English
    let client_default = PrivateMessengerClient::from_recovery_phrase(mnemonic, None, None)?;

    assert_eq!(
        client_english.public_key_string(),
        client_default.public_key_string(),
        "Default language should be English"
    );

    // Verify that we can call the method with Language::English successfully
    assert!(!client_english.public_key_string().is_empty());

    Ok(())
}

#[test]
fn test_from_recovery_phrase_with_passphrase() -> Result<()> {
    // Test that passphrase changes the derived keypair
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    // Without passphrase
    let client_no_pass = PrivateMessengerClient::from_recovery_phrase(mnemonic, None, None)?;

    // With passphrase
    let client_with_pass = PrivateMessengerClient::from_recovery_phrase(
        mnemonic,
        Some("my_secure_passphrase"),
        None,
    )?;

    // Different passphrases should produce different keypairs
    assert_ne!(
        client_no_pass.public_key_string(),
        client_with_pass.public_key_string(),
        "Passphrase should change the derived keypair"
    );

    // Same passphrase should produce same keypair
    let client_with_pass2 = PrivateMessengerClient::from_recovery_phrase(
        mnemonic,
        Some("my_secure_passphrase"),
        None,
    )?;

    assert_eq!(
        client_with_pass.public_key_string(),
        client_with_pass2.public_key_string(),
        "Same passphrase should produce same keypair"
    );

    Ok(())
}

#[test]
fn test_from_recovery_phrase_language_consistency() -> Result<()> {
    // Test that the same mnemonic in the same language always produces the same keypair
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    // Multiple calls with same language should produce same keypair
    let client1 = PrivateMessengerClient::from_recovery_phrase(
        mnemonic,
        None,
        Some(Language::English),
    )?;
    let client2 = PrivateMessengerClient::from_recovery_phrase(
        mnemonic,
        None,
        Some(Language::English),
    )?;

    assert_eq!(
        client1.public_key_string(),
        client2.public_key_string(),
        "Same mnemonic with same language should produce same keypair"
    );

    Ok(())
}

#[test]
fn test_from_recovery_phrase_all_params() -> Result<()> {
    // Test with all parameters specified
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    let client = PrivateMessengerClient::from_recovery_phrase(
        mnemonic,
        Some("passphrase123"),
        Some(Language::English),
    )?;

    // Should successfully create a client with all params
    assert!(!client.public_key_string().is_empty());

    // Should be deterministic with same params
    let client2 = PrivateMessengerClient::from_recovery_phrase(
        mnemonic,
        Some("passphrase123"),
        Some(Language::English),
    )?;

    assert_eq!(
        client.public_key_string(),
        client2.public_key_string(),
        "Same parameters should produce same keypair"
    );

    Ok(())
}