//! What the pubky 0.4 releases wrote still opens on this one.
//!
//! The DM storage path and the message cipher are pinned by the fixture tests in `src/crypto.rs`
//! and `tests/integration_test.rs`, which this release did not change. This pins the recovery
//! files.

use pubky_messenger::PrivateMessengerClient;

/// `p1.pkarr` and `p2.pkarr` were written by the 0.4 stack. These are the keys release 0.4.0
/// (`4fff0ce`) derives from them with passphrase `password`, in the bare z32 form that DM paths,
/// peer ids and swap authorizations use.
#[test]
fn recovery_files_from_the_0_4_stack_open_to_the_same_keys() {
    for (file, key) in [
        (
            "p1.pkarr",
            "w5ux3c55ujxq7rpb6x9z9wo554s4eb4zeuh1933b94zk7qsfxd1o",
        ),
        (
            "p2.pkarr",
            "ssffc7wiswjzdtt7nw93fa9wy9bus34puyy39giityofcibh9qny",
        ),
    ] {
        let bytes = std::fs::read(file).unwrap();
        let client = PrivateMessengerClient::from_recovery_file(&bytes, Some("password")).unwrap();
        assert_eq!(client.public_key_string(), key, "{file}");
        assert_eq!(client.public_key().to_string(), key, "{file}");
    }
}
