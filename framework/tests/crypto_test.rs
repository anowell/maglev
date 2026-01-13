use maglev::crypto::{decrypt, encrypt, EncryptionKey};

fn test_key() -> EncryptionKey {
    EncryptionKey::try_from(&[0u8; 32][..]).unwrap()
}

fn another_test_key() -> EncryptionKey {
    EncryptionKey::try_from(&[1u8; 32][..]).unwrap()
}

#[tokio::test]
async fn encryption_roundtrip() {
    let key = test_key();
    let plaintext = "secret message";

    let ciphertext = encrypt(key.clone(), plaintext.to_string()).await.unwrap();
    let decrypted = decrypt(key, ciphertext).await.unwrap();

    assert_eq!(decrypted, plaintext);
}

#[tokio::test]
async fn wrong_key_fails_decryption() {
    let key1 = test_key();
    let key2 = another_test_key();

    let plaintext = "secret";
    let ciphertext = encrypt(key1, plaintext.to_string()).await.unwrap();

    assert!(decrypt(key2, ciphertext).await.is_err());
}

#[tokio::test]
async fn tampered_ciphertext_fails() {
    let key = test_key();
    let plaintext = "secret";

    let mut ciphertext = encrypt(key.clone(), plaintext.to_string()).await.unwrap();
    ciphertext[0] ^= 1; // Flip a bit

    assert!(decrypt(key, ciphertext).await.is_err());
}
