//! Cryptographic operations for SendTo.
//!
//! Uses NaCl crypto_box (X25519 + XSalsa20-Poly1305) for authenticated
//! public-key encryption. This is compatible across Rust, JavaScript, and Python.

use crypto_box::{
    aead::{Aead, AeadCore, OsRng},
    Nonce, PublicKey, SalsaBox, SecretKey,
};
use thiserror::Error;

pub const PUBLIC_KEY_SIZE: usize = 32;
pub const SECRET_KEY_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 24;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Decryption failed (wrong key or corrupted data)")]
    DecryptionFailed,
    #[error("Invalid public key: expected {PUBLIC_KEY_SIZE} bytes, got {0}")]
    InvalidPublicKey(usize),
    #[error("Invalid secret key: expected {SECRET_KEY_SIZE} bytes, got {0}")]
    InvalidSecretKey(usize),
    #[error("Invalid nonce: expected {NONCE_SIZE} bytes, got {0}")]
    InvalidNonce(usize),
    #[error("Metadata serialization error: {0}")]
    MetadataError(String),
}

#[derive(Clone)]
pub struct KeyPair {
    pub public_key: PublicKey,
    pub secret_key: SecretKey,
}

impl KeyPair {
    pub fn generate() -> Self {
        let secret_key = SecretKey::generate(&mut OsRng);
        let public_key = secret_key.public_key();
        Self {
            public_key,
            secret_key,
        }
    }

    pub fn from_bytes(
        public_key_bytes: &[u8],
        secret_key_bytes: &[u8],
    ) -> Result<Self, CryptoError> {
        let public_key = public_key_from_bytes(public_key_bytes)?;
        let secret_key = secret_key_from_bytes(secret_key_bytes)?;
        Ok(Self {
            public_key,
            secret_key,
        })
    }

    pub fn public_key_bytes(&self) -> &[u8; PUBLIC_KEY_SIZE] {
        self.public_key.as_bytes()
    }

    pub fn secret_key_bytes(&self) -> [u8; SECRET_KEY_SIZE] {
        self.secret_key.to_bytes()
    }
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPair")
            .field("public_key", &hex_encode(self.public_key.as_bytes()))
            .field("secret_key", &"[REDACTED]")
            .finish()
    }
}

pub struct EncryptedData {
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; NONCE_SIZE],
}

pub fn encrypt(
    plaintext: &[u8],
    recipient_public_key: &PublicKey,
    sender_secret_key: &SecretKey,
) -> Result<EncryptedData, CryptoError> {
    let salsa_box = SalsaBox::new(recipient_public_key, sender_secret_key);
    let nonce = SalsaBox::generate_nonce(&mut OsRng);

    let ciphertext = salsa_box
        .encrypt(&nonce, plaintext)
        .map_err(|_| CryptoError::EncryptionFailed)?;

    Ok(EncryptedData {
        ciphertext,
        nonce: nonce.into(),
    })
}

pub fn decrypt(
    ciphertext: &[u8],
    nonce: &[u8],
    sender_public_key: &PublicKey,
    recipient_secret_key: &SecretKey,
) -> Result<Vec<u8>, CryptoError> {
    if nonce.len() != NONCE_SIZE {
        return Err(CryptoError::InvalidNonce(nonce.len()));
    }
    let nonce = Nonce::from_slice(nonce);
    let salsa_box = SalsaBox::new(sender_public_key, recipient_secret_key);

    salsa_box
        .decrypt(nonce, ciphertext)
        .map_err(|_| CryptoError::DecryptionFailed)
}

pub fn encrypt_metadata(
    metadata: &crate::types::FileMetadata,
    recipient_public_key: &PublicKey,
    sender_secret_key: &SecretKey,
) -> Result<EncryptedData, CryptoError> {
    let json =
        serde_json::to_vec(metadata).map_err(|e| CryptoError::MetadataError(e.to_string()))?;
    encrypt(&json, recipient_public_key, sender_secret_key)
}

pub fn decrypt_metadata(
    ciphertext: &[u8],
    nonce: &[u8],
    sender_public_key: &PublicKey,
    recipient_secret_key: &SecretKey,
) -> Result<crate::types::FileMetadata, CryptoError> {
    let plaintext = decrypt(ciphertext, nonce, sender_public_key, recipient_secret_key)?;
    serde_json::from_slice(&plaintext).map_err(|e| CryptoError::MetadataError(e.to_string()))
}

pub fn public_key_from_bytes(bytes: &[u8]) -> Result<PublicKey, CryptoError> {
    if bytes.len() != PUBLIC_KEY_SIZE {
        return Err(CryptoError::InvalidPublicKey(bytes.len()));
    }
    let mut arr = [0u8; PUBLIC_KEY_SIZE];
    arr.copy_from_slice(bytes);
    Ok(PublicKey::from(arr))
}

pub fn secret_key_from_bytes(bytes: &[u8]) -> Result<SecretKey, CryptoError> {
    if bytes.len() != SECRET_KEY_SIZE {
        return Err(CryptoError::InvalidSecretKey(bytes.len()));
    }
    let mut arr = [0u8; SECRET_KEY_SIZE];
    arr.copy_from_slice(bytes);
    Ok(SecretKey::from(arr))
}

pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn hex_decode(s: &str) -> Result<Vec<u8>, CryptoError> {
    if s.len() % 2 != 0 {
        return Err(CryptoError::InvalidPublicKey(s.len() / 2));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|_| CryptoError::InvalidPublicKey(s.len() / 2))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let kp = KeyPair::generate();
        assert_eq!(kp.public_key_bytes().len(), PUBLIC_KEY_SIZE);
        assert_eq!(kp.secret_key_bytes().len(), SECRET_KEY_SIZE);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let sender = KeyPair::generate();
        let recipient = KeyPair::generate();

        let plaintext = b"Hello, SendTo!";
        let encrypted = encrypt(plaintext, &recipient.public_key, &sender.secret_key).unwrap();

        let decrypted = decrypt(
            &encrypted.ciphertext,
            &encrypted.nonce,
            &sender.public_key,
            &recipient.secret_key,
        )
        .unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_with_wrong_key_fails() {
        let sender = KeyPair::generate();
        let recipient = KeyPair::generate();
        let wrong = KeyPair::generate();

        let plaintext = b"Secret data";
        let encrypted = encrypt(plaintext, &recipient.public_key, &sender.secret_key).unwrap();

        let result = decrypt(
            &encrypted.ciphertext,
            &encrypted.nonce,
            &sender.public_key,
            &wrong.secret_key,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_decrypt_large_payload() {
        let sender = KeyPair::generate();
        let recipient = KeyPair::generate();

        let plaintext: Vec<u8> = (0..1_000_000).map(|i| (i % 256) as u8).collect();
        let encrypted = encrypt(&plaintext, &recipient.public_key, &sender.secret_key).unwrap();

        let decrypted = decrypt(
            &encrypted.ciphertext,
            &encrypted.nonce,
            &sender.public_key,
            &recipient.secret_key,
        )
        .unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_empty_payload() {
        let sender = KeyPair::generate();
        let recipient = KeyPair::generate();

        let plaintext = b"";
        let encrypted = encrypt(plaintext, &recipient.public_key, &sender.secret_key).unwrap();

        let decrypted = decrypt(
            &encrypted.ciphertext,
            &encrypted.nonce,
            &sender.public_key,
            &recipient.secret_key,
        )
        .unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_metadata_encrypt_decrypt() {
        let sender = KeyPair::generate();
        let recipient = KeyPair::generate();

        let metadata = crate::types::FileMetadata {
            filename: "report.pdf".into(),
            mime: "application/pdf".into(),
            size: 52_428_800,
        };

        let encrypted =
            encrypt_metadata(&metadata, &recipient.public_key, &sender.secret_key).unwrap();

        let decrypted = decrypt_metadata(
            &encrypted.ciphertext,
            &encrypted.nonce,
            &sender.public_key,
            &recipient.secret_key,
        )
        .unwrap();

        assert_eq!(decrypted.filename, metadata.filename);
        assert_eq!(decrypted.mime, metadata.mime);
        assert_eq!(decrypted.size, metadata.size);
    }

    #[test]
    fn test_keypair_from_bytes_roundtrip() {
        let original = KeyPair::generate();

        let restored =
            KeyPair::from_bytes(original.public_key_bytes(), &original.secret_key_bytes()).unwrap();

        assert_eq!(
            restored.public_key.as_bytes(),
            original.public_key.as_bytes()
        );
        assert_eq!(
            restored.secret_key.to_bytes(),
            original.secret_key.to_bytes()
        );
    }

    #[test]
    fn test_hex_roundtrip() {
        let bytes = vec![0x00, 0x01, 0xAB, 0xCD, 0xEF, 0xFF];
        let hex = hex_encode(&bytes);
        assert_eq!(hex, "0001abcdefff");
        let decoded = hex_decode(&hex).unwrap();
        assert_eq!(decoded, bytes);
    }
}
