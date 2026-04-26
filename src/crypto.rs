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

// ── Streaming chunk encryption ──────────────────────────────────────

/// Plaintext chunk size for streaming transfers (256 KB).
pub const CHUNK_PLAINTEXT_SIZE: usize = 256 * 1024;
/// Poly1305 authentication tag overhead per chunk.
pub const CHUNK_TAG_SIZE: usize = 16;
/// Random nonce size for per-transfer key derivation.
pub const TRANSFER_NONCE_SIZE: usize = 32;
/// XChaCha20-Poly1305 nonce size.
const XCHACHA_NONCE_SIZE: usize = 24;

/// Derive a per-transfer symmetric key from X25519 shared secret.
///
/// Uses BLAKE3 derive_key with context string and:
///   shared_secret || sender_pk || recipient_pk || transfer_nonce
fn derive_transfer_key(
    sender_sk: &SecretKey,
    recipient_pk: &PublicKey,
    transfer_nonce: &[u8; TRANSFER_NONCE_SIZE],
) -> [u8; 32] {
    use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

    // Perform raw X25519 DH to get shared secret
    let sk_bytes = sender_sk.to_bytes();
    let static_secret = StaticSecret::from(sk_bytes);
    let x_pk = X25519Public::from(*recipient_pk.as_bytes());
    let shared_secret = static_secret.diffie_hellman(&x_pk);

    let sender_pk = sender_sk.public_key();

    // KDF input: shared_secret || sender_pk || recipient_pk || transfer_nonce
    let mut kdf_input = Vec::with_capacity(32 + 32 + 32 + TRANSFER_NONCE_SIZE);
    kdf_input.extend_from_slice(shared_secret.as_bytes());
    kdf_input.extend_from_slice(sender_pk.as_bytes());
    kdf_input.extend_from_slice(recipient_pk.as_bytes());
    kdf_input.extend_from_slice(transfer_nonce);

    blake3::derive_key("sendto.v1.transfer", &kdf_input)
}

/// Build a per-chunk nonce: chunk index in bytes 0..8, flags in byte 8, rest zero.
fn chunk_nonce(index: u64, is_final: bool) -> [u8; XCHACHA_NONCE_SIZE] {
    let mut nonce = [0u8; XCHACHA_NONCE_SIZE];
    nonce[0..8].copy_from_slice(&index.to_le_bytes());
    if is_final {
        nonce[8] = 0x01;
    }
    nonce
}

/// Streaming encryptor for chunked file transfers.
///
/// Encrypts fixed-size plaintext chunks using XChaCha20-Poly1305 with a
/// per-transfer key derived from X25519 + BLAKE3 KDF.
pub struct StreamEncryptor {
    key: chacha20poly1305::Key,
    transfer_nonce: [u8; TRANSFER_NONCE_SIZE],
    chunk_index: u64,
}

impl StreamEncryptor {
    /// Create a new encryptor with a fresh random transfer nonce.
    pub fn new(sender_sk: &SecretKey, recipient_pk: &PublicKey) -> Self {
        use rand::RngCore;
        let mut transfer_nonce = [0u8; TRANSFER_NONCE_SIZE];
        OsRng.fill_bytes(&mut transfer_nonce);

        let key_bytes = derive_transfer_key(sender_sk, recipient_pk, &transfer_nonce);
        let key = chacha20poly1305::Key::from(key_bytes);

        Self {
            key,
            transfer_nonce,
            chunk_index: 0,
        }
    }

    /// The random transfer nonce (sent to receiver for key derivation).
    pub fn transfer_nonce(&self) -> &[u8; TRANSFER_NONCE_SIZE] {
        &self.transfer_nonce
    }

    /// Encrypt one chunk. Set `is_final` to true on the last chunk.
    ///
    /// Returns the ciphertext (plaintext.len() + 16 bytes).
    pub fn encrypt_chunk(
        &mut self,
        plaintext: &[u8],
        is_final: bool,
    ) -> Result<Vec<u8>, CryptoError> {
        use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};

        let nonce_bytes = chunk_nonce(self.chunk_index, is_final);
        let nonce = XNonce::from_slice(&nonce_bytes);
        let cipher = XChaCha20Poly1305::new(&self.key);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| CryptoError::EncryptionFailed)?;

        self.chunk_index += 1;
        Ok(ciphertext)
    }
}

/// Streaming decryptor for chunked file transfers.
pub struct StreamDecryptor {
    key: chacha20poly1305::Key,
    chunk_index: u64,
}

impl StreamDecryptor {
    /// Create a decryptor from the sender's public key, recipient's secret key,
    /// and the transfer nonce received from the sender.
    pub fn new(
        recipient_sk: &SecretKey,
        sender_pk: &PublicKey,
        transfer_nonce: &[u8; TRANSFER_NONCE_SIZE],
    ) -> Self {
        // The KDF must produce the same key as the encryptor.
        // The encryptor calls derive_transfer_key(sender_sk, recipient_pk, nonce).
        // X25519 DH is commutative: sender_sk * recipient_pk == recipient_sk * sender_pk.
        // But our KDF also includes sender_pk || recipient_pk in the input.
        // So we must pass the keys in the SAME order as the sender did.
        //
        // The sender called: derive_transfer_key(sender_sk, recipient_pk, nonce)
        //   which internally does: sender_sk DH recipient_pk, then hashes with sender_pk || recipient_pk
        //
        // The receiver must reconstruct the same KDF input, so we need
        // the sender's public key as the "recipient" for DH (gives same shared secret),
        // but we must reconstruct the same pk ordering in the hash.
        //
        // We'll use a separate derivation that takes explicit pks.
        let key_bytes = derive_transfer_key_for_receiver(recipient_sk, sender_pk, transfer_nonce);
        let key = chacha20poly1305::Key::from(key_bytes);

        Self {
            key,
            chunk_index: 0,
        }
    }

    /// Decrypt one chunk. Returns `(plaintext, is_final)`.
    pub fn decrypt_chunk(&mut self, ciphertext: &[u8]) -> Result<(Vec<u8>, bool), CryptoError> {
        use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};

        let cipher = XChaCha20Poly1305::new(&self.key);

        // Try decrypting as non-final chunk first
        let nonce_bytes = chunk_nonce(self.chunk_index, false);
        let nonce = XNonce::from_slice(&nonce_bytes);

        if let Ok(plaintext) = cipher.decrypt(nonce, ciphertext) {
            self.chunk_index += 1;
            return Ok((plaintext, false));
        }

        // Try as final chunk
        let nonce_bytes = chunk_nonce(self.chunk_index, true);
        let nonce = XNonce::from_slice(&nonce_bytes);

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| CryptoError::DecryptionFailed)?;

        self.chunk_index += 1;
        Ok((plaintext, true))
    }
}

/// Derive transfer key from the receiver's perspective.
///
/// The KDF input must match the sender's: shared_secret || sender_pk || recipient_pk || nonce.
/// Since DH is commutative, recipient_sk * sender_pk == sender_sk * recipient_pk.
fn derive_transfer_key_for_receiver(
    recipient_sk: &SecretKey,
    sender_pk: &PublicKey,
    transfer_nonce: &[u8; TRANSFER_NONCE_SIZE],
) -> [u8; 32] {
    use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

    let sk_bytes = recipient_sk.to_bytes();
    let static_secret = StaticSecret::from(sk_bytes);
    let x_pk = X25519Public::from(*sender_pk.as_bytes());
    let shared_secret = static_secret.diffie_hellman(&x_pk);

    let recipient_pk = recipient_sk.public_key();

    // MUST match sender's ordering: sender_pk || recipient_pk
    let mut kdf_input = Vec::with_capacity(32 + 32 + 32 + TRANSFER_NONCE_SIZE);
    kdf_input.extend_from_slice(shared_secret.as_bytes());
    kdf_input.extend_from_slice(sender_pk.as_bytes());
    kdf_input.extend_from_slice(recipient_pk.as_bytes());
    kdf_input.extend_from_slice(transfer_nonce);

    blake3::derive_key("sendto.v1.transfer", &kdf_input)
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
    fn test_stream_encrypt_decrypt_roundtrip() {
        let sender = KeyPair::generate();
        let recipient = KeyPair::generate();

        let plaintext = b"Hello, streaming world!";
        let mut encryptor = StreamEncryptor::new(&sender.secret_key, &recipient.public_key);
        let transfer_nonce = *encryptor.transfer_nonce();

        let ciphertext = encryptor.encrypt_chunk(plaintext, true).unwrap();

        let mut decryptor =
            StreamDecryptor::new(&recipient.secret_key, &sender.public_key, &transfer_nonce);

        let (decrypted, is_final) = decryptor.decrypt_chunk(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
        assert!(is_final);
    }

    #[test]
    fn test_stream_multi_chunk_roundtrip() {
        let sender = KeyPair::generate();
        let recipient = KeyPair::generate();

        // Create a payload larger than one chunk
        let plaintext: Vec<u8> = (0..CHUNK_PLAINTEXT_SIZE * 3 + 42)
            .map(|i| (i % 256) as u8)
            .collect();

        let mut encryptor = StreamEncryptor::new(&sender.secret_key, &recipient.public_key);
        let transfer_nonce = *encryptor.transfer_nonce();

        // Encrypt in chunks
        let mut ciphertexts = Vec::new();
        let mut offset = 0;
        while offset < plaintext.len() {
            let end = (offset + CHUNK_PLAINTEXT_SIZE).min(plaintext.len());
            let is_final = end == plaintext.len();
            let ct = encryptor
                .encrypt_chunk(&plaintext[offset..end], is_final)
                .unwrap();
            ciphertexts.push(ct);
            offset = end;
        }
        assert_eq!(ciphertexts.len(), 4); // 3 full chunks + 1 partial

        // Decrypt
        let mut decryptor =
            StreamDecryptor::new(&recipient.secret_key, &sender.public_key, &transfer_nonce);

        let mut decrypted = Vec::new();
        let mut saw_final = false;
        for ct in &ciphertexts {
            let (chunk, is_final) = decryptor.decrypt_chunk(ct).unwrap();
            decrypted.extend_from_slice(&chunk);
            if is_final {
                saw_final = true;
            }
        }

        assert_eq!(decrypted, plaintext);
        assert!(saw_final);
    }

    #[test]
    fn test_stream_empty_chunk() {
        let sender = KeyPair::generate();
        let recipient = KeyPair::generate();

        let mut encryptor = StreamEncryptor::new(&sender.secret_key, &recipient.public_key);
        let transfer_nonce = *encryptor.transfer_nonce();

        let ciphertext = encryptor.encrypt_chunk(b"", true).unwrap();
        assert_eq!(ciphertext.len(), CHUNK_TAG_SIZE); // just the tag

        let mut decryptor =
            StreamDecryptor::new(&recipient.secret_key, &sender.public_key, &transfer_nonce);

        let (decrypted, is_final) = decryptor.decrypt_chunk(&ciphertext).unwrap();
        assert!(decrypted.is_empty());
        assert!(is_final);
    }

    #[test]
    fn test_stream_wrong_key_fails() {
        let sender = KeyPair::generate();
        let recipient = KeyPair::generate();
        let wrong = KeyPair::generate();

        let mut encryptor = StreamEncryptor::new(&sender.secret_key, &recipient.public_key);
        let transfer_nonce = *encryptor.transfer_nonce();
        let ciphertext = encryptor.encrypt_chunk(b"secret", true).unwrap();

        let mut decryptor =
            StreamDecryptor::new(&wrong.secret_key, &sender.public_key, &transfer_nonce);

        assert!(decryptor.decrypt_chunk(&ciphertext).is_err());
    }

    #[test]
    fn test_stream_exactly_one_chunk() {
        let sender = KeyPair::generate();
        let recipient = KeyPair::generate();

        let plaintext = vec![0xABu8; CHUNK_PLAINTEXT_SIZE];
        let mut encryptor = StreamEncryptor::new(&sender.secret_key, &recipient.public_key);
        let transfer_nonce = *encryptor.transfer_nonce();

        let ct = encryptor.encrypt_chunk(&plaintext, true).unwrap();
        assert_eq!(ct.len(), CHUNK_PLAINTEXT_SIZE + CHUNK_TAG_SIZE);

        let mut decryptor =
            StreamDecryptor::new(&recipient.secret_key, &sender.public_key, &transfer_nonce);
        let (dec, is_final) = decryptor.decrypt_chunk(&ct).unwrap();
        assert_eq!(dec, plaintext);
        assert!(is_final);
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
