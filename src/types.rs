//! Core domain and envelope types shared between hosted service and clients.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    #[serde(with = "hex_bytes")]
    pub public_key: Vec<u8>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceType {
    Device,
    Agent,
}

impl Default for DeviceType {
    fn default() -> Self {
        Self::Device
    }
}

impl std::fmt::Display for DeviceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Device => write!(f, "device"),
            Self::Agent => write!(f, "agent"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MessageStatus {
    Queued,
    Delivered,
    Expired,
}

impl std::fmt::Display for MessageStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Queued => write!(f, "queued"),
            Self::Delivered => write!(f, "delivered"),
            Self::Expired => write!(f, "expired"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub id: Uuid,
    pub sender_device_id: Option<Uuid>,
    pub recipient_device_id: Uuid,
    pub size_bytes: i64,
    pub status: MessageStatus,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMetadata {
    pub filename: String,
    pub mime: String,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedEnvelope {
    #[serde(with = "hex_bytes")]
    pub ciphertext: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub nonce: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub encrypted_metadata: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub metadata_nonce: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub sender_public_key: Vec<u8>,
}

pub fn validate_device_name(name: &str) -> Result<(), &'static str> {
    if name.is_empty() || name.len() > 32 {
        return Err("Device name must be 1-32 characters");
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err("Device name must contain only lowercase letters, digits, and hyphens");
    }
    if name.starts_with('-') || name.ends_with('-') {
        return Err("Device name must not start or end with a hyphen");
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboxMetaFile {
    pub message_id: Uuid,
    pub sender: String,
    pub filename: String,
    pub size_bytes: u64,
    pub timestamp: DateTime<Utc>,
}

// ── Chunked blob wire format ───────────────────────────────────────

/// Magic bytes for the blob prologue.
pub const BLOB_MAGIC: &[u8; 4] = b"ST02";
pub const BLOB_VERSION: u8 = 2;
pub const BLOB_ALGORITHM_ID: u8 = 2;
/// Magic bytes for the blob trailer.
pub const TRAILER_MAGIC: &[u8; 4] = b"STTR";
/// Prologue size in bytes.
pub const BLOB_PROLOGUE_SIZE: usize = 40;
/// Trailer size in bytes (4 magic + 4 total_chunks + 8 plaintext_size + 32 hash).
pub const BLOB_TRAILER_SIZE: usize = 48;

/// Fixed-size binary prologue for a chunked encrypted blob.
#[derive(Debug, Clone, PartialEq)]
pub struct BlobPrologue {
    pub version: u8,
    pub algorithm_id: u8,
    pub chunk_plaintext_size: u32,
    pub known_plaintext_size: u64,
}

impl BlobPrologue {
    pub fn to_bytes(&self) -> [u8; BLOB_PROLOGUE_SIZE] {
        let mut buf = [0u8; BLOB_PROLOGUE_SIZE];
        buf[0..4].copy_from_slice(BLOB_MAGIC);
        buf[4] = self.version;
        buf[5] = self.algorithm_id;
        // bytes 6..8 reserved
        buf[8..12].copy_from_slice(&self.chunk_plaintext_size.to_be_bytes());
        // bytes 12..16 reserved
        buf[16..24].copy_from_slice(&self.known_plaintext_size.to_be_bytes());
        // bytes 24..40 reserved
        buf
    }

    pub fn from_bytes(buf: &[u8; BLOB_PROLOGUE_SIZE]) -> Result<Self, &'static str> {
        if &buf[0..4] != BLOB_MAGIC {
            return Err("Invalid blob magic");
        }
        let version = buf[4];
        if version != BLOB_VERSION {
            return Err("Unsupported blob version");
        }
        let algorithm_id = buf[5];
        if algorithm_id != BLOB_ALGORITHM_ID {
            return Err("Unsupported algorithm");
        }
        let chunk_plaintext_size = u32::from_be_bytes(buf[8..12].try_into().unwrap());
        let known_plaintext_size = u64::from_be_bytes(buf[16..24].try_into().unwrap());

        Ok(Self {
            version,
            algorithm_id,
            chunk_plaintext_size,
            known_plaintext_size,
        })
    }
}

/// Fixed-size binary trailer appended after all chunk frames.
#[derive(Debug, Clone, PartialEq)]
pub struct BlobTrailer {
    pub total_chunks: u32,
    pub total_plaintext_size: u64,
    pub file_hash: [u8; 32],
}

impl BlobTrailer {
    pub fn to_bytes(&self) -> [u8; BLOB_TRAILER_SIZE] {
        let mut buf = [0u8; BLOB_TRAILER_SIZE];
        buf[0..4].copy_from_slice(TRAILER_MAGIC);
        buf[4..8].copy_from_slice(&self.total_chunks.to_be_bytes());
        buf[8..16].copy_from_slice(&self.total_plaintext_size.to_be_bytes());
        buf[16..48].copy_from_slice(&self.file_hash);
        buf
    }

    /// Parse from a full 48-byte buffer.
    pub fn from_bytes(buf: &[u8; BLOB_TRAILER_SIZE]) -> Result<Self, &'static str> {
        if &buf[0..4] != TRAILER_MAGIC {
            return Err("Invalid trailer magic");
        }
        let total_chunks = u32::from_be_bytes(buf[4..8].try_into().unwrap());
        let total_plaintext_size = u64::from_be_bytes(buf[8..16].try_into().unwrap());
        let mut file_hash = [0u8; 32];
        file_hash.copy_from_slice(&buf[16..48]);

        Ok(Self {
            total_chunks,
            total_plaintext_size,
            file_hash,
        })
    }

    /// Parse when the first 4 bytes (trailer magic) have already been read.
    pub fn from_remaining(magic: &[u8; 4], rest: &[u8; 44]) -> Result<Self, &'static str> {
        if magic != TRAILER_MAGIC {
            return Err("Invalid trailer magic");
        }
        let total_chunks = u32::from_be_bytes(rest[0..4].try_into().unwrap());
        let total_plaintext_size = u64::from_be_bytes(rest[4..12].try_into().unwrap());
        let mut file_hash = [0u8; 32];
        file_hash.copy_from_slice(&rest[12..44]);

        Ok(Self {
            total_chunks,
            total_plaintext_size,
            file_hash,
        })
    }
}

mod hex_bytes {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let hex_string = hex_encode(bytes);
        serializer.serialize_str(&hex_string)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        hex_decode(&s).map_err(serde::de::Error::custom)
    }

    fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
        if s.len() % 2 != 0 {
            return Err("Hex string must have even length".to_string());
        }
        (0..s.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&s[i..i + 2], 16)
                    .map_err(|e| format!("Invalid hex at position {i}: {e}"))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_device_name() {
        assert!(validate_device_name("my-laptop").is_ok());
        assert!(validate_device_name("desktop01").is_ok());
        assert!(validate_device_name("a").is_ok());

        assert!(validate_device_name("").is_err());
        assert!(validate_device_name("My-Laptop").is_err());
        assert!(validate_device_name("-leading").is_err());
        assert!(validate_device_name("trailing-").is_err());
        assert!(validate_device_name("has space").is_err());
        assert!(validate_device_name("has_underscore").is_err());
    }

    #[test]
    fn test_message_status_display() {
        assert_eq!(MessageStatus::Queued.to_string(), "queued");
        assert_eq!(MessageStatus::Delivered.to_string(), "delivered");
        assert_eq!(MessageStatus::Expired.to_string(), "expired");
    }

    #[test]
    fn test_blob_prologue_roundtrip() {
        let prologue = BlobPrologue {
            version: BLOB_VERSION,
            algorithm_id: BLOB_ALGORITHM_ID,
            chunk_plaintext_size: 262144,
            known_plaintext_size: 1_000_000,
        };
        let bytes = prologue.to_bytes();
        assert_eq!(&bytes[0..4], BLOB_MAGIC);
        let parsed = BlobPrologue::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, prologue);
    }

    #[test]
    fn test_blob_prologue_bad_magic() {
        let mut bytes = [0u8; BLOB_PROLOGUE_SIZE];
        bytes[0..4].copy_from_slice(b"XXXX");
        assert!(BlobPrologue::from_bytes(&bytes).is_err());
    }

    #[test]
    fn test_blob_prologue_rejects_v1_magic() {
        let mut bytes = BlobPrologue {
            version: BLOB_VERSION,
            algorithm_id: BLOB_ALGORITHM_ID,
            chunk_plaintext_size: 262144,
            known_plaintext_size: 1_000_000,
        }
        .to_bytes();
        bytes[0..4].copy_from_slice(b"ST01");
        assert!(BlobPrologue::from_bytes(&bytes).is_err());
    }

    #[test]
    fn test_blob_prologue_rejects_old_version_and_algorithm() {
        let mut bytes = BlobPrologue {
            version: BLOB_VERSION,
            algorithm_id: BLOB_ALGORITHM_ID,
            chunk_plaintext_size: 262144,
            known_plaintext_size: 1_000_000,
        }
        .to_bytes();
        bytes[4] = 1;
        assert!(BlobPrologue::from_bytes(&bytes).is_err());

        let mut bytes = BlobPrologue {
            version: BLOB_VERSION,
            algorithm_id: BLOB_ALGORITHM_ID,
            chunk_plaintext_size: 262144,
            known_plaintext_size: 1_000_000,
        }
        .to_bytes();
        bytes[5] = 1;
        assert!(BlobPrologue::from_bytes(&bytes).is_err());
    }

    #[test]
    fn test_blob_trailer_roundtrip() {
        let trailer = BlobTrailer {
            total_chunks: 42,
            total_plaintext_size: 11_000_000,
            file_hash: [0xAB; 32],
        };
        let bytes = trailer.to_bytes();
        assert_eq!(&bytes[0..4], TRAILER_MAGIC);
        let parsed = BlobTrailer::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, trailer);
    }

    #[test]
    fn test_blob_trailer_from_remaining() {
        let trailer = BlobTrailer {
            total_chunks: 7,
            total_plaintext_size: 1_800_000,
            file_hash: [0xCD; 32],
        };
        let bytes = trailer.to_bytes();
        let magic: [u8; 4] = bytes[0..4].try_into().unwrap();
        let rest: [u8; 44] = bytes[4..48].try_into().unwrap();
        let parsed = BlobTrailer::from_remaining(&magic, &rest).unwrap();
        assert_eq!(parsed, trailer);
    }

    #[test]
    fn test_file_metadata_roundtrip() {
        let meta = FileMetadata {
            filename: "test.pdf".into(),
            mime: "application/pdf".into(),
            size: 1024,
        };
        let json = serde_json::to_string(&meta).unwrap();
        let parsed: FileMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.filename, "test.pdf");
        assert_eq!(parsed.size, 1024);
    }
}
