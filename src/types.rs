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
