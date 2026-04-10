//! API request/response types for the SendTo server.
//!
//! These types define the contract between the hosted service and clients.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::types::{DeviceType, MessageStatus};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignupRequest {
    pub email: String,
    pub passphrase: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub passphrase: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    pub token: String,
    pub user_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoogleAuthExchangeRequest {
    pub code: String,
    pub redirect_uri: String,
    pub code_verifier: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeResponse {
    pub user_id: Uuid,
    pub email: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceCodeResponse {
    pub code: String,
    pub device_code_id: Uuid,
    pub verification_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmDeviceCodeRequest {
    pub code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmDeviceCodeResponse {
    pub success: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceCodePollResponse {
    pub status: DeviceCodeStatus,
    pub token: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceCodeStatus {
    Pending,
    Confirmed,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyDeviceCodeRequest {
    pub code: String,
    pub email: String,
    pub passphrase: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterDeviceRequest {
    pub name: String,
    pub public_key: String,
    #[serde(default)]
    pub device_type: DeviceType,
    /// Optional APNS or FCM push token for mobile devices.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_token: Option<String>,
    /// Platform the push token belongs to ("ios" or "android").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_platform: Option<PushPlatform>,
}

/// Push notification platform for mobile devices.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PushPlatform {
    /// Apple Push Notification service (iOS).
    Ios,
    /// Firebase Cloud Messaging (Android).
    Android,
}

impl PushPlatform {
    pub fn as_str(&self) -> &'static str {
        match self {
            PushPlatform::Ios => "ios",
            PushPlatform::Android => "android",
        }
    }
}

/// Request body for `PATCH /devices/:id/push-token`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdatePushTokenRequest {
    /// The new push token, or `None` to clear it (e.g. on logout).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_platform: Option<PushPlatform>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub id: Uuid,
    pub name: String,
    #[serde(default)]
    pub device_type: DeviceType,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceListResponse {
    pub devices: Vec<DeviceInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyResponse {
    pub public_key: String,
    pub device_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendResponse {
    pub message_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboxItem {
    pub message_id: Uuid,
    pub sender: String,
    pub size_bytes: i64,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboxResponse {
    pub messages: Vec<InboxItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResponse {
    pub message_id: Uuid,
    pub status: MessageStatus,
    pub created_at: DateTime<Utc>,
    pub acked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    pub code: String,
    pub message: String,
}

impl ApiError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new("not_found", message)
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new("bad_request", message)
    }

    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::new("unauthorized", message)
    }

    pub fn rate_limited(message: impl Into<String>) -> Self {
        Self::new("rate_limited", message)
    }

    pub fn quota_exceeded(message: impl Into<String>) -> Self {
        Self::new("quota_exceeded", message)
    }

    pub fn payload_too_large(message: impl Into<String>) -> Self {
        Self::new("payload_too_large", message)
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new("internal_error", message)
    }
}
