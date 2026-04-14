//! Agent interaction types shared between clients and protocol.
//!
//! Defines the wire format for agent ↔ daemon communication (over IPC),
//! agent configuration schema, and activity/status reporting types.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use uuid::Uuid;

// ── Agent ↔ Daemon wire protocol ─────────────────────────────────────

/// Message from an agent to the daemon (over IPC).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum AgentMessage {
    /// Initial handshake: agent identifies itself.
    #[serde(rename = "handshake")]
    Handshake { agent_name: String },

    /// Enter the receive loop — start receiving incoming messages.
    #[serde(rename = "listen")]
    Listen,

    /// Acknowledge receipt of a message.
    #[serde(rename = "ack")]
    Ack { id: Uuid },

    /// Send data to a target device/agent.
    #[serde(rename = "send")]
    Send {
        target: String,
        data: String,
        filename: String,
        mime: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        message: Option<String>,
    },
}

/// Response from the daemon to an agent (over IPC).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum AgentResponse {
    /// Operation succeeded.
    #[serde(rename = "ok")]
    Ok { message: String },

    /// Incoming message/file for this agent.
    #[serde(rename = "incoming")]
    Incoming {
        id: Uuid,
        from: String,
        content_type: String,
        filename: String,
        path: String,
        size_bytes: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        message: Option<String>,
    },

    /// Acknowledgement confirmed.
    #[serde(rename = "ack_ok")]
    AckOk { id: Uuid },

    /// Send confirmation.
    #[serde(rename = "sent")]
    Sent { message_id: Uuid },

    /// Error response.
    #[serde(rename = "error")]
    Error { code: String, message: String },
}

// ── Agent configuration schema ───────────────────────────────────────

/// Agent activation mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AgentMode {
    /// Spawn per message, exit when done.
    OnDemand,
    /// Long-running, respawn on crash.
    Persistent,
}

impl fmt::Display for AgentMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AgentMode::OnDemand => write!(f, "on-demand"),
            AgentMode::Persistent => write!(f, "persistent"),
        }
    }
}

impl std::str::FromStr for AgentMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "on-demand" | "ondemand" => Ok(AgentMode::OnDemand),
            "persistent" => Ok(AgentMode::Persistent),
            other => Err(format!(
                "unknown agent mode: '{other}' (use 'on-demand' or 'persistent')"
            )),
        }
    }
}

/// Configuration for a single managed agent.
///
/// This is the schema only — persistence (loading/saving `agents.toml`)
/// is handled by the client implementation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedAgentConfig {
    /// Agent name (same rules as device names).
    pub name: String,

    /// Shell command to execute.
    pub command: String,

    /// Optional command arguments.
    #[serde(default)]
    pub args: Vec<String>,

    /// Working directory for the child process.
    #[serde(default)]
    pub working_directory: Option<String>,

    /// Activation mode.
    pub mode: AgentMode,

    /// On-demand: max seconds before SIGTERM/kill. Default 30.
    #[serde(default)]
    pub timeout_secs: Option<u64>,

    /// On-demand: max concurrent instances. Default 3.
    #[serde(default)]
    pub max_instances: Option<u32>,

    /// Persistent: max respawn attempts before giving up. Default 10.
    #[serde(default)]
    pub max_retries: Option<u32>,

    /// Additional environment variables for the child process.
    #[serde(default)]
    pub env: HashMap<String, String>,
}

impl ManagedAgentConfig {
    pub fn timeout(&self) -> u64 {
        self.timeout_secs.unwrap_or(30)
    }

    pub fn max_instances(&self) -> u32 {
        self.max_instances.unwrap_or(3)
    }

    pub fn max_retries(&self) -> u32 {
        self.max_retries.unwrap_or(10)
    }
}

// ── Agent status and activity ────────────────────────────────────────

/// Status of a registered agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentStatusEntry {
    pub name: String,
    pub device_id: Uuid,
    pub listening: bool,
}

/// Kind of activity event reported by the daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ActivityKind {
    MessageReceived,
    AgentMessageReceived,
    AgentConnected,
    AgentDisconnected,
    MessageSent,
    AgentActivated,
    AgentDeactivated,
    Error,
    PollSuccess,
    PollFailed,
    PeerOnline,
    PeerOffline,
    LoggedIn,
    LoggedOut,
    Registered,
}

impl fmt::Display for ActivityKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ActivityKind::MessageReceived => write!(f, "RECV"),
            ActivityKind::AgentMessageReceived => write!(f, "AGENT_RECV"),
            ActivityKind::AgentConnected => write!(f, "AGENT_ON"),
            ActivityKind::AgentDisconnected => write!(f, "AGENT_OFF"),
            ActivityKind::MessageSent => write!(f, "SENT"),
            ActivityKind::AgentActivated => write!(f, "AGENT_ACTIVATE"),
            ActivityKind::AgentDeactivated => write!(f, "AGENT_DEACTIVATE"),
            ActivityKind::Error => write!(f, "ERROR"),
            ActivityKind::PollSuccess => write!(f, "POLL_OK"),
            ActivityKind::PollFailed => write!(f, "POLL_FAIL"),
            ActivityKind::PeerOnline => write!(f, "PEER_ON"),
            ActivityKind::PeerOffline => write!(f, "PEER_OFF"),
            ActivityKind::LoggedIn => write!(f, "LOGIN"),
            ActivityKind::LoggedOut => write!(f, "LOGOUT"),
            ActivityKind::Registered => write!(f, "REGISTER"),
        }
    }
}

/// Structured metadata for a file-related activity event (MessageReceived,
/// MessageSent, AgentMessageReceived). Optional — events that don't involve a
/// file leave this as None.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileActivity {
    pub message_id: Uuid,
    pub filename: String,
    pub mime: String,
    pub size: u64,
    /// Absolute path to the file on disk, if it was persisted locally.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Device name of the peer involved (sender for receives, recipient for sends).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer: Option<String>,
}

/// A single activity event from the daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityEntry {
    pub timestamp: DateTime<Utc>,
    pub kind: ActivityKind,
    pub detail: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<FileActivity>,
}

impl ActivityEntry {
    pub fn new(kind: ActivityKind, detail: impl Into<String>) -> Self {
        Self {
            timestamp: Utc::now(),
            kind,
            detail: detail.into(),
            file: None,
        }
    }

    /// Attach structured file metadata to this activity entry.
    pub fn with_file(mut self, file: FileActivity) -> Self {
        self.file = Some(file);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_handshake_serialization() {
        let msg = AgentMessage::Handshake {
            agent_name: "claude-project1".into(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("handshake"));
        assert!(json.contains("claude-project1"));
        let parsed: AgentMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            AgentMessage::Handshake { agent_name } => {
                assert_eq!(agent_name, "claude-project1");
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_agent_listen_serialization() {
        let msg = AgentMessage::Listen;
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: AgentMessage = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, AgentMessage::Listen));
    }

    #[test]
    fn test_agent_incoming_serialization() {
        let resp = AgentResponse::Incoming {
            id: Uuid::nil(),
            from: "my-phone".into(),
            content_type: "file".into(),
            filename: "photo.jpg".into(),
            path: "/tmp/cache/abc123".into(),
            size_bytes: 4096,
            message: Some("Please resize this to 800px".into()),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("incoming"));
        let parsed: AgentResponse = serde_json::from_str(&json).unwrap();
        match parsed {
            AgentResponse::Incoming {
                id,
                from,
                filename,
                size_bytes,
                ..
            } => {
                assert_eq!(id, Uuid::nil());
                assert_eq!(from, "my-phone");
                assert_eq!(filename, "photo.jpg");
                assert_eq!(size_bytes, 4096);
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_agent_send_serialization() {
        let msg = AgentMessage::Send {
            target: "my-laptop".into(),
            data: "aGVsbG8=".into(),
            filename: "hello.txt".into(),
            mime: "text/plain".into(),
            message: None,
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: AgentMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            AgentMessage::Send {
                target, filename, ..
            } => {
                assert_eq!(target, "my-laptop");
                assert_eq!(filename, "hello.txt");
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_agent_mode_display_and_parse() {
        assert_eq!(AgentMode::OnDemand.to_string(), "on-demand");
        assert_eq!(AgentMode::Persistent.to_string(), "persistent");

        assert_eq!(
            "on-demand".parse::<AgentMode>().unwrap(),
            AgentMode::OnDemand
        );
        assert_eq!(
            "ondemand".parse::<AgentMode>().unwrap(),
            AgentMode::OnDemand
        );
        assert_eq!(
            "persistent".parse::<AgentMode>().unwrap(),
            AgentMode::Persistent
        );
        assert!("invalid".parse::<AgentMode>().is_err());
    }

    #[test]
    fn test_agent_mode_serde() {
        let mode = AgentMode::OnDemand;
        let json = serde_json::to_string(&mode).unwrap();
        assert_eq!(json, "\"on-demand\"");
        let parsed: AgentMode = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, AgentMode::OnDemand);
    }

    #[test]
    fn test_managed_agent_config_defaults() {
        let config = ManagedAgentConfig {
            name: "test-agent".into(),
            command: "python".into(),
            args: vec!["agent.py".into()],
            working_directory: None,
            mode: AgentMode::OnDemand,
            timeout_secs: None,
            max_instances: None,
            max_retries: None,
            env: HashMap::new(),
        };
        assert_eq!(config.timeout(), 30);
        assert_eq!(config.max_instances(), 3);
        assert_eq!(config.max_retries(), 10);
    }

    #[test]
    fn test_activity_entry_display() {
        assert_eq!(ActivityKind::MessageReceived.to_string(), "RECV");
        assert_eq!(ActivityKind::AgentConnected.to_string(), "AGENT_ON");
        assert_eq!(ActivityKind::PollFailed.to_string(), "POLL_FAIL");
    }
}
