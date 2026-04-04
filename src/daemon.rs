//! IPC types for communication between the `sendto` CLI and `sendtod` daemon.
//!
//! The daemon listens on a local Unix socket (Linux/macOS) or named pipe (Windows).
//! Both the CLI and optional tray app are clients of this same API.
//!
//! Default socket path: `/var/run/sendto/sendtod.sock` (root) or
//! `$XDG_RUNTIME_DIR/sendto/sendtod.sock` (user-mode).
//! Windows named pipe: `\\.\pipe\sendto-daemon`.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Request from CLI/tray to the daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum DaemonRequest {
    /// Get daemon and connection status.
    Status,

    /// Bring the daemon online (authenticate + register device if needed).
    Up,

    /// Take the daemon offline (stop polling, disconnect).
    Down,

    /// Send a file or payload to a device/agent by name.
    Send {
        target: String,
        #[serde(default)]
        file_path: Option<String>,
        #[serde(default)]
        payload: Option<Vec<u8>>,
    },

    /// List messages in the inbox.
    Inbox,

    /// Receive/download a specific message.
    Receive { message_id: Uuid },

    /// List registered devices for this account.
    Devices,

    /// Register the current machine as a device.
    Register { name: String },

    /// Register an agent under this device.
    RegisterAgent { name: String },

    /// Remove an agent from this device.
    RemoveAgent { name: String },

    /// Ping the daemon (health check).
    Ping,
}

/// Response from the daemon to CLI/tray.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DaemonResponse {
    /// Daemon status info.
    Status(DaemonStatus),

    /// Operation succeeded with an optional message.
    Ok {
        #[serde(default)]
        message: Option<String>,
    },

    /// Inbox listing.
    Inbox { items: Vec<InboxEntry> },

    /// Device listing.
    Devices { devices: Vec<DeviceEntry> },

    /// File/payload received.
    Received {
        message_id: Uuid,
        filename: String,
        size_bytes: u64,
        saved_to: String,
    },

    /// Send confirmation.
    Sent { message_id: Uuid },

    /// Pong.
    Pong,

    /// Error.
    Error { code: String, message: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionState {
    /// Daemon is running but not authenticated.
    Offline,
    /// Connecting to the server.
    Connecting,
    /// Authenticated and polling for messages.
    Online,
}

impl std::fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Offline => write!(f, "offline"),
            Self::Connecting => write!(f, "connecting"),
            Self::Online => write!(f, "online"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonStatus {
    pub state: ConnectionState,
    pub device_name: Option<String>,
    pub user_email: Option<String>,
    pub version: String,
    pub inbox_count: u32,
    pub agents: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboxEntry {
    pub message_id: Uuid,
    pub sender: String,
    pub filename: String,
    pub size_bytes: u64,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceEntry {
    pub name: String,
    pub device_type: String,
    pub is_self: bool,
}

/// Well-known paths for the daemon socket.
pub mod socket {
    /// Default socket path for Linux/macOS when running as a user service.
    pub fn default_user_socket() -> String {
        if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
            format!("{runtime_dir}/sendto/sendtod.sock")
        } else {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
            format!("{home}/.sendto/sendtod.sock")
        }
    }

    /// Named pipe path for Windows.
    #[cfg(target_os = "windows")]
    pub fn default_windows_pipe() -> &'static str {
        r"\\.\pipe\sendto-daemon"
    }
}
