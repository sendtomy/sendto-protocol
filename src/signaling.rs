//! WebSocket signaling types for WebRTC peer-to-peer file transfer.
//!
//! The server acts as a signaling relay only — it forwards SDP offers/answers
//! and ICE candidates between peers. Actual file data flows directly over
//! WebRTC data channels.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Message sent from client to signaling server.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMessage {
    /// Authenticate this WebSocket connection.
    Authenticate {
        token: String,
        device_id: Uuid,
    },

    /// Forward an SDP offer to a target device.
    SdpOffer {
        target_device: String,
        sdp: String,
    },

    /// Forward an SDP answer back to the offering device.
    SdpAnswer {
        target_device: String,
        sdp: String,
    },

    /// Forward an ICE candidate to a target device.
    IceCandidate {
        target_device: String,
        candidate: String,
    },

    /// Heartbeat to keep the connection alive.
    Ping,
}

/// Message sent from signaling server to client.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    /// Authentication succeeded.
    Authenticated {
        device_name: String,
        email: String,
        /// Names of other devices currently online for this account.
        online_peers: Vec<String>,
    },

    /// An SDP offer from another device.
    SdpOffer {
        from_device: String,
        sdp: String,
    },

    /// An SDP answer from another device.
    SdpAnswer {
        from_device: String,
        sdp: String,
    },

    /// An ICE candidate from another device.
    IceCandidate {
        from_device: String,
        candidate: String,
    },

    /// Another device on this account came online.
    PeerOnline {
        device_name: String,
    },

    /// Another device on this account went offline.
    PeerOffline {
        device_name: String,
    },

    /// A new message is available in the server relay inbox.
    NewMessage {
        message_id: Uuid,
        sender: String,
        size_bytes: i64,
    },

    /// Heartbeat response.
    Pong,

    /// Error from the server.
    Error {
        code: String,
        message: String,
    },
}

/// Metadata sent as the first message on a WebRTC data channel
/// before file chunks begin streaming.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferHeader {
    /// Unique transfer ID (lets receiver correlate chunks).
    pub transfer_id: Uuid,
    /// Original filename.
    pub filename: String,
    /// MIME type.
    pub mime: String,
    /// Total size in bytes of the encrypted payload.
    pub size: u64,
    /// Total number of chunks that will follow.
    pub total_chunks: u32,
    /// Hex-encoded sender public key (for decryption).
    pub sender_public_key: String,
    /// Hex-encoded nonce used to encrypt the file.
    pub nonce: String,
}

/// A single chunk of an encrypted file sent over a WebRTC data channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferChunk {
    /// Transfer ID (matches the header).
    pub transfer_id: Uuid,
    /// Zero-based chunk index.
    pub index: u32,
    /// Base64-encoded chunk data.
    pub data: String,
}

/// Final message after all chunks are sent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferComplete {
    pub transfer_id: Uuid,
}

/// Messages sent over the WebRTC data channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DataChannelMessage {
    /// First message: transfer metadata.
    Header(TransferHeader),
    /// File chunk.
    Chunk(TransferChunk),
    /// All chunks sent.
    Complete(TransferComplete),
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use uuid::Uuid;

    // --- ClientMessage roundtrip tests ---

    #[test]
    fn client_message_authenticate_roundtrip() {
        let id = Uuid::new_v4();
        let msg = ClientMessage::Authenticate {
            token: "tok_abc".into(),
            device_id: id,
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: ClientMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            ClientMessage::Authenticate { token, device_id } => {
                assert_eq!(token, "tok_abc");
                assert_eq!(device_id, id);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn client_message_sdp_offer_roundtrip() {
        let msg = ClientMessage::SdpOffer {
            target_device: "laptop".into(),
            sdp: "v=0\r\n...".into(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: ClientMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            ClientMessage::SdpOffer { target_device, sdp } => {
                assert_eq!(target_device, "laptop");
                assert_eq!(sdp, "v=0\r\n...");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn client_message_sdp_answer_roundtrip() {
        let msg = ClientMessage::SdpAnswer {
            target_device: "desktop".into(),
            sdp: "answer-sdp".into(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: ClientMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            ClientMessage::SdpAnswer { target_device, sdp } => {
                assert_eq!(target_device, "desktop");
                assert_eq!(sdp, "answer-sdp");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn client_message_ice_candidate_roundtrip() {
        let msg = ClientMessage::IceCandidate {
            target_device: "phone".into(),
            candidate: "candidate:1 ...".into(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: ClientMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            ClientMessage::IceCandidate { target_device, candidate } => {
                assert_eq!(target_device, "phone");
                assert_eq!(candidate, "candidate:1 ...");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn client_message_ping_roundtrip() {
        let msg = ClientMessage::Ping;
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: ClientMessage = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, ClientMessage::Ping));
    }

    // --- ServerMessage roundtrip tests ---

    #[test]
    fn server_message_authenticated_roundtrip() {
        let msg = ServerMessage::Authenticated {
            device_name: "my-pc".into(),
            email: "user@example.com".into(),
            online_peers: vec!["laptop".into(), "phone".into()],
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: ServerMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            ServerMessage::Authenticated { device_name, email, online_peers } => {
                assert_eq!(device_name, "my-pc");
                assert_eq!(email, "user@example.com");
                assert_eq!(online_peers, vec!["laptop", "phone"]);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn server_message_sdp_offer_roundtrip() {
        let msg = ServerMessage::SdpOffer {
            from_device: "laptop".into(),
            sdp: "offer-sdp".into(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: ServerMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            ServerMessage::SdpOffer { from_device, sdp } => {
                assert_eq!(from_device, "laptop");
                assert_eq!(sdp, "offer-sdp");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn server_message_sdp_answer_roundtrip() {
        let msg = ServerMessage::SdpAnswer {
            from_device: "desktop".into(),
            sdp: "answer-sdp".into(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: ServerMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            ServerMessage::SdpAnswer { from_device, sdp } => {
                assert_eq!(from_device, "desktop");
                assert_eq!(sdp, "answer-sdp");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn server_message_ice_candidate_roundtrip() {
        let msg = ServerMessage::IceCandidate {
            from_device: "phone".into(),
            candidate: "candidate:2 ...".into(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: ServerMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            ServerMessage::IceCandidate { from_device, candidate } => {
                assert_eq!(from_device, "phone");
                assert_eq!(candidate, "candidate:2 ...");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn server_message_peer_online_roundtrip() {
        let msg = ServerMessage::PeerOnline { device_name: "tablet".into() };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: ServerMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            ServerMessage::PeerOnline { device_name } => assert_eq!(device_name, "tablet"),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn server_message_peer_offline_roundtrip() {
        let msg = ServerMessage::PeerOffline { device_name: "tablet".into() };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: ServerMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            ServerMessage::PeerOffline { device_name } => assert_eq!(device_name, "tablet"),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn server_message_pong_roundtrip() {
        let msg = ServerMessage::Pong;
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: ServerMessage = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, ServerMessage::Pong));
    }

    #[test]
    fn server_message_error_roundtrip() {
        let msg = ServerMessage::Error {
            code: "auth_failed".into(),
            message: "Invalid token".into(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: ServerMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            ServerMessage::Error { code, message } => {
                assert_eq!(code, "auth_failed");
                assert_eq!(message, "Invalid token");
            }
            _ => panic!("wrong variant"),
        }
    }

    // --- DataChannelMessage roundtrip tests ---

    #[test]
    fn data_channel_header_roundtrip() {
        let header = TransferHeader {
            transfer_id: Uuid::new_v4(),
            filename: "photo.jpg".into(),
            mime: "image/jpeg".into(),
            size: 1024,
            total_chunks: 2,
            sender_public_key: "abcdef".into(),
            nonce: "112233".into(),
        };
        let msg = DataChannelMessage::Header(header.clone());
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: DataChannelMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            DataChannelMessage::Header(h) => {
                assert_eq!(h.transfer_id, header.transfer_id);
                assert_eq!(h.filename, "photo.jpg");
                assert_eq!(h.size, 1024);
                assert_eq!(h.total_chunks, 2);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn data_channel_chunk_roundtrip() {
        let id = Uuid::new_v4();
        let msg = DataChannelMessage::Chunk(TransferChunk {
            transfer_id: id,
            index: 0,
            data: "base64data==".into(),
        });
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: DataChannelMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            DataChannelMessage::Chunk(c) => {
                assert_eq!(c.transfer_id, id);
                assert_eq!(c.index, 0);
                assert_eq!(c.data, "base64data==");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn data_channel_complete_roundtrip() {
        let id = Uuid::new_v4();
        let msg = DataChannelMessage::Complete(TransferComplete { transfer_id: id });
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: DataChannelMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            DataChannelMessage::Complete(c) => assert_eq!(c.transfer_id, id),
            _ => panic!("wrong variant"),
        }
    }

    // --- TransferHeader standalone roundtrip ---

    #[test]
    fn transfer_header_roundtrip() {
        let header = TransferHeader {
            transfer_id: Uuid::new_v4(),
            filename: "doc.pdf".into(),
            mime: "application/pdf".into(),
            size: 999_999,
            total_chunks: 10,
            sender_public_key: "deadbeef".into(),
            nonce: "cafe0123".into(),
        };
        let json = serde_json::to_string(&header).unwrap();
        let parsed: TransferHeader = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.transfer_id, header.transfer_id);
        assert_eq!(parsed.filename, "doc.pdf");
        assert_eq!(parsed.mime, "application/pdf");
        assert_eq!(parsed.size, 999_999);
        assert_eq!(parsed.total_chunks, 10);
        assert_eq!(parsed.sender_public_key, "deadbeef");
        assert_eq!(parsed.nonce, "cafe0123");
    }

    // --- JSON tag verification ---

    #[test]
    fn client_message_json_tag_sdp_offer() {
        let msg = ClientMessage::SdpOffer {
            target_device: "x".into(),
            sdp: "y".into(),
        };
        let v: Value = serde_json::to_value(&msg).unwrap();
        assert_eq!(v["type"], "sdp_offer");
    }

    #[test]
    fn client_message_json_tag_authenticate() {
        let msg = ClientMessage::Authenticate {
            token: "t".into(),
            device_id: Uuid::new_v4(),
        };
        let v: Value = serde_json::to_value(&msg).unwrap();
        assert_eq!(v["type"], "authenticate");
    }

    #[test]
    fn client_message_json_tag_ping() {
        let msg = ClientMessage::Ping;
        let v: Value = serde_json::to_value(&msg).unwrap();
        assert_eq!(v["type"], "ping");
    }

    #[test]
    fn server_message_json_tag_authenticated() {
        let msg = ServerMessage::Authenticated {
            device_name: "d".into(),
            email: "e".into(),
            online_peers: vec![],
        };
        let v: Value = serde_json::to_value(&msg).unwrap();
        assert_eq!(v["type"], "authenticated");
    }

    #[test]
    fn server_message_json_tag_pong() {
        let msg = ServerMessage::Pong;
        let v: Value = serde_json::to_value(&msg).unwrap();
        assert_eq!(v["type"], "pong");
    }

    #[test]
    fn server_message_json_tag_error() {
        let msg = ServerMessage::Error {
            code: "c".into(),
            message: "m".into(),
        };
        let v: Value = serde_json::to_value(&msg).unwrap();
        assert_eq!(v["type"], "error");
    }

    #[test]
    fn data_channel_json_tag_header() {
        let msg = DataChannelMessage::Header(TransferHeader {
            transfer_id: Uuid::new_v4(),
            filename: "f".into(),
            mime: "m".into(),
            size: 0,
            total_chunks: 0,
            sender_public_key: "k".into(),
            nonce: "n".into(),
        });
        let v: Value = serde_json::to_value(&msg).unwrap();
        assert_eq!(v["type"], "header");
    }

    #[test]
    fn data_channel_json_tag_chunk() {
        let msg = DataChannelMessage::Chunk(TransferChunk {
            transfer_id: Uuid::new_v4(),
            index: 0,
            data: "d".into(),
        });
        let v: Value = serde_json::to_value(&msg).unwrap();
        assert_eq!(v["type"], "chunk");
    }

    #[test]
    fn data_channel_json_tag_complete() {
        let msg = DataChannelMessage::Complete(TransferComplete {
            transfer_id: Uuid::new_v4(),
        });
        let v: Value = serde_json::to_value(&msg).unwrap();
        assert_eq!(v["type"], "complete");
    }
}
