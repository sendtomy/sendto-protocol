# SendTo Protocol

Shared SendTo protocol, API contract, and crypto helpers used by both clients and the hosted service.

This crate contains:

- API request/response types (`api`)
- Daemon IPC types (`daemon`) — contract between `sendto` CLI and `sendtod` daemon
- Shared domain types (`types`)
- Crypto helpers (`crypto`)

## Architecture

```
┌──────────────────────────────────────────────────┐
│                   sendtod (daemon)                │
│                                                   │
│  • Runs as systemd service / launchd / Windows    │
│    service                                        │
│  • Holds the device keypair                       │
│  • Polls the server for incoming messages         │
│  • Listens on a local socket for CLI/tray comms   │
│  • Manages agent registrations                    │
└────────────┬──────────────────────┬───────────────┘
             │ Unix socket /        │ HTTPS
             │ named pipe           │
     ┌───────┴───────┐      ┌──────┴──────┐
     │  CLI / Tray   │      │  SendTo     │
     │  (clients)    │      │  Server     │
     └───────────────┘      └─────────────┘
```

### Packages

| Package        | Description                                        |
|----------------|----------------------------------------------------|
| `sendto`       | CLI + daemon (`sendtod`). Core install.             |
| `sendto-tray`  | Optional GUI tray app. Depends on `sendto`.         |

### CLI commands (talks to daemon via socket)

```sh
sendto up                    # authenticate + bring online
sendto down                  # go offline
sendto status                # show connection state, device, inbox count
sendto send <target> <file>  # send file to device or agent
sendto inbox                 # list pending messages
sendto receive <message_id>  # download a message
sendto devices               # list devices on your account
sendto register <name>       # register this machine
sendto agent add <name>      # register an agent under this device
sendto agent rm <name>       # remove an agent
```

### Daemon socket

- **Linux/macOS**: `$XDG_RUNTIME_DIR/sendto/sendtod.sock` or `~/.sendto/sendtod.sock`
- **Windows**: `\\.\pipe\sendto-daemon`

Both CLI and tray are thin clients — all state lives in the daemon.

## Development

```sh
cargo test
```
