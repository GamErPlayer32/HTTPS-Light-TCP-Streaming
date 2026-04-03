# HTTPS Light TCP Streaming

A fast, lightweight TCP/UDP-over-HTTP tunneling application with a modern GUI, headless terminal mode, and a browser-based web dashboard.

**Version:** 1.1.0  
**Python:** 3.8+  
**License:** MIT  

---

## What It Does

Bridges TCP or UDP traffic over standard HTTP/HTTPS connections. A **server** sits next to your backend service (e.g. a game server) and exposes an HTTP endpoint. A **client** creates a local listener that applications connect to normally — all traffic is transparently tunneled over HTTP to the server, which forwards it to the backend.

This is useful when:
- Firewalls or proxies block raw TCP/UDP but allow HTTP(S).
- You need to tunnel game traffic (Minecraft, Source engine, Terraria, etc.) through restrictive networks.
- You want to add TLS encryption and authentication to an existing unencrypted service.

```
┌──────────┐     TCP/UDP      ┌────────────┐       HTTP        ┌────────────┐     TCP/UDP     ┌──────────┐
│  Game /  │ ──────────────►  │   Client   │ ────────────────► │   Server   │ ──────────────► │ Backend  │
│  App     │ ◄──────────────  │  (local)   │ ◄──────────────── │  (remote)  │ ◄────────────── │ Service  │
└──────────┘                  └────────────┘    Chunked/WS/    └────────────┘                 └──────────┘
                                                SSE/LongPoll
```

---

## Features

- **5 streaming methods** — Chunked Transfer, WebSocket, Server-Sent Events, Long Polling, HTTP/2
- **Auto-detect** — Client tests each server-allowed method and picks the fastest automatically
- **Per-method server control** — Enable/disable individual methods with checkboxes; see live connection counts per method
- **TCP & UDP** support
- **TLS/SSL** encryption with optional certificate verification
- **Token authentication** — Shared secret between server and client
- **Split streaming** — Breaks large payloads into smaller chunks for consistent delivery
- **Zlib compression** — Optional fast compression to reduce bandwidth
- **TCP_NODELAY** — Disable Nagle's algorithm for minimal latency (critical for gaming)
- **Real-time statistics** — Active connections, throughput, latency, jitter, packet loss
- **Live charts** — Throughput, latency, and system resource graphs
- **Network tests** — Built-in latency ping test and throughput benchmark
- **Profiles** — Save and load named configuration profiles
- **Modern GUI** — DearPyGui-based desktop interface with a dark Catppuccin theme
- **Terminal mode** (`--nogui`) — Run headless from the command line
- **Web dashboard** (`--webgui`) — Browser-based monitoring on a configurable port with JSON API
- **Full CLI** — Every setting available as a command-line argument

---

## Requirements

| Package | Min Version | Purpose |
|---------|-------------|---------|
| [aiohttp](https://pypi.org/project/aiohttp/) | 3.9.0 | HTTP server & client, WebSocket, web dashboard |
| [dearpygui](https://pypi.org/project/dearpygui/) | 2.0.0 | Desktop GUI (not needed for `--nogui`) |
| [psutil](https://pypi.org/project/psutil/) | 5.9.0 | CPU / memory monitoring |

All other imports (`asyncio`, `ssl`, `zlib`, `argparse`, etc.) are Python standard library.

---

## Installation

```bash
# Clone or download the project
cd "HTTPS Light TCP Streaming"

# Install dependencies
pip install -r requirements.txt

# (Optional) If you only need headless mode, skip dearpygui:
pip install aiohttp psutil
```

---

## Quick Start

### GUI Mode (default)

```bash
python main.py
```

Opens the desktop interface where you can configure everything visually.

### Headless Server

```bash
python main.py --nogui --mode server --http-host 0.0.0.0 --http-port 8080 --tcp-host 127.0.0.1 --tcp-port 25565
```

### Headless Client

```bash
python main.py --nogui --mode client --remote http://your-server.com:8080 --local-host 127.0.0.1 --local-port 25565
```

### With Web Dashboard

```bash
python main.py --nogui --mode server --webgui 0.0.0.0:9090
```

Then open `http://your-server:9090` in a browser.

---

## CLI Reference

```
python main.py [OPTIONS]
```

### General

| Flag | Description |
|------|-------------|
| `--nogui` | Run in terminal-only mode (no desktop GUI) |
| `--mode {server,client}` | Operating mode |
| `--profile NAME` | Load a saved settings profile |

### Server Options

| Flag | Description |
|------|-------------|
| `--tcp-host HOST` | Backend service IP (default: `127.0.0.1`) |
| `--tcp-port PORT` | Backend service port (default: `25565`) |
| `--http-host HOST` | HTTP listen address (default: `0.0.0.0`) |
| `--http-port PORT` | HTTP listen port (default: `8080`) |
| `--protocol {tcp,udp}` | Backend transport protocol |
| `--allowed-methods M [M ...]` | Space-separated list: `chunked websocket sse long_poll http2` |

### Client Options

| Flag | Description |
|------|-------------|
| `--local-host HOST` | Local listen address (default: `127.0.0.1`) |
| `--local-port PORT` | Local listen port (default: `25565`) |
| `--remote URL` | Server URL, e.g. `http://example.com:8080` |
| `--method METHOD` | Force a specific streaming method |
| `--auto-detect` | Test all server methods and pick fastest |

### Performance

| Flag | Description |
|------|-------------|
| `--split-streaming BOOL` | Enable payload splitting |
| `--split-threshold BYTES` | Split threshold (default: `32768`) |
| `--compression BOOL` | Enable zlib compression |
| `--no-nagle` | Disable Nagle's algorithm (TCP_NODELAY) |
| `--buffer-size BYTES` | Read buffer size (default: `65536`) |
| `--max-connections N` | Max simultaneous sessions (default: `100`) |
| `--worker-threads N` | Async worker threads (default: `4`) |

### Security

| Flag | Description |
|------|-------------|
| `--tls` | Enable TLS/SSL |
| `--tls-cert PATH` | TLS certificate file (.pem) |
| `--tls-key PATH` | TLS private key file (.pem) |
| `--no-verify-ssl` | Skip server certificate verification |
| `--auth-token TOKEN` | Shared authentication token |

### Web Dashboard

| Flag | Description |
|------|-------------|
| `--webgui HOST:PORT` | Enable browser dashboard (e.g. `0.0.0.0:9090`) |

---

## Streaming Methods

| Method | Latency | Throughput | Compatibility | Best For |
|--------|---------|------------|---------------|----------|
| **WebSocket** | Very Low | High | Moderate | Real-time gaming, bidirectional |
| **Chunked Transfer** | Low | High | High | General purpose |
| **HTTP/2** | Low | Very High | Low | Modern infrastructure |
| **SSE** | Medium | Medium | High | Server-push heavy workloads |
| **Long Polling** | High | Low | Very High | Maximum firewall compatibility |

Use **Auto-Detect** to let the client benchmark each method against the server and pick the best one automatically.

---

## GUI Tabs

| Tab | Description |
|-----|-------------|
| **Connection** | Mode selector, server/client config, method selection, start/stop |
| **Statistics** | Live connection counts, data transferred, latency, system resources |
| **Charts** | Throughput, latency, and system graphs over time |
| **Network Test** | One-click latency ping test and throughput benchmark |
| **Settings** | Profiles, performance tuning, security (TLS, auth), web GUI config |
| **Log** | Live scrolling application log |

---

## Web Dashboard API

When `--webgui` is enabled, the following endpoints are available:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | HTML dashboard (auto-refreshes every 2s) |
| `/api/stats` | GET | JSON — connections, throughput, latency, per-method counts |
| `/api/log` | GET | JSON — last 100 log entries |
| `/api/settings` | GET | JSON — current settings (sensitive fields excluded) |

---

## Settings & Data

All settings and logs are stored in:

```
~/.httplighttcp/
├── settings.json    # All config + saved profiles
└── app.log          # Application log
```

Settings are auto-saved on exit and can be manually saved from the Settings tab or via profiles.

---

## Examples

**Tunnel a Minecraft server through HTTP:**

```bash
# On the server machine (next to the Minecraft server)
python main.py --nogui --mode server --tcp-port 25565 --http-port 8080

# On the client machine
python main.py --nogui --mode client --remote http://server-ip:8080 --local-port 25565 --auto-detect

# Point Minecraft at localhost:25565
```

**Restrict server to WebSocket and Chunked only:**

```bash
python main.py --nogui --mode server --allowed-methods websocket chunked
```

**Run with TLS and auth:**

```bash
# Server
python main.py --nogui --mode server --tls --tls-cert cert.pem --tls-key key.pem --auth-token mysecret

# Client
python main.py --nogui --mode client --remote https://server:8080 --auth-token mysecret
```

**Monitor remotely via web dashboard:**

```bash
python main.py --nogui --mode server --webgui 0.0.0.0:9090
# Open http://server-ip:9090 in any browser
```

---

## Architecture

The application is a single-file Python program (`main.py`) with these core classes:

| Class | Role |
|-------|------|
| `AppSettings` | Dataclass config with JSON persistence and profile support |
| `ConnectionStats` | Thread-safe statistics collection with rolling history |
| `TunnelServer` | aiohttp HTTP server bridging to a backend TCP/UDP service |
| `TunnelClient` | Local TCP/UDP listener forwarding over HTTP to the server |
| `TunnelPacket` | Binary packet framing (length-prefixed, sequenced, compressed) |
| `NetworkTester` | Latency and throughput benchmarking tools |
| `AppUI` | DearPyGui desktop interface |
| `TerminalUI` | Headless terminal mode for `--nogui` |
| `WebGUI` | aiohttp-based browser dashboard for `--webgui` |

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `ModuleNotFoundError: dearpygui` | Run `pip install dearpygui` or use `--nogui` |
| Connection refused | Check firewall, verify `--http-host`/`--http-port` match |
| High latency | Try `--method websocket` or `--auto-detect`, enable `--no-nagle` |
| Auth errors | Ensure `--auth-token` matches on both server and client |
| SSL errors | Use `--no-verify-ssl` for self-signed certs (dev only) |
| Methods rejected | Server must have the method enabled in `--allowed-methods` |
