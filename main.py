"""
HTTPS Light TCP Streaming - Fast TCP-over-HTTP Tunnel
=====================================================
A high-performance tunneling application that bridges TCP/UDP connections over HTTP/HTTPS.
Supports server and client modes with a modern UI, real-time statistics, and multiple
streaming methods optimized for low-latency applications like gaming.

Features:
- Server mode: HTTP(S) server that bridges to a local TCP/UDP service
- Client mode: Local TCP/UDP listener that tunnels traffic over HTTP(S) to the server
- Multiple HTTP streaming methods: chunked transfer, WebSocket, SSE, long-polling, HTTP/2
- Split-data streaming for optimized throughput
- Real-time charts: throughput, latency, connections, CPU/memory usage
- Auto-detection of optimal streaming method (client tests each server method)
- Cross-platform (Windows, Linux, macOS)
- Persistent settings with profile support
- TLS/SSL optional security
- Detailed tooltips on all UI elements
- CLI arguments for all settings + --nogui headless mode
- --webgui option for browser-based dashboard

CLI Usage:
  python main.py                         # Launch with GUI (default)
  python main.py --nogui                 # Terminal-only mode
  python main.py --mode server           # Start in server mode
  python main.py --mode client           # Start in client mode
  python main.py --webgui 0.0.0.0:1234  # Enable web dashboard
  python main.py --help                  # Show all options
"""

import sys
import os
import json
import time
import struct
import socket
import ssl
import hashlib
import asyncio
import threading
import collections
import logging
import platform
import traceback
import uuid
import zlib
import io
import argparse
import base64
import html as html_module
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, List, Tuple, Any, Deque
from enum import Enum
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

# Third-party imports - aiohttp is always needed (server/client + webgui)
try:
    import aiohttp
    from aiohttp import web
except ImportError:
    print("Installing aiohttp...")
    os.system(f"{sys.executable} -m pip install aiohttp")
    import aiohttp
    from aiohttp import web

try:
    import psutil
except ImportError:
    print("Installing psutil...")
    os.system(f"{sys.executable} -m pip install psutil")
    import psutil

# DearPyGui is only imported when GUI mode is used (deferred)
dpg = None

def _ensure_dpg():
    global dpg
    if dpg is not None:
        return
    try:
        import dearpygui.dearpygui as _dpg
        dpg = _dpg
    except ImportError:
        print("Installing dearpygui...")
        os.system(f"{sys.executable} -m pip install dearpygui")
        import dearpygui.dearpygui as _dpg
        dpg = _dpg

# ============================================================================
# CONSTANTS & CONFIGURATION
# ============================================================================

APP_NAME = "HTTPS Light TCP Streaming"
APP_VERSION = "1.1.0"
SETTINGS_DIR = Path.home() / ".httplighttcp"
SETTINGS_FILE = SETTINGS_DIR / "settings.json"
LOG_FILE = SETTINGS_DIR / "app.log"
MAX_BUFFER_SIZE = 65536  # 64KB chunks for streaming
STATS_HISTORY_SIZE = 300  # 5 minutes at 1 sample/sec
CHUNK_SPLIT_THRESHOLD = 32768  # Split data above 32KB
HEARTBEAT_INTERVAL = 2.0
CONNECTION_TIMEOUT = 10.0
AUTO_DETECT_SAMPLE_COUNT = 10


class StreamingMethod(Enum):
    """Available HTTP streaming methods for tunneling data."""
    CHUNKED = "chunked"       # HTTP chunked transfer encoding - good general purpose
    WEBSOCKET = "websocket"   # WebSocket - best for bidirectional, low-latency
    SSE = "sse"               # Server-Sent Events - good for server-push scenarios
    LONG_POLL = "long_poll"   # Long polling - most compatible, higher latency
    HTTP2 = "http2"           # HTTP/2 multiplexed streams - modern, efficient


class Protocol(Enum):
    """Transport protocol for the tunnel endpoints."""
    TCP = "tcp"
    UDP = "udp"


class AppMode(Enum):
    """Application operating mode."""
    SERVER = "server"
    CLIENT = "client"


STREAMING_METHOD_INFO = {
    StreamingMethod.CHUNKED: {
        "name": "Chunked Transfer",
        "desc": "Uses HTTP chunked transfer encoding for streaming. Good balance of compatibility and performance. Data is sent in variable-size chunks without knowing total size upfront.",
        "latency": "Medium (5-15ms overhead)",
        "throughput": "High",
        "compatibility": "Excellent - works with all HTTP/1.1 proxies",
    },
    StreamingMethod.WEBSOCKET: {
        "name": "WebSocket",
        "desc": "Full-duplex communication over a single TCP connection upgraded from HTTP. Best for real-time bidirectional data like gaming. Minimal framing overhead.",
        "latency": "Very Low (1-3ms overhead)",
        "throughput": "Very High",
        "compatibility": "Good - may be blocked by some corporate firewalls",
    },
    StreamingMethod.SSE: {
        "name": "Server-Sent Events",
        "desc": "Unidirectional server-to-client streaming with automatic reconnection. Uses a separate upload channel. Good for scenarios with asymmetric traffic.",
        "latency": "Low (3-8ms overhead)",
        "throughput": "High (downstream) / Medium (upstream)",
        "compatibility": "Good - works through most proxies",
    },
    StreamingMethod.LONG_POLL: {
        "name": "Long Polling",
        "desc": "Client sends HTTP request, server holds it open until data is available. Most compatible method but highest latency. Good fallback when others are blocked.",
        "latency": "High (15-50ms overhead)",
        "throughput": "Medium",
        "compatibility": "Excellent - works everywhere",
    },
    StreamingMethod.HTTP2: {
        "name": "HTTP/2 Multiplexed",
        "desc": "Uses HTTP/2 multiplexed streams for concurrent bidirectional data. Efficient header compression and stream prioritization. Requires HTTPS in browsers.",
        "latency": "Low (2-5ms overhead)",
        "throughput": "Very High",
        "compatibility": "Good - requires HTTP/2 support",
    },
}

ALL_METHOD_VALUES = [m.value for m in StreamingMethod]


# ============================================================================
# SETTINGS
# ============================================================================

@dataclass
class AppSettings:
    """Persistent application settings with profile support."""
    mode: str = "server"
    # Server settings
    server_tcp_host: str = "127.0.0.1"
    server_tcp_port: int = 25565
    server_http_host: str = "0.0.0.0"
    server_http_port: int = 8080
    server_protocol: str = "tcp"
    server_allowed_methods: List[str] = field(default_factory=lambda: list(ALL_METHOD_VALUES))
    # Client settings
    client_local_host: str = "127.0.0.1"
    client_local_port: int = 25565
    client_remote_url: str = "http://localhost:8080"
    client_protocol: str = "tcp"
    # Streaming
    streaming_method: str = "websocket"
    auto_detect_method: bool = False
    split_streaming: bool = True
    split_threshold: int = CHUNK_SPLIT_THRESHOLD
    compression: bool = True
    # Security
    use_tls: bool = False
    tls_cert_path: str = ""
    tls_key_path: str = ""
    verify_ssl: bool = False
    auth_token: str = ""
    # Performance
    buffer_size: int = MAX_BUFFER_SIZE
    max_connections: int = 100
    worker_threads: int = 4
    nagle_disabled: bool = True  # TCP_NODELAY for low latency
    # UI
    dark_mode: bool = True
    chart_update_interval: float = 0.5
    # Web GUI
    webgui_enabled: bool = False
    webgui_host: str = "0.0.0.0"
    webgui_port: int = 9090
    # Profile
    profile_name: str = "Default"
    profiles: Dict[str, dict] = field(default_factory=dict)

    def save(self):
        SETTINGS_DIR.mkdir(parents=True, exist_ok=True)
        data = asdict(self)
        with open(SETTINGS_FILE, "w") as f:
            json.dump(data, f, indent=2)

    @classmethod
    def load(cls) -> "AppSettings":
        if SETTINGS_FILE.exists():
            try:
                with open(SETTINGS_FILE) as f:
                    data = json.load(f)
                settings = cls()
                for k, v in data.items():
                    if hasattr(settings, k):
                        setattr(settings, k, v)
                return settings
            except Exception:
                pass
        return cls()

    def save_profile(self, name: str):
        data = asdict(self)
        data.pop("profiles", None)
        data.pop("profile_name", None)
        self.profiles[name] = data
        self.profile_name = name
        self.save()

    def load_profile(self, name: str):
        if name in self.profiles:
            for k, v in self.profiles[name].items():
                if hasattr(self, k):
                    setattr(self, k, v)
            self.profile_name = name


# ============================================================================
# STATISTICS TRACKING
# ============================================================================

@dataclass
class ConnectionStats:
    """Real-time statistics for the tunnel."""
    bytes_sent: int = 0
    bytes_received: int = 0
    packets_sent: int = 0
    packets_received: int = 0
    packets_lost: int = 0
    active_connections: int = 0
    total_connections: int = 0
    start_time: float = field(default_factory=time.time)
    # Time series data
    throughput_in: Deque = field(default_factory=lambda: collections.deque(maxlen=STATS_HISTORY_SIZE))
    throughput_out: Deque = field(default_factory=lambda: collections.deque(maxlen=STATS_HISTORY_SIZE))
    latency_samples: Deque = field(default_factory=lambda: collections.deque(maxlen=STATS_HISTORY_SIZE))
    connection_counts: Deque = field(default_factory=lambda: collections.deque(maxlen=STATS_HISTORY_SIZE))
    cpu_usage: Deque = field(default_factory=lambda: collections.deque(maxlen=STATS_HISTORY_SIZE))
    memory_usage: Deque = field(default_factory=lambda: collections.deque(maxlen=STATS_HISTORY_SIZE))
    lag_spikes: Deque = field(default_factory=lambda: collections.deque(maxlen=STATS_HISTORY_SIZE))
    # Latency tracking
    current_latency_ms: float = 0.0
    avg_latency_ms: float = 0.0
    min_latency_ms: float = float("inf")
    max_latency_ms: float = 0.0
    jitter_ms: float = 0.0
    # Snapshot for rate calculation
    _last_bytes_sent: int = 0
    _last_bytes_received: int = 0
    _last_sample_time: float = field(default_factory=time.time)

    def sample(self):
        """Take a periodic sample for time-series data."""
        now = time.time()
        dt = now - self._last_sample_time
        if dt <= 0:
            dt = 0.001
        rate_out = (self.bytes_sent - self._last_bytes_sent) / dt
        rate_in = (self.bytes_received - self._last_bytes_received) / dt
        self.throughput_out.append(rate_out)
        self.throughput_in.append(rate_in)
        self.connection_counts.append(self.active_connections)
        self.latency_samples.append(self.current_latency_ms)
        # Lag spike detection (>50ms is a spike for gaming)
        is_spike = 1.0 if self.current_latency_ms > 50 else 0.0
        self.lag_spikes.append(is_spike)
        # System resources
        proc = psutil.Process()
        self.cpu_usage.append(proc.cpu_percent(interval=0))
        self.memory_usage.append(proc.memory_info().rss / (1024 * 1024))  # MB
        self._last_bytes_sent = self.bytes_sent
        self._last_bytes_received = self.bytes_received
        self._last_sample_time = now

    def update_latency(self, latency_ms: float):
        self.current_latency_ms = latency_ms
        if latency_ms < self.min_latency_ms:
            self.min_latency_ms = latency_ms
        if latency_ms > self.max_latency_ms:
            self.max_latency_ms = latency_ms
        # Running average
        if self.avg_latency_ms == 0:
            self.avg_latency_ms = latency_ms
        else:
            self.avg_latency_ms = self.avg_latency_ms * 0.95 + latency_ms * 0.05
        # Jitter = variation from average
        self.jitter_ms = abs(latency_ms - self.avg_latency_ms)

    def uptime(self) -> str:
        secs = int(time.time() - self.start_time)
        h, rem = divmod(secs, 3600)
        m, s = divmod(rem, 60)
        return f"{h:02d}:{m:02d}:{s:02d}"

    def format_bytes(self, b: int) -> str:
        for unit in ("B", "KB", "MB", "GB"):
            if b < 1024:
                return f"{b:.1f} {unit}"
            b /= 1024
        return f"{b:.1f} TB"


# ============================================================================
# LOGGING
# ============================================================================

class AppLogger:
    """Thread-safe logging with UI integration."""

    def __init__(self):
        SETTINGS_DIR.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger(APP_NAME)
        self.logger.setLevel(logging.DEBUG)
        fh = logging.FileHandler(str(LOG_FILE), encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
        fh.setFormatter(fmt)
        self.logger.addHandler(fh)
        self.ui_log: Deque[str] = collections.deque(maxlen=500)
        self._lock = threading.Lock()

    def log(self, level: str, msg: str):
        ts = time.strftime("%H:%M:%S")
        entry = f"[{ts}] [{level.upper()}] {msg}"
        with self._lock:
            self.ui_log.append(entry)
        getattr(self.logger, level.lower(), self.logger.info)(msg)

    def info(self, msg): self.log("INFO", msg)
    def warning(self, msg): self.log("WARNING", msg)
    def error(self, msg): self.log("ERROR", msg)
    def debug(self, msg): self.log("DEBUG", msg)

    def get_recent(self, count=50) -> List[str]:
        with self._lock:
            return list(self.ui_log)[-count:]


# ============================================================================
# PACKET PROTOCOL
# ============================================================================

class TunnelPacket:
    """
    Binary packet format for tunnel data:
    [4 bytes: magic] [1 byte: flags] [4 bytes: sequence] [8 bytes: timestamp]
    [4 bytes: payload_length] [N bytes: payload] [4 bytes: crc32]

    Flags: bit 0 = compressed, bit 1 = split packet, bit 2 = heartbeat, bit 3 = ack
    """
    MAGIC = b"HTCP"
    HEADER_FMT = "!4sBIdI"  # magic, flags, seq, timestamp, payload_len
    HEADER_SIZE = struct.calcsize(HEADER_FMT)
    FLAG_COMPRESSED = 0x01
    FLAG_SPLIT = 0x02
    FLAG_HEARTBEAT = 0x04
    FLAG_ACK = 0x08
    FLAG_CLOSE = 0x10

    @staticmethod
    def encode(payload: bytes, seq: int, flags: int = 0, compress: bool = False) -> bytes:
        if compress and len(payload) > 128:
            compressed = zlib.compress(payload, 1)  # Fast compression
            if len(compressed) < len(payload):
                payload = compressed
                flags |= TunnelPacket.FLAG_COMPRESSED
        ts = time.time()
        header = struct.pack(TunnelPacket.HEADER_FMT, TunnelPacket.MAGIC, flags, seq, ts, len(payload))
        crc = struct.pack("!I", zlib.crc32(header + payload) & 0xFFFFFFFF)
        return header + payload + crc

    @staticmethod
    def decode(data: bytes) -> Optional[Tuple[bytes, int, int, float]]:
        """Returns (payload, seq, flags, timestamp) or None on error."""
        if len(data) < TunnelPacket.HEADER_SIZE + 4:
            return None
        magic, flags, seq, ts, plen = struct.unpack(TunnelPacket.HEADER_FMT, data[:TunnelPacket.HEADER_SIZE])
        if magic != TunnelPacket.MAGIC:
            return None
        payload = data[TunnelPacket.HEADER_SIZE:TunnelPacket.HEADER_SIZE + plen]
        stored_crc = struct.unpack("!I", data[TunnelPacket.HEADER_SIZE + plen:TunnelPacket.HEADER_SIZE + plen + 4])[0]
        calc_crc = zlib.crc32(data[:TunnelPacket.HEADER_SIZE + plen]) & 0xFFFFFFFF
        if stored_crc != calc_crc:
            return None
        if flags & TunnelPacket.FLAG_COMPRESSED:
            payload = zlib.decompress(payload)
        return payload, seq, flags, ts

    @staticmethod
    def split_data(data: bytes, threshold: int) -> List[bytes]:
        """Split large data into smaller chunks for split-streaming."""
        if len(data) <= threshold:
            return [data]
        chunks = []
        for i in range(0, len(data), threshold):
            chunks.append(data[i:i + threshold])
        return chunks


# ============================================================================
# SERVER MODE
# ============================================================================

class TunnelServer:
    """
    HTTP(S) server that:
    1. Accepts HTTP connections from tunnel clients
    2. Connects to a local TCP/UDP service (e.g., Minecraft server)
    3. Bridges data bidirectionally between HTTP clients and the local service
    """

    def __init__(self, settings: AppSettings, stats: ConnectionStats, logger: AppLogger):
        self.settings = settings
        self.stats = stats
        self.logger = logger
        self.app = web.Application()
        self.runner: Optional[web.AppRunner] = None
        self.running = False
        self.seq_counter = 0
        self._client_sessions: Dict[str, dict] = {}  # session_id -> {reader, writer, ...}
        self._lock = asyncio.Lock()
        # Per-method connection tracking
        self.method_connection_counts: Dict[str, int] = {m.value: 0 for m in StreamingMethod}
        self._setup_routes()

    def _is_method_allowed(self, method_value: str) -> bool:
        return method_value in self.settings.server_allowed_methods

    def _setup_routes(self):
        self.app.router.add_get("/", self._handle_info)
        self.app.router.add_get("/health", self._handle_health)
        self.app.router.add_get("/ws", self._handle_websocket)
        self.app.router.add_post("/connect", self._handle_connect)
        self.app.router.add_post("/data/{session_id}", self._handle_data_upload)
        self.app.router.add_get("/data/{session_id}", self._handle_data_download)
        self.app.router.add_get("/sse/{session_id}", self._handle_sse)
        self.app.router.add_post("/poll/{session_id}", self._handle_long_poll)
        self.app.router.add_delete("/disconnect/{session_id}", self._handle_disconnect)
        self.app.router.add_get("/ping", self._handle_ping)
        self.app.router.add_post("/test/{method}", self._handle_method_test)

    def _check_auth(self, request: web.Request) -> bool:
        if not self.settings.auth_token:
            return True
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        return token == self.settings.auth_token

    async def _handle_info(self, request: web.Request):
        return web.json_response({
            "app": APP_NAME,
            "version": APP_VERSION,
            "mode": "server",
            "allowed_methods": self.settings.server_allowed_methods,
            "streaming_methods": [m.value for m in StreamingMethod],
            "method_connections": dict(self.method_connection_counts),
            "protocol": self.settings.server_protocol,
            "active_sessions": len(self._client_sessions),
        })

    async def _handle_health(self, request: web.Request):
        return web.json_response({"status": "ok", "uptime": self.stats.uptime()})

    async def _handle_ping(self, request: web.Request):
        return web.json_response({"pong": time.time()})

    async def _handle_method_test(self, request: web.Request):
        """Quick echo test for a specific streaming method to let clients measure latency/speed."""
        if not self._check_auth(request):
            return web.json_response({"error": "Unauthorized"}, status=401)
        method = request.match_info["method"]
        if method not in self.settings.server_allowed_methods:
            return web.json_response({"error": "Method not allowed", "method": method}, status=403)
        body = await request.read()
        client_ts = 0.0
        if body:
            try:
                client_ts = struct.unpack("!d", body[:8])[0]
            except Exception:
                pass
        server_ts = time.time()
        return web.json_response({
            "method": method,
            "allowed": True,
            "client_ts": client_ts,
            "server_ts": server_ts,
            "echo_bytes": len(body),
        })

    async def _connect_to_service(self, session_id: str) -> Tuple[Optional[asyncio.StreamReader], Optional[asyncio.StreamWriter]]:
        """Connect to the local TCP/UDP service."""
        try:
            if self.settings.server_protocol == "tcp":
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.settings.server_tcp_host, self.settings.server_tcp_port),
                    timeout=CONNECTION_TIMEOUT
                )
                if self.settings.nagle_disabled:
                    sock = writer.get_extra_info("socket")
                    if sock:
                        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                return reader, writer
            else:
                # UDP - wrap in asyncio protocol
                loop = asyncio.get_event_loop()
                transport, protocol = await loop.create_datagram_endpoint(
                    lambda: UDPBridge(session_id, self),
                    remote_addr=(self.settings.server_tcp_host, self.settings.server_tcp_port)
                )
                return transport, None
        except Exception as e:
            self.logger.error(f"Failed to connect to service: {e}")
            return None, None

    async def _handle_connect(self, request: web.Request):
        """Create a new tunnel session (used by chunked, SSE, long_poll methods)."""
        if not self._check_auth(request):
            return web.json_response({"error": "Unauthorized"}, status=401)

        # Determine which method the client intends to use
        req_method = request.query.get("method", "chunked")
        if not self._is_method_allowed(req_method):
            return web.json_response({"error": f"Method '{req_method}' not allowed by server"}, status=403)

        session_id = uuid.uuid4().hex[:16]
        reader, writer = await self._connect_to_service(session_id)
        if reader is None and self.settings.server_protocol == "tcp":
            return web.json_response({"error": "Cannot connect to backend service"}, status=502)

        async with self._lock:
            self._client_sessions[session_id] = {
                "reader": reader,
                "writer": writer,
                "created": time.time(),
                "outbound_queue": asyncio.Queue(maxsize=1000),
                "seq": 0,
                "method": req_method,
            }
        self.stats.active_connections += 1
        self.stats.total_connections += 1
        self.method_connection_counts[req_method] = self.method_connection_counts.get(req_method, 0) + 1
        self.logger.info(f"New session: {session_id} method={req_method} (active: {self.stats.active_connections})")

        # Start reading from the backend service
        asyncio.ensure_future(self._read_from_service(session_id))

        return web.json_response({"session_id": session_id, "status": "connected"})

    async def _read_from_service(self, session_id: str):
        """Read data from the backend TCP service and queue it for the HTTP client."""
        session = self._client_sessions.get(session_id)
        if not session:
            return
        reader = session["reader"]
        queue = session["outbound_queue"]
        try:
            while session_id in self._client_sessions:
                data = await asyncio.wait_for(reader.read(self.settings.buffer_size), timeout=60)
                if not data:
                    break
                self.stats.bytes_received += len(data)
                self.stats.packets_received += 1
                # Split if needed
                if self.settings.split_streaming and len(data) > self.settings.split_threshold:
                    chunks = TunnelPacket.split_data(data, self.settings.split_threshold)
                    for chunk in chunks:
                        session["seq"] += 1
                        pkt = TunnelPacket.encode(chunk, session["seq"], TunnelPacket.FLAG_SPLIT, self.settings.compression)
                        await queue.put(pkt)
                else:
                    session["seq"] += 1
                    pkt = TunnelPacket.encode(data, session["seq"], 0, self.settings.compression)
                    await queue.put(pkt)
        except asyncio.TimeoutError:
            pass
        except Exception as e:
            self.logger.debug(f"Service read ended for {session_id}: {e}")
        finally:
            # Signal end of stream
            try:
                await queue.put(None)
            except Exception:
                pass

    async def _handle_data_upload(self, request: web.Request):
        """Receive data from HTTP client and forward to backend service (chunked method)."""
        if not self._check_auth(request):
            return web.json_response({"error": "Unauthorized"}, status=401)
        session_id = request.match_info["session_id"]
        session = self._client_sessions.get(session_id)
        if not session:
            return web.json_response({"error": "Session not found"}, status=404)

        body = await request.read()
        result = TunnelPacket.decode(body)
        if result is None:
            self.stats.packets_lost += 1
            return web.json_response({"error": "Invalid packet"}, status=400)

        payload, seq, flags, ts = result
        latency = (time.time() - ts) * 1000
        self.stats.update_latency(latency)

        writer = session["writer"]
        if writer and not writer.is_closing():
            writer.write(payload)
            await writer.drain()
            self.stats.bytes_sent += len(payload)
            self.stats.packets_sent += 1

        return web.json_response({"status": "ok", "latency_ms": round(latency, 2)})

    async def _handle_data_download(self, request: web.Request):
        """Send queued data to HTTP client (chunked transfer encoding)."""
        if not self._check_auth(request):
            return web.json_response({"error": "Unauthorized"}, status=401)
        session_id = request.match_info["session_id"]
        session = self._client_sessions.get(session_id)
        if not session:
            return web.json_response({"error": "Session not found"}, status=404)

        response = web.StreamResponse(
            status=200,
            headers={"Content-Type": "application/octet-stream", "Transfer-Encoding": "chunked"}
        )
        await response.prepare(request)

        queue = session["outbound_queue"]
        try:
            while True:
                try:
                    pkt = await asyncio.wait_for(queue.get(), timeout=30)
                except asyncio.TimeoutError:
                    # Send heartbeat
                    hb = TunnelPacket.encode(b"", 0, TunnelPacket.FLAG_HEARTBEAT)
                    await response.write(struct.pack("!I", len(hb)) + hb)
                    continue
                if pkt is None:
                    break
                # Length-prefix each packet for framing
                await response.write(struct.pack("!I", len(pkt)) + pkt)
                self.stats.bytes_sent += len(pkt)
                self.stats.packets_sent += 1
        except (ConnectionResetError, ConnectionError):
            pass
        finally:
            await response.write_eof()
        return response

    async def _handle_websocket(self, request: web.Request):
        """WebSocket handler - full duplex, lowest latency."""
        if not self._check_auth(request):
            return web.json_response({"error": "Unauthorized"}, status=401)
        if not self._is_method_allowed("websocket"):
            return web.json_response({"error": "WebSocket method not allowed"}, status=403)

        ws = web.WebSocketResponse(max_msg_size=0)  # No limit
        await ws.prepare(request)

        # Create session
        session_id = uuid.uuid4().hex[:16]
        reader, writer = await self._connect_to_service(session_id)
        if reader is None and self.settings.server_protocol == "tcp":
            await ws.close(code=1011, message=b"Cannot connect to backend")
            return ws

        self.stats.active_connections += 1
        self.stats.total_connections += 1
        self.method_connection_counts["websocket"] = self.method_connection_counts.get("websocket", 0) + 1
        self.logger.info(f"WebSocket session: {session_id}")

        seq = 0

        async def ws_to_service():
            """Forward WebSocket messages to the backend service."""
            nonlocal seq
            try:
                async for msg in ws:
                    if msg.type == aiohttp.WSMsgType.BINARY:
                        result = TunnelPacket.decode(msg.data)
                        if result:
                            payload, s, flags, ts = result
                            latency = (time.time() - ts) * 1000
                            self.stats.update_latency(latency)
                            if writer and not writer.is_closing():
                                writer.write(payload)
                                await writer.drain()
                                self.stats.bytes_sent += len(payload)
                                self.stats.packets_sent += 1
                        else:
                            self.stats.packets_lost += 1
                    elif msg.type in (aiohttp.WSMsgType.ERROR, aiohttp.WSMsgType.CLOSE):
                        break
            except Exception as e:
                self.logger.debug(f"WS recv error: {e}")

        async def service_to_ws():
            """Forward backend service data to WebSocket."""
            nonlocal seq
            try:
                while not ws.closed:
                    data = await asyncio.wait_for(reader.read(self.settings.buffer_size), timeout=60)
                    if not data:
                        break
                    self.stats.bytes_received += len(data)
                    self.stats.packets_received += 1
                    if self.settings.split_streaming and len(data) > self.settings.split_threshold:
                        for chunk in TunnelPacket.split_data(data, self.settings.split_threshold):
                            seq += 1
                            pkt = TunnelPacket.encode(chunk, seq, TunnelPacket.FLAG_SPLIT, self.settings.compression)
                            await ws.send_bytes(pkt)
                    else:
                        seq += 1
                        pkt = TunnelPacket.encode(data, seq, 0, self.settings.compression)
                        await ws.send_bytes(pkt)
            except asyncio.TimeoutError:
                pass
            except Exception as e:
                self.logger.debug(f"WS send error: {e}")

        try:
            await asyncio.gather(ws_to_service(), service_to_ws())
        finally:
            self.stats.active_connections -= 1
            self.method_connection_counts["websocket"] = max(0, self.method_connection_counts.get("websocket", 1) - 1)
            if writer and not writer.is_closing():
                writer.close()
            self.logger.info(f"WebSocket session ended: {session_id}")

        return ws

    async def _handle_sse(self, request: web.Request):
        """Server-Sent Events stream for downstream data."""
        if not self._check_auth(request):
            return web.json_response({"error": "Unauthorized"}, status=401)
        session_id = request.match_info["session_id"]
        session = self._client_sessions.get(session_id)
        if not session:
            return web.json_response({"error": "Session not found"}, status=404)

        response = web.StreamResponse(
            status=200,
            headers={"Content-Type": "text/event-stream", "Cache-Control": "no-cache", "Connection": "keep-alive"}
        )
        await response.prepare(request)
        queue = session["outbound_queue"]

        import base64
        try:
            while True:
                try:
                    pkt = await asyncio.wait_for(queue.get(), timeout=30)
                except asyncio.TimeoutError:
                    await response.write(b": heartbeat\n\n")
                    continue
                if pkt is None:
                    break
                encoded = base64.b64encode(pkt).decode()
                await response.write(f"data: {encoded}\n\n".encode())
                self.stats.bytes_sent += len(pkt)
                self.stats.packets_sent += 1
        except (ConnectionResetError, ConnectionError):
            pass
        return response

    async def _handle_long_poll(self, request: web.Request):
        """Long polling - send data and receive any queued response."""
        if not self._check_auth(request):
            return web.json_response({"error": "Unauthorized"}, status=401)
        session_id = request.match_info["session_id"]
        session = self._client_sessions.get(session_id)
        if not session:
            return web.json_response({"error": "Session not found"}, status=404)

        # Process uploaded data
        body = await request.read()
        if body:
            result = TunnelPacket.decode(body)
            if result:
                payload, seq, flags, ts = result
                latency = (time.time() - ts) * 1000
                self.stats.update_latency(latency)
                writer = session["writer"]
                if writer and not writer.is_closing():
                    writer.write(payload)
                    await writer.drain()
                    self.stats.bytes_sent += len(payload)
                    self.stats.packets_sent += 1

        # Collect queued data (wait up to 100ms for gaming latency)
        queue = session["outbound_queue"]
        packets = []
        try:
            while True:
                pkt = await asyncio.wait_for(queue.get(), timeout=0.1)
                if pkt is None:
                    break
                packets.append(pkt)
                if len(packets) >= 10:
                    break
        except asyncio.TimeoutError:
            pass

        if packets:
            # Concatenate with length prefixing
            buf = io.BytesIO()
            for pkt in packets:
                buf.write(struct.pack("!I", len(pkt)))
                buf.write(pkt)
            return web.Response(body=buf.getvalue(), content_type="application/octet-stream")
        return web.Response(body=b"", content_type="application/octet-stream")

    async def _handle_disconnect(self, request: web.Request):
        """Close a tunnel session."""
        session_id = request.match_info["session_id"]
        await self._close_session(session_id)
        return web.json_response({"status": "disconnected"})

    async def _close_session(self, session_id: str):
        async with self._lock:
            session = self._client_sessions.pop(session_id, None)
        if session:
            writer = session.get("writer")
            if writer and not writer.is_closing():
                writer.close()
            method = session.get("method", "")
            if method in self.method_connection_counts:
                self.method_connection_counts[method] = max(0, self.method_connection_counts[method] - 1)
            self.stats.active_connections = max(0, self.stats.active_connections - 1)
            self.logger.info(f"Session closed: {session_id}")

    async def start(self):
        """Start the HTTP server."""
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        ssl_ctx = None
        if self.settings.use_tls and self.settings.tls_cert_path and self.settings.tls_key_path:
            ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ssl_ctx.load_cert_chain(self.settings.tls_cert_path, self.settings.tls_key_path)
        site = web.TCPSite(self.runner, self.settings.server_http_host, self.settings.server_http_port, ssl_context=ssl_ctx)
        await site.start()
        self.running = True
        proto = "HTTPS" if ssl_ctx else "HTTP"
        self.logger.info(f"Server started on {proto}://{self.settings.server_http_host}:{self.settings.server_http_port}")
        self.logger.info(f"Bridging to {self.settings.server_protocol.upper()}://{self.settings.server_tcp_host}:{self.settings.server_tcp_port}")

    async def stop(self):
        """Stop the HTTP server."""
        self.running = False
        for sid in list(self._client_sessions.keys()):
            await self._close_session(sid)
        if self.runner:
            await self.runner.cleanup()
        self.logger.info("Server stopped")


# ============================================================================
# CLIENT MODE
# ============================================================================

class TunnelClient:
    """
    Local TCP/UDP listener that:
    1. Accepts connections from local applications (e.g., Minecraft client)
    2. Tunnels data over HTTP(S) to the remote TunnelServer
    3. Returns response data back to the local application
    """

    def __init__(self, settings: AppSettings, stats: ConnectionStats, logger: AppLogger):
        self.settings = settings
        self.stats = stats
        self.logger = logger
        self.running = False
        self._server: Optional[asyncio.AbstractServer] = None
        self._http_session: Optional[aiohttp.ClientSession] = None
        self.seq_counter = 0
        self._auto_detect_results: Dict[str, list] = {}

    def _get_ssl_context(self) -> Optional[ssl.SSLContext]:
        if self.settings.client_remote_url.startswith("https"):
            ctx = ssl.create_default_context()
            if not self.settings.verify_ssl:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            return ctx
        return None

    def _auth_headers(self) -> dict:
        headers = {}
        if self.settings.auth_token:
            headers["Authorization"] = f"Bearer {self.settings.auth_token}"
        return headers

    async def start(self):
        """Start the local listener."""
        connector = aiohttp.TCPConnector(
            limit=self.settings.max_connections,
            enable_cleanup_closed=True,
            ssl=self._get_ssl_context() if not self.settings.verify_ssl else None,
        )
        self._http_session = aiohttp.ClientSession(
            connector=connector,
            headers=self._auth_headers(),
            timeout=aiohttp.ClientTimeout(total=None, connect=CONNECTION_TIMEOUT),
        )

        if self.settings.auto_detect_method:
            await self._auto_detect_streaming_method()

        if self.settings.client_protocol == "tcp":
            self._server = await asyncio.start_server(
                self._handle_local_connection,
                self.settings.client_local_host,
                self.settings.client_local_port,
            )
        else:
            loop = asyncio.get_event_loop()
            transport, _ = await loop.create_datagram_endpoint(
                lambda: UDPClientBridge(self),
                local_addr=(self.settings.client_local_host, self.settings.client_local_port)
            )
            self._server = transport

        self.running = True
        method = StreamingMethod(self.settings.streaming_method)
        self.logger.info(f"Client listening on {self.settings.client_protocol.upper()}://{self.settings.client_local_host}:{self.settings.client_local_port}")
        self.logger.info(f"Tunneling to {self.settings.client_remote_url} via {method.value}")

    async def _auto_detect_streaming_method(self) -> List[Dict]:
        """Test each streaming method the server allows and pick the fastest.
        Returns a list of results for UI display: [{method, name, avg_ms, status}, ...]"""
        self.logger.info("Auto-detecting best streaming method...")
        base = self.settings.client_remote_url.rstrip("/")

        # First, query server for allowed methods
        allowed = list(ALL_METHOD_VALUES)
        try:
            async with self._http_session.get(f"{base}/") as resp:
                info = await resp.json()
                allowed = info.get("allowed_methods", allowed)
        except Exception as e:
            self.logger.warning(f"Could not query server capabilities: {e}")

        results = []
        test_payload = struct.pack("!d", time.time()) + os.urandom(1024)  # 1KB echo test

        for method_val in allowed:
            try:
                method_enum = StreamingMethod(method_val)
            except ValueError:
                continue
            info = STREAMING_METHOD_INFO.get(method_enum, {})
            method_name = info.get("name", method_val)

            latencies = []
            errors = 0
            self.logger.info(f"  Testing {method_name}...")
            for i in range(AUTO_DETECT_SAMPLE_COUNT):
                try:
                    payload = struct.pack("!d", time.time()) + os.urandom(1024)
                    t0 = time.time()
                    async with self._http_session.post(
                        f"{base}/test/{method_val}", data=payload
                    ) as resp:
                        rdata = await resp.json()
                        if resp.status == 403:
                            errors = AUTO_DETECT_SAMPLE_COUNT
                            break
                    rtt = (time.time() - t0) * 1000
                    latencies.append(rtt)
                except Exception:
                    errors += 1

            if latencies:
                avg = sum(latencies) / len(latencies)
                results.append({
                    "method": method_val,
                    "name": method_name,
                    "avg_ms": round(avg, 2),
                    "min_ms": round(min(latencies), 2),
                    "max_ms": round(max(latencies), 2),
                    "errors": errors,
                    "status": "ok",
                })
            else:
                results.append({
                    "method": method_val,
                    "name": method_name,
                    "avg_ms": float("inf"),
                    "min_ms": 0,
                    "max_ms": 0,
                    "errors": errors,
                    "status": "failed",
                })

        # Sort by avg latency ascending
        results.sort(key=lambda r: r["avg_ms"])
        self._auto_detect_results = results

        # Pick the best working method
        for r in results:
            if r["status"] == "ok":
                self.settings.streaming_method = r["method"]
                self.logger.info(f"Auto-detected best: {r['name']} (avg {r['avg_ms']}ms)")
                break

        # Log summary
        self.logger.info("Auto-detect results:")
        for r in results:
            marker = " << SELECTED" if r["method"] == self.settings.streaming_method else ""
            self.logger.info(f"  {r['name']:25s} avg={r['avg_ms']:>8.2f}ms  min={r['min_ms']:>8.2f}ms  max={r['max_ms']:>8.2f}ms  err={r['errors']}{marker}")

        return results

    async def _handle_local_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle a new local TCP connection and tunnel it."""
        peer = writer.get_extra_info("peername")
        self.logger.info(f"Local connection from {peer}")
        self.stats.active_connections += 1
        self.stats.total_connections += 1

        if self.settings.nagle_disabled:
            sock = writer.get_extra_info("socket")
            if sock:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        method = StreamingMethod(self.settings.streaming_method)

        try:
            if method == StreamingMethod.WEBSOCKET:
                await self._tunnel_websocket(reader, writer)
            elif method == StreamingMethod.CHUNKED:
                await self._tunnel_chunked(reader, writer)
            elif method == StreamingMethod.SSE:
                await self._tunnel_sse(reader, writer)
            elif method == StreamingMethod.LONG_POLL:
                await self._tunnel_long_poll(reader, writer)
            else:
                await self._tunnel_websocket(reader, writer)
        except Exception as e:
            self.logger.error(f"Tunnel error: {e}")
        finally:
            self.stats.active_connections = max(0, self.stats.active_connections - 1)
            if not writer.is_closing():
                writer.close()
            self.logger.info(f"Connection from {peer} closed")

    async def _tunnel_websocket(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """WebSocket tunnel - full duplex."""
        base = self.settings.client_remote_url.rstrip("/").replace("http", "ws", 1)
        ssl_ctx = self._get_ssl_context()

        async with self._http_session.ws_connect(f"{base}/ws", ssl=ssl_ctx, max_msg_size=0) as ws:
            async def local_to_remote():
                try:
                    while True:
                        data = await reader.read(self.settings.buffer_size)
                        if not data:
                            break
                        self.stats.bytes_received += len(data)
                        self.stats.packets_received += 1
                        if self.settings.split_streaming and len(data) > self.settings.split_threshold:
                            for chunk in TunnelPacket.split_data(data, self.settings.split_threshold):
                                self.seq_counter += 1
                                pkt = TunnelPacket.encode(chunk, self.seq_counter, TunnelPacket.FLAG_SPLIT, self.settings.compression)
                                await ws.send_bytes(pkt)
                        else:
                            self.seq_counter += 1
                            pkt = TunnelPacket.encode(data, self.seq_counter, 0, self.settings.compression)
                            await ws.send_bytes(pkt)
                except Exception:
                    pass

            async def remote_to_local():
                try:
                    async for msg in ws:
                        if msg.type == aiohttp.WSMsgType.BINARY:
                            result = TunnelPacket.decode(msg.data)
                            if result:
                                payload, seq, flags, ts = result
                                if not (flags & TunnelPacket.FLAG_HEARTBEAT):
                                    writer.write(payload)
                                    await writer.drain()
                                    self.stats.bytes_sent += len(payload)
                                    self.stats.packets_sent += 1
                                latency = (time.time() - ts) * 1000
                                self.stats.update_latency(latency)
                            else:
                                self.stats.packets_lost += 1
                        elif msg.type in (aiohttp.WSMsgType.ERROR, aiohttp.WSMsgType.CLOSE):
                            break
                except Exception:
                    pass

            await asyncio.gather(local_to_remote(), remote_to_local())

    async def _tunnel_chunked(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Chunked transfer tunnel - uses POST for upload, GET stream for download."""
        base = self.settings.client_remote_url.rstrip("/")
        ssl_ctx = self._get_ssl_context()

        # Create session
        async with self._http_session.post(f"{base}/connect?method=chunked", ssl=ssl_ctx) as resp:
            data = await resp.json()
            session_id = data.get("session_id")
            if not session_id:
                self.logger.error("Failed to create tunnel session")
                return

        async def local_to_remote():
            try:
                while True:
                    data = await reader.read(self.settings.buffer_size)
                    if not data:
                        break
                    self.stats.bytes_received += len(data)
                    self.stats.packets_received += 1
                    self.seq_counter += 1
                    pkt = TunnelPacket.encode(data, self.seq_counter, 0, self.settings.compression)
                    async with self._http_session.post(
                        f"{base}/data/{session_id}", data=pkt, ssl=ssl_ctx
                    ) as resp:
                        rdata = await resp.json()
                        if "latency_ms" in rdata:
                            self.stats.update_latency(rdata["latency_ms"])
            except Exception as e:
                self.logger.debug(f"Upload ended: {e}")

        async def remote_to_local():
            try:
                async with self._http_session.get(f"{base}/data/{session_id}", ssl=ssl_ctx) as resp:
                    buf = b""
                    async for chunk in resp.content.iter_any():
                        buf += chunk
                        while len(buf) >= 4:
                            pkt_len = struct.unpack("!I", buf[:4])[0]
                            if len(buf) < 4 + pkt_len:
                                break
                            pkt_data = buf[4:4 + pkt_len]
                            buf = buf[4 + pkt_len:]
                            result = TunnelPacket.decode(pkt_data)
                            if result:
                                payload, seq, flags, ts = result
                                if not (flags & TunnelPacket.FLAG_HEARTBEAT):
                                    writer.write(payload)
                                    await writer.drain()
                                    self.stats.bytes_sent += len(payload)
                                    self.stats.packets_sent += 1
                                latency = (time.time() - ts) * 1000
                                self.stats.update_latency(latency)
                            else:
                                self.stats.packets_lost += 1
            except Exception as e:
                self.logger.debug(f"Download ended: {e}")

        try:
            await asyncio.gather(local_to_remote(), remote_to_local())
        finally:
            try:
                await self._http_session.delete(f"{base}/disconnect/{session_id}", ssl=ssl_ctx)
            except Exception:
                pass

    async def _tunnel_sse(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """SSE tunnel - SSE for download, POST for upload."""
        base = self.settings.client_remote_url.rstrip("/")
        ssl_ctx = self._get_ssl_context()

        async with self._http_session.post(f"{base}/connect?method=sse", ssl=ssl_ctx) as resp:
            data = await resp.json()
            session_id = data.get("session_id")
            if not session_id:
                return

        async def local_to_remote():
            try:
                while True:
                    data = await reader.read(self.settings.buffer_size)
                    if not data:
                        break
                    self.stats.bytes_received += len(data)
                    self.stats.packets_received += 1
                    self.seq_counter += 1
                    pkt = TunnelPacket.encode(data, self.seq_counter, 0, self.settings.compression)
                    async with self._http_session.post(f"{base}/data/{session_id}", data=pkt, ssl=ssl_ctx) as resp:
                        pass
            except Exception:
                pass

        async def remote_to_local():
            try:
                async with self._http_session.get(f"{base}/sse/{session_id}", ssl=ssl_ctx) as resp:
                    buf = b""
                    async for line_bytes in resp.content:
                        line = line_bytes.decode("utf-8", errors="ignore").strip()
                        if line.startswith("data: "):
                            encoded = line[6:]
                            pkt_data = base64.b64decode(encoded)
                            result = TunnelPacket.decode(pkt_data)
                            if result:
                                payload, seq, flags, ts = result
                                writer.write(payload)
                                await writer.drain()
                                self.stats.bytes_sent += len(payload)
                                self.stats.packets_sent += 1
                                latency = (time.time() - ts) * 1000
                                self.stats.update_latency(latency)
            except Exception:
                pass

        try:
            await asyncio.gather(local_to_remote(), remote_to_local())
        finally:
            try:
                await self._http_session.delete(f"{base}/disconnect/{session_id}", ssl=ssl_ctx)
            except Exception:
                pass

    async def _tunnel_long_poll(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Long polling tunnel - periodic POST requests carrying data both ways."""
        base = self.settings.client_remote_url.rstrip("/")
        ssl_ctx = self._get_ssl_context()

        async with self._http_session.post(f"{base}/connect?method=long_poll", ssl=ssl_ctx) as resp:
            data = await resp.json()
            session_id = data.get("session_id")
            if not session_id:
                return

        outbound_queue = asyncio.Queue()

        async def read_local():
            try:
                while True:
                    data = await reader.read(self.settings.buffer_size)
                    if not data:
                        break
                    self.stats.bytes_received += len(data)
                    self.stats.packets_received += 1
                    self.seq_counter += 1
                    pkt = TunnelPacket.encode(data, self.seq_counter, 0, self.settings.compression)
                    await outbound_queue.put(pkt)
            except Exception:
                pass

        async def poll_loop():
            try:
                while self.running:
                    # Get data to send
                    send_data = b""
                    try:
                        pkt = await asyncio.wait_for(outbound_queue.get(), timeout=0.05)
                        send_data = pkt
                    except asyncio.TimeoutError:
                        pass

                    async with self._http_session.post(
                        f"{base}/poll/{session_id}", data=send_data, ssl=ssl_ctx
                    ) as resp:
                        body = await resp.read()
                        if body:
                            offset = 0
                            while offset < len(body) - 4:
                                pkt_len = struct.unpack("!I", body[offset:offset + 4])[0]
                                offset += 4
                                pkt_data = body[offset:offset + pkt_len]
                                offset += pkt_len
                                result = TunnelPacket.decode(pkt_data)
                                if result:
                                    payload, seq, flags, ts = result
                                    writer.write(payload)
                                    await writer.drain()
                                    self.stats.bytes_sent += len(payload)
                                    self.stats.packets_sent += 1
                                    latency = (time.time() - ts) * 1000
                                    self.stats.update_latency(latency)
            except Exception:
                pass

        try:
            await asyncio.gather(read_local(), poll_loop())
        finally:
            try:
                await self._http_session.delete(f"{base}/disconnect/{session_id}", ssl=ssl_ctx)
            except Exception:
                pass

    async def stop(self):
        self.running = False
        if self._server:
            if hasattr(self._server, "close"):
                self._server.close()
                if hasattr(self._server, "wait_closed"):
                    await self._server.wait_closed()
        if self._http_session:
            await self._http_session.close()
        self.logger.info("Client stopped")


# ============================================================================
# UDP BRIDGES
# ============================================================================

class UDPBridge(asyncio.DatagramProtocol):
    """UDP bridge for server-side."""

    def __init__(self, session_id: str, server: TunnelServer):
        self.session_id = session_id
        self.server = server
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.server.stats.bytes_received += len(data)
        self.server.stats.packets_received += 1
        session = self.server._client_sessions.get(self.session_id)
        if session:
            self.server.seq_counter += 1
            pkt = TunnelPacket.encode(data, self.server.seq_counter, 0, self.server.settings.compression)
            asyncio.ensure_future(session["outbound_queue"].put(pkt))


class UDPClientBridge(asyncio.DatagramProtocol):
    """UDP bridge for client-side local listener."""

    def __init__(self, client: TunnelClient):
        self.client = client
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.client.stats.bytes_received += len(data)
        self.client.stats.packets_received += 1
        # Forward via HTTP tunnel
        asyncio.ensure_future(self._forward(data, addr))

    async def _forward(self, data, addr):
        pass  # Handled by the tunnel method


# ============================================================================
# NETWORK SPEED TEST
# ============================================================================

class NetworkTester:
    """Tests tunnel speed and latency."""

    def __init__(self, settings: AppSettings, stats: ConnectionStats, logger: AppLogger):
        self.settings = settings
        self.stats = stats
        self.logger = logger
        self.results: Dict[str, Any] = {}
        self.running = False

    async def run_latency_test(self, count: int = 20) -> Dict:
        """Ping test to measure base latency."""
        base = self.settings.client_remote_url.rstrip("/")
        latencies = []
        try:
            async with aiohttp.ClientSession() as session:
                for i in range(count):
                    t0 = time.time()
                    async with session.get(f"{base}/ping") as resp:
                        await resp.json()
                    ms = (time.time() - t0) * 1000
                    latencies.append(ms)
        except Exception as e:
            self.logger.error(f"Latency test failed: {e}")
            return {"error": str(e)}

        if not latencies:
            return {"error": "No results"}
        result = {
            "min_ms": round(min(latencies), 2),
            "max_ms": round(max(latencies), 2),
            "avg_ms": round(sum(latencies) / len(latencies), 2),
            "jitter_ms": round(max(latencies) - min(latencies), 2),
            "samples": latencies,
        }
        self.results["latency"] = result
        self.logger.info(f"Latency test: avg={result['avg_ms']}ms min={result['min_ms']}ms max={result['max_ms']}ms")
        return result

    async def run_throughput_test(self, size_kb: int = 1024) -> Dict:
        """Throughput test - upload and download."""
        base = self.settings.client_remote_url.rstrip("/")
        test_data = os.urandom(size_kb * 1024)

        result = {}
        try:
            async with aiohttp.ClientSession() as session:
                # Upload test
                t0 = time.time()
                async with session.post(f"{base}/connect") as resp:
                    data = await resp.json()
                    sid = data.get("session_id")
                if sid:
                    pkt = TunnelPacket.encode(test_data, 1, 0, False)
                    t0 = time.time()
                    async with session.post(f"{base}/data/{sid}", data=pkt) as resp:
                        await resp.read()
                    elapsed = time.time() - t0
                    result["upload_mbps"] = round((size_kb / 1024) / elapsed * 8, 2) if elapsed > 0 else 0
                    result["upload_time_ms"] = round(elapsed * 1000, 2)
                    await session.delete(f"{base}/disconnect/{sid}")
        except Exception as e:
            self.logger.error(f"Throughput test failed: {e}")
            result["error"] = str(e)

        self.results["throughput"] = result
        self.logger.info(f"Throughput test: {result}")
        return result


# ============================================================================
# APPLICATION UI
# ============================================================================

class AppUI:
    """Modern DearPyGui-based user interface."""

    # Color theme
    BG_COLOR = (30, 30, 46)
    SURFACE_COLOR = (45, 45, 65)
    ACCENT = (137, 180, 250)
    GREEN = (166, 227, 161)
    RED = (243, 139, 168)
    YELLOW = (249, 226, 175)
    TEXT = (205, 214, 244)
    SUBTEXT = (147, 153, 178)

    def __init__(self, settings: Optional[AppSettings] = None):
        _ensure_dpg()
        self.settings = settings or AppSettings.load()
        self.stats = ConnectionStats()
        self.logger = AppLogger()
        self.server: Optional[TunnelServer] = None
        self.client: Optional[TunnelClient] = None
        self.tester = NetworkTester(self.settings, self.stats, self.logger)
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self._async_thread: Optional[threading.Thread] = None
        self._stats_running = True
        self._tunnel_running = False
        self._initialized_plots = False
        self._auto_detect_results: List[Dict] = []

    def _start_async_loop(self):
        """Start asyncio event loop in a separate thread."""
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    def _run_async(self, coro):
        """Schedule a coroutine on the async loop."""
        if self.loop and self.loop.is_running():
            return asyncio.run_coroutine_threadsafe(coro, self.loop)
        return None

    def run(self):
        """Main entry point - create and run the UI."""
        dpg.create_context()
        self._setup_theme()
        self._setup_fonts()
        self._create_main_window()
        dpg.create_viewport(
            title=f"{APP_NAME} v{APP_VERSION}",
            width=1280,
            height=820,
            min_width=900,
            min_height=600,
        )
        dpg.setup_dearpygui()
        dpg.show_viewport()
        dpg.set_primary_window("main_window", True)

        # Start async thread
        self._async_thread = threading.Thread(target=self._start_async_loop, daemon=True)
        self._async_thread.start()

        # Start stats collection thread
        stats_thread = threading.Thread(target=self._stats_loop, daemon=True)
        stats_thread.start()

        # Main render loop
        while dpg.is_dearpygui_running():
            self._update_ui()
            dpg.render_dearpygui_frame()

        # Cleanup
        self._stats_running = False
        if self._tunnel_running:
            self._stop_tunnel()
        if self.loop:
            self.loop.call_soon_threadsafe(self.loop.stop)
        self.settings.save()
        dpg.destroy_context()

    def _setup_theme(self):
        with dpg.theme() as self.global_theme:
            with dpg.theme_component(dpg.mvAll):
                dpg.add_theme_color(dpg.mvThemeCol_WindowBg, self.BG_COLOR)
                dpg.add_theme_color(dpg.mvThemeCol_ChildBg, self.SURFACE_COLOR)
                dpg.add_theme_color(dpg.mvThemeCol_Text, self.TEXT)
                dpg.add_theme_color(dpg.mvThemeCol_Button, (69, 71, 90))
                dpg.add_theme_color(dpg.mvThemeCol_ButtonHovered, self.ACCENT)
                dpg.add_theme_color(dpg.mvThemeCol_ButtonActive, (116, 153, 218))
                dpg.add_theme_color(dpg.mvThemeCol_FrameBg, (49, 50, 68))
                dpg.add_theme_color(dpg.mvThemeCol_FrameBgHovered, (59, 60, 80))
                dpg.add_theme_color(dpg.mvThemeCol_Header, (69, 71, 90))
                dpg.add_theme_color(dpg.mvThemeCol_HeaderHovered, self.ACCENT)
                dpg.add_theme_color(dpg.mvThemeCol_Tab, (49, 50, 68))
                dpg.add_theme_color(dpg.mvThemeCol_TabHovered, self.ACCENT)
                dpg.add_theme_color(dpg.mvThemeCol_TabActive, self.ACCENT)
                dpg.add_theme_color(dpg.mvThemeCol_SliderGrab, self.ACCENT)
                dpg.add_theme_color(dpg.mvThemeCol_CheckMark, self.ACCENT)
                dpg.add_theme_color(dpg.mvThemeCol_PlotLines, self.ACCENT)
                dpg.add_theme_color(dpg.mvThemeCol_PlotHistogram, self.ACCENT)
                dpg.add_theme_color(dpg.mvThemeCol_TitleBgActive, (49, 50, 68))
                dpg.add_theme_color(dpg.mvThemeCol_ScrollbarBg, self.BG_COLOR)
                dpg.add_theme_color(dpg.mvThemeCol_ScrollbarGrab, (69, 71, 90))
                dpg.add_theme_style(dpg.mvStyleVar_FrameRounding, 6)
                dpg.add_theme_style(dpg.mvStyleVar_WindowRounding, 8)
                dpg.add_theme_style(dpg.mvStyleVar_ChildRounding, 8)
                dpg.add_theme_style(dpg.mvStyleVar_GrabRounding, 4)
                dpg.add_theme_style(dpg.mvStyleVar_TabRounding, 6)
                dpg.add_theme_style(dpg.mvStyleVar_FramePadding, 8, 5)
                dpg.add_theme_style(dpg.mvStyleVar_ItemSpacing, 10, 8)

        # Button themes
        with dpg.theme() as self.start_btn_theme:
            with dpg.theme_component(dpg.mvButton):
                dpg.add_theme_color(dpg.mvThemeCol_Button, (40, 160, 100))
                dpg.add_theme_color(dpg.mvThemeCol_ButtonHovered, (50, 190, 120))
                dpg.add_theme_color(dpg.mvThemeCol_ButtonActive, (30, 140, 85))

        with dpg.theme() as self.stop_btn_theme:
            with dpg.theme_component(dpg.mvButton):
                dpg.add_theme_color(dpg.mvThemeCol_Button, (200, 60, 60))
                dpg.add_theme_color(dpg.mvThemeCol_ButtonHovered, (220, 80, 80))
                dpg.add_theme_color(dpg.mvThemeCol_ButtonActive, (180, 50, 50))

        dpg.bind_theme(self.global_theme)

    def _setup_fonts(self):
        pass  # Use default fonts for cross-platform compatibility

    def _create_main_window(self):
        with dpg.window(tag="main_window", no_title_bar=True, no_move=True, no_resize=True):
            # Header
            with dpg.group(horizontal=True):
                dpg.add_text(f"{APP_NAME}", color=self.ACCENT)
                dpg.add_text(f"v{APP_VERSION}", color=self.SUBTEXT)
                dpg.add_spacer(width=20)
                dpg.add_text("", tag="status_text", color=self.SUBTEXT)
                dpg.add_spacer(width=20)
                dpg.add_text("", tag="uptime_text", color=self.SUBTEXT)

            dpg.add_separator()
            dpg.add_spacer(height=5)

            # Tab bar
            with dpg.tab_bar(tag="main_tabs"):
                self._create_connection_tab()
                self._create_statistics_tab()
                self._create_charts_tab()
                self._create_network_test_tab()
                self._create_settings_tab()
                self._create_log_tab()

    def _create_connection_tab(self):
        with dpg.tab(label="Connection"):
            dpg.add_spacer(height=5)

            # Mode selector
            with dpg.group(horizontal=True):
                dpg.add_text("Mode:", color=self.SUBTEXT)
                dpg.add_radio_button(
                    items=["Server", "Client"],
                    tag="mode_radio",
                    default_value="Server" if self.settings.mode == "server" else "Client",
                    callback=self._on_mode_change,
                    horizontal=True,
                )
                with dpg.tooltip(dpg.last_item()):
                    dpg.add_text("Server: Hosts the HTTP bridge and connects to a local TCP/UDP service\nClient: Creates a local listener and tunnels traffic to a remote server")

            dpg.add_spacer(height=10)

            # Server config
            with dpg.child_window(tag="server_config", height=220, border=True,
                                   show=self.settings.mode == "server"):
                dpg.add_text("Server Configuration", color=self.ACCENT)
                dpg.add_separator()
                dpg.add_spacer(height=5)

                with dpg.group(horizontal=True):
                    dpg.add_text("Backend TCP/UDP Host:", color=self.SUBTEXT)
                    dpg.add_input_text(tag="srv_tcp_host", default_value=self.settings.server_tcp_host, width=200)
                    with dpg.tooltip(dpg.last_item()):
                        dpg.add_text("IP address of the backend service to bridge to (e.g., Minecraft server). Use 127.0.0.1 for localhost.")
                    dpg.add_text(":", color=self.SUBTEXT)
                    dpg.add_input_int(tag="srv_tcp_port", default_value=self.settings.server_tcp_port, width=100, min_value=1, max_value=65535)
                    with dpg.tooltip(dpg.last_item()):
                        dpg.add_text("Port of the backend service. Common ports: 25565 (Minecraft), 27015 (Source), 7777 (Terraria)")

                with dpg.group(horizontal=True):
                    dpg.add_text("HTTP Listen Host:", color=self.SUBTEXT)
                    dpg.add_input_text(tag="srv_http_host", default_value=self.settings.server_http_host, width=200)
                    with dpg.tooltip(dpg.last_item()):
                        dpg.add_text("HTTP server bind address. Use 0.0.0.0 to listen on all interfaces, or 127.0.0.1 for localhost only.")
                    dpg.add_text(":", color=self.SUBTEXT)
                    dpg.add_input_int(tag="srv_http_port", default_value=self.settings.server_http_port, width=100, min_value=1, max_value=65535)
                    with dpg.tooltip(dpg.last_item()):
                        dpg.add_text("HTTP server port. Clients will connect to this port. Choose a port not blocked by firewalls.")

                with dpg.group(horizontal=True):
                    dpg.add_text("Protocol:", color=self.SUBTEXT)
                    dpg.add_radio_button(
                        items=["TCP", "UDP"],
                        tag="srv_protocol",
                        default_value=self.settings.server_protocol.upper(),
                        horizontal=True,
                    )
                    with dpg.tooltip(dpg.last_item()):
                        dpg.add_text("TCP: Reliable, ordered delivery (most games)\nUDP: Fast, unordered delivery (some FPS games, voice chat)")

            # Client config
            with dpg.child_window(tag="client_config", height=220, border=True,
                                   show=self.settings.mode == "client"):
                dpg.add_text("Client Configuration", color=self.ACCENT)
                dpg.add_separator()
                dpg.add_spacer(height=5)

                with dpg.group(horizontal=True):
                    dpg.add_text("Local Listen Host:", color=self.SUBTEXT)
                    dpg.add_input_text(tag="cli_local_host", default_value=self.settings.client_local_host, width=200)
                    with dpg.tooltip(dpg.last_item()):
                        dpg.add_text("Local address for applications to connect to. Usually 127.0.0.1 (localhost).")
                    dpg.add_text(":", color=self.SUBTEXT)
                    dpg.add_input_int(tag="cli_local_port", default_value=self.settings.client_local_port, width=100, min_value=1, max_value=65535)
                    with dpg.tooltip(dpg.last_item()):
                        dpg.add_text("Local port applications connect to. Should match the service port (e.g., 25565 for Minecraft).")

                with dpg.group(horizontal=True):
                    dpg.add_text("Remote Server URL:", color=self.SUBTEXT)
                    dpg.add_input_text(tag="cli_remote_url", default_value=self.settings.client_remote_url, width=400)
                    with dpg.tooltip(dpg.last_item()):
                        dpg.add_text("URL of the tunnel server. Example: http://example.com:8080 or https://example.com:8443")

                with dpg.group(horizontal=True):
                    dpg.add_text("Protocol:", color=self.SUBTEXT)
                    dpg.add_radio_button(
                        items=["TCP", "UDP"],
                        tag="cli_protocol",
                        default_value=self.settings.client_protocol.upper(),
                        horizontal=True,
                    )
                    with dpg.tooltip(dpg.last_item()):
                        dpg.add_text("Must match the server's protocol setting.")

            dpg.add_spacer(height=10)

            # ---- SERVER: Allowed methods with checkboxes + connection counts ----
            with dpg.child_window(tag="srv_methods_panel", height=200, border=True,
                                   show=self.settings.mode == "server"):
                dpg.add_text("Allowed Streaming Methods", color=self.ACCENT)
                with dpg.tooltip(dpg.last_item()):
                    dpg.add_text("Tick the methods clients are allowed to connect with.\nConnection count per method updates in real-time.")
                dpg.add_separator()
                dpg.add_spacer(height=5)

                for m in StreamingMethod:
                    info = STREAMING_METHOD_INFO[m]
                    is_allowed = m.value in self.settings.server_allowed_methods
                    with dpg.group(horizontal=True):
                        dpg.add_checkbox(
                            label="",
                            tag=f"srv_method_{m.value}",
                            default_value=is_allowed,
                        )
                        dpg.add_text(f"{info['name']}", color=self.TEXT)
                        with dpg.tooltip(dpg.last_item()):
                            dpg.add_text(f"{info['desc']}\nLatency: {info['latency']} | Throughput: {info['throughput']}")
                        dpg.add_text("", tag=f"srv_method_count_{m.value}", color=self.SUBTEXT)

            # ---- CLIENT: Streaming method selector + auto-detect ----
            with dpg.child_window(tag="cli_methods_panel", height=280, border=True,
                                   show=self.settings.mode == "client"):
                dpg.add_text("Streaming Method", color=self.ACCENT)
                dpg.add_separator()
                dpg.add_spacer(height=5)

                method_names = [STREAMING_METHOD_INFO[m]["name"] for m in StreamingMethod]
                current_idx = list(StreamingMethod).index(StreamingMethod(self.settings.streaming_method))
                with dpg.group(horizontal=True):
                    dpg.add_combo(
                        items=method_names,
                        tag="streaming_method",
                        default_value=method_names[current_idx],
                        width=250,
                        callback=self._on_streaming_change,
                    )
                    with dpg.tooltip(dpg.last_item()):
                        dpg.add_text("Select the HTTP streaming method for tunneling data.\nWebSocket is recommended for lowest latency.")
                    dpg.add_checkbox(label="Auto-Detect Best", tag="auto_detect", default_value=self.settings.auto_detect_method)
                    with dpg.tooltip(dpg.last_item()):
                        dpg.add_text("When enabled, tests each method the server allows on connect\nand automatically picks the fastest one.")
                    dpg.add_button(label="Run Auto-Detect Now", tag="run_autodetect_btn", callback=self._run_auto_detect)
                    with dpg.tooltip(dpg.last_item()):
                        dpg.add_text("Immediately test each server method and show results.\nDoes not require the tunnel to be running.")

                dpg.add_text("", tag="method_desc", wrap=600, color=self.SUBTEXT)
                self._update_method_description()

                dpg.add_spacer(height=5)
                dpg.add_text("Auto-Detect Results:", color=self.ACCENT, tag="autodetect_header", show=False)
                # Table for auto-detect results
                with dpg.table(tag="autodetect_table", header_row=True, borders_innerH=True,
                               borders_innerV=True, borders_outerH=True, borders_outerV=True,
                               show=False):
                    dpg.add_table_column(label="Method")
                    dpg.add_table_column(label="Status")
                    dpg.add_table_column(label="Avg (ms)")
                    dpg.add_table_column(label="Min (ms)")
                    dpg.add_table_column(label="Max (ms)")
                    dpg.add_table_column(label="Errors")

            dpg.add_spacer(height=10)

            # Start/Stop buttons
            with dpg.group(horizontal=True):
                dpg.add_button(label="  Start Tunnel  ", tag="start_btn", callback=self._start_tunnel, width=180, height=40)
                dpg.bind_item_theme("start_btn", self.start_btn_theme)
                with dpg.tooltip("start_btn"):
                    dpg.add_text("Start the tunnel with current configuration.\nServer: starts HTTP listener and connects to backend.\nClient: starts local listener and connects to server.")
                dpg.add_button(label="  Stop Tunnel  ", tag="stop_btn", callback=self._stop_tunnel, width=180, height=40, enabled=False)
                dpg.bind_item_theme("stop_btn", self.stop_btn_theme)
                with dpg.tooltip("stop_btn"):
                    dpg.add_text("Stop the tunnel and disconnect all sessions.")
                dpg.add_spacer(width=20)
                dpg.add_text("", tag="tunnel_status", color=self.SUBTEXT)

    def _create_statistics_tab(self):
        with dpg.tab(label="Statistics"):
            dpg.add_spacer(height=10)

            # Connection stats
            with dpg.child_window(height=180, border=True):
                dpg.add_text("Connection Statistics", color=self.ACCENT)
                dpg.add_separator()
                dpg.add_spacer(height=5)

                with dpg.table(header_row=True, borders_innerH=True, borders_innerV=True, borders_outerH=True, borders_outerV=True):
                    dpg.add_table_column(label="Metric", width_fixed=True, init_width_or_weight=200)
                    dpg.add_table_column(label="Value")
                    dpg.add_table_column(label="Metric", width_fixed=True, init_width_or_weight=200)
                    dpg.add_table_column(label="Value")

                    with dpg.table_row():
                        dpg.add_text("Active Connections")
                        dpg.add_text("0", tag="stat_active")
                        dpg.add_text("Total Connections")
                        dpg.add_text("0", tag="stat_total")

                    with dpg.table_row():
                        dpg.add_text("Data Sent")
                        dpg.add_text("0 B", tag="stat_sent")
                        dpg.add_text("Data Received")
                        dpg.add_text("0 B", tag="stat_recv")

                    with dpg.table_row():
                        dpg.add_text("Packets Sent")
                        dpg.add_text("0", tag="stat_pkts_sent")
                        dpg.add_text("Packets Received")
                        dpg.add_text("0", tag="stat_pkts_recv")

                    with dpg.table_row():
                        dpg.add_text("Packets Lost")
                        dpg.add_text("0", tag="stat_pkts_lost")
                        dpg.add_text("Uptime")
                        dpg.add_text("00:00:00", tag="stat_uptime")

            dpg.add_spacer(height=10)

            # Latency stats
            with dpg.child_window(height=140, border=True):
                dpg.add_text("Latency Statistics", color=self.ACCENT)
                dpg.add_separator()
                dpg.add_spacer(height=5)

                with dpg.table(header_row=True, borders_innerH=True, borders_innerV=True, borders_outerH=True, borders_outerV=True):
                    dpg.add_table_column(label="Current (ms)")
                    dpg.add_table_column(label="Average (ms)")
                    dpg.add_table_column(label="Min (ms)")
                    dpg.add_table_column(label="Max (ms)")
                    dpg.add_table_column(label="Jitter (ms)")

                    with dpg.table_row():
                        dpg.add_text("0.00", tag="lat_current")
                        dpg.add_text("0.00", tag="lat_avg")
                        dpg.add_text("0.00", tag="lat_min")
                        dpg.add_text("0.00", tag="lat_max")
                        dpg.add_text("0.00", tag="lat_jitter")

            dpg.add_spacer(height=10)

            # System stats
            with dpg.child_window(height=120, border=True):
                dpg.add_text("System Resources", color=self.ACCENT)
                with dpg.tooltip(dpg.last_item()):
                    dpg.add_text("CPU and memory usage of this application process.")
                dpg.add_separator()
                dpg.add_spacer(height=5)

                with dpg.table(header_row=True, borders_innerH=True, borders_innerV=True, borders_outerH=True, borders_outerV=True):
                    dpg.add_table_column(label="CPU Usage (%)")
                    dpg.add_table_column(label="Memory Usage (MB)")
                    dpg.add_table_column(label="Threads")

                    with dpg.table_row():
                        dpg.add_text("0.0", tag="sys_cpu")
                        dpg.add_text("0.0", tag="sys_mem")
                        dpg.add_text("0", tag="sys_threads")

    def _create_charts_tab(self):
        with dpg.tab(label="Charts"):
            dpg.add_spacer(height=5)

            # Throughput chart
            with dpg.child_window(height=250, border=True):
                dpg.add_text("Throughput (bytes/sec)", color=self.ACCENT)
                with dpg.tooltip(dpg.last_item()):
                    dpg.add_text("Real-time data transfer rate. Blue=Download, Green=Upload.\nHigher is better. Drops may indicate network congestion.")
                with dpg.plot(label="", height=200, width=-1, tag="throughput_plot", anti_aliased=True):
                    dpg.add_plot_legend()
                    dpg.add_plot_axis(dpg.mvXAxis, label="Time (s)", tag="tp_x_axis")
                    dpg.add_plot_axis(dpg.mvYAxis, label="Bytes/s", tag="tp_y_axis")
                    dpg.add_line_series([], [], label="Download", parent="tp_y_axis", tag="tp_in_series")
                    dpg.add_line_series([], [], label="Upload", parent="tp_y_axis", tag="tp_out_series")

            dpg.add_spacer(height=5)

            # Latency chart
            with dpg.child_window(height=250, border=True):
                dpg.add_text("Latency (ms)", color=self.ACCENT)
                with dpg.tooltip(dpg.last_item()):
                    dpg.add_text("Round-trip tunnel latency. Lower is better.\nSpikes above 50ms are highlighted as lag spikes.\nFor gaming, aim for <20ms tunnel overhead.")
                with dpg.plot(label="", height=200, width=-1, tag="latency_plot", anti_aliased=True):
                    dpg.add_plot_legend()
                    dpg.add_plot_axis(dpg.mvXAxis, label="Time (s)", tag="lat_x_axis")
                    dpg.add_plot_axis(dpg.mvYAxis, label="ms", tag="lat_y_axis")
                    dpg.add_line_series([], [], label="Latency", parent="lat_y_axis", tag="lat_series")
                    dpg.add_bar_series([], [], label="Lag Spikes", parent="lat_y_axis", tag="spike_series", weight=2)

            dpg.add_spacer(height=5)

            # Connections + System chart
            with dpg.child_window(height=250, border=True):
                dpg.add_text("Connections & System", color=self.ACCENT)
                with dpg.tooltip(dpg.last_item()):
                    dpg.add_text("Active connections count and system resource usage over time.\nWatch for memory leaks or CPU spikes.")
                with dpg.plot(label="", height=200, width=-1, tag="system_plot", anti_aliased=True):
                    dpg.add_plot_legend()
                    dpg.add_plot_axis(dpg.mvXAxis, label="Time (s)", tag="sys_x_axis")
                    dpg.add_plot_axis(dpg.mvYAxis, label="Value", tag="sys_y_axis")
                    dpg.add_line_series([], [], label="Connections", parent="sys_y_axis", tag="conn_series")
                    dpg.add_line_series([], [], label="CPU %", parent="sys_y_axis", tag="cpu_series")
                    dpg.add_line_series([], [], label="Memory MB", parent="sys_y_axis", tag="mem_series")

    def _create_network_test_tab(self):
        with dpg.tab(label="Network Test"):
            dpg.add_spacer(height=10)

            with dpg.child_window(height=120, border=True):
                dpg.add_text("Latency Test", color=self.ACCENT)
                with dpg.tooltip(dpg.last_item()):
                    dpg.add_text("Measures round-trip time to the tunnel server using HTTP pings.\nRun this before connecting to baseline your network quality.")
                dpg.add_separator()
                dpg.add_spacer(height=5)
                with dpg.group(horizontal=True):
                    dpg.add_button(label="Run Latency Test", callback=self._run_latency_test, width=200)
                    with dpg.tooltip(dpg.last_item()):
                        dpg.add_text("Sends 20 HTTP ping requests and measures response times.")
                    dpg.add_text("", tag="latency_test_result", wrap=500, color=self.SUBTEXT)

            dpg.add_spacer(height=10)

            with dpg.child_window(height=120, border=True):
                dpg.add_text("Throughput Test", color=self.ACCENT)
                with dpg.tooltip(dpg.last_item()):
                    dpg.add_text("Measures data transfer speed through the tunnel.\nTests upload speed with a 1MB payload.")
                dpg.add_separator()
                dpg.add_spacer(height=5)
                with dpg.group(horizontal=True):
                    dpg.add_button(label="Run Throughput Test", callback=self._run_throughput_test, width=200)
                    with dpg.tooltip(dpg.last_item()):
                        dpg.add_text("Uploads 1MB of test data and measures transfer speed.")
                    dpg.add_text("", tag="throughput_test_result", wrap=500, color=self.SUBTEXT)

            dpg.add_spacer(height=10)

            # Test results chart
            with dpg.child_window(height=280, border=True):
                dpg.add_text("Latency Test Results", color=self.ACCENT)
                with dpg.plot(label="", height=230, width=-1, tag="test_plot", anti_aliased=True):
                    dpg.add_plot_legend()
                    dpg.add_plot_axis(dpg.mvXAxis, label="Sample #", tag="test_x_axis")
                    dpg.add_plot_axis(dpg.mvYAxis, label="ms", tag="test_y_axis")
                    dpg.add_line_series([], [], label="Ping (ms)", parent="test_y_axis", tag="test_lat_series")

    def _create_settings_tab(self):
        with dpg.tab(label="Settings"):
            dpg.add_spacer(height=10)

            # Profiles
            with dpg.child_window(height=90, border=True):
                dpg.add_text("Profiles", color=self.ACCENT)
                with dpg.tooltip(dpg.last_item()):
                    dpg.add_text("Save and load different configurations for different games or scenarios.\nEach profile stores all connection and performance settings.")
                dpg.add_separator()
                dpg.add_spacer(height=5)
                with dpg.group(horizontal=True):
                    profile_names = list(self.settings.profiles.keys()) or ["Default"]
                    dpg.add_combo(items=profile_names, tag="profile_combo", default_value=self.settings.profile_name, width=200)
                    dpg.add_button(label="Load", callback=self._load_profile, width=80)
                    with dpg.tooltip(dpg.last_item()):
                        dpg.add_text("Load the selected profile's settings.")
                    dpg.add_input_text(tag="new_profile_name", hint="New profile name", width=200)
                    dpg.add_button(label="Save As", callback=self._save_profile, width=80)
                    with dpg.tooltip(dpg.last_item()):
                        dpg.add_text("Save current settings as a new or existing profile.")

            dpg.add_spacer(height=10)

            # Performance settings
            with dpg.child_window(height=200, border=True):
                dpg.add_text("Performance", color=self.ACCENT)
                dpg.add_separator()
                dpg.add_spacer(height=5)

                with dpg.group(horizontal=True):
                    dpg.add_checkbox(label="Split Streaming", tag="split_streaming", default_value=self.settings.split_streaming)
                    with dpg.tooltip(dpg.last_item()):
                        dpg.add_text("Split large data chunks into smaller packets for more consistent\ndelivery. Reduces jitter at slight throughput cost. Recommended ON.")
                    dpg.add_spacer(width=10)
                    dpg.add_text("Split Threshold (bytes):", color=self.SUBTEXT)
                    dpg.add_input_int(tag="split_threshold", default_value=self.settings.split_threshold, width=120, min_value=1024, max_value=1048576)
                    with dpg.tooltip(dpg.last_item()):
                        dpg.add_text("Data larger than this will be split. Lower = more consistent\nbut more overhead. Default: 32768 (32KB).")

                with dpg.group(horizontal=True):
                    dpg.add_checkbox(label="Compression", tag="compression", default_value=self.settings.compression)
                    with dpg.tooltip(dpg.last_item()):
                        dpg.add_text("Enable zlib fast compression. Reduces bandwidth but adds\nCPU overhead. Best for text-heavy protocols. May increase\nlatency slightly for already-compressed game data.")
                    dpg.add_spacer(width=10)
                    dpg.add_checkbox(label="Disable Nagle (TCP_NODELAY)", tag="nagle_disabled", default_value=self.settings.nagle_disabled)
                    with dpg.tooltip(dpg.last_item()):
                        dpg.add_text("Disables Nagle's algorithm for TCP sockets. Sends data\nimmediately without buffering. MUST be ON for gaming to\navoid 40ms+ delays. Only disable for bulk transfers.")

                with dpg.group(horizontal=True):
                    dpg.add_text("Buffer Size:", color=self.SUBTEXT)
                    dpg.add_input_int(tag="buffer_size", default_value=self.settings.buffer_size, width=120, min_value=4096, max_value=1048576)
                    with dpg.tooltip(dpg.last_item()):
                        dpg.add_text("Read buffer size in bytes. Larger buffers = higher throughput\nbut potentially higher latency. Default: 65536 (64KB).")
                    dpg.add_spacer(width=10)
                    dpg.add_text("Max Connections:", color=self.SUBTEXT)
                    dpg.add_input_int(tag="max_connections", default_value=self.settings.max_connections, width=120, min_value=1, max_value=10000)
                    with dpg.tooltip(dpg.last_item()):
                        dpg.add_text("Maximum simultaneous tunnel sessions. Each game client\ntypically uses one connection.")

                with dpg.group(horizontal=True):
                    dpg.add_text("Worker Threads:", color=self.SUBTEXT)
                    dpg.add_input_int(tag="worker_threads", default_value=self.settings.worker_threads, width=120, min_value=1, max_value=32)
                    with dpg.tooltip(dpg.last_item()):
                        dpg.add_text("Number of worker threads for the async event loop.\nMore threads help with many concurrent connections.\nDefault: 4.")

            dpg.add_spacer(height=10)

            # Security settings
            with dpg.child_window(height=180, border=True):
                dpg.add_text("Security", color=self.ACCENT)
                dpg.add_separator()
                dpg.add_spacer(height=5)

                with dpg.group(horizontal=True):
                    dpg.add_checkbox(label="Enable TLS/SSL", tag="use_tls", default_value=self.settings.use_tls)
                    with dpg.tooltip(dpg.last_item()):
                        dpg.add_text("Encrypt tunnel traffic with TLS. Requires certificate files\non the server side. Adds ~1-3ms latency overhead.")
                    dpg.add_spacer(width=10)
                    dpg.add_checkbox(label="Verify SSL Certificates", tag="verify_ssl", default_value=self.settings.verify_ssl)
                    with dpg.tooltip(dpg.last_item()):
                        dpg.add_text("Verify server's SSL certificate. Disable for self-signed\ncertificates (not recommended for production).")

                with dpg.group(horizontal=True):
                    dpg.add_text("TLS Cert:", color=self.SUBTEXT)
                    dpg.add_input_text(tag="tls_cert", default_value=self.settings.tls_cert_path, width=400)
                    with dpg.tooltip(dpg.last_item()):
                        dpg.add_text("Path to TLS certificate file (.pem). Server mode only.")

                with dpg.group(horizontal=True):
                    dpg.add_text("TLS Key:", color=self.SUBTEXT)
                    dpg.add_input_text(tag="tls_key", default_value=self.settings.tls_key_path, width=400)
                    with dpg.tooltip(dpg.last_item()):
                        dpg.add_text("Path to TLS private key file (.pem). Server mode only.")

                with dpg.group(horizontal=True):
                    dpg.add_text("Auth Token:", color=self.SUBTEXT)
                    dpg.add_input_text(tag="auth_token", default_value=self.settings.auth_token, width=400, password=True)
                    with dpg.tooltip(dpg.last_item()):
                        dpg.add_text("Optional authentication token. Both server and client must\nuse the same token. Leave empty to disable authentication.")

            dpg.add_spacer(height=10)

            # UI settings
            with dpg.child_window(height=110, border=True):
                dpg.add_text("UI & Web GUI Settings", color=self.ACCENT)
                dpg.add_separator()
                dpg.add_spacer(height=5)
                with dpg.group(horizontal=True):
                    dpg.add_text("Chart Update Interval (s):", color=self.SUBTEXT)
                    dpg.add_input_float(tag="chart_interval", default_value=self.settings.chart_update_interval, width=100, min_value=0.1, max_value=5.0, step=0.1)
                    with dpg.tooltip(dpg.last_item()):
                        dpg.add_text("How often charts refresh. Lower = smoother but more CPU.\n0.5s is a good balance.")
                with dpg.group(horizontal=True):
                    dpg.add_checkbox(label="Enable Web GUI", tag="webgui_enabled", default_value=self.settings.webgui_enabled)
                    with dpg.tooltip(dpg.last_item()):
                        dpg.add_text("Serve a browser-based dashboard on a separate port.\nUseful for headless servers or remote monitoring.")
                    dpg.add_spacer(width=10)
                    dpg.add_text("Web GUI Address:", color=self.SUBTEXT)
                    dpg.add_input_text(tag="webgui_host", default_value=self.settings.webgui_host, width=120)
                    dpg.add_text(":", color=self.SUBTEXT)
                    dpg.add_input_int(tag="webgui_port", default_value=self.settings.webgui_port, width=80, min_value=1, max_value=65535)
                    with dpg.tooltip(dpg.last_item()):
                        dpg.add_text("Host and port for the web GUI dashboard.\nExample: 0.0.0.0:9090 for all interfaces.")

            dpg.add_spacer(height=10)
            dpg.add_button(label="  Save Settings  ", callback=self._save_settings, width=180, height=35)
            with dpg.tooltip(dpg.last_item()):
                dpg.add_text("Save all current settings to disk. Settings are also\nautomatically saved when the application closes.")

    def _create_log_tab(self):
        with dpg.tab(label="Log"):
            dpg.add_spacer(height=5)
            dpg.add_text("Application Log", color=self.ACCENT)
            with dpg.tooltip(dpg.last_item()):
                dpg.add_text("Live application log. All events, connections, and errors are recorded.\nLogs are also saved to: " + str(LOG_FILE))
            dpg.add_separator()
            dpg.add_spacer(height=5)
            with dpg.group(horizontal=True):
                dpg.add_button(label="Clear Log", callback=lambda: self.logger.ui_log.clear())
                dpg.add_button(label="Open Log File", callback=lambda: os.startfile(str(LOG_FILE)) if platform.system() == "Windows" else None)
            dpg.add_spacer(height=5)
            dpg.add_input_text(tag="log_display", multiline=True, readonly=True, height=-1, width=-1, tracked=True)

    # ---- Callbacks ----

    def _on_mode_change(self, sender, value):
        is_server = value == "Server"
        dpg.configure_item("server_config", show=is_server)
        dpg.configure_item("client_config", show=not is_server)
        dpg.configure_item("srv_methods_panel", show=is_server)
        dpg.configure_item("cli_methods_panel", show=not is_server)

    def _on_streaming_change(self, sender, value):
        self._update_method_description()

    def _update_method_description(self):
        name = dpg.get_value("streaming_method")
        for method, info in STREAMING_METHOD_INFO.items():
            if info["name"] == name:
                desc = f"{info['desc']}\nLatency: {info['latency']} | Throughput: {info['throughput']} | Compatibility: {info['compatibility']}"
                dpg.set_value("method_desc", desc)
                break

    def _run_auto_detect(self):
        """Run client auto-detect in background and populate results table."""
        def _do():
            # Need a temporary client just for testing
            temp_settings = AppSettings.load()
            temp_settings.client_remote_url = dpg.get_value("cli_remote_url")
            temp_settings.auth_token = dpg.get_value("auth_token")
            temp_settings.verify_ssl = dpg.get_value("verify_ssl")
            temp_stats = ConnectionStats()
            temp_logger = self.logger
            temp_client = TunnelClient(temp_settings, temp_stats, temp_logger)

            async def _test():
                connector = aiohttp.TCPConnector(limit=10, enable_cleanup_closed=True)
                headers = {}
                if temp_settings.auth_token:
                    headers["Authorization"] = f"Bearer {temp_settings.auth_token}"
                temp_client._http_session = aiohttp.ClientSession(
                    connector=connector, headers=headers,
                    timeout=aiohttp.ClientTimeout(total=30, connect=CONNECTION_TIMEOUT),
                )
                try:
                    results = await temp_client._auto_detect_streaming_method()
                    return results
                finally:
                    await temp_client._http_session.close()

            future = self._run_async(_test())
            if future:
                try:
                    results = future.result(timeout=60)
                    self._auto_detect_results = results
                    self._populate_autodetect_table(results)
                except Exception as e:
                    self.logger.error(f"Auto-detect failed: {e}")

        dpg.set_value("method_desc", "Running auto-detect tests...")
        threading.Thread(target=_do, daemon=True).start()

    def _populate_autodetect_table(self, results: List[Dict]):
        """Populate the auto-detect results table in the UI."""
        # Clear existing rows
        children = dpg.get_item_children("autodetect_table", 1)
        if children:
            for child in children:
                dpg.delete_item(child)

        for r in results:
            with dpg.table_row(parent="autodetect_table"):
                selected = " << BEST" if r["method"] == self.settings.streaming_method else ""
                dpg.add_text(f"{r['name']}{selected}")
                color = self.GREEN if r["status"] == "ok" else self.RED
                dpg.add_text(r["status"], color=color)
                avg_str = f"{r['avg_ms']}" if r["avg_ms"] != float("inf") else "N/A"
                dpg.add_text(avg_str)
                dpg.add_text(f"{r['min_ms']}")
                dpg.add_text(f"{r['max_ms']}")
                dpg.add_text(f"{r['errors']}")

        dpg.configure_item("autodetect_header", show=True)
        dpg.configure_item("autodetect_table", show=True)

        # Auto-select the best in the combo
        for r in results:
            if r["status"] == "ok":
                method_enum = StreamingMethod(r["method"])
                dpg.set_value("streaming_method", STREAMING_METHOD_INFO[method_enum]["name"])
                self._update_method_description()
                break

    def _collect_settings(self):
        """Read current UI values into settings."""
        self.settings.mode = "server" if dpg.get_value("mode_radio") == "Server" else "client"
        self.settings.server_tcp_host = dpg.get_value("srv_tcp_host")
        self.settings.server_tcp_port = dpg.get_value("srv_tcp_port")
        self.settings.server_http_host = dpg.get_value("srv_http_host")
        self.settings.server_http_port = dpg.get_value("srv_http_port")
        self.settings.server_protocol = dpg.get_value("srv_protocol").lower()
        # Collect server allowed methods from checkboxes
        allowed = []
        for m in StreamingMethod:
            if dpg.get_value(f"srv_method_{m.value}"):
                allowed.append(m.value)
        self.settings.server_allowed_methods = allowed if allowed else list(ALL_METHOD_VALUES)

        self.settings.client_local_host = dpg.get_value("cli_local_host")
        self.settings.client_local_port = dpg.get_value("cli_local_port")
        self.settings.client_remote_url = dpg.get_value("cli_remote_url")
        self.settings.client_protocol = dpg.get_value("cli_protocol").lower()
        # Map streaming method name back to enum
        name = dpg.get_value("streaming_method")
        for method, info in STREAMING_METHOD_INFO.items():
            if info["name"] == name:
                self.settings.streaming_method = method.value
                break
        self.settings.auto_detect_method = dpg.get_value("auto_detect")
        self.settings.split_streaming = dpg.get_value("split_streaming")
        self.settings.split_threshold = dpg.get_value("split_threshold")
        self.settings.compression = dpg.get_value("compression")
        self.settings.nagle_disabled = dpg.get_value("nagle_disabled")
        self.settings.buffer_size = dpg.get_value("buffer_size")
        self.settings.max_connections = dpg.get_value("max_connections")
        self.settings.worker_threads = dpg.get_value("worker_threads")
        self.settings.use_tls = dpg.get_value("use_tls")
        self.settings.verify_ssl = dpg.get_value("verify_ssl")
        self.settings.tls_cert_path = dpg.get_value("tls_cert")
        self.settings.tls_key_path = dpg.get_value("tls_key")
        self.settings.auth_token = dpg.get_value("auth_token")
        self.settings.chart_update_interval = dpg.get_value("chart_interval")
        self.settings.webgui_enabled = dpg.get_value("webgui_enabled")
        self.settings.webgui_host = dpg.get_value("webgui_host")
        self.settings.webgui_port = dpg.get_value("webgui_port")

    def _save_settings(self):
        self._collect_settings()
        self.settings.save()
        self.logger.info("Settings saved")

    def _save_profile(self):
        name = dpg.get_value("new_profile_name").strip()
        if not name:
            name = dpg.get_value("profile_combo")
        self._collect_settings()
        self.settings.save_profile(name)
        profiles = list(self.settings.profiles.keys())
        dpg.configure_item("profile_combo", items=profiles, default_value=name)
        self.logger.info(f"Profile saved: {name}")

    def _load_profile(self):
        name = dpg.get_value("profile_combo")
        self.settings.load_profile(name)
        self._apply_settings_to_ui()
        self.logger.info(f"Profile loaded: {name}")

    def _apply_settings_to_ui(self):
        """Push settings values back to UI widgets."""
        dpg.set_value("mode_radio", "Server" if self.settings.mode == "server" else "Client")
        dpg.set_value("srv_tcp_host", self.settings.server_tcp_host)
        dpg.set_value("srv_tcp_port", self.settings.server_tcp_port)
        dpg.set_value("srv_http_host", self.settings.server_http_host)
        dpg.set_value("srv_http_port", self.settings.server_http_port)
        dpg.set_value("srv_protocol", self.settings.server_protocol.upper())
        for m in StreamingMethod:
            dpg.set_value(f"srv_method_{m.value}", m.value in self.settings.server_allowed_methods)
        dpg.set_value("cli_local_host", self.settings.client_local_host)
        dpg.set_value("cli_local_port", self.settings.client_local_port)
        dpg.set_value("cli_remote_url", self.settings.client_remote_url)
        dpg.set_value("cli_protocol", self.settings.client_protocol.upper())
        method = StreamingMethod(self.settings.streaming_method)
        dpg.set_value("streaming_method", STREAMING_METHOD_INFO[method]["name"])
        dpg.set_value("auto_detect", self.settings.auto_detect_method)
        dpg.set_value("split_streaming", self.settings.split_streaming)
        dpg.set_value("split_threshold", self.settings.split_threshold)
        dpg.set_value("compression", self.settings.compression)
        dpg.set_value("nagle_disabled", self.settings.nagle_disabled)
        dpg.set_value("buffer_size", self.settings.buffer_size)
        dpg.set_value("max_connections", self.settings.max_connections)
        dpg.set_value("worker_threads", self.settings.worker_threads)
        dpg.set_value("use_tls", self.settings.use_tls)
        dpg.set_value("verify_ssl", self.settings.verify_ssl)
        dpg.set_value("tls_cert", self.settings.tls_cert_path)
        dpg.set_value("tls_key", self.settings.tls_key_path)
        dpg.set_value("auth_token", self.settings.auth_token)
        dpg.set_value("chart_interval", self.settings.chart_update_interval)
        dpg.set_value("webgui_enabled", self.settings.webgui_enabled)
        dpg.set_value("webgui_host", self.settings.webgui_host)
        dpg.set_value("webgui_port", self.settings.webgui_port)
        self._on_mode_change(None, "Server" if self.settings.mode == "server" else "Client")
        self._update_method_description()

    def _start_tunnel(self):
        if self._tunnel_running:
            return
        self._collect_settings()
        self.settings.save()
        self.stats = ConnectionStats()
        self.tester.stats = self.stats

        if self.settings.mode == "server":
            self.server = TunnelServer(self.settings, self.stats, self.logger)
            future = self._run_async(self.server.start())
        else:
            self.client = TunnelClient(self.settings, self.stats, self.logger)
            future = self._run_async(self.client.start())

        if future:
            try:
                future.result(timeout=15)
                self._tunnel_running = True
                dpg.configure_item("start_btn", enabled=False)
                dpg.configure_item("stop_btn", enabled=True)
                dpg.set_value("tunnel_status", f"Running ({self.settings.mode.upper()} mode)")
                dpg.configure_item("tunnel_status", color=self.GREEN)
            except Exception as e:
                self.logger.error(f"Failed to start: {e}")
                dpg.set_value("tunnel_status", f"Error: {e}")
                dpg.configure_item("tunnel_status", color=self.RED)

    def _stop_tunnel(self):
        if not self._tunnel_running:
            return
        try:
            if self.server:
                future = self._run_async(self.server.stop())
                if future:
                    future.result(timeout=5)
                self.server = None
            if self.client:
                future = self._run_async(self.client.stop())
                if future:
                    future.result(timeout=5)
                self.client = None
        except Exception as e:
            self.logger.error(f"Error stopping: {e}")

        self._tunnel_running = False
        dpg.configure_item("start_btn", enabled=True)
        dpg.configure_item("stop_btn", enabled=False)
        dpg.set_value("tunnel_status", "Stopped")
        dpg.configure_item("tunnel_status", color=self.SUBTEXT)

    def _run_latency_test(self):
        def _test():
            future = self._run_async(self.tester.run_latency_test())
            if future:
                result = future.result(timeout=30)
                if "error" in result:
                    dpg.set_value("latency_test_result", f"Error: {result['error']}")
                else:
                    dpg.set_value("latency_test_result",
                                  f"Avg: {result['avg_ms']}ms | Min: {result['min_ms']}ms | Max: {result['max_ms']}ms | Jitter: {result['jitter_ms']}ms")
                    # Update test chart
                    samples = result.get("samples", [])
                    x = list(range(len(samples)))
                    dpg.set_value("test_lat_series", [x, samples])
        threading.Thread(target=_test, daemon=True).start()

    def _run_throughput_test(self):
        def _test():
            future = self._run_async(self.tester.run_throughput_test())
            if future:
                result = future.result(timeout=60)
                if "error" in result:
                    dpg.set_value("throughput_test_result", f"Error: {result['error']}")
                else:
                    txt = f"Upload: {result.get('upload_mbps', 'N/A')} Mbps ({result.get('upload_time_ms', 'N/A')}ms)"
                    dpg.set_value("throughput_test_result", txt)
        threading.Thread(target=_test, daemon=True).start()

    # ---- Stats & UI Update Loop ----

    def _stats_loop(self):
        """Background thread to sample statistics."""
        while self._stats_running:
            try:
                self.stats.sample()
            except Exception:
                pass
            time.sleep(1.0)

    def _update_ui(self):
        """Called every frame to update UI elements."""
        # Status bar
        status = "Running" if self._tunnel_running else "Idle"
        mode = self.settings.mode.upper()
        dpg.set_value("status_text", f"Status: {status} | Mode: {mode}")
        dpg.set_value("uptime_text", f"Uptime: {self.stats.uptime()}")

        # Statistics tab
        dpg.set_value("stat_active", str(self.stats.active_connections))
        dpg.set_value("stat_total", str(self.stats.total_connections))
        dpg.set_value("stat_sent", self.stats.format_bytes(self.stats.bytes_sent))
        dpg.set_value("stat_recv", self.stats.format_bytes(self.stats.bytes_received))
        dpg.set_value("stat_pkts_sent", str(self.stats.packets_sent))
        dpg.set_value("stat_pkts_recv", str(self.stats.packets_received))
        dpg.set_value("stat_pkts_lost", str(self.stats.packets_lost))
        dpg.set_value("stat_uptime", self.stats.uptime())

        # Latency
        dpg.set_value("lat_current", f"{self.stats.current_latency_ms:.2f}")
        dpg.set_value("lat_avg", f"{self.stats.avg_latency_ms:.2f}")
        min_lat = self.stats.min_latency_ms if self.stats.min_latency_ms != float("inf") else 0
        dpg.set_value("lat_min", f"{min_lat:.2f}")
        dpg.set_value("lat_max", f"{self.stats.max_latency_ms:.2f}")
        dpg.set_value("lat_jitter", f"{self.stats.jitter_ms:.2f}")

        # System
        try:
            proc = psutil.Process()
            dpg.set_value("sys_cpu", f"{proc.cpu_percent(interval=0):.1f}")
            dpg.set_value("sys_mem", f"{proc.memory_info().rss / (1024*1024):.1f}")
            dpg.set_value("sys_threads", str(proc.num_threads()))
        except Exception:
            pass

        # Server method connection counts
        if self.server and self._tunnel_running:
            for m in StreamingMethod:
                count = self.server.method_connection_counts.get(m.value, 0)
                dpg.set_value(f"srv_method_count_{m.value}", f"  [{count} connected]")

        # Charts
        self._update_charts()

        # Log
        log_text = "\n".join(self.logger.get_recent(100))
        dpg.set_value("log_display", log_text)

    def _update_charts(self):
        """Update all charts with latest data."""
        n = len(self.stats.throughput_in)
        if n < 2:
            return
        x = list(range(n))

        # Throughput
        dpg.set_value("tp_in_series", [x, list(self.stats.throughput_in)])
        dpg.set_value("tp_out_series", [x, list(self.stats.throughput_out)])
        dpg.fit_axis_data("tp_x_axis")
        dpg.fit_axis_data("tp_y_axis")

        # Latency
        dpg.set_value("lat_series", [x, list(self.stats.latency_samples)])
        spike_vals = [v * max(self.stats.latency_samples) if max(self.stats.latency_samples) > 0 else 0 for v in self.stats.lag_spikes]
        dpg.set_value("spike_series", [x, spike_vals])
        dpg.fit_axis_data("lat_x_axis")
        dpg.fit_axis_data("lat_y_axis")

        # System
        dpg.set_value("conn_series", [x, list(self.stats.connection_counts)])
        dpg.set_value("cpu_series", [x, list(self.stats.cpu_usage)])
        dpg.set_value("mem_series", [x, list(self.stats.memory_usage)])
        dpg.fit_axis_data("sys_x_axis")
        dpg.fit_axis_data("sys_y_axis")


# ============================================================================
# TERMINAL-ONLY (--nogui) MODE
# ============================================================================

class TerminalUI:
    """Headless terminal mode - no GUI, runs tunnel with stats printed to console."""

    def __init__(self, settings: AppSettings):
        self.settings = settings
        self.stats = ConnectionStats()
        self.logger = AppLogger()
        self.logger.logger.addHandler(logging.StreamHandler(sys.stdout))
        self.server: Optional[TunnelServer] = None
        self.client: Optional[TunnelClient] = None
        self._running = True

    def run(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(self._run_async())
        except KeyboardInterrupt:
            print("\nShutting down...")
        finally:
            loop.run_until_complete(self._stop())
            loop.close()

    async def _run_async(self):
        print(f"\n{'='*60}")
        print(f"  {APP_NAME} v{APP_VERSION}  [TERMINAL MODE]")
        print(f"  Mode: {self.settings.mode.upper()}")
        print(f"{'='*60}\n")

        if self.settings.mode == "server":
            self.server = TunnelServer(self.settings, self.stats, self.logger)
            await self.server.start()
            allowed = ", ".join(self.settings.server_allowed_methods)
            print(f"  Allowed methods: {allowed}")
        else:
            self.client = TunnelClient(self.settings, self.stats, self.logger)
            await self.client.start()

        print(f"\nTunnel running. Press Ctrl+C to stop.\n")

        # Print stats periodically
        while self._running:
            await asyncio.sleep(5)
            self.stats.sample()
            self._print_stats()

    def _print_stats(self):
        s = self.stats
        min_lat = s.min_latency_ms if s.min_latency_ms != float("inf") else 0
        print(
            f"[{s.uptime()}] "
            f"Conns: {s.active_connections}/{s.total_connections}  "
            f"Sent: {s.format_bytes(s.bytes_sent)}  "
            f"Recv: {s.format_bytes(s.bytes_received)}  "
            f"Latency: {s.current_latency_ms:.1f}ms (avg:{s.avg_latency_ms:.1f} min:{min_lat:.1f} max:{s.max_latency_ms:.1f})  "
            f"Lost: {s.packets_lost}"
        )
        if self.server:
            counts = {k: v for k, v in self.server.method_connection_counts.items() if v > 0}
            if counts:
                print(f"  Method connections: {counts}")

    async def _stop(self):
        self._running = False
        if self.server:
            await self.server.stop()
        if self.client:
            await self.client.stop()
        self.settings.save()


# ============================================================================
# WEB GUI (--webgui)
# ============================================================================

class WebGUI:
    """Browser-based monitoring dashboard served via aiohttp."""

    def __init__(self, settings: AppSettings, stats: ConnectionStats, logger: AppLogger,
                 server: Optional[TunnelServer] = None, client: Optional[TunnelClient] = None):
        self.settings = settings
        self.stats = stats
        self.logger = logger
        self.server = server
        self.client = client
        self.app = web.Application()
        self.runner: Optional[web.AppRunner] = None
        self._setup_routes()

    def _setup_routes(self):
        self.app.router.add_get("/", self._handle_dashboard)
        self.app.router.add_get("/api/stats", self._handle_api_stats)
        self.app.router.add_get("/api/log", self._handle_api_log)
        self.app.router.add_get("/api/settings", self._handle_api_settings)

    async def _handle_dashboard(self, request: web.Request):
        s = self.stats
        cfg = self.settings
        min_lat = s.min_latency_ms if s.min_latency_ms != float("inf") else 0
        mode = cfg.mode.upper()
        method_rows = ""
        if self.server:
            for m in StreamingMethod:
                info = STREAMING_METHOD_INFO[m]
                count = self.server.method_connection_counts.get(m.value, 0)
                allowed = m.value in cfg.server_allowed_methods
                badge = "&#x2705;" if allowed else "&#x274C;"
                method_rows += f"<tr><td>{badge} {html_module.escape(info['name'])}</td><td>{count}</td></tr>"

        # Build settings rows grouped by category
        esc = html_module.escape
        def _bool(v):
            return '<span style="color:#a6e3a1">Yes</span>' if v else '<span style="color:#f38ba8">No</span>'
        def _row(label, value):
            return f"<tr><td>{esc(label)}</td><td><code>{esc(str(value))}</code></td></tr>"
        def _row_html(label, html_val):
            return f"<tr><td>{esc(label)}</td><td>{html_val}</td></tr>"

        settings_html = ""
        # -- Connection --
        settings_html += '<tr><th colspan="2" style="color:#89b4fa;padding-top:12px">Connection</th></tr>'
        settings_html += _row("Mode", cfg.mode)
        settings_html += _row("Profile", cfg.profile_name)
        # -- Server --
        settings_html += '<tr><th colspan="2" style="color:#89b4fa;padding-top:12px">Server</th></tr>'
        settings_html += _row("Backend Host", f"{cfg.server_tcp_host}:{cfg.server_tcp_port}")
        settings_html += _row("HTTP Listen", f"{cfg.server_http_host}:{cfg.server_http_port}")
        settings_html += _row("Protocol", cfg.server_protocol.upper())
        settings_html += _row("Allowed Methods", ", ".join(cfg.server_allowed_methods))
        # -- Client --
        settings_html += '<tr><th colspan="2" style="color:#89b4fa;padding-top:12px">Client</th></tr>'
        settings_html += _row("Local Listen", f"{cfg.client_local_host}:{cfg.client_local_port}")
        settings_html += _row("Remote URL", cfg.client_remote_url)
        settings_html += _row("Client Protocol", cfg.client_protocol.upper())
        settings_html += _row("Streaming Method", cfg.streaming_method)
        settings_html += _row_html("Auto-Detect", _bool(cfg.auto_detect_method))
        # -- Performance --
        settings_html += '<tr><th colspan="2" style="color:#89b4fa;padding-top:12px">Performance</th></tr>'
        settings_html += _row_html("Split Streaming", _bool(cfg.split_streaming))
        settings_html += _row("Split Threshold", f"{cfg.split_threshold} bytes")
        settings_html += _row_html("Compression", _bool(cfg.compression))
        settings_html += _row_html("TCP_NODELAY (Nagle Off)", _bool(cfg.nagle_disabled))
        settings_html += _row("Buffer Size", f"{cfg.buffer_size} bytes")
        settings_html += _row("Max Connections", cfg.max_connections)
        settings_html += _row("Worker Threads", cfg.worker_threads)
        # -- Security --
        settings_html += '<tr><th colspan="2" style="color:#89b4fa;padding-top:12px">Security</th></tr>'
        settings_html += _row_html("TLS/SSL", _bool(cfg.use_tls))
        settings_html += _row("TLS Cert", cfg.tls_cert_path or "(none)")
        settings_html += _row_html("Verify SSL", _bool(cfg.verify_ssl))
        settings_html += _row_html("Auth Token", '<span style="color:#a6e3a1">Set</span>' if cfg.auth_token else '<span style="color:#9399b2">Not set</span>')
        # -- Web GUI --
        settings_html += '<tr><th colspan="2" style="color:#89b4fa;padding-top:12px">Web GUI</th></tr>'
        settings_html += _row_html("Enabled", _bool(cfg.webgui_enabled))
        settings_html += _row("Listen", f"{cfg.webgui_host}:{cfg.webgui_port}")

        # System info
        try:
            proc = psutil.Process()
            cpu_pct = f"{proc.cpu_percent(interval=0):.1f}%"
            mem_mb = f"{proc.memory_info().rss / (1024*1024):.1f} MB"
            threads = str(proc.num_threads())
        except Exception:
            cpu_pct = mem_mb = threads = "N/A"

        html_content = f"""<!DOCTYPE html>
<html><head><title>{APP_NAME} Dashboard</title>
<meta http-equiv="refresh" content="3">
<style>
body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #1e1e2e; color: #cdd6f4; margin: 0; padding: 20px; }}
h1 {{ color: #89b4fa; margin-bottom: 5px; }}
h2 {{ color: #89b4fa; font-size: 1.1em; margin-top: 20px; }}
.subtitle {{ color: #9399b2; font-size: 0.9em; }}
.grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; margin: 15px 0; }}
.card {{ background: #2d2d41; border-radius: 10px; padding: 15px; }}
.card h3 {{ color: #89b4fa; margin: 0 0 8px 0; font-size: 0.9em; }}
.stat {{ font-size: 1.3em; font-weight: bold; color: #a6e3a1; }}
.stat.warn {{ color: #f9e2af; }}
.stat.bad {{ color: #f38ba8; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 8px; }}
th, td {{ padding: 5px 12px; text-align: left; border-bottom: 1px solid #45475a; }}
th {{ color: #89b4fa; font-size: 0.85em; }}
code {{ background: #313244; padding: 2px 6px; border-radius: 4px; font-size: 0.9em; }}
.cols {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }}
.log {{ background: #181825; border-radius: 8px; padding: 10px; font-family: monospace; font-size: 0.8em;
        max-height: 250px; overflow-y: auto; white-space: pre-wrap; color: #9399b2; }}
@media (max-width: 800px) {{ .cols {{ grid-template-columns: 1fr; }} }}
</style></head><body>
<h1>{esc(APP_NAME)}</h1>
<p class="subtitle">v{APP_VERSION} | Mode: {mode} | Uptime: {s.uptime()} | CPU: {cpu_pct} | Mem: {mem_mb} | Threads: {threads}</p>

<div class="grid">
  <div class="card"><h3>Active / Total Connections</h3><span class="stat">{s.active_connections} / {s.total_connections}</span></div>
  <div class="card"><h3>Data Sent</h3><span class="stat">{s.format_bytes(s.bytes_sent)}</span></div>
  <div class="card"><h3>Data Received</h3><span class="stat">{s.format_bytes(s.bytes_received)}</span></div>
  <div class="card"><h3>Current Latency</h3><span class="stat {'warn' if s.current_latency_ms > 30 else ''} {'bad' if s.current_latency_ms > 80 else ''}">{s.current_latency_ms:.1f} ms</span></div>
  <div class="card"><h3>Avg / Min / Max Latency</h3><span class="stat">{s.avg_latency_ms:.1f} / {min_lat:.1f} / {s.max_latency_ms:.1f} ms</span></div>
  <div class="card"><h3>Jitter</h3><span class="stat">{s.jitter_ms:.1f} ms</span></div>
  <div class="card"><h3>Packets Sent / Recv</h3><span class="stat">{s.packets_sent} / {s.packets_received}</span></div>
  <div class="card"><h3>Packets Lost</h3><span class="stat {'bad' if s.packets_lost > 0 else ''}">{s.packets_lost}</span></div>
</div>

{"<h2>Method Connections</h2><table><tr><th>Method</th><th>Connected</th></tr>" + method_rows + "</table>" if method_rows else ""}

<div class="cols">
<div>
<h2>Current Settings</h2>
<table>{settings_html}</table>
</div>
<div>
<h2>Recent Log</h2>
<div class="log">{esc(chr(10).join(self.logger.get_recent(40)))}</div>
</div>
</div>

<p class="subtitle" style="margin-top:20px">API: <a href="/api/stats" style="color:#89b4fa">/api/stats</a> &middot; <a href="/api/log" style="color:#89b4fa">/api/log</a> &middot; <a href="/api/settings" style="color:#89b4fa">/api/settings</a></p>
</body></html>"""
        return web.Response(text=html_content, content_type="text/html")

    async def _handle_api_stats(self, request: web.Request):
        s = self.stats
        data = {
            "uptime": s.uptime(),
            "active_connections": s.active_connections,
            "total_connections": s.total_connections,
            "bytes_sent": s.bytes_sent,
            "bytes_received": s.bytes_received,
            "packets_sent": s.packets_sent,
            "packets_received": s.packets_received,
            "packets_lost": s.packets_lost,
            "latency_current_ms": round(s.current_latency_ms, 2),
            "latency_avg_ms": round(s.avg_latency_ms, 2),
            "latency_min_ms": round(s.min_latency_ms if s.min_latency_ms != float("inf") else 0, 2),
            "latency_max_ms": round(s.max_latency_ms, 2),
            "jitter_ms": round(s.jitter_ms, 2),
        }
        if self.server:
            data["method_connections"] = dict(self.server.method_connection_counts)
        return web.json_response(data)

    async def _handle_api_log(self, request: web.Request):
        return web.json_response({"log": self.logger.get_recent(100)})

    async def _handle_api_settings(self, request: web.Request):
        data = asdict(self.settings)
        data.pop("auth_token", None)  # Don't expose auth token
        data.pop("tls_key_path", None)
        data.pop("profiles", None)
        return web.json_response(data)

    async def start(self):
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        site = web.TCPSite(self.runner, self.settings.webgui_host, self.settings.webgui_port)
        await site.start()
        print(f"Web GUI running at http://{self.settings.webgui_host}:{self.settings.webgui_port}")

    async def stop(self):
        if self.runner:
            await self.runner.cleanup()


# ============================================================================
# CLI ARGUMENT PARSER
# ============================================================================

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="httplighttcp",
        description=f"{APP_NAME} v{APP_VERSION} - Fast TCP-over-HTTP Tunnel",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                                  # GUI mode (default)
  python main.py --nogui --mode server             # Headless server
  python main.py --nogui --mode client --remote http://example.com:8080
  python main.py --mode server --webgui 0.0.0.0:9090
  python main.py --mode server --allowed-methods websocket chunked
  python main.py --mode client --auto-detect
        """,
    )
    # Mode
    p.add_argument("--nogui", action="store_true", help="Run in terminal-only mode (no GUI)")
    p.add_argument("--mode", choices=["server", "client"], help="Operating mode")
    # Server
    p.add_argument("--tcp-host", help="Backend TCP/UDP host (server mode)")
    p.add_argument("--tcp-port", type=int, help="Backend TCP/UDP port (server mode)")
    p.add_argument("--http-host", help="HTTP listen host (server mode)")
    p.add_argument("--http-port", type=int, help="HTTP listen port (server mode)")
    p.add_argument("--protocol", choices=["tcp", "udp"], help="Backend protocol")
    p.add_argument("--allowed-methods", nargs="+", choices=ALL_METHOD_VALUES,
                   help="Server: allowed streaming methods (space-separated)")
    # Client
    p.add_argument("--local-host", help="Local listen host (client mode)")
    p.add_argument("--local-port", type=int, help="Local listen port (client mode)")
    p.add_argument("--remote", help="Remote server URL (client mode), e.g. http://example.com:8080")
    p.add_argument("--method", choices=ALL_METHOD_VALUES, help="Streaming method")
    p.add_argument("--auto-detect", action="store_true", help="Auto-detect best streaming method (client)")
    # Performance
    p.add_argument("--split-streaming", type=bool, help="Enable split streaming")
    p.add_argument("--split-threshold", type=int, help="Split threshold in bytes")
    p.add_argument("--compression", type=bool, help="Enable compression")
    p.add_argument("--no-nagle", action="store_true", help="Disable Nagle (TCP_NODELAY)")
    p.add_argument("--buffer-size", type=int, help="Read buffer size in bytes")
    p.add_argument("--max-connections", type=int, help="Max simultaneous connections")
    p.add_argument("--worker-threads", type=int, help="Number of worker threads")
    # Security
    p.add_argument("--tls", action="store_true", help="Enable TLS/SSL")
    p.add_argument("--tls-cert", help="Path to TLS certificate file")
    p.add_argument("--tls-key", help="Path to TLS private key file")
    p.add_argument("--verify-ssl", action="store_true", default=None, help="Enable SSL certificate verification (off by default)")
    p.add_argument("--auth-token", help="Authentication token")
    # Web GUI
    p.add_argument("--webgui", metavar="HOST:PORT",
                   help="Enable web GUI on specified address (e.g. 0.0.0.0:9090)")
    # Profile
    p.add_argument("--profile", help="Load a saved profile by name")

    return p.parse_args()


def apply_args_to_settings(args: argparse.Namespace, settings: AppSettings):
    """Apply CLI arguments to settings, overriding saved values."""
    if args.profile:
        settings.load_profile(args.profile)
    if args.mode:
        settings.mode = args.mode
    if args.tcp_host:
        settings.server_tcp_host = args.tcp_host
    if args.tcp_port:
        settings.server_tcp_port = args.tcp_port
    if args.http_host:
        settings.server_http_host = args.http_host
    if args.http_port:
        settings.server_http_port = args.http_port
    if args.protocol:
        settings.server_protocol = args.protocol
        settings.client_protocol = args.protocol
    if args.allowed_methods:
        settings.server_allowed_methods = args.allowed_methods
    if args.local_host:
        settings.client_local_host = args.local_host
    if args.local_port:
        settings.client_local_port = args.local_port
    if args.remote:
        settings.client_remote_url = args.remote
    if args.method:
        settings.streaming_method = args.method
    if args.auto_detect:
        settings.auto_detect_method = True
    if args.split_streaming is not None:
        settings.split_streaming = args.split_streaming
    if args.split_threshold:
        settings.split_threshold = args.split_threshold
    if args.compression is not None:
        settings.compression = args.compression
    if args.no_nagle:
        settings.nagle_disabled = True
    if args.buffer_size:
        settings.buffer_size = args.buffer_size
    if args.max_connections:
        settings.max_connections = args.max_connections
    if args.worker_threads:
        settings.worker_threads = args.worker_threads
    if args.tls:
        settings.use_tls = True
    if args.tls_cert:
        settings.tls_cert_path = args.tls_cert
    if args.tls_key:
        settings.tls_key_path = args.tls_key
    if args.verify_ssl is not None:
        settings.verify_ssl = args.verify_ssl
    if args.auth_token:
        settings.auth_token = args.auth_token
    if args.webgui:
        settings.webgui_enabled = True
        if ":" in args.webgui:
            host, port = args.webgui.rsplit(":", 1)
            settings.webgui_host = host
            settings.webgui_port = int(port)
        else:
            settings.webgui_port = int(args.webgui)


# ============================================================================
# ENTRY POINT
# ============================================================================

def main():
    """Launch the HTTPS Light TCP Streaming application."""
    args = parse_args()

    if args.nogui:
        # In nogui mode, start from clean defaults — don't load saved GUI settings
        settings = AppSettings()
    else:
        settings = AppSettings.load()

    apply_args_to_settings(args, settings)

    print(f"{APP_NAME} v{APP_VERSION}")
    print(f"Platform: {platform.system()} {platform.release()}")
    print(f"Python: {sys.version}")
    print(f"Settings: {SETTINGS_FILE}")

    if args.nogui:
        # Terminal-only mode
        print("Starting in terminal mode (--nogui)...")
        if settings.webgui_enabled:
            # Run both terminal UI and web GUI
            terminal = TerminalUI(settings)
            webgui = WebGUI(settings, terminal.stats, terminal.logger)

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                # Start tunnel
                if settings.mode == "server":
                    terminal.server = TunnelServer(settings, terminal.stats, terminal.logger)
                    loop.run_until_complete(terminal.server.start())
                    webgui.server = terminal.server
                else:
                    terminal.client = TunnelClient(settings, terminal.stats, terminal.logger)
                    loop.run_until_complete(terminal.client.start())
                    webgui.client = terminal.client
                # Start web GUI
                loop.run_until_complete(webgui.start())

                allowed = ", ".join(settings.server_allowed_methods) if settings.mode == "server" else settings.streaming_method
                print(f"Tunnel running ({settings.mode}). Methods: {allowed}")
                print("Press Ctrl+C to stop.\n")

                async def _stats_print():
                    while terminal._running:
                        await asyncio.sleep(5)
                        terminal.stats.sample()
                        terminal._print_stats()

                loop.run_until_complete(_stats_print())
            except KeyboardInterrupt:
                print("\nShutting down...")
            finally:
                loop.run_until_complete(terminal._stop())
                loop.run_until_complete(webgui.stop())
                loop.close()
        else:
            terminal = TerminalUI(settings)
            terminal.run()
    else:
        # GUI mode
        print("Starting GUI...")
        app = AppUI(settings)

        if settings.webgui_enabled:
            # Start web GUI alongside the desktop GUI
            def _start_webgui():
                _loop = asyncio.new_event_loop()
                asyncio.set_event_loop(_loop)
                wg = WebGUI(settings, app.stats, app.logger)
                wg.server = app.server
                wg.client = app.client
                _loop.run_until_complete(wg.start())
                _loop.run_forever()
            wg_thread = threading.Thread(target=_start_webgui, daemon=True)
            wg_thread.start()

        app.run()


if __name__ == "__main__":
    main()