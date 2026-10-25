"""
config.py - Configuration for the Zero-Download Telegram Video Metadata Bot.

THEORY: WHY NOTHING IS DOWNLOADED
---------------------------------
Container formats keep their metadata in small, well-defined regions:

  * MP4 / MOV : the `moov` atom (index + codec tables) sits either at byte 0
                (FastStart) or at EOF (standard recorder output).
  * MKV / WebM: EBML header, SeekHead, Info and Tracks live near the start.
  * AVI       : the RIFF `hdrl` list is inside the first ~64 KiB.
  * `mdat` / Clusters (the compressed payload) are >99.8% of the file and are
    NEVER needed to describe a file.

MTPROTO CHUNKING
----------------
Telegram serves files via `upload.getFile` in aligned chunks of 1 MiB
(1,048,576 bytes). Pyrogram/Pyrofork exposes this as
`client.stream_media(message, offset, limit)` where `offset` and `limit`
are counted in *chunks*, not bytes.

For an HTTP request `Range: bytes=start-end` the bot computes:

    start_chunk     = start // 1_048_576
    end_chunk       = end   // 1_048_576
    chunks_to_fetch = end_chunk - start_chunk + 1

fetches only those chunks, then slices the exact byte window out of them:

    slice_start = max(0, start - chunk_index * 1_048_576)
    slice_end   = min(len(chunk), end - chunk_index * 1_048_576 + 1)

`ffprobe` is pointed at a loopback HTTP/206 server that performs this
translation, so a 4 GB file with `moov` at EOF costs ~1-2 MiB of traffic.

Bot tokens may stream files up to 2 GB. For files up to 4 GB a Telegram
Premium *user* session string is required (TELEGRAM_USER_SESSION_STRING).
"""

from __future__ import annotations

import ipaddress
import os
from typing import Final

from dotenv import load_dotenv

load_dotenv()


def _int(name: str, default: int = 0) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(f"Environment variable {name} must be an integer, got {raw!r}") from exc


def _float(name: str, default: float) -> float:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError as exc:
        raise ValueError(f"Environment variable {name} must be a number, got {raw!r}") from exc


def _bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name, "").strip().lower()
    if not raw:
        return default
    return raw in ("1", "true", "yes", "on")


def _id_set(name: str) -> frozenset[int]:
    raw = os.getenv(name, "")
    out: set[int] = set()
    for part in raw.replace(";", ",").replace(" ", ",").split(","):
        part = part.strip()
        if part:
            out.add(int(part))
    return frozenset(out)


# Anti-SSRF bogon list: anything in these networks is never fetched.
BLOCKED_NETWORKS: Final[tuple[ipaddress._BaseNetwork, ...]] = tuple(
    ipaddress.ip_network(n)
    for n in (
        # IPv4
        "0.0.0.0/8",          # "this" network
        "10.0.0.0/8",         # RFC 1918
        "100.64.0.0/10",      # CGNAT
        "127.0.0.0/8",        # loopback
        "169.254.0.0/16",     # link-local, AWS/GCP/Azure IMDS
        "172.16.0.0/12",      # RFC 1918
        "192.0.0.0/24",       # IETF protocol assignments
        "192.0.2.0/24",       # TEST-NET-1
        "192.168.0.0/16",     # RFC 1918
        "198.18.0.0/15",      # benchmarking
        "198.51.100.0/24",    # TEST-NET-2
        "203.0.113.0/24",     # TEST-NET-3
        "224.0.0.0/4",        # multicast
        "240.0.0.0/4",        # reserved
        "255.255.255.255/32", # broadcast
        # IPv6
        "::/128",             # unspecified
        "::1/128",            # loopback
        "::ffff:0:0/96",      # IPv4-mapped (re-checked after unmapping)
        "64:ff9b::/96",       # NAT64
        "100::/64",           # discard
        "fc00::/7",           # unique local
        "fe80::/10",          # link-local
        "ff00::/8",           # multicast
    )
)


class Config:
    """Runtime configuration, read once from the environment / .env file."""

    # --- Telegram credentials ---
    TELEGRAM_API_ID: int = _int("TELEGRAM_API_ID")
    TELEGRAM_API_HASH: str = os.getenv("TELEGRAM_API_HASH", "").strip()
    TELEGRAM_BOT_TOKEN: str = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    # Optional Premium user session -> enables streaming files up to 4 GB.
    TELEGRAM_USER_SESSION_STRING: str = os.getenv("TELEGRAM_USER_SESSION_STRING", "").strip()

    # --- Access control (empty ALLOWED_USERS => public mode) ---
    OWNER_ID: int = _int("OWNER_ID")
    ALLOWED_USERS: frozenset[int] = _id_set("ALLOWED_USERS")

    # --- Loopback streaming proxy ---
    STREAM_HOST: str = os.getenv("STREAM_HOST", "127.0.0.1").strip() or "127.0.0.1"
    STREAM_PORT: int = _int("STREAM_PORT", 0)  # 0 => OS-assigned dynamic port

    # --- ffprobe ---
    FFPROBE_BIN: str = os.getenv("FFPROBE_BIN", "ffprobe").strip() or "ffprobe"
    PROBE_TIMEOUT_SECONDS: float = _float("PROBE_TIMEOUT_SECONDS", 240.0)
    FFPROBE_PROBESIZE: str = os.getenv("FFPROBE_PROBESIZE", "5000000")
    FFPROBE_ANALYZEDURATION: str = os.getenv("FFPROBE_ANALYZEDURATION", "5000000")

    # --- Concurrency & rate limiting (token bucket per user) ---
    MAX_CONCURRENT_PROBES: int = _int("MAX_CONCURRENT_PROBES", 10)
    RATE_LIMIT_BURST: float = _float("RATE_LIMIT_BURST", 3.0)
    RATE_LIMIT_REFILL_RATE: float = _float("RATE_LIMIT_REFILL_RATE", 0.2)  # tokens/sec

    # --- Output ---
    # "telegraph": MediaInfo as a graph.org (Telegraph) link (falls back to .txt only if Telegraph fails)
    # "txt":       .txt document only
    # "both":      link AND .txt document
    OUTPUT_MODE: str = (os.getenv("OUTPUT_MODE", "telegraph").strip().lower() or "telegraph")
    TELEGRAPH_ACCESS_TOKEN: str = os.getenv("TELEGRAPH_ACCESS_TOKEN", "").strip()  # optional; auto-created if empty
    # API hosts tried in order (some networks block one of them)
    TELEGRAPH_API_URLS: tuple[str, ...] = tuple(
        u.strip().rstrip("/")
        for u in os.getenv("TELEGRAPH_API_URLS", "https://api.telegra.ph,https://api.graph.org").split(",")
        if u.strip()
    )
    # false = never send a .txt file when the link fails (the user gets an error message instead)
    TXT_FALLBACK: bool = _bool("TXT_FALLBACK", False)
    TELEGRAPH_AUTHOR: str = os.getenv("TELEGRAPH_AUTHOR", "MediaInfo Bot").strip() or "MediaInfo Bot"

    # Domain shown in the link. Telegraph serves every page on both telegra.ph and graph.org.
    TELEGRAPH_DOMAIN: str = os.getenv("TELEGRAPH_DOMAIN", "graph.org").strip().lower()

    # --- Behaviour ---
    # The bot NEVER inspects anything automatically: it only answers /mediainfo, /ml and /mi.
    CACHE_TTL_SECONDS: int = _int("CACHE_TTL_SECONDS", 3600)
    CACHE_MAX_ENTRIES: int = _int("CACHE_MAX_ENTRIES", 500)

    # --- Streaming internals ---
    CHUNK_SIZE: int = 1_048_576          # Telegram MTProto chunk quantum (1 MiB)
    WRITE_SLICE: int = 64 * 1024         # max bytes per socket write (backpressure)
    MAX_HTTP_REDIRECTS: int = 3

    BLOCKED_NETWORKS = BLOCKED_NETWORKS

    @classmethod
    def validate(cls) -> None:
        missing = [
            name
            for name, val in (
                ("TELEGRAM_API_ID", cls.TELEGRAM_API_ID),
                ("TELEGRAM_API_HASH", cls.TELEGRAM_API_HASH),
                ("TELEGRAM_BOT_TOKEN", cls.TELEGRAM_BOT_TOKEN),
            )
            if not val
        ]
        if missing:
            raise RuntimeError("Missing required configuration: " + ", ".join(missing))
        if cls.STREAM_HOST not in ("127.0.0.1", "localhost", "::1"):
            raise RuntimeError("STREAM_HOST must be a loopback address (127.0.0.1).")
        if cls.OUTPUT_MODE not in ("telegraph", "txt", "both"):
            raise RuntimeError("OUTPUT_MODE must be one of: telegraph, txt, both")
        if cls.MAX_CONCURRENT_PROBES < 1:
            raise RuntimeError("MAX_CONCURRENT_PROBES must be >= 1")
