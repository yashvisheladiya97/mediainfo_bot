"""
bot.py - Zero-Download Telegram Video Metadata Extraction Bot

Architecture (see config.py for the theory):

    Telegram file / HTTP link
            |
            v
   Source (TelegramSource | HttpSource)         <- fetches ONLY requested bytes
            |
            v
   Loopback aiohttp server (127.0.0.1:<port>/stream/<token>)   HTTP 206 bridge
            |
            v
   ffprobe (subprocess, argv-only, hard timeout)  -> JSON
            |
            v
   MediaInfo-style report (in memory) -> published to Telegraph (graph.org link)
   Runs ONLY when a user sends /mediainfo (or /ml, /mi); never automatically.

External links are ALSO proxied through the loopback server, so ffprobe never
resolves or connects to a user-supplied host itself. The bot's own HTTP client
uses an SSRF-safe resolver that rejects bogon addresses at connect time, which
closes the DNS-rebinding / TOCTOU window.
"""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import html
import io
import ipaddress
import json
import logging
import os
import re
import secrets
import signal
import socket
import sys
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import AsyncIterator, Optional
from urllib.parse import urljoin, urlsplit

import aiohttp
from aiohttp import web
from aiohttp.abc import AbstractResolver

from config import Config

log = logging.getLogger("mediainfo-bot")

ClientConnectionResetError = getattr(aiohttp, "ClientConnectionResetError", ConnectionResetError)
DISCONNECT_ERRORS = (
    ConnectionResetError,
    BrokenPipeError,
    ConnectionAbortedError,
    ClientConnectionResetError,
    asyncio.CancelledError,
)

PROTOCOL_WHITELIST = "file,crypto,data,http,https,tcp,tls"


# =============================================================================
# 1. RFC 7233 range parser
# =============================================================================
class RangeNotSatisfiable(ValueError):
    """Raised when a Range header is malformed or cannot be satisfied (HTTP 416)."""


_RANGE_RE = re.compile(r"^\s*bytes\s*=\s*(\d*)\s*-\s*(\d*)\s*$", re.IGNORECASE)


def parse_range(header: Optional[str], size: int) -> Optional[tuple[int, int]]:
    """
    Parse an HTTP Range header against a resource of `size` bytes.

    Returns (start, end) inclusive, or None when there is no header (serve 200).
    Raises RangeNotSatisfiable for malformed / unsatisfiable / multi-range input.

      bytes=s-e  closed range   (end clamped to size-1)
      bytes=s-   open-ended
      bytes=-N   suffix: last N bytes
    """
    if header is None or not header.strip():
        return None
    if size <= 0:
        raise RangeNotSatisfiable("empty resource")
    if "," in header:
        # Multipart/byteranges is not supported; ffprobe never asks for it.
        raise RangeNotSatisfiable("multiple ranges unsupported")
    m = _RANGE_RE.match(header)
    if not m:
        raise RangeNotSatisfiable("malformed range")
    s_raw, e_raw = m.groups()
    if not s_raw and not e_raw:
        raise RangeNotSatisfiable("malformed range")

    if not s_raw:  # suffix range
        n = int(e_raw)
        if n == 0:
            raise RangeNotSatisfiable("zero-length suffix")
        return max(0, size - n), size - 1

    start = int(s_raw)
    if start >= size:
        raise RangeNotSatisfiable("start beyond EOF")
    if not e_raw:
        return start, size - 1
    end = int(e_raw)
    if end < start:
        raise RangeNotSatisfiable("end before start")
    return start, min(end, size - 1)


# =============================================================================
# 2. Anti-SSRF guard
# =============================================================================
class SSRFError(ValueError):
    pass


def is_blocked_ip(ip: "ipaddress._BaseAddress | str") -> bool:
    addr = ipaddress.ip_address(ip) if isinstance(ip, str) else ip
    candidates = [addr]
    if isinstance(addr, ipaddress.IPv6Address):
        if addr.ipv4_mapped is not None:
            candidates.append(addr.ipv4_mapped)
        if addr.sixtofour is not None:
            candidates.append(addr.sixtofour)
    for a in candidates:
        if any(a in net for net in Config.BLOCKED_NETWORKS):
            return True
        if (
            a.is_private or a.is_loopback or a.is_link_local or a.is_multicast
            or a.is_reserved or a.is_unspecified
        ):
            return True
    return False


def validate_url_syntax(url: str) -> "urlsplit":
    """Cheap, synchronous checks: scheme, host, no credentials, literal-IP check."""
    if len(url) > 2048:
        raise SSRFError("URL too long")
    parts = urlsplit(url.strip())
    if parts.scheme not in ("http", "https"):
        raise SSRFError("Only http:// and https:// links are supported.")
    if not parts.hostname:
        raise SSRFError("The link has no host name.")
    if parts.username or parts.password:
        raise SSRFError("Links with embedded credentials are not allowed.")
    try:
        literal = ipaddress.ip_address(parts.hostname)
    except ValueError:
        literal = None
    if literal is not None and is_blocked_ip(literal):
        raise SSRFError("That address is not publicly routable and is blocked.")
    return parts


async def assert_public_host(url: str) -> None:
    """Resolve the host and refuse if ANY answer is a blocked address (UX pre-check)."""
    parts = validate_url_syntax(url)
    host = parts.hostname
    assert host is not None
    try:
        ipaddress.ip_address(host)
        return  # literal already validated
    except ValueError:
        pass
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, parts.port or (443 if parts.scheme == "https" else 80),
                                       type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise SSRFError(f"Could not resolve host: {host}") from exc
    for info in infos:
        if is_blocked_ip(info[4][0]):
            raise SSRFError("That host resolves to a private/internal address and is blocked.")


class SafeResolver(AbstractResolver):
    """aiohttp resolver that drops bogon addresses; enforcement point at connect time."""

    async def resolve(self, host: str, port: int = 0, family: int = socket.AF_UNSPEC):
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(host, port, family=family, type=socket.SOCK_STREAM)
        out = []
        for fam, _t, proto, _c, sockaddr in infos:
            ip = sockaddr[0]
            if is_blocked_ip(ip):
                continue
            out.append({
                "hostname": host, "host": ip, "port": port,
                "family": fam, "proto": proto, "flags": socket.AI_NUMERICHOST,
            })
        if not out:
            raise OSError(f"Blocked by SSRF policy: {host}")
        return out

    async def close(self) -> None:
        return None


# =============================================================================
# Byte sources
# =============================================================================
class SourceError(Exception):
    pass


class Source:
    size: int = 0
    mime: str = "application/octet-stream"
    bytes_fetched: int = 0  # bytes actually pulled from the remote side

    def read_range(self, start: int, end: int) -> AsyncIterator[bytes]:
        raise NotImplementedError


class TelegramSource(Source):
    """Streams 1 MiB MTProto chunks with Pyrogram/Pyrofork `stream_media`."""

    def __init__(self, client, message, size: int, mime: str | None):
        self.client = client
        self.message = message
        self.size = size
        self.mime = mime or "application/octet-stream"
        self.bytes_fetched = 0

    async def read_range(self, start: int, end: int) -> AsyncIterator[bytes]:
        cs = Config.CHUNK_SIZE
        start_chunk = start // cs
        end_chunk = end // cs
        chunks_to_fetch = (end_chunk - start_chunk) + 1
        gen = self.client.stream_media(self.message, offset=start_chunk, limit=chunks_to_fetch)
        async with contextlib.aclosing(gen):
            idx = start_chunk
            async for chunk in gen:
                if idx > end_chunk:
                    break
                self.bytes_fetched += len(chunk)
                slice_start = max(0, start - idx * cs)
                slice_end = min(len(chunk), end - idx * cs + 1)
                if slice_end > slice_start:
                    yield chunk[slice_start:slice_end]
                idx += 1


class HttpSource(Source):
    """Range-reads an external HTTP(S) file via an SSRF-safe client."""

    def __init__(self, session: aiohttp.ClientSession, url: str):
        self.session = session
        self.url = url
        self.bytes_fetched = 0
        self.filename = ""

    async def _open(self, start: int, end: Optional[int]) -> aiohttp.ClientResponse:
        url = self.url
        rng = f"bytes={start}-" if end is None else f"bytes={start}-{end}"
        for _ in range(Config.MAX_HTTP_REDIRECTS + 1):
            validate_url_syntax(url)
            resp = await self.session.get(
                url,
                headers={"Range": rng, "Accept-Encoding": "identity", "User-Agent": "MediaInfoBot/1.0"},
                allow_redirects=False,
            )
            if resp.status in (301, 302, 303, 307, 308):
                loc = resp.headers.get("Location")
                resp.close()
                if not loc:
                    raise SourceError("Redirect without Location header.")
                url = urljoin(url, loc)
                continue
            self.url = url
            return resp
        raise SourceError("Too many redirects.")

    async def probe_size(self) -> None:
        try:
            resp = await self._open(0, 0)
        except SSRFError:
            raise
        except (aiohttp.ClientError, OSError, asyncio.TimeoutError) as exc:
            raise SourceError(f"Could not connect to the server ({type(exc).__name__}).") from exc
        try:
            if resp.status == 206:
                cr = resp.headers.get("Content-Range", "")
                m = re.match(r"bytes\s+\d+-\d+/(\d+)", cr)
                if not m:
                    raise SourceError("Server did not report the total file size.")
                self.size = int(m.group(1))
            elif resp.status == 200:
                raise SourceError(
                    "This server does not support HTTP Range requests, so the file cannot be "
                    "inspected without downloading it. Zero-download mode refuses such links."
                )
            elif resp.status == 416:
                self.size = 0  # empty resource
            else:
                raise SourceError(f"Server answered HTTP {resp.status}.")
            self.mime = resp.headers.get("Content-Type", "application/octet-stream").split(";")[0]
            cd = resp.headers.get("Content-Disposition", "")
            m = re.search(r'filename\*?=(?:UTF-8\'\')?"?([^";]+)', cd)
            self.filename = m.group(1) if m else os.path.basename(urlsplit(self.url).path)
        finally:
            resp.close()

    async def read_range(self, start: int, end: int) -> AsyncIterator[bytes]:
        resp = await self._open(start, end)
        try:
            if resp.status not in (200, 206):
                raise SourceError(f"Upstream HTTP {resp.status}")
            async for part in resp.content.iter_chunked(Config.WRITE_SLICE):
                self.bytes_fetched += len(part)
                yield part
        finally:
            resp.close()


# =============================================================================
# 3. Loopback HTTP 206 streaming server
# =============================================================================
@dataclass
class Session:
    token: str
    source: Source
    name: str
    created: float = field(default_factory=time.monotonic)
    requests: int = 0


class StreamServer:
    def __init__(self) -> None:
        self.sessions: dict[str, Session] = {}
        self.port: int = 0
        self._runner: Optional[web.AppRunner] = None

    # -- lifecycle ------------------------------------------------------------
    async def start(self) -> None:
        app = web.Application()
        app.router.add_get("/stream/{token}", self._handle)  # HEAD added automatically
        self._runner = web.AppRunner(app, access_log=None)
        await self._runner.setup()
        site = web.TCPSite(self._runner, Config.STREAM_HOST, Config.STREAM_PORT)
        await site.start()
        self.port = self._runner.addresses[0][1]
        log.info("Loopback stream server on %s:%d", Config.STREAM_HOST, self.port)

    async def stop(self) -> None:
        if self._runner:
            await self._runner.cleanup()

    # -- sessions -------------------------------------------------------------
    def register(self, source: Source, name: str) -> Session:
        token = secrets.token_urlsafe(32)  # 256 bits
        sess = Session(token=token, source=source, name=name)
        self.sessions[token] = sess
        return sess

    def unregister(self, token: str) -> None:
        self.sessions.pop(token, None)

    def url_for(self, sess: Session) -> str:
        return f"http://127.0.0.1:{self.port}/stream/{sess.token}"

    def _lookup(self, candidate: str) -> Optional[Session]:
        cand = candidate.encode("utf-8", "ignore")
        found: Optional[Session] = None
        for tok, sess in list(self.sessions.items()):
            if hmac.compare_digest(cand, tok.encode()):  # constant time, no early exit
                found = sess
        return found

    # -- request handling -----------------------------------------------------
    async def _handle(self, request: web.Request) -> web.StreamResponse:
        # DNS-rebinding defence
        host = request.headers.get("Host", "").lower()
        if host not in (f"127.0.0.1:{self.port}", f"localhost:{self.port}"):
            return web.Response(status=403, text="bad host")

        sess = self._lookup(request.match_info["token"])
        if sess is None:
            return web.Response(status=404, text="not found")
        sess.requests += 1
        src = sess.source
        size = src.size

        try:
            rng = parse_range(request.headers.get("Range"), size)
        except RangeNotSatisfiable:
            return web.Response(status=416, headers={"Content-Range": f"bytes */{size}"})

        headers = {
            "Content-Type": src.mime,
            "Accept-Ranges": "bytes",
            "Cache-Control": "no-store",
        }
        if rng is None:
            status, start, end = 200, 0, size - 1
        else:
            status = 206
            start, end = rng
            headers["Content-Range"] = f"bytes {start}-{end}/{size}"
        length = max(0, end - start + 1)
        headers["Content-Length"] = str(length)

        resp = web.StreamResponse(status=status, headers=headers)
        try:
            await resp.prepare(request)
            if request.method == "HEAD" or length == 0:
                return resp
            async for piece in src.read_range(start, end):
                mv = memoryview(piece)
                for i in range(0, len(mv), Config.WRITE_SLICE):  # bounded slices
                    await resp.write(mv[i:i + Config.WRITE_SLICE])  # awaits drain
            await resp.write_eof()
        except DISCONNECT_ERRORS:
            # ffprobe closes the socket as soon as it has what it needs - expected.
            pass
        except Exception as exc:  # upstream failure mid-stream
            log.warning("Stream error for %s: %s: %s", sess.name, type(exc).__name__, exc)
            if request.transport is not None:
                request.transport.close()
        return resp


# =============================================================================
# 4. ffprobe runner + metadata synthesis
# =============================================================================
class ProbeError(Exception):
    """Carries a user-facing diagnosis."""


async def _kill_tree(proc: asyncio.subprocess.Process) -> None:
    if proc.returncode is not None:
        return
    try:
        if os.name == "nt":
            killer = await asyncio.create_subprocess_exec(
                "taskkill", "/F", "/T", "/PID", str(proc.pid),
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
            )
            await killer.wait()
        else:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    with contextlib.suppress(Exception):
        proc.kill()


async def run_ffprobe(url: str) -> dict:
    """
    `url` is ALWAYS the bot-generated loopback URL (never user text), so argv
    carries no attacker-controlled data; execution is shell-free regardless.
    """
    argv = [
        Config.FFPROBE_BIN,
        "-v", "error",
        "-protocol_whitelist", PROTOCOL_WHITELIST,
        "-probesize", str(Config.FFPROBE_PROBESIZE),
        "-analyzeduration", str(Config.FFPROBE_ANALYZEDURATION),
        "-print_format", "json",
        "-show_format", "-show_streams", "-show_chapters",
        "--", url,  # end-of-options marker: url is a literal operand
    ]
    kwargs: dict = {}
    if os.name != "nt":
        kwargs["start_new_session"] = True  # own process group for killpg
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            **kwargs,
        )
    except FileNotFoundError as exc:
        raise ProbeError(f"ffprobe was not found ('{Config.FFPROBE_BIN}'). The bot admin must install FFmpeg.") from exc

    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=Config.PROBE_TIMEOUT_SECONDS)
    except asyncio.TimeoutError:
        await _kill_tree(proc)
        with contextlib.suppress(Exception):
            await asyncio.wait_for(proc.wait(), 5)
        raise ProbeError(
            f"Inspection timed out after {Config.PROBE_TIMEOUT_SECONDS:.0f}s. The file's header may be "
            "unusually large or the source is very slow."
        )
    except asyncio.CancelledError:
        await _kill_tree(proc)
        raise

    err = stderr.decode("utf-8", "replace").strip()
    try:
        data = json.loads(stdout.decode("utf-8", "replace") or "{}")
    except json.JSONDecodeError:
        data = {}

    if proc.returncode != 0 or not data.get("streams"):
        raise ProbeError(diagnose(err, bool(data)))
    return data


def diagnose(stderr: str, had_json: bool) -> str:
    low = stderr.lower()
    if "moov atom not found" in low:
        return ("The MP4's index (moov atom) is missing - the file is probably an incomplete or interrupted "
                "recording/upload, so no metadata can be read.")
    if "invalid data found" in low:
        return ("ffprobe could not recognise this as a valid media container. The file is likely corrupt, "
                "truncated, encrypted, or not a video.")
    if "server returned 4" in low or "server returned 5" in low:
        return "The source refused or failed the range request."
    if "connection refused" in low or "connection reset" in low:
        return "The streaming bridge dropped the connection while reading the file."
    if had_json:
        return "The file was readable but contains no audio/video/subtitle streams."
    tail = stderr.splitlines()[-1][:200] if stderr else "no diagnostic output"
    return f"Could not extract metadata ({tail})."


# ---- formatting helpers -----------------------------------------------------
VIDEO_FORMATS = {
    "h264": "AVC", "hevc": "HEVC", "av1": "AV1", "vp9": "VP9", "vp8": "VP8", "mpeg4": "MPEG-4 Visual",
    "mpeg2video": "MPEG Video", "mpeg1video": "MPEG Video", "vc1": "VC-1", "wmv3": "VC-1",
    "prores": "ProRes", "mjpeg": "JPEG", "theora": "Theora", "h263": "H.263", "msmpeg4v3": "MPEG-4 Visual",
}
AUDIO_FORMATS = {
    "aac": "AAC", "ac3": "AC-3", "eac3": "E-AC-3", "dts": "DTS", "truehd": "MLP FBA", "flac": "FLAC",
    "opus": "Opus", "vorbis": "Vorbis", "mp3": "MPEG Audio", "mp2": "MPEG Audio", "alac": "ALAC",
    "wmav2": "WMA", "wmav1": "WMA", "amr_nb": "AMR", "amr_wb": "AMR",
}
TEXT_FORMATS = {
    "subrip": "SubRip", "srt": "SubRip", "ass": "ASS", "ssa": "SSA", "mov_text": "Timed Text",
    "webvtt": "WebVTT", "hdmv_pgs_subtitle": "PGS", "dvd_subtitle": "VobSub",
    "dvb_subtitle": "DVB Subtitle", "text": "Text", "eia_608": "EIA-608",
}
LANGS = {
    "eng": "English", "hin": "Hindi", "jpn": "Japanese", "spa": "Spanish", "fre": "French", "fra": "French",
    "ger": "German", "deu": "German", "ita": "Italian", "por": "Portuguese", "rus": "Russian",
    "kor": "Korean", "chi": "Chinese", "zho": "Chinese", "tam": "Tamil", "tel": "Telugu", "ara": "Arabic",
    "mal": "Malayalam", "ben": "Bengali", "kan": "Kannada", "mar": "Marathi", "guj": "Gujarati",
    "tur": "Turkish", "tha": "Thai", "ind": "Indonesian", "und": "Undefined",
}
TRANSFERS = {
    "smpte2084": "PQ (SMPTE ST 2084)", "arib-std-b67": "HLG (ARIB STD-B67)", "bt709": "BT.709",
    "bt2020-10": "BT.2020 (10-bit)", "bt2020-12": "BT.2020 (12-bit)", "smpte170m": "BT.601",
    "iec61966-2-1": "sRGB",
}
PRIMARIES = {"bt709": "BT.709", "bt2020": "BT.2020", "smpte170m": "BT.601 NTSC", "bt470bg": "BT.601 PAL"}
MATRICES = {"bt709": "BT.709", "bt2020nc": "BT.2020 non-constant", "bt2020c": "BT.2020 constant",
            "smpte170m": "BT.601", "bt470bg": "BT.601"}
BRANDS = {"isom": "Base Media", "iso2": "Base Media / Version 2", "mp41": "Base Media / Version 1",
          "mp42": "Base Media / Version 2", "avc1": "Base Media / AVC", "M4V ": "Apple iTunes Video",
          "M4A ": "Apple iTunes Audio", "qt  ": "QuickTime", "3gp4": "3GPP Media Release 4",
          "3gp5": "3GPP Media Release 5"}


def _num(v) -> Optional[float]:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def fmt_size(n: float) -> str:
    n = float(n)
    for unit in ("bytes", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024 or unit == "TiB":
            return f"{int(n)} bytes" if unit == "bytes" else f"{n:.2f} {unit}"
        n /= 1024
    return f"{n:.2f} TiB"


def fmt_duration(sec: Optional[float]) -> Optional[str]:
    if sec is None or sec < 0:
        return None
    total_ms = int(round(sec * 1000))
    h, rem = divmod(total_ms, 3_600_000)
    m, rem = divmod(rem, 60_000)
    s, ms = divmod(rem, 1000)
    parts = []
    if h:
        parts.append(f"{h} h")
    if m:
        parts.append(f"{m} min")
    if s or not parts:
        parts.append(f"{s} s")
    if ms and not h:
        parts.append(f"{ms} ms")
    return " ".join(parts)


def fmt_clock(sec: float) -> str:
    ms = int(round(sec * 1000))
    h, rem = divmod(ms, 3_600_000)
    m, rem = divmod(rem, 60_000)
    s, ms = divmod(rem, 1000)
    return f"{h:02d}:{m:02d}:{s:02d}.{ms:03d}"


def fmt_bitrate(bps: Optional[float]) -> Optional[str]:
    if not bps or bps <= 0:
        return None
    if bps >= 1_000_000:
        return f"{bps / 1000:,.0f} kb/s".replace(",", " ")
    return f"{bps / 1000:.0f} kb/s"


def parse_fraction(s) -> Optional[float]:
    if not s or s in ("0/0", "N/A"):
        return None
    try:
        if "/" in str(s):
            a, b = str(s).split("/")
            return float(a) / float(b) if float(b) else None
        return float(s)
    except ValueError:
        return None


def tag(tags: dict, *names: str) -> Optional[str]:
    low = {k.lower(): v for k, v in (tags or {}).items()}
    for n in names:
        if n.lower() in low and low[n.lower()]:
            return str(low[n.lower()])
    return None


def stream_duration(st: dict) -> Optional[float]:
    d = _num(st.get("duration"))
    if d:
        return d
    t = tag(st.get("tags", {}), "DURATION")  # MKV: 00:42:11.123000000
    if t:
        m = re.match(r"(\d+):(\d+):(\d+(?:\.\d+)?)", t)
        if m:
            return int(m[1]) * 3600 + int(m[2]) * 60 + float(m[3])
    return None


def stream_bitrate(st: dict) -> Optional[float]:
    b = _num(st.get("bit_rate"))
    if b:
        return b
    return _num(tag(st.get("tags", {}), "BPS", "BPS-eng"))


def lang_name(st: dict) -> Optional[str]:
    code = tag(st.get("tags", {}), "language")
    if not code:
        return None
    if code.lower() in ("und", "unk"):
        return None
    return LANGS.get(code.lower(), code)


def pix_info(st: dict) -> tuple[Optional[str], Optional[str], Optional[str]]:
    pf = st.get("pix_fmt") or ""
    space = chroma = depth = None
    if pf.startswith(("yuv", "yuvj")):
        space = "YUV"
        m = re.match(r"yuvj?a?(\d{3})", pf)
        if m:
            chroma = {"420": "4:2:0", "422": "4:2:2", "444": "4:4:4", "411": "4:1:1", "410": "4:1:0"}.get(m[1])
    elif pf.startswith(("rgb", "gbr", "bgr")):
        space = "RGB"
    elif pf.startswith("gray"):
        space = "Y"
    brs = st.get("bits_per_raw_sample")
    if brs and str(brs).isdigit():
        depth = f"{brs} bits"
    else:
        m = re.search(r"(\d+)(?:le|be)?$", pf)
        depth = f"{m[1]} bits" if m and int(m[1]) in (9, 10, 12, 14, 16) else ("8 bits" if pf else None)
    return space, chroma, depth


def container_info(data: dict, name: str) -> tuple[str, Optional[str]]:
    fmt = data.get("format", {})
    fn = fmt.get("format_name", "")
    tags = fmt.get("tags", {})
    ext = os.path.splitext(name)[1].lower()
    if "matroska" in fn or "webm" in fn:
        return ("WebM" if ext == ".webm" else "Matroska"), "Version 4"
    if "mp4" in fn or "mov" in fn:
        brand = tag(tags, "major_brand") or ""
        if brand == "qt  ":
            return "QuickTime", None
        return "MPEG-4", BRANDS.get(brand, brand.strip() or None)
    if fn == "avi":
        return "AVI", None
    if "mpegts" in fn:
        return "MPEG-TS", None
    if fn == "flv":
        return "Flash Video", None
    if "asf" in fn:
        return "Windows Media", None
    if "ogg" in fn:
        return "Ogg", None
    return fn.split(",")[0].upper() or "Unknown", None


def rows(pairs: list[tuple[str, Optional[str]]]) -> str:
    return "\n".join(f"{k:<41}: {v}" for k, v in pairs if v not in (None, ""))


def _yesno(st: dict, key: str) -> str:
    return "Yes" if (st.get("disposition") or {}).get(key) else "No"


def format_mediainfo(data: dict, name: str, size: int, fetched: int, source_note: str) -> str:
    fmt = data.get("format", {})
    streams = data.get("streams", [])
    videos = [s for s in streams if s.get("codec_type") == "video"
              and not (s.get("disposition") or {}).get("attached_pic")]
    audios = [s for s in streams if s.get("codec_type") == "audio"]
    texts = [s for s in streams if s.get("codec_type") == "subtitle"]
    out: list[str] = []

    # ---------------- General ----------------
    cont, profile = container_info(data, name)
    v0 = videos[0] if videos else {}
    fr = parse_fraction(v0.get("avg_frame_rate")) or parse_fraction(v0.get("r_frame_rate"))
    ftags = fmt.get("tags", {})
    out.append("General\n" + rows([
        ("Complete name", name),
        ("Format", cont),
        ("Format profile", profile),
        ("File size", fmt_size(size)),
        ("Duration", fmt_duration(_num(fmt.get("duration")))),
        ("Overall bit rate", fmt_bitrate(_num(fmt.get("bit_rate")))),
        ("Frame rate", f"{fr:.3f} FPS" if fr else None),
        ("Encoded date", tag(ftags, "creation_time")),
        ("Title", tag(ftags, "title")),
        ("Writing application", tag(ftags, "encoder", "writing_application")),
        ("Number of streams", str(len(streams))),
        ("Source", source_note),
    ]))

    # ---------------- Video ----------------
    for i, st in enumerate(videos, 1):
        w, h = st.get("width"), st.get("height")
        dar = st.get("display_aspect_ratio")
        if (not dar or dar in ("0:1", "N/A")) and w and h:
            dar = f"{w / h:.3f}:1"
        sr = parse_fraction(st.get("avg_frame_rate")) or parse_fraction(st.get("r_frame_rate"))
        space, chroma, depth = pix_info(st)
        ct = st.get("color_transfer")
        hdr = None
        if ct == "smpte2084":
            hdr = "SMPTE ST 2084, HDR10 compatible"
        elif ct == "arib-std-b67":
            hdr = "HLG"
        for sd in st.get("side_data_list", []) or []:
            if str(sd.get("side_data_type", "")).startswith("DOVI"):
                hdr = f"Dolby Vision, Profile {sd.get('dv_profile', '?')}.{sd.get('dv_bl_signal_compatibility_id', '?')}"
        fo = st.get("field_order")
        scan = None
        if fo:
            scan = "Progressive" if fo == "progressive" else "Interlaced" if fo in ("tt", "bb", "tb", "bt") else None
        title = "Video" if len(videos) == 1 else f"Video #{i}"
        cr = st.get("color_range")
        out.append(title + "\n" + rows([
            ("ID", str(st.get("index", 0) + 1)),
            ("Format", VIDEO_FORMATS.get(st.get("codec_name", ""), (st.get("codec_name") or "Unknown").upper())),
            ("Format/Info", st.get("codec_long_name")),
            ("Format profile", f"{st['profile']}@L{st['level'] / 10:g}" if st.get("profile") and st.get("level", 0) > 0 and st.get("codec_name") == "h264"
             else st.get("profile")),
            ("Codec ID", st.get("codec_tag_string") if st.get("codec_tag_string", "").isprintable()
             and not st.get("codec_tag_string", "").startswith("[") else None),
            ("Duration", fmt_duration(stream_duration(st))),
            ("Bit rate", fmt_bitrate(stream_bitrate(st))),
            ("Width", f"{w} pixels" if w else None),
            ("Height", f"{h} pixels" if h else None),
            ("Display aspect ratio", dar),
            ("Frame rate", f"{sr:.3f} FPS" if sr else None),
            ("Color space", space),
            ("Chroma subsampling", chroma),
            ("Bit depth", depth),
            ("Scan type", scan),
            ("Color range", cr.capitalize() if cr else None),
            ("Color primaries", PRIMARIES.get(st.get("color_primaries", ""), st.get("color_primaries"))),
            ("Transfer characteristics", TRANSFERS.get(ct or "", ct)),
            ("Matrix coefficients", MATRICES.get(st.get("color_space", ""), st.get("color_space"))),
            ("HDR format", hdr),
            ("Title", tag(st.get("tags", {}), "title", "handler_name")
             if tag(st.get("tags", {}), "title") else None),
            ("Language", lang_name(st)),
            ("Default", _yesno(st, "default")),
            ("Forced", _yesno(st, "forced")),
        ]))

    # ---------------- Audio ----------------
    for i, st in enumerate(audios, 1):
        ch = st.get("channels")
        sr = _num(st.get("sample_rate"))
        brs = st.get("bits_per_raw_sample") or (str(st["bits_per_sample"]) if st.get("bits_per_sample") else None)
        out.append(f"Audio #{i}\n" + rows([
            ("ID", str(st.get("index", 0) + 1)),
            ("Format", AUDIO_FORMATS.get(st.get("codec_name", ""),
                                         "PCM" if str(st.get("codec_name", "")).startswith("pcm")
                                         else (st.get("codec_name") or "Unknown").upper())),
            ("Format/Info", st.get("codec_long_name")),
            ("Format profile", st.get("profile")),
            ("Codec ID", st.get("codec_tag_string") if st.get("codec_tag_string", "").isprintable()
             and not st.get("codec_tag_string", "").startswith("[") else None),
            ("Duration", fmt_duration(stream_duration(st))),
            ("Bit rate", fmt_bitrate(stream_bitrate(st))),
            ("Channel(s)", f"{ch} channel{'s' if ch != 1 else ''}" if ch else None),
            ("Channel layout", st.get("channel_layout")),
            ("Sampling rate", f"{sr / 1000:g} kHz" if sr else None),
            ("Bit depth", f"{brs} bits" if brs and str(brs) != "0" else None),
            ("Title", tag(st.get("tags", {}), "title")),
            ("Language", lang_name(st)),
            ("Default", _yesno(st, "default")),
            ("Forced", _yesno(st, "forced")),
        ]))

    # ---------------- Text ----------------
    for i, st in enumerate(texts, 1):
        out.append(f"Text #{i}\n" + rows([
            ("ID", str(st.get("index", 0) + 1)),
            ("Format", TEXT_FORMATS.get(st.get("codec_name", ""), (st.get("codec_name") or "Unknown").upper())),
            ("Codec ID", st.get("codec_tag_string") if st.get("codec_tag_string", "").isprintable()
             and not st.get("codec_tag_string", "").startswith("[") else None),
            ("Title", tag(st.get("tags", {}), "title")),
            ("Language", lang_name(st)),
            ("Default", _yesno(st, "default")),
            ("Forced", _yesno(st, "forced")),
        ]))

    # ---------------- Menu / chapters ----------------
    chapters = data.get("chapters", [])
    if chapters:
        lines = []
        for ch in chapters:
            t = _num(ch.get("start_time")) or 0.0
            title = tag(ch.get("tags", {}), "title") or ""
            lines.append(f"{fmt_clock(t):<41}: {title}")
        out.append("Menu\n" + "\n".join(lines))

    # ---------------- Transfer stats ----------------
    saved = 100.0 * (1 - fetched / size) if size else 0.0
    out.append("Data Transferred\n" + rows([
        ("Data transferred", fmt_size(fetched)),
        ("Total file size", fmt_size(size)),
        ("Bandwidth saved", f"{saved:.3f} %"),
        ("Bytes written to disk", "0 bytes"),
    ]))
    return "\n\n".join(out) + "\n"


def format_summary(data: dict, name: str, size: int, fetched: int, link: Optional[str] = None,
                   cached: bool = False, txt_fallback: bool = False) -> str:
    e = html.escape
    streams = data.get("streams", [])
    v = next((s for s in streams if s.get("codec_type") == "video"
              and not (s.get("disposition") or {}).get("attached_pic")), None)
    audios = [s for s in streams if s.get("codec_type") == "audio"]
    texts = [s for s in streams if s.get("codec_type") == "subtitle"]
    cont, _ = container_info(data, name)
    dur = fmt_duration(_num(data.get("format", {}).get("duration")))
    lines = [f"🎬 <b>{e(name[:120])}</b>",
             f"📦 {e(cont)} • {e(fmt_size(size))}" + (f" • {e(dur)}" if dur else "")]
    if v:
        fr = parse_fraction(v.get("avg_frame_rate"))
        _, _, depth = pix_info(v)
        bits = [VIDEO_FORMATS.get(v.get("codec_name", ""), (v.get("codec_name") or "?").upper()),
                f"{v.get('width')}x{v.get('height')}" if v.get("width") else None,
                f"{fr:.3f} FPS" if fr else None, depth, fmt_bitrate(stream_bitrate(v))]
        lines.append("🎞 " + e(" • ".join(b for b in bits if b)))
    for i, a in enumerate(audios[:6], 1):
        bits = [AUDIO_FORMATS.get(a.get("codec_name", ""), (a.get("codec_name") or "?").upper()),
                a.get("channel_layout"), lang_name(a)]
        lines.append(f"🔊 {i}. " + e(" • ".join(b for b in bits if b)))
    if len(audios) > 6:
        lines.append(f"🔊 … +{len(audios) - 6} more audio tracks")
    if texts:
        langs = [lang_name(t) or "?" for t in texts[:10]]
        lines.append("💬 " + e(", ".join(langs)) + (f" (+{len(texts) - 10})" if len(texts) > 10 else ""))
    saved = 100.0 * (1 - fetched / size) if size else 0.0
    if cached:
        lines.append("⚡ Cached result (no new data read)")
    else:
        lines.append(f"⚡ Read {e(fmt_size(fetched))} of {e(fmt_size(size))} ({saved:.2f}% saved, 0 bytes on disk)")
    if link:
        lines.insert(0, f'<b>MediaInfo Generated 📄:</b>\n\n{html.escape(link)}\n')
    elif txt_fallback:
        lines.append("\n📄 Full MediaInfo attached as .txt (Telegraph was unavailable).")
    else:
        lines.append("\n📄 Full MediaInfo report attached.")
    return "\n".join(lines)


# =============================================================================
# Telegraph publishing (MediaInfo as a link)
# =============================================================================
class TelegraphError(Exception):
    pass


TELEGRAPH_MAX_BYTES = 60_000  # API limit is 64 KB of content; keep headroom


def _nodes_from_blocks(blocks: list[str]) -> list[dict]:
    nodes: list[dict] = []
    for block in blocks:
        head, _, body = block.partition("\n")
        nodes.append({"tag": "h4", "children": [head.strip()]})
        if body:
            nodes.append({"tag": "pre", "children": [body]})
    return nodes


def _nodes_size(nodes: list[dict]) -> int:
    return len(json.dumps(nodes, ensure_ascii=False).encode("utf-8"))


def report_to_nodes(report: str) -> list[dict]:
    """
    Convert the plain-text report into Telegraph nodes (one h4 + pre per section).
    If it exceeds the page limit, drop chapters first, then trailing subtitle
    tracks, and add a note. Raises TelegraphError if it still cannot fit.
    """
    blocks = report.strip().split("\n\n")
    nodes = _nodes_from_blocks(blocks)
    if _nodes_size(nodes) <= TELEGRAPH_MAX_BYTES:
        return nodes

    trimmed = [b for b in blocks if not b.startswith("Menu\n")]
    dropped = len(blocks) - len(trimmed)
    while True:
        nodes = _nodes_from_blocks(trimmed) + [
            {"tag": "p", "children": [f"Report trimmed to fit Telegraph ({dropped} section(s) omitted)."]}
        ]
        if _nodes_size(nodes) <= TELEGRAPH_MAX_BYTES:
            return nodes
        text_idx = [i for i, b in enumerate(trimmed) if b.startswith("Text #")]
        if not text_idx:
            raise TelegraphError("report too large for a Telegraph page")
        trimmed.pop(text_idx[-1])
        dropped += 1


def public_link(url: str) -> str:
    """Show Telegraph pages on TELEGRAPH_DOMAIN (default graph.org), e.g. https://graph.org/MediaInfo-10-18-11318."""
    domain = Config.TELEGRAPH_DOMAIN
    if not domain:
        return url
    parts = urlsplit(url)
    if parts.hostname in ("telegra.ph", "graph.org"):
        return parts._replace(netloc=domain).geturl()
    return url


class Telegraph:
    """Minimal telegra.ph client (createAccount / createPage)."""

    def __init__(self, session: aiohttp.ClientSession) -> None:
        self.session = session
        self.token = Config.TELEGRAPH_ACCESS_TOKEN
        self._lock = asyncio.Lock()

    async def _call(self, method: str, **params: str) -> dict:
        """POST to the Telegraph API, trying every configured API host (with retries)."""
        last = "unknown error"
        for base in Config.TELEGRAPH_API_URLS:
            for attempt in range(2):
                try:
                    async with self.session.post(
                        f"{base}/{method}", data=params,
                        headers={"User-Agent": "MediaInfoBot/1.0"},
                        timeout=aiohttp.ClientTimeout(total=20),
                    ) as resp:
                        payload = await resp.json(content_type=None)
                except (aiohttp.ClientError, asyncio.TimeoutError, OSError, ValueError) as exc:
                    last = f"{base}: network error ({type(exc).__name__})"
                    await asyncio.sleep(0.5 * (attempt + 1))
                    continue
                if isinstance(payload, dict) and payload.get("ok"):
                    return payload["result"]
                err = payload.get("error", "unknown error") if isinstance(payload, dict) else "bad response"
                raise TelegraphError(str(err))  # API answered: retrying another host will not help
            log.warning("Telegraph host failed: %s", last)
        raise TelegraphError(last)

    async def _ensure_token(self, force: bool = False) -> None:
        if self.token and not force:
            return
        async with self._lock:
            if self.token and not force:
                return
            res = await self._call(
                "createAccount",
                short_name=Config.TELEGRAPH_AUTHOR[:32],
                author_name=Config.TELEGRAPH_AUTHOR[:128],
            )
            self.token = res["access_token"]

    async def publish(self, title: str, report: str) -> str:
        nodes = report_to_nodes(report)
        await self._ensure_token()
        for attempt in range(2):
            try:
                res = await self._call(
                    "createPage",
                    access_token=self.token,
                    title=(title or "MediaInfo")[:256],
                    author_name=Config.TELEGRAPH_AUTHOR[:128],
                    content=json.dumps(nodes, ensure_ascii=False),
                    return_content="false",
                )
                return public_link(res["url"])
            except TelegraphError as exc:
                if attempt == 0 and "ACCESS_TOKEN" in str(exc).upper():
                    await self._ensure_token(force=True)  # stale/invalid token: make a new account
                    continue
                raise
        raise TelegraphError("could not publish")


# =============================================================================
# Result cache and runtime statistics
# =============================================================================
@dataclass
class Result:
    name: str
    size: int
    data: dict
    report: str
    link: Optional[str] = None
    error: Optional[str] = None
    created: float = field(default_factory=time.monotonic)


class ResultCache:
    """TTL + LRU cache so re-inspecting the same file costs zero network."""

    def __init__(self, ttl: float, max_entries: int) -> None:
        self.ttl, self.max = ttl, max_entries
        self._d: "OrderedDict[str, Result]" = OrderedDict()

    def get(self, key: str) -> Optional[Result]:
        r = self._d.get(key)
        if r is None:
            return None
        if time.monotonic() - r.created > self.ttl:
            del self._d[key]
            return None
        self._d.move_to_end(key)
        return r

    def put(self, key: str, result: Result) -> None:
        if self.ttl <= 0 or self.max <= 0:
            return
        self._d[key] = result
        self._d.move_to_end(key)
        while len(self._d) > self.max:
            self._d.popitem(last=False)


@dataclass
class Stats:
    started: float = field(default_factory=time.monotonic)
    inspections: int = 0
    cache_hits: int = 0
    failures: int = 0
    bytes_fetched: int = 0
    bytes_total: int = 0


# =============================================================================
# Access control, rate limiting
# =============================================================================
def is_authorized(user_id: Optional[int]) -> bool:
    if not Config.ALLOWED_USERS and not Config.OWNER_ID:
        return True  # public mode
    if user_id is None:
        return False
    return user_id == Config.OWNER_ID or user_id in Config.ALLOWED_USERS


class TokenBucket:
    def __init__(self, burst: float, rate: float) -> None:
        self.burst, self.rate = burst, rate
        self._state: dict[int, tuple[float, float]] = {}

    def take(self, uid: int) -> float:
        """Return 0.0 if allowed, else seconds to wait."""
        now = time.monotonic()
        tokens, last = self._state.get(uid, (self.burst, now))
        tokens = min(self.burst, tokens + (now - last) * self.rate)
        if tokens >= 1.0:
            self._state[uid] = (tokens - 1.0, now)
            if len(self._state) > 5000:
                self._state = {k: v for k, v in self._state.items() if now - v[1] < 3600}
            return 0.0
        self._state[uid] = (tokens, now)
        return (1.0 - tokens) / self.rate if self.rate > 0 else 60.0


# =============================================================================
# 5. Telegram handlers
# =============================================================================
URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
MEDIA_EXTS = {
    # video
    ".mkv", ".mp4", ".m4v", ".mov", ".avi", ".webm", ".ts", ".m2ts", ".mts", ".flv",
    ".wmv", ".3gp", ".mpg", ".mpeg", ".ogv", ".vob",
    # audio
    ".mp3", ".flac", ".m4a", ".aac", ".opus", ".ogg", ".wav", ".mka", ".ac3", ".eac3", ".dts",
}
TWO_GIB = 2 * 1024 ** 3
# Commands that trigger a MediaInfo report. Nothing else ever does.
MEDIAINFO_COMMANDS = ["mediainfo", "ml", "mi"]

HELP_TEXT = (
    "👋 <b>Zero-Download MediaInfo Bot</b>\n\n"
    "Share a <b>video / audio file</b>, then reply to it with <code>/mediainfo</code> (or "
    "<code>/ml</code>) and I'll give you the full MediaInfo as a <b>graph.org link</b> - "
    "open it right in Telegram, nothing to download.\n\n"
    "<b>Commands</b>\n"
    "/mediainfo or /ml - reply to a video/audio file (or a message with a link) with this\n"
    "/mediainfo &lt;link&gt; - inspect a direct link\n"
    "• You can also send a file with <code>/mediainfo</code> as its caption.\n"
    "/help - this message\n\n"
    "• I <b>never</b> send MediaInfo unless you use a command.\n"
    "• Files are <b>never downloaded</b> - only the few KB/MB of header data are read.\n"
    "• Any file size (up to 4 GB with a Premium session configured).\n"
    "• External links must support HTTP Range requests."
)
MI_USAGE = (
    "Reply to a video/audio file or a link with <code>/mediainfo</code> (or <code>/ml</code>), "
    "or send <code>/mediainfo &lt;direct link&gt;</code>."
)


def safe_filename(name: str) -> str:
    stem = os.path.splitext(name)[0]
    stem = re.sub(r"[^\w.\- ]+", "_", stem).strip(" ._")[:80] or "video"
    return f"{stem}_mediainfo.txt"


def fmt_uptime(seconds: float) -> str:
    d, rem = divmod(int(seconds), 86400)
    h, rem = divmod(rem, 3600)
    m, s = divmod(rem, 60)
    return (f"{d}d " if d else "") + f"{h}h {m}m {s}s"


class BotApp:
    def __init__(self) -> None:
        from pyrogram import Client  # imported lazily so unit tests need no Telegram stack

        common = dict(api_id=Config.TELEGRAM_API_ID, api_hash=Config.TELEGRAM_API_HASH, in_memory=True)
        self.bot = Client("mediainfo_bot", bot_token=Config.TELEGRAM_BOT_TOKEN, **common)
        self.user = (
            Client("mediainfo_user", session_string=Config.TELEGRAM_USER_SESSION_STRING, **common)
            if Config.TELEGRAM_USER_SESSION_STRING else None
        )
        self.server = StreamServer()
        self.sem = asyncio.Semaphore(Config.MAX_CONCURRENT_PROBES)
        self.limiter = TokenBucket(Config.RATE_LIMIT_BURST, Config.RATE_LIMIT_REFILL_RATE)
        self.cache = ResultCache(Config.CACHE_TTL_SECONDS, Config.CACHE_MAX_ENTRIES)
        self.stats = Stats()
        self.http: Optional[aiohttp.ClientSession] = None
        self.telegraph: Optional[Telegraph] = None

    # -- wiring ---------------------------------------------------------------
    def register_handlers(self) -> None:
        from pyrogram import filters
        from pyrogram.handlers import MessageHandler

        # Order matters: Pyrogram runs only the first matching handler per group,
        # so commands must come before the generic media/text handlers.
        add = self.bot.add_handler
        add(MessageHandler(self.on_help, filters.command(["start", "help"])))
        add(MessageHandler(self.on_stats, filters.command(["stats"])))
        # The ONLY trigger for a MediaInfo report. No handler reacts to plain media/text,
        # so files and links shared without a command are ignored.
        # (filters.command also matches a command placed in a media caption.)
        add(MessageHandler(self.on_mi, filters.command(MEDIAINFO_COMMANDS)))
        add(MessageHandler(self.on_fallback, filters.private & ~filters.service))

    async def run(self) -> None:
        from pyrogram import idle

        Config.validate()
        await self.server.start()
        self.http = aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(resolver=SafeResolver(), limit=20),
            timeout=aiohttp.ClientTimeout(total=None, sock_connect=10, sock_read=20),
        )
        self.telegraph = Telegraph(self.http)
        self.register_handlers()
        await self.bot.start()
        if self.user:
            await self.user.start()
        me = await self.bot.get_me()
        log.info("Bot @%s started (premium session: %s, output: %s)",
                 me.username, bool(self.user), Config.OUTPUT_MODE)
        await self._set_menu()
        try:
            await idle()
        finally:
            if self.user:
                await self.user.stop()
            await self.bot.stop()
            await self.http.close()
            await self.server.stop()

    # -- helpers --------------------------------------------------------------
    async def _set_menu(self) -> None:
        """Show the commands in Telegram's / menu (best effort)."""
        from pyrogram.types import BotCommand
        try:
            await self.bot.set_bot_commands([
                BotCommand("mediainfo", "Reply to a media file/link to get its MediaInfo"),
                BotCommand("ml", "Short for /mediainfo"),
                BotCommand("help", "How to use this bot"),
            ])
        except Exception as exc:
            log.info("Could not set bot command menu: %s", exc)

    @staticmethod
    def _media_of(message):
        if message is None:
            return None
        return message.video or message.animation or message.audio or message.document

    async def _authorized(self, message) -> bool:
        uid = message.from_user.id if message.from_user else None
        if not is_authorized(uid):
            await message.reply_text("⛔ You are not authorised to use this bot.")
            return False
        return True

    async def _gate(self, message) -> bool:
        if not await self._authorized(message):
            return False
        uid = message.from_user.id if message.from_user else 0
        wait = self.limiter.take(uid)
        if wait > 0:
            await message.reply_text(f"⏳ Slow down - try again in {wait:.0f}s.")
            return False
        return True

    # -- command / message handlers -------------------------------------------
    async def on_help(self, client, message) -> None:
        from pyrogram.enums import ParseMode
        user_id = message.from_user.id if message.from_user else None
        log.info("Received /start or /help from user: %s", user_id)
        if not is_authorized(user_id):
            log.warning("User %s is not authorized to use this bot", user_id)
            return
        await message.reply_text(HELP_TEXT, parse_mode=ParseMode.HTML)
        log.info("Replied to user %s with help text", user_id)

    async def on_fallback(self, client, message) -> None:
        from pyrogram.enums import ParseMode
        user_id = message.from_user.id if message.from_user else None
        if not is_authorized(user_id):
            return
        text = (message.text or message.caption or "").strip()
        cmd = text.split()[0].lower() if text else ""
        if any(cmd.startswith(f"/{c}") for c in ("start", "help")):
            await self.on_help(client, message)
            return
        if any(cmd.startswith(f"/{c}") for c in MEDIAINFO_COMMANDS):
            await self.on_mi(client, message)
            return
        if self._media_of(message):
            await message.reply_text(
                "💡 Reply to this media with <code>/mediainfo</code> (or <code>/mi</code>) to generate its MediaInfo report.",
                parse_mode=ParseMode.HTML,
            )
        else:
            log.info("Received generic message from user %s, sending help text", user_id)
            await message.reply_text(HELP_TEXT, parse_mode=ParseMode.HTML)

    async def on_stats(self, client, message) -> None:
        from pyrogram.enums import ParseMode
        uid = message.from_user.id if message.from_user else None
        if not Config.OWNER_ID or uid != Config.OWNER_ID:
            return
        st = self.stats
        saved = 100.0 * (1 - st.bytes_fetched / st.bytes_total) if st.bytes_total else 0.0
        await message.reply_text(
            "📊 <b>Bot stats</b>\n"
            f"Uptime: {fmt_uptime(time.monotonic() - st.started)}\n"
            f"Inspections: {st.inspections} (cache hits: {st.cache_hits}, failures: {st.failures})\n"
            f"Data read: {html.escape(fmt_size(st.bytes_fetched))} of "
            f"{html.escape(fmt_size(st.bytes_total))} inspected ({saved:.3f}% saved)\n"
            f"Output mode: <code>{Config.OUTPUT_MODE}</code> • Premium session: {bool(self.user)}",
            parse_mode=ParseMode.HTML,
        )

    async def on_mi(self, client, message) -> None:
        """/mi - reply to media/link, attach to media caption, or pass a link."""
        from pyrogram.enums import ParseMode

        if not await self._authorized(message):
            return
        target = message.reply_to_message
        for cand in (target, message):
            if self._media_of(cand):
                await self._start_media(client, message, cand)
                return
        arg = " ".join(message.command[1:]) if message.command else ""
        m = URL_RE.search(arg)
        if not m and target is not None:
            m = URL_RE.search(target.text or target.caption or "")
        if m:
            await self._start_url(message, m.group(0))
            return
        await message.reply_text(MI_USAGE, parse_mode=ParseMode.HTML)

    # -- entry points ---------------------------------------------------------
    async def _start_media(self, client, reply_to, media_msg) -> None:
        """`reply_to` receives the answer; `media_msg` carries the file."""
        from pyrogram.enums import ParseMode

        media = self._media_of(media_msg)
        if media is None or not await self._gate(reply_to):
            return
        name = getattr(media, "file_name", None) or f"media_{media_msg.id}"
        mime = getattr(media, "mime_type", None) or ""
        ext = os.path.splitext(name)[1].lower()
        if media_msg.document and not (
            mime.startswith(("video/", "audio/")) or ext in MEDIA_EXTS
        ):
            await reply_to.reply_text("That document doesn't look like a video/audio file (by type/extension).")
            return
        size = getattr(media, "file_size", 0) or 0
        if size == 0:
            await reply_to.reply_text(
                "⚠️ This file is <b>0 bytes</b> - it's empty, so there's no metadata to read. "
                "The upload probably failed; try sending it again.", parse_mode=ParseMode.HTML)
            return

        key = f"tg:{getattr(media, 'file_unique_id', '') or media_msg.id}:{size}"
        cached = self.cache.get(key)
        if cached is not None:
            self.stats.cache_hits += 1
            await self._deliver(reply_to, cached, fetched=0, cached=True)
            return

        stream_client, stream_msg = client, media_msg
        if size > TWO_GIB and self.user is not None:
            try:
                um = await self.user.get_messages(media_msg.chat.id, media_msg.id)
                if um and not um.empty and self._media_of(um):
                    stream_client, stream_msg = self.user, um
            except Exception as exc:  # user session not in this chat
                log.info("User session cannot see message, falling back to bot: %s", exc)

        source = TelegramSource(stream_client, stream_msg, size, mime)
        note = "Telegram MTProto range streaming" + (" (Premium user session)" if stream_client is self.user else "")
        await self._inspect(reply_to, source, name, note, key)

    async def _start_url(self, reply_to, url: str) -> None:
        from pyrogram.enums import ParseMode

        if not await self._gate(reply_to):
            return
        url = url.rstrip(").,;]")
        try:
            await assert_public_host(url)  # SSRF check always runs, even for cached URLs
        except SSRFError as exc:
            await reply_to.reply_text(f"🚫 {html.escape(str(exc))}", parse_mode=ParseMode.HTML)
            return
        key = f"url:{url}"
        cached = self.cache.get(key)
        if cached is not None:
            self.stats.cache_hits += 1
            await self._deliver(reply_to, cached, fetched=0, cached=True)
            return

        assert self.http is not None
        src = HttpSource(self.http, url)
        status = await reply_to.reply_text("🔎 Contacting server…")
        try:
            await src.probe_size()
        except (SSRFError, SourceError) as exc:
            self.stats.failures += 1
            await status.edit_text(f"❌ {html.escape(str(exc))}", parse_mode=ParseMode.HTML)
            return
        except Exception as exc:
            self.stats.failures += 1
            log.warning("HTTP probe failed: %r", exc)
            await status.edit_text("❌ Could not reach that link.")
            return
        if src.size == 0:
            await status.edit_text("⚠️ The remote file is <b>0 bytes</b> - nothing to inspect.",
                                   parse_mode=ParseMode.HTML)
            return
        name = src.filename or "remote_media"
        await self._inspect(reply_to, src, name, "HTTP range streaming (external link)", key, status=status)

    # -- core flow ------------------------------------------------------------
    async def _inspect(self, message, source: Source, name: str, note: str, cache_key: str,
                       status=None) -> None:
        from pyrogram.enums import ParseMode

        if status is None:
            status = await message.reply_text("🔎 Inspecting headers…")
        sess = None
        try:
            async with self.sem:
                sess = self.server.register(source, name)
                data = await run_ffprobe(self.server.url_for(sess))
            report = format_mediainfo(data, name, source.size, source.bytes_fetched, note)
            result = Result(name=name, size=source.size, data=data, report=report)
            result.link = await self._publish(result)
            if result.link or Config.OUTPUT_MODE == "txt":  # never cache a failed publish
                self.cache.put(cache_key, result)
            self.stats.inspections += 1
            self.stats.bytes_fetched += source.bytes_fetched
            self.stats.bytes_total += source.size
            await self._deliver(message, result, fetched=source.bytes_fetched, cached=False)
            with contextlib.suppress(Exception):
                await status.delete()
        except ProbeError as exc:
            self.stats.failures += 1
            await status.edit_text(f"❌ {html.escape(str(exc))}", parse_mode=ParseMode.HTML)
        except Exception as exc:
            self.stats.failures += 1
            log.exception("Unexpected failure inspecting %s", name)
            with contextlib.suppress(Exception):
                await status.edit_text(f"💥 Unexpected error: {html.escape(type(exc).__name__)}")
        finally:
            if sess is not None:
                self.server.unregister(sess.token)

    async def _publish(self, result: Result) -> Optional[str]:
        """Publish to Telegraph unless OUTPUT_MODE is 'txt'. Returns the link or None (reason in result.error)."""
        if Config.OUTPUT_MODE == "txt" or self.telegraph is None:
            return None
        try:
            return await self.telegraph.publish(f"{result.name} - MediaInfo", result.report)
        except Exception as exc:
            result.error = str(exc) or type(exc).__name__
            log.warning("Telegraph publish failed: %s", result.error)
            return None

    @staticmethod
    def _wants_txt(result: Result) -> bool:
        mode = Config.OUTPUT_MODE
        return mode in ("txt", "both") or (result.link is None and Config.TXT_FALLBACK)

    async def _deliver(self, message, result: Result, fetched: int, cached: bool) -> None:
        from pyrogram.enums import ParseMode
        from pyrogram.types import InlineKeyboardButton, InlineKeyboardMarkup

        link = result.link
        send_txt = self._wants_txt(result)
        summary = format_summary(
            result.data, result.name, result.size, fetched, link=link, cached=cached,
            txt_fallback=(link is None and send_txt and Config.OUTPUT_MODE != "txt"),
        )

        def make_doc() -> io.BytesIO:
            bio = io.BytesIO(result.report.encode("utf-8"))
            bio.name = safe_filename(result.name)
            return bio

        if link:
            markup = InlineKeyboardMarkup([[InlineKeyboardButton("📄 Full MediaInfo", url=link)]])
            await message.reply_text(summary, parse_mode=ParseMode.HTML, reply_markup=markup)
            if send_txt:  # OUTPUT_MODE=both
                await message.reply_document(make_doc(), caption="📄 MediaInfo (.txt)")
        elif send_txt:
            # Telegram captions are limited to 1024 chars.
            if len(summary) <= 1000:
                await message.reply_document(make_doc(), caption=summary, parse_mode=ParseMode.HTML)
            else:
                await message.reply_document(make_doc(), caption="📄 MediaInfo (.txt)")
                await message.reply_text(summary, parse_mode=ParseMode.HTML)
        else:
            await message.reply_text(
                "❌ <b>Could not create the graph.org link.</b>\n"
                f"Reason: <code>{html.escape(result.error or 'Telegraph unavailable')}</code>\n"
                "Please try again in a moment.",
                parse_mode=ParseMode.HTML,
            )


def sync_telegram_clock() -> None:
    """Detect and compensate for system clock drift against Telegram's servers."""
    import email.utils
    import urllib.request

    for url in ("https://api.telegram.org", "https://telegram.org"):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                date_header = resp.headers.get("Date")
                if date_header:
                    server_time = email.utils.parsedate_to_datetime(date_header).timestamp()
                    local_time = time.time()
                    skew = server_time - local_time
                    if abs(skew) > 15:
                        log.warning(
                            "System clock is skewed by %.1f seconds from Telegram server time. "
                            "Auto-compensating timestamp generation so Telegram doesn't reject packets.", skew
                        )
                        _orig_time = time.time
                        time.time = lambda: _orig_time() + skew
                    return
        except Exception as exc:
            log.debug("Could not sync clock with %s: %s", url, exc)


async def _async_main() -> None:
    app = BotApp()
    await app.run()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    logging.getLogger("pyrogram").setLevel(logging.WARNING)
    sync_telegram_clock()
    try:
        asyncio.run(_async_main())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
