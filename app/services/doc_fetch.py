"""Fetch a document from a URL and extract plain text for evidence extraction.

Security: fetching arbitrary URLs server-side is an SSRF risk, so this module
hard-blocks private / loopback / link-local / reserved IPs and the cloud metadata
endpoint, validates every redirect hop, enforces http(s) only, and caps size + time.
Supported content: HTML (tags stripped), plain text / markdown, and PDF (best effort).
"""
from __future__ import annotations

import contextlib
import ipaddress
import re
import socket
from html.parser import HTMLParser
from urllib.parse import urlparse

import requests

MAX_BYTES = 8 * 1024 * 1024      # 8 MB cap
TIMEOUT = 12                     # seconds
MAX_REDIRECTS = 3
_UA = "CompLens-EvidenceFetcher/1.0"


class FetchError(Exception):
    pass


def _is_blocked_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return (addr.is_private or addr.is_loopback or addr.is_link_local
            or addr.is_reserved or addr.is_multicast or addr.is_unspecified
            or str(addr) == "169.254.169.254")  # cloud metadata


def _assert_safe(url: str) -> None:
    p = urlparse(url)
    if p.scheme not in ("http", "https"):
        raise FetchError("Only http/https URLs are allowed.")
    host = p.hostname
    if not host:
        raise FetchError("URL has no host.")
    # resolve ALL addresses the host maps to; block if any is internal
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        raise FetchError(f"Cannot resolve host: {host}") from None
    for info in infos:
        ip = info[4][0]
        if _is_blocked_ip(ip):
            raise FetchError("Refusing to fetch an internal/private address.")


class _TextExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self._skip = 0
        self.parts = []

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style", "noscript", "svg"):
            self._skip += 1

    def handle_endtag(self, tag):
        if tag in ("script", "style", "noscript", "svg") and self._skip:
            self._skip -= 1

    def handle_data(self, data):
        if not self._skip and data.strip():
            self.parts.append(data)


def _html_to_text(html: str) -> str:
    ex = _TextExtractor()
    with contextlib.suppress(Exception):
        ex.feed(html)
    text = " ".join(ex.parts)
    return re.sub(r"\s+", " ", text).strip()


def _pdf_to_text(raw: bytes) -> str:
    try:
        import io

        from pypdf import PdfReader
        reader = PdfReader(io.BytesIO(raw))
        return "\n".join((page.extract_text() or "") for page in reader.pages).strip()
    except ImportError:
        raise FetchError("PDF support not installed (pypdf).") from None
    except Exception as e:
        raise FetchError(f"Could not extract PDF text: {e}") from e


def fetch_url_text(url: str) -> tuple[str, str]:
    """Return (extracted_text, source_type). Raises FetchError on any problem."""
    current = url
    session = requests.Session()
    session.max_redirects = 0
    for _ in range(MAX_REDIRECTS + 1):
        _assert_safe(current)
        resp = session.get(current, timeout=TIMEOUT, stream=True,
                           allow_redirects=False, headers={"User-Agent": _UA})
        if resp.is_redirect or resp.status_code in (301, 302, 303, 307, 308):
            loc = resp.headers.get("Location")
            resp.close()
            if not loc:
                raise FetchError("Redirect without a location.")
            current = requests.compat.urljoin(current, loc)
            continue
        if resp.status_code != 200:
            resp.close()
            raise FetchError(f"Fetch failed with HTTP {resp.status_code}.")
        # read with a hard size cap
        chunks, total = [], 0
        for chunk in resp.iter_content(8192):
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_BYTES:
                resp.close()
                raise FetchError("Document exceeds the 8 MB size limit.")
        resp.close()
        raw = b"".join(chunks)
        ctype = resp.headers.get("Content-Type", "").lower()

        if "application/pdf" in ctype or current.lower().endswith(".pdf"):
            return _pdf_to_text(raw), "url:pdf"
        body = raw.decode("utf-8", errors="replace")
        if "text/html" in ctype or "<html" in body[:2000].lower():
            text = _html_to_text(body)
            if not text:
                raise FetchError("No readable text found at that URL.")
            return text, "url:html"
        return body.strip(), "url:text"
    raise FetchError("Too many redirects.")
