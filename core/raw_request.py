"""
Parse Burp/HTTP raw request files into FuzzPhantom request templates.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlsplit


@dataclass
class RawRequestTemplate:
    method: str
    target_url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""


def parse_raw_request(text: str, default_scheme: str = "https") -> RawRequestTemplate:
    normalized = text.replace("\r\n", "\n")
    header_blob, sep, body = normalized.partition("\n\n")
    lines = [line for line in header_blob.split("\n") if line.strip()]
    if not lines:
        raise ValueError("Raw request is empty")

    request_parts = lines[0].split()
    if len(request_parts) < 2:
        raise ValueError("Raw request first line must include method and path")

    method = request_parts[0].upper()
    raw_target = request_parts[1]
    headers: dict[str, str] = {}

    for line in lines[1:]:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        name = name.strip()
        if name:
            headers[name] = value.strip()

    host = headers.get("Host") or headers.get("host")
    if raw_target.startswith(("http://", "https://")):
        target_url = raw_target
        if not host:
            host = urlsplit(raw_target).netloc
    else:
        if not host:
            raise ValueError("Raw request must include Host header for relative paths")
        path = raw_target if raw_target.startswith("/") else f"/{raw_target}"
        target_url = f"{default_scheme}://{host}{path}"

    headers.pop("Host", None)
    headers.pop("host", None)

    return RawRequestTemplate(
        method=method,
        target_url=target_url,
        headers=headers,
        body=body,
    )
