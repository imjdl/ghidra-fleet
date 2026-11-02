"""Small shared helpers: pagination clamps, truncation, hashing."""

from __future__ import annotations

import hashlib

DEFAULT_LIMIT = 100
MAX_LIMIT = 1000
MAX_SCAN = 2_000_000  # safety cap when scanning huge programs


def clamp_limit(limit: int | None) -> int:
    if limit is None:
        return DEFAULT_LIMIT
    return max(1, min(int(limit), MAX_LIMIT))


def clamp_offset(offset: int | None) -> int:
    return max(0, int(offset or 0))


def truncate(text: str, max_chars: int | None) -> str:
    if max_chars is None or max_chars <= 0:
        max_chars = 20_000
    max_chars = min(int(max_chars), 200_000)
    if len(text) <= max_chars:
        return text
    note = f"... [截断：共 {len(text)} 字符，仅显示前 {max_chars} 字符，可用 max_chars 参数调整]"
    return text[:max_chars] + "\n" + note


def sha256_file(path: str, chunk_size: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()
