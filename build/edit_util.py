"""Edit text files while preserving their original newline style (LF or CRLF)."""
from pathlib import Path


def edit(path, pairs):
    p = Path(path)
    raw = p.read_bytes().decode("utf-8")
    crlf = "\r\n" in raw
    s = raw.replace("\r\n", "\n")
    for old, new in pairs:
        if old not in s:
            raise AssertionError(f"{path}: pattern not found: {old[:70]!r}")
        s = s.replace(old, new, 1)
    if crlf:
        s = s.replace("\n", "\r\n")
    p.write_bytes(s.encode("utf-8"))
