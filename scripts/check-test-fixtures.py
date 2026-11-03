#!/usr/bin/env python3
"""Keep crate-local distribution fixtures identical to canonical public vectors."""
from pathlib import Path

root = Path(__file__).resolve().parent.parent
for crate, filename in (
    ("foctet", "archive-v0.json"),
    ("foctet", "frame-v0.json"),
    ("foctet", "handshake-v0.json"),
    ("foctet", "negative-v0.json"),
    ("foctet", "rekey-v0.json"),
    ("foctet-archive", "recovery-stream-v1.json"),
    ("foctet-storage-wire", "storage-text-v1.json"),
):
    canonical = root / "test-vectors" / filename
    packaged = root / crate / "tests" / "fixtures" / filename
    if canonical.read_bytes() != packaged.read_bytes():
        raise SystemExit(f"Fixture mismatch: {packaged.relative_to(root)}")
print("Crate fixtures match canonical public vectors")
