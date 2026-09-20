from __future__ import annotations

import hashlib
import os
import struct
from pathlib import Path
from typing import Any

from .errors import SourceOpenError

BLOCK_SIZE = 256 * 1024
FULL_HASH_LIMIT = 1024 * 1024
ALGORITHM = "blake2s-128:size+4x256k"


def quick_fingerprint(path: Path) -> dict[str, Any]:
    """Cheap change detector, not a cryptographic file identity."""
    try:
        stat = path.stat()
        if not path.is_file():
            raise OSError(f"not a regular file: {path}")
        size = stat.st_size
        digest = hashlib.blake2s(digest_size=16, person=b"ida-src")
        digest.update(struct.pack("<Q", size))
        with path.open("rb") as handle:
            if size <= FULL_HASH_LIMIT:
                digest.update(handle.read())
            else:
                offsets = (0, size // 3, (size * 2) // 3, size - BLOCK_SIZE)
                for offset in offsets:
                    offset = min(max(0, offset), size - BLOCK_SIZE)
                    handle.seek(offset)
                    digest.update(struct.pack("<Q", offset))
                    digest.update(handle.read(BLOCK_SIZE))
    except OSError as exc:
        code = getattr(exc, "winerror", None) or getattr(exc, "errno", None)
        raise SourceOpenError(
            f"SOURCE_READ_FAILED: cannot read {path}; os_error={code}; "
            "the agent must decide how to handle the source"
        ) from exc
    return {
        "algorithm": ALGORITHM,
        "size": size,
        "mtime_ns": stat.st_mtime_ns,
        "quick_hash": digest.hexdigest(),
    }


def same_content(left: dict[str, Any], right: dict[str, Any]) -> bool:
    return (
        left.get("algorithm") == right.get("algorithm")
        and left.get("size") == right.get("size")
        and left.get("quick_hash") == right.get("quick_hash")
    )


def canonical_path(path: Path) -> str:
    value = os.path.normcase(str(path.resolve()))
    return value.rstrip("\\/")
