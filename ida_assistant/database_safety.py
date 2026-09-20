"""On-disk IDB publication, change detection and orphan recovery."""

from __future__ import annotations

import os
import uuid
from collections.abc import Callable
from pathlib import Path

from .fingerprint import quick_fingerprint

SIDECAR_SUFFIXES = (".id0", ".id1", ".id2", ".nam", ".til")


def atomic_save(database: Path, save: Callable[[str], bool], close: Callable[[], None]) -> None:
    """Publish only a completed, closed database; failed candidates remain recoverable."""
    staging = database.with_name(f"{database.stem}.save-{uuid.uuid4().hex}{database.suffix}")
    if not save(str(staging)) or not staging.is_file() or not staging.stat().st_size:
        raise RuntimeError(f"DATABASE_SAVE_FAILED: original retained; candidate: {staging}")
    # IDA may switch PATH_TYPE_IDB when saving as. Close before replacing on Windows.
    close()
    with staging.open("r+b") as stream:
        os.fsync(stream.fileno())
    os.replace(staging, database)


def quarantine_sidecars(database: Path) -> list[str]:
    """Called only under managed IDB ownership; retain leftovers for recovery."""
    leftovers = [database.with_suffix(suffix) for suffix in SIDECAR_SUFFIXES]
    leftovers = [path for path in leftovers if path.exists()]
    if not leftovers:
        return []
    recovery = database.parent / f"orphan-{uuid.uuid4().hex}"
    recovery.mkdir()
    moved: list[str] = []
    for path in leftovers:
        path.rename(recovery / path.name)
        moved.append(str(recovery / path.name))
    return moved


def verify_fingerprint(database: Path, expected: dict | None) -> None:
    if expected is not None and quick_fingerprint(database) != expected:
        raise RuntimeError(
            "DATABASE_CHANGED: published IDB differs from its saved fingerprint; "
            "inspect/recover it or explicitly rebuild with open(reset_if_changed=true)"
        )
