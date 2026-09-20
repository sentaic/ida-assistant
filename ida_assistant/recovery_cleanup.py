"""Bounded retention of plugin-owned recovery files in a managed IDB directory."""

from __future__ import annotations

import logging
import re
import stat
import time
from pathlib import Path

from .asset_lock import AssetLock
from .errors import SampleBusy

RETENTION_SECONDS = 24 * 60 * 60
CHECK_INTERVAL_SECONDS = 3 * 60 * 60
_SIDECARS = (".id0", ".id1", ".id2", ".nam", ".til")
_LOG = logging.getLogger(__name__)


def _plain(path: Path, directory: bool = False) -> bool:
    """Do not traverse symlinks, Windows junctions or other reparse points."""
    info = path.lstat()
    if getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
        return False
    return stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)


def _groups(database: Path) -> dict[str, list[tuple[float, list[Path], Path | None]]]:
    root = database.parent
    suffixes = (database.suffix, *_SIDECARS)
    pattern = re.compile(
        re.escape(database.stem)
        + r"\.save-[0-9a-f]{32}("
        + "|".join(re.escape(suffix) for suffix in suffixes)
        + r")$"
    )
    saves: dict[str, list[Path]] = {}
    result: dict[str, list[tuple[float, list[Path], Path | None]]] = {"save": [], "orphan": []}
    for path in root.iterdir():
        if pattern.fullmatch(path.name):
            saves.setdefault(path.stem, []).append(path)
        elif re.fullmatch(r"orphan-[0-9a-f]{32}", path.name) and _plain(path, directory=True):
            files = list(path.iterdir())
            allowed = {database.stem + suffix for suffix in _SIDECARS}
            if all(child.name in allowed and _plain(child) for child in files):
                # The quarantine directory's timestamp dates the recovery event;
                # moved IDA files can have much older modification timestamps.
                result["orphan"].append((path.stat().st_mtime, files, path))
    for files in saves.values():
        if all(_plain(path) for path in files):
            result["save"].append((max(path.stat().st_mtime for path in files), files, None))
    return result


def prune_recovery(
    database: Path, *, successful_save: bool = False, now: float | None = None
) -> list[str]:
    """Caller owns the IDB lock and no worker is using its recovery files.

    Keep at most the newest save family and newest orphan family for 24 hours.
    A successful save supersedes all recovery families. Never recursively delete
    a directory or touch manually named backups or unfamiliar files.
    """
    removed: list[str] = []
    try:
        if not _plain(database.parent, directory=True):
            return removed
        root = database.parent.resolve(strict=True)
        database = root / database.name
        if not _plain(database) or not database.stat().st_size:
            return removed
        cutoff = (time.time() if now is None else now) - RETENTION_SECONDS
        groups = _groups(database)
        for entries in groups.values():
            for index, (modified, files, directory) in enumerate(
                sorted(entries, key=lambda entry: entry[0], reverse=True)
            ):
                if not successful_save and index == 0 and modified > cutoff:
                    continue
                try:
                    parent = root
                    if directory is not None:
                        if (
                            not _plain(directory, directory=True)
                            or directory.resolve().parent != root
                        ):
                            continue
                        parent = directory
                    for path in files:
                        if path.resolve().parent != parent or not _plain(path):
                            continue
                        path.unlink()
                        removed.append(str(path))
                    if directory is not None:
                        directory.rmdir()  # Refuse nonempty directories; no recursive removal.
                        removed.append(str(directory))
                except OSError as exc:
                    _LOG.warning("Recovery cleanup deferred: %s", exc)
    except OSError as exc:
        _LOG.warning("Recovery cleanup deferred for %s: %s", database, exc)
    return removed


def prune_inactive_recovery(database: Path, state_dir: Path) -> None:
    """Periodic cleanup also covers closed sessions; busy IDBs are skipped."""
    if not database.parent.is_dir():
        return
    if not any(database.parent.glob(f"{database.stem}.save-*")) and not any(
        database.parent.glob("orphan-*")
    ):
        return
    registry = guard = None
    try:
        registry = AssetLock.acquire(
            state_dir,
            {"operation": "recovery_cleanup"},
            filename="registry.lock",
            purpose="project registry",
        )
        guard = AssetLock.acquire(database.parent, {"operation": "recovery_cleanup"})
        prune_recovery(database)
    except SampleBusy:
        pass
    except OSError as exc:
        _LOG.warning("Recovery cleanup deferred for %s: %s", database, exc)
    finally:
        if guard is not None:
            guard.release()
        if registry is not None:
            registry.release()
