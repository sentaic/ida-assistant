from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from .errors import SampleBusy


@dataclass(slots=True)
class AssetLock:
    """Cross-process ownership for one shared IDB/worker asset."""

    path: Path
    handle: BinaryIO

    @classmethod
    def acquire(
        cls,
        asset_dir: Path,
        owner: dict[str, object],
        filename: str = "worker.lock",
        purpose: str = "shared IDB",
    ) -> AssetLock:
        asset_dir.mkdir(parents=True, exist_ok=True)
        path = asset_dir / filename
        handle = path.open("a+b")
        try:
            handle.seek(0)
            if handle.read(1) == b"":
                handle.seek(0)
                handle.write(b"\0")
                handle.flush()
            handle.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (OSError, BlockingIOError) as exc:
            handle.seek(1)
            detail = handle.read().decode("utf-8", "replace").strip()
            handle.close()
            raise SampleBusy(
                f"{purpose} is active in another scheduler: {detail or asset_dir}"
            ) from exc
        handle.seek(1)
        handle.truncate()
        ownership = {"pid": os.getpid(), **owner}
        handle.write(json.dumps(ownership, ensure_ascii=False).encode())
        handle.flush()
        owner_path = path.with_name(f"{path.name}.owner.json")
        temporary = owner_path.with_name(f".{owner_path.name}.{os.getpid()}.tmp")
        temporary.write_text(json.dumps(ownership, ensure_ascii=False), encoding="utf-8")
        os.replace(temporary, owner_path)
        return cls(path, handle)

    @classmethod
    def inspect(cls, asset_dir: Path, filename: str = "worker.lock") -> dict[str, object]:
        """Inspect a lock without creating project state or changing its owner data."""
        path = asset_dir / filename
        if not path.is_file():
            return {"locked": False, "owner": None}
        handle = path.open("r+b")
        locked = False
        try:
            # Read diagnostic ownership before probing the locked byte.  On
            # Windows a failed msvcrt.locking call can leave subsequent reads on
            # that handle failing with ERROR_LOCK_VIOLATION even when they start
            # beyond byte zero.
            owner_path = path.with_name(f"{path.name}.owner.json")
            try:
                detail = owner_path.read_text(encoding="utf-8").strip()
            except (FileNotFoundError, OSError):
                try:
                    handle.seek(1)
                    detail = handle.read().decode("utf-8", "replace").strip()
                except OSError:
                    detail = ""
            handle.seek(0)
            if os.name == "nt":
                import msvcrt

                try:
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                except OSError:
                    locked = True
                else:
                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                try:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                except (OSError, BlockingIOError):
                    locked = True
                else:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            try:
                owner = json.loads(detail) if detail else None
            except json.JSONDecodeError:
                owner = {"detail": detail}
            return {"locked": locked, "owner": owner if locked else None}
        finally:
            handle.close()

    def release(self) -> None:
        if self.handle.closed:
            return
        try:
            self.handle.seek(0)
            if os.name == "nt":
                import msvcrt

                try:
                    msvcrt.locking(self.handle.fileno(), msvcrt.LK_UNLCK, 1)
                except OSError:
                    # Closing the Windows handle releases any remaining byte-range lock.
                    pass
            else:
                import fcntl

                fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
        finally:
            self.handle.close()
