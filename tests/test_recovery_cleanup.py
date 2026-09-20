from __future__ import annotations

import os
import stat
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

from ida_assistant.asset_lock import AssetLock
from ida_assistant.config import Settings
from ida_assistant.pool import SessionPool
from ida_assistant.recovery_cleanup import (
    CHECK_INTERVAL_SECONDS,
    RETENTION_SECONDS,
    _plain,
    prune_inactive_recovery,
    prune_recovery,
)


class RecoveryCleanupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.database = self.root / "sample.i64"
        self.database.write_bytes(b"published")
        self.now = time.time()

    def save_family(self, index: int, age: float = 0) -> list[Path]:
        files = [self.root / f"sample.save-{index:032x}{suffix}" for suffix in (".i64", ".id0")]
        for file in files:
            file.write_bytes(b"candidate")
            os.utime(file, (self.now - age, self.now - age))
        return files

    def orphan(self, index: int, age: float = 0) -> Path:
        folder = self.root / f"orphan-{index:032x}"
        folder.mkdir()
        (folder / "sample.id0").write_bytes(b"recovery")
        os.utime(folder, (self.now - age, self.now - age))
        return folder

    def test_keeps_only_latest_family_of_each_kind(self) -> None:
        older = self.save_family(1, 60)
        newest = self.save_family(2, 10)
        old_orphan, new_orphan = self.orphan(1, 60), self.orphan(2, 10)
        prune_recovery(self.database, now=self.now)
        self.assertTrue(all(file.exists() for file in newest))
        self.assertTrue(all(not file.exists() for file in older))
        self.assertTrue(new_orphan.exists())
        self.assertFalse(old_orphan.exists())
        self.assertEqual(self.database.read_bytes(), b"published")

    def test_expiry_removes_even_latest_family(self) -> None:
        files = self.save_family(1, RETENTION_SECONDS + 1)
        folder = self.orphan(1, RETENTION_SECONDS + 1)
        prune_recovery(self.database, now=self.now)
        self.assertTrue(all(not file.exists() for file in files))
        self.assertFalse(folder.exists())

    def test_successful_save_removes_fresh_recovery_but_not_manual_files(self) -> None:
        files = self.save_family(1)
        folder = self.orphan(1)
        manual = self.root / "sample.backup.i64"
        manual.write_bytes(b"manual")
        unrelated = self.root / f"other.save-{2:032x}.i64"
        unrelated.write_bytes(b"other database")
        prune_recovery(self.database, successful_save=True)
        self.assertTrue(all(not file.exists() for file in files))
        self.assertFalse(folder.exists())
        self.assertEqual(manual.read_bytes(), b"manual")
        self.assertTrue(unrelated.exists())

    def test_unknown_files_prevent_directory_cleanup(self) -> None:
        folder = self.orphan(1)
        (folder / "notes.txt").write_text("user file")
        prune_recovery(self.database, successful_save=True)
        self.assertTrue((folder / "sample.id0").exists())
        self.assertTrue((folder / "notes.txt").exists())

    def test_no_cleanup_without_nonempty_published_database(self) -> None:
        files = self.save_family(1, RETENTION_SECONDS + 1)
        self.database.unlink()
        self.assertEqual(prune_recovery(self.database), [])
        self.database.touch()
        self.assertEqual(prune_recovery(self.database), [])
        self.assertTrue(all(file.exists() for file in files))

    def test_periodic_cleanup_skips_busy_worker(self) -> None:
        files = self.save_family(1, RETENTION_SECONDS + 1)
        guard = AssetLock.acquire(self.root, {"test": "busy worker"})
        try:
            prune_inactive_recovery(self.database, self.root / "state")
            self.assertTrue(all(file.exists() for file in files))
        finally:
            guard.release()
        prune_inactive_recovery(self.database, self.root / "state")
        self.assertTrue(all(not file.exists() for file in files))

    def test_reparse_points_are_not_followed(self) -> None:
        info = SimpleNamespace(
            st_mode=stat.S_IFDIR, st_file_attributes=stat.FILE_ATTRIBUTE_REPARSE_POINT
        )
        with patch.object(Path, "lstat", return_value=info):
            self.assertFalse(_plain(self.root, directory=True))
            self.assertEqual(prune_recovery(self.database, successful_save=True), [])

    def test_unlink_failure_does_not_fail_database_lifecycle(self) -> None:
        files = self.save_family(1, RETENTION_SECONDS + 1)
        with (
            patch.object(Path, "unlink", side_effect=PermissionError("locked")),
            self.assertLogs("ida_assistant.recovery_cleanup", level="WARNING"),
        ):
            self.assertEqual(prune_recovery(self.database, now=self.now), [])
        self.assertTrue(all(file.exists() for file in files))


class RecoveryScheduleTests(unittest.IsolatedAsyncioTestCase):
    async def test_scans_only_when_three_hour_deadline_is_due(self) -> None:
        with TemporaryDirectory() as folder:
            pool = SessionPool(Settings.from_args(["--project-root", folder]))
            database = Path(folder) / "sample.i64"
            pool._analyses["managed"] = SimpleNamespace(database=database, external_database=False)
            pool._analyses["external"] = SimpleNamespace(database=database, external_database=True)
            with patch("ida_assistant.pool.prune_inactive_recovery") as cleanup:
                await pool.reap()
                cleanup.assert_not_called()
                pool._next_recovery_cleanup = 0
                before = time.monotonic()
                await pool.reap()
                cleanup.assert_called_once_with(database, pool.settings.state_dir)
                self.assertGreaterEqual(
                    pool._next_recovery_cleanup, before + CHECK_INTERVAL_SECONDS
                )
                await pool.reap()
                cleanup.assert_called_once()
