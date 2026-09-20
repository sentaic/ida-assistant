from __future__ import annotations

import asyncio
import unittest
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from test_pool import make_settings

from ida_assistant.asset_lock import AssetLock
from ida_assistant.errors import SampleBusy, WorkerFailed, WorkerTimedOut
from ida_assistant.pool import SessionPool


class WorkerRetirementTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.temp = TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "sample.i64").write_bytes(b"fake-idb")
        self.pool = SessionPool(
            make_settings(
                self.root,
                call_timeout=0.5,
                drain_timeout=3,
                shutdown_timeout=0.1,
                flush_timeout=0.1,
            )
        )
        await self.pool.open("sample.i64", "test", "test")
        await self.pool.call_active("test", "test", "get_metadata", {})
        self.record = self.pool._sessions["sample"]

    async def asyncTearDown(self) -> None:
        await self.pool.shutdown()
        self.temp.cleanup()

    async def wait_file(self, name: str) -> None:
        async with asyncio.timeout(5):
            while not (self.record.session_dir / name).exists():
                await asyncio.sleep(0.02)

    async def test_cancel_drains_with_ownership_and_reopens_after_exit(self) -> None:
        task = asyncio.create_task(
            self.pool.call_active("test", "test", "test_hang", {"seconds": 0.8}, False)
        )
        await self.wait_file("call-started")
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertTrue(AssetLock.inspect(self.record.database_dir)["locked"])
        with self.assertRaises(SampleBusy):
            await self.pool.call_active("test", "test", "get_metadata", {})
        await asyncio.gather(*self.pool._retiring.values())
        self.assertTrue((self.record.session_dir / "call-finished").exists())
        self.assertTrue((self.record.session_dir / "close-finished").exists())
        self.assertFalse(AssetLock.inspect(self.record.database_dir)["locked"])
        await self.pool.call_active("test", "test", "get_metadata", {})

    async def test_flush_timeout_does_not_kill_or_release_lock(self) -> None:
        worker = self.record.worker
        (self.record.session_dir / "close-delay").write_text("0.8")
        with self.assertRaises(WorkerTimedOut):
            await self.pool.close("test", "test")
        self.assertTrue(AssetLock.inspect(self.record.database_dir)["locked"])
        with self.assertRaisesRegex(WorkerFailed, "FLUSH_IN_PROGRESS"):
            await worker.force_stop("explicit abort")
        await asyncio.gather(*self.pool._retiring.values())
        self.assertTrue((self.record.session_dir / "close-finished").exists())
        self.assertFalse(AssetLock.inspect(self.record.database_dir)["locked"])

    async def test_query_timeout_drains_instead_of_replaying(self) -> None:
        with self.assertRaises(WorkerTimedOut):
            await self.pool.call_active("test", "test", "test_hang", {"seconds": 0.8})
        self.assertTrue(AssetLock.inspect(self.record.database_dir)["locked"])
        await asyncio.gather(*self.pool._retiring.values())
        self.assertTrue((self.record.session_dir / "call-finished").exists())

    async def test_hard_drain_deadline_releases_ownership_after_exit(self) -> None:
        worker = self.record.worker
        worker.settings = replace(worker.settings, drain_timeout=0.1)
        with self.assertRaises(WorkerTimedOut):
            await self.pool.call_active("test", "test", "test_hang", {"seconds": 30}, False)
        await asyncio.gather(*self.pool._retiring.values())
        self.assertFalse(worker.running)
        self.assertFalse(AssetLock.inspect(self.record.database_dir)["locked"])
        self.assertFalse((self.record.session_dir / "call-finished").exists())

    async def test_failed_termination_keeps_lock_until_natural_close(self) -> None:
        worker = self.record.worker
        worker.settings = replace(worker.settings, drain_timeout=0.1)
        attempted = asyncio.Event()

        async def failed_kill(reason: str) -> None:
            attempted.set()
            raise OSError("injected termination failure")

        with patch.object(worker, "force_stop", failed_kill):
            with self.assertRaises(WorkerTimedOut):
                await self.pool.call_active("test", "test", "test_hang", {"seconds": 1.2}, False)
            await asyncio.wait_for(attempted.wait(), 3)
            await asyncio.sleep(0)
            self.assertTrue(worker.running)
            self.assertTrue(AssetLock.inspect(self.record.database_dir)["locked"])
            with self.assertRaises(SampleBusy):
                await self.pool.call_active("test", "test", "get_metadata", {})
            await asyncio.wait_for(asyncio.gather(*self.pool._retiring.values()), 5)
        self.assertFalse(worker.running)
        self.assertTrue((self.record.session_dir / "close-finished").exists())
        self.assertFalse(AssetLock.inspect(self.record.database_dir)["locked"])
