from __future__ import annotations

import asyncio
import json
import os
import sys
import time
import unittest
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory

from ida_assistant.config import Settings
from ida_assistant.errors import SourceChanged, ToolFailed, WorkerFailed, WorkerTimedOut
from ida_assistant.pool import SessionPool

ROOT = Path(__file__).resolve().parents[1]
FAKE = ROOT / "tests" / "fake_idalib_stdio_mcp.py"


def make_settings(root: Path, **changes: object) -> Settings:
    base = Settings.from_args(
        [
            "--project-root",
            str(root),
            "--worker-command",
            sys.executable,
            "--worker-script",
            str(FAKE),
            "--max-sessions",
            "3",
            "--max-workers",
            "2",
            "--worker-idle-seconds",
            "1",
            "--session-idle-seconds",
            "2",
            "--startup-timeout",
            "5",
            "--call-timeout",
            "2",
            "--shutdown-timeout",
            "2",
        ]
    )
    return replace(base, **changes)


class PoolTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.temp = TemporaryDirectory(prefix="ida-pool-test-")
        self.root = Path(self.temp.name)
        self.pools: list[SessionPool] = []

    async def asyncTearDown(self) -> None:
        for pool in self.pools:
            for name, row in pool.status()["sessions"].items():
                job = row.get("analysis_job") or {}
                if row["phase"] in {"launching", "queued", "analyzing", "publishing"}:
                    try:
                        await pool.abort("cleanup", name, job.get("job_id"))
                    except (OSError, RuntimeError):
                        pass
            await pool.shutdown()
        await asyncio.sleep(0.05)
        self.temp.cleanup()

    def pool(self, **changes: object) -> SessionPool:
        value = SessionPool(make_settings(self.root, **changes))
        self.pools.append(value)
        return value

    async def wait_ready(self, pool: SessionPool, session: str, timeout: float = 8) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if pool.analysis_status(session)["phase"] == "ready":
                return
            await asyncio.sleep(0.05)
        self.fail(str(pool.analysis_status(session)))

    async def open_ready(
        self, pool: SessionPool, path: str, owner: str = "agent", binding: str = "connection"
    ) -> dict[str, object]:
        opened = await pool.open(path, owner, binding)
        await self.wait_ready(pool, str(opened["session"]))
        return opened

    async def test_existing_path_is_automatically_reused(self) -> None:
        (self.root / "shared.bin").write_bytes(b"x")
        pool = self.pool()
        first = await pool.open("shared.bin", "codex", "codex", "friendly")
        manifest_path = self.root / ".ida" / "databases" / "friendly" / "database.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        second = await pool.open("shared.bin", "pi", "pi", "ignored-name")
        self.assertEqual(manifest["version"], 2)
        self.assertEqual(manifest["source"], str((self.root / "shared.bin").resolve()))
        self.assertEqual(manifest["database"], "databases/friendly/friendly.i64")
        self.assertEqual(first["session"], "friendly")
        self.assertEqual(second["session"], "friendly")
        self.assertTrue(second["reused"])
        self.assertTrue(second["requested_session_ignored"])
        self.assertEqual(first["result"]["job"]["job_id"], second["result"]["job"]["job_id"])

    async def test_source_update_requires_explicit_reset(self) -> None:
        sample = self.root / "changed.bin"
        sample.write_bytes(b"before")
        pool = self.pool()
        await self.open_ready(pool, "changed.bin")
        sample.write_bytes(b"after")
        with self.assertRaises(SourceChanged):
            await pool.open("changed.bin", "agent", "connection")
        reset = await pool.open("changed.bin", "agent", "connection", reset_if_changed=True)
        self.assertEqual(reset["result"]["job"]["generation"], 2)
        await self.wait_ready(pool, "changed")

    async def test_session_rename_after_analysis_preserves_alias_hint(self) -> None:
        (self.root / "rename.bin").write_bytes(b"x")
        pool = self.pool()
        await pool.open("rename.bin", "agent", "connection", "old")
        await self.wait_ready(pool, "old")
        renamed = await pool.rename("old", "new", "agent")
        self.assertEqual(renamed["session"], "new")
        self.assertEqual(pool.current("connection")["session"], "new")
        with self.assertRaisesRegex(Exception, "SESSION_RENAMED"):
            await pool.use("agent", "other", session="old")

    async def test_crash_recovery_and_idle_reaper(self) -> None:
        (self.root / "recover.bin").write_bytes(b"x")
        pool = self.pool()
        await self.open_ready(pool, "recover.bin")
        first = await pool.call_active("connection", "agent", "get_metadata", {})
        with self.assertRaises(WorkerFailed):
            await pool.call_active("connection", "agent", "test_crash", {}, False)
        second = await pool.call_active("connection", "agent", "get_metadata", {})
        self.assertNotEqual(first["pid"], second["pid"])
        record = pool._sessions["recover"]
        record.last_used = time.time() - 1.5
        self.assertEqual(await pool.reap(), {"workers": ["recover"], "sessions": []})

    async def test_hung_worker_drains_without_harming_other_session(self) -> None:
        for name in ("hang", "healthy"):
            (self.root / f"{name}.bin").write_bytes(name.encode())
        pool = self.pool(call_timeout=1)
        await asyncio.gather(
            self.open_ready(pool, "hang.bin", "a", "hang"),
            self.open_ready(pool, "healthy.bin", "b", "healthy"),
        )
        with self.assertRaises(WorkerTimedOut):
            await pool.call_active("hang", "a", "test_hang", {"seconds": 10}, False)
        meta = await pool.call_active("healthy", "b", "get_metadata", {})
        self.assertEqual(Path(str(meta["path"])).name, "healthy.bin")

    async def test_tool_error_does_not_restart_healthy_worker(self) -> None:
        (self.root / "tool-error.bin").write_bytes(b"x")
        pool = self.pool()
        await self.open_ready(pool, "tool-error.bin")
        before = await pool.call_active("connection", "agent", "get_metadata", {})
        with self.assertRaisesRegex(ToolFailed, "deliberate tool error"):
            await pool.call_active("connection", "agent", "test_error", {}, False)
        after = await pool.call_active("connection", "agent", "get_metadata", {})
        self.assertEqual(before["pid"], after["pid"])

    async def test_changed_published_idb_is_rejected_before_open(self) -> None:
        (self.root / "changed.bin").write_bytes(b"sample")
        pool = self.pool()
        await self.open_ready(pool, "changed.bin")
        database = pool._analyses["changed"].database
        database.write_bytes(b"unexpected rewrite")
        with self.assertRaisesRegex(RuntimeError, "DATABASE_CHANGED"):
            await pool.call_active("connection", "agent", "get_metadata", {})

    async def test_recovery_cleanup_waits_for_close_and_reaps_closed_sessions(self) -> None:
        (self.root / "cleanup.bin").write_bytes(b"sample")
        pool = self.pool()
        await self.open_ready(pool, "cleanup.bin")
        await pool.call_active("connection", "agent", "get_metadata", {})
        database = pool._analyses["cleanup"].database
        candidate = database.with_name(f"cleanup.save-{'a' * 32}.i64")
        candidate.write_bytes(b"failed-save")
        orphan = database.parent / f"orphan-{'b' * 32}"
        orphan.mkdir()
        (orphan / "cleanup.id0").write_bytes(b"orphan")
        pool._next_recovery_cleanup = 0
        await pool.reap()
        self.assertTrue(candidate.exists())
        self.assertTrue(orphan.exists())
        await pool.close("connection", "agent", save=True)
        self.assertFalse(candidate.exists())
        self.assertFalse(orphan.exists())
        candidate.write_bytes(b"expired-save")
        os.utime(candidate, (time.time() - 90000, time.time() - 90000))
        await pool.reap()
        self.assertTrue(candidate.exists())
        pool._next_recovery_cleanup = 0
        await pool.reap()
        self.assertFalse(candidate.exists())
        self.assertEqual(database.read_bytes(), b"fake-idb")

    async def test_orphan_sidecars_are_quarantined_and_bad_probe_is_rejected(self) -> None:
        (self.root / "probe.bin").write_bytes(b"sample")
        pool = self.pool()
        await self.open_ready(pool, "probe.bin")
        database = pool._analyses["probe"].database
        sidecar = database.with_suffix(".id0")
        sidecar.write_bytes(b"orphan recovery")
        await pool.call_active("connection", "agent", "get_metadata", {})
        self.assertFalse(sidecar.exists())
        quarantined = list(database.parent.glob("orphan-*/*.id0"))
        self.assertEqual(quarantined[0].read_bytes(), b"orphan recovery")
        await pool.close("connection", "agent")
        (pool.sessions_dir / "probe" / "bad-integrity").touch()
        with self.assertRaisesRegex(WorkerFailed, "DATABASE_INTEGRITY_FAILED"):
            await pool.call("probe", "agent", "get_metadata", {}, False)
        self.assertIsNone(pool._sessions["probe"].worker)

    async def test_existing_external_idb_is_opened_lazily(self) -> None:
        database = self.root / "existing.i64"
        database.write_text("EXISTING\n", encoding="utf-8")
        pool = self.pool()
        opened = await pool.open("existing.i64", "agent", "connection")
        manifest_path = self.root / ".ida" / "databases" / "existing" / "database.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertTrue(opened["result"]["legacy_ready"])
        self.assertEqual(manifest["source"], str(database.resolve()))
        self.assertEqual(manifest["database"], str(database.resolve()))
        self.assertNotIn("existing", pool._sessions)
        metadata = await pool.call_active("connection", "agent", "get_metadata", {})
        self.assertEqual(Path(str(metadata["path"])), database)

    async def test_relative_managed_state_survives_project_move(self) -> None:
        source = self.root / "assets" / "movable.bin"
        source.parent.mkdir()
        source.write_bytes(b"movable")
        old_root = self.root / "old-project"
        new_root = self.root / "new-project"
        old_root.mkdir()
        new_root.mkdir()
        old_pool = SessionPool(make_settings(old_root))
        self.pools.append(old_pool)

        await old_pool.open(str(source), "agent", "connection", "movable")
        await self.wait_ready(old_pool, "movable")
        manifest_path = old_root / ".ida" / "databases" / "movable" / "database.json"
        job_state_path = old_root / ".ida" / "sessions" / "movable" / "analysis-job.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        job_state = json.loads(job_state_path.read_text(encoding="utf-8"))
        self.assertEqual(manifest["database"], "databases/movable/movable.i64")
        self.assertEqual(job_state["database"], "databases/movable/movable.i64")
        self.assertTrue(job_state["staging"].startswith("databases/movable/"))
        self.assertEqual(manifest["source"], str(source.resolve()))

        await old_pool.shutdown()
        self.pools.remove(old_pool)
        (old_root / ".ida").rename(new_root / ".ida")
        new_pool = SessionPool(make_settings(new_root))
        self.pools.append(new_pool)

        row = new_pool.status()["sessions"]["movable"]
        self.assertEqual(
            Path(row["database"]),
            (new_root / ".ida" / "databases" / "movable" / "movable.i64").resolve(),
        )
        self.assertEqual(Path(row["source"]), source.resolve())
        self.assertEqual(row["phase"], "ready")

    async def test_legacy_absolute_managed_database_relocates_when_old_path_is_gone(self) -> None:
        source = self.root / "assets" / "legacy.bin"
        source.parent.mkdir()
        source.write_bytes(b"legacy")
        old_root = self.root / "legacy-old"
        new_root = self.root / "legacy-new"
        database_dir = old_root / ".ida" / "databases" / "legacy"
        database_dir.mkdir(parents=True)
        database = database_dir / "legacy.i64"
        database.write_bytes(b"legacy-idb")
        manifest_path = database_dir / "database.json"
        manifest_path.write_text(
            json.dumps(
                {
                    "version": 1,
                    "session": "legacy",
                    "source": str(source.resolve()),
                    "fingerprint": {},
                    "database": str(database.resolve()),
                    "external_database": False,
                }
            ),
            encoding="utf-8",
        )
        new_root.mkdir()
        (old_root / ".ida").rename(new_root / ".ida")
        pool = SessionPool(make_settings(new_root))
        self.pools.append(pool)

        row = pool.status()["sessions"]["legacy"]
        self.assertEqual(
            Path(row["database"]),
            (new_root / ".ida" / "databases" / "legacy" / "legacy.i64").resolve(),
        )
        self.assertEqual(row["phase"], "ready")

    async def test_flow_and_python_tools_reach_active_worker(self) -> None:
        (self.root / "surface.bin").write_bytes(b"surface")
        pool = self.pool()
        await self.open_ready(pool, "surface.bin")
        blocks = await pool.call_active(
            "connection", "agent", "ida_basic_blocks", {"address": "0x140001000"}
        )
        self.assertEqual(blocks["blocks"][0]["start"], "0x140001000")
        executed = await pool.call_active(
            "connection", "agent", "ida_python_exec", {"code": "result = 6 * 7"}, False
        )
        self.assertEqual(executed["result"], 42)


if __name__ == "__main__":
    unittest.main()
