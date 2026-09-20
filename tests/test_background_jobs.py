from __future__ import annotations

import asyncio
import json
import sys
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from ida_assistant.config import Settings
from ida_assistant.errors import AnalysisPending
from ida_assistant.pool import SessionPool

ROOT = Path(__file__).resolve().parents[1]
FAKE = ROOT / "tests" / "fake_idalib_stdio_mcp.py"


def settings(root: Path, analysis_timeout: float = 0) -> Settings:
    return Settings.from_args(
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
            "--startup-timeout",
            "5",
            "--call-timeout",
            "1",
            "--shutdown-timeout",
            "2",
            "--analysis-timeout",
            str(analysis_timeout),
        ]
    )


class BackgroundJobTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.temp = TemporaryDirectory(prefix="ida-background-test-")
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
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            locked = (
                list((self.root / ".ida").rglob("*.lock")) if (self.root / ".ida").exists() else []
            )
            if not any(self._locked(path) for path in locked):
                break
            await asyncio.sleep(0.05)
        self.temp.cleanup()

    @staticmethod
    def _locked(path: Path) -> bool:
        try:
            with path.open("a+b"):
                return False
        except OSError:
            return True

    def pool(self) -> SessionPool:
        value = SessionPool(settings(self.root))
        self.pools.append(value)
        return value

    async def wait_phase(
        self, pool: SessionPool, session: str, phases: set[str], timeout: float = 8
    ) -> dict[str, object]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            row = pool.analysis_status(session)
            if row["phase"] in phases:
                return row
            await asyncio.sleep(0.05)
        self.fail(f"session {session} did not reach {phases}: {pool.analysis_status(session)}")

    async def test_default_open_is_nonblocking_but_job_requests_full_analysis(self) -> None:
        (self.root / "slow.bin").write_bytes(b"WAIT_FOR_RELEASE")
        pool = self.pool()
        started = time.perf_counter()
        opened = await pool.open("slow.bin", "agent", "connection")
        elapsed = time.perf_counter() - started
        self.assertLess(elapsed, 1)
        self.assertTrue(opened["result"]["non_blocking"])
        job = opened["result"]["job"]
        self.assertTrue(job["complete_analysis"])
        args_path = self.root / ".ida" / "sessions" / "slow" / "bootstrap-args.json"
        deadline = time.monotonic() + 3
        while not args_path.is_file() and time.monotonic() < deadline:
            await asyncio.sleep(0.02)
        args = json.loads(args_path.read_text())
        self.assertTrue(args["bootstrap_wait"])
        self.assertFalse(Path(opened["database"]).exists())

    async def test_query_is_gated_until_atomic_ready(self) -> None:
        (self.root / "gate.bin").write_bytes(b"WAIT_FOR_RELEASE")
        pool = self.pool()
        opened = await pool.open("gate.bin", "agent", "connection")
        with self.assertRaisesRegex(AnalysisPending, "ANALYSIS_PENDING"):
            await pool.call_active("connection", "agent", "get_metadata", {})
        self.assertNotIn("gate", pool._sessions)
        session_dir = self.root / ".ida" / "sessions" / "gate"
        (session_dir / "analysis.release").write_text("1", encoding="ascii")
        ready = await self.wait_phase(pool, "gate", {"ready"})
        self.assertTrue(ready["database_ready"])
        self.assertEqual(Path(opened["database"]).read_bytes(), b"fake-idb")
        metadata = await pool.call_active("connection", "agent", "get_metadata", {})
        self.assertEqual(Path(str(metadata["path"])), self.root / "gate.bin")

    async def test_scheduler_shutdown_does_not_stop_analysis_job(self) -> None:
        (self.root / "detach.bin").write_bytes(b"WAIT_FOR_RELEASE")
        first = self.pool()
        opened = await first.open("detach.bin", "one", "one")
        job_id = opened["result"]["job"]["job_id"]
        await first.shutdown()
        second = self.pool()
        await second.use("two", "two", session="detach")
        observed = second.analysis_status("detach")
        self.assertEqual(observed["job"]["job_id"], job_id)
        self.assertIn(observed["phase"], {"queued", "analyzing", "publishing"})
        (self.root / ".ida" / "sessions" / "detach" / "analysis.release").write_text(
            "1", encoding="ascii"
        )
        await self.wait_phase(second, "detach", {"ready"})
        metadata = await second.call_active("two", "two", "get_metadata", {})
        self.assertEqual(Path(str(metadata["path"])).name, "detach.bin")

    async def test_abort_uses_job_identity_and_retry_gets_new_generation(self) -> None:
        (self.root / "abort.bin").write_bytes(b"WAIT_FOR_RELEASE")
        pool = self.pool()
        opened = await pool.open("abort.bin", "agent", "connection")
        old = opened["result"]["job"]
        mismatch = await pool.abort("connection", job_id="not-the-current-job")
        self.assertEqual(mismatch["reason"], "job_id_mismatch")
        self.assertIn(pool.analysis_status("abort")["phase"], {"queued", "analyzing"})
        aborted = await pool.abort("connection", job_id=old["job_id"])
        self.assertTrue(aborted["aborted"])
        self.assertEqual(pool.analysis_status("abort")["phase"], "aborted")
        (self.root / "abort.bin").write_bytes(b"ready-now")
        retried = await pool.open("abort.bin", "agent", "connection", reset_if_changed=True)
        new = retried["result"]["job"]
        self.assertNotEqual(new["job_id"], old["job_id"])
        self.assertGreater(new["generation"], old["generation"])
        await self.wait_phase(pool, "abort", {"ready"})

    async def test_legacy_managed_database_is_ready_without_reanalysis(self) -> None:
        source = self.root / "legacy.bin"
        source.write_bytes(b"legacy")
        first = self.pool()
        opened = await first.open("legacy.bin", "agent", "connection")
        await self.wait_phase(first, "legacy", {"ready"})
        status_path = self.root / ".ida" / "sessions" / "legacy" / "analysis-job.json"
        status_path.unlink()
        second = self.pool()
        reused = await second.open("legacy.bin", "other", "other")
        self.assertTrue(reused["result"]["legacy_ready"])
        self.assertFalse(reused["result"]["submitted"])
        self.assertTrue(Path(opened["database"]).is_file())


if __name__ == "__main__":
    unittest.main()
