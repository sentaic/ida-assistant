"""Optional smoke test: imports IDA 9.1 idalib but does not open or modify a database."""

from __future__ import annotations

import asyncio
import os
import sys
import time
import unittest
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory

from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from ida_assistant.config import Settings
from ida_assistant.errors import ToolFailed, WorkerFailed
from ida_assistant.fingerprint import quick_fingerprint
from ida_assistant.worker_client import WorkerActor

# These smoke tests need a real IDA 9.1 installation plus the `ida-pro-mcp`
# package that provides `ida_pro_mcp`. Override the defaults with these
# environment variables instead of editing the file:
#   IDA_ASSISTANT_IDA_DIR        IDA installation directory
#   IDA_ASSISTANT_IDA_MCP_PATH   site-packages directory of the ida-pro-mcp tool
IDA_DIR = os.environ.get("IDA_ASSISTANT_IDA_DIR", r"C:\Program Files\IDA Professional 9.1")
IDA_MCP_PATH = os.environ.get(
    "IDA_ASSISTANT_IDA_MCP_PATH",
    os.path.join(
        os.environ.get("APPDATA", os.path.expanduser("~")),
        "uv",
        "tools",
        "ida-pro-mcp",
        "Lib",
        "site-packages",
    ),
)


class RealWorkerStartupTest(unittest.IsolatedAsyncioTestCase):
    async def test_pythonw_stdio_scheduler_can_bootstrap_a_database(self) -> None:
        sample = Path(r"C:\Windows\System32\where.exe")
        pythonw = Path(sys.executable).with_name("pythonw.exe")
        scheduler = Path(__file__).resolve().parents[1] / "scripts" / "ida_lazy_mcp.py"
        if not sample.is_file() or not pythonw.is_file():
            self.skipTest("Windows sample or pythonw.exe is unavailable")
        with TemporaryDirectory(prefix="ida-real-pythonw-") as value:
            params = StdioServerParameters(
                command=str(pythonw),
                args=[
                    str(scheduler),
                    "--project-root",
                    value,
                    "--worker-command",
                    sys.executable,
                    "--ida-dir",
                    IDA_DIR,
                    "--pythonpath",
                    IDA_MCP_PATH,
                    "--startup-timeout",
                    "120",
                    "--call-timeout",
                    "30",
                ],
                cwd=value,
            )
            async with (
                stdio_client(params) as (read, write),
                ClientSession(
                    read,
                    write,
                    read_timeout_seconds=timedelta(seconds=30),
                ) as client,
            ):
                await client.initialize()
                started = time.perf_counter()
                opened = await client.call_tool("open", {"path": str(sample)})
                self.assertFalse(opened.isError)
                self.assertLess(time.perf_counter() - started, 10)
                deadline = time.monotonic() + 180
                while True:
                    status = await client.call_tool("analysis_status", {})
                    self.assertFalse(status.isError)
                    structured = status.structuredContent or {}
                    phase = (structured.get("analysis") or {}).get("phase")
                    if phase == "ready":
                        break
                    if phase in {"failed", "aborted", "interrupted"}:
                        self.fail(str(structured))
                    if time.monotonic() >= deadline:
                        self.fail(f"analysis did not finish: {structured}")
                    await asyncio.sleep(0.2)
                metadata = await client.call_tool("metadata", {})
                self.assertFalse(metadata.isError, metadata)
                closed = await client.call_tool("close", {})
                self.assertFalse(closed.isError)
                selected = await client.call_tool("use", {"path": str(sample)})
                self.assertFalse(selected.isError, selected)
                enabled = await client.call_tool("set_capabilities", {"python": True})
                self.assertFalse(enabled.isError, enabled)
                executed = await client.call_tool("python", {"code": "result = 42"})
                self.assertFalse(executed.isError, executed)
                saved = await client.call_tool("close", {})
                self.assertFalse(saved.isError, saved)
                selected = await client.call_tool("use", {"path": str(sample)})
                self.assertFalse(selected.isError, selected)
                reopened = await client.call_tool("metadata", {})
                self.assertFalse(reopened.isError, reopened)
                self.assertFalse((await client.call_tool("close", {})).isError)

    async def test_real_idalib_worker_initializes(self) -> None:
        with TemporaryDirectory(prefix="ida-real-startup-") as value:
            root = Path(value)
            settings = Settings.from_args(
                [
                    "--project-root",
                    str(root),
                    "--worker-command",
                    sys.executable,
                    "--ida-dir",
                    IDA_DIR,
                    "--pythonpath",
                    IDA_MCP_PATH,
                    "--startup-timeout",
                    "120",
                    "--call-timeout",
                    "30",
                ]
            )
            actor = WorkerActor(
                settings,
                "real-startup",
                root / "session",
                root / "database",
                asyncio.Semaphore(1),
            )
            try:
                await actor.start()
                status = await actor.call("ida_status", {})
                self.assertEqual(status["session_id"], "real-startup")
                self.assertFalse(status["has_database"])
            finally:
                await actor.stop(graceful=True)

    async def test_raw_binary_is_read_directly_and_idb_is_project_local(self) -> None:
        sample = Path(r"C:\Windows\System32\where.exe")
        if not sample.is_file():
            self.skipTest("Windows where.exe is unavailable")
        with TemporaryDirectory(prefix="ida-real-open-") as value:
            root = Path(value)
            settings = Settings.from_args(
                [
                    "--project-root",
                    str(root),
                    "--worker-command",
                    sys.executable,
                    "--ida-dir",
                    IDA_DIR,
                    "--pythonpath",
                    IDA_MCP_PATH,
                    "--startup-timeout",
                    "120",
                    "--call-timeout",
                    "120",
                ]
            )
            database_dir = root / ".ida" / "databases" / "real-open"
            database_path = database_dir / "real-open.i64"
            actor = WorkerActor(
                settings,
                "real-open",
                root / ".ida" / "sessions" / "real-open",
                database_dir,
                asyncio.Semaphore(1),
            )
            try:
                await actor.bootstrap_database(sample, database_path, False)
                self.assertTrue(database_path.exists())
                published = quick_fingerprint(database_path)
                await actor.start()
                try:
                    opened = await actor.call(
                        "ida_open_file",
                        {
                            "path": str(sample),
                            "database_path": str(database_path),
                            "create_database": True,
                            "wait_for_analysis": False,
                            "save_previous": True,
                        },
                        timeout=120,
                    )
                except WorkerFailed as exc:
                    stderr = actor.stderr_path.read_text(encoding="utf-8", errors="replace")
                    self.fail(f"{exc}\nworker stderr:\n{stderr}")
                self.assertEqual(opened["source"].casefold(), str(sample).casefold())
                self.assertEqual(Path(opened["database"]), database_path)
                metadata = await actor.call("get_metadata", {}, timeout=30)
                self.assertTrue(metadata["module"])
                analysis_status = await actor.call("ida_analysis_status", {}, timeout=30)
                self.assertIn("done", analysis_status)
                self.assertIn("state_name", analysis_status)
                catalog = await actor.call(
                    "ida_action_catalog",
                    {"plane": "read", "filter": "list_globals"},
                    timeout=30,
                )
                self.assertEqual(catalog[0]["action"], "list_globals")
                self.assertIn("arguments_schema", catalog[0])
                functions = await actor.call(
                    "list_functions", {"offset": 0, "count": 1}, timeout=30
                )
                self.assertTrue(functions["data"])
                address = functions["data"][0]["address"]
                name = functions["data"][0]["name"]
                disassembly = await actor.call(
                    "disassemble_function", {"start_address": address}, timeout=30
                )
                self.assertIsInstance(disassembly, dict)
                filtered = await actor.call(
                    "ida_functions_filter",
                    {"filter": name, "offset": 0, "count": 10},
                    timeout=30,
                )
                self.assertTrue(filtered["data"])
                blocks = await actor.call("ida_basic_blocks", {"address": address}, timeout=30)
                self.assertTrue(blocks["blocks"])
                xrefs = await actor.call("ida_xrefs_from", {"address": address}, timeout=30)
                self.assertIsInstance(xrefs, list)
                segments = await actor.call("ida_segments", {}, timeout=30)
                self.assertTrue(segments)
                entries = await actor.call("ida_entry_points", {}, timeout=30)
                self.assertIsInstance(entries, list)
                exports = await actor.call("ida_exports", {}, timeout=30)
                self.assertIsInstance(exports, list)
                mz = await actor.call(
                    "ida_search",
                    {
                        "query": "4D 5A",
                        "kind": "bytes",
                        "start": metadata["base"],
                        "max_results": 1,
                    },
                    timeout=30,
                )
                self.assertTrue(mz)
                text_match = await actor.call(
                    "ida_search",
                    {
                        "query": "KERNEL32.dll",
                        "kind": "text",
                        "encoding": "UTF-8",
                        "max_results": 1,
                    },
                    timeout=30,
                )
                self.assertTrue(text_match)
                wide_match = await actor.call(
                    "ida_search",
                    {
                        "query": "PATHEXT",
                        "kind": "text",
                        "encoding": "UTF-16LE",
                        "max_results": 1,
                    },
                    timeout=30,
                )
                self.assertTrue(wide_match)
                integrity = await actor.call("ida_integrity_probe", {})
                self.assertTrue(integrity["ok"], integrity)
                self.assertGreater(integrity["samples"], 0)
                self.assertFalse((await actor.call("ida_status", {}))["dirty"])
                with self.assertRaisesRegex(ToolFailed, "UNLOADED_RANGE"):
                    await actor.call("read_memory_bytes", {"memory_address": "0x1", "size": 16})
                closed = await actor.call("ida_close_file", {})
                self.assertFalse(closed["save"])
                self.assertEqual(quick_fingerprint(database_path), published)
                await actor.call(
                    "ida_open_file", {"path": str(sample), "database_path": str(database_path)}
                )
                executed = await actor.call(
                    "ida_python_exec",
                    {
                        "code": "result = arguments['prefix'] + idaapi.get_root_filename()",
                        "arguments": {"prefix": "module:"},
                    },
                    timeout=30,
                )
                self.assertEqual(executed["result"], f"module:{metadata['module']}")
                self.assertTrue((await actor.call("ida_status", {}))["dirty"])
                closed = await actor.call("ida_close_file", {}, timeout=120)
                self.assertTrue(closed["save"])
                self.assertTrue(database_path.is_file())
                await actor.call(
                    "ida_open_file", {"path": str(sample), "database_path": str(database_path)}
                )
                self.assertTrue((await actor.call("ida_integrity_probe", {}))["ok"])
                self.assertFalse((await actor.call("ida_close_file", {}))["save"])
                await actor.call(
                    "ida_open_file", {"path": str(sample), "database_path": str(database_path)}
                )
                await actor.call(
                    "rename_function",
                    {"function_address": address, "new_name": "ida_safety_regression"},
                )
                self.assertTrue((await actor.call("ida_status", {}))["dirty"])
                self.assertTrue((await actor.call("ida_close_file", {}))["save"])
                await actor.call(
                    "ida_open_file", {"path": str(sample), "database_path": str(database_path)}
                )
                renamed = await actor.call("get_function_by_address", {"address": address})
                self.assertEqual(renamed["name"], "ida_safety_regression")
                with self.assertRaises(ToolFailed):
                    await actor.call("ida_python_exec", {"code": "raise RuntimeError('partial')"})
                self.assertTrue((await actor.call("ida_status", {}))["dirty"])
                self.assertFalse((await actor.call("ida_close_file", {"save": False}))["save"])
                self.assertFalse((database_dir / sample.name).exists())
            finally:
                await actor.stop(graceful=False)


if __name__ == "__main__":
    unittest.main()
