from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from ida_assistant.actions import DEBUG_ACTIONS, EDIT_ACTIONS, READ_ACTIONS
from ida_assistant.capabilities import Capabilities, CapabilityRegistry
from ida_assistant.config import Settings
from ida_assistant.server import _load_python_source, create_server


class CapabilityTests(unittest.TestCase):
    def test_action_planes_are_explicit_and_disjoint(self) -> None:
        self.assertFalse(READ_ACTIONS & EDIT_ACTIONS)
        self.assertFalse(READ_ACTIONS & DEBUG_ACTIONS)
        self.assertFalse(EDIT_ACTIONS & DEBUG_ACTIONS)
        self.assertIn("list_globals", READ_ACTIONS)
        self.assertIn("rename_function", EDIT_ACTIONS)
        self.assertIn("dbg_start_process", DEBUG_ACTIONS)

    def test_connections_are_safe_and_isolated_by_default(self) -> None:
        registry = CapabilityRegistry(default_unsafe=False)
        self.assertEqual(registry.get("agent-a"), Capabilities())
        enabled = registry.set("agent-a", edit=True, python=True)
        self.assertEqual(enabled, Capabilities(edit=True, python=True))
        self.assertEqual(registry.get("agent-b"), Capabilities())
        self.assertEqual(registry.set("agent-a", edit=False, python=False), Capabilities())

    def test_cli_unsafe_changes_only_the_default(self) -> None:
        registry = CapabilityRegistry(default_unsafe=True)
        self.assertEqual(registry.get("agent"), Capabilities(True, True, True))
        self.assertEqual(registry.set("agent", python=False), Capabilities(True, False, True))

    def test_registry_is_bounded(self) -> None:
        registry = CapabilityRegistry(default_unsafe=False, max_entries=2)
        registry.set("a", edit=True)
        registry.set("b", edit=True)
        registry.set("c", edit=True)
        self.assertEqual(registry.get("a"), Capabilities())
        self.assertEqual(registry.get("b"), Capabilities(edit=True))
        self.assertEqual(registry.get("c"), Capabilities(edit=True))

    def test_project_relative_python_script_is_loaded_without_copying(self) -> None:
        with TemporaryDirectory(prefix="ida-script-test-") as value:
            root = Path(value)
            script = root / "analysis.py"
            script.write_text("result = arguments['value']\n", encoding="utf-8")
            settings = Settings.from_args(["--project-root", str(root)])
            code, filename = _load_python_source(settings, "analysis.py")
            self.assertEqual(code, "result = arguments['value']\n")
            self.assertEqual(Path(filename), script)


class CapabilitySchemaTests(unittest.IsolatedAsyncioTestCase):
    async def test_python_capability_replaces_per_call_confirmation(self) -> None:
        with TemporaryDirectory(prefix="ida-schema-test-") as value:
            settings = Settings.from_args(["--project-root", value])
            server, pool = create_server(settings)
            try:
                tools = {tool.name: tool for tool in await server.list_tools()}
                self.assertEqual(
                    set(tools),
                    {
                        "health",
                        "set_capabilities",
                        "sessions",
                        "logs",
                        "open",
                        "use",
                        "current",
                        "rename_session",
                        "close",
                        "abort",
                        "metadata",
                        "wait_for_analysis",
                        "analysis_status",
                        "actions",
                        "functions",
                        "function",
                        "imports",
                        "strings",
                        "decompile",
                        "disassemble",
                        "xrefs",
                        "basic_blocks",
                        "xrefs_from",
                        "inspect",
                        "search",
                        "bytes",
                        "query",
                        "edit",
                        "python",
                    },
                )
                properties = tools["python"].inputSchema["properties"]
                self.assertNotIn("confirm", properties)
                self.assertIn("code", properties)
                self.assertIn("script", properties)
            finally:
                await pool.shutdown()


if __name__ == "__main__":
    unittest.main()
