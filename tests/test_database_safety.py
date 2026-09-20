from __future__ import annotations

import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

from ida_assistant.database_safety import atomic_save, quarantine_sidecars, verify_fingerprint
from ida_assistant.fingerprint import quick_fingerprint
from ida_assistant.ida_integrity import read_loaded_bytes


class DatabaseSafetyTests(unittest.TestCase):
    def test_failed_save_and_failed_replace_preserve_original(self) -> None:
        with TemporaryDirectory() as folder:
            database = Path(folder) / "sample.i64"
            database.write_bytes(b"original")

            def save(path: str) -> bool:
                Path(path).write_bytes(b"candidate")
                return True

            with self.assertRaisesRegex(RuntimeError, "DATABASE_SAVE_FAILED"):
                atomic_save(database, lambda _: False, lambda: self.fail("must not close"))
            self.assertEqual(database.read_bytes(), b"original")
            with (
                patch("ida_assistant.database_safety.os.replace", side_effect=OSError("locked")),
                self.assertRaises(OSError),
            ):
                atomic_save(database, save, lambda: None)
            self.assertEqual(database.read_bytes(), b"original")
            self.assertEqual(len(list(Path(folder).glob("*.save-*.i64"))), 1)
            atomic_save(database, save, lambda: None)
            self.assertEqual(database.read_bytes(), b"candidate")

    def test_sidecars_are_preserved_and_fingerprint_detects_change(self) -> None:
        with TemporaryDirectory() as folder:
            database = Path(folder) / "sample.i64"
            database.write_bytes(b"original")
            expected = quick_fingerprint(database)
            sidecar = database.with_suffix(".id0")
            sidecar.write_bytes(b"recovery")
            moved = quarantine_sidecars(database)
            self.assertFalse(sidecar.exists())
            self.assertEqual(Path(moved[0]).read_bytes(), b"recovery")
            verify_fingerprint(database, expected)
            database.write_bytes(b"modified")
            with self.assertRaisesRegex(RuntimeError, "DATABASE_CHANGED"):
                verify_fingerprint(database, expected)

    def test_real_ff_is_allowed_but_hole_is_rejected(self) -> None:
        api = SimpleNamespace(
            is_loaded=lambda ea: ea != 11, get_bytes=lambda ea, size: b"\xff" * size
        )
        with patch.dict(sys.modules, {"ida_bytes": api}):
            self.assertEqual(read_loaded_bytes(10, 1), "0xff")
            with self.assertRaisesRegex(ValueError, "UNLOADED_RANGE"):
                read_loaded_bytes(10, 2)
