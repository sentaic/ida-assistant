from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from ida_assistant.analysis_job import job_path, read_job, write_job
from ida_assistant.state_paths import load_state_path, store_state_path


class StatePathTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = TemporaryDirectory(prefix="ida-state-paths-")
        self.root = Path(self.temp.name)
        self.state_dir = self.root / "project" / ".ida"
        self.session_dir = self.state_dir / "sessions" / "sample"
        self.database_dir = self.state_dir / "databases" / "sample"
        self.database = self.database_dir / "sample.i64"
        self.staging = self.database_dir / "sample.job.staging.i64"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_owned_state_paths_are_stored_relative(self) -> None:
        asset = (self.root / "assets" / "sample.bin").resolve()
        state = {
            "version": 2,
            "session": "sample",
            "source": str(asset),
            "database": str(self.database.resolve()),
            "staging": str(self.staging.resolve()),
        }

        write_job(self.session_dir, state)

        stored = json.loads(job_path(self.session_dir).read_text(encoding="utf-8"))
        self.assertEqual(stored["source"], str(asset))
        self.assertEqual(stored["database"], "databases/sample/sample.i64")
        self.assertEqual(stored["staging"], "databases/sample/sample.job.staging.i64")
        self.assertEqual(state["database"], str(self.database.resolve()))
        self.assertEqual(read_job(self.session_dir)["database"], str(self.database.resolve()))

    def test_external_path_remains_absolute(self) -> None:
        external = (self.root / "assets" / "external.i64").resolve()
        self.assertEqual(store_state_path(external, self.state_dir), str(external))

    def test_legacy_absolute_path_relocates_with_state_directory(self) -> None:
        old = (self.root / "old" / ".ida" / "databases" / "sample" / "sample.i64").resolve()
        self.database_dir.mkdir(parents=True)
        self.database.write_bytes(b"idb")

        loaded = load_state_path(
            str(old),
            self.state_dir,
            legacy_directory=self.database_dir,
        )

        self.assertEqual(loaded, self.database.resolve())

    def test_existing_legacy_absolute_path_is_preserved(self) -> None:
        old = (self.root / "old" / ".ida" / "databases" / "sample" / "sample.i64").resolve()
        old.parent.mkdir(parents=True)
        old.write_bytes(b"idb")

        loaded = load_state_path(
            str(old),
            self.state_dir,
            legacy_directory=self.database_dir,
        )

        self.assertEqual(loaded, old)


if __name__ == "__main__":
    unittest.main()
