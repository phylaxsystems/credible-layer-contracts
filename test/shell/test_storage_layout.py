#!/usr/bin/env python3

import copy
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

CHECK = Path(__file__).resolve().parents[2] / "shell/check_storage_layout.sh"
BASE_LAYOUT = {
    "storage": [
        {"label": "owner", "slot": "0", "offset": 0, "type": "t_uint256"},
        {"label": "count", "slot": "3", "offset": 0, "type": "t_uint256"},
    ],
    "types": {
        "t_uint256": {
            "encoding": "inplace",
            "label": "uint256",
            "numberOfBytes": "32",
        }
    },
}


class StorageLayoutTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.snapshot = self.root / ".storage-layout"
        self.snapshot.write_text(json.dumps(BASE_LAYOUT))
        self.git("init", "--quiet")
        self.git("add", ".storage-layout")
        self.git(
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "Baseline",
        )
        self.base = self.git("rev-parse", "HEAD").strip()
        binary = self.root / "bin"
        binary.mkdir()
        forge = binary / "forge"
        forge.write_text('#!/bin/sh\ncat "$LAYOUT_FIXTURE"\n')
        forge.chmod(0o755)
        self.environment = {
            **os.environ,
            "PATH": f"{binary}:{os.environ['PATH']}",
            "LAYOUT_FIXTURE": str(self.root / "actual.json"),
        }

    def git(self, *arguments):
        return subprocess.check_output(
            ["git", *arguments],
            cwd=self.root,
            text=True,
            stderr=subprocess.STDOUT,
        )

    def check(self, layout, base=None):
        (self.root / "actual.json").write_text(json.dumps(layout))
        return subprocess.run(
            ["bash", str(CHECK), *([base] if base is not None else [])],
            cwd=self.root,
            env=self.environment,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )

    def test_updated_snapshot_cannot_bless_moved_storage(self):
        changed = copy.deepcopy(BASE_LAYOUT)
        changed["storage"][1]["slot"] = "7"
        self.snapshot.write_text(json.dumps(changed))
        result = self.check(changed, self.base)
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertIn("count", result.stdout)
        self.assertIn("slot 3 to slot 7", result.stdout)

    def test_safe_append_requires_current_snapshot(self):
        changed = copy.deepcopy(BASE_LAYOUT)
        changed["storage"].append(
            {"label": "extra", "slot": "4", "offset": 0, "type": "t_uint256"}
        )
        stale = self.check(changed, self.base)
        self.assertEqual(stale.returncode, 1, stale.stdout)
        self.snapshot.write_text(json.dumps(changed))
        current = self.check(changed, self.base)
        self.assertEqual(current.returncode, 0, current.stdout)

    def test_baseline_errors_do_not_fall_back_to_candidate(self):
        self.git("rm", "--quiet", ".storage-layout")
        self.git(
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "No baseline snapshot",
        )
        missing = self.git("rev-parse", "HEAD").strip()
        self.snapshot.write_text(json.dumps(BASE_LAYOUT))
        for base in ("", "not-a-revision", missing):
            with self.subTest(base=base):
                result = self.check(BASE_LAYOUT, base)
                self.assertEqual(result.returncode, 3, result.stdout)

    def test_unchanged_and_local_snapshot_checks(self):
        for base in (None, self.base):
            with self.subTest(base=base):
                result = self.check(BASE_LAYOUT, base)
                self.assertEqual(result.returncode, 0, result.stdout)


if __name__ == "__main__":
    unittest.main()
