# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Retain original export provenance without hiding maintained proof changes."""

import contextlib
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from export_sparse_proofs import ROOT, SOURCES, check


class SparseProvenanceTests(unittest.TestCase):
    def test_repository_provenance(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            check(ROOT)
        self.assertIn("maintained revisions checked: 1", output.getvalue())

    def test_changed_bodies_and_missing_reason_fail(self):
        with tempfile.TemporaryDirectory(prefix="sparse-provenance-") as directory:
            root = Path(directory)
            (root / "Sparse").mkdir()
            for target, _ in SOURCES.values():
                relative = Path(target.replace(".", "/") + ".lean")
                shutil.copyfile(ROOT / relative, root / relative)
            manifest = root / "Sparse/provenance.json"
            shutil.copyfile(ROOT / "Sparse/provenance.json", manifest)
            for relative in ("Sparse/Queue.lean", "Sparse/ArrayLog.lean"):
                with self.subTest(relative=relative):
                    path = root / relative
                    original = path.read_text(encoding="ascii")
                    path.write_text(
                        original + "-- unrecorded change\n", encoding="ascii"
                    )
                    with self.assertRaisesRegex(ValueError, "exported proof changed"):
                        check(root)
                    path.write_text(original, encoding="ascii")
            records = json.loads(manifest.read_text(encoding="ascii"))
            records[0]["revision"]["reason"] = ""
            manifest.write_text(json.dumps(records), encoding="ascii")
            with self.assertRaisesRegex(ValueError, "invalid maintained revision"):
                check(root)


if __name__ == "__main__":
    unittest.main()
