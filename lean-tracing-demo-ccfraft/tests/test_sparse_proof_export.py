# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import contextlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import export_sparse_proofs as exporter


class SparseProofExportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="sparse-proof-export-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.destination = self.root / "destination"
        self.source.mkdir()
        self.body = (
            "namespace CCFRaft.SparseQueuePrototype\n"
            "theorem identity (n : Nat) : n = n := rfl\n"
            "end CCFRaft.SparseQueuePrototype\n"
        )
        self.original = (
            self.body
            + "#print axioms CCFRaft.SparseQueuePrototype.identity\n"
            + "\n/-!\nCommand log, historical\n-/\n"
        )
        (self.source / "SparseQueuePrototype.lean").write_text(
            self.original, encoding="ascii"
        )
        self.enterContext(
            patch.object(
                exporter,
                "SOURCES",
                {
                    "SparseQueuePrototype": (
                        "Sparse.Queue",
                        exporter.sha256(self.original.encode("ascii")),
                    )
                },
            )
        )
        self.enterContext(contextlib.redirect_stdout(io.StringIO()))

    def test_export_is_reversible_and_idempotent(self) -> None:
        exporter.export(self.source, self.destination)
        exported = self.destination / "Sparse" / "Queue.lean"
        expected = self.body.replace("SparseQueuePrototype", "Sparse.Queue")
        self.assertEqual(exported.read_text(encoding="ascii"), expected)
        exporter.export(self.source, self.destination)
        exporter.check(self.destination)

    def test_changed_source_does_not_create_destination(self) -> None:
        (self.source / "SparseQueuePrototype.lean").write_text(
            self.original + "-- changed\n", encoding="ascii"
        )
        with self.assertRaisesRegex(ValueError, "reviewed source changed"):
            exporter.export(self.source, self.destination)
        self.assertFalse(self.destination.exists())

    def test_changed_destination_is_detected_and_preserved(self) -> None:
        exporter.export(self.source, self.destination)
        exported = self.destination / "Sparse" / "Queue.lean"
        changed = exported.read_text(encoding="ascii") + "-- user change\n"
        exported.write_text(changed, encoding="ascii")
        with self.assertRaisesRegex(ValueError, "exported proof changed"):
            exporter.check(self.destination)
        with self.assertRaisesRegex(ValueError, "refusing to overwrite"):
            exporter.export(self.source, self.destination)
        self.assertEqual(exported.read_text(encoding="ascii"), changed)

    def test_rename_preserves_longer_identifiers(self) -> None:
        self.assertEqual(
            exporter.rename(
                "SparseQueuePrototype SparseQueuePrototypeHelper",
                {"SparseQueuePrototype": "Sparse.Queue"},
            ),
            "Sparse.Queue SparseQueuePrototypeHelper",
        )

    def test_extending_export_preserves_previous_records(self) -> None:
        exporter.export(self.source, self.destination)
        first = (self.destination / "Sparse" / "Queue.lean").read_bytes()
        new_source = b"import SparseQueuePrototype\n"
        (self.source / "SparseNextPrototype.lean").write_bytes(new_source)
        with patch.dict(
            exporter.SOURCES,
            {"SparseNextPrototype": ("Sparse.Next", exporter.sha256(new_source))},
        ):
            exporter.export(self.source, self.destination)
            exporter.check(self.destination)
            self.assertEqual(
                (self.destination / "Sparse" / "Next.lean").read_text(encoding="ascii"),
                "import Sparse.Queue\n",
            )
        self.assertEqual((self.destination / "Sparse" / "Queue.lean").read_bytes(), first)

    def test_invalid_later_source_does_not_partially_extend_export(self) -> None:
        exporter.export(self.source, self.destination)
        manifest = self.destination / "Sparse" / "provenance.json"
        previous = manifest.read_bytes()
        (self.source / "SparseNextPrototype.lean").write_text("changed\n", encoding="ascii")
        with patch.dict(
            exporter.SOURCES,
            {"SparseNextPrototype": ("Sparse.Next", exporter.sha256(b"reviewed\n"))},
        ), self.assertRaisesRegex(ValueError, "reviewed source changed"):
            exporter.export(self.source, self.destination)
        self.assertEqual(manifest.read_bytes(), previous)
        self.assertFalse((self.destination / "Sparse" / "Next.lean").exists())


class SparseProofSnapshotTests(unittest.TestCase):
    def test_repository_proofs_match_reviewed_snapshots(self) -> None:
        with contextlib.redirect_stdout(io.StringIO()):
            exporter.check(exporter.ROOT)


if __name__ == "__main__":
    unittest.main()
