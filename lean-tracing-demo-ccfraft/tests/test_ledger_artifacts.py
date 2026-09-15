# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Lossless artifact compaction must never discard the only valid copy."""

import gzip
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from compact_ledger_artifacts import compress_file


class LedgerArtifactTests(unittest.TestCase):
    def test_verified_compression_preserves_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "query.smt2"
            data = b"(assert true)\n" * 100
            path.write_bytes(data)
            record = compress_file(path, minimum=0)
            self.assertFalse(path.exists())
            with gzip.open(path.with_suffix(".smt2.gz"), "rb") as stream:
                self.assertEqual(stream.read(), data)
            self.assertEqual(record["original_bytes"], len(data))

    def test_existing_compressed_file_does_not_remove_original(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "encoding.json"
            path.write_bytes(b"original")
            path.with_suffix(".json.gz").write_bytes(b"existing")
            with self.assertRaises(ValueError):
                compress_file(path, minimum=0)
            self.assertEqual(path.read_bytes(), b"original")

    def test_unlisted_file_is_not_modified(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "stream.json"
            path.write_bytes(b"source stream")
            self.assertIsNone(compress_file(path, minimum=0))
            self.assertEqual(path.read_bytes(), b"source stream")

    def test_symlink_is_not_followed(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "original"
            source.write_bytes(b"keep")
            path = Path(directory) / "request.json"
            path.symlink_to(source)
            self.assertIsNone(compress_file(path, minimum=0))
            self.assertEqual(source.read_bytes(), b"keep")


if __name__ == "__main__":
    unittest.main()
