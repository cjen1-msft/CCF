# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Parse saved normalized traces through Lean, without execution or solver claims."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from raw_normalization import normalize
from reduction import build_certificate
from Shared.trace_io import read_ndjson

ROOT = Path(__file__).resolve().parents[1]


class SymbolicTraceDecodingTests(unittest.TestCase):
    def test_saved_normalized_traces_decode_with_shared_unknown_offsets(self) -> None:
        sources = sorted((ROOT / "Traces/Captured").glob("*.ndjson"))
        sources += sorted((ROOT / "Traces/Mutated").glob("*.ndjson"))
        self.assertEqual(len(sources), 6)
        # Explicit test bounds, not bounds inferred from observations or a SAT claim.
        bounds = {
            "transaction_count": 4,
            "term_count": 4,
            "index_count": 16,
            "log_capacity": 2,
            "queue_capacity": 2,
        }
        with tempfile.TemporaryDirectory(prefix="ccf-symbolic-decode-") as temporary:
            documents = {}
            for source in sources:
                normalized = normalize(build_certificate(read_ndjson(source)))
                document = normalized.certificate(bounds)
                path = Path(temporary) / f"{source.parent.name}-{source.stem}.json"
                path.write_text(json.dumps(document), encoding="utf-8")
                documents[str(path)] = document

            result = subprocess.run(
                [
                    "nice",
                    "-n",
                    "10",
                    "lake",
                    "env",
                    "lean",
                    "--run",
                    "MachineGenerated/SymbolicTraceCertificateTests.lean",
                    "--decode",
                    *documents,
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            reports = [
                json.loads(line)
                for line in result.stdout.splitlines()
                if line.startswith("{")
            ]
            self.assertEqual(len(reports), len(documents), result.stdout)
            self.assertEqual(
                {report["certificate"] for report in reports}, set(documents)
            )
            for report in reports:
                with self.subTest(certificate=Path(report["certificate"]).name):
                    document = documents[report["certificate"]]
                    self.assertEqual(report["mode"], "decode-only")
                    self.assertNotIn("verdict", report)
                    self.assertEqual(report["steps"], len(document["steps"]))
                    self.assertTrue(report["raw_steps_preserved"])
                    start = report["entry_width"]
                    self.assertGreater(start, 0)
                    slots = {
                        name: start + index
                        for index, name in enumerate(document["unknowns"])
                    }
                    self.assertEqual(
                        report["unknowns"],
                        [
                            {"name": name, "index": index}
                            for name, index in slots.items()
                        ],
                    )
                    expected = []
                    for index, step in enumerate(document["steps"], 1):
                        if "transaction" not in step:
                            continue
                        value = step["transaction"]
                        if isinstance(value, dict):
                            expected.append(
                                {
                                    "step": index,
                                    "unknown_index": slots[value["unknown"]],
                                }
                            )
                        else:
                            expected.append({"step": index, "literal": value})
                    self.assertEqual(report["transaction_references"], expected)
                    self.assertGreater(len(expected), 0)


if __name__ == "__main__":
    unittest.main()
