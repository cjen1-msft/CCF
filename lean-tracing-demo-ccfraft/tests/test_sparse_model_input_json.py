"""Opt-in JSON-value atom and ordered-name codecs; no raw-text parser claims."""

import json
import os
from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(
    os.environ.get("CCF_SPARSE_SMT_TESTS") == "1",
    "set CCF_SPARSE_SMT_TESTS=1 with Lean available; no solver required",
)
class SparseModelInputJsonTests(unittest.TestCase):
    def test_atoms_and_complete_name_tables(self) -> None:
        subprocess.run(
            ["nice", "-n", "10", "lake", "build", "Sparse.ModelInputJsonFixtureMain"],
            cwd=ROOT, capture_output=True, text=True, check=True,
        )
        generated = subprocess.run(
            ["nice", "-n", "10", "lake", "env", "lean", "--run",
             "Sparse/ModelInputJsonFixtureMain.lean"],
            cwd=ROOT, capture_output=True, text=True, check=True,
        )
        result = json.loads(generated.stdout)
        self.assertEqual(len(result["controls"]), 32)
        self.assertEqual(len({name for name, _ in result["controls"]}), 32)
        for name, passed in result["controls"]:
            with self.subTest(control=name):
                self.assertTrue(passed)
        self.assertEqual([table["count"] for table in result["tables"]], [0, 1, 40, 400])
        for table in result["tables"]:
            count = table["count"]
            names = [f"slot-{index}" for index in range(count)]
            self.assertEqual(table["declared"], names)
            self.assertEqual(table["encoded_names"], names)
            self.assertEqual(len(table["lookups"]), count)
            for index, item in enumerate(table["lookups"]):
                with self.subTest(count=count, index=index):
                    value = 0 if index % 2 == 0 else index + 1
                    self.assertEqual(item["name"], names[index])
                    self.assertEqual(item["index"], index)
                    self.assertEqual(item["numeric"], value)
                    self.assertIs(item["zero"], value == 0)
                    self.assertEqual(item["encoded_nat"], {"unknown": names[index]})
                    self.assertEqual(
                        item["encoded_bool"], {"isZero": {"unknown": names[index]}}
                    )
            for field in ["index", "numeric", "zero", "encoded_nat", "encoded_bool"]:
                self.assertIn("undeclaredName", table["missing"][field]["error"])


if __name__ == "__main__":
    unittest.main()
