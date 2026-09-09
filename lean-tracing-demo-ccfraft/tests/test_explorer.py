# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Standalone explorer rendering, safe embedding, and browser interactions."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.test_client_request_encoding import CONSTRAINT_MAP_SCHEMA
from explore_checked import TEMPLATE, build_explorer_data, generate_explorer
from Shared.solver import ValidationError


class ExplorerFixture(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="checked-explorer-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "run"
        self.source.mkdir()
        self.output = self.root / "report.html"
        self.raw = self.root / "raw.ndjson"
        self.raw.write_text('{"event":"write"}\n{"event":"send"}\n', encoding="utf-8")
        self.result = {
            "status": "unsat",
            "assurance": {
                "granularity": "group",
                "backend": "lean-checked trace encoder",
                "entry": "template",
            },
            "proof_gate": {"checked": True, "fixture": "UI data, not model evidence"},
        }
        self.groups = [
            {
                "index": index,
                "name": f"group_{index}",
                "label": label,
                "kind": kind,
                "instruction": instruction,
                "clauses": [
                    {
                        "name": f"group_{index}_clause_0",
                        "label": label,
                        "expression": expression,
                    }
                ],
            }
            for index, (label, kind, instruction, expression) in enumerate(
                [
                    ("unknown domains", "bounds", None, "true"),
                    (
                        "appendEntries",
                        "action",
                        {
                            "kind": "action",
                            "action": "appendEntries",
                            "node": 0,
                            "destination": 1,
                            "provenance": [{"line": 2}],
                        },
                        "(= length 1)",
                    ),
                    (
                        "observed queue",
                        "observation",
                        {
                            "kind": "observation",
                            "variable": "queueLength",
                            "node": 1,
                            "value": 0,
                            "provenance": [{"line": 2}],
                        },
                        "(= length 0)",
                    ),
                ]
            )
        ]
        self.mapping = {
            "schema_version": CONSTRAINT_MAP_SCHEMA,
            "certificate_schema": "ccfraft-trace/v1",
            "entry": "template",
            "bounds": {},
            "unknowns": [],
            "supported_actions": ["appendEntries"],
            "inspect_group": None,
            "groups": self.groups,
        }
        self.save()

    def save(self) -> None:
        (self.source / "result.json").write_text(
            json.dumps(self.result), encoding="utf-8"
        )
        (self.source / "constraint-map.json").write_text(
            json.dumps(self.mapping), encoding="utf-8"
        )
        (self.source / "unsat-core.txt").write_text(
            "(group_1 group_2)\n", encoding="utf-8"
        )


class ExplorerTests(ExplorerFixture):
    def test_data_keeps_instruction_order_and_raw_lines(self) -> None:
        data = build_explorer_data(
            self.source,
            raw_trace=self.raw,
            refinement_directory=None,
            cvc5=None,
            workspace_uri="vscode://vscode-remote/ssh-remote+host/root/project",
        )
        self.assertEqual(data["groups"], self.groups)
        self.assertEqual(data["core"], ["group_1", "group_2"])
        self.assertEqual(data["raw_lines"], ['{"event":"write"}', '{"event":"send"}'])

    def test_embedded_data_cannot_close_its_script_element(self) -> None:
        malicious = "</script><script>window.injected = true</script>"
        self.groups[1]["instruction"]["action"] = malicious
        self.save()
        generate_explorer(self.source, self.output, raw_trace=self.raw, refine=False)
        document = self.output.read_text(encoding="utf-8")
        self.assertNotIn(malicious, document)
        self.assertIn(r"\u003c/script>", document)
        self.assertNotIn("__EXPLORER_DATA__", document)
        self.assertIn('id="raw"', document)
        self.assertIn('id="instructions"', document)
        self.assertIn('id="core"', document)
        self.assertIn("vscode://vscode-remote/", document)
        payload = re.search(
            r'<script id="explorer-data" type="application/json">(.*?)</script>',
            document,
            re.DOTALL,
        )
        self.assertIsNotNone(payload)
        source_url = json.loads(payload.group(1))["source_url"]
        self.assertIn("/lean-tracing-demo-ccfraft/BoundedTrace.lean:", source_url)
        line_number = int(source_url.rsplit(":", 2)[1])
        source_lines = (
            (TEMPLATE.parents[1] / "BoundedTrace.lean").read_text().splitlines()
        )
        self.assertTrue(source_lines[line_number - 1].startswith("def Follows "))

    def test_group_names_cannot_escape_the_refinement_directory(self) -> None:
        self.groups[1]["name"] = "../../outside"
        self.save()
        with self.assertRaisesRegex(ValidationError, "group name"):
            generate_explorer(self.source, self.output, raw_trace=self.raw)
        self.assertFalse(self.output.exists())

    def test_malformed_group_and_clause_metadata_is_rejected(self) -> None:
        for field, value in (("index", True), ("index", 7), ("kind", "other")):
            with self.subTest(field=field, value=value):
                original = self.groups[1][field]
                self.groups[1][field] = value
                self.save()
                with self.assertRaises(ValidationError):
                    generate_explorer(self.source, self.output, refine=False)
                self.groups[1][field] = original
        self.groups[1]["clauses"][0]["name"] = "unrelated"
        self.save()
        with self.assertRaisesRegex(ValidationError, "clause name"):
            generate_explorer(self.source, self.output, refine=False)

    def test_failed_generation_removes_a_stale_report(self) -> None:
        self.output.write_text("old verdict", encoding="utf-8")
        self.result["proof_gate"]["checked"] = False
        self.save()
        with self.assertRaisesRegex(ValidationError, "checked"):
            generate_explorer(self.source, self.output, refine=False)
        self.assertFalse(self.output.exists())

    def test_invalid_provenance_is_reported_before_rendering(self) -> None:
        for provenance in ([None], [{"line": True}], [{"line": 0}], [{"line": 3}]):
            with self.subTest(provenance=provenance):
                self.groups[1]["instruction"]["provenance"] = provenance
                self.save()
                with self.assertRaises(ValidationError):
                    generate_explorer(
                        self.source, self.output, raw_trace=self.raw, refine=False
                    )
                self.assertFalse(self.output.exists())

    def test_template_and_non_html_outputs_are_protected(self) -> None:
        for output in (TEMPLATE, self.source / "result.json"):
            with self.subTest(output=output), self.assertRaises(ValidationError):
                generate_explorer(self.source, output, refine=False)

    def test_sat_does_not_load_a_stale_unsat_core(self) -> None:
        self.result["status"] = "sat"
        self.save()
        with patch("explore_checked.refine_checked_core") as refine:
            data = build_explorer_data(
                self.source,
                raw_trace=None,
                refinement_directory=self.root / "refine",
                cvc5=None,
                workspace_uri="vscode://vscode-remote/ssh-remote+host/root/project",
            )
        self.assertEqual(data["core"], [])
        refine.assert_not_called()


@unittest.skipUnless(shutil.which("chromium"), "needs Chromium on PATH")
class ExplorerBrowserTests(ExplorerFixture):
    def test_selection_refinement_search_and_reset(self) -> None:
        data = build_explorer_data(
            self.source,
            raw_trace=self.raw,
            refinement_directory=None,
            cvc5=None,
            workspace_uri="vscode://vscode-remote/ssh-remote+host/root/project",
        )
        data["source_url"] = "https://github.com/cjen1-msft/CCF"
        data["refinements"] = {
            "group_1": {
                "result": {
                    "core_fixed_context_assertions": 1,
                    "core_reduction_complete": True,
                    "core_kind": "subset-minimal with fixed context",
                },
                "diagnosis": {
                    "named_assertions": ["group_1_clause_0", "group_2"],
                    "items": [
                        {
                            "name": "group_1_clause_0",
                            "group_index": 1,
                            "granularity": "clause",
                            "label": "queue length",
                        },
                        {"name": "group_2", "group_index": 2, "granularity": "group"},
                    ],
                },
            }
        }
        document = TEMPLATE.read_text(encoding="utf-8").replace(
            "__EXPLORER_DATA__", json.dumps(data).replace("<", "\\u003c"), 1
        )
        document = document.replace(
            "<head>",
            "<head><script>history.replaceState = function() { "
            'throw new DOMException("opaque origin", "SecurityError"); };</script>',
            1,
        )
        checks = """
<script>
function check(value, message) { if (!value) throw new Error(message); }
try {
  check(document.querySelectorAll("#instructions button").length === 2, "ordered instructions");
  check(document.getElementById("detail-title").textContent.includes("appendEntries"), "initial file deep link");
  document.querySelector('#instructions [data-group="group_1"]').click();
  check(document.querySelector('#raw [data-line="2"]').classList.contains("selected"), "raw source highlight");
  check(document.querySelectorAll("#detail .clause").length === 1, "constraint details");
  document.getElementById("refine").click();
  check(document.querySelectorAll("#core [data-clause]").length === 1, "reduced clauses");
  check(document.getElementById("core-note").textContent.includes("1 other groups stayed fixed"), "fixed context");
  check(document.getElementById("core-note").textContent.includes("subset-minimal with fixed context"), "reduction explanation");
  data.refinements.group_1.diagnosis.items = [{name:"group_2",group_index:2,granularity:"group"}];
  data.refinements.group_1.result.core_kind = "the clauses of group_1 are not required for UNSAT";
  document.getElementById("refine").click();
  check(document.querySelectorAll("#core [data-clause]").length === 0, "irrelevant action");
  check(document.getElementById("core-note").textContent.includes("not required for UNSAT"), "irrelevance explanation");
  document.getElementById("reset-core").click();
  check(document.querySelectorAll("#core [data-clause]").length === 0, "group reset");
  document.getElementById("search").value = "appendEntries";
  document.getElementById("search").dispatchEvent(new Event("input"));
  check(document.querySelectorAll("#instructions button").length === 1, "search");
  document.title = "EXPLORER_TEST_PASSED";
} catch (error) { document.title = "EXPLORER_TEST_FAILED: " + error.message; }
</script>
"""
        self.output.write_text(
            document.replace("</body>", checks + "</body>"), encoding="utf-8"
        )
        completed = subprocess.run(
            [
                "chromium",
                "--headless",
                "--no-sandbox",
                "--disable-gpu",
                "--disable-dev-shm-usage",
                "--no-first-run",
                f"--user-data-dir={self.root / 'browser'}",
                "--dump-dom",
                self.output.as_uri() + "#group_1",
            ],
            check=True,
            capture_output=True,
            text=True,
            env=os.environ.copy(),
        )
        title = re.search(r"<title>(.*?)</title>", completed.stdout)
        self.assertIsNotNone(title, "the browser returned no document title")
        self.assertEqual(title.group(1), "EXPLORER_TEST_PASSED")


if __name__ == "__main__":
    unittest.main()
