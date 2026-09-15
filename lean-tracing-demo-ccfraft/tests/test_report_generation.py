# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Report composition tests with mock run artifacts, not raw-model evidence."""

from __future__ import annotations

import contextlib
from copy import deepcopy
from html.parser import HTMLParser
import io
import json
from pathlib import Path
from urllib.parse import unquote
from unittest.mock import patch
import unittest

import explore_checked as explorer
import generate_report as report
from reduction import build_certificate, write_certificate
from Shared.solver import ValidationError
from Shared.trace_io import read_ndjson
from tests.test_explorer import ExplorerFixture
from tests.test_raw_orchestration import BOUNDS


class Links(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.urls: list[str] = []
        self.tags: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append(tag)
        for name, value in attrs:
            if tag == "a" and name == "href" and value is not None:
                self.urls.append(value)


class ReportGenerationTests(ExplorerFixture):
    def setUp(self) -> None:
        super().setUp()
        self.runs = self.root / "runs"
        self.output = self.root / "report/index.html"
        self.enterContext(
            patch("subprocess.run", side_effect=AssertionError("unexpected process"))
        )
        self.result["assurance"].update(entry="symbolic", bounds=BOUNDS)
        self.mapping.update(
            entry="symbolic",
            certificate_schema="ccfraft-symbolic-trace/v1",
            theorem="CCFRaft.SymbolicTraceEncoding.encode_holds_correct",
            bounds=BOUNDS,
        )
        for index, (stem, _) in enumerate(report.RUNS):
            directory = self.runs / stem
            directory.mkdir(parents=True)
            result = deepcopy(self.result)
            result["status"] = ("sat", "unknown", "unsat", "unsat", "unsat", "unsat")[
                index
            ]
            write_certificate(directory / "result.json", result)
            write_certificate(directory / "constraint-map.json", self.mapping)
            write_certificate(
                directory / "certificate.json",
                {
                    "schema_version": "ccfraft-symbolic-trace/v1",
                    "entry": "symbolic",
                    "bounds": BOUNDS,
                    "unknowns": [],
                    "steps": [group["instruction"] for group in self.groups[1:]],
                },
            )
            (directory / "unsat-core.txt").write_text("(group_1 group_2)\n")

    def test_small_index_reuses_six_explorers_and_actual_bounds(self) -> None:
        with (
            patch.object(
                explorer, "generate_explorer", wraps=explorer.generate_explorer
            ) as generate,
            patch.object(
                explorer,
                "refine_checked_core",
                side_effect=AssertionError("refinement disabled"),
            ),
        ):
            self.assertEqual(
                report.generate_report(self.runs, self.output, refine=False),
                self.output,
            )
        self.assertEqual(generate.call_count, 6)
        document = self.output.read_text()
        parsed = Links()
        parsed.feed(document)
        self.assertEqual(parsed.tags.count("li"), 6)
        self.assertNotIn("script", parsed.tags)
        self.assertIn("<code>unknown</code>", document)
        self.assertNotIn("projection", document)
        self.assertNotIn("wsl", document.lower())
        self.assertNotIn("wall_ms", document)
        for bound, value in BOUNDS.items():
            self.assertEqual(document.count(f"&quot;{bound}&quot;: {value}"), 6)
        for call, (stem, directory) in zip(
            generate.call_args_list, report.RUNS, strict=True
        ):
            args, kwargs = call
            self.assertEqual(args[0], self.runs / stem)
            page = self.output.parent / "index-runs" / f"{stem}.html"
            self.assertEqual(args[1], page)
            self.assertEqual(
                kwargs["raw_trace"],
                report.ROOT / "Traces" / directory / f"{stem}.ndjson",
            )
            self.assertIs(kwargs["refine"], False)
            self.assertIn(f"index-runs/{stem}.html", parsed.urls)
            for pane in ("raw", "instructions", "core"):
                self.assertIn(f'id="{pane}"', page.read_text())
        for url in parsed.urls:
            if not url.startswith(("vscode:", "https:")):
                self.assertTrue((self.output.parent / unquote(url)).is_file(), url)
        workspace = explorer.REMOTE + str(report.ROOT.parent)
        self.assertIn(workspace, parsed.urls)
        contract_url = next(
            url for url in parsed.urls if "/BoundedSymbolicTrace.lean:" in url
        )
        number = int(contract_url.rsplit(":", 2)[1])
        lines = (report.ROOT / "BoundedSymbolicTrace.lean").read_text().splitlines()
        self.assertTrue(lines[number - 1].startswith("def Follows "))
        self.assertFalse(any(url.startswith("https:") for url in parsed.urls))

    def test_default_precomputes_existing_core_refinements(self) -> None:
        def refine(source: Path, output: Path, **kwargs: object) -> dict:
            output.mkdir(parents=True)
            write_certificate(output / "diagnosis.json", {"items": []})
            return {"status": "unsat", "fixture": "mock refinement"}

        with patch.object(
            explorer, "refine_checked_core", side_effect=refine
        ) as refine_core:
            report.generate_report(self.runs, self.output, cvc5=Path("/mock/cvc5"))
        self.assertEqual(refine_core.call_count, 4)
        for call in refine_core.call_args_list:
            self.assertEqual(
                call.kwargs, {"inspect_group": 1, "cvc5": Path("/mock/cvc5")}
            )

    def test_missing_or_unproved_run_cannot_publish_index(self) -> None:
        last = self.runs / report.RUNS[-1][0]
        for problem in ("missing", "unproved", "malformed", "certificate"):
            with self.subTest(problem=problem):
                original = (last / "result.json").read_bytes()
                certificate = (last / "certificate.json").read_bytes()
                self.output.parent.mkdir(parents=True, exist_ok=True)
                self.output.write_text("old completed index")
                if problem == "missing":
                    (last / "result.json").unlink()
                elif problem == "unproved":
                    value = json.loads(original)
                    value["proof_gate"]["checked"] = False
                    write_certificate(last / "result.json", value)
                elif problem == "malformed":
                    (last / "result.json").write_text("{bad")
                else:
                    (last / "certificate.json").write_text("[]")
                with self.assertRaises((ValidationError, OSError)):
                    report.generate_report(self.runs, self.output, refine=False)
                self.assertFalse(self.output.exists())
                (last / "result.json").write_bytes(original)
                (last / "certificate.json").write_bytes(certificate)

    def test_malformed_constraints_use_existing_explorer_validation(self) -> None:
        source = self.runs / report.RUNS[-1][0]
        mapping = deepcopy(self.mapping)
        mapping["groups"][1]["index"] = True
        write_certificate(source / "constraint-map.json", mapping)
        with self.assertRaisesRegex(ValidationError, "encoder order"):
            report.generate_report(self.runs, self.output, refine=False)
        self.assertFalse(self.output.exists())

    def test_failed_refinement_cannot_publish_index(self) -> None:
        with (
            patch.object(
                explorer,
                "refine_checked_core",
                side_effect=ValidationError("refinement failed"),
            ),
            self.assertRaisesRegex(ValidationError, "refinement failed"),
        ):
            report.generate_report(self.runs, self.output)
        self.assertFalse(self.output.exists())

    def test_missing_bounds_are_not_inferred(self) -> None:
        source = self.runs / report.RUNS[-1][0]
        result = deepcopy(self.result)
        del result["assurance"]["bounds"]
        write_certificate(source / "result.json", result)
        with self.assertRaisesRegex(ValidationError, "bounds"):
            report.generate_report(self.runs, self.output, refine=False)
        self.assertFalse(self.output.exists())

    def test_template_and_input_artifacts_are_not_overwritten(self) -> None:
        for output in (explorer.TEMPLATE, self.runs / "bad_network/result.json"):
            with self.subTest(output=output):
                original = output.read_bytes()
                with self.assertRaises(ValidationError):
                    report.generate_report(self.runs, output, refine=False)
                self.assertEqual(output.read_bytes(), original)

    def test_source_link_requires_the_actual_declaration(self) -> None:
        missing = self.root / "contract.lean"
        missing.write_text("-- no declaration\n")
        with self.assertRaisesRegex(ValidationError, "declaration"):
            report.source_line(missing, "def Follows ")

    def test_cli_defaults_and_flags(self) -> None:
        with (
            patch.object(
                report, "generate_report", return_value=self.output
            ) as generate,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(report.main([]), 0)
            generate.assert_called_once_with(
                report.ROOT / "Artifacts/runs",
                report.ROOT / "Report/index.html",
                cvc5=None,
                refine=True,
            )
            generate.reset_mock()
            self.assertEqual(
                report.main(
                    [
                        "--runs-dir",
                        str(self.runs),
                        "--output",
                        str(self.output),
                        "--cvc5",
                        "/mock/cvc5",
                        "--no-refine",
                    ]
                ),
                0,
            )
            generate.assert_called_once_with(
                self.runs,
                self.output,
                cvc5=Path("/mock/cvc5"),
                refine=False,
            )
        with (
            patch.object(
                report, "generate_report", side_effect=ValidationError("unproved")
            ),
            contextlib.redirect_stderr(io.StringIO()) as stderr,
            self.assertRaises(SystemExit) as failure,
        ):
            report.main([])
        self.assertEqual(failure.exception.code, 2)
        self.assertIn("unproved", stderr.getvalue())

    def test_demo_gate_can_compare_reduced_certificates_byte_for_byte(self) -> None:
        for stem, directory in report.RUNS:
            with self.subTest(trace=stem):
                raw = report.ROOT / "Traces" / directory / f"{stem}.ndjson"
                regenerated = self.root / "reduced-certificate.json"
                write_certificate(regenerated, build_certificate(read_ndjson(raw)))
                expected = report.ROOT / "Traces/Certificates" / f"{stem}.json"
                self.assertEqual(regenerated.read_bytes(), expected.read_bytes())


if __name__ == "__main__":
    unittest.main()
