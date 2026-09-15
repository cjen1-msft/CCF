# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Audit and benchmark routing with no native processes or semantic claims."""

from __future__ import annotations

from collections.abc import Callable, Sequence
import contextlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import audit_trace_coverage as audit
import benchmark_pipeline as benchmark
from reduction import ReductionError, write_certificate
from Shared.solver import ValidationError
from tests.test_raw_orchestration import BOUNDS, TRACE, fake_result
import validate
import validate_checked as checked


class PipelineOrchestrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="raw-pipeline-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.scenario_root = self.root / "tests/raft_scenarios"
        self.scenario_root.mkdir(parents=True)
        (self.scenario_root / "example").write_text("mock scenario\n")
        self.output = self.root / "report.json"
        self.artifacts = self.root / "artifacts"
        self.profile = self.root / "bounds.json"
        write_certificate(self.profile, BOUNDS)
        self.raw = TRACE.read_bytes()
        self.enterContext(
            patch("subprocess.run", side_effect=AssertionError("native call"))
        )
        self.find_solver = self.enterContext(
            patch.object(audit, "find_cvc5", return_value=Path("/mock/cvc5"))
        )
        self.enterContext(patch.object(audit, "find_repo_root", return_value=self.root))
        self.enterContext(patch.object(benchmark, "find_repo_root", return_value=self.root))
        self.enterContext(patch.object(audit, "EXPECTED_SCENARIOS", 1))

    def args(self) -> list[str]:
        return [
            "--bounds",
            str(self.profile),
            "--output",
            str(self.output),
            "--artifacts",
            str(self.artifacts),
        ]

    def report(self) -> dict:
        return json.loads(self.output.read_text())

    @staticmethod
    def backend(certificate: Path, output: Path, **kwargs: object) -> str:
        result = fake_result()
        (output / "formula.smt2").write_text(
            "(set-logic QF_UF)\n(assert (! true :named group_0))\n(check-sat)\n"
        )
        write_certificate(output / "result.json", result)
        print("sat")
        return "sat"

    def test_audit_solve_uses_raw_checked_pipeline_and_declared_bounds(self) -> None:
        self.profile = self.artifacts / "example/bounds.json"
        self.profile.parent.mkdir(parents=True)
        write_certificate(self.profile, BOUNDS)
        with (
            patch.object(audit, "find_repo_root", return_value=self.root),
            patch.object(audit, "capture", return_value=(self.raw, 2.0)),
            patch.object(
                checked, "validate_checked", side_effect=self.backend
            ) as backend,
            contextlib.redirect_stdout(io.StringIO()) as stdout,
        ):
            self.assertEqual(
                audit.main(
                    self.args()
                    + [
                        "--scenario",
                        "example",
                        "--solve",
                        "--require-all",
                        "--capture-dir",
                        str(self.profile.parent),
                    ]
                ),
                0,
            )
        backend.assert_called_once()
        self.assertIn("scenarios=1 accepted=1 sat=1", stdout.getvalue())
        row = self.report()["scenarios"][0]
        self.assertTrue(row["reduction"]["accepted"])
        self.assertTrue(row["smt"]["accepted"])
        self.assertEqual(row["solver"], "sat")
        self.assertEqual(row["smt"]["assurance"], fake_result()["assurance"])
        self.assertEqual(self.report()["bounds"], BOUNDS)
        certificate = json.loads(
            (self.artifacts / "example/certificate.json").read_text()
        )
        self.assertEqual(certificate["bounds"], BOUNDS)
        self.assertEqual(certificate["schema_version"], "ccfraft-symbolic-trace/v1")
        self.assertEqual(json.loads(self.profile.read_text()), BOUNDS)
        self.assertEqual(
            (self.profile.parent / "example.ndjson").read_bytes(), self.raw
        )

    def test_audit_default_encodes_only_after_gate(self) -> None:
        events = []

        def gate(*args: object) -> dict:
            events.append("gate")
            return {"checked": True}

        def encode(
            root: Path, certificate: Path, output: Path, **kwargs: object
        ) -> float:
            events.append("encoder")
            self.backend(certificate, output)
            return 3.0

        constraint_map = {
            "entry": "symbolic",
            "certificate_schema": "ccfraft-symbolic-trace/v1",
            "theorem": checked.SYMBOLIC_THEOREM,
            "bounds": BOUNDS,
            "unknowns": [],
            "supported_actions": ["receive"],
        }
        with (
            patch.object(audit, "find_repo_root", return_value=self.root),
            patch.object(audit, "capture", return_value=(self.raw, 2.0)),
            patch.object(checked, "build_proof_gate", side_effect=gate),
            patch.object(checked, "run_encoder", side_effect=encode),
            patch.object(checked, "read_constraint_map", return_value=constraint_map),
            patch.object(checked, "validate_checked") as solver_backend,
            contextlib.redirect_stdout(io.StringIO()) as stdout,
        ):
            self.assertEqual(audit.main(self.args() + ["--scenario", "example"]), 0)
        self.assertEqual(events, ["gate", "encoder"])
        solver_backend.assert_not_called()
        self.find_solver.assert_not_called()
        self.assertIn("sat=not-run", stdout.getvalue())
        row = self.report()["scenarios"][0]
        self.assertTrue(row["smt"]["accepted"])
        self.assertNotIn("solver", row)

    def test_audit_reports_normalization_and_backend_errors_separately(self) -> None:
        for target, phase, error in (
            ("normalize", "normalization", ReductionError("unsupported raw syntax")),
            (
                "backend",
                "checked_backend",
                ValidationError("symbolic gate unavailable"),
            ),
        ):
            with (
                self.subTest(phase=phase),
                patch.object(audit, "find_repo_root", return_value=self.root),
                patch.object(audit, "capture", return_value=(self.raw, 2.0)),
                patch.object(
                    validate if target == "normalize" else checked,
                    "normalize" if target == "normalize" else "validate_checked",
                    side_effect=error,
                ),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(
                    audit.main(
                        self.args()
                        + ["--scenario", "example", "--solve", "--require-all"]
                    ),
                    1,
                )
            row = self.report()["scenarios"][0]
            self.assertTrue(row["reduction"]["accepted"])
            self.assertFalse(row["smt"]["accepted"])
            self.assertEqual(row["error"]["phase"], phase)
            self.assertEqual(self.report()["accepted"], [])
            self.assertFalse((self.artifacts / "example/result.json").exists())

    def test_audit_unknown_is_not_reported_as_sat(self) -> None:
        def backend(certificate: Path, output: Path, **kwargs: object) -> str:
            self.backend(certificate, output)
            write_certificate(output / "result.json", fake_result("unknown"))
            return "unknown"

        with (
            patch.object(audit, "find_repo_root", return_value=self.root),
            patch.object(audit, "capture", return_value=(self.raw, 2.0)),
            patch.object(checked, "validate_checked", side_effect=backend),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(
                audit.main(
                    self.args() + ["--scenario", "example", "--solve", "--require-all"]
                ),
                1,
            )
        self.assertEqual(self.report()["accepted"], ["example"])
        self.assertEqual(self.report()["sat"], [])
        self.assertEqual(self.report()["scenarios"][0]["solver"], "unknown")

    def test_audit_capture_failure_does_not_reuse_previous_success(self) -> None:
        directory = self.artifacts / "example"
        directory.mkdir(parents=True)
        write_certificate(directory / "result.json", fake_result())
        write_certificate(directory / "reduced-certificate.json", {"counts": {}})
        with (
            patch.object(audit, "find_repo_root", return_value=self.root),
            patch.object(audit, "capture", side_effect=RuntimeError("capture failed")),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(
                audit.main(self.args() + ["--scenario", "example", "--require-all"]), 1
            )
        self.assertFalse((directory / "result.json").exists())
        row = self.report()["scenarios"][0]
        self.assertFalse(row["reduction"]["accepted"])
        self.assertEqual(row["error"]["phase"], "capture")

    def test_audit_malformed_capture_keeps_raw_error_context(self) -> None:
        raw = b'{"cmd":"test","tag":"raft_trace"}\n{bad\n'
        with (
            patch.object(audit, "find_repo_root", return_value=self.root),
            patch.object(audit, "capture", return_value=(raw, 2.0)),
            patch.object(checked, "validate_checked") as backend,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(
                audit.main(self.args() + ["--scenario", "example", "--require-all"]),
                1,
            )
        backend.assert_not_called()
        row = self.report()["scenarios"][0]
        self.assertFalse(row["reduction"]["accepted"])
        self.assertEqual(row["error"]["context"][-1], {"line": 2, "raw": "{bad"})
        self.assertEqual((self.artifacts / "example/raw.ndjson").read_bytes(), raw)

    def test_benchmark_keeps_build_tree_and_measures_checked_gate(self) -> None:
        self.profile = self.artifacts / "example/bounds.json"
        self.profile.parent.mkdir(parents=True)
        write_certificate(self.profile, BOUNDS)
        fixture = self.root / "Traces/Captured/example.ndjson"
        fixture.parent.mkdir(parents=True)
        fixture.write_bytes(self.raw)
        sentinel = self.root / ".lake/build/keep"
        sentinel.parent.mkdir(parents=True)
        sentinel.write_text("another worker's build")
        events = []

        def gate(root: Path, log: Path) -> dict:
            self.assertEqual(root, self.root)
            self.assertTrue(sentinel.is_file())
            events.append("gate")
            log.write_text("mock proof gate")
            return {"checked": True, "build_target": checked.ENCODER_TARGET}

        def backend(certificate: Path, output: Path, **kwargs: object) -> str:
            events.append("validate")
            return self.backend(certificate, output, **kwargs)

        def command(
            command: list[str], **kwargs: object
        ) -> subprocess.CompletedProcess:
            if command == ["/mock/cvc5", "--version"]:
                return subprocess.CompletedProcess(command, 0, "mock cvc5\n", "")
            if command == ["git", "rev-parse", "HEAD"]:
                return subprocess.CompletedProcess(command, 0, "mock-revision\n", "")
            raise AssertionError(f"unexpected command: {command}")

        with (
            patch.object(benchmark, "ROOT", self.root),
            patch.object(benchmark, "RUNS", (("example", fixture),)),
            patch.object(benchmark, "SCENARIOS", ("example",)),
            patch.object(benchmark, "find_repo_root", return_value=self.root),
            patch.object(benchmark, "capture", return_value=(self.raw, 2.0)) as capture,
            patch.object(benchmark, "find_cvc5", return_value=Path("/mock/cvc5")),
            patch.object(benchmark.platform, "platform", return_value="mock-platform"),
            patch.object(checked, "build_proof_gate", side_effect=gate) as build,
            patch.object(checked, "validate_checked", side_effect=backend),
            patch("subprocess.run", side_effect=command),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(benchmark.main(self.args() + ["--samples", "2"]), 0)
            self.assertEqual(events, ["gate", "validate", "validate"])
            build.assert_called_once()
            first = self.report()
            self.assertEqual(
                benchmark.main(
                    self.args() + ["--samples", "1", "--reuse-build-timings"]
                ),
                0,
            )
            build.assert_called_once()
            capture.reset_mock()
            self.assertFalse((self.root / "build/raft_driver").exists())
            with patch.object(
                benchmark,
                "find_repo_root",
                side_effect=AssertionError("saved traces must not locate raft_driver"),
            ):
                self.assertEqual(
                    benchmark.main(
                        self.args()
                        + ["--samples", "1", "--reuse-build-timings", "--saved-traces"]
                    ),
                    0,
                )
            capture.assert_not_called()
            build.assert_called_once()
            self.assertEqual(self.report()["capture"], {})
            self.assertEqual(self.report()["trace_source"], "saved")
        self.assertEqual(sentinel.read_text(), "another worker's build")
        self.assertNotIn("cold_build_wall_ms", first["lean"])
        self.assertNotIn("warm_build_wall_ms", first["lean"])
        self.assertEqual(first["lean"]["proof_gate"]["build_target"], "encode_trace")
        self.assertEqual(first["bounds"], BOUNDS)
        result = first["validations"]["example"]
        self.assertEqual(len(result["samples"]), 2)
        self.assertGreater(result["actions"], 0)
        self.assertGreater(result["observations"], 0)
        self.assertGreater(result["trace_records"], 0)
        self.assertIn("normalization", result["phase_wall_ms"])
        self.assertEqual(self.report()["lean"]["reused"], True)
        self.assertEqual(json.loads(self.profile.read_text()), BOUNDS)

    def test_benchmark_rejects_legacy_demo_build_timings(self) -> None:
        write_certificate(
            self.output, {"lean": {"cold_build_wall_ms": 1, "warm_build_wall_ms": 2}}
        )
        with (
            patch.object(benchmark, "find_cvc5", return_value=Path("/mock/cvc5")),
            contextlib.redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit),
        ):
            benchmark.main(self.args() + ["--reuse-build-timings"])

    def test_all_cli_callers_require_explicit_bounds(self) -> None:
        for caller in (audit.main, benchmark.main):
            with (
                self.subTest(caller=caller.__module__),
                contextlib.redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit),
            ):
                caller([])

    def test_invalid_profile_prevents_capture_or_build_and_removes_old_report(
        self,
    ) -> None:
        for caller in (audit.main, benchmark.main):
            with (
                self.subTest(caller=caller.__module__),
                patch.object(audit, "capture") as audit_capture,
                patch.object(benchmark, "capture") as benchmark_capture,
                patch.object(checked, "build_proof_gate") as build,
                contextlib.redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit),
            ):
                write_certificate(self.profile, {**BOUNDS, "queue_capacity": -1})
                write_certificate(self.output, {"status": "stale success"})
                caller(self.args())
            audit_capture.assert_not_called()
            benchmark_capture.assert_not_called()
            build.assert_not_called()
            self.assertFalse(self.output.exists())

    def test_benchmark_refuses_to_hide_changed_status_between_samples(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "statuses changed"):
            benchmark.aggregate_samples([{"status": "sat"}, {"status": "unsat"}])

    def test_audit_missing_solver_fails_once_before_any_capture(self) -> None:
        for requested in (None, "/missing/cvc5"):
            with (
                self.subTest(requested=requested),
                patch.object(
                    audit, "find_cvc5", side_effect=ValidationError("cvc5 unavailable")
                ) as find,
                patch.object(audit, "capture") as capture,
                patch.object(checked, "validate_checked") as backend,
                contextlib.redirect_stderr(io.StringIO()) as stderr,
                self.assertRaises(SystemExit) as failure,
            ):
                args = self.args() + ["--solve"]
                if requested is not None:
                    args += ["--cvc5", requested]
                audit.main(args)
            self.assertEqual(failure.exception.code, 2)
            self.assertEqual(stderr.getvalue().count("cvc5 unavailable"), 1)
            find.assert_called_once_with(Path(requested) if requested else None)
            capture.assert_not_called()
            backend.assert_not_called()

    def test_benchmark_aggregates_checked_core_solver_timing(self) -> None:
        samples = [
            {
                "status": "unsat",
                "core_solver_wall_ms": value,
                "phase_wall_ms": {"checked_backend": value + 1},
            }
            for value in (1.0, 4.0, 10.0)
        ]
        result = benchmark.aggregate_samples(samples)
        self.assertEqual(result["core_solver_wall_ms"], 4.0)
        self.assertAlmostEqual(result["core_solver_wall_ms_p90"], 8.8)
        self.assertNotIn("unsat_core_wall_ms", result)
        self.assertEqual(result["samples"], samples)

    def snapshot(self) -> dict:
        return {
            str(path.relative_to(self.root)): (
                path.read_bytes() if path.is_file() else None,
                path.lstat().st_ino,
                path.lstat().st_mtime_ns,
            )
            for path in self.root.rglob("*")
        }

    def assert_profile_collision(
        self,
        caller: Callable[[Sequence[str]], int],
        profile: Path,
        extra_args: list[str],
    ) -> None:
        before = self.snapshot()
        with (
            patch.object(audit, "capture") as audit_capture,
            patch.object(benchmark, "capture") as benchmark_capture,
            patch.object(benchmark, "find_cvc5", return_value=Path("/mock/cvc5")),
            patch.object(checked, "build_proof_gate") as gate,
            patch.object(checked, "validate_checked") as backend,
            contextlib.redirect_stderr(io.StringIO()) as stderr,
            contextlib.redirect_stdout(io.StringIO()) as stdout,
            self.assertRaises(SystemExit) as failure,
        ):
            caller(self.args() + ["--bounds", str(profile)] + extra_args)
        self.assertEqual(failure.exception.code, 2)
        self.assertIn("collision", stderr.getvalue())
        self.assertEqual(stdout.getvalue(), "")
        audit_capture.assert_not_called()
        benchmark_capture.assert_not_called()
        gate.assert_not_called()
        backend.assert_not_called()
        self.assertEqual(self.snapshot(), before)

    def test_both_clis_reject_report_profile_collision_without_mutation(self) -> None:
        for caller in (audit.main, benchmark.main):
            with self.subTest(caller=caller.__module__):
                write_certificate(self.output, BOUNDS)
                self.assert_profile_collision(caller, self.output, [])

    def test_both_clis_preflight_every_selected_run_before_capture(self) -> None:
        (self.scenario_root / "zlast").write_text("last scenario")
        runs = (("example", TRACE), ("zlast", TRACE))
        with patch.object(benchmark, "RUNS", runs):
            for caller in (audit.main, benchmark.main):
                for name in (
                    "certificate.json",
                    "constraint-map.json",
                    "error.json",
                    "cvc5-extra.stdout",
                ):
                    with self.subTest(caller=caller.__module__, artifact=name):
                        directory = self.artifacts / "zlast"
                        directory.mkdir(parents=True, exist_ok=True)
                        profile = directory / name
                        write_certificate(profile, BOUNDS)
                        self.output.write_text("old report")
                        (directory / "unrelated.txt").write_text("keep")
                        first = self.artifacts / "example"
                        first.mkdir(exist_ok=True)
                        (first / "result.json").write_text("first old result")
                        args = (
                            ["--scenario", "example", "--scenario", "zlast"]
                            if caller is audit.main
                            else []
                        )
                        self.assert_profile_collision(caller, profile, args)

    def test_audit_preflights_both_raw_capture_destinations(self) -> None:
        capture = self.root / "captured"
        for profile in (
            self.artifacts / "example/raw.ndjson",
            capture / "example.ndjson",
        ):
            with self.subTest(profile=profile):
                profile.parent.mkdir(parents=True, exist_ok=True)
                write_certificate(profile, BOUNDS)
                self.output.write_text("old report")
                self.assert_profile_collision(
                    audit.main,
                    profile,
                    ["--scenario", "example", "--capture-dir", str(capture)],
                )

    def test_pipeline_profile_aliases_are_rejected_without_mutation(self) -> None:
        with patch.object(benchmark, "RUNS", (("example", TRACE),)):
            for caller in (audit.main, benchmark.main):
                for kind in ("symlink", "hardlink"):
                    with self.subTest(caller=caller.__module__, kind=kind):
                        artifact = self.artifacts / "example/error.json"
                        artifact.parent.mkdir(parents=True, exist_ok=True)
                        if kind == "symlink":
                            artifact.symlink_to(self.profile)
                        else:
                            artifact.hardlink_to(self.profile)
                        self.output.write_text("old report")
                        args = ["--scenario", "example"] if caller is audit.main else []
                        self.assert_profile_collision(caller, self.profile, args)
                        artifact.unlink()

    def test_benchmark_proof_gate_log_cannot_overwrite_profile(self) -> None:
        profile = self.artifacts / "lean-proof-gate.log"
        profile.parent.mkdir(parents=True)
        write_certificate(profile, BOUNDS)
        self.output.write_text("old report")
        self.assert_profile_collision(benchmark.main, profile, [])

    def test_audit_refresh_destination_cannot_overwrite_profile(self) -> None:
        raw = self.root / "Traces/Captured/fixture.ndjson"
        raw.parent.mkdir(parents=True)
        raw.write_bytes(self.raw)
        profile = self.root / "Traces/Certificates/fixture.json"
        profile.parent.mkdir(parents=True)
        write_certificate(profile, BOUNDS)
        self.output.write_text("old report")
        with patch.object(audit, "ROOT", self.root):
            self.assert_profile_collision(
                audit.main,
                profile,
                ["--scenario", "example", "--refresh-demo-certificates"],
            )

    def test_benchmark_report_cannot_replace_trace_or_comparison_fixture(self) -> None:
        trace = self.root / "run.ndjson"
        trace.write_bytes(self.raw)
        comparison = self.root / "Traces/Captured/comparison.ndjson"
        comparison.parent.mkdir(parents=True)
        comparison.write_bytes(self.raw)
        with (
            patch.object(benchmark, "ROOT", self.root),
            patch.object(benchmark, "RUNS", (("example", trace),)),
            patch.object(benchmark, "SCENARIOS", ("comparison",)),
        ):
            for source in (trace, comparison):
                with self.subTest(source=source):
                    self.assert_profile_collision(
                        benchmark.main, self.profile, ["--output", str(source)]
                    )

    def test_audit_report_cannot_replace_scenario_or_driver(self) -> None:
        driver = self.root / "build/raft_driver"
        driver.parent.mkdir()
        driver.write_text("mock driver, never executed")
        for source in (self.scenario_root / "example", driver):
            with self.subTest(source=source):
                self.assert_profile_collision(
                    audit.main,
                    self.profile,
                    ["--scenario", "example", "--output", str(source)],
                )

    def test_benchmark_report_cannot_replace_scenario_or_driver(self) -> None:
        driver = self.root / "build/raft_driver"
        driver.parent.mkdir()
        driver.write_text("mock driver, never executed")
        with (
            patch.object(benchmark, "find_repo_root", return_value=self.root),
            patch.object(benchmark, "SCENARIOS", ("example",)),
        ):
            for source in (self.scenario_root / "example", driver):
                with self.subTest(source=source):
                    self.assert_profile_collision(
                        benchmark.main, self.profile, ["--output", str(source)]
                    )

    def test_audit_report_cannot_replace_a_refresh_source(self) -> None:
        source = self.root / "Traces/Captured/fixture.ndjson"
        source.parent.mkdir(parents=True)
        source.write_bytes(self.raw)
        with patch.object(audit, "ROOT", self.root):
            self.assert_profile_collision(
                audit.main,
                self.profile,
                [
                    "--scenario",
                    "example",
                    "--refresh-demo-certificates",
                    "--output",
                    str(source),
                ],
            )


if __name__ == "__main__":
    unittest.main()
