# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import base64
import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import vegeta_logging_jwt


class VegetaLoggingJwtTests(unittest.TestCase):
    def test_summarise_results_uses_completion_window_for_throughput(self):
        results = [
            {
                "timestamp": "2026-08-17T12:00:00.000000000Z",
                "latency": 100_000_000,
                "code": 200,
                "error": "",
            },
            {
                "timestamp": "2026-08-17T12:00:29.900000000Z",
                "latency": 200_000_000,
                "code": 200,
                "error": "",
            },
            {
                "timestamp": "2026-08-17T12:00:01.000000000Z",
                "latency": 50_000_000,
                "code": 503,
                "error": "",
            },
            {
                "timestamp": "2026-08-17T12:00:02.000000000Z",
                "latency": 10_000_000_000,
                "code": 0,
                "error": "Get: context deadline exceeded",
            },
        ]

        summary = vegeta_logging_jwt.summarise_results(
            results, duration_s=30, target_rate=1
        )

        self.assertEqual(summary["requests"], 4)
        self.assertAlmostEqual(summary["actual_issue_rate"], 4 / 30)
        self.assertAlmostEqual(summary["achieved_throughput"], 1 / 30)
        self.assertEqual(summary["successful_requests"], 2)
        self.assertEqual(summary["successful_in_window"], 1)
        self.assertEqual(summary["peak_concurrency"], 1)
        self.assertEqual(summary["status_counts"], {"0": 1, "200": 2, "503": 1})
        self.assertEqual(summary["errors"], {"timeout": 1})
        self.assertEqual(summary["timeouts"], 1)
        self.assertEqual(summary["successful_latencies_ns"], [100_000_000, 200_000_000])

    def test_summarise_results_reports_peak_concurrency(self):
        results = [
            {
                "timestamp": "2026-08-17T12:00:00.000000000Z",
                "latency": 10_000_000_000,
                "code": 200,
                "error": "",
            },
            {
                "timestamp": "2026-08-17T12:00:01.000000000Z",
                "latency": 10_000_000_000,
                "code": 200,
                "error": "",
            },
        ]

        summary = vegeta_logging_jwt.summarise_results(
            results, duration_s=30, target_rate=1
        )

        self.assertEqual(summary["peak_concurrency"], 2)

    def test_summarise_results_rejects_malformed_records(self):
        with self.assertRaisesRegex(ValueError, "timestamp"):
            vegeta_logging_jwt.summarise_results(
                [{"code": 200, "latency": 1, "error": ""}],
                duration_s=30,
                target_rate=1,
            )

    def test_stop_after_two_consecutive_half_rate_points(self):
        points = [
            {"target_rate": 64, "achieved_throughput": 50},
            {"target_rate": 128, "achieved_throughput": 64},
        ]
        self.assertFalse(vegeta_logging_jwt.should_stop_sweep(points))

        points.append({"target_rate": 256, "achieved_throughput": 100})
        self.assertTrue(vegeta_logging_jwt.should_stop_sweep(points))

    def test_sweep_rates_use_cube_root_of_two_steps(self):
        self.assertEqual(
            [vegeta_logging_jwt.sweep_rate(64, step) for step in range(7)],
            [64, 81, 102, 128, 161, 203, 256],
        )

    def test_waits_until_target_connections_are_released(self):
        with (
            mock.patch.object(
                vegeta_logging_jwt,
                "_count_target_sockets",
                side_effect=[2, 1, 0],
            ),
            mock.patch.object(vegeta_logging_jwt.time, "monotonic", return_value=0),
            mock.patch.object(vegeta_logging_jwt.time, "sleep") as sleep,
        ):
            vegeta_logging_jwt.wait_for_port_release(
                "https://127.0.0.1:8000", timeout_s=70
            )

        self.assertEqual(sleep.call_count, 2)

    def test_counts_sockets_for_target_address(self):
        with tempfile.TemporaryDirectory() as directory:
            proc_path = Path(directory) / "tcp"
            proc_path.write_text(
                "sl local_address rem_address st\n"
                "0: 0100007F:C350 0100007F:1F40 06\n"
                "1: 0100007F:C351 0100007F:1F41 06\n",
                encoding="ascii",
            )

            count = vegeta_logging_jwt._count_target_sockets(
                "https://127.0.0.1:8000", proc_path
            )

        self.assertEqual(count, 1)

    def test_attack_command_caps_vegeta_workers(self):
        command = vegeta_logging_jwt.make_attack_command(
            Path("targets.json"),
            Path("service_cert.pem"),
            Path("results.bin"),
            target_rate=1290,
            duration_s=30,
            timeout_s=10,
            max_workers=10_000,
        )

        self.assertIn("-max-workers=10000", command)

    def test_targets_cycle_tokens_without_cartesian_product(self):
        targets = vegeta_logging_jwt.make_targets(
            "https://127.0.0.1:8000",
            [{"id": 1, "msg": "one"}, {"id": 2, "msg": "two"}],
            ["token-a", "token-b", "token-c"],
        )

        self.assertEqual(len(targets), 2)
        self.assertEqual(
            [target["header"]["Authorization"][0] for target in targets],
            ["Bearer token-a", "Bearer token-b"],
        )
        self.assertEqual(
            [json.loads(base64.b64decode(target["body"]))["id"] for target in targets],
            [1, 2],
        )
        self.assertTrue(
            all(
                target["url"].endswith("/app/log/blocking/private/receipt")
                for target in targets
            )
        )

    def test_targets_require_bodies_and_tokens(self):
        with self.assertRaisesRegex(ValueError, "body"):
            vegeta_logging_jwt.make_targets("https://localhost", [], ["token"])
        with self.assertRaisesRegex(ValueError, "token"):
            vegeta_logging_jwt.make_targets(
                "https://localhost", [{"id": 1, "msg": "one"}], []
            )

    def test_errors_are_grouped_into_stable_categories(self):
        errors = [
            'Post "https://localhost": EOF',
            'Post "https://localhost": context deadline exceeded',
            ("dial tcp 0.0.0.0:0->127.0.0.1:8000: " "bind: address already in use"),
            "read tcp 127.0.0.1:1234: connection reset by peer",
            "503 SERVICE_UNAVAILABLE",
        ]

        self.assertEqual(
            [vegeta_logging_jwt.classify_error(error) for error in errors],
            [
                "eof",
                "timeout",
                "local_address_exhausted",
                "connection_reset",
                "http_503",
            ],
        )

    def test_write_targets_restricts_sensitive_file_permissions(self):
        targets = vegeta_logging_jwt.make_targets(
            "https://localhost", [{"id": 1, "msg": "one"}], ["token"]
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "targets.json"
            vegeta_logging_jwt.write_targets(path, targets)

            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(
                [json.loads(line) for line in path.read_text().splitlines()], targets
            )

    @unittest.skipUnless(
        vegeta_logging_jwt.plotting_available(), "matplotlib and numpy are required"
    )
    def test_plot_sweep_writes_two_panel_svg(self):
        points = [
            {
                "target_rate": 64,
                "achieved_throughput": 60,
                "successful_latencies_ns": [10_000_000, 20_000_000, 30_000_000],
            },
            {
                "target_rate": 128,
                "achieved_throughput": 70,
                "successful_latencies_ns": [20_000_000, 40_000_000, 80_000_000],
            },
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sweep.svg"
            vegeta_logging_jwt.plot_sweep(points, path, max_workers=10_000)

            svg = path.read_text()
            self.assertIn("Achieved rate (req/s)", svg)
            self.assertIn("Latency (ms, symlog)", svg)
            self.assertIn("Target rate of test (requests/s)", svg)
            self.assertIn("Target throughput compared to achieved throughput", svg)
            self.assertIn("Latency distribution at each target throughput", svg)
            self.assertIn("Vegeta max workers: 10,000", svg)
            self.assertGreater(os.path.getsize(path), 1000)

    @unittest.skipUnless(
        vegeta_logging_jwt.plotting_available(), "matplotlib and numpy are required"
    )
    def test_zero_success_point_still_produces_plot(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sweep.svg"
            vegeta_logging_jwt.plot_sweep(
                [
                    {
                        "target_rate": 64,
                        "achieved_throughput": 0,
                        "successful_latencies_ns": [],
                    }
                ],
                path,
            )

            self.assertIn("No successful responses", path.read_text())
            self.assertGreater(os.path.getsize(path), 1000)

    def test_zero_success_point_prints_na_percentiles(self):
        points = [
            {
                "target_rate": 64,
                "achieved_throughput": 0,
                "successful_latencies_ns": [],
                "latency_percentiles_ms": {
                    "p50": None,
                    "p90": None,
                    "p99": None,
                },
                "status_counts": {"0": 1920},
                "errors": {"context deadline exceeded": 1920},
                "timeouts": 1920,
            }
        ]
        with contextlib.redirect_stdout(io.StringIO()) as output:
            vegeta_logging_jwt._print_interpretation(
                points, "two_consecutive_half_rate_points"
            )

        self.assertIn("p50=N/A", output.getvalue())


if __name__ == "__main__":
    unittest.main()
