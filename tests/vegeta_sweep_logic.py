# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import itertools
import json
import os
import subprocess
import tempfile

import infra.vegeta_load as vegeta_load


class FakeNetwork:
    def __init__(self, common_dir):
        self.common_dir = common_dir

    def find_nodes(self):
        return object(), []


class FakeClient:
    def __init__(self, network, config, result):
        self.network = network
        self.config = config
        self.result = result
        prefix = config.output_prefix
        self.targets_path = os.path.join(network.common_dir, f"{prefix}_targets.jsonl")
        self.results_path = os.path.join(network.common_dir, f"{prefix}_results.bin")
        self.report_path = os.path.join(network.common_dir, f"{prefix}_report.json")
        self.attack_stdout_path = os.path.join(
            network.common_dir, f"{prefix}_attack_stdout.log"
        )
        self.attack_stderr_path = os.path.join(
            network.common_dir, f"{prefix}_attack_stderr.log"
        )
        self.report_stderr_path = os.path.join(
            network.common_dir, f"{prefix}_report_stderr.log"
        )

    def artifact_paths(self):
        return {
            "targets_path": self.targets_path,
            "results_path": self.results_path,
            "report_path": self.report_path,
            "attack_stdout_path": self.attack_stdout_path,
            "attack_stderr_path": self.attack_stderr_path,
            "report_stderr_path": self.report_stderr_path,
        }

    def run(self):
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


class PhaseFailureClient(vegeta_load.VegetaLoadClient):
    def __init__(self, network, failure_phase):
        super().__init__(network, vegeta_load.VegetaLoadConfig())
        self.failure_phase = failure_phase

    def _write_targets(self, primary, backups):
        if self.failure_phase == "target_generation":
            raise RuntimeError("target generation failed")

    def _run_attack(self, primary):
        if self.failure_phase == "attack":
            raise subprocess.CalledProcessError(1, ["vegeta", "attack"])
        if self.failure_phase == "missing":
            super()._run_attack(primary)

    def _write_report(self):
        if self.failure_phase == "report":
            raise subprocess.CalledProcessError(1, ["vegeta", "report"])
        if self.failure_phase == "parse":
            with open(self.report_path, "w", encoding="utf-8") as report:
                report.write("not json")


def make_report(desired_rate, throughput):
    return {
        "requests": max(1, int(desired_rate)),
        "rate": desired_rate,
        "throughput": throughput,
        "success": 1,
        "status_codes": {"200": max(1, int(throughput))},
        "errors": [],
    }


def run_fake_sweep(results, config=None):
    config = config or vegeta_load.VegetaSweepConfig()
    results_iter = iter(results)

    def client_factory(network, load_config):
        return FakeClient(network, load_config, next(results_iter))

    with tempfile.TemporaryDirectory() as common_dir:
        network = FakeNetwork(common_dir)
        try:
            summary = vegeta_load.run_sweep(network, config, client_factory)
            raised = None
        except Exception as exc:
            summary = None
            raised = exc
        with open(vegeta_load.sweep_summary_path(network), encoding="utf-8") as f:
            written_summary = json.load(f)
        return summary, raised, written_summary


def expect_raises(fn, expected_exception):
    try:
        fn()
    except expected_exception:
        return
    raise AssertionError(f"Expected {expected_exception}")


def test_desired_rates():
    config = vegeta_load.VegetaSweepConfig()
    assert list(itertools.islice(vegeta_load.desired_rates(config), 6)) == [
        64,
        128,
        256,
        512,
        1024,
        2048,
    ]

    config = vegeta_load.VegetaSweepConfig(start_rate=100)
    assert list(itertools.islice(vegeta_load.desired_rates(config), 3)) == [
        100,
        200,
        400,
    ]


def test_goodput_uses_vegeta_throughput_directly():
    assert vegeta_load.goodput({"throughput": 500.0, "success": 0.5}) == 500.0


def test_numeric_report_validation():
    expect_raises(lambda: vegeta_load.goodput({}), TypeError)
    expect_raises(lambda: vegeta_load.goodput({"throughput": True}), TypeError)
    expect_raises(lambda: vegeta_load.actual_rate({}), TypeError)
    expect_raises(lambda: vegeta_load.actual_rate({"rate": False}), TypeError)


def test_low_goodput_and_reset():
    assert vegeta_load.is_low_goodput(100, 50, 0.5)
    assert not vegeta_load.is_low_goodput(100, 51, 0.5)

    count = 0
    count = vegeta_load.update_low_goodput_count(count, True)
    count = vegeta_load.update_low_goodput_count(count, True)
    count = vegeta_load.update_low_goodput_count(count, False)
    count = vegeta_load.update_low_goodput_count(count, True)
    assert count == 1


def test_stop_example():
    desired = [64, 128, 256, 512, 1024, 2048]
    achieved = [64, 128, 256, 500, 498, 502]
    reports = [make_report(rate, throughput) for rate, throughput in zip(desired, achieved)]

    summary, raised, written_summary = run_fake_sweep(reports)

    assert raised is None
    assert summary["termination_reason"] == vegeta_load.TERMINATION_LOW_GOODPUT
    assert written_summary["termination_reason"] == vegeta_load.TERMINATION_LOW_GOODPUT
    assert [sample["desired_rate"] for sample in summary["samples"]] == desired
    assert summary["peak_goodput"] == 502


def test_non_default_consecutive_low_goodput_count():
    config = vegeta_load.VegetaSweepConfig(consecutive_low_goodput_count=3)
    desired = [64, 128, 256, 512, 1024, 2048, 4096]
    achieved = [64, 128, 256, 500, 498, 502, 499]
    reports = [make_report(rate, throughput) for rate, throughput in zip(desired, achieved)]

    summary, raised, _ = run_fake_sweep(reports, config)

    assert raised is None
    assert [sample["desired_rate"] for sample in summary["samples"]] == desired


def test_actual_rate_underdelivery_writes_summary_before_failure():
    report = make_report(64, 64)
    report["rate"] = 10

    _, raised, summary = run_fake_sweep([report])

    assert isinstance(raised, AssertionError)
    assert summary["termination_reason"] == vegeta_load.TERMINATION_ACTUAL_RATE_UNDERDELIVERED
    assert not summary["pass"]
    assert summary["samples"][0]["actual_rate_underdelivered"]


def test_request_errors_are_coalesced_like_http_errors():
    reports = []
    for desired_rate in (64, 128):
        report = make_report(desired_rate, 0)
        report["status_codes"] = {"0": desired_rate}
        report["errors"] = ["dial tcp connection refused"]
        reports.append(report)

    summary, raised, written_summary = run_fake_sweep(reports)

    assert raised is None
    assert summary["termination_reason"] == vegeta_load.TERMINATION_LOW_GOODPUT
    assert written_summary["termination_reason"] == vegeta_load.TERMINATION_LOW_GOODPUT
    assert summary["samples"][0]["request_errors"] == ["dial tcp connection refused"]


def test_malformed_report_writes_summary_before_failure():
    _, raised, summary = run_fake_sweep([{"requests": 1, "throughput": 1}])

    assert isinstance(raised, vegeta_load.VegetaLoadFailure)
    assert raised.kind == vegeta_load.TERMINATION_MALFORMED_REPORT
    assert summary["termination_reason"] == vegeta_load.TERMINATION_MALFORMED_REPORT
    assert summary["samples"][0]["invalid_report_field"] == "rate"


def test_pre_report_failures_write_summary_before_failure():
    for failure_kind in [
        vegeta_load.VEGETA_MISSING,
        vegeta_load.TARGET_GENERATION_FAILED,
        vegeta_load.VEGETA_ATTACK_FAILED,
        vegeta_load.VEGETA_REPORT_FAILED,
        vegeta_load.VEGETA_REPORT_PARSE_FAILED,
    ]:
        failure = vegeta_load.VegetaLoadFailure(
            failure_kind,
            f"{failure_kind} message",
            paths={"report_path": f"/{failure_kind}.json"},
        )
        _, raised, summary = run_fake_sweep([failure])

        assert isinstance(raised, vegeta_load.VegetaLoadFailure)
        assert summary["termination_reason"] == failure_kind
        assert summary["samples"][0]["desired_rate"] == 64
        assert summary["samples"][0]["report_path"] == f"/{failure_kind}.json"


def test_vegeta_load_client_phase_classification():
    with tempfile.TemporaryDirectory() as common_dir:
        network = FakeNetwork(common_dir)

        cases = [
            ("target_generation", vegeta_load.TARGET_GENERATION_FAILED),
            ("attack", vegeta_load.VEGETA_ATTACK_FAILED),
            ("report", vegeta_load.VEGETA_REPORT_FAILED),
            ("parse", vegeta_load.VEGETA_REPORT_PARSE_FAILED),
        ]
        for phase, expected_kind in cases:
            client = PhaseFailureClient(network, phase)
            try:
                client.run()
            except vegeta_load.VegetaLoadFailure as exc:
                assert exc.kind == expected_kind
            else:
                raise AssertionError(f"Expected VegetaLoadFailure for {phase}")

        old_which = vegeta_load.shutil.which
        vegeta_load.shutil.which = lambda _: None
        try:
            client = PhaseFailureClient(network, "missing")
            try:
                client.run()
            except vegeta_load.VegetaLoadFailure as exc:
                assert exc.kind == vegeta_load.VEGETA_MISSING
            else:
                raise AssertionError("Expected VegetaLoadFailure for missing vegeta")
        finally:
            vegeta_load.shutil.which = old_which


def test_invalid_sweep_config():
    invalid_kwargs = [
        {"start_rate": 0},
        {"duration": 0},
        {"timeout": 0},
        {"low_goodput_ratio": 0},
        {"low_goodput_ratio": 1.1},
        {"consecutive_low_goodput_count": 0},
        {"actual_rate_floor_ratio": 0},
        {"actual_rate_floor_ratio": 1.1},
    ]
    for kwargs in invalid_kwargs:
        expect_raises(lambda kwargs=kwargs: vegeta_load.VegetaSweepConfig(**kwargs), ValueError)


if __name__ == "__main__":
    test_desired_rates()
    test_goodput_uses_vegeta_throughput_directly()
    test_numeric_report_validation()
    test_low_goodput_and_reset()
    test_stop_example()
    test_non_default_consecutive_low_goodput_count()
    test_actual_rate_underdelivery_writes_summary_before_failure()
    test_request_errors_are_coalesced_like_http_errors()
    test_malformed_report_writes_summary_before_failure()
    test_pre_report_failures_write_summary_before_failure()
    test_vegeta_load_client_phase_classification()
    test_invalid_sweep_config()
