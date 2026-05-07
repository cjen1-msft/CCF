# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import base64
import dataclasses
import json
import math
import os
import shutil
import subprocess
from enum import Enum, auto
from typing import FrozenSet, Optional

from loguru import logger as LOG

DEFAULT_REQUEST_RATE_S = 100
DEFAULT_START_RATE_S = 64
DEFAULT_DURATION_S = 30
DEFAULT_TIMEOUT_S = 10
DEFAULT_LOW_GOODPUT_RATIO = 0.5
DEFAULT_CONSECUTIVE_LOW_GOODPUT_COUNT = 2
DEFAULT_ACTUAL_RATE_FLOOR_RATIO = 0.9
DEFAULT_ENDPOINT = "/app/log/blocking/private?scope=load"
DEFAULT_PREFIX = "vegeta_load"
SWEEP_SUMMARY_FILE_NAME = "vegeta_load_sweep_summary.json"
TARGET_SAFETY_MARGIN = 1.1

TERMINATION_LOW_GOODPUT = "low_goodput"
TERMINATION_ACTUAL_RATE_UNDERDELIVERED = "actual_rate_underdelivered"
TERMINATION_MALFORMED_REPORT = "malformed_report"

VEGETA_MISSING = "vegeta_missing"
TARGET_GENERATION_FAILED = "target_generation_failed"
VEGETA_ATTACK_FAILED = "vegeta_attack_failed"
VEGETA_REPORT_FAILED = "vegeta_report_failed"
VEGETA_REPORT_PARSE_FAILED = "vegeta_report_parse_failed"


class LoadStrategy(Enum):
    PRIMARY = auto()
    ALL = auto()
    ANY_BACKUP = auto()
    SINGLE = auto()


def make_target_host(target_node):
    return f"https://{target_node.get_public_rpc_host()}:{target_node.get_public_rpc_port()}"


@dataclasses.dataclass(frozen=True)
class VegetaLoadConfig:
    rate: int = DEFAULT_REQUEST_RATE_S
    duration: int = DEFAULT_DURATION_S
    timeout: int = DEFAULT_TIMEOUT_S
    method: str = "POST"
    endpoint: str = DEFAULT_ENDPOINT
    strategy: LoadStrategy = LoadStrategy.PRIMARY
    target_node: object = None
    allowed_status_codes: Optional[FrozenSet[str]] = None
    output_prefix: str = DEFAULT_PREFIX

    def __post_init__(self):
        object.__setattr__(
            self,
            "allowed_status_codes",
            (
                None
                if self.allowed_status_codes is None
                else frozenset(str(code) for code in self.allowed_status_codes)
            ),
        )
        if not self.method:
            raise ValueError("Vegeta method must be non-empty")
        if self.rate <= 0:
            raise ValueError("Vegeta rate must be positive")
        if self.duration <= 0:
            raise ValueError("Vegeta duration must be positive")
        if self.timeout <= 0:
            raise ValueError("Vegeta timeout must be positive")
        if not self.endpoint.startswith("/"):
            raise ValueError("Vegeta endpoint must start with '/'")
        if self.allowed_status_codes is not None and not self.allowed_status_codes:
            raise ValueError("Vegeta allowed_status_codes must be non-empty when set")
        if self.strategy == LoadStrategy.SINGLE and self.target_node is None:
            raise ValueError("Vegeta SINGLE target strategy requires target_node")


@dataclasses.dataclass(frozen=True)
class VegetaSweepConfig:
    start_rate: int = DEFAULT_START_RATE_S
    duration: int = DEFAULT_DURATION_S
    timeout: int = DEFAULT_TIMEOUT_S
    low_goodput_ratio: float = DEFAULT_LOW_GOODPUT_RATIO
    consecutive_low_goodput_count: int = DEFAULT_CONSECUTIVE_LOW_GOODPUT_COUNT
    actual_rate_floor_ratio: float = DEFAULT_ACTUAL_RATE_FLOOR_RATIO

    def __post_init__(self):
        if self.start_rate <= 0:
            raise ValueError("Vegeta sweep start_rate must be positive")
        if self.duration <= 0:
            raise ValueError("Vegeta sweep duration must be positive")
        if self.timeout <= 0:
            raise ValueError("Vegeta sweep timeout must be positive")
        if not 0 < self.low_goodput_ratio <= 1:
            raise ValueError("Vegeta sweep low_goodput_ratio must be in (0, 1]")
        if self.consecutive_low_goodput_count <= 0:
            raise ValueError(
                "Vegeta sweep consecutive_low_goodput_count must be positive"
            )
        if not 0 < self.actual_rate_floor_ratio <= 1:
            raise ValueError("Vegeta sweep actual_rate_floor_ratio must be in (0, 1]")


class VegetaLoadFailure(Exception):
    def __init__(self, kind, message, paths=None, original=None):
        self.kind = kind
        self.message = message
        self.paths = paths or {}
        self.original = original
        super().__init__(f"{kind}: {message}")


def _in_common_dir(network, file_name):
    return os.path.join(network.common_dir, file_name)


def _target_count(config):
    return math.ceil(config.rate * config.duration * TARGET_SAFETY_MARGIN)


def _make_target_url(node, endpoint):
    return f"{make_target_host(node)}{endpoint}"


def _target_nodes(config, primary, backups):
    if config.strategy == LoadStrategy.PRIMARY:
        return [primary]
    if config.strategy == LoadStrategy.ALL:
        return [primary] + backups
    if config.strategy == LoadStrategy.ANY_BACKUP:
        if not backups:
            raise ValueError("Vegeta ANY_BACKUP target strategy requires a backup")
        return [backups[0]]
    if config.strategy == LoadStrategy.SINGLE:
        return [config.target_node]
    raise ValueError(f"Unsupported Vegeta load strategy: {config.strategy}")


def _make_logging_body(message_id):
    return {
        "id": message_id,
        "msg": f"Vegeta load message {message_id}",
    }


def _make_target(method, url, body):
    return {
        "method": method,
        "url": url,
        "header": {"Content-Type": ["application/json"]},
        "body": base64.b64encode(json.dumps(body).encode()).decode(),
    }


class VegetaLoadClient:
    def __init__(self, network, config=None):
        self.network = network
        self.config = config or VegetaLoadConfig()
        self.targets_path = _in_common_dir(
            self.network, f"{self.config.output_prefix}_targets.jsonl"
        )
        self.results_path = _in_common_dir(
            self.network, f"{self.config.output_prefix}_results.bin"
        )
        self.report_path = _in_common_dir(
            self.network, f"{self.config.output_prefix}_report.json"
        )
        self.attack_stdout_path = _in_common_dir(
            self.network, f"{self.config.output_prefix}_attack_stdout.log"
        )
        self.attack_stderr_path = _in_common_dir(
            self.network, f"{self.config.output_prefix}_attack_stderr.log"
        )
        self.report_stderr_path = _in_common_dir(
            self.network, f"{self.config.output_prefix}_report_stderr.log"
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

    def _vegeta_path(self):
        vegeta_path = shutil.which("vegeta")
        if vegeta_path is None:
            raise VegetaLoadFailure(
                VEGETA_MISSING,
                "Could not find 'vegeta' in PATH",
                paths=self.artifact_paths(),
            )
        return vegeta_path

    def _write_targets(self, primary, backups):
        nodes = _target_nodes(self.config, primary, backups)
        count = _target_count(self.config)
        with open(self.targets_path, "w", encoding="utf-8") as targets_file:
            for i in range(count):
                node = nodes[i % len(nodes)]
                target = _make_target(
                    self.config.method,
                    _make_target_url(node, self.config.endpoint),
                    _make_logging_body(i),
                )
                targets_file.write(json.dumps(target))
                targets_file.write("\n")
        LOG.info(f"Wrote {count} Vegeta targets to {self.targets_path}")

    def _run_attack(self, primary):
        vegeta_path = self._vegeta_path()
        session_auth = primary.session_auth("user0")["session_auth"]
        cmd = [
            vegeta_path,
            "attack",
            "-format=json",
            f"-rate={self.config.rate}/1s",
            f"-duration={self.config.duration}s",
            f"-timeout={self.config.timeout}s",
            f"-targets={self.targets_path}",
            f"-output={self.results_path}",
            "-max-body=0",
            f"-cert={session_auth.cert}",
            f"-key={session_auth.key}",
            f"-root-certs={primary.session_ca()['ca']}",
            "-http2=false",
        ]
        LOG.info(f"Starting Vegeta: {' '.join(cmd)}")
        with open(self.attack_stdout_path, "w", encoding="utf-8") as stdout, open(
            self.attack_stderr_path, "w", encoding="utf-8"
        ) as stderr:
            subprocess.run(cmd, stdout=stdout, stderr=stderr, check=True)

    def _write_report(self):
        vegeta_path = self._vegeta_path()
        cmd = [vegeta_path, "report", "-type=json"]
        with open(self.results_path, "rb") as results, open(
            self.report_path, "w", encoding="utf-8"
        ) as report, open(self.report_stderr_path, "w", encoding="utf-8") as stderr:
            subprocess.run(
                cmd, stdin=results, stdout=report, stderr=stderr, check=True
            )

    def run(self):
        primary, backups = self.network.find_nodes()
        try:
            self._write_targets(primary, backups)
        except VegetaLoadFailure:
            raise
        except Exception as exc:
            raise VegetaLoadFailure(
                TARGET_GENERATION_FAILED,
                str(exc),
                paths=self.artifact_paths(),
                original=exc,
            ) from exc

        try:
            self._run_attack(primary)
        except VegetaLoadFailure:
            raise
        except Exception as exc:
            raise VegetaLoadFailure(
                VEGETA_ATTACK_FAILED,
                str(exc),
                paths=self.artifact_paths(),
                original=exc,
            ) from exc

        try:
            self._write_report()
        except VegetaLoadFailure:
            raise
        except Exception as exc:
            raise VegetaLoadFailure(
                VEGETA_REPORT_FAILED,
                str(exc),
                paths=self.artifact_paths(),
                original=exc,
            ) from exc

        try:
            with open(self.report_path, encoding="utf-8") as report:
                return json.load(report)
        except Exception as exc:
            raise VegetaLoadFailure(
                VEGETA_REPORT_PARSE_FAILED,
                str(exc),
                paths=self.artifact_paths(),
                original=exc,
            ) from exc


def report_summary(report):
    status_codes = report.get("status_codes", {})
    errors = report.get("errors", [])
    latencies = report.get("latencies", {})
    return {
        "requests": report.get("requests", 0),
        "rate": report.get("rate"),
        "throughput": report.get("throughput"),
        "success": report.get("success"),
        "status_codes": status_codes,
        "errors": errors,
        "latencies": {
            "mean": latencies.get("mean"),
            "50th": latencies.get("50th"),
            "95th": latencies.get("95th"),
            "99th": latencies.get("99th"),
            "max": latencies.get("max"),
        },
    }


def assert_accepted_report(report, allowed_status_codes=None):
    status_codes = report.get("status_codes", {})
    summary = report_summary(report)

    requests = report.get("requests", 0)
    assert requests > 0, f"Vegeta did not issue any requests: {summary}"

    if allowed_status_codes is not None:
        unexpected_status_codes = set(status_codes) - allowed_status_codes
        assert not unexpected_status_codes, (
            f"Vegeta reported unexpected status codes: {unexpected_status_codes}; "
            f"summary: {summary}"
        )



def desired_rates(config):
    rate = config.start_rate
    while True:
        yield rate
        rate *= 2


def _required_number(report, field):
    value = report.get(field)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"Vegeta report field '{field}' must be numeric: {report}")
    return value


def goodput(report):
    return _required_number(report, "throughput")


def actual_rate(report):
    return _required_number(report, "rate")


def is_low_goodput(desired_rate, achieved_goodput, ratio):
    return achieved_goodput <= desired_rate * ratio


def is_actual_rate_underdelivered(desired_rate, achieved_actual_rate, floor_ratio):
    return achieved_actual_rate < desired_rate * floor_ratio


def update_low_goodput_count(previous_count, is_low):
    return previous_count + 1 if is_low else 0


def sweep_summary_path(network):
    return _in_common_dir(network, SWEEP_SUMMARY_FILE_NAME)


def _write_sweep_summary(network, summary):
    path = sweep_summary_path(network)
    with open(path, "w", encoding="utf-8") as summary_file:
        json.dump(summary, summary_file, indent=2)
    return path


def _peak_goodput(samples):
    goodputs = [sample.get("goodput") for sample in samples]
    numeric_goodputs = [
        sample_goodput
        for sample_goodput in goodputs
        if isinstance(sample_goodput, (int, float)) and not isinstance(sample_goodput, bool)
    ]
    return max(numeric_goodputs) if numeric_goodputs else None


def _sample_from_failure(sample_index, desired_rate, failure, client):
    paths = failure.paths or client.artifact_paths()
    return {
        "sample_index": sample_index,
        "desired_rate": desired_rate,
        "termination_reason": failure.kind,
        "pass": False,
        "failure_message": failure.message,
        **paths,
    }


def _sample_from_report(
    sample_index,
    desired_rate,
    report,
    client,
    achieved_actual_rate,
    achieved_goodput,
    low_goodput,
    actual_rate_underdelivered,
    invalid_report_field=None,
):
    summary = report_summary(report)
    return {
        "sample_index": sample_index,
        "desired_rate": desired_rate,
        "actual_rate": achieved_actual_rate,
        "throughput": achieved_goodput,
        "goodput": achieved_goodput,
        "success": report.get("success"),
        "goodput_to_desired_ratio": (
            achieved_goodput / desired_rate if achieved_goodput is not None else None
        ),
        "low_goodput": low_goodput,
        "actual_rate_underdelivered": actual_rate_underdelivered,
        "request_errors": summary["errors"],
        "invalid_report_field": invalid_report_field,
        "status_codes": summary["status_codes"],
        "errors": summary["errors"],
        **client.artifact_paths(),
    }


def _finalize_summary(summary, termination_reason, passed):
    summary["termination_reason"] = termination_reason
    summary["pass"] = passed
    summary["peak_goodput"] = _peak_goodput(summary["samples"])
    return summary


def run_sweep(network, config, client_factory=VegetaLoadClient):
    summary = {
        "termination_reason": None,
        "pass": None,
        "peak_goodput": None,
        "samples": [],
    }
    consecutive_low_goodput = 0

    for sample_index, desired_rate in enumerate(desired_rates(config)):
        load_config = VegetaLoadConfig(
            rate=desired_rate,
            duration=config.duration,
            timeout=config.timeout,
            output_prefix=f"{DEFAULT_PREFIX}_{sample_index:03d}_desired_{desired_rate}",
        )
        client = client_factory(network, load_config)

        try:
            report = client.run()
        except VegetaLoadFailure as exc:
            summary["samples"].append(
                _sample_from_failure(sample_index, desired_rate, exc, client)
            )
            _finalize_summary(summary, exc.kind, False)
            _write_sweep_summary(network, summary)
            raise

        try:
            achieved_actual_rate = actual_rate(report)
            achieved_goodput = goodput(report)
        except (TypeError, ValueError) as exc:
            invalid_report_field = "rate" if "'rate'" in str(exc) else "throughput"
            failure = VegetaLoadFailure(
                TERMINATION_MALFORMED_REPORT,
                str(exc),
                paths=client.artifact_paths(),
                original=exc,
            )
            summary["samples"].append(
                _sample_from_report(
                    sample_index,
                    desired_rate,
                    report,
                    client,
                    None,
                    None,
                    None,
                    False,
                    invalid_report_field=invalid_report_field,
                )
            )
            summary["samples"][-1]["termination_reason"] = failure.kind
            summary["samples"][-1]["pass"] = False
            summary["samples"][-1]["failure_message"] = failure.message
            _finalize_summary(summary, failure.kind, False)
            _write_sweep_summary(network, summary)
            raise failure from exc

        low_goodput = is_low_goodput(
            desired_rate, achieved_goodput, config.low_goodput_ratio
        )
        actual_rate_underdelivered = is_actual_rate_underdelivered(
            desired_rate, achieved_actual_rate, config.actual_rate_floor_ratio
        )
        summary["samples"].append(
            _sample_from_report(
                sample_index,
                desired_rate,
                report,
                client,
                achieved_actual_rate,
                achieved_goodput,
                low_goodput,
                actual_rate_underdelivered,
            )
        )

        if actual_rate_underdelivered:
            _finalize_summary(summary, TERMINATION_ACTUAL_RATE_UNDERDELIVERED, False)
            _write_sweep_summary(network, summary)
            raise AssertionError(
                f"Vegeta actual issue rate {achieved_actual_rate} was below "
                f"{config.actual_rate_floor_ratio:.2f} of desired rate {desired_rate}"
            )

        consecutive_low_goodput = update_low_goodput_count(
            consecutive_low_goodput, low_goodput
        )
        if consecutive_low_goodput >= config.consecutive_low_goodput_count:
            _finalize_summary(summary, TERMINATION_LOW_GOODPUT, True)
            _write_sweep_summary(network, summary)
            return summary

        _write_sweep_summary(network, summary)

    raise RuntimeError("Unreachable: desired_rates is an infinite generator")
