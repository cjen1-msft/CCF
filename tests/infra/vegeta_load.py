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
DEFAULT_DURATION_S = 30
DEFAULT_TIMEOUT_S = 10
DEFAULT_ENDPOINT = "/app/log/blocking/private?scope=load"
DEFAULT_PREFIX = "vegeta_load"
TARGET_SAFETY_MARGIN = 1.1


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

    def _vegeta_path(self):
        vegeta_path = shutil.which("vegeta")
        if vegeta_path is None:
            raise RuntimeError("Could not find 'vegeta' in PATH")
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
        self._write_targets(primary, backups)
        self._run_attack(primary)
        self._write_report()
        with open(self.report_path, encoding="utf-8") as report:
            return json.load(report)


def _is_http_error(error, status_codes):
    return any(error.startswith(f"{status_code} ") for status_code in status_codes)


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
    errors = report.get("errors", [])
    summary = report_summary(report)

    requests = report.get("requests", 0)
    assert requests > 0, f"Vegeta did not issue any requests: {summary}"

    if allowed_status_codes is not None:
        unexpected_status_codes = set(status_codes) - allowed_status_codes
        assert not unexpected_status_codes, (
            f"Vegeta reported unexpected status codes: {unexpected_status_codes}; "
            f"summary: {summary}"
        )

    transport_errors = [
        error for error in errors if not _is_http_error(error, status_codes)
    ]
    assert transport_errors == [], (
        f"Vegeta reported transport/load-generator errors: {transport_errors}; "
        f"summary: {summary}"
    )
