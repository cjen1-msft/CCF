# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import base64
import copy
import importlib.util
import ipaddress
import json
import os
import re
import shutil
import ssl
import subprocess
import time
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit
from uuid import UUID

RECEIPT_PATH = "/app/log/blocking/private/receipt"
NANOSECONDS_PER_SECOND = 1_000_000_000
DEFAULT_INITIAL_RATE = 64
DEFAULT_DURATION_S = 30
DEFAULT_TIMEOUT_S = 10
DEFAULT_PORT_RELEASE_TIMEOUT_S = 70
TARGET_BODY_COUNT = 100
SYNTHETIC_TENANT_ID = UUID("00000000-0000-4000-8000-000000000001")
SYNTHETIC_ISSUER = f"https://login.microsoftonline.com/{SYNTHETIC_TENANT_ID}/v2.0"
_TIMESTAMP_RE = re.compile(
    r"^(?P<seconds>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"
    r"(?:\.(?P<fraction>\d{1,9}))?Z$"
)


def _timestamp_ns(value):
    if not isinstance(value, str):
        raise TypeError("Vegeta result timestamp must be a string")

    match = _TIMESTAMP_RE.fullmatch(value)
    if match is None:
        raise ValueError(f"Invalid Vegeta result timestamp: {value!r}")

    seconds = datetime.strptime(match.group("seconds"), "%Y-%m-%dT%H:%M:%S").replace(
        tzinfo=timezone.utc
    )
    fraction = (match.group("fraction") or "").ljust(9, "0")
    return int(seconds.timestamp()) * NANOSECONDS_PER_SECOND + int(fraction or 0)


def _percentile(values, percentile):
    if not values:
        return None
    ordered = sorted(values)
    rank = (len(ordered) - 1) * percentile
    lower = int(rank)
    upper = min(lower + 1, len(ordered) - 1)
    weight = rank - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def classify_error(error):
    lower_error = error.lower()
    if "address already in use" in lower_error:
        return "local_address_exhausted"
    if "timeout" in lower_error or "deadline exceeded" in lower_error:
        return "timeout"
    if "connection reset by peer" in lower_error:
        return "connection_reset"
    if lower_error.endswith("eof"):
        return "eof"
    if error.startswith("503 "):
        return "http_503"
    return error


def summarise_results(results, duration_s, target_rate):
    if duration_s <= 0:
        raise ValueError("duration_s must be positive")
    if target_rate <= 0:
        raise ValueError("target_rate must be positive")
    if not results:
        raise ValueError("Vegeta produced no results")

    parsed = []
    for result in results:
        try:
            timestamp_ns = _timestamp_ns(result["timestamp"])
            latency_ns = result["latency"]
            code = result["code"]
            error = result.get("error", "")
        except KeyError as exc:
            raise ValueError(f"Malformed Vegeta result missing {exc.args[0]}") from exc
        if not isinstance(latency_ns, int):
            raise TypeError("Vegeta result latency must be an integer")
        if latency_ns < 0:
            raise ValueError("Vegeta result latency must be a non-negative integer")
        if not isinstance(code, int):
            raise TypeError("Vegeta result code must be an integer")
        if not isinstance(error, str):
            raise TypeError("Vegeta result error must be a string")
        parsed.append((timestamp_ns, latency_ns, code, error))

    attack_start_ns = min(result[0] for result in parsed)
    attack_end_ns = attack_start_ns + duration_s * NANOSECONDS_PER_SECOND
    launched = [result for result in parsed if result[0] < attack_end_ns]
    successful = [result for result in launched if result[2] == 200 and not result[3]]
    successful_in_window = [
        result for result in successful if result[0] + result[1] <= attack_end_ns
    ]
    latencies = [result[1] for result in successful]
    raw_errors = Counter(result[3] for result in launched if result[3])
    errors = Counter()
    for error, count in raw_errors.items():
        errors[classify_error(error)] += count
    statuses = Counter(str(result[2]) for result in launched)

    actual_issue_rate = len(launched) / duration_s
    return {
        "target_rate": target_rate,
        "duration_s": duration_s,
        "requests": len(launched),
        "actual_issue_rate": actual_issue_rate,
        "generator_valid": actual_issue_rate >= target_rate * 0.9,
        "achieved_throughput": len(successful_in_window) / duration_s,
        "successful_requests": len(successful),
        "successful_in_window": len(successful_in_window),
        "status_counts": dict(sorted(statuses.items())),
        "errors": dict(sorted(errors.items())),
        "timeouts": sum(
            count
            for error, count in raw_errors.items()
            if "timeout" in error.lower() or "deadline exceeded" in error.lower()
        ),
        "successful_latencies_ns": latencies,
        "latency_percentiles_ms": {
            name: (percentile_ns / 1_000_000 if percentile_ns is not None else None)
            for name, percentile_ns in (
                ("p50", _percentile(latencies, 0.50)),
                ("p90", _percentile(latencies, 0.90)),
                ("p99", _percentile(latencies, 0.99)),
            )
        },
    }


def should_stop_sweep(points):
    if len(points) < 2:
        return False
    return all(
        point["achieved_throughput"] <= point["target_rate"] * 0.5
        for point in points[-2:]
    )


def sweep_rate(initial_rate, step):
    if initial_rate <= 0:
        raise ValueError("initial_rate must be positive")
    if step < 0:
        raise ValueError("step must be non-negative")
    return round(initial_rate * 2 ** (step / 3))


def _count_target_sockets(base_url, proc_path=Path("/proc/net/tcp")):
    parsed_url = urlsplit(base_url)
    if parsed_url.hostname is None or parsed_url.port is None:
        raise ValueError(f"URL has no host and port: {base_url}")
    address = ipaddress.IPv4Address(parsed_url.hostname)
    proc_address = address.packed[::-1].hex().upper()
    remote = f"{proc_address}:{parsed_url.port:04X}"
    return sum(
        line.split()[2] == remote
        for line in proc_path.read_text(encoding="ascii").splitlines()[1:]
    )


def wait_for_port_release(base_url, timeout_s):
    if timeout_s <= 0:
        raise ValueError("Port release timeout must be positive")
    deadline = time.monotonic() + timeout_s
    while (socket_count := _count_target_sockets(base_url)) > 0:
        if time.monotonic() >= deadline:
            raise TimeoutError(
                f"{socket_count} client sockets for {base_url} remain after "
                f"{timeout_s}s"
            )
        time.sleep(1)


def make_targets(base_url, bodies, tokens):
    if not bodies:
        raise ValueError("At least one request body is required")
    if not tokens:
        raise ValueError("At least one bearer token is required")

    return [
        {
            "method": "POST",
            "url": base_url.rstrip("/") + RECEIPT_PATH,
            "body": base64.b64encode(
                json.dumps(body, separators=(",", ":")).encode("utf-8")
            ).decode("ascii"),
            "header": {
                "Authorization": [f"Bearer {tokens[index % len(tokens)]}"],
                "Content-Type": ["application/json"],
            },
        }
        for index, body in enumerate(bodies)
    ]


def write_targets(path, targets):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as target_file:
            for target in targets:
                json.dump(target, target_file, separators=(",", ":"))
                target_file.write("\n")
    finally:
        os.chmod(path, 0o600)


def plotting_available():
    return (
        importlib.util.find_spec("matplotlib") is not None
        and importlib.util.find_spec("numpy") is not None
    )


def plot_sweep(points, output_path):
    if not plotting_available():
        raise RuntimeError("Plotting requires matplotlib and numpy")
    if not points:
        raise ValueError("Cannot plot an empty sweep")

    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np

    matplotlib.rcParams["svg.fonttype"] = "none"
    columns = np.arange(len(points))
    target_rates = [point["target_rate"] for point in points]
    achieved = [point["achieved_throughput"] for point in points]
    successful_latencies_ms = [
        latency_ns / 1_000_000
        for point in points
        for latency_ns in point["successful_latencies_ns"]
        if latency_ns > 0
    ]
    maximum_latency_ms = max(1, max(successful_latencies_ms, default=1))
    bins = np.concatenate(([0], np.geomspace(0.1, maximum_latency_ms, 100)))

    figure, (throughput_axis, latency_axis) = plt.subplots(
        2, 1, figsize=(9, 9), sharex=True
    )
    throughput_axis.plot(columns, achieved, marker="o", label="Measured")
    throughput_axis.plot(
        columns, target_rates, linestyle="--", color="grey", label="Ideal"
    )
    throughput_axis.set_yscale("symlog", base=2, linthresh=min(target_rates))
    throughput_axis.set_ylabel("Achieved rate (req/s)")
    throughput_axis.set_title("Target throughput compared to achieved throughput")
    throughput_axis.grid(axis="y", alpha=0.3)
    throughput_axis.legend()

    for column, point in zip(columns, points):
        latencies_ms = [
            latency_ns / 1_000_000
            for latency_ns in point["successful_latencies_ns"]
            if latency_ns > 0
        ]
        if not latencies_ms:
            latency_axis.text(
                column,
                maximum_latency_ms / 2,
                "No successful responses",
                ha="center",
                va="center",
                rotation=90,
                fontsize="small",
            )
            continue
        density, edges = np.histogram(latencies_ms, bins=bins, density=True)
        if density.max() > 0:
            density = density / density.max() * 0.9
        centres = (edges[:-1] + edges[1:]) / 2
        latency_axis.fill_betweenx(
            centres, column, column + density, alpha=0.55, linewidth=0
        )
        latency_axis.plot(column + density, centres, linewidth=1)

    latency_axis.set_ylim(0, maximum_latency_ms)
    latency_axis.set_yscale("symlog", base=10, linthresh=0.1)
    latency_axis.set_ylabel("Latency (ms, symlog)")
    latency_axis.set_xlabel("Target rate of test (requests/s)")
    latency_axis.set_xticks(columns, [str(rate) for rate in target_rates])
    latency_axis.tick_params(axis="x", labelrotation=45)
    latency_axis.set_title("Latency distribution at each target throughput")
    latency_axis.grid(axis="y", alpha=0.3)
    figure.tight_layout()
    figure.savefig(output_path, format="svg")
    plt.close(figure)


def _run_command(command, description):
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        raise RuntimeError(
            f"{description} failed with exit code {completed.returncode}: "
            f"{completed.stderr.strip()}"
        )


def _decode_results(raw_path, decoded_path):
    _run_command(
        [
            "vegeta",
            "encode",
            "--to",
            "json",
            "--output",
            str(decoded_path),
            str(raw_path),
        ],
        "Decoding Vegeta results",
    )
    results = []
    with decoded_path.open(encoding="utf-8") as decoded:
        for line_number, line in enumerate(decoded, start=1):
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Malformed Vegeta JSON result on line {line_number}"
                ) from exc
    if not results:
        raise ValueError("Vegeta produced no decoded results")
    return results


def _serialisable_point(point):
    return {
        key: value for key, value in point.items() if key != "successful_latencies_ns"
    }


def _write_summary(path, points, termination_reason):
    summary = {
        "benchmark": (
            "CCF Logging blocking/receipt benchmark using a locally signed, "
            "Entra-shaped RS256 token"
        ),
        "endpoint": RECEIPT_PATH,
        "http_version": "HTTP/1.1",
        "termination_reason": termination_reason,
        "points": [_serialisable_point(point) for point in points],
    }
    path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")


def _print_interpretation(points, termination_reason):
    def format_percentile(value):
        return "N/A" if value is None else f"{value:.2f}ms"

    peak = max(points, key=lambda point: point["achieved_throughput"])
    under_delivered = next(
        (
            point
            for point in points
            if point["achieved_throughput"] < point["target_rate"] * 0.9
        ),
        None,
    )
    print(
        f"Peak achieved throughput: {peak['achieved_throughput']:.2f} requests/s "
        f"at target {peak['target_rate']} requests/s"
    )
    if under_delivered is None:
        print("First material under-delivery: none")
    else:
        print(
            "First material under-delivery: "
            f"target {under_delivered['target_rate']} requests/s, "
            f"achieved {under_delivered['achieved_throughput']:.2f} requests/s"
        )
    for point in points:
        percentiles = point["latency_percentiles_ms"]
        print(
            f"Target {point['target_rate']}: "
            f"p50={format_percentile(percentiles['p50'])} "
            f"p90={format_percentile(percentiles['p90'])} "
            f"p99={format_percentile(percentiles['p99'])}; "
            f"statuses={point['status_counts']}; "
            f"errors={point['errors']}; timeouts={point['timeouts']}"
        )
    print(f"Sweep termination: {termination_reason}")


def _run_attack(
    target_path,
    service_cert_path,
    point_dir,
    target_rate,
    duration_s,
    timeout_s,
):
    point_dir.mkdir(exist_ok=True)
    raw_path = point_dir / "results.bin"
    report_path = point_dir / "report.txt"
    decoded_path = point_dir / "results.json"
    _run_command(
        [
            "vegeta",
            "attack",
            "-format=json",
            f"-rate={target_rate}/s",
            f"-duration={duration_s}s",
            f"-timeout={timeout_s}s",
            "-http2=false",
            "-max-body=0",
            f"-root-certs={service_cert_path}",
            f"-targets={target_path}",
            f"-output={raw_path}",
        ],
        f"Vegeta attack at {target_rate} requests/s",
    )
    _run_command(
        [
            "vegeta",
            "report",
            "--output",
            str(report_path),
            str(raw_path),
        ],
        f"Generating Vegeta report at {target_rate} requests/s",
    )
    return _decode_results(raw_path, decoded_path)


def _jwt_preflight(base_url, service_cert_path, token):
    request = urllib.request.Request(
        base_url + RECEIPT_PATH,
        data=json.dumps({"id": 0, "msg": "Vegeta JWT preflight"}).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    context = ssl.create_default_context(cafile=service_cert_path)
    with urllib.request.urlopen(
        request, context=context, timeout=DEFAULT_TIMEOUT_S
    ) as response:
        if response.status != 200:
            raise RuntimeError(
                f"JWT-only benchmark preflight returned HTTP {response.status}"
            )
        if response.headers.get_content_type() != "application/cose":
            raise RuntimeError(
                "JWT-only benchmark preflight did not return an application/cose receipt"
            )


def run_benchmark(args):
    import infra.e2e_args
    import infra.interfaces
    import infra.jwt_issuer
    import infra.network

    if shutil.which("vegeta") is None:
        raise RuntimeError("vegeta is required but was not found on PATH")

    issuer = infra.jwt_issuer.JwtIssuer(
        SYNTHETIC_ISSUER,
        auth_type=infra.jwt_issuer.JwtAuthType.KEY,
        alg=infra.jwt_issuer.JwtAlg.RS256,
    )
    issuer.auto_refresh = False

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    common_dir = Path(infra.network.get_common_folder_name(args.workspace, args.label))
    artifact_dir = common_dir / f"vegeta_logging_jwt_{timestamp}"
    artifact_dir.mkdir(mode=0o700, parents=True)
    bodies = [
        {"id": index, "msg": f"Vegeta Logging JWT message {index}"}
        for index in range(TARGET_BODY_COUNT)
    ]
    (artifact_dir / "bodies.json").write_text(
        json.dumps(bodies, indent=2) + "\n", encoding="utf-8"
    )

    points = []
    termination_reason = None
    summary_path = artifact_dir / "summary.json"
    plot_path = artifact_dir / "sweep.svg"
    while termination_reason is None:
        step = len(points)
        target_rate = sweep_rate(args.initial_rate, step)
        point_name = f"step_{step:02d}_rate_{target_rate}"
        point_dir = artifact_dir / point_name
        point_dir.mkdir()
        point_args = copy.deepcopy(args)
        point_args.label = f"{args.label}_{point_name}"
        point_args.nodes = infra.e2e_args.min_nodes(point_args, f=0)
        with infra.network.network(
            point_args.nodes,
            point_args.binary_dir,
            point_args.debug_nodes,
            pdb=point_args.pdb,
            library_directory=point_args.library_dir,
        ) as network:
            network.start_and_open(point_args)
            issuer.register(network)
            token = issuer.issue_jwt(claims={"tid": str(SYNTHETIC_TENANT_ID)})
            primary, _ = network.find_primary()
            base_url = "https://" + infra.interfaces.make_address(
                primary.get_public_rpc_host(), primary.get_public_rpc_port()
            )
            _jwt_preflight(base_url, network.cert_path, token)
            target_path = point_dir / "targets.json"
            write_targets(target_path, make_targets(base_url, bodies, [token]))
            results = _run_attack(
                target_path,
                network.cert_path,
                point_dir,
                target_rate,
                args.duration_s,
                args.request_timeout_s,
            )

        point = summarise_results(results, args.duration_s, target_rate)
        point["artifacts"] = {
            "targets": str(target_path),
            "raw_results": str(point_dir / "results.bin"),
            "report": str(point_dir / "report.txt"),
            "decoded_results": str(point_dir / "results.json"),
        }
        points.append(point)
        if not point["generator_valid"]:
            termination_reason = "generator_under_delivery"
        elif should_stop_sweep(points):
            termination_reason = "two_consecutive_half_rate_points"
        _write_summary(summary_path, points, termination_reason or "sweep_in_progress")
        if termination_reason is None:
            print(f"Waiting for client ports used by {base_url} to be released")
            wait_for_port_release(base_url, args.port_release_timeout_s)

    plot_sweep(points, plot_path)
    _write_summary(summary_path, points, termination_reason)
    _print_interpretation(points, termination_reason)
    print(f"Artifacts: {artifact_dir}")
    if termination_reason == "generator_under_delivery":
        raise RuntimeError(
            "Invalid sweep: Vegeta issued less than 90% of the target rate"
        )
    return artifact_dir


def run(args):
    run_benchmark(args)


if __name__ == "__main__":
    import infra.e2e_args

    def add(parser):
        parser.add_argument("--duration-s", type=int, default=DEFAULT_DURATION_S)
        parser.add_argument("--initial-rate", type=int, default=DEFAULT_INITIAL_RATE)
        parser.add_argument("--request-timeout-s", type=int, default=DEFAULT_TIMEOUT_S)
        parser.add_argument(
            "--port-release-timeout-s",
            type=int,
            default=DEFAULT_PORT_RELEASE_TIMEOUT_S,
        )

    cli_args = infra.e2e_args.cli_args(add=add)
    cli_args.package = "samples/apps/logging/logging"
    cli_args.max_open_sessions = int(cli_args.max_open_sessions)
    cli_args.max_open_sessions_hard = int(cli_args.max_open_sessions_hard)
    cli_args.initial_member_count = 1
    cli_args.sig_ms_interval = 100
    run(cli_args)
