# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Run fixed-connection offered-load sweeps through the existing CCF test wrapper."""

import argparse
import hashlib
import json
import math
import os
import re
import selectors
import shutil
import socket
import subprocess
import time
from itertools import pairwise
from pathlib import Path

HZ = os.sysconf("SC_CLK_TCK")
PAGE_KIB = os.sysconf("SC_PAGE_SIZE") / 1024


def percentile(values, p):
    ordered = sorted(values)
    if not ordered:
        raise ValueError("No samples in measurement window")
    return ordered[max(0, math.ceil(p * len(ordered)) - 1)]


def sample(node_dirs):
    now = time.monotonic()
    nodes = []
    for folder in node_dirs:
        pid_file = folder / "node.pid"
        if not pid_file.exists():
            return None
        pid = int(pid_file.read_text())
        try:
            fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        except FileNotFoundError:
            return None
        nodes.append(
            {
                "pid": pid,
                "cpu_seconds": (int(fields[11]) + int(fields[12])) / HZ,
                "rss_mib": int(fields[21]) * PAGE_KIB / 1024,
                "major_faults": int(fields[9]),
            }
        )
    mem = {
        parts[0].rstrip(":"): int(parts[1])
        for line in Path("/proc/meminfo").read_text().splitlines()
        if len(parts := line.split()) >= 2
    }
    vm = dict(line.split() for line in Path("/proc/vmstat").read_text().splitlines())
    cpu = list(map(int, Path("/proc/stat").read_text().splitlines()[0].split()[1:9]))
    return {
        "time": now,
        "nodes": nodes,
        "cpu_seconds": sum(n["cpu_seconds"] for n in nodes),
        "rss_mib": sum(n["rss_mib"] for n in nodes),
        "major_faults": sum(n["major_faults"] for n in nodes),
        "host_cpu_total": sum(cpu),
        "host_cpu_idle": cpu[3] + cpu[4],
        "host_ram_used_percent": 100 * (1 - mem["MemAvailable"] / mem["MemTotal"]),
        "host_mem_available_mib": mem["MemAvailable"] / 1024,
        "load1": float(Path("/proc/loadavg").read_text().split()[0]),
        "allocstalls": sum(int(v) for k, v in vm.items() if k.startswith("allocstall")),
        "direct_reclaim_pages": (
            int(vm["pgscan_direct"]) if "pgscan_direct" in vm else None
        ),
        "swap_pages": int(vm["pswpin"]) + int(vm["pswpout"]),
    }


def sample_threads(node_dirs):
    result = {"time": time.monotonic(), "threads": []}
    for node, folder in enumerate(node_dirs):
        pid_file = folder / "node.pid"
        if not pid_file.exists():
            continue
        pid = int(pid_file.read_text())
        tasks = Path(f"/proc/{pid}/task")
        if not tasks.exists():
            continue
        for task in tasks.iterdir():
            try:
                fields = (task / "stat").read_text().rsplit(")", 1)[1].split()
                status = dict(
                    line.split(":", 1)
                    for line in (task / "status").read_text().splitlines()
                    if ":" in line
                )
                scheduling = list(map(int, (task / "schedstat").read_text().split()))
            except FileNotFoundError:
                continue
            result["threads"].append(
                {
                    "node": node,
                    "tid": int(task.name),
                    "cpu_ticks": int(fields[11]) + int(fields[12]),
                    "voluntary_switches": int(status["voluntary_ctxt_switches"]),
                    "involuntary_switches": int(status["nonvoluntary_ctxt_switches"]),
                    "runqueue_ns": scheduling[1],
                }
            )
    return result


def run(args, mode):
    folder = args.output / mode
    folder.mkdir()
    workspace = (
        args.workspace_root / mode if args.workspace_root else folder / "workspace"
    )
    node_dirs = [workspace / f"{mode}_{i}" for i in range(2)]
    command = [
        str(args.build / "env/bin/python"),
        str(args.repo / "tests/basicperf_locust.py"),
        "--binary-dir",
        str(args.build),
        "--package",
        str(args.build / "samples/apps/basic/basic"),
        "--label",
        mode,
        "--perf-label",
        "Basic Blocking Rate Sweep",
        "--workspace",
        str(workspace),
        "--node-count",
        "2",
        "--worker-threads",
        "2",
        "--users",
        "1000",
        "--spawn-rate",
        "100",
        "--locust-processes",
        "4",
        "--measure-time-s",
        str(args.seconds),
        "--settle-time-s",
        str(args.settle),
        "--sig-ms-intervals",
        "100",
        "--tick-ms",
        "1",
        "--snapshot-tx-interval",
        "1000000000",
        "--max-open-sessions",
        "1000",
        "--max-open-sessions-hard",
        "1010",
        "--log-level",
        "fail",
        "--target-rps",
        *map(str, args.rates),
    ]
    for fragment in ("actions", "validate", "resolve", "apply"):
        command += [
            "--constitution",
            str(args.repo / f"samples/constitutions/default/{fragment}.js"),
        ]
    environment = os.environ.copy()
    environment.pop("CCF_PERF", None)
    environment.pop("CCF_PERF_ARGS", None)
    environment.pop("CCF_BENCHMARK_WINDOW", None)
    if args.profile:
        environment["CCF_PERF"] = "1"
        environment["CCF_PERF_ARGS"] = (
            "-m 64 -e task-clock -F 499 -g --call-graph dwarf,16384 --clockid mono --quiet"
        )
    samples, traffic, completed = [], [], []
    thread_samples = []
    with (
        socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener,
        selectors.DefaultSelector() as selector,
        (folder / "run.log").open("w") as log,
    ):
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.setblocking(False)
        selector.register(listener, selectors.EVENT_READ)
        host, port = listener.getsockname()
        if mode != "off":
            fluentd = {
                "host": host,
                "port": str(port),
                "discard": mode in ("discard", "ring_discard"),
                "buffered": mode in ("buffered", "ring_discard"),
                "ring_buffer_size": args.ring_size,
            }
            if args.benchmark_variant:
                fluentd["benchmark_variant"] = args.benchmark_variant
                fluentd["benchmark_stats_file"] = "trace_ablation.json"
            command += ["--observability", json.dumps({"fluentd": fluentd})]
        cmake_args = " ".join(f"[==[{arg}]==]" for arg in command)
        limit = 240 + len(args.rates) * (args.seconds + args.settle + 35)
        (folder / "CTestTestfile.cmake").write_text(
            f"add_test(basic_rate_sweep {cmake_args})\n"
            f'set_tests_properties(basic_rate_sweep PROPERTIES TIMEOUT {limit} ENVIRONMENT "PYTHONPATH={args.repo}/tests")\n'
        )
        (folder / "command.json").write_text(json.dumps(command, indent=2))
        connections = {}
        next_sample = 0
        with subprocess.Popen(
            [
                str(args.build / "tests.sh"),
                "--test-dir",
                str(folder),
                "-R",
                "^basic_rate_sweep$",
                "--output-on-failure",
            ],
            cwd=args.build,
            stdout=log,
            stderr=subprocess.STDOUT,
            env=environment,
        ) as process:
            try:
                while True:
                    events = selector.select(0.02)
                    for key, _ in events:
                        if key.fileobj is listener:
                            connection, _ = listener.accept()
                            connection.setblocking(False)
                            selector.register(connection, selectors.EVENT_READ)
                            connections[connection] = 0
                        else:
                            connection = key.fileobj
                            data = connection.recv(1024 * 1024)
                            if data:
                                connections[connection] += len(data)
                                traffic.append([time.monotonic(), len(data)])
                            else:
                                completed.append(connections.pop(connection))
                                selector.unregister(connection)
                                connection.close()
                    if time.monotonic() >= next_sample:
                        if row := sample(node_dirs):
                            samples.append(row)
                            if args.thread_stats:
                                thread_samples.append(sample_threads(node_dirs))
                        next_sample = time.monotonic() + 0.2
                    if process.poll() is not None and not connections and not events:
                        break
                if process.returncode:
                    raise RuntimeError(f"Sweep {mode} failed: {folder / 'run.log'}")
            finally:
                for connection in connections:
                    connection.close()
                if process.poll() is None:
                    process.terminate()
                process.wait()
    (folder / "samples.json").write_text(json.dumps(samples))
    (folder / "thread-samples.json").write_text(json.dumps(thread_samples))
    (folder / "traffic.json").write_text(json.dumps(traffic))
    for node_dir in node_dirs:
        config = json.loads(next(node_dir.glob("*.config.json")).read_text())
        assert config["worker_threads"] == 2
        assert config["ledger_signatures"]["delay"] == "100ms"
        fluentd = config.get("observability", {}).get("fluentd")
        assert bool(fluentd) == (mode != "off")
        if fluentd:
            assert fluentd["discard"] == (mode in ("discard", "ring_discard"))
            assert fluentd["buffered"] == (mode in ("buffered", "ring_discard"))
    assert (sum(completed) > 0) == (mode in ("tcp", "buffered"))
    warnings = []
    drop_events = []
    slow_storage = []
    for node_dir in node_dirs:
        text = (node_dir / "out").read_text()
        warnings += re.findall(r"Dropped (\d+) raft_trace events", text)
        for threshold, timestamp in re.findall(
            r"Dropped (\d+) raft_trace events[^\n]*monotonic_us (\d+)", text
        ):
            drop_events.append(
                {
                    "node": node_dir.name,
                    "threshold": int(threshold),
                    "time": int(timestamp) / 1_000_000,
                }
            )
        slow_storage += [
            line
            for line in text.splitlines()
            if "fsync(" in line and "Operation took too long" in line
        ]
        archive = folder / node_dir.name
        archive.mkdir()
        for filename in ("out", "err", next(node_dir.glob("*.config.json")).name):
            shutil.copyfile(node_dir / filename, archive / filename)
        if args.profile:
            shutil.copyfile(node_dir / "perf.data", archive / "perf.data")
        if args.benchmark_variant:
            shutil.copyfile(
                node_dir / "trace_ablation.json", archive / "trace_ablation.json"
            )
    (folder / "drop-events.json").write_text(json.dumps(drop_events, indent=2))
    common = workspace / f"{mode}_common"
    stages = json.loads((common / "rate_sweep.json").read_text())
    for source in [common / "rate_sweep.json", *common.glob("locust*.csv")]:
        shutil.copyfile(source, folder / source.name)
    for stage in stages:
        start, end = stage["measure_start"], stage["end"]
        cpu, rss = [], []
        for before, after in pairwise(samples):
            if start <= before["time"] < after["time"] <= end:
                dt = after["time"] - before["time"]
                cpu.append(100 * (after["cpu_seconds"] - before["cpu_seconds"]) / dt)
                rss.append(after["rss_mib"])
        inflight = [n for _, n in stage["inflight_samples"]]
        stage.update(
            {
                "mode": mode,
                "missed_percent": 100 * stage["missed_pool"] / stage["offered"],
                "inflight_p50": percentile(inflight, 0.5),
                "inflight_p99": percentile(inflight, 0.99),
                "inflight_max": max(inflight),
                "node_cpu_p50_percent": percentile(cpu, 0.5),
                "node_cpu_p99_percent": percentile(cpu, 0.99),
                "node_rss_p50_mib": percentile(rss, 0.5),
                "node_rss_p99_mib": percentile(rss, 0.99),
                "received_bytes": sum(n for t, n in traffic if start <= t < end),
                "run_transport_drop_warnings": warnings,
                "run_tcp_connections": len(completed),
                "run_slow_storage_warnings": slow_storage,
                "drop_lower_bound_end": sum(
                    max(
                        (
                            e["threshold"]
                            for e in drop_events
                            if e["node"] == node.name and e["time"] <= end
                        ),
                        default=0,
                    )
                    for node in node_dirs
                ),
                "drop_observations": [
                    e for e in drop_events if start <= e["time"] <= end
                ],
            }
        )
        assert stage["clients"] == 1000
        assert stage["inflight_max"] <= 1000
        print(
            {
                k: stage[k]
                for k in (
                    "mode",
                    "rate",
                    "dispatched_rps",
                    "completed_rps",
                    "mean_ms",
                    "p99_ms",
                    "missed_percent",
                    "inflight_p50",
                    "inflight_p99",
                    "dispatch_lag_p99_ms",
                    "failures",
                    "received_bytes",
                )
            },
            flush=True,
        )
    (folder / "results.json").write_text(json.dumps(stages, indent=2))
    return stages


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seconds", type=int, default=30)
    parser.add_argument("--settle", type=int, default=5)
    parser.add_argument(
        "--rates",
        type=int,
        nargs="+",
        default=[500, 1000, 2000, 4000, 6000, 8000, 10000],
    )
    parser.add_argument("--modes", nargs="+", default=["off", "discard", "tcp"])
    parser.add_argument("--workspace-root", type=Path)
    parser.add_argument("--profile", action="store_true")
    parser.add_argument("--thread-stats", action="store_true")
    parser.add_argument("--ring-size", default="1MB")
    parser.add_argument("--implementation-name")
    parser.add_argument("--benchmark-variant")
    args = parser.parse_args()
    for key in ("repo", "build", "output"):
        setattr(args, key, getattr(args, key).resolve())
    if args.workspace_root:
        args.workspace_root = args.workspace_root.resolve()
        args.workspace_root.mkdir(parents=True, exist_ok=True)
        filesystem = subprocess.check_output(
            ["stat", "-f", "-c", "%T", str(args.workspace_root)], text=True
        ).strip()
        if filesystem != "tmpfs":
            raise RuntimeError("The benchmark workspace must be mounted as tmpfs")
    args.output.mkdir(parents=True, exist_ok=False)
    with (args.build / "samples/apps/basic/basic").open("rb") as binary:
        sha = hashlib.file_digest(binary, "sha256").hexdigest()
    (args.output / "metadata.json").write_text(
        json.dumps(
            {
                "command": os.sys.argv,
                "binary_sha256": sha,
                "cmake_cache": (args.build / "CMakeCache.txt").read_text(),
                "profiling": args.profile,
                "thread_stats": args.thread_stats,
                "ring_size": args.ring_size,
                "implementation": args.implementation_name,
                "pool": "Four worker-local pools of 250 warmed HTTP/1.1 connections",
                "receiver": "colocated raw TCP drain",
                "latency_cohort": "requests offered inside the measurement window, including drain completions",
                "workspace_root": (
                    str(args.workspace_root) if args.workspace_root else None
                ),
                "storage": (
                    "RAM-backed tmpfs; not a durable-storage benchmark"
                    if args.workspace_root
                    else "normal filesystem"
                ),
            },
            indent=2,
        )
    )
    all_results = []
    for mode in args.modes:
        all_results.extend(run(args, mode))
        (args.output / "results.json").write_text(json.dumps(all_results, indent=2))


if __name__ == "__main__":
    main()
