# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""
Locust benchmark for the Basic C++ and JavaScript applications.

The endpoint is selected by the test registration. The C++ workload uses
blocking writes which only return once the transaction has committed, while the
JavaScript workload uses its standard PUT /records/{key} endpoint.

The load itself is defined in infra/basicperf_locustfile.py. Shared Locust
orchestration and statistics handling live in infra/locust_benchmark.py.

With --target-rps, the same workload uses a fixed pool of warmed connections
and measures each offered rate after --settle-time-s. Per-rate measurements,
including missed arrivals, are written to rate_sweep.json in the common folder.
"""

import argparse
import dataclasses
import json
import os

import infra.e2e_args
import infra.key_space
import infra.locust_benchmark
import infra.network

LOCUST_FILE_NAME = "basicperf_locustfile.py"
BLOCKING_ENDPOINT = "/records/blocking/{key}"


def prepare_workload(args, _network, primary) -> infra.locust_benchmark.Workload:
    infra.key_space.create_and_fill_key_space(args.key_space_size, primary)
    session_auth = primary.session_auth("user0")["session_auth"]
    return infra.locust_benchmark.Workload(
        locust_file_name=LOCUST_FILE_NAME,
        arguments=(
            "--cert",
            session_auth.cert,
            "--key",
            session_auth.key,
            "--key-space-size",
            str(args.key_space_size),
            "--endpoint",
            args.endpoint,
        ),
    )


def cli_args():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    infra.locust_benchmark.add_cli_arguments(parser)
    parser.add_argument(
        "--target-rps",
        type=infra.locust_benchmark.positive_int,
        nargs="+",
        help="Run an offered-load sweep over these request rates",
    )
    parser.add_argument("--settle-time-s", type=int, default=5)
    parser.add_argument(
        "--node-count",
        help="Number of nodes, including the primary",
        type=infra.locust_benchmark.positive_int,
        default=1,
    )
    parser.add_argument(
        "--key-space-size",
        help="Size of the key space which is pre-populated and written to",
        type=int,
        default=1000,
    )
    parser.add_argument(
        "--endpoint",
        help="Path to write to, in which {key} is replaced by the key written",
        default=BLOCKING_ENDPOINT,
    )
    return infra.e2e_args.cli_args(
        parser=parser, accept_unknown=False, ledger_chunk_bytes_override="5MB"
    )


def run_rate_sweep(args):
    if len(args.sig_ms_intervals) != 1:
        raise ValueError("A rate sweep requires exactly one signature interval")
    args.sig_ms_interval = args.sig_ms_intervals[0]
    args.consensus_update_timeout_ms = args.sig_ms_interval
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, pdb=args.pdb
    ) as network:
        network.start_and_open(args)
        primary, _ = network.find_primary()
        workload = prepare_workload(args, network, primary)
        results_file = os.path.join(network.common_dir, "rate_sweep.json")
        workload = dataclasses.replace(
            workload,
            arguments=(
                *workload.arguments,
                "--target-rps",
                *(str(rate) for rate in args.target_rps),
                "--settle-time-s",
                str(args.settle_time_s),
                "--rate-results",
                results_file,
                "--exit-code-on-error",
                "0",
            ),
        )
        infra.locust_benchmark.run_locust(
            args,
            network,
            primary,
            workload,
            run_time_s=120
            + len(args.target_rps) * (args.settle_time_s + args.measure_time_s + 35),
        )
        with open(results_file, encoding="utf-8") as source:
            results = json.load(source)
        if [row["rate"] for row in results] != args.target_rps:
            raise RuntimeError("Incomplete rate sweep")
        for row in results:
            print(
                f"Target {row['rate']} RPS: dispatched {row['dispatched_rps']:.1f}, "
                f"completed {row['completed_rps']:.1f}, mean {row['mean_ms']:.2f} ms, "
                f"p99 {row['p99_ms']:.2f} ms, missed {row['missed_pool']}, "
                f"errors {row['failures']}"
            )


if __name__ == "__main__":
    args = cli_args()
    # The workload targets the primary, and additional nodes only add
    # replication cost.
    args.nodes = infra.e2e_args.nodes(args, args.node_count)

    if args.target_rps:
        run_rate_sweep(args)
    else:
        infra.locust_benchmark.run(args, prepare_workload)
