# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import infra.e2e_args
import infra.network
import infra.vegeta_load

from loguru import logger as LOG


def run(args):
    config = infra.vegeta_load.VegetaSweepConfig(
        start_rate=args.vegeta_start_rate,
        duration=args.vegeta_duration,
        timeout=args.vegeta_timeout,
        low_goodput_ratio=args.vegeta_low_goodput_ratio,
        consecutive_low_goodput_count=args.vegeta_consecutive_low_goodput_count,
        actual_rate_floor_ratio=args.vegeta_actual_rate_floor_ratio,
    )

    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, pdb=args.pdb
    ) as network:
        network.start_and_open(args)

        LOG.info(
            f"Running Vegeta load sweep from {config.start_rate} requests/s "
            f"with {config.duration}s samples"
        )
        summary = infra.vegeta_load.run_sweep(network, config)

        for sample in summary["samples"]:
            LOG.info(f"Vegeta sweep sample summary: {sample}")

        LOG.info(
            f"Vegeta load sweep summary written to "
            f"{infra.vegeta_load.sweep_summary_path(network)}"
        )
        LOG.info(f"Discovered peak goodput: {summary['peak_goodput']}")

    return network


if __name__ == "__main__":

    def add(parser):
        parser.add_argument(
            "--vegeta-start-rate",
            help="Initial desired request rate for the Vegeta sweep",
            type=int,
            default=infra.vegeta_load.DEFAULT_START_RATE_S,
        )
        parser.add_argument(
            "--vegeta-duration",
            help="Duration for each Vegeta attack sample, in seconds",
            type=int,
            default=infra.vegeta_load.DEFAULT_DURATION_S,
        )
        parser.add_argument(
            "--vegeta-timeout",
            help="Per-request timeout for Vegeta, in seconds",
            type=int,
            default=infra.vegeta_load.DEFAULT_TIMEOUT_S,
        )
        parser.add_argument(
            "--vegeta-low-goodput-ratio",
            help="Stop after consecutive samples at or below this goodput/desired-rate ratio",
            type=float,
            default=infra.vegeta_load.DEFAULT_LOW_GOODPUT_RATIO,
        )
        parser.add_argument(
            "--vegeta-consecutive-low-goodput-count",
            help="Number of consecutive low-goodput samples required to stop the sweep",
            type=int,
            default=infra.vegeta_load.DEFAULT_CONSECUTIVE_LOW_GOODPUT_COUNT,
        )
        parser.add_argument(
            "--vegeta-actual-rate-floor-ratio",
            help="Fail if Vegeta issues requests below this fraction of desired rate",
            type=float,
            default=infra.vegeta_load.DEFAULT_ACTUAL_RATE_FLOOR_RATIO,
        )

    args = infra.e2e_args.cli_args(add=add)
    args.package = "samples/apps/logging/logging"
    args.nodes = infra.e2e_args.min_nodes(args, f=0)
    args.initial_member_count = 1
    run(args)
