# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import infra.e2e_args
import infra.network
import infra.vegeta_load

from loguru import logger as LOG


def run(args):
    config = infra.vegeta_load.VegetaLoadConfig(
        rate=args.vegeta_rate,
        duration=args.vegeta_duration,
        timeout=args.vegeta_timeout,
    )

    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, pdb=args.pdb
    ) as network:
        network.start_and_open(args)

        LOG.info(
            f"Running Vegeta load for {config.duration}s at {config.rate} requests/s"
        )
        client = infra.vegeta_load.VegetaLoadClient(network, config)
        report = client.run()
        summary = infra.vegeta_load.report_summary(report)
        LOG.info(f"Vegeta load summary: {summary}")
        infra.vegeta_load.assert_accepted_report(report, config.allowed_status_codes)

        LOG.info(f"Vegeta report written to {client.report_path}")
        LOG.info(f"Vegeta targets written to {client.targets_path}")

    return network


if __name__ == "__main__":

    def add(parser):
        parser.add_argument(
            "--vegeta-rate",
            help="Request rate to apply with Vegeta",
            type=int,
            default=infra.vegeta_load.DEFAULT_REQUEST_RATE_S,
        )
        parser.add_argument(
            "--vegeta-duration",
            help="Duration for the Vegeta attack, in seconds",
            type=int,
            default=infra.vegeta_load.DEFAULT_DURATION_S,
        )
        parser.add_argument(
            "--vegeta-timeout",
            help="Per-request timeout for Vegeta, in seconds",
            type=int,
            default=infra.vegeta_load.DEFAULT_TIMEOUT_S,
        )

    args = infra.e2e_args.cli_args(add=add)
    args.package = "samples/apps/logging/logging"
    args.nodes = infra.e2e_args.min_nodes(args, f=0)
    args.initial_member_count = 1
    run(args)
