# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Open-arrival pacing over a fixed pool of local, forked Locust users."""

import collections
import json
import logging
import math
import time

import gevent
from gevent.queue import Empty, Queue
from locust.runners import MasterRunner, WorkerRunner

LOG = logging.getLogger(__name__)


def quantile(histogram, fraction):
    target = math.ceil(sum(histogram.values()) * fraction)
    count = 0
    for value, n in sorted(histogram.items()):
        count += n
        if count >= target:
            return value / 10
    return None


class Worker:
    def __init__(self, environment):
        self.environment = environment
        self.ready = 0
        self.warm_errors = 0
        self.idle = Queue()
        self.inflight = 0
        self.stage = None
        self.active = False

    def warm(self, user):
        user.rate_token = Queue(maxsize=1)
        if user.write_once():
            self.ready += 1
        else:
            self.warm_errors += 1

    def execute(self, user):
        self.idle.put(user)
        scheduled, measured = user.rate_token.get()
        stage = self.stage
        started = time.monotonic()
        if stage["measure_start"] <= started < stage["end"]:
            stage["started_in_window"] += 1
        try:
            success = user.write_once()
            finished = time.monotonic()
            if stage["measure_start"] <= finished < stage["end"]:
                stage["completed_in_window"] += 1
                stage["successful_in_window"] += int(success)
            if measured:
                latency = (finished - started) * 1000
                lag = (started - scheduled) * 1000
                stage["completed"] += 1
                stage["failures"] += int(not success)
                stage["latency_sum_ms"] += latency
                stage["latency_hist"][round(latency * 10)] += 1
                stage["lag_hist"][round(lag * 10)] += 1
        finally:
            self.inflight -= 1

    def status(self, environment, msg):
        self.environment.runner.send_message(
            "rate_status_reply",
            {"ready": self.ready, "warm_errors": self.warm_errors},
        )

    def begin(self, environment, msg):
        if self.active:
            raise RuntimeError("Overlapping rate stages")
        self.active = True
        gevent.spawn(self.run_stage, msg.data)

    def run_stage(self, command):
        stage = self.stage = {
            **command,
            "offered": 0,
            "assigned": 0,
            "missed_pool": 0,
            "started_in_window": 0,
            "completed_in_window": 0,
            "successful_in_window": 0,
            "completed": 0,
            "failures": 0,
            "latency_sum_ms": 0.0,
            "latency_hist": collections.Counter(),
            "lag_hist": collections.Counter(),
            "occupancy": [],
        }
        sample = gevent.spawn(self.sample_occupancy, stage)
        runner = self.environment.runner
        slot = 0
        scheduled = command["start"] + runner.worker_index / command["rate"]
        while scheduled < command["end"]:
            now = time.monotonic()
            if now < scheduled:
                gevent.sleep(scheduled - now)
                continue
            measured = scheduled >= command["measure_start"]
            if measured:
                stage["offered"] += 1
            try:
                user = self.idle.get_nowait()
            except Empty:
                if measured:
                    stage["missed_pool"] += 1
            else:
                if measured:
                    stage["assigned"] += 1
                self.inflight += 1
                user.rate_token.put((scheduled, measured))
            slot += 1
            scheduled = (
                command["start"]
                + (slot * command["workers"] + runner.worker_index) / command["rate"]
            )
            # Yield after each dispatch so the ready client can start its request.
            gevent.sleep(0)
        deadline = time.monotonic() + 30
        while self.inflight:
            if time.monotonic() > deadline:
                raise RuntimeError("Requests did not drain after a rate plateau")
            gevent.sleep(0.01)
        sample.join()
        stage["latency_hist"] = list(stage["latency_hist"].items())
        stage["lag_hist"] = list(stage["lag_hist"].items())
        self.active = False
        runner.send_message("rate_result", stage)

    def sample_occupancy(self, stage):
        i = 0
        while (deadline := stage["measure_start"] + i * 0.1) < stage["end"]:
            gevent.sleep(max(0, deadline - time.monotonic()))
            stage["occupancy"].append([i, self.inflight])
            i += 1


class Master:
    def __init__(self, environment):
        self.environment = environment
        self.statuses = {}
        self.replies = {}
        self.started = False

    def status(self, environment, msg):
        self.statuses[msg.node_id] = msg.data

    def result(self, environment, msg):
        self.replies[msg.node_id] = msg.data

    def start(self, **_kwargs):
        if not self.started:
            self.started = True
            gevent.spawn(self.run)

    def run(self):
        env = self.environment
        runner = env.runner
        opts = env.parsed_options
        try:
            deadline = time.monotonic() + 60
            while True:
                self.statuses.clear()
                runner.send_message("rate_status")
                gevent.sleep(0.1)
                if any(s["warm_errors"] for s in self.statuses.values()):
                    raise RuntimeError("Connection warmup had failed requests")
                if sum(s["ready"] for s in self.statuses.values()) == opts.num_users:
                    break
                if time.monotonic() > deadline:
                    raise RuntimeError("Not all fixed-pool connections warmed up")
            workers = len(self.statuses)
            results = []
            for index, rate in enumerate(opts.target_rps):
                self.replies.clear()
                start = time.monotonic() + 1
                command = {
                    "index": index,
                    "rate": rate,
                    "workers": workers,
                    "start": start,
                    "measure_start": start + opts.settle_time_s,
                    "end": start + opts.settle_time_s + opts.measure_time_s,
                }
                runner.send_message("rate_begin", command)
                deadline = command["end"] + 35
                while len(self.replies) != workers:
                    if time.monotonic() > deadline:
                        raise RuntimeError("Workers did not report a completed plateau")
                    gevent.sleep(0.1)
                rows = list(self.replies.values())
                if any(row["index"] != index for row in rows):
                    raise RuntimeError("Mixed plateau results")
                latency, lag, occupancy = (collections.Counter() for _ in range(3))
                for row in rows:
                    latency.update(dict(row["latency_hist"]))
                    lag.update(dict(row["lag_hist"]))
                    occupancy.update(dict(row["occupancy"]))
                totals = {
                    key: sum(row[key] for row in rows)
                    for key in (
                        "offered",
                        "assigned",
                        "missed_pool",
                        "started_in_window",
                        "completed_in_window",
                        "successful_in_window",
                        "completed",
                        "failures",
                        "latency_sum_ms",
                    )
                }
                if totals["offered"] != totals["assigned"] + totals["missed_pool"]:
                    raise RuntimeError("Offered load accounting mismatch")
                if totals["assigned"] != totals["completed"]:
                    raise RuntimeError("Incomplete request cohort")
                if not totals["completed"]:
                    raise RuntimeError("No measured requests completed")
                result = {
                    **command,
                    **totals,
                    "dispatched_rps": totals["started_in_window"] / opts.measure_time_s,
                    "completed_rps": totals["successful_in_window"]
                    / opts.measure_time_s,
                    "mean_ms": totals["latency_sum_ms"] / totals["completed"],
                    "p50_ms": quantile(latency, 0.5),
                    "p99_ms": quantile(latency, 0.99),
                    "dispatch_lag_p99_ms": quantile(lag, 0.99),
                    "latency_histogram_tenths_ms": sorted(latency.items()),
                    "dispatch_lag_histogram_tenths_ms": sorted(lag.items()),
                    "inflight_samples": sorted(occupancy.items()),
                    "clients": opts.num_users,
                }
                results.append(result)
                with open(opts.rate_results, "w", encoding="utf-8") as output:
                    json.dump(results, output, indent=2)
                LOG.info(
                    "Rate plateau: %s",
                    {k: v for k, v in result.items() if not isinstance(v, list)},
                )
        except (RuntimeError, OSError):
            LOG.exception("Rate sweep failed")
            env.process_exit_code = 1
        finally:
            runner.quit()


def install(environment):
    if any(rate <= 0 for rate in environment.parsed_options.target_rps):
        raise ValueError("Target request rates must be positive")
    if environment.parsed_options.settle_time_s < 0:
        raise ValueError("Settle time cannot be negative")
    runner = environment.runner
    if isinstance(runner, WorkerRunner):
        controller = Worker(environment)
        runner.register_message("rate_status", controller.status)
        runner.register_message("rate_begin", controller.begin)
    elif isinstance(runner, MasterRunner):
        controller = Master(environment)
        runner.register_message("rate_status_reply", controller.status)
        runner.register_message("rate_result", controller.result)
        environment.events.spawning_complete.add_listener(controller.start)
    else:
        raise TypeError("Rate sweep requires local forked Locust workers")
    environment.rate_control = controller
