# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import time
import types
import unittest

import gevent
from gevent.queue import Queue
from infra.rate_control import Worker, quantile


class RateControlTest(unittest.TestCase):
    def run_worker(self, rate, response_time):
        results = []
        runner = types.SimpleNamespace(
            worker_index=0,
            send_message=lambda kind, result: results.append((kind, result)),
        )
        worker = Worker(types.SimpleNamespace(runner=runner))

        def write():
            gevent.sleep(response_time)
            return True

        def execute(user):
            while True:
                worker.execute(user)

        clients = [
            gevent.spawn(
                execute,
                types.SimpleNamespace(rate_token=Queue(maxsize=1), write_once=write),
            )
            for _ in range(2)
        ]
        start = time.monotonic() + 0.02
        try:
            worker.run_stage(
                {
                    "index": 0,
                    "rate": rate,
                    "workers": 1,
                    "start": start,
                    "measure_start": start + 0.1,
                    "end": start + 0.5,
                }
            )
        finally:
            gevent.killall(clients)
        self.assertEqual(len(results), 1)
        result = results[0][1]
        self.assertEqual(result["assigned"], result["completed"])
        self.assertEqual(result["offered"], result["assigned"] + result["missed_pool"])
        self.assertLessEqual(max(n for _, n in result["occupancy"]), 2)
        return result

    def test_tracks_target_when_connections_are_available(self):
        result = self.run_worker(10, 0.001)
        self.assertEqual(result["offered"], 4)
        self.assertEqual(result["missed_pool"], 0)
        self.assertEqual(result["failures"], 0)

    def test_counts_missed_arrivals_without_growing_pool(self):
        result = self.run_worker(1000, 0.02)
        self.assertEqual(result["offered"], 400)
        self.assertGreater(result["missed_pool"], 300)
        self.assertGreater(result["completed"], 0)

    def test_histogram_percentiles(self):
        self.assertEqual(quantile({100: 9, 1000: 1}, 0.5), 10)
        self.assertEqual(quantile({100: 9, 1000: 1}, 0.99), 100)
        self.assertIsNone(quantile({}, 0.99))

    def test_locust_message_callback_keywords(self):
        replies = []
        env = types.SimpleNamespace(
            runner=types.SimpleNamespace(
                send_message=lambda *args: replies.append(args)
            )
        )
        worker = Worker(env)
        worker.status(environment=env, msg=None)
        self.assertEqual(
            replies, [("rate_status_reply", {"ready": 0, "warm_errors": 0})]
        )


if __name__ == "__main__":
    unittest.main()
