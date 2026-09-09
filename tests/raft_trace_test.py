# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import os
import pathlib
import socket
import struct
import sys
import time
import unittest
from unittest.mock import patch

from raft_trace import run_driver

import msgpack


class CaptureTest(unittest.TestCase):
    @staticmethod
    def encode(sequence, event):
        return msgpack.packb(
            [
                "ccf.raft_trace",
                msgpack.ExtType(0, struct.pack(">II", 123, 456)),
                {"h_ts": sequence, "msg": event},
            ]
        )

    def capture(self, data):
        with patch.dict(os.environ, {"RAFT_TRACE_TEST_BYTES": data.hex()}):
            return run_driver(sys.executable, pathlib.Path(__file__))

    def test_complete_stream(self):
        records = [{"function": "test", "text": 'a"b\n'}, {"cmd": "replicate,1"}]
        payload = b"".join(self.encode(i, record) for i, record in enumerate(records))
        result, actual = self.capture(payload)
        self.assertEqual(result.returncode, 0)
        self.assertEqual([record["msg"] for record in actual], records)

    def test_multiple_connections_out_of_order(self):
        first = self.encode(0, {"cmd": "start_node,0"})
        second = self.encode(1, {"function": "become_leader"})
        with patch.dict(
            os.environ,
            {
                "RAFT_TRACE_TEST_BYTES": first.hex(),
                "RAFT_TRACE_SECOND_BYTES": second.hex(),
            },
        ):
            result, actual = run_driver(sys.executable, pathlib.Path(__file__))
        self.assertEqual(result.returncode, 0)
        self.assertEqual([record["h_ts"] for record in actual], [0, 1])

    def test_missing_sequence(self):
        with self.assertRaisesRegex(ValueError, "Missing or duplicate"):
            self.capture(self.encode(1, {}))

    def test_duplicate_sequence(self):
        with self.assertRaisesRegex(ValueError, "Missing or duplicate"):
            self.capture(self.encode(0, {}) * 2)

    def test_truncated_stream(self):
        with self.assertRaisesRegex(ValueError, "Truncated"):
            self.capture(b"\x93")

    def test_invalid_time(self):
        with self.assertRaisesRegex(ValueError, "EventTime"):
            self.capture(msgpack.packb(["ccf.raft_trace", 0, {"h_ts": 0, "msg": {}}]))

    def test_duplicate_keys(self):
        timestamp = msgpack.ExtType(0, struct.pack(">II", 0, 0))
        prefix = b"\x93" + msgpack.packb("ccf.raft_trace") + msgpack.packb(timestamp)
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            self.capture(prefix + b"\x82\xa1a\x01\xa1a\x02")

    def test_exit_without_connecting(self):
        result, records = run_driver("/bin/false", pathlib.Path(__file__))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(records, [])

    def test_missing_driver(self):
        with self.assertRaises(FileNotFoundError):
            run_driver("/nonexistent/raft_driver", pathlib.Path(__file__))


if __name__ == "__main__":
    if len(sys.argv) == 3:
        with socket.create_connection((sys.argv[1], int(sys.argv[2]))) as connection:
            if "RAFT_TRACE_SECOND_BYTES" in os.environ:
                with socket.create_connection(
                    (sys.argv[1], int(sys.argv[2]))
                ) as second:
                    second.sendall(bytes.fromhex(os.environ["RAFT_TRACE_SECOND_BYTES"]))
                time.sleep(0.05)
            # Fragment the stream independently of the sender's record boundaries.
            data = bytes.fromhex(os.environ["RAFT_TRACE_TEST_BYTES"])
            for start in range(0, len(data), 3):
                connection.sendall(data[start : start + 3])
    else:
        unittest.main()
