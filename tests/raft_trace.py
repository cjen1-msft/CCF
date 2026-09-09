# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Capture Fluentd Message-mode records from a single raft_driver run."""

import pathlib
import selectors
import socket
import struct
import subprocess
import tempfile
import time

import msgpack


def unique_map(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate MessagePack map key: {key}")
        result[key] = value
    return result


def run_driver(driver, scenario, timeout=60, *, buffered=False):
    """Return process output and decoded records, rejecting incomplete streams."""
    records = []
    with (
        socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener,
        selectors.DefaultSelector() as selector,
        tempfile.TemporaryFile() as stdout,
        tempfile.TemporaryFile() as stderr,
    ):
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.setblocking(False)
        host, port = listener.getsockname()
        command = [
            str(pathlib.Path(driver).absolute()),
            str(pathlib.Path(scenario).resolve()),
            host,
            str(port),
        ]
        if buffered:
            command.append("--buffered")
        selector.register(listener, selectors.EVENT_READ)
        connections = {}
        with subprocess.Popen(command, stdout=stdout, stderr=stderr) as process:
            deadline = time.monotonic() + timeout
            try:
                while True:
                    if time.monotonic() > deadline:
                        raise subprocess.TimeoutExpired(command, timeout)
                    events = selector.select(0.05)
                    for key, _ in events:
                        if key.fileobj is listener:
                            connection, _ = listener.accept()
                            connection.setblocking(False)
                            selector.register(connection, selectors.EVENT_READ)
                            connections[connection] = [
                                msgpack.Unpacker(
                                    raw=False, object_pairs_hook=unique_map
                                ),
                                0,
                                0,
                            ]
                            continue

                        connection = key.fileobj
                        unpacker, received, complete = connections[connection]
                        data = connection.recv(64 * 1024)
                        if not data:
                            if received != complete:
                                raise ValueError("Truncated MessagePack stream")
                            selector.unregister(connection)
                            connection.close()
                            del connections[connection]
                            continue
                        received += len(data)
                        unpacker.feed(data)
                        for entry in unpacker:
                            if not isinstance(entry, list) or len(entry) != 3:
                                raise ValueError(f"Invalid Fluentd entry: {entry}")
                            tag, timestamp, record = entry
                            if tag != "ccf.raft_trace" or not isinstance(record, dict):
                                raise ValueError(f"Invalid trace entry: {entry}")
                            if (
                                set(record) != {"h_ts", "msg"}
                                or type(record["h_ts"]) is not int
                                or record["h_ts"] < 0
                                or not isinstance(record["msg"], dict)
                            ):
                                raise ValueError(f"Invalid trace record: {record}")
                            if (
                                not isinstance(timestamp, msgpack.ExtType)
                                or timestamp.code != 0
                                or len(timestamp.data) != 8
                                or struct.unpack(">II", timestamp.data)[1] >= 10**9
                            ):
                                raise ValueError(f"Invalid EventTime: {timestamp}")
                            records.append(record)
                            complete = unpacker.tell()
                        connections[connection] = [unpacker, received, complete]

                    if process.poll() is not None and not connections and not events:
                        break
            finally:
                for connection in connections:
                    connection.close()
                if process.poll() is None:
                    process.kill()
                process.wait()

            stdout.seek(0)
            stderr.seek(0)
            result = subprocess.CompletedProcess(
                command,
                process.returncode,
                stdout.read().decode(),
                stderr.read().decode(),
            )
    records.sort(key=lambda record: record["h_ts"])
    for expected, record in enumerate(records):
        if record["h_ts"] != expected:
            raise ValueError(
                f"Missing or duplicate trace sequence: expected {expected}, "
                f"received {record['h_ts']}"
            )
    return result, records


def as_log_lines(records):
    """Restore the scenario parser's command/message wrapper in emission order."""
    return [
        (
            {"tag": "raft_trace", **record["msg"]}
            if "cmd" in record["msg"]
            else {
                "tag": "raft_trace",
                "h_ts": str(record["h_ts"]),
                "msg": record["msg"],
            }
        )
        for record in records
    ]
