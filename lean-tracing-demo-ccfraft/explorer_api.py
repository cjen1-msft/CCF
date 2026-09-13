#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Serve read-only JSON inspection of one retained native Lean run on loopback."""

from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from native_run import NativeRun
from reduction import ReductionError
from Shared.solver import ValidationError


class ApiError(ValueError):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


def natural(text: str) -> int:
    if not text or not text.isascii() or not text.isdecimal() or len(text) > 18:
        raise ApiError(400, "expected a nonnegative decimal integer")
    return int(text)


class ExplorerApi:
    def __init__(self, run: NativeRun):
        self.run = run
        self.core_indices = {
            index
            for index, clause in enumerate(run.details["clauses"])
            if clause["name"] in run.core
        }
        self.core_instructions = {
            run.owners[index]
            for index in self.core_indices
            if run.owners[index] is not None
        }

    def get(self, target: str) -> object:
        try:
            parsed = urlsplit(target)
            query = parse_qs(
                parsed.query,
                keep_blank_values=True,
                strict_parsing=True,
                max_num_fields=4,
            )
        except ValueError as error:
            raise ApiError(400, "invalid request target") from error
        if parsed.scheme or parsed.netloc or parsed.fragment:
            raise ApiError(400, "expected a relative API path")
        if any(len(values) != 1 for values in query.values()):
            raise ApiError(400, "duplicate query parameters are not accepted")
        path = parsed.path
        if path != "/api/instructions" and query:
            raise ApiError(400, "this endpoint accepts no query parameters")
        if path == "/api/run":
            return {
                "api_schema": "ccfraft-native-explorer/v1",
                "result": self.run.result,
                "nodes": self.run.document["nodes"],
                "bootstrap": self.run.document["bootstrap"],
                "instruction_count": len(self.run.document["instructions"]),
                "constraint_count": len(self.run.details["clauses"]),
                "core_constraint_count": len(self.run.core),
                "links": {
                    "input": "/api/input",
                    "instructions": "/api/instructions",
                    "core": "/api/core",
                    **({"reduction": "/api/reduction"} if self.run.origin else {}),
                },
            }
        if path == "/api/input":
            return self.run.document
        if path == "/api/reduction":
            if self.run.origin is None:
                raise ApiError(404, "run has no raw reduction")
            return self.run.origin.certificate
        if path == "/api/core":
            return {
                "status": self.run.result["status"],
                "clauses": [
                    self.run.constraint(index) for index in sorted(self.core_indices)
                ],
                "instructions": sorted(self.core_instructions),
                "includes_initial_domains": any(
                    self.run.owners[index] is None for index in self.core_indices
                ),
                "minimal": False,
            }
        if path == "/api/instructions":
            if set(query) - {"offset", "limit"}:
                raise ApiError(400, "expected only offset and limit")
            offset = natural(query.get("offset", ["0"])[0])
            limit = natural(query.get("limit", ["50"])[0])
            if not 1 <= limit <= 200:
                raise ApiError(400, "limit must be between 1 and 200")
            instructions = self.run.document["instructions"]
            items = []
            for index in range(offset, min(offset + limit, len(instructions))):
                group = self.run.details["groups"][index + 1]
                items.append(
                    {
                        "index": index,
                        "instruction": instructions[index],
                        "clause_count": group["stop"] - group["start"],
                        "in_core": index in self.core_instructions,
                    }
                )
            return {
                "offset": offset,
                "limit": limit,
                "total": len(instructions),
                "items": items,
            }
        if path.startswith("/api/instructions/"):
            index = natural(path.removeprefix("/api/instructions/"))
            if index >= len(self.run.document["instructions"]):
                raise ApiError(404, "instruction not found")
            return self.run.instruction(index)
        if path.startswith("/api/constraints/assertion_"):
            index = natural(path.removeprefix("/api/constraints/assertion_"))
            if index >= len(self.run.details["clauses"]):
                raise ApiError(404, "constraint not found")
            return self.run.constraint(index)
        raise ApiError(404, "endpoint not found")


def make_server(run: NativeRun, port: int = 8091) -> HTTPServer:
    api = ExplorerApi(run)

    class Handler(BaseHTTPRequestHandler):
        def send_json(self, status: int, value: object) -> None:
            body = (
                json.dumps(value, ensure_ascii=True, allow_nan=False) + "\n"
            ).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            if status == 405:
                self.send_header("Allow", "GET, HEAD")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def do_GET(self) -> None:
            hosts = self.headers.get_all("Host", [])
            try:
                host = urlsplit("//" + hosts[0]) if len(hosts) == 1 else None
                valid_host = (
                    host is not None
                    and host.hostname in {"127.0.0.1", "localhost"}
                    and host.username is None
                    and host.password is None
                    and not host.path
                    and not host.query
                    and not host.fragment
                    and (host.port is None or 1 <= host.port <= 65535)
                )
            except ValueError:
                self.send_json(400, {"error": "invalid Host header"})
                return
            if not valid_host:
                self.send_json(
                    403, {"error": "only loopback Host headers are accepted"}
                )
                return
            try:
                value = api.get(self.path)
            except ApiError as error:
                self.send_json(error.status, {"error": str(error)})
                return
            self.send_json(200, value)

        do_HEAD = do_GET

        def reject_write(self) -> None:
            self.send_json(405, {"error": "the explorer API is read-only"})

        do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = reject_write

    return HTTPServer(("127.0.0.1", port), Handler)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path)
    parser.add_argument("--port", type=int, default=8091)
    args = parser.parse_args()
    if not 0 <= args.port <= 65535:
        parser.error("port must be between 0 and 65535")
    try:
        run = NativeRun.load(args.run)
        with make_server(run, args.port) as server:
            print(f"http://127.0.0.1:{server.server_port}/api/run", flush=True)
            server.serve_forever()
    except (ValidationError, ReductionError, OSError, ValueError) as error:
        parser.exit(2, f"explorer API: {error}\n")
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
