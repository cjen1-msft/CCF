# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Native explorer artifact and HTTP contracts; fixtures are not proof evidence."""

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from http.client import HTTPConnection
from pathlib import Path
from threading import Thread

from explorer_api import ApiError, ExplorerApi, make_server
from native_run import (
    ASSURANCE,
    ENCODER,
    ENCODING_SCHEMA,
    RUN_SCHEMA,
    NativeRun,
    artifact_hashes,
)
from Shared.solver import ValidationError


class NativeExplorerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="native-explorer-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.document = {
            "nodes": ["a"],
            "bootstrap": ["a"],
            "instructions": [
                {"kind": "allocated", "node": "a", "value": True},
                {"kind": "allocated", "node": "a", "value": False},
            ],
        }
        self.details = {
            "schema": ENCODING_SCHEMA,
            "input": copy.deepcopy(self.document),
            "queries": {"unsatCore": "(get-unsat-core)\n"},
            "script": (
                "(set-logic ALL)\n(declare-const flag Bool)\n"
                "(assert (! true :named assertion_0))\n"
                "(assert (! flag :named assertion_1))\n"
                "(assert (! (not flag) :named assertion_2))\n(check-sat)\n"
            ),
            "groups": [
                {"instruction": None, "start": 0, "stop": 1},
                {"instruction": 0, "start": 1, "stop": 2},
                {"instruction": 1, "start": 2, "stop": 3},
            ],
            "clauses": [
                {"name": f"assertion_{index}", "expression": expression}
                for index, expression in enumerate(("true", "flag", "(not flag)"))
            ],
        }
        self.stdout = "unsat\n(assertion_2 assertion_1)\n"
        self.result = {
            "schema": RUN_SCHEMA,
            "encoder": ENCODER,
            "solver": "z3",
            "status": "unsat",
            "solver_ms": 0.1,
            "assurance": dict(ASSURANCE),
            "artifacts": {},
        }
        self.save()

    def save(self):
        for name, value in (
            ("input.json", self.document),
            ("encoding.json", self.details),
        ):
            (self.root / name).write_text(json.dumps(value), encoding="utf-8")
        (self.root / "trace.smt2").write_text(self.details["script"], encoding="ascii")
        (self.root / "trace.stdout").write_text(self.stdout, encoding="utf-8")
        (self.root / "trace.stderr").write_text("", encoding="utf-8")
        self.result["artifacts"] = artifact_hashes(self.root)
        (self.root / "result.json").write_text(
            json.dumps(self.result), encoding="utf-8"
        )

    def test_instruction_constraint_and_core_links(self):
        api = ExplorerApi(NativeRun.load(self.root))
        summary = api.get("/api/run")
        self.assertEqual(summary["instruction_count"], 2)
        self.assertEqual(summary["constraint_count"], 3)
        self.assertEqual(summary["result"]["assurance"], ASSURANCE)
        page = api.get("/api/instructions?offset=1&limit=1")
        self.assertEqual(page["total"], 2)
        self.assertEqual(page["items"][0]["index"], 1)
        self.assertTrue(page["items"][0]["in_core"])
        instruction = api.get("/api/instructions/1")
        self.assertEqual(instruction["instruction"], self.document["instructions"][1])
        self.assertEqual(instruction["clauses"][0]["name"], "assertion_2")
        self.assertEqual(api.get("/api/constraints/assertion_1")["instruction"], 0)
        self.assertIsNone(api.get("/api/constraints/assertion_0")["instruction"])
        core = api.get("/api/core")
        self.assertEqual(core["instructions"], [0, 1])
        self.assertFalse(core["minimal"])
        self.assertFalse(core["includes_initial_domains"])
        self.assertEqual(api.get("/api/input"), self.document)

    def test_unknown_does_not_become_sat(self):
        self.result["status"] = "unknown"
        self.stdout = "unknown\n"
        self.save()
        api = ExplorerApi(NativeRun.load(self.root))
        self.assertEqual(api.get("/api/run")["result"]["status"], "unknown")
        self.assertEqual(api.get("/api/core")["clauses"], [])

    def test_changed_artifacts_are_rejected(self):
        (self.root / "trace.smt2").write_text("(check-sat)\n", encoding="ascii")
        with self.assertRaisesRegex(ValidationError, "artifacts changed"):
            NativeRun.load(self.root)

    def test_old_schemas_and_other_solvers_are_rejected(self):
        original = copy.deepcopy(self.result)
        for field, value in (("schema", "ccfraft-native-run/v1"), ("solver", "cvc5")):
            with self.subTest(field=field):
                self.result = copy.deepcopy(original)
                self.result[field] = value
                self.save()
                with self.assertRaises(ValidationError):
                    NativeRun.load(self.root)
        self.result = original
        self.details["schema"] = "ccfraft-native-encoding/v1"
        self.save()
        with self.assertRaisesRegex(ValidationError, "encoding schema"):
            NativeRun.load(self.root)

    def test_missing_or_invalid_solver_queries_are_rejected(self):
        original = copy.deepcopy(self.details)
        for queries in ({}, {"unsatCore": ""}, {"unsatCore": False}):
            with self.subTest(queries=queries):
                self.details = copy.deepcopy(original)
                self.details["queries"] = queries
                self.save()
                with self.assertRaises(ValidationError):
                    NativeRun.load(self.root)

    def test_encoding_is_bound_to_exact_input_types(self):
        self.document["instructions"][0]["value"] = 1
        self.save()
        with self.assertRaisesRegex(ValidationError, "different Model input"):
            NativeRun.load(self.root)

    def test_gapped_overlapping_and_reordered_groups_are_rejected(self):
        original = copy.deepcopy(self.details)
        mutations = [
            lambda groups: groups[1].update(start=0),
            lambda groups: groups[1].update(start=2),
            lambda groups: groups[2].update(stop=4),
            lambda groups: groups[2].update(instruction=0),
            lambda groups: groups[1].update(instruction=False),
        ]
        for mutation in mutations:
            self.details = copy.deepcopy(original)
            mutation(self.details["groups"])
            self.save()
            with self.assertRaises(ValidationError):
                NativeRun.load(self.root)

    def test_checked_claims_and_unknown_core_labels_are_rejected(self):
        self.result["assurance"]["full_model_to_script_proved"] = True
        self.save()
        with self.assertRaisesRegex(ValidationError, "claims"):
            NativeRun.load(self.root)
        self.result["assurance"] = dict(ASSURANCE)
        self.stdout = "unsat\n(assertion_999)\n"
        self.save()
        with self.assertRaisesRegex(ValidationError, "unknown clause"):
            NativeRun.load(self.root)

    def test_mismatched_verdict_and_duplicate_json_are_rejected(self):
        self.result["status"] = "sat"
        self.save()
        with self.assertRaisesRegex(ValidationError, "verdict"):
            NativeRun.load(self.root)
        (self.root / "result.json").write_text('{"status":"sat","status":"unsat"}')
        with self.assertRaisesRegex(ValidationError, "duplicate JSON field"):
            NativeRun.load(self.root)

    def test_multiple_solver_verdicts_are_rejected(self):
        self.stdout = "unsat\nsat\n(assertion_1 assertion_2)\n"
        self.save()
        with self.assertRaisesRegex(ValidationError, "exactly one"):
            NativeRun.load(self.root)

    def test_bad_queries_and_paths_do_not_select_files(self):
        api = ExplorerApi(NativeRun.load(self.root))
        for target, status in [
            ("/api/instructions?offset=-1", 400),
            ("/api/instructions?limit=201", 400),
            ("/api/instructions?limit=1&limit=2", 400),
            ("/api/instructions?file=/etc/passwd", 400),
            ("/api/run?limit=1", 400),
            ("/api/instructions/999", 404),
            ("/api/constraints/assertion_999", 404),
            ("/../../etc/passwd", 404),
            ("http://example.com/api/run", 400),
        ]:
            with self.subTest(target=target), self.assertRaises(ApiError) as caught:
                api.get(target)
            self.assertEqual(caught.exception.status, status)

    def test_http_server_is_read_only_and_loopback_scoped(self):
        server = make_server(NativeRun.load(self.root), 0)
        thread = Thread(target=server.serve_forever)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(thread.join)
        self.addCleanup(server.shutdown)
        self.assertEqual(server.server_address[0], "127.0.0.1")

        def request(method, target, headers=None):
            connection = HTTPConnection(*server.server_address, timeout=5)
            try:
                connection.request(method, target, headers=headers or {})
                response = connection.getresponse()
                body = response.read()
                return response.status, dict(response.getheaders()), body
            finally:
                connection.close()

        status, headers, body = request("GET", "/api/run")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["result"]["status"], "unsat")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertNotIn("Access-Control-Allow-Origin", headers)
        status, _, body = request("HEAD", "/api/run")
        self.assertEqual((status, body), (200, b""))
        self.assertEqual(request("POST", "/api/run")[0], 405)
        self.assertEqual(request("GET", "/api/run", {"Host": "example.com"})[0], 403)
        self.assertEqual(request("GET", "/api/instructions?limit=0")[0], 400)
        self.assertEqual(request("GET", "/api/missing")[0], 404)


if __name__ == "__main__":
    unittest.main()
