# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Validate retained native-run artifacts for read-only inspection."""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from pathlib import Path

from native_input import canonical_json, unique_object
from Shared.smt import parse_unsat_core
from Shared.solver import SolverRun, ValidationError, query_payload, solver_status

ENCODER = "native-lean-experimental"
RUN_SCHEMA = "ccfraft-native-run/v2"
ENCODING_SCHEMA = "ccfraft-native-encoding/v2"
ARTIFACTS = (
    "input.json",
    "encoding.json",
    "trace.smt2",
    "trace.stdout",
    "trace.stderr",
)
ASSURANCE = {
    "full_model_to_script_proved": False,
    "raw_reducer_integrated": False,
}


def _object(value: object, fields: set[str], where: str) -> dict:
    if not isinstance(value, dict) or set(value) != fields:
        raise ValidationError(f"{where}: expected fields {sorted(fields)}")
    return value


def _array(value: object, where: str) -> list:
    if not isinstance(value, list):
        raise ValidationError(f"{where}: expected an array")
    return value


def _natural(value: object, where: str) -> int:
    if type(value) is not int or value < 0:
        raise ValidationError(f"{where}: expected a natural number")
    return value


def validate_encoding(document: object, details: object) -> dict:
    """Require ordered, exhaustive ownership of the Lean-generated clauses."""
    fields = {"nodes", "bootstrap", "instructions"}
    if isinstance(document, dict) and "unknowns" in document:
        fields.add("unknowns")
    document = _object(document, fields, "input")
    unknowns = _array(document.get("unknowns", []), "unknowns")
    if (
        any(not isinstance(name, str) or not name for name in unknowns)
        or len(unknowns) != len(set(unknowns))
    ):
        raise ValidationError("unknowns must be distinct nonempty strings")
    nodes = _array(document["nodes"], "nodes")
    if (
        not nodes
        or any(not isinstance(node, str) or not node for node in nodes)
        or len(nodes) != len(set(nodes))
    ):
        raise ValidationError("nodes must be distinct nonempty strings")
    bootstrap = _array(document["bootstrap"], "bootstrap")
    if not bootstrap or any(
        not isinstance(node, str) or node not in nodes for node in bootstrap
    ):
        raise ValidationError("bootstrap must contain declared nodes")
    instructions = _array(document["instructions"], "instructions")
    for index, instruction in enumerate(instructions):
        if not isinstance(instruction, dict) or not isinstance(
            instruction.get("kind"), str
        ):
            raise ValidationError(
                f"instruction {index}: expected an instruction object"
            )
    details = _object(
        details,
        {"schema", "input", "script", "queries", "groups", "clauses"},
        "encoding",
    )
    if details["schema"] != ENCODING_SCHEMA:
        raise ValidationError("unsupported native encoding schema")
    if canonical_json(details["input"]) != canonical_json(document):
        raise ValidationError("encoding belongs to different Model input")
    if not isinstance(details["script"], str) or not details["script"]:
        raise ValidationError("encoding script must be nonempty text")
    queries = _object(details["queries"], {"unsatCore"}, "queries")
    if not isinstance(queries["unsatCore"], str) or not queries["unsatCore"].strip():
        raise ValidationError("unsat-core query must be nonempty text")
    clauses = _array(details["clauses"], "clauses")
    for index, clause in enumerate(clauses):
        clause = _object(clause, {"name", "expression"}, f"clause {index}")
        if clause["name"] != f"assertion_{index}":
            raise ValidationError("clause names must follow their emitted order")
        if not isinstance(clause["expression"], str) or not clause["expression"]:
            raise ValidationError("clause expression must be nonempty text")
    groups = _array(details["groups"], "groups")
    if len(groups) != len(instructions) + 1:
        raise ValidationError("expected initial domains and one group per instruction")
    position = 0
    for index, group in enumerate(groups):
        group = _object(group, {"instruction", "start", "stop"}, f"group {index}")
        owner = group["instruction"]
        if index == 0:
            if owner is not None:
                raise ValidationError(
                    "initial domains must not belong to an instruction"
                )
        elif _natural(owner, "group instruction") != index - 1:
            raise ValidationError("groups must preserve instruction order")
        start = _natural(group["start"], "group start")
        stop = _natural(group["stop"], "group stop")
        if start != position or not start <= stop <= len(clauses):
            raise ValidationError(
                "group ranges must cover clauses without gaps or overlaps"
            )
        position = stop
    if position != len(clauses):
        raise ValidationError("group ranges omit emitted clauses")
    return details


def core_names(run: SolverRun, details: dict) -> tuple[str, ...]:
    """Reject unknown core labels rather than attributing them to the wrong event."""
    statuses = [
        line.strip()
        for line in run.stdout.splitlines()
        if line.strip() in {"sat", "unsat", "unknown"}
    ]
    if statuses != [run.status]:
        raise ValidationError("expected exactly one solver verdict")
    if run.status != "unsat":
        return ()
    core = parse_unsat_core(query_payload(run, "unsat-core"))
    available = {clause["name"] for clause in details["clauses"]}
    if set(core) - available:
        raise ValidationError("solver core contains unknown clause names")
    return core


def artifact_hashes(directory: Path) -> dict[str, str]:
    return {
        name: hashlib.sha256((directory / name).read_bytes()).hexdigest()
        for name in ARTIFACTS
    }


@dataclass(frozen=True)
class NativeRun:
    """A validated snapshot; request handling never rereads files."""

    document: dict
    details: dict
    result: dict
    core: frozenset[str]
    owners: tuple[int | None, ...]

    @classmethod
    def load(cls, directory: Path) -> NativeRun:
        result = _object(
            json.loads(
                (directory / "result.json").read_text(encoding="utf-8"),
                object_pairs_hook=unique_object,
            ),
            {
                "schema",
                "encoder",
                "solver",
                "status",
                "solver_ms",
                "assurance",
                "artifacts",
            },
            "result",
        )
        if result["schema"] != RUN_SCHEMA or result["encoder"] != ENCODER:
            raise ValidationError("the API requires a native Lean run")
        if result["solver"] != "z3":
            raise ValidationError("unsupported native solver")
        assurance = _object(result["assurance"], set(ASSURANCE), "assurance")
        if any(assurance[key] is not value for key, value in ASSURANCE.items()):
            raise ValidationError("unsupported native proof or integration claims")
        duration = result["solver_ms"]
        if (
            type(duration) not in (int, float)
            or not math.isfinite(duration)
            or duration < 0
        ):
            raise ValidationError("solver_ms must be a finite nonnegative number")
        expected = _object(result["artifacts"], set(ARTIFACTS), "artifact hashes")
        data = {name: (directory / name).read_bytes() for name in ARTIFACTS}
        actual = {
            name: hashlib.sha256(value).hexdigest() for name, value in data.items()
        }
        if actual != expected:
            raise ValidationError("run artifacts changed or belong to different runs")
        document = json.loads(data["input.json"], object_pairs_hook=unique_object)
        details = validate_encoding(
            document, json.loads(data["encoding.json"], object_pairs_hook=unique_object)
        )
        script = data["trace.smt2"].decode("ascii")
        if script != details["script"]:
            raise ValidationError(
                "retained SMT does not match the Lean encoding artifact"
            )
        stdout, stderr = (
            data[name].decode("utf-8") for name in ("trace.stdout", "trace.stderr")
        )
        status = solver_status(stdout)
        if result["status"] != status:
            raise ValidationError("result verdict does not match solver output")
        run = SolverRun(status, stdout, stderr, duration)
        core = core_names(run, details)
        owners = tuple(
            group["instruction"]
            for group in details["groups"]
            for _ in range(group["start"], group["stop"])
        )
        return cls(document, details, result, frozenset(core), owners)

    def instruction(self, index: int) -> dict:
        if _natural(index, "instruction index") >= len(self.document["instructions"]):
            raise IndexError("instruction index is outside the run")
        group = self.details["groups"][index + 1]
        return {
            "index": index,
            "instruction": self.document["instructions"][index],
            "clauses": [
                self.constraint(position)
                for position in range(group["start"], group["stop"])
            ],
        }

    def constraint(self, index: int) -> dict:
        if _natural(index, "constraint index") >= len(self.details["clauses"]):
            raise IndexError("constraint index is outside the run")
        clause = self.details["clauses"][index]
        return {
            **clause,
            "instruction": self.owners[index],
            "in_core": clause["name"] in self.core,
        }
