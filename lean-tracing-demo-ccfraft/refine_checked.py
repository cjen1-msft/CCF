#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Refine one action inside a previously reduced checked UNSAT core."""

from __future__ import annotations

import argparse
import json
from collections.abc import Mapping, Sequence
from pathlib import Path

from Shared.smt import (
    NAMED_ASSERTION,
    SmtEncodingError,
    parse_unsat_core,
    restrict_to_assertions,
    write_formula,
)
from Shared.solver import ValidationError, find_cvc5, run_solver
from validate_checked import (
    _assurance,
    _mapping,
    _record_failure,
    _remove_stale_artifacts,
    _sequence,
    explain_unsat,
    read_constraint_map,
)


def refine_formula(
    formula: str,
    constraint_map: Mapping[str, object],
    core_names: tuple[str, ...],
    inspect_group: int,
) -> tuple[str, tuple[str, ...]]:
    """Split one checked group without restoring any discarded group."""

    selected_name = f"group_{inspect_group}"
    if selected_name not in core_names:
        raise ValidationError("select an action in the reduced group core")
    groups = [
        _mapping(group, "group")
        for group in _sequence(constraint_map["groups"], "groups")
    ]
    assertions: dict[str, str] = {}
    selected_clauses: list[str] | None = None
    for index, group in enumerate(groups):
        if group["index"] != index or group["name"] != f"group_{index}":
            raise ValidationError("constraint map groups are not in encoder order")
        clauses = [
            _mapping(clause, "clause")
            for clause in _sequence(group["clauses"], "clauses")
        ]
        for clause_index, clause in enumerate(clauses):
            if clause["name"] != f"group_{index}_clause_{clause_index}":
                raise ValidationError("constraint map has an invalid clause name")
        expressions = [str(clause["expression"]) for clause in clauses]
        conjunction = (
            "true"
            if not expressions
            else (
                expressions[0]
                if len(expressions) == 1
                else "(and " + " ".join(expressions) + ")"
            )
        )
        name = str(group["name"])
        assertions[name] = f"(assert (! {conjunction} :named {name}))"
        if name == selected_name:
            if group["kind"] != "action":
                raise ValidationError(
                    "refinement must select an action, not bounds or an observation"
                )
            selected_clauses = [
                f"(assert (! {clause['expression']} :named {clause['name']}))"
                for clause in clauses
            ]
    if selected_clauses is None:
        raise ValidationError("the selected action is absent from the constraint map")

    seen: set[str] = set()
    for line in formula.splitlines():
        match = NAMED_ASSERTION.fullmatch(line)
        if match is not None:
            name = match.group(1)
            if name in seen or assertions.get(name) != line:
                raise ValidationError("the formula and constraint map disagree")
            seen.add(name)
    if seen != assertions.keys():
        raise ValidationError("the formula is missing a mapped group")

    restricted = restrict_to_assertions(formula, core_names)
    refined: list[str] = []
    for line in restricted.splitlines():
        if line == assertions[selected_name]:
            refined.extend(selected_clauses)
        else:
            refined.append(line)
    return "\n".join(refined) + "\n", tuple(
        name for name in core_names if name != selected_name
    )


def refine_checked_core(
    source_directory: Path,
    output_directory: Path,
    *,
    inspect_group: int,
    cvc5: Path | None = None,
    core_reduction_budget_seconds: float = 5.0,
) -> dict[str, object]:
    """Keep the previously reduced context fixed while shrinking one action."""

    if source_directory.resolve() == output_directory.resolve():
        raise ValidationError("refinement output must differ from the source run")
    output_directory.mkdir(parents=True, exist_ok=True)
    _remove_stale_artifacts(output_directory)
    try:
        try:
            source = _mapping(
                json.loads(
                    (source_directory / "result.json").read_text(encoding="utf-8")
                ),
                "source result",
            )
        except json.JSONDecodeError as error:
            raise ValidationError(f"invalid source result: {error}") from error
        assurance = _mapping(source.get("assurance"), "source assurance")
        gate = _mapping(source.get("proof_gate"), "source proof gate")
        if (
            source.get("status") != "unsat"
            or assurance.get("granularity") != "group"
            or assurance.get("backend") != "lean-checked trace encoder"
            or gate.get("checked") is not True
        ):
            raise ValidationError(
                "refinement requires a checked, group-level UNSAT run"
            )
        constraint_map = read_constraint_map(
            source_directory / "constraint-map.json", inspect_group=None
        )
        core_names = parse_unsat_core(
            (source_directory / "unsat-core.txt").read_text(encoding="utf-8")
        )
        formula, fixed_context = refine_formula(
            (source_directory / "formula.smt2").read_text(encoding="utf-8"),
            constraint_map,
            core_names,
            inspect_group,
        )
        solver = find_cvc5(cvc5)
        formula_path = output_directory / "formula.smt2"
        write_formula(formula_path, formula)
        refined_map = {**constraint_map, "inspect_group": inspect_group}
        (output_directory / "constraint-map.json").write_text(
            json.dumps(refined_map, indent=2) + "\n", encoding="utf-8"
        )
        status = run_solver(solver, formula_path, output_directory, "cvc5-status")
        if status.status != "unsat":
            raise ValidationError("the reduced context did not reproduce UNSAT")
        result: dict[str, object] = {
            "status": "unsat",
            "assurance": _assurance(refined_map, inspect_group=inspect_group),
            "proof_gate": dict(gate),
            "source_run": str(source_directory.resolve()),
            "source_core": list(core_names),
            "constraint_map": "constraint-map.json",
            "formula": "formula.smt2",
            "cvc5": str(solver),
            "check_sat_wall_ms": status.wall_time_ms,
            "interpretation": (
                "the selected action was refined inside the previously reduced "
                "group core; every other group in that core stayed fixed"
            ),
        }
        result.update(
            explain_unsat(
                solver,
                formula,
                output_directory,
                refined_map,
                core_reduction_budget_seconds=core_reduction_budget_seconds,
                inspect_group=inspect_group,
                fixed_context_names=fixed_context,
            )
        )
        (output_directory / "result.json").write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        return result
    except (SmtEncodingError, ValidationError, OSError) as error:
        _record_failure(output_directory, error)
        raise


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source_directory", type=Path)
    parser.add_argument("output_directory", type=Path)
    parser.add_argument("--inspect-group", type=int, required=True)
    parser.add_argument("--cvc5", type=Path)
    parser.add_argument("--core-reduction-budget-seconds", type=float, default=5.0)
    args = parser.parse_args(argv)
    try:
        result = refine_checked_core(
            args.source_directory,
            args.output_directory,
            inspect_group=args.inspect_group,
            cvc5=args.cvc5,
            core_reduction_budget_seconds=args.core_reduction_budget_seconds,
        )
    except (SmtEncodingError, ValidationError, OSError) as error:
        parser.exit(2, f"core refinement failed: {error}\n")
    print(result["status"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
