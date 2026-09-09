#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Check a bounded trace certificate with the Lean-checked encoder.

The formula solved here is produced by ``MachineGenerated/TraceEncoding.lean``,
whose ``encode_correct`` theorem is compiled by the proof gate this runner
builds before every check. The gate is the reviewed command-line module itself,
so the encoder proofs, the reviewed certificate decoder, the ascription of the
encoder to ``BoundedTrace.VerifiedEncoder``, and its axiom audit all have
to compile before any certificate is read. The checked fragment is deliberately small:

* entry is the canonical bootstrap or an explicit full-state template;
* the template need not be reachable; its control fields and shape are concrete;
* actions are clientRequest, signCommittableMessages, changeConfiguration,
  and appendRetiredCommitted;
* the only observations are ``role``, ``currentTerm``, ``logLength``,
  ``commitIndex``, ``allocated``, ``joined``, and ``submitted``;
* transaction identifiers may be concrete numbers or declared unknowns, and
  every unknown ranges over the declared ``transaction_count`` bound.

Anything outside that fragment is rejected by the Lean decoder. This runner
never falls back to the projected ``validate.py`` backend, whose encoding is
not derived from the model.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from Shared.smt import (  # noqa: E402
    SmtEncodingError,
    add_query,
    parse_unsat_core,
    reduce_unsat_core,
    restrict_to_assertions,
    write_formula,
)
from Shared.solver import (  # noqa: E402
    ValidationError,
    find_cvc5,
    query_payload,
    run_solver,
    solver_status,
)


class CertificateRejected(ValidationError):
    """The Lean decoder refused this certificate, so nothing was encoded."""


CERTIFICATE_SCHEMA = "ccfraft-trace/v1"
CONSTRAINT_MAP_SCHEMA = "ccfraft-trace-constraints/v1"
PROOF_GATE_TARGET = "EncodeTrace"
ENCODER_TARGET = "encode_trace"
ENCODER_BINARY = Path(".lake/build/bin") / ENCODER_TARGET
DEFAULT_THEOREM = "CCFRaft.TraceEncoding.encode_correct"
INSPECT_GROUP_NOTE = (
    "this is a naming granularity, not a second encoding: the constraints are "
    "identical to the coarse run, but the selected group is printed as one "
    "named assertion per clause while every other group stays a single coarse "
    "assertion. Core reduction then holds those other assertions fixed and "
    "only removes clauses of the selected group, so the explanation keeps "
    "blaming the same steps and refines the selected action"
)

DECODER_MARKER = "encoding error:"

GROUP_NAME = re.compile(r"^group_(\d+)$")
CLAUSE_NAME = re.compile(r"^group_(\d+)_clause_(\d+)$")

_PROOF_GATE_BUILDS: dict[tuple[str, tuple[tuple[str, int, int], ...]], float] = {}


def _lean_sources(project_root: Path) -> list[Path]:
    sources = sorted(project_root.glob("*.lean"))
    for directory in ("Shared", "MachineGenerated"):
        sources.extend(sorted((project_root / directory).rglob("*.lean")))
    for name in (
        "lakefile.toml",
        "lakefile.lean",
        "lean-toolchain",
        "lake-manifest.json",
    ):
        candidate = project_root / name
        if candidate.is_file():
            sources.append(candidate)
    return sources


def _source_fingerprint(project_root: Path) -> tuple[tuple[str, int, int], ...]:
    """Invalidate the cached gate when sources or the executable change."""

    entries: list[tuple[str, int, int]] = []
    paths = _lean_sources(project_root)
    binary = project_root / ENCODER_BINARY
    if binary.is_file():
        paths.append(binary)
    for path in paths:
        stat = path.stat()
        entries.append(
            (str(path.relative_to(project_root)), stat.st_mtime_ns, stat.st_size)
        )
    return tuple(entries)


def build_proof_gate(project_root: Path, log_path: Path) -> dict[str, object]:
    """Build the audited encoder executable. A build failure stops the run."""

    key = (str(project_root), _source_fingerprint(project_root))
    cached = _PROOF_GATE_BUILDS.get(key)
    if cached is not None:
        log_path.write_text(
            f"proof gate {PROOF_GATE_TARGET} already built in this process "
            f"for unchanged Lean sources\n",
            encoding="utf-8",
        )
        return {
            "target": PROOF_GATE_TARGET,
            "build_target": ENCODER_TARGET,
            "checked": True,
            "cached": True,
            "log": log_path.name,
            "wall_ms": cached,
        }

    started = time.perf_counter_ns()
    completed = subprocess.run(
        ["nice", "-n", "10", "lake", "build", ENCODER_TARGET],
        cwd=project_root,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    wall_ms = (time.perf_counter_ns() - started) / 1_000_000
    log_path.write_text(completed.stdout + completed.stderr, encoding="utf-8")
    if completed.returncode != 0:
        raise ValidationError(
            f"the proof gate {PROOF_GATE_TARGET} failed to build "
            f"(exit {completed.returncode}); see {log_path}"
        )
    _encoder_binary(project_root)
    _PROOF_GATE_BUILDS[(str(project_root), _source_fingerprint(project_root))] = wall_ms
    return {
        "target": PROOF_GATE_TARGET,
        "build_target": ENCODER_TARGET,
        "checked": True,
        "cached": False,
        "log": log_path.name,
        "wall_ms": wall_ms,
    }


def _encoder_binary(project_root: Path) -> Path:
    """Locate the executable built from the audited command-line module."""

    binary = project_root / ENCODER_BINARY
    if binary.is_file():
        return binary.resolve()
    raise ValidationError(
        f"no checked encoder entry point at {binary}; build {ENCODER_TARGET} "
        f"from the proof gate module {PROOF_GATE_TARGET}"
    )


def encoder_failure(returncode: int, stdout: str, stderr: str) -> ValidationError:
    """Separate a decoder verdict on the certificate from a toolchain failure."""

    if DECODER_MARKER in stderr:
        reason = stderr.split(DECODER_MARKER, 1)[1].strip()
        return CertificateRejected(
            f"the Lean encoder rejected this certificate: {reason}"
        )
    detail = (stderr.strip() or stdout.strip()) or "no output"
    return ValidationError(
        f"the Lean encoder failed to run (exit {returncode}); this is a toolchain "
        f"failure, not a certificate verdict: {detail}"
    )


def run_encoder(
    project_root: Path,
    certificate_path: Path,
    output_directory: Path,
    *,
    inspect_group: int | None,
) -> float:
    """Run the Lean encoder, which decodes the certificate and emits SMT."""

    binary = _encoder_binary(project_root)
    command = [
        str(binary),
        str(certificate_path.resolve()),
        str(output_directory.resolve()),
    ]
    if inspect_group is not None:
        command.append(str(inspect_group))
    started = time.perf_counter_ns()
    completed = subprocess.run(
        command,
        cwd=project_root,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    wall_ms = (time.perf_counter_ns() - started) / 1_000_000
    (output_directory / "lean-encoder.stdout").write_text(
        completed.stdout, encoding="utf-8"
    )
    (output_directory / "lean-encoder.stderr").write_text(
        completed.stderr, encoding="utf-8"
    )
    if completed.returncode != 0:
        raise encoder_failure(completed.returncode, completed.stdout, completed.stderr)
    return wall_ms


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise ValidationError(f"{label} is not an object")
    return value


def _sequence(value: object, label: str) -> Sequence[object]:
    if not isinstance(value, list):
        raise ValidationError(f"{label} is not an array")
    return value


def read_constraint_map(
    path: Path, *, inspect_group: int | None
) -> Mapping[str, object]:
    """Read the emitted constraint map and check the fields this runner uses."""

    if not path.is_file():
        raise ValidationError(f"the Lean encoder emitted no constraint map: {path}")
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ValidationError(f"constraint map is not valid JSON: {error}") from error
    constraint_map = _mapping(loaded, "constraint map")
    schema = constraint_map.get("schema_version")
    if schema != CONSTRAINT_MAP_SCHEMA:
        raise ValidationError(
            f"unsupported constraint map schema_version: {schema!r}; "
            f"expected {CONSTRAINT_MAP_SCHEMA!r}"
        )
    if constraint_map.get("entry") not in ("bootstrap", "template"):
        raise ValidationError(
            f"unsupported constraint map entry: {constraint_map.get('entry')!r}"
        )
    certificate_schema = constraint_map.get("certificate_schema")
    if not isinstance(certificate_schema, str) or not certificate_schema:
        raise ValidationError("constraint map has no certificate_schema")
    actions = _sequence(constraint_map.get("supported_actions"), "supported actions")
    if not actions or not all(isinstance(action, str) and action for action in actions):
        raise ValidationError(
            "constraint map supported_actions must be nonempty strings"
        )
    _mapping(constraint_map.get("bounds"), "constraint map bounds")
    _sequence(constraint_map.get("unknowns"), "constraint map unknowns")
    groups = _sequence(constraint_map.get("groups"), "constraint map groups")
    if not groups:
        raise ValidationError("constraint map has no groups")
    for group in groups:
        entry = _mapping(group, "constraint map group")
        for field in ("index", "name", "label", "kind"):
            if field not in entry:
                raise ValidationError(f"constraint map group has no {field}")
        clauses = _sequence(entry.get("clauses"), f"clauses of {entry['name']}")
        for raw_clause in clauses:
            clause = _mapping(raw_clause, f"clause of {entry['name']}")
            for field in ("name", "label", "expression"):
                if not isinstance(clause.get(field), str):
                    raise ValidationError(
                        f"clause of {entry['name']} has no string {field}"
                    )
    if constraint_map.get("inspect_group") != inspect_group:
        raise ValidationError(
            f"constraint map reports inspect_group "
            f"{constraint_map.get('inspect_group')!r}, not {inspect_group!r}"
        )
    return constraint_map


def _clause_index(
    constraint_map: Mapping[str, object],
) -> tuple[
    dict[str, Mapping[str, object]],
    dict[str, tuple[Mapping[str, object], Mapping[str, object]]],
]:
    groups: dict[str, Mapping[str, object]] = {}
    clauses: dict[str, tuple[Mapping[str, object], Mapping[str, object]]] = {}
    for raw_group in _sequence(constraint_map["groups"], "groups"):
        group = _mapping(raw_group, "group")
        name = group["name"]
        assert isinstance(name, str)
        groups[name] = group
        for raw_clause in _sequence(group["clauses"], f"clauses of {name}"):
            clause = _mapping(raw_clause, "clause")
            clause_name = clause["name"]
            assert isinstance(clause_name, str)
            clauses[clause_name] = (group, clause)
    return groups, clauses


def _group_summary(group: Mapping[str, object]) -> dict[str, object]:
    return {
        "group_index": group["index"],
        "group_kind": group["kind"],
        "group_label": group["label"],
        "instruction": group.get("instruction"),
        "instruction_index": group.get("instruction_index"),
    }


def core_diagnosis(
    constraint_map: Mapping[str, object],
    names: Sequence[str],
    *,
    core_kind: str,
) -> dict[str, object]:
    """Bind every core assertion name to the constraint it was printed from.

    ``instruction_index`` is one-based, matching the convention of the
    projected backend in ``validate.py``.
    """

    groups, clauses = _clause_index(constraint_map)
    items: list[dict[str, object]] = []
    for name in names:
        if name in groups:
            group = groups[name]
            items.append(
                {
                    "name": name,
                    "granularity": "group",
                    **_group_summary(group),
                    "clauses": [
                        {
                            "name": clause["name"],
                            "label": clause["label"],
                            "expression": clause["expression"],
                        }
                        for clause in (
                            _mapping(entry, "clause")
                            for entry in _sequence(group["clauses"], "clauses")
                        )
                    ],
                }
            )
        elif name in clauses:
            group, clause = clauses[name]
            items.append(
                {
                    "name": name,
                    "granularity": "clause",
                    **_group_summary(group),
                    "label": clause["label"],
                    "expression": clause["expression"],
                }
            )
        else:
            expected = "group_N" if GROUP_NAME.fullmatch(name) else "group_N_clause_M"
            raise ValidationError(
                f"the unsat core names {name!r}, which the constraint map does "
                f"not define; the encoder and the map disagree about {expected} "
                f"assertion names"
            )
    return {
        "core_kind": core_kind,
        "items": items,
        "named_assertions": list(names),
    }


def _assurance(
    constraint_map: Mapping[str, object],
    *,
    inspect_group: int | None,
) -> dict[str, object]:
    theorem = constraint_map.get("theorem")
    return {
        "claim": "bounded-trace",
        "certificate_schema": constraint_map["certificate_schema"],
        "scope": "bounded",
        "entry": constraint_map["entry"],
        "bounds": constraint_map["bounds"],
        "unknowns": constraint_map["unknowns"],
        "supported_actions": constraint_map["supported_actions"],
        "coverage": (
            ", ".join(
                str(action)
                for action in _sequence(
                    constraint_map["supported_actions"], "supported actions"
                )
            )
            + " actions plus role, currentTerm, logLength, commitIndex, "
            "allocated, joined, and submitted observations; only transaction "
            "identifiers may be symbolic"
        ),
        "granularity": "clause" if inspect_group is not None else "group",
        "inspect_group": inspect_group,
        "encoder_theorem": theorem if isinstance(theorem, str) else DEFAULT_THEOREM,
        "proof_gate": PROOF_GATE_TARGET,
        "backend": "lean-checked trace encoder",
    }


def _remove_stale_artifacts(output_directory: Path) -> None:
    """Delete artifacts of an earlier run so no stale evidence is read back.

    A reused output directory must never mix runs: an old ``result.json``
    reporting ``sat`` alongside a rejected certificate would read as the
    current verdict. Only names this runner writes are removed.
    """

    for name in (
        "constraint-map.json",
        "diagnosis.json",
        "error.json",
        "formula.smt2",
        "formula-core-candidate.smt2",
        "formula-reduced.smt2",
        "formula-unsat-core.smt2",
        "lake-build.log",
        "lean-encoder.stderr",
        "lean-encoder.stdout",
        "result.json",
        "unsat-core.txt",
        "unsat-core-original.txt",
    ):
        (output_directory / name).unlink(missing_ok=True)
    for path in output_directory.glob("cvc5-*.stdout"):
        path.unlink(missing_ok=True)
    for path in output_directory.glob("cvc5-*.stderr"):
        path.unlink(missing_ok=True)


def _record_failure(output_directory: Path, error: Exception) -> None:
    """Leave an explicit failure record where a verdict would have been."""

    try:
        output_directory.mkdir(parents=True, exist_ok=True)
        (output_directory / "error.json").write_text(
            json.dumps(
                {
                    "status": "error",
                    "certificate_rejected": isinstance(error, CertificateRejected),
                    "error": str(error),
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
    except OSError as record_error:
        print(f"could not write error.json: {record_error}", file=sys.stderr)


def _interpretation(status: str, entry: str) -> str:
    profile = "bootstrap" if entry == "bootstrap" else "explicit entry-template"
    if status == "sat":
        return (
            f"the encoded {profile} trace constraints are jointly "
            "satisfiable within the declared bounds; nothing outside the "
            "encoded fragment was checked"
        )
    if status == "unsat":
        return (
            "no assignment of the declared transaction unknowns satisfies the "
            f"encoded {profile} trace constraints within the declared "
            "bounds"
        )
    return "cvc5 could not decide the encoded constraints"


def validate_checked(
    certificate_path: Path,
    output_directory: Path,
    *,
    cvc5: Path | None = None,
    inspect_group: int | None = None,
    core_reduction_budget_seconds: float = 5.0,
    project_root: Path = PROJECT_ROOT,
) -> str:
    """Validate one certificate, leaving either a verdict or a failure record.

    The output directory is cleared of this runner's artifacts before any
    other work, so a reused directory can never present an earlier verdict as
    the current one. Failures write ``error.json`` when the directory is writable.
    """

    output_directory.mkdir(parents=True, exist_ok=True)
    _remove_stale_artifacts(output_directory)
    try:
        return _run_validation(
            certificate_path,
            output_directory,
            cvc5=cvc5,
            inspect_group=inspect_group,
            core_reduction_budget_seconds=core_reduction_budget_seconds,
            project_root=project_root,
        )
    except (SmtEncodingError, ValidationError, OSError) as error:
        _record_failure(output_directory, error)
        raise


def _run_validation(
    certificate_path: Path,
    output_directory: Path,
    *,
    cvc5: Path | None,
    inspect_group: int | None,
    core_reduction_budget_seconds: float,
    project_root: Path,
) -> str:
    """Build the proof gate, encode in Lean, solve, and keep all evidence."""

    started = time.perf_counter_ns()
    if inspect_group is not None and inspect_group < 1:
        raise ValidationError("--inspect-group selects a step, so it starts at 1")
    if not certificate_path.is_file():
        raise ValidationError(f"certificate does not exist: {certificate_path}")
    solver = find_cvc5(cvc5)

    proof_gate = build_proof_gate(project_root, output_directory / "lake-build.log")
    encoder_wall_ms = run_encoder(
        project_root,
        certificate_path,
        output_directory,
        inspect_group=inspect_group,
    )

    formula_path = output_directory / "formula.smt2"
    if not formula_path.is_file():
        raise ValidationError(f"the Lean encoder emitted no formula: {formula_path}")
    formula_text = formula_path.read_text(encoding="utf-8")
    constraint_map = read_constraint_map(
        output_directory / "constraint-map.json",
        inspect_group=inspect_group,
    )

    status_run = run_solver(solver, formula_path, output_directory, "cvc5-status")
    status = status_run.status
    print(status, flush=True)

    result: dict[str, object] = {
        "assurance": _assurance(constraint_map, inspect_group=inspect_group),
        "certificate": str(certificate_path),
        "constraint_map": "constraint-map.json",
        "cvc5": str(solver),
        "encoder_wall_ms": encoder_wall_ms,
        "formula": formula_path.name,
        "interpretation": _interpretation(status, str(constraint_map["entry"])),
        "named_assertions": formula_text.count("(assert (! "),
        "proof_gate": proof_gate,
        "status": status,
        "check_sat_wall_ms": status_run.wall_time_ms,
        "total_solver_wall_ms": status_run.wall_time_ms,
    }
    if inspect_group is not None:
        result["inspect_group_note"] = INSPECT_GROUP_NOTE

    if status == "unsat":
        result.update(
            explain_unsat(
                solver,
                formula_text,
                output_directory,
                constraint_map,
                core_reduction_budget_seconds=core_reduction_budget_seconds,
                inspect_group=inspect_group,
            )
        )
        result["total_solver_wall_ms"] = status_run.wall_time_ms + float(
            result["core_solver_wall_ms"]
        )

    (output_directory / "result.json").write_text(
        json.dumps(
            {
                **result,
                "validation_wall_ms": (time.perf_counter_ns() - started) / 1_000_000,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return status


@dataclass(frozen=True)
class CoreOutcome:
    """One reduction of an UNSAT core, with the claim it supports."""

    names: tuple[str, ...]
    checks: int
    complete: bool
    kind: str
    scope: str
    wall_time_ms: float


def reduce_core(
    original_core_names: tuple[str, ...],
    fixed_context: tuple[str, ...],
    reducible: tuple[str, ...],
    check_candidate: Callable[[tuple[str, ...], float], str],
    *,
    budget_seconds: float,
    inspect_group: int | None,
) -> CoreOutcome:
    """Reduce a whole core, or only the inspected group against fixed context."""

    if not budget_seconds > 0:
        raise SmtEncodingError("core reduction budget must be positive")

    if inspect_group is None:
        reduced = reduce_unsat_core(
            original_core_names,
            check_candidate,
            budget_seconds=budget_seconds,
        )
        return CoreOutcome(
            names=reduced.names,
            checks=reduced.checks,
            complete=reduced.complete,
            kind=(
                "subset-minimal"
                if reduced.complete
                else "heuristically reduced within budget"
            ),
            scope="every core assertion",
            wall_time_ms=reduced.wall_time_ms,
        )

    group = f"group_{inspect_group}"
    scope = (
        f"the clauses of {group}; every other core assertion is fixed context "
        f"and was never removed"
    )
    if not reducible:
        return CoreOutcome(
            names=original_core_names,
            checks=0,
            complete=True,
            kind=f"unreduced; {group} contributed no assertion to the core",
            scope=scope,
            wall_time_ms=0.0,
        )

    started = time.perf_counter_ns()
    context_only = check_candidate((), budget_seconds)
    if context_only == "unsat":
        return CoreOutcome(
            names=fixed_context,
            checks=1,
            complete=True,
            kind=(
                f"the clauses of {group} are not required; the fixed context "
                f"assertions are unsat on their own"
            ),
            scope=scope,
            wall_time_ms=(time.perf_counter_ns() - started) / 1_000_000,
        )

    remaining_seconds = (
        budget_seconds - (time.perf_counter_ns() - started) / 1_000_000_000
    )
    if context_only != "sat" or remaining_seconds <= 0:
        return CoreOutcome(
            names=original_core_names,
            checks=1,
            complete=False,
            kind=f"heuristically reduced within budget inside {group}",
            scope=scope,
            wall_time_ms=(time.perf_counter_ns() - started) / 1_000_000,
        )

    reduced = reduce_unsat_core(
        reducible,
        check_candidate,
        budget_seconds=remaining_seconds,
    )
    kept = set(fixed_context).union(reduced.names)
    return CoreOutcome(
        names=tuple(name for name in original_core_names if name in kept),
        checks=reduced.checks + 1,
        complete=reduced.complete,
        kind=(
            f"clause-minimal inside {group} with the other core assertions fixed"
            if reduced.complete
            else (
                f"heuristically reduced within budget inside {group} with the "
                f"other core assertions fixed"
            )
        ),
        scope=scope,
        wall_time_ms=(time.perf_counter_ns() - started) / 1_000_000,
    )


def explain_unsat(
    solver: Path,
    formula_text: str,
    output_directory: Path,
    constraint_map: Mapping[str, object],
    *,
    core_reduction_budget_seconds: float,
    inspect_group: int | None = None,
) -> dict[str, object]:
    """Extract, reduce, and explain one UNSAT core.

    Without an inspected group every core assertion is a reduction candidate.
    With one, only that group's clauses are candidates and every other core
    assertion is held fixed, so reduction refines the inspected action instead
    of rewriting which steps the explanation blames.
    """

    core_formula_path = output_directory / "formula-unsat-core.smt2"
    write_formula(core_formula_path, add_query(formula_text, "get-unsat-core"))
    core_run = run_solver(
        solver,
        core_formula_path,
        output_directory,
        "cvc5-unsat-core",
    )
    if core_run.status != "unsat":
        raise ValidationError("the unsat-core run did not reproduce UNSAT")
    original_core = query_payload(core_run, "an unsat core")
    original_core_names = parse_unsat_core(original_core)
    original_core_path = output_directory / "unsat-core-original.txt"
    original_core_path.write_text(original_core, encoding="utf-8")

    candidate_path = output_directory / "formula-core-candidate.smt2"

    if inspect_group is None:
        fixed_context: tuple[str, ...] = ()
        reducible = original_core_names
    else:
        clause_prefix = f"group_{inspect_group}_clause_"
        fixed_context = tuple(
            name for name in original_core_names if not name.startswith(clause_prefix)
        )
        reducible = tuple(
            name for name in original_core_names if name.startswith(clause_prefix)
        )
    held = set(fixed_context)

    def check_candidate(
        candidate_names: tuple[str, ...],
        remaining_seconds: float,
    ) -> str:
        keep = held.union(candidate_names)
        selected = tuple(name for name in original_core_names if name in keep)
        write_formula(
            candidate_path,
            restrict_to_assertions(formula_text, selected),
        )
        try:
            completed = subprocess.run(
                [str(solver), "--lang=smt2", str(candidate_path)],
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=remaining_seconds,
            )
        except subprocess.TimeoutExpired:
            return "inconclusive"
        if completed.returncode != 0:
            return "inconclusive"
        try:
            status = solver_status(completed.stdout)
            return "inconclusive" if status == "unknown" else status
        except ValidationError:
            return "inconclusive"

    reduction = reduce_core(
        original_core_names,
        fixed_context,
        reducible,
        check_candidate,
        budget_seconds=core_reduction_budget_seconds,
        inspect_group=inspect_group,
    )
    core_names = reduction.names
    core_path = output_directory / "unsat-core.txt"
    core_path.write_text("(\n" + "\n".join(core_names) + "\n)\n", encoding="utf-8")

    reduced_formula_path = output_directory / "formula-reduced.smt2"
    write_formula(
        reduced_formula_path,
        restrict_to_assertions(formula_text, core_names),
    )
    core_kind = reduction.kind
    diagnosis = core_diagnosis(constraint_map, core_names, core_kind=core_kind)
    diagnosis_path = output_directory / "diagnosis.json"
    diagnosis_path.write_text(
        json.dumps(diagnosis, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return {
        "core_kind": core_kind,
        "core_fixed_context_assertions": len(fixed_context),
        "core_reduction_budget_seconds": core_reduction_budget_seconds,
        "core_reduction_candidates": len(reducible),
        "core_reduction_checks": reduction.checks,
        "core_reduction_complete": reduction.complete,
        "core_reduction_scope": reduction.scope,
        "core_reduction_wall_ms": reduction.wall_time_ms,
        "core_reduced_by": "deterministic chunk and greedy deletion",
        "core_solver_wall_ms": core_run.wall_time_ms + reduction.wall_time_ms,
        "diagnosis": diagnosis_path.name,
        "original_unsat_core": original_core_path.name,
        "original_unsat_core_assertions": len(original_core_names),
        "reduced_formula": reduced_formula_path.name,
        "reduced_unsat_core_assertions": len(core_names),
        "unsat_core": core_path.name,
        "unsat_core_checked_by_cvc5": True,
    }


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "certificate",
        type=Path,
        help=f"trace certificate JSON ({CERTIFICATE_SCHEMA}; client-request v1/v2 also accepted)",
    )
    parser.add_argument(
        "output_directory",
        type=Path,
        help="directory for the formula, constraint map, and solver output",
    )
    parser.add_argument(
        "--cvc5",
        type=Path,
        help="cvc5 executable; defaults to cvc5 on PATH",
    )
    parser.add_argument(
        "--inspect-group",
        type=int,
        help=(
            "print the constraints of one clientRequest step as separate named "
            "clauses; every other group stays one coarse assertion"
        ),
    )
    parser.add_argument(
        "--core-reduction-budget-seconds",
        type=float,
        default=5.0,
        help="wall-clock budget for automatic UNSAT core reduction",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        validate_checked(
            args.certificate,
            args.output_directory,
            cvc5=args.cvc5,
            inspect_group=args.inspect_group,
            core_reduction_budget_seconds=args.core_reduction_budget_seconds,
        )
    except (SmtEncodingError, ValidationError, OSError) as error:
        print(f"checked trace validation failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
