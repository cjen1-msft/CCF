#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Generate the self-contained deterministic-reduction critique report."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import html
import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Mapping, Sequence

SCRIPT_PATH = Path(__file__).resolve()
REPO_ROOT = SCRIPT_PATH.parents[2]
LEAN_ROOT = REPO_ROOT / "lean"
DEFAULT_CERTIFICATE = (
    LEAN_ROOT
    / ".lake"
    / "build"
    / "full-trace-prototype"
    / "proposed-mapping-certificate-v2.json"
)
DEFAULT_AUDIT = (
    LEAN_ROOT / ".lake" / "build" / "reduction-critique" / "corpus-audit-v1.json"
)
DEFAULT_CANONICAL_REPORT = (
    LEAN_ROOT
    / ".lake"
    / "build"
    / "cheap-full-state-smt"
    / "canonical-check-report-v1.json"
)
DEFAULT_CANONICAL_OUTPUT = (
    LEAN_ROOT / ".lake" / "build" / "cheap-full-state-smt" / "canonical-lean.out"
)
DEFAULT_CONTEXT_REPORT = LEAN_ROOT / "CCFRaft" / "trace-validation-pipeline-report.html"
DEFAULT_OUTPUT = LEAN_ROOT / "CCFRaft" / "reduction-critique-report.html"
WORKSPACE_URL = (
    "vscode://vscode-remote/wsl+AzureLinux3.0"
    "/home/cjen1-msft/CCF/.worktrees/veil-consistency"
)
CERTIFICATE_SCHEMA = "ccfraft-proposed-deterministic-mapping/v2"
AUDIT_SCHEMA = "ccfraft-reduction-corpus-audit/v1"
EXPECTED_RISK_COUNTS = {
    "total": 28,
    "severity": {"High": 12, "Medium": 16},
    "lens": {"Correctness": 10, "Maintainability": 8, "Operational": 10},
    "disposition": {"Act now": 24, "Consider": 2, "Noted": 2},
}


class ReportError(RuntimeError):
    """Report an absent or inconsistent report input."""


def require(condition: bool, message: str) -> None:
    """Raise a report error when a required condition is false."""

    if not condition:
        raise ReportError(message)


def read_json(path: Path) -> dict[str, Any]:
    """Read a JSON object with a path-labelled error."""

    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ReportError(f"cannot read JSON artifact {path}: {error}") from error
    require(isinstance(value, dict), f"JSON artifact is not an object: {path}")
    return value


def sha256_file(path: Path) -> str:
    """Return one file's SHA-256 digest."""

    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def run_git(args: Sequence[str]) -> str:
    """Run a read-only git command from the repository root."""

    completed = subprocess.run(
        ["git", *args],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    require(
        completed.returncode == 0,
        f"git {' '.join(args)} failed: {completed.stderr.strip()}",
    )
    return completed.stdout.strip()


def repository_relative(path: Path) -> str:
    """Return a repository-relative POSIX path."""

    return path.resolve().relative_to(REPO_ROOT).as_posix()


def find_line(path: Path, needle: str) -> int:
    """Find a stable needle in a current working-tree file."""

    for number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        if needle in line:
            return number
    raise ReportError(f"source marker {needle!r} is absent from {path}")


def find_committed_line(head: str, relative: str, needle: str) -> int:
    """Find a stable needle in the commit-pinned file."""

    source = run_git(["show", f"{head}:{relative}"])
    for number, line in enumerate(source.splitlines(), start=1):
        if needle in line:
            return number
    raise ReportError(f"source marker {needle!r} is absent from {relative}@{head}")


def vscode_url(path: Path, line: int = 1) -> str:
    """Build a VS Code WSL source link."""

    return "vscode://vscode-remote/wsl+AzureLinux3.0" f"{path.resolve()}:{line}:1"


def github_url(head: str, relative: str, line: int) -> str:
    """Build a commit-pinned GitHub source link."""

    return f"https://github.com/cjen1-msft/CCF/blob/{head}/{relative}#L{line}"


def safe_json(value: Any) -> str:
    """Serialize data for an inert HTML JSON script."""

    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"))
        .replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
    )


def nested(mapping: Mapping[str, Any], *keys: str) -> Any:
    """Read one required nested field."""

    value: Any = mapping
    traversed: list[str] = []
    for key in keys:
        traversed.append(key)
        require(
            isinstance(value, Mapping) and key in value,
            f"artifact field is absent: {'.'.join(traversed)}",
        )
        value = value[key]
    return value


def as_int(value: Any, label: str) -> int:
    """Read a JSON integer without accepting booleans."""

    require(type(value) is int, f"{label} is not an integer")
    return value


def source_specs() -> list[tuple[str, Path, str, str]]:
    """Return source-map entries and their stable line needles."""

    return [
        (
            "Replicate scenario",
            REPO_ROOT / "tests" / "raft_scenarios" / "replicate",
            "start_node,0",
            "Golden fixture input.",
        ),
        (
            "Trace preprocessor",
            REPO_ROOT / "tests" / "raft_scenarios_runner.py",
            "def preprocess_for_trace_validation",
            "Removes producer records, synthesizes bootstrap, and merges node streams.",
        ),
        (
            "Deterministic reducer",
            LEAN_ROOT / "CCFRaft" / "full_trace_prototype.py",
            "def validate_events",
            "Pins 53 event objects, 22 reductions, and 43 action templates.",
        ),
        (
            "Corpus audit",
            LEAN_ROOT / "CCFRaft" / "audit_reduction_corpus.py",
            "def audit_scenario",
            "Runs the exact preprocessor and reducer across all scenarios.",
        ),
        (
            "Report generator",
            SCRIPT_PATH,
            "def build_report_data",
            "Builds this report from live artifacts and source markers.",
        ),
        (
            "Report check",
            LEAN_ROOT / "check_ccfraft_reduction_critique_report.sh",
            "set -euo pipefail",
            "Regenerates and validates every report artifact.",
        ),
        (
            "Canonical witness generator",
            LEAN_ROOT / "CCFRaft" / "cheap_full_state_lean.py",
            "def generate(",
            "Generates canonical replay checks for projected fields and spans.",
        ),
        (
            "Grammar-safe cuts ADR",
            LEAN_ROOT
            / "adr"
            / "0002-grammar-safe-cuts-and-symbolic-trace-alignment.md",
            "Define grammar safety over one global event order",
            "Defines interleaved reductions, safe cuts, and footprint proof duties.",
        ),
        (
            "TLA trace checker",
            REPO_ROOT / "tla" / "consensus" / "Traceccfraft.tla",
            "TraceAppendEntriesBatchsize",
            "Retains physical batch ranges and broader election and cleanup events.",
        ),
    ]


def is_tracked(relative: str) -> bool:
    """Return whether Git tracks a path."""

    completed = subprocess.run(
        ["git", "ls-files", "--error-unmatch", "--", relative],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    return completed.returncode == 0


def path_status(relative: str) -> str:
    """Return the short Git status for one path."""

    return run_git(["status", "--short", "--untracked-files=all", "--", relative])


def build_source_map(head: str) -> list[dict[str, Any]]:
    """Choose commit-pinned links for clean files and VS Code links otherwise."""

    sources: list[dict[str, Any]] = []
    for name, path, needle, role in source_specs():
        require(path.is_file(), f"source-map file is absent: {path}")
        relative = repository_relative(path)
        status = path_status(relative)
        tracked = is_tracked(relative)
        if tracked and not status:
            line = find_committed_line(head, relative, needle)
            url = github_url(head, relative, line)
            authority = f"HEAD {head[:12]}"
            link_kind = "GitHub"
        else:
            line = find_line(path, needle)
            url = vscode_url(path, line)
            authority = "current working tree"
            link_kind = "VS Code"
        sources.append(
            {
                "name": name,
                "path": relative,
                "line": line,
                "role": role,
                "status": status or "clean",
                "authority": authority,
                "linkKind": link_kind,
                "url": url,
            }
        )
    return sources


def build_event_rows(certificate: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Flatten certificate observations into the omission and span explorer."""

    raw_events = certificate.get("raw_events")
    reductions = certificate.get("reductions")
    require(isinstance(raw_events, list), "certificate raw_events is absent")
    require(isinstance(reductions, list), "certificate reductions is absent")
    functions: dict[int, str] = {}
    for event in raw_events:
        require(isinstance(event, Mapping), "raw event is malformed")
        number = as_int(event.get("event"), "raw event number")
        raw = event.get("raw")
        require(isinstance(raw, str), f"event {number}: raw input is absent")
        row = json.loads(raw)
        functions[number] = str(row["msg"]["function"])

    rows: list[dict[str, Any]] = []
    for reduction in reductions:
        require(isinstance(reduction, Mapping), "certificate reduction is malformed")
        reduction_number = as_int(reduction.get("reduction"), "reduction number")
        observations = reduction.get("observations")
        require(isinstance(observations, list), "reduction observations are absent")
        action_numbers = [
            as_int(action.get("action"), "action number")
            for action in reduction.get("actions", [])
            if isinstance(action, Mapping)
        ]
        for observation in observations:
            require(isinstance(observation, Mapping), "observation is malformed")
            number = as_int(observation.get("event"), "observation event")
            decisions = observation.get("field_decisions")
            require(isinstance(decisions, list), f"event {number}: decisions absent")
            reason_counts = Counter(
                str(decision["reason"])
                for decision in decisions
                if isinstance(decision, Mapping) and decision.get("status") == "omitted"
            )
            position = observation.get("position")
            require(isinstance(position, Mapping), f"event {number}: position absent")
            rows.append(
                {
                    "event": number,
                    "function": functions[number],
                    "reduction": reduction_number,
                    "reductionName": str(reduction.get("name", "")),
                    "actions": action_numbers,
                    "position": dict(position),
                    "positionKind": str(position.get("kind", "")),
                    "projected": sum(
                        isinstance(decision, Mapping)
                        and decision.get("status") == "projected"
                        for decision in decisions
                    ),
                    "omitted": sum(
                        isinstance(decision, Mapping)
                        and decision.get("status") == "omitted"
                        for decision in decisions
                    ),
                    "omissionReasons": dict(sorted(reason_counts.items())),
                    "exceptions": list(observation.get("exception_ids", [])),
                }
            )
    return sorted(rows, key=lambda row: int(row["event"]))


def build_reduction_rows(certificate: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Build compact N-to-M rows from certificate reductions."""

    reductions = certificate.get("reductions")
    require(isinstance(reductions, list), "certificate reductions are absent")
    result: list[dict[str, Any]] = []
    for reduction in reductions:
        require(isinstance(reduction, Mapping), "certificate reduction is malformed")
        events = reduction.get("events")
        actions = reduction.get("actions")
        require(
            isinstance(events, list) and isinstance(actions, list),
            "reduction cardinality data is malformed",
        )
        result.append(
            {
                "reduction": as_int(reduction.get("reduction"), "reduction number"),
                "name": str(reduction.get("name", "")),
                "events": events,
                "eventCount": len(events),
                "actions": [
                    {
                        "action": as_int(action.get("action"), "action number"),
                        "kind": str(action.get("kind", "")),
                        "template": str(action.get("template", "")),
                    }
                    for action in actions
                    if isinstance(action, Mapping)
                ],
                "actionCount": len(actions),
                "summary": str(reduction.get("summary", "")),
                "exceptions": list(reduction.get("exception_ids", [])),
            }
        )
    return result


def risk_rows() -> list[dict[str, str]]:
    """Return the reviewed correctness, maintenance, and operations risks."""

    return [
        {
            "id": "C1",
            "lens": "Correctness",
            "title": "S0 is not proved reachable",
            "severity": "High",
            "disposition": "Noted",
            "evidence": "Canonical output says arbitrary_existential=true, reachable_claim=false, and invariant_claim=false.",
            "failure": "A valid segment can begin in a state that no CCF execution can reach.",
            "mitigation": "Keep VALID_SEGMENT semantics. Require a reachable checkpoint before making a reachability or invariant claim.",
            "confidence": "High",
        },
        {
            "id": "C2",
            "lens": "Correctness",
            "title": "Reducer and checker share one mapping",
            "severity": "High",
            "disposition": "Act now",
            "evidence": "The certificate supplies both action skeletons and observation positions consumed downstream.",
            "failure": "A wrong event-to-action mapping can generate a witness that the checker accepts under the same wrong mapping.",
            "mitigation": "Author an independent event-to-macrostep relation and test it against the reducer output.",
            "confidence": "High",
        },
        {
            "id": "C3",
            "lens": "Correctness",
            "title": "Synthetic unit batches lack a refinement proof",
            "severity": "High",
            "disposition": "Act now",
            "evidence": "Physical batches 1..3 and 5..6 become unit sends, unit receives, and synthetic ACKs 1, 2, and 5.",
            "failure": "An intermediate unit state can violate or satisfy a property even though C++ exposes only the batch macrostep.",
            "mitigation": "Add a batch-aware action or prove that the unit-action sequence refines one C++ batch step.",
            "confidence": "High",
        },
        {
            "id": "C4",
            "lens": "Correctness",
            "title": "Preprocessing destroys input records",
            "severity": "High",
            "disposition": "Act now",
            "evidence": "The preprocessor pops producer records, collapses candidate records, and replaces bootstrap records before hashing.",
            "failure": "A changed discarded record can leave the transformed 53-event stream unchanged and pass the certificate hash.",
            "mitigation": "Hash the raw stream and emit a record-by-record transformation manifest.",
            "confidence": "High",
        },
        {
            "id": "C5",
            "lens": "Correctness",
            "title": "Event 5 packet correspondence is weakened",
            "severity": "Medium",
            "disposition": "Act now",
            "evidence": "The cheap footprint records a source-log reconstruction exception for the initial follower receive.",
            "failure": "The model can explain the receive with reconstructed source state that the physical packet did not establish.",
            "mitigation": "Give event 5 an explicit exception class and independently check the packet-to-request relation.",
            "confidence": "Medium",
        },
        {
            "id": "C6",
            "lens": "Correctness",
            "title": "Committable frontier is omitted",
            "severity": "Medium",
            "disposition": "Act now",
            "evidence": "All 54 committable_indices leaves are input-validated but not projected into canonical semantics.",
            "failure": "The trace can report a wrong committable frontier while the reduced action sequence still passes.",
            "mitigation": "Check the frontier against signatures and the canonical state at every relevant observation.",
            "confidence": "High",
        },
        {
            "id": "C7",
            "lens": "Correctness",
            "title": "Capacity derives from proposed actions",
            "severity": "Medium",
            "disposition": "Act now",
            "evidence": "infer_capacities recomputes lane and action bounds from the reducer's own 43-action expansion.",
            "failure": "A mapping bug can omit an action and lower the bound that might have exposed that omission.",
            "mitigation": "Derive lower bounds from raw observations, then close the footprint over canonical action reads and writes.",
            "confidence": "High",
        },
        {
            "id": "C8",
            "lens": "Correctness",
            "title": "Entry contents have no stable identity",
            "severity": "Medium",
            "disposition": "Consider",
            "evidence": "Packets expose ranges and terms but the production trace does not carry a digest for each replicated entry.",
            "failure": "Different payloads with equal indices and terms can collapse to the same explanation.",
            "mitigation": "Instrument packet and entry digests with privacy and cost review.",
            "confidence": "Medium",
        },
        {
            "id": "C9",
            "lens": "Correctness",
            "title": "Span post-state metadata is not an independent check",
            "severity": "Medium",
            "disposition": "Act now",
            "evidence": "Six spans name post_state_observation_event and post_state_fields, but downstream checks derive observations from the shared certificate.",
            "failure": "Span-end state can drift while metadata still looks complete.",
            "mitigation": "Consume and validate span post-state metadata in an independently authored correspondence checker.",
            "confidence": "Medium",
        },
        {
            "id": "C10",
            "lens": "Correctness",
            "title": "One passing scenario cannot establish general correspondence",
            "severity": "Medium",
            "disposition": "Act now",
            "evidence": "Only replicate passes. It accounts for 53 of 9,480 post-preprocessing events.",
            "failure": "Election, reconfiguration, retirement, loss, and conflict behavior can remain unmapped.",
            "mitigation": "Run a versioned corpus manifest in CI and require declared grammar coverage.",
            "confidence": "High",
        },
        {
            "id": "M1",
            "lens": "Maintainability",
            "title": "The transcript is not a grammar",
            "severity": "High",
            "disposition": "Act now",
            "evidence": "EXPECTED_EVENTS pins every ordinal from 1 through 53 and reduction_specs pins all 22 groups.",
            "failure": "A valid interleaving or compatible extra event becomes an edit across fixture tables.",
            "mitigation": "Freeze this file as replicate-v1 and build productions over per-node FIFOs and open reductions.",
            "confidence": "High",
        },
        {
            "id": "M2",
            "lens": "Maintainability",
            "title": "Mapping correctness has no independent owner",
            "severity": "High",
            "disposition": "Act now",
            "evidence": "The reducer defines action templates, positions, exceptions, and field semantics in one module.",
            "failure": "A reviewer must validate one large self-consistent story rather than compare independent specifications.",
            "mitigation": "Separate parsing, mapping, and semantic correspondence into independently tested artifacts.",
            "confidence": "High",
        },
        {
            "id": "M3",
            "lens": "Maintainability",
            "title": "Footprint and topology are duplicated",
            "severity": "High",
            "disposition": "Act now",
            "evidence": "Two active nodes, 15 world nodes, queue lanes, index bounds, and configuration records recur across reducer, SMT, and checker.",
            "failure": "One layer can change without the others, producing false capacity or completion claims.",
            "mitigation": "Extract the footprint from semantic reads and writes and make every backend consume it.",
            "confidence": "High",
        },
        {
            "id": "M4",
            "lens": "Maintainability",
            "title": "Event meaning is split across many tables",
            "severity": "Medium",
            "disposition": "Act now",
            "evidence": "Expected rows, packets, reductions, positions, spans, exceptions, and omissions all key by absolute event number.",
            "failure": "A local event edit can leave a stale position or omission entry elsewhere.",
            "mitigation": "Define each production once with its fields, actions, checks, and exception class.",
            "confidence": "High",
        },
        {
            "id": "M5",
            "lens": "Maintainability",
            "title": "Downstream checks duplicate absolute positions",
            "severity": "Medium",
            "disposition": "Act now",
            "evidence": "Action numbers, event numbers, and six span event IDs recur in generated SMT and Lean checks.",
            "failure": "Inserting one action shifts later constants and can bind checks to the wrong state.",
            "mitigation": "Use stable reduction IDs and derive ordinals after parsing.",
            "confidence": "High",
        },
        {
            "id": "M6",
            "lens": "Maintainability",
            "title": "Exception metadata can drift from effective omissions",
            "severity": "Medium",
            "disposition": "Act now",
            "evidence": "The reducer checks bidirectional exception references, but omission behavior also lives in FIELD_OMISSIONS and downstream encoders.",
            "failure": "An exception can remain documented while a backend weakens a different field.",
            "mitigation": "Generate effective omission reports from one typed exception registry and reject undeclared weakening.",
            "confidence": "Medium",
        },
        {
            "id": "M7",
            "lens": "Maintainability",
            "title": "Exact schema rejects compatible changes",
            "severity": "Medium",
            "disposition": "Noted",
            "evidence": "Top-level and message objects must equal the pinned dictionaries exactly.",
            "failure": "A harmless trace field addition breaks the oracle.",
            "mitigation": "Keep exactness for replicate-v1. Give a production grammar an explicit compatible version policy.",
            "confidence": "High",
        },
        {
            "id": "M8",
            "lens": "Maintainability",
            "title": "Claim boundaries are spread across documents",
            "severity": "Medium",
            "disposition": "Act now",
            "evidence": "Certificate, pipeline report, canonical output, and ADR each qualify the result differently.",
            "failure": "A caller can quote VALID_SEGMENT without the arbitrary-S0 and unproved-mapping qualifiers.",
            "mitigation": "Emit one typed result with claim level, assumptions, and artifact hashes.",
            "confidence": "Medium",
        },
        {
            "id": "O1",
            "lens": "Operational",
            "title": "The input contract exists only in the test harness",
            "severity": "High",
            "disposition": "Act now",
            "evidence": "Raft tracing is off by default, cmd annotations come from raft_driver, and production replicate records lack payload identity.",
            "failure": "A production collector cannot recreate the accepted input contract.",
            "mitigation": "Version a production event envelope with correlation and packet or entry identity.",
            "confidence": "High",
        },
        {
            "id": "O2",
            "lens": "Operational",
            "title": "h_ts is not distributed order",
            "severity": "High",
            "disposition": "Act now",
            "evidence": "The fixture requires global monotonic h_ts and thread_id 0 after a process-local merge.",
            "failure": "Cross-node clock or collector reorder looks like a semantic trace failure.",
            "mitigation": "Add per-node sequence, stream incarnation, and correlation. Present collector order separately.",
            "confidence": "High",
        },
        {
            "id": "O3",
            "lens": "Operational",
            "title": "Partial windows and loss look invalid",
            "severity": "High",
            "disposition": "Act now",
            "evidence": "The fixed transcript starts at synthetic bootstrap and infer_capacities requires every modeled queue to drain.",
            "failure": "A valid capture that starts mid-operation or ends with messages in flight is rejected.",
            "mitigation": "Parse open reductions, over-read to grammar-safe cuts, and classify incomplete capture separately.",
            "confidence": "High",
        },
        {
            "id": "O4",
            "lens": "Operational",
            "title": "Dense index bounds do not fit long-lived logs",
            "severity": "High",
            "disposition": "Act now",
            "evidence": "The prototype allocates through max absolute index 7 and couples capacity to the fixed trace.",
            "failure": "A production index in the millions creates an impractical dense model or a false resource failure.",
            "mitigation": "Use sparse absolute indices with proved summaries for omitted ranges.",
            "confidence": "High",
        },
        {
            "id": "O5",
            "lens": "Operational",
            "title": "CI does not protect corpus coverage",
            "severity": "High",
            "disposition": "Act now",
            "evidence": "The reducer check runs replicate only; this audit is the first all-scenario manifest.",
            "failure": "Trace schema or scenario behavior can drift without a reviewed coverage delta.",
            "mitigation": "Commit a corpus baseline policy and run the audit in CI.",
            "confidence": "High",
        },
        {
            "id": "O6",
            "lens": "Operational",
            "title": "Production schema and timing have no version",
            "severity": "Medium",
            "disposition": "Act now",
            "evidence": "The certificate is versioned, but the source raft_trace envelope is inferred from exact fields and h_ts.",
            "failure": "A producer upgrade cannot negotiate compatible parser behavior.",
            "mitigation": "Add event_schema_version and timing_semantics_version to every stream.",
            "confidence": "High",
        },
        {
            "id": "O7",
            "lens": "Operational",
            "title": "Certificate omits producer artifact identity",
            "severity": "Medium",
            "disposition": "Act now",
            "evidence": "The v2 certificate names the scenario and preprocessor but does not hash driver, preprocessor, or scenario files.",
            "failure": "The same certificate label can refer to a different producer pipeline.",
            "mitigation": "Record driver, scenario, preprocessor, reducer, and raw-stream hashes.",
            "confidence": "High",
        },
        {
            "id": "O8",
            "lens": "Operational",
            "title": "Failure classes are not a stable API",
            "severity": "Medium",
            "disposition": "Act now",
            "evidence": "The preprocessor uses Python assert and the reducer returns one generic process failure.",
            "failure": "Automation cannot distinguish malformed input, unsupported grammar, incomplete capture, invalid behavior, and internal error.",
            "mitigation": "Return typed failure classes with stable exit codes and structured details.",
            "confidence": "High",
        },
        {
            "id": "O9",
            "lens": "Operational",
            "title": "Reducer work has no explicit resource ceiling",
            "severity": "Medium",
            "disposition": "Act now",
            "evidence": "The fixture reducer has fixed size, but the proposed production path has no event, memory, or closure limit contract.",
            "failure": "A large or adversarial trace can consume unbounded parser or solver resources.",
            "mitigation": "Set event, open-reduction, footprint, memory, and time ceilings. Report ceiling failures as inconclusive.",
            "confidence": "Medium",
        },
        {
            "id": "O10",
            "lens": "Operational",
            "title": "The input hash normalizes line endings",
            "severity": "Medium",
            "disposition": "Consider",
            "evidence": "read_events uses splitlines and _input_digest rejoins records with newline.",
            "failure": "Byte-distinct captures can share the normalized certificate digest.",
            "mitigation": "Keep a byte-level raw-stream digest next to a canonical NDJSON digest.",
            "confidence": "High",
        },
    ]


def action_categories() -> dict[str, list[str]]:
    """Return the prominent disposition summary."""

    return {
        "Act on now": [
            "Freeze and rename the current reducer as the replicate-v1 golden oracle.",
            "Preserve and hash the raw stream. Emit a transformation manifest.",
            "Version the production event envelope. Add per-node sequence, stream incarnation, packet or entry digest, and correlation.",
            "Implement a real interleaving grammar with per-node FIFOs, open reductions, and set coverage.",
            "Independently encode and check event-to-macrostep correspondence.",
            "Move footprint extraction to semantic reads and writes. Derive lower bounds from raw input.",
            "Add the corpus manifest to CI with typed failure classes and resource ceilings.",
            "Fix event 5 classification, committable frontier checks, and span post-state consumption.",
        ],
        "Consider": [
            "Choose a batch-aware Lean action or prove a macrostep refinement lemma.",
            "Instrument packet and entry digests after privacy and cost review.",
            "Prove grammar coverage and footprint coverage.",
            "Decide whether the UI presents partial order or collector order as the primary view.",
        ],
        "Noted": [
            "Arbitrary S0 is intentional for VALID_SEGMENT semantics.",
            "The 695 semantic omissions are still exact input facts.",
            "Strict exact schema checking is useful for a golden regression oracle.",
        ],
        "Dismissed": [
            "Do not evolve the 53-row ordinal tables into a production parser.",
            "Do not claim that 558 checks independently prove the mapping.",
            "Do not interpret bounded UNSAT as proof that a trace is invalid.",
        ],
    }


def atomicity_shims() -> list[dict[str, str]]:
    """Describe the six current N-to-M correspondence shims."""

    return [
        {
            "id": "bootstrap",
            "title": "Synthetic bootstrap",
            "implementation": "The preprocessor removes the initial leader, configuration producer, signature producer, and commit sequence.",
            "mapping": "The commit record becomes event 1 bootstrap. The reducer begins before canonical commit action 1.",
            "risk": "The certificate hashes only the transformed record, not the discarded bootstrap history.",
            "hardening": "Retain raw records and declare each consumed or synthesized record in a transformation manifest.",
        },
        {
            "id": "event3",
            "title": "Event 3 add-configuration hook",
            "implementation": "C++ emits a heartbeat inside add_configuration before state exposes configuration entry 3.",
            "mapping": "The reducer interprets it as changeConfiguration followed by an append of entry 3.",
            "risk": "Six packet or state fields are exact fixture facts but omitted from action checkpoints.",
            "hardening": "Give the hook a versioned phase and prove its macrostep correspondence.",
        },
        {
            "id": "term-nack",
            "title": "Term update plus NACK",
            "implementation": "Events 5 through 7 show receive, follower transition, and response.",
            "mapping": "The reducer emits updateTerm 0 1 and one receive action.",
            "risk": "Event 5 relies on reconstructed source-log correspondence rather than one explicit packet relation.",
            "hardening": "Independently check the packet, term transition, and generated NACK as one production.",
        },
        {
            "id": "split-batches",
            "title": "Split batches and synthetic ACKs",
            "implementation": "C++ sends physical batches 1..3 and 5..6 and emits one response for each batch.",
            "mapping": "The reducer emits unit sends and receives plus synthetic responses at indices 1, 2, and 5.",
            "risk": "The generated intermediate states are not proved to refine the C++ macrostep.",
            "hardening": "Use a batch action or prove stuttering and safety refinement for the unit sequence.",
        },
        {
            "id": "helpers",
            "title": "Helper callbacks as assertions",
            "implementation": "add_configuration, execute_append_entries_sync, commit, and response callbacks appear inside receive handling.",
            "mapping": "Eighteen helper events constrain the owning reduction but add no action.",
            "risk": "A callback can move phase or change semantics while remaining grouped by a fixed ordinal.",
            "hardening": "Parse named begin, phase, and end productions instead of absolute positions.",
        },
        {
            "id": "heartbeats",
            "title": "Heartbeat round trips",
            "implementation": "Three heartbeat groups include send, receive, optional commit callback, response, and response receive.",
            "mapping": "Each group becomes appendEntries, receive, and response receive.",
            "risk": "The golden transcript requires drained queues and cannot represent a window ending with a heartbeat in flight.",
            "hardening": "Allow open reductions and certify grammar-safe outer cuts.",
        },
    ]


def corpus_rows(audit: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Build sortable report rows for all corpus scenarios."""

    scenarios = audit.get("scenarios")
    require(isinstance(scenarios, list), "audit scenarios are absent")
    result: list[dict[str, Any]] = []
    for scenario in scenarios:
        require(isinstance(scenario, Mapping), "audit scenario row is malformed")
        reducer = scenario.get("reducer")
        require(isinstance(reducer, Mapping), "audit reducer result is absent")
        result.append(
            {
                "scenario": str(scenario.get("scenario", "")),
                "raw": as_int(scenario.get("raw_count"), "raw count"),
                "preprocessed": as_int(
                    scenario.get("preprocessed_count"), "preprocessed count"
                ),
                "nodes": as_int(scenario.get("node_count"), "node count"),
                "functions": len(scenario.get("function_counts", {})),
                "packets": len(scenario.get("packet_family_counts", {})),
                "accepted": bool(reducer.get("accepted")),
                "stage": reducer.get("rejection_stage") or "accepted",
                "reason": str(reducer.get("reason", "")),
            }
        )
    return result


def count_risks(risks: Sequence[Mapping[str, str]]) -> dict[str, Any]:
    """Count report risks by reviewed dimensions."""

    return {
        "total": len(risks),
        "severity": dict(sorted(Counter(row["severity"] for row in risks).items())),
        "lens": dict(sorted(Counter(row["lens"] for row in risks).items())),
        "disposition": dict(
            sorted(Counter(row["disposition"] for row in risks).items())
        ),
    }


def artifact_entry(name: str, path: Path) -> dict[str, Any]:
    """Build one local artifact link and digest."""

    require(path.is_file(), f"report artifact is absent: {path}")
    return {
        "name": name,
        "path": repository_relative(path),
        "bytes": path.stat().st_size,
        "sha256": sha256_file(path),
        "url": vscode_url(path),
    }


def build_report_data(args: argparse.Namespace, generated_at: str) -> dict[str, Any]:
    """Read live evidence and build the browser data model."""

    certificate = read_json(args.certificate)
    audit = read_json(args.audit)
    require(
        certificate.get("schema_version") == CERTIFICATE_SCHEMA,
        "certificate schema is not v2",
    )
    require(
        audit.get("schema_version") == AUDIT_SCHEMA,
        "corpus audit schema is not v1",
    )
    counts = certificate.get("counts")
    require(
        counts
        == {
            "events": 53,
            "consumed_events": 53,
            "reductions": 22,
            "actions": 43,
            "observations": 53,
            "action_span_observations": 6,
            "action_checkpoint_observations": 47,
        },
        f"certificate counts drifted: {counts}",
    )
    exceptions = certificate.get("correspondence_exceptions")
    require(
        isinstance(exceptions, Mapping) and len(exceptions) == 9,
        "certificate must contain nine exception groups",
    )
    event_rows = build_event_rows(certificate)
    projected = sum(int(row["projected"]) for row in event_rows)
    omitted = sum(int(row["omitted"]) for row in event_rows)
    require(
        projected == 558 and omitted == 695,
        f"field counts drifted: projected={projected} omitted={omitted}",
    )

    aggregate = nested(audit, "aggregate")
    expected_audit = {
        "scenario_count": 50,
        "driver_successes": 50,
        "preprocessor_successes": 50,
        "total_raw_events": 10092,
        "total_preprocessed_events": 9480,
        "accepted_scenario_count": 1,
        "accepted_scenarios": ["replicate"],
        "accepted_event_instances": 53,
        "accepted_event_percentage": 0.56,
        "function_inventory_count": 19,
        "packet_family_count": 7,
        "reducer_expected_function_count": 10,
        "event_count_rejections": 49,
    }
    for key, value in expected_audit.items():
        require(aggregate.get(key) == value, f"audit baseline drifted at {key}")
    require(
        nested(aggregate, "preprocessed_event_count")
        == {"minimum": 3, "maximum": 696, "median": 151, "mean": 189.6},
        "preprocessed event distribution drifted",
    )
    require(
        nested(aggregate, "node_count") == {"minimum": 1, "maximum": 5},
        "corpus node range drifted",
    )

    canonical_context: dict[str, Any] = {
        "available": False,
        "result": "not read",
    }
    artifacts = [
        artifact_entry("V2 reduction certificate", args.certificate),
        artifact_entry("Corpus audit v1", args.audit),
    ]
    if args.canonical_report.is_file():
        canonical_report = read_json(args.canonical_report)
        canonical_counts = nested(canonical_report, "counts")
        require(
            canonical_counts.get("projected_fields") == 558
            and canonical_counts.get("explicit_omissions") == 695
            and canonical_counts.get("projected_unchecked") == 0,
            "canonical report field counts drifted",
        )
        canonical_context = {
            "available": True,
            "result": "VALID_SEGMENT",
            "counts": canonical_counts,
            "initialState": nested(canonical_report, "initial_state_semantics"),
        }
        artifacts.append(
            artifact_entry("Canonical check report", args.canonical_report)
        )
    if args.canonical_output.is_file():
        canonical_output = args.canonical_output.read_text(encoding="utf-8")
        require("VALID_SEGMENT" in canonical_output, "canonical output did not pass")
        artifacts.append(
            artifact_entry("Canonical checker output", args.canonical_output)
        )
    if args.context_report.is_file():
        artifacts.append(artifact_entry("Prior pipeline report", args.context_report))

    head = run_git(["rev-parse", "HEAD"])
    status = run_git(["status", "--short", "--untracked-files=all"])
    risks = risk_rows()
    risk_counts = count_risks(risks)
    require(
        risk_counts == EXPECTED_RISK_COUNTS,
        f"risk inventory drifted: {risk_counts}",
    )
    reductions = build_reduction_rows(certificate)
    return {
        "generatedAt": generated_at,
        "head": head,
        "git": {
            "dirty": bool(status),
            "changedPathCount": len(status.splitlines()) if status else 0,
        },
        "workspace": WORKSPACE_URL,
        "verdict": {
            "answer": "Keep the exact reducer as a fail-closed golden regression oracle. Replace it as the production grammar.",
            "keep": "replicate-v1 golden oracle",
            "replace": "fixed ordinal tables as production grammar",
        },
        "certificate": {
            "counts": counts,
            "projected": projected,
            "omitted": omitted,
            "exceptionCount": len(exceptions),
            "inputSha256": nested(certificate, "input", "sha256"),
            "reductions": reductions,
            "events": event_rows,
        },
        "audit": {
            "aggregate": aggregate,
            "scenarios": corpus_rows(audit),
        },
        "canonical": canonical_context,
        "risks": risks,
        "riskCounts": risk_counts,
        "actions": action_categories(),
        "shims": atomicity_shims(),
        "sources": build_source_map(head),
        "artifacts": artifacts,
    }


HTML_TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="dark">
  <title>CCFRaft deterministic reduction critique</title>
  <style>
    :root {
      color-scheme: dark;
      --bg: #0c1117;
      --panel: #121a23;
      --panel-2: #17212c;
      --line: #2a3948;
      --text: #e7edf3;
      --muted: #9db0c0;
      --green: #4fc38a;
      --green-bg: #10291f;
      --amber: #e5b454;
      --amber-bg: #2a2111;
      --red: #ef6b73;
      --red-bg: #30171b;
      --blue: #6eb5e8;
      --focus: #9dd7ff;
      --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      --sans: Inter, "Segoe UI", Arial, sans-serif;
    }
    * { box-sizing: border-box; }
    html { scroll-behavior: smooth; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: var(--sans);
      font-size: 16px;
      line-height: 1.55;
    }
    a { color: var(--blue); }
    a:hover { color: var(--focus); }
    button, input, select { font: inherit; }
    button, input, select, summary, a { outline-offset: 3px; }
    :focus-visible { outline: 2px solid var(--focus); }
    code, pre, .mono { font-family: var(--mono); }
    code {
      color: #c9e7fb;
      background: #0b141d;
      padding: 0.08rem 0.3rem;
      border-radius: 3px;
    }
    .wrap { width: min(1180px, calc(100% - 2rem)); margin: 0 auto; }
    .skip {
      position: absolute;
      width: 1px;
      height: 1px;
      padding: 0;
      margin: -1px;
      overflow: hidden;
      clip: rect(0, 0, 0, 0);
      white-space: nowrap;
      border: 0;
    }
    .skip:focus {
      position: fixed;
      width: auto;
      height: auto;
      margin: 0;
      clip: auto;
      top: 0.5rem;
      left: 0.5rem;
      padding: 0.6rem;
      background: var(--panel);
      z-index: 20;
    }
    header {
      border-bottom: 1px solid var(--line);
      background: #0e151d;
    }
    nav {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 1rem;
      padding: 0.8rem 0;
    }
    nav .links { display: flex; flex-wrap: wrap; gap: 0.8rem; }
    nav a { color: var(--muted); text-decoration: none; font-size: 0.9rem; }
    .hero { padding: 4.2rem 0 3rem; }
    .eyebrow {
      color: var(--blue);
      font: 700 0.78rem var(--mono);
      letter-spacing: 0.1em;
      text-transform: uppercase;
    }
    h1, h2, h3 { line-height: 1.15; }
    h1 {
      max-width: 920px;
      margin: 0.7rem 0 1rem;
      font-size: clamp(2.2rem, 6vw, 4.5rem);
      letter-spacing: -0.045em;
    }
    h2 {
      margin: 0 0 0.8rem;
      font-size: clamp(1.7rem, 4vw, 2.55rem);
      letter-spacing: -0.025em;
    }
    h3 { margin: 0 0 0.45rem; font-size: 1.06rem; }
    p { margin: 0.45rem 0 1rem; }
    .lede {
      max-width: 880px;
      color: var(--text);
      font-size: 1.22rem;
    }
    .subtle { color: var(--muted); }
    .badges { display: flex; flex-wrap: wrap; gap: 0.55rem; margin: 1.3rem 0; }
    .badge {
      display: inline-flex;
      align-items: center;
      min-height: 2rem;
      padding: 0.25rem 0.65rem;
      border: 1px solid var(--line);
      border-radius: 999px;
      background: var(--panel);
      color: var(--muted);
      font: 700 0.78rem var(--mono);
    }
    .badge.green { border-color: #2f7655; color: var(--green); background: var(--green-bg); }
    .badge.amber { border-color: #735925; color: var(--amber); background: var(--amber-bg); }
    .badge.red { border-color: #7b343b; color: var(--red); background: var(--red-bg); }
    .verdict-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 1rem;
      margin-top: 1.5rem;
    }
    .verdict {
      padding: 1.35rem;
      border: 1px solid var(--line);
      border-top-width: 4px;
      border-radius: 8px;
      background: var(--panel);
    }
    .verdict.keep { border-top-color: var(--green); }
    .verdict.replace { border-top-color: var(--red); }
    .verdict strong {
      display: block;
      margin-bottom: 0.3rem;
      font: 800 1rem var(--mono);
      letter-spacing: 0.06em;
    }
    .verdict.keep strong { color: var(--green); }
    .verdict.replace strong { color: var(--red); }
    main section {
      padding: 4.2rem 0;
      border-top: 1px solid var(--line);
      scroll-margin-top: 1rem;
    }
    .section-head {
      display: grid;
      grid-template-columns: minmax(0, 2fr) minmax(230px, 1fr);
      gap: 2rem;
      align-items: end;
      margin-bottom: 1.6rem;
    }
    .section-head p { color: var(--muted); margin: 0; }
    .card-grid {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 0.8rem;
    }
    .card, .note, details {
      border: 1px solid var(--line);
      border-radius: 7px;
      background: var(--panel);
    }
    .card { padding: 1rem; }
    .card .value {
      color: var(--blue);
      font: 700 1.6rem var(--mono);
      margin: 0.35rem 0;
    }
    .note {
      padding: 1rem 1.1rem;
      margin: 1rem 0;
      border-left: 4px solid var(--amber);
    }
    .note.green { border-left-color: var(--green); }
    .note.red { border-left-color: var(--red); }
    .architecture {
      display: grid;
      grid-template-columns: minmax(220px, 0.75fr) minmax(0, 1.25fr);
      gap: 1rem;
      margin: 1.4rem 0;
    }
    .stage-list { display: grid; gap: 0.5rem; }
    .stage-button, .chip-button {
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 5px;
      background: var(--panel);
      color: var(--text);
      text-align: left;
      padding: 0.75rem;
      cursor: pointer;
    }
    .stage-button[aria-selected="true"], .chip-button[aria-selected="true"] {
      border-color: var(--blue);
      background: #142536;
    }
    .stage-button span { display: block; color: var(--muted); font-size: 0.85rem; }
    .stage-detail {
      min-height: 220px;
      padding: 1.2rem;
      border: 1px solid var(--line);
      border-radius: 7px;
      background: var(--panel-2);
    }
    .strictness {
      display: grid;
      grid-template-columns: minmax(200px, 0.7fr) minmax(0, 1.3fr);
      gap: 1.5rem;
      align-items: center;
      margin-top: 1.5rem;
      padding: 1.2rem;
      border: 1px solid var(--line);
      border-radius: 7px;
      background: var(--panel);
    }
    input[type="range"] { width: 100%; accent-color: var(--blue); }
    .range-labels { display: flex; justify-content: space-between; color: var(--muted); font-size: 0.75rem; }
    .table-wrap {
      width: 100%;
      overflow-x: auto;
      border: 1px solid var(--line);
      border-radius: 7px;
    }
    table { width: 100%; border-collapse: collapse; min-width: 760px; }
    th, td {
      padding: 0.72rem 0.75rem;
      border-bottom: 1px solid var(--line);
      text-align: left;
      vertical-align: top;
    }
    th {
      background: #101923;
      color: var(--muted);
      font: 700 0.76rem var(--mono);
      letter-spacing: 0.04em;
      text-transform: uppercase;
    }
    th button {
      border: 0;
      background: transparent;
      color: inherit;
      padding: 0;
      cursor: pointer;
      text-align: left;
      text-transform: inherit;
      letter-spacing: inherit;
      font: inherit;
    }
    tbody tr:hover { background: #121f2b; }
    tbody tr:last-child td { border-bottom: 0; }
    .status-green { color: var(--green); }
    .status-amber { color: var(--amber); }
    .status-red { color: var(--red); }
    .controls {
      display: flex;
      flex-wrap: wrap;
      gap: 0.7rem;
      align-items: end;
      margin: 1rem 0;
    }
    .controls label { display: grid; gap: 0.25rem; color: var(--muted); font-size: 0.82rem; }
    input[type="search"], select {
      min-height: 2.5rem;
      border: 1px solid var(--line);
      border-radius: 5px;
      background: #0b141d;
      color: var(--text);
      padding: 0.45rem 0.65rem;
    }
    details { margin: 0.7rem 0; }
    details > summary {
      cursor: pointer;
      padding: 0.85rem 1rem;
      font-weight: 700;
    }
    details > div { padding: 0 1rem 1rem; }
    .decision-grid {
      display: grid;
      grid-template-columns: 1.3fr 1fr 1fr 1fr;
      gap: 0.8rem;
    }
    .decision-card { border-top: 3px solid var(--line); }
    .decision-card.act { border-top-color: var(--red); }
    .decision-card.consider { border-top-color: var(--amber); }
    .decision-card.noted { border-top-color: var(--blue); }
    .decision-card.dismissed { border-top-color: var(--muted); }
    .decision-card ul { margin: 0.5rem 0 0; padding-left: 1.15rem; }
    .decision-card li { margin-bottom: 0.45rem; }
    .nm-grid {
      display: grid;
      grid-template-columns: minmax(210px, 0.7fr) minmax(0, 1.3fr);
      gap: 1rem;
    }
    .chip-list { display: grid; gap: 0.45rem; }
    .mapping {
      display: grid;
      grid-template-columns: 1fr auto 1fr;
      gap: 0.8rem;
      align-items: stretch;
    }
    .mapping-lane {
      padding: 1rem;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: var(--panel);
    }
    .mapping-arrow { align-self: center; color: var(--blue); font: 800 1.25rem var(--mono); }
    .token {
      display: block;
      margin: 0.35rem 0;
      padding: 0.45rem 0.55rem;
      border: 1px solid var(--line);
      border-radius: 4px;
      background: #0b141d;
      font-family: var(--mono);
      font-size: 0.82rem;
    }
    .explorer {
      display: grid;
      grid-template-columns: minmax(210px, 0.7fr) minmax(0, 1.3fr);
      gap: 1rem;
    }
    .explorer-list {
      max-height: 470px;
      overflow: auto;
      display: grid;
      gap: 0.4rem;
      align-content: start;
    }
    .explorer-detail {
      min-height: 320px;
      padding: 1.15rem;
      border: 1px solid var(--line);
      border-radius: 7px;
      background: var(--panel);
    }
    .field-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 0.8rem;
      margin-top: 1rem;
    }
    .field-grid > div {
      padding: 0.8rem;
      border: 1px solid var(--line);
      border-radius: 5px;
      background: #0d161f;
    }
    .risk-meta { display: flex; flex-wrap: wrap; gap: 0.45rem; margin-bottom: 0.8rem; }
    .risk-meta span {
      border: 1px solid var(--line);
      border-radius: 999px;
      padding: 0.2rem 0.5rem;
      color: var(--muted);
      font: 700 0.74rem var(--mono);
    }
    .risk-detail-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 0.8rem;
    }
    .risk-detail-grid div {
      padding: 0.8rem;
      background: #0d161f;
      border: 1px solid var(--line);
      border-radius: 5px;
    }
    .bar-row {
      display: grid;
      grid-template-columns: minmax(180px, 1fr) 3fr minmax(70px, auto);
      gap: 0.7rem;
      align-items: center;
      margin: 0.42rem 0;
    }
    .bar-track { height: 0.55rem; background: #0a1219; border: 1px solid var(--line); }
    .bar { height: 100%; background: var(--blue); }
    .matrix {
      display: grid;
      grid-template-columns: 130px 1fr 1fr;
      border: 1px solid var(--line);
      border-radius: 7px;
      overflow: hidden;
    }
    .matrix > div { padding: 1rem; border-right: 1px solid var(--line); border-bottom: 1px solid var(--line); }
    .matrix > div:nth-child(3n) { border-right: 0; }
    .matrix .head { background: #101923; color: var(--muted); font: 700 0.8rem var(--mono); }
    .roadmap { display: grid; gap: 0.8rem; }
    .roadmap article {
      display: grid;
      grid-template-columns: 110px 1fr 1fr;
      gap: 1rem;
      padding: 1rem;
      border: 1px solid var(--line);
      border-left: 4px solid var(--blue);
      border-radius: 7px;
      background: var(--panel);
    }
    .roadmap .phase { color: var(--blue); font: 800 0.85rem var(--mono); }
    footer {
      padding: 2rem 0 3rem;
      border-top: 1px solid var(--line);
      color: var(--muted);
    }
    @media (max-width: 900px) {
      .card-grid, .decision-grid { grid-template-columns: 1fr 1fr; }
      .section-head, .architecture, .strictness, .nm-grid, .explorer { grid-template-columns: 1fr; }
      .roadmap article { grid-template-columns: 1fr; }
    }
    @media (max-width: 620px) {
      .wrap { width: min(100% - 1rem, 1180px); }
      .hero { padding-top: 2.7rem; }
      .verdict-grid, .card-grid, .decision-grid, .mapping, .field-grid, .risk-detail-grid { grid-template-columns: 1fr; }
      .mapping-arrow { justify-self: center; transform: rotate(90deg); }
      .matrix { grid-template-columns: 90px 1fr; }
      .matrix > div { border-right: 0; }
      .matrix .blank { display: none; }
    }
    @media print {
      :root { color-scheme: light; --bg: #fff; --panel: #fff; --panel-2: #fff; --line: #777; --text: #111; --muted: #333; --blue: #164f73; }
      body { background: #fff; color: #111; font-size: 10pt; }
      nav, .controls, input[type="range"] { display: none !important; }
      main section { padding: 1.2rem 0; break-inside: avoid; }
      details > div { display: block !important; }
      .table-wrap { overflow: visible; }
      table { min-width: 0; font-size: 8pt; }
      a { color: #111; text-decoration: underline; }
    }
  </style>
</head>
<body>
  <a class="skip" href="#main">Skip to report</a>
  <header>
    <div class="wrap">
      <nav aria-label="Report sections">
        <span class="mono">CCFRaft / reduction critique</span>
        <div class="links">
          <a href="#explanation">Explanation</a>
          <a href="#correctness">Risks</a>
          <a href="#corpus">Corpus</a>
          <a href="#roadmap">Roadmap</a>
          <a href="#sources">Sources</a>
        </div>
      </nav>
      <div class="hero">
        <div class="eyebrow">Deterministic reduction review</div>
        <h1>Keep the oracle. Replace the grammar.</h1>
        <p class="lede">The exact 53-event reducer is a strong fail-closed regression test for <code>replicate</code>. Its ordinal tables and shared correspondence are not a safe production parser.</p>
        <div class="badges" aria-label="Evidence summary">
          <span class="badge green">53 / 53 events exact</span>
          <span class="badge green">22 reductions / 43 actions</span>
          <span class="badge amber">53 / 9,480 corpus events</span>
          <span class="badge red">1 / 50 scenarios accepted</span>
          <span class="badge amber">mapping not independently proved</span>
        </div>
        <div class="verdict-grid" aria-label="Split verdict">
          <article class="verdict keep">
            <strong>KEEP</strong>
            <h2>replicate-v1 golden oracle</h2>
            <p>Preserve exact schema, field, ordering, ownership, coverage, hash, exception, and capacity checks as a fixed regression.</p>
          </article>
          <article class="verdict replace">
            <strong>REPLACE</strong>
            <h2>production grammar</h2>
            <p>Do not extend fixed event ordinals. Build interleaving productions, raw provenance, independent correspondence, and semantic footprint extraction.</p>
          </article>
        </div>
      </div>
    </div>
  </header>

  <main id="main">
    <section id="verdict">
      <div class="wrap">
        <div class="section-head">
          <div>
            <div class="eyebrow">Verdict</div>
            <h2>One sentence, then the work</h2>
          </div>
          <p>The current result is useful because it is narrow and strict. Risk starts when that narrow result is treated as a general parser or an independent correspondence proof.</p>
        </div>
        <div class="note green"><strong>Answer.</strong> Keep the exact reducer as a fail-closed golden regression oracle. Replace it as the production grammar.</div>
        <div class="decision-grid" id="decisionGrid" aria-label="Decision categories">
          <article class="card">Loading decisions...</article>
        </div>
      </div>
    </section>

    <section id="explanation">
      <div class="wrap">
        <div class="section-head">
          <div>
            <div class="eyebrow">Explanation</div>
            <h2>What the current chain checks</h2>
          </div>
          <p>Click each stage before reading the critique. The distinction between raw input, transformed input, mapping data, and canonical semantics drives every recommendation below.</p>
        </div>
        <div class="architecture">
          <div class="stage-list" id="architectureStages" role="tablist" aria-label="Reduction architecture">
            <button class="stage-button" type="button">Loading architecture...</button>
          </div>
          <div class="stage-detail" id="architectureDetail" role="tabpanel" aria-live="polite">
            <p>Loading stage evidence...</p>
          </div>
        </div>
        <div class="card-grid">
          <article class="card"><h3>Fixture lock</h3><div class="value">53 exact</div><p>Top-level keys, message objects, state, command context, source envelope, and strict <code>h_ts</code> order must match.</p></article>
          <article class="card"><h3>Reduction coverage</h3><div class="value">22 to 43</div><p>Every event has one owner. Actions are contiguous. Every event has one observation.</p></article>
          <article class="card"><h3>Semantic projection</h3><div class="value">558</div><p>Canonical replay checks projected state, packet, action, and span fields.</p></article>
          <article class="card"><h3>Input-only facts</h3><div class="value">695</div><p>Omitted semantic fields still match exact input. They are not ignored bytes.</p></article>
        </div>
        <details open>
          <summary>How preprocessing changes the trace</summary>
          <div>
            <p>The reducer never sees raw <code>raft_driver</code> output. <code>preprocess_for_trace_validation</code> removes the producer immediately before each <code>add_configuration</code>, collapses <code>recv_propose_request_vote</code> plus <code>become_candidate</code>, synthesizes bootstrap from the initial leader sequence, groups records by node, and merges them by <code>h_ts</code>.</p>
            <p>The v2 certificate retains and hashes the resulting NDJSON lines. It does not retain the discarded records or a manifest that explains each transformation.</p>
          </div>
        </details>
        <div class="strictness">
          <div>
            <label for="strictnessRange"><strong>Strictness versus generality</strong></label>
            <input id="strictnessRange" type="range" min="0" max="2" step="1" value="0" aria-describedby="strictnessLabels strictnessDetail">
            <div class="range-labels" id="strictnessLabels"><span>Golden</span><span>Grammar</span><span>Production</span></div>
          </div>
          <div id="strictnessDetail" aria-live="polite"><p>Loading profile...</p></div>
        </div>
      </div>
    </section>

    <section id="guarantee-map">
      <div class="wrap">
        <div class="section-head">
          <div>
            <div class="eyebrow">Guarantee map</div>
            <h2>Each stage proves a different claim</h2>
          </div>
          <p>A passing stage cannot lend authority to an earlier unproved transformation.</p>
        </div>
        <div class="table-wrap">
          <table>
            <thead><tr><th>Layer</th><th>Established</th><th>Not established</th><th>Status</th></tr></thead>
            <tbody>
              <tr><td>Raw driver input</td><td>The corpus audit records 10,092 function events and producer artifact hashes.</td><td>The v2 certificate does not preserve this stream.</td><td class="status-amber">Audit only</td></tr>
              <tr><td>Transformed input</td><td>All 53 lines, line hashes, fields, command annotations, and strict order match replicate-v1.</td><td>Discarded raw records did not affect the result.</td><td class="status-green">Exact fixture</td></tr>
              <tr><td>Certificate shape</td><td>One owner per event, 22 reductions, 43 contiguous actions, 53 observations, six spans, and bidirectional exception references.</td><td>The selected action expansion matches C++ semantics.</td><td class="status-green">Structurally checked</td></tr>
              <tr><td>Projected semantics</td><td>All 558 projected fields pass the canonical model for an arbitrary segment entry.</td><td>The mapping is independently correct. The 695 input-only facts constrain semantics.</td><td class="status-amber">Valid segment</td></tr>
              <tr><td>Canonical replay</td><td>All 43 actions apply. State and edge checks pass. Queues drain in the fixed completion.</td><td>The hand-maintained SMT lowering is equivalent to the model.</td><td class="status-green">Witness checked</td></tr>
              <tr><td>Reachability</td><td>No reachability claim is made.</td><td>S0 follows from canonical initialization or satisfies the full inductive invariant.</td><td class="status-red">Not established</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </section>

    <section id="n-to-m">
      <div class="wrap">
        <div class="section-head">
          <div>
            <div class="eyebrow">N-to-M example</div>
            <h2>Physical batches become model microsteps</h2>
          </div>
          <p>Select a reduction to see why event count and action count cannot be assumed equal.</p>
        </div>
        <div class="nm-grid">
          <div class="chip-list" id="mappingChoices"><button class="chip-button" type="button">Loading reductions...</button></div>
          <div id="mappingDetail" aria-live="polite"><p>Loading mapping...</p></div>
        </div>
        <div class="note"><strong>Traceccfraft contrast.</strong> The TLA trace checker retains physical AppendEntries batch ranges and one aggregate ACK. It also handles election, vote, drop, cleanup, and retirement behavior. The current reducer instead splits selected batches into unit actions because the Lean action is single-entry.</div>
      </div>
    </section>

    <section id="omissions">
      <div class="wrap">
        <div class="section-head">
          <div>
            <div class="eyebrow">Omission and span explorer</div>
            <h2>Exact input does not mean projected semantics</h2>
          </div>
          <p>Choose any event to inspect projected fields, input-only fields, action position, span metadata, and exception references.</p>
        </div>
        <div class="controls">
          <label>Filter events<input id="eventFilter" type="search" placeholder="Function, event, exception"></label>
          <label>Position<select id="eventPosition"><option value="all">All positions</option><option value="action_checkpoint">Point checkpoints</option><option value="action_span">Action spans</option></select></label>
        </div>
        <div class="explorer">
          <div class="explorer-list" id="eventList"><button class="chip-button" type="button">Loading events...</button></div>
          <div class="explorer-detail" id="eventDetail" aria-live="polite"><p>Loading event detail...</p></div>
        </div>
        <details>
          <summary>Why 695 omissions are still exact input facts</summary>
          <div>
            <p><code>validate_events</code> compares each complete message object with the pinned fixture before the certificate classifies fields. The 695 omissions therefore cannot vary in the transformed replicate-v1 input. The limitation is narrower: canonical replay does not consume those fields as semantic constraints.</p>
            <p>The largest groups are the trace envelope, scenario provenance, membership derived from logs, pre-vote state outside the Lean scope, configuration history assertions, and the committable frontier. Nine exception groups document deliberate N-to-M weakening.</p>
          </div>
        </details>
        <h3 style="margin-top:1.5rem">Atomicity shims</h3>
        <div class="nm-grid">
          <div class="chip-list" id="shimChoices"><button class="chip-button" type="button">Loading shims...</button></div>
          <div class="explorer-detail" id="shimDetail" aria-live="polite"><p>Loading shim...</p></div>
        </div>
      </div>
    </section>

    <section id="correctness">
      <div class="wrap">
        <div class="section-head">
          <div>
            <div class="eyebrow">Correctness critique</div>
            <h2>The main risk is shared interpretation</h2>
          </div>
          <p>The canonical checker gives strong evidence for the chosen 43-action segment. It cannot independently validate the reducer's choice because both consume the same mapping.</p>
        </div>
        <div class="note red"><strong>Highest priority.</strong> Preserve raw provenance, independently check event-to-macrostep correspondence, and settle batch atomicity before using this approach beyond replicate-v1.</div>
        <div class="controls">
          <label>Lens<select id="riskLens"><option value="all">All lenses</option><option value="Correctness">Correctness</option><option value="Maintainability">Maintainability</option><option value="Operational">Operational</option></select></label>
          <label>Severity<select id="riskSeverity"><option value="all">All severities</option><option value="High">High</option><option value="Medium">Medium</option></select></label>
          <label>Disposition<select id="riskDisposition"><option value="all">All dispositions</option><option value="Act now">Act now</option><option value="Consider">Consider</option><option value="Noted">Noted</option><option value="Dismissed">Dismissed</option></select></label>
          <label>Find risk<input id="riskFilter" type="search" placeholder="Evidence, failure, mitigation"></label>
        </div>
        <div class="explorer">
          <div class="explorer-list" id="riskList"><button class="chip-button" type="button">Loading risks...</button></div>
          <div class="explorer-detail" id="riskDetail" aria-live="polite"><p>Loading risk...</p></div>
        </div>
        <h3 style="margin-top:1.5rem">Sortable risk register</h3>
        <div class="table-wrap">
          <table id="riskTable">
            <thead><tr>
              <th><button type="button" data-sort="id">ID</button></th>
              <th><button type="button" data-sort="lens">Lens</button></th>
              <th><button type="button" data-sort="severity">Severity</button></th>
              <th><button type="button" data-sort="disposition">Disposition</button></th>
              <th><button type="button" data-sort="title">Risk</button></th>
              <th><button type="button" data-sort="confidence">Confidence</button></th>
            </tr></thead>
            <tbody><tr><td colspan="6">Loading risks...</td></tr></tbody>
          </table>
        </div>
      </div>
    </section>

    <section id="corpus">
      <div class="wrap">
        <div class="section-head">
          <div>
            <div class="eyebrow">Corpus coverage</div>
            <h2>One scenario passes out of fifty</h2>
          </div>
          <p>All scenarios pass the driver and the exact preprocessor. The other 49 fail at the reducer's first event-count check.</p>
        </div>
        <div class="card-grid">
          <article class="card"><h3>Driver and preprocessor</h3><div class="value">50 / 50</div><p>Every corpus scenario produces a transformed stream.</p></article>
          <article class="card"><h3>Reducer acceptance</h3><div class="value">1 / 50</div><p>Only <code>replicate</code> has exactly 53 pinned events.</p></article>
          <article class="card"><h3>Event coverage</h3><div class="value">0.56%</div><p>Accepted events are 53 of 9,480 post-preprocessing event instances.</p></article>
          <article class="card"><h3>Corpus shape</h3><div class="value">3..696</div><p>Median 151, mean 189.6, and one through five observed nodes.</p></article>
        </div>
        <div class="note"><strong>Function switches are insufficient.</strong> Eight rejected scenarios use no function outside the reducer's ten-function inventory: <code>append</code>, <code>large_entry_batching</code>, <code>reconfiguration</code>, <code>reconnect</code>, <code>retire_one</code>, <code>startup</code>, <code>startup_2nodes</code>, and <code>swap_single_node</code>.</div>
        <details open>
          <summary>Function and packet-family coverage</summary>
          <div>
            <p>The transformed corpus contains 19 functions and seven packet families. It includes candidate, pre-vote candidate, and retired states, terms 0 through 10, and indices 0 through 29.</p>
            <div id="functionBars"><p>Loading function inventory...</p></div>
            <h3 style="margin-top:1.2rem">Packet families</h3>
            <div id="packetBars"><p>Loading packet inventory...</p></div>
          </div>
        </details>
        <div class="controls">
          <label>Filter scenarios<input id="corpusFilter" type="search" placeholder="Scenario, stage, reason"></label>
          <label>Acceptance<select id="corpusAcceptance"><option value="all">All scenarios</option><option value="accepted">Accepted</option><option value="rejected">Rejected</option></select></label>
        </div>
        <div class="table-wrap">
          <table id="corpusTable">
            <thead><tr>
              <th><button type="button" data-sort="scenario">Scenario</button></th>
              <th><button type="button" data-sort="raw">Raw</button></th>
              <th><button type="button" data-sort="preprocessed">Preprocessed</button></th>
              <th><button type="button" data-sort="nodes">Nodes</button></th>
              <th><button type="button" data-sort="functions">Functions</button></th>
              <th><button type="button" data-sort="packets">Packets</button></th>
              <th><button type="button" data-sort="accepted">Reducer</button></th>
              <th><button type="button" data-sort="stage">Stage</button></th>
              <th>Reason</th>
            </tr></thead>
            <tbody><tr><td colspan="9">Loading corpus...</td></tr></tbody>
          </table>
        </div>
      </div>
    </section>

    <section id="maintainability">
      <div class="wrap">
        <div class="section-head">
          <div>
            <div class="eyebrow">Maintainability critique</div>
            <h2>Absolute positions multiply change cost</h2>
          </div>
          <p>A change to one event can touch expected messages, reductions, action positions, spans, omissions, exceptions, SMT constants, and generated checker positions.</p>
        </div>
        <div class="card-grid">
          <article class="card"><h3>Fixed transcript</h3><div class="value">1..53</div><p>The parser recognizes one flattened total order, not per-node productions with interleaving.</p></article>
          <article class="card"><h3>Mapping tables</h3><div class="value">many</div><p>Meaning is split across expected rows, packet maps, reductions, positions, spans, and exceptions.</p></article>
          <article class="card"><h3>Topology copies</h3><div class="value">3 layers</div><p>Reducer, SMT, and checker repeat the two-node footprint and 15-node completion.</p></article>
          <article class="card"><h3>Useful strictness</h3><div class="value">fail closed</div><p>Exact schema remains the right policy for the frozen golden oracle.</p></article>
        </div>
        <details>
          <summary>Conflict with the grammar-safe cuts ADR</summary>
          <div><p>The ADR allows reductions to consume non-contiguous global events while each node advances through local grammar. A safe cut closes every overlapping reduction interval. The fixed reducer instead assumes one complete 53-event order and cannot leave a reduction open at either edge.</p></div>
        </details>
      </div>
    </section>

    <section id="operational">
      <div class="wrap">
        <div class="section-head">
          <div>
            <div class="eyebrow">Operational critique</div>
            <h2>The test trace is not a production envelope</h2>
          </div>
          <p>Production needs stream identity, per-node order, correlation, partial-window handling, sparse absolute indices, safe failure classes, and resource ceilings.</p>
        </div>
        <div class="card-grid">
          <article class="card"><h3>Ordering</h3><div class="value">h_ts</div><p>Process-local timestamps merged by the harness are not a distributed happens-before relation.</p></article>
          <article class="card"><h3>Threading</h3><div class="value">thread 0</div><p>The oracle rejects any different producer-thread contract.</p></article>
          <article class="card"><h3>Window shape</h3><div class="value">closed</div><p>The trace starts at synthetic bootstrap and ends with every modeled queue drained.</p></article>
          <article class="card"><h3>Failure API</h3><div class="value">generic</div><p>Python assertions and one reducer exit do not separate invalid, unsupported, incomplete, inconclusive, and internal failure.</p></article>
        </div>
      </div>
    </section>

    <section id="false-matrix">
      <div class="wrap">
        <div class="section-head">
          <div>
            <div class="eyebrow">False acceptance and rejection</div>
            <h2>Strictness shifts risk rather than removing it</h2>
          </div>
          <p>The golden oracle is intentionally biased toward false rejection outside its fixture. A production validator must classify unsupported evidence without calling it invalid.</p>
        </div>
        <div class="matrix" role="table" aria-label="False acceptance and false rejection matrix">
          <div class="head blank"></div><div class="head">Trace is semantically valid</div><div class="head">Trace is semantically invalid</div>
          <div class="head">Validator accepts</div>
          <div><strong class="status-green">True accept</strong><p>Exact replicate-v1 transformed stream maps to the checked canonical segment.</p></div>
          <div><strong class="status-red">False accept</strong><p>Shared wrong mapping, destructive preprocessing, synthetic macrosteps, or omitted frontier and payload facts hide a mismatch.</p></div>
          <div class="head">Validator rejects</div>
          <div><strong class="status-amber">False reject</strong><p>Compatible schema additions, different interleaving, partial windows, in-flight messages, large indices, or another valid scenario fail the fixture table.</p></div>
          <div><strong class="status-green">True reject</strong><p>The transformed replicate-v1 stream changes an exact field, event owner, ordinal, hash, action position, or capacity invariant.</p></div>
        </div>
      </div>
    </section>

    <section id="alternatives">
      <div class="wrap">
        <div class="section-head">
          <div>
            <div class="eyebrow">Alternatives</div>
            <h2>Keep the oracle and build beside it</h2>
          </div>
          <p>The recommended path avoids weakening the useful golden test while production grammar and proof obligations mature independently.</p>
        </div>
        <div class="table-wrap">
          <table>
            <thead><tr><th>Alternative</th><th>What it buys</th><th>Main cost or flaw</th><th>Decision</th></tr></thead>
            <tbody>
              <tr><td>Keep oracle plus new grammar</td><td>Preserves exact regression evidence and gives production a clean grammar design.</td><td>Two named claim levels and two test paths.</td><td class="status-green">Recommended</td></tr>
              <tr><td>Evolve fixed tables</td><td>Small first diff for a second fixture.</td><td>Ordinal coupling grows and still cannot parse real interleaving.</td><td class="status-red">Dismissed</td></tr>
              <tr><td>Batch-aware Lean action</td><td>Matches physical atomicity and one aggregate ACK.</td><td>Expands the model API and proof work.</td><td class="status-amber">Consider</td></tr>
              <tr><td>Unit actions plus refinement lemma</td><td>Keeps current model actions and proves the microstep expansion.</td><td>Needs a precise C++ macrostep relation and stuttering argument.</td><td class="status-amber">Consider</td></tr>
              <tr><td>Keep destructive preprocessing</td><td>Produces compact legacy traces.</td><td>Cannot prove what discarded records said.</td><td class="status-red">Do not use alone</td></tr>
              <tr><td>Raw stream plus manifest</td><td>Auditable transformation, raw digest, and replayable provenance.</td><td>Larger artifact and versioned transformation schema.</td><td class="status-green">Required</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </section>

    <section id="roadmap">
      <div class="wrap">
        <div class="section-head">
          <div>
            <div class="eyebrow">Hardening roadmap</div>
            <h2>Gate each claim before widening it</h2>
          </div>
          <p>Each stage ends with an acceptance test. Do not use the next claim level until its gate passes.</p>
        </div>
        <div class="roadmap">
          <article><div class="phase">Stage 0</div><div><h3>Freeze the oracle</h3><p>Rename the current contract <code>replicate-v1</code>. Preserve exact schema, exceptions, negative controls, certificate rebuild, and canonical replay.</p></div><div><h3>Gate</h3><p>The current fixture and mutation suite pass byte-for-byte. No production caller imports ordinal tables.</p></div></article>
          <article><div class="phase">Stage 1</div><div><h3>Make input provenance lossless</h3><p>Store the raw digest, producer hashes, event schema, timing semantics, per-node sequence, stream incarnation, and a transformation manifest.</p></div><div><h3>Gate</h3><p>Changing any discarded raw record changes the manifest or raw digest. The transformed fixture still rebuilds v2 semantics.</p></div></article>
          <article><div class="phase">Stage 2</div><div><h3>Build the interleaving grammar</h3><p>Use per-node FIFOs, open reductions, N-to-M productions, set coverage, grammar-safe cuts, typed failure classes, and resource ceilings.</p></div><div><h3>Gate</h3><p>All 50 scenarios have a declared accepted, unsupported, incomplete, or invalid result. The eight same-function scenarios need no ordinal special case.</p></div></article>
          <article><div class="phase">Stage 3</div><div><h3>Prove correspondence and footprint</h3><p>Independently check event-to-macrostep relations. Add a batch action or refinement lemma. Extract the footprint from raw lower bounds and canonical reads and writes.</p></div><div><h3>Gate</h3><p>Every accepted production has an independent correspondence result and footprint coverage witness. Bounded UNSAT is invalid only after completeness.</p></div></article>
          <article><div class="phase">Stage 4</div><div><h3>Add production instrumentation and CI</h3><p>Add correlation and entry digests if review accepts them. Run the corpus manifest and grammar coverage proof in CI.</p></div><div><h3>Gate</h3><p>Version skew, partial capture, loss, timeouts, and ceilings return safe typed results. Coverage deltas require review.</p></div></article>
        </div>
      </div>
    </section>

    <section id="evidence">
      <div class="wrap">
        <div class="section-head">
          <div>
            <div class="eyebrow">Tests and evidence</div>
            <h2>What a rerun establishes</h2>
          </div>
          <p>The check regenerates the corpus and report, then validates syntax, links, deterministic data, baseline facts, and the report's own risk inventory.</p>
        </div>
        <div class="card-grid">
          <article class="card"><h3>Corpus execution</h3><div class="value">50</div><p>Runs <code>build/raft_driver</code>, exact preprocessing, and current <code>validate_events</code> for every scenario.</p></article>
          <article class="card"><h3>Golden acceptance</h3><div class="value">1</div><p>Asserts that only <code>replicate</code> passes and all other scenarios fail at event count.</p></article>
          <article class="card"><h3>Canonical context</h3><div class="value">VALID_SEGMENT</div><p>Reads current canonical output when present and checks 558 projected fields, 695 explicit omissions, and zero unchecked projections.</p></article>
          <article class="card"><h3>Report checks</h3><div class="value">28 risks</div><p>Checks Python, Black, ShellCheck, HTML structure, JavaScript syntax, HTML Tidy, ASCII, links, and deterministic regeneration.</p></article>
        </div>
        <details>
          <summary>Negative controls worth preserving</summary>
          <div><p>Keep field mutation, event deletion, event duplication, order change, hash mismatch, action-number gaps, ownership overlap, exception-reference mismatch, span mismatch, capacity mismatch, canonical action rejection, and observation mismatch tests. Add raw-record mutation, interleaving, open-window, batch-intermediate, payload-digest, version-skew, and resource-ceiling tests.</p></div>
        </details>
      </div>
    </section>

    <section id="sources">
      <div class="wrap">
        <div class="section-head">
          <div>
            <div class="eyebrow">Source map</div>
            <h2>Open the exact evidence</h2>
          </div>
          <p>Clean committed files use commit-pinned GitHub links. Modified and untracked files use current VS Code WSL links.</p>
        </div>
        <p><a href="__WORKSPACE_URL__">Open this workspace in VS Code</a></p>
        <div class="table-wrap">
          <table id="sourceTable">
            <thead><tr><th>Source</th><th>Role</th><th>Authority</th><th>Status</th><th>Open</th></tr></thead>
            <tbody><tr><td colspan="5">Loading sources...</td></tr></tbody>
          </table>
        </div>
        <details>
          <summary>Generated artifact hashes</summary>
          <div>
            <div class="table-wrap">
              <table id="artifactTable">
                <thead><tr><th>Artifact</th><th>Bytes</th><th>SHA-256</th><th>Open</th></tr></thead>
                <tbody><tr><td colspan="4">Loading artifacts...</td></tr></tbody>
              </table>
            </div>
          </div>
        </details>
      </div>
    </section>
  </main>

  <footer>
    <div class="wrap">
      <p>Generated <time datetime="__GENERATED_AT__">__GENERATED_AT__</time> from HEAD <code id="headValue">loading</code>. Report data is embedded. No network dependency is required.</p>
    </div>
  </footer>

  <script id="report-data" type="application/json">__REPORT_DATA__</script>
  <script>
  "use strict";
  const data = JSON.parse(document.getElementById("report-data").textContent);

  function element(tag, text, className) {
    const node = document.createElement(tag);
    if (text !== undefined) node.textContent = String(text);
    if (className) node.className = className;
    return node;
  }

  function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  function chooseButtons(container, items, render, label) {
    clear(container);
    items.forEach((item, index) => {
      const button = element("button", label(item), "chip-button");
      button.type = "button";
      button.setAttribute("aria-selected", String(index === 0));
      button.addEventListener("click", () => {
        container.querySelectorAll("button").forEach((candidate) => candidate.setAttribute("aria-selected", "false"));
        button.setAttribute("aria-selected", "true");
        render(item);
      });
      container.append(button);
    });
    if (items.length) render(items[0]);
  }

  function renderDecisions() {
    const grid = document.getElementById("decisionGrid");
    clear(grid);
    const classes = {"Act on now": "act", "Consider": "consider", "Noted": "noted", "Dismissed": "dismissed"};
    Object.entries(data.actions).forEach(([name, items]) => {
      const card = element("article", undefined, "card decision-card " + classes[name]);
      card.append(element("h3", name));
      const list = element("ul");
      items.forEach((item) => list.append(element("li", item)));
      card.append(list);
      grid.append(card);
    });
  }

  const architecture = [
    {
      title: "Raw driver stream",
      short: "10,092 corpus events plus command records",
      established: "The corpus audit runs the current driver and hashes the driver and scenario files.",
      transform: "Command markers and function events are still present. No reduction has run.",
      missing: "The v2 certificate does not retain this byte stream."
    },
    {
      title: "Preprocessor",
      short: "9,480 corpus events, 53 for replicate",
      established: "The exact test harness function runs. It groups by node and merges by h_ts.",
      transform: "It removes producer records, collapses candidate pairs, synthesizes bootstrap, and attaches cmd context.",
      missing: "There is no raw-to-transformed manifest."
    },
    {
      title: "V2 reducer",
      short: "53 events -> 22 reductions -> 43 actions",
      established: "Exact objects, one event owner, contiguous actions, one observation per event, six spans, and nine exception groups.",
      transform: "It assigns action templates, positions, omissions, synthetic actions, and capacities.",
      missing: "No independent proof says this mapping matches C++ macrosteps."
    },
    {
      title: "Bounded explanation",
      short: "Arbitrary S0 and fixture footprint",
      established: "A bounded witness exists for the chosen action skeleton and observations.",
      transform: "The solver fills states, queues, logs, and one fresh transaction in a hardcoded footprint.",
      missing: "The lowering and footprint are not proved complete."
    },
    {
      title: "Canonical replay",
      short: "43 actions and 558 projected fields",
      established: "Canonical applyAction, state checks, edge checks, observations, and spans pass.",
      transform: "None. This is the semantic gate for the decoded segment.",
      missing: "Reachable S0, full invariant, and independent C++ to Lean correspondence."
    }
  ];

  function renderArchitecture() {
    const tabs = document.getElementById("architectureStages");
    const detail = document.getElementById("architectureDetail");
    clear(tabs);
    function show(stage, button) {
      tabs.querySelectorAll("button").forEach((item) => item.setAttribute("aria-selected", "false"));
      button.setAttribute("aria-selected", "true");
      clear(detail);
      detail.append(element("h3", stage.title));
      detail.append(element("p", stage.short, "subtle"));
      const fields = [
        ["Established", stage.established],
        ["Transformation", stage.transform],
        ["Not established", stage.missing]
      ];
      const grid = element("div", undefined, "field-grid");
      fields.forEach(([title, text]) => {
        const box = element("div");
        box.append(element("h3", title), element("p", text));
        grid.append(box);
      });
      detail.append(grid);
    }
    architecture.forEach((stage, index) => {
      const button = element("button", undefined, "stage-button");
      button.type = "button";
      button.setAttribute("role", "tab");
      button.setAttribute("aria-selected", String(index === 0));
      button.append(element("strong", stage.title), element("span", stage.short));
      button.addEventListener("click", () => show(stage, button));
      tabs.append(button);
      if (index === 0) show(stage, button);
    });
  }

  const strictnessProfiles = [
    {
      title: "Current golden oracle",
      status: "Maximum fixture strictness, minimum generality",
      text: "Exact schema, exact event order, exact message objects, fixed reductions, and fixed actions. Keep this behavior under the replicate-v1 name.",
      className: "status-green"
    },
    {
      title: "Next grammar",
      status: "Strict productions, broader interleaving",
      text: "Consume every event once through per-node FIFOs and open N-to-M reductions. Reject unknown semantics, but classify incomplete windows and unsupported productions safely.",
      className: "status-amber"
    },
    {
      title: "Production target",
      status: "Versioned evidence with proved claim levels",
      text: "Add raw provenance, stream and packet correlation, sparse footprint extraction, independent macrostep checking, resource ceilings, and explicit valid, invalid, unsupported, incomplete, or inconclusive results.",
      className: "status-red"
    }
  ];

  function renderStrictness() {
    const range = document.getElementById("strictnessRange");
    const detail = document.getElementById("strictnessDetail");
    function show() {
      const profile = strictnessProfiles[Number(range.value)];
      clear(detail);
      detail.append(element("h3", profile.title));
      detail.append(element("p", profile.status, profile.className));
      detail.append(element("p", profile.text));
    }
    range.addEventListener("input", show);
    show();
  }

  function renderMapping(reduction) {
    const detail = document.getElementById("mappingDetail");
    clear(detail);
    detail.append(element("h3", "Reduction " + reduction.reduction + ": " + reduction.name));
    detail.append(element("p", reduction.summary, "subtle"));
    const mapping = element("div", undefined, "mapping");
    const events = element("div", undefined, "mapping-lane");
    events.append(element("h3", reduction.eventCount + " implementation events"));
    reduction.events.forEach((number) => events.append(element("span", "event " + number, "token")));
    const actions = element("div", undefined, "mapping-lane");
    actions.append(element("h3", reduction.actionCount + " model actions"));
    reduction.actions.forEach((action) => actions.append(element("span", "A" + action.action + " " + action.template, "token")));
    mapping.append(events, element("div", "->", "mapping-arrow"), actions);
    detail.append(mapping);
    if (reduction.exceptions.length) detail.append(element("p", "Exceptions: " + reduction.exceptions.join(", "), "subtle"));
  }

  function renderMappings() {
    const choices = document.getElementById("mappingChoices");
    const wanted = data.certificate.reductions.filter((row) => [6, 7, 9, 13, 14, 15].includes(row.reduction));
    chooseButtons(choices, wanted, renderMapping, (row) => "R" + row.reduction + "  " + row.eventCount + " events -> " + row.actionCount + " actions");
  }

  let selectedEvent = null;
  function renderEventDetail(row) {
    selectedEvent = row.event;
    const detail = document.getElementById("eventDetail");
    clear(detail);
    detail.append(element("h3", "Event " + row.event + ": " + row.function));
    detail.append(element("p", "Reduction " + row.reduction + " " + row.reductionName, "subtle"));
    const meta = element("div", undefined, "risk-meta");
    meta.append(element("span", row.positionKind === "action_span" ? "action span" : "point checkpoint"));
    meta.append(element("span", row.projected + " projected"));
    meta.append(element("span", row.omitted + " input-only"));
    detail.append(meta);
    const grid = element("div", undefined, "field-grid");
    const position = element("div");
    position.append(element("h3", "Position"), element("pre", JSON.stringify(row.position, null, 2)));
    const reasons = element("div");
    reasons.append(element("h3", "Omission reasons"));
    if (Object.keys(row.omissionReasons).length) {
      Object.entries(row.omissionReasons).forEach(([name, count]) => reasons.append(element("p", name + ": " + count)));
    } else {
      reasons.append(element("p", "No input-only fields."));
    }
    grid.append(position, reasons);
    detail.append(grid);
    detail.append(element("p", row.exceptions.length ? "Exceptions: " + row.exceptions.join(", ") : "Exceptions: none", "subtle"));
  }

  function renderEventList() {
    const filter = document.getElementById("eventFilter").value.toLowerCase();
    const position = document.getElementById("eventPosition").value;
    const rows = data.certificate.events.filter((row) => {
      const haystack = [row.event, row.function, row.reductionName, row.exceptions.join(" ")].join(" ").toLowerCase();
      return haystack.includes(filter) && (position === "all" || row.positionKind === position);
    });
    const list = document.getElementById("eventList");
    clear(list);
    rows.forEach((row, index) => {
      const button = element("button", undefined, "chip-button");
      button.type = "button";
      button.setAttribute("aria-selected", String(row.event === selectedEvent || (selectedEvent === null && index === 0)));
      button.append(element("strong", "Event " + row.event + "  " + row.function));
      button.append(element("span", row.projected + " projected / " + row.omitted + " input-only", "subtle"));
      button.addEventListener("click", () => {
        list.querySelectorAll("button").forEach((item) => item.setAttribute("aria-selected", "false"));
        button.setAttribute("aria-selected", "true");
        renderEventDetail(row);
      });
      list.append(button);
    });
    if (rows.length && !rows.some((row) => row.event === selectedEvent)) renderEventDetail(rows[0]);
    if (!rows.length) list.append(element("p", "No matching events."));
  }

  function renderShim(shim) {
    const detail = document.getElementById("shimDetail");
    clear(detail);
    detail.append(element("h3", shim.title));
    const fields = [
      ["C++ shape", shim.implementation],
      ["Current mapping", shim.mapping],
      ["Failure risk", shim.risk],
      ["Hardening", shim.hardening]
    ];
    const grid = element("div", undefined, "risk-detail-grid");
    fields.forEach(([title, text]) => {
      const box = element("div");
      box.append(element("h3", title), element("p", text));
      grid.append(box);
    });
    detail.append(grid);
  }

  function renderShims() {
    chooseButtons(document.getElementById("shimChoices"), data.shims, renderShim, (shim) => shim.title);
  }

  let selectedRisk = null;
  function filteredRisks() {
    const lens = document.getElementById("riskLens").value;
    const severity = document.getElementById("riskSeverity").value;
    const disposition = document.getElementById("riskDisposition").value;
    const filter = document.getElementById("riskFilter").value.toLowerCase();
    return data.risks.filter((risk) => {
      const haystack = Object.values(risk).join(" ").toLowerCase();
      return (lens === "all" || risk.lens === lens) &&
        (severity === "all" || risk.severity === severity) &&
        (disposition === "all" || risk.disposition === disposition) &&
        haystack.includes(filter);
    });
  }

  function renderRiskDetail(risk) {
    selectedRisk = risk.id;
    const detail = document.getElementById("riskDetail");
    clear(detail);
    detail.append(element("h3", risk.id + "  " + risk.title));
    const meta = element("div", undefined, "risk-meta");
    [risk.lens, risk.severity, risk.disposition, risk.confidence + " confidence"].forEach((value) => meta.append(element("span", value)));
    detail.append(meta);
    const grid = element("div", undefined, "risk-detail-grid");
    [["Evidence", risk.evidence], ["Failure example", risk.failure], ["Mitigation", risk.mitigation], ["Confidence", risk.confidence]].forEach(([title, text]) => {
      const box = element("div");
      box.append(element("h3", title), element("p", text));
      grid.append(box);
    });
    detail.append(grid);
  }

  let riskSort = {key: "id", direction: 1};
  function compareValues(a, b, direction) {
    if (typeof a === "number" && typeof b === "number") return direction * (a - b);
    return direction * String(a).localeCompare(String(b), undefined, {numeric: true});
  }

  function renderRiskTable(rows) {
    const body = document.querySelector("#riskTable tbody");
    clear(body);
    const sorted = [...rows].sort((a, b) => compareValues(a[riskSort.key], b[riskSort.key], riskSort.direction));
    sorted.forEach((risk) => {
      const row = document.createElement("tr");
      const severityClass = risk.severity === "High" ? "status-red" : "status-amber";
      [risk.id, risk.lens, risk.severity, risk.disposition, risk.title, risk.confidence].forEach((value, index) => {
        const cell = element("td", value, index === 2 ? severityClass : "");
        row.append(cell);
      });
      row.tabIndex = 0;
      row.addEventListener("click", () => renderRiskDetail(risk));
      row.addEventListener("keydown", (event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          renderRiskDetail(risk);
        }
      });
      body.append(row);
    });
    if (!sorted.length) {
      const row = document.createElement("tr");
      const cell = element("td", "No matching risks.");
      cell.colSpan = 6;
      row.append(cell);
      body.append(row);
    }
  }

  function renderRisks() {
    const rows = filteredRisks();
    const list = document.getElementById("riskList");
    clear(list);
    rows.forEach((risk, index) => {
      const button = element("button", undefined, "chip-button");
      button.type = "button";
      button.setAttribute("aria-selected", String(risk.id === selectedRisk || (selectedRisk === null && index === 0)));
      button.append(element("strong", risk.id + "  " + risk.title));
      button.append(element("span", risk.severity + " / " + risk.disposition, "subtle"));
      button.addEventListener("click", () => {
        list.querySelectorAll("button").forEach((item) => item.setAttribute("aria-selected", "false"));
        button.setAttribute("aria-selected", "true");
        renderRiskDetail(risk);
      });
      list.append(button);
    });
    if (rows.length && !rows.some((risk) => risk.id === selectedRisk)) renderRiskDetail(rows[0]);
    if (!rows.length) list.append(element("p", "No matching risks."));
    renderRiskTable(rows);
  }

  function renderBars(targetId, rows) {
    const target = document.getElementById(targetId);
    clear(target);
    const maximum = Math.max(...rows.map((row) => row.event_count), 1);
    rows.forEach((row) => {
      const line = element("div", undefined, "bar-row");
      line.append(element("span", row.name, "mono"));
      const track = element("div", undefined, "bar-track");
      const bar = element("div", undefined, "bar");
      bar.style.width = (100 * row.event_count / maximum).toFixed(1) + "%";
      track.append(bar);
      line.append(track, element("span", row.event_count + " / " + row.scenario_count, "mono"));
      target.append(line);
    });
  }

  let corpusSort = {key: "scenario", direction: 1};
  function filteredCorpus() {
    const filter = document.getElementById("corpusFilter").value.toLowerCase();
    const acceptance = document.getElementById("corpusAcceptance").value;
    return data.audit.scenarios.filter((row) => {
      const haystack = [row.scenario, row.stage, row.reason].join(" ").toLowerCase();
      const status = acceptance === "all" || (acceptance === "accepted" && row.accepted) || (acceptance === "rejected" && !row.accepted);
      return status && haystack.includes(filter);
    });
  }

  function renderCorpus() {
    const rows = filteredCorpus().sort((a, b) => compareValues(a[corpusSort.key], b[corpusSort.key], corpusSort.direction));
    const body = document.querySelector("#corpusTable tbody");
    clear(body);
    rows.forEach((item) => {
      const row = document.createElement("tr");
      [item.scenario, item.raw, item.preprocessed, item.nodes, item.functions, item.packets].forEach((value) => row.append(element("td", value)));
      row.append(element("td", item.accepted ? "accepted" : "rejected", item.accepted ? "status-green" : "status-red"));
      row.append(element("td", item.stage));
      row.append(element("td", item.reason));
      body.append(row);
    });
  }

  function installSort(tableId, state, render) {
    document.querySelectorAll("#" + tableId + " th button[data-sort]").forEach((button) => {
      button.addEventListener("click", () => {
        const key = button.dataset.sort;
        if (state.key === key) state.direction *= -1;
        else {
          state.key = key;
          state.direction = 1;
        }
        render();
      });
    });
  }

  function renderSources() {
    const sourceBody = document.querySelector("#sourceTable tbody");
    clear(sourceBody);
    data.sources.forEach((source) => {
      const row = document.createElement("tr");
      row.append(element("td", source.name));
      row.append(element("td", source.role));
      row.append(element("td", source.authority));
      row.append(element("td", source.status));
      const linkCell = element("td");
      const link = element("a", source.linkKind + " line " + source.line);
      link.href = source.url;
      linkCell.append(link);
      row.append(linkCell);
      sourceBody.append(row);
    });
    const artifactBody = document.querySelector("#artifactTable tbody");
    clear(artifactBody);
    data.artifacts.forEach((artifact) => {
      const row = document.createElement("tr");
      row.append(element("td", artifact.name));
      row.append(element("td", artifact.bytes));
      row.append(element("td", artifact.sha256, "mono"));
      const linkCell = element("td");
      const link = element("a", "VS Code");
      link.href = artifact.url;
      linkCell.append(link);
      row.append(linkCell);
      artifactBody.append(row);
    });
  }

  function initialize() {
    document.getElementById("headValue").textContent = data.head.slice(0, 12);
    renderDecisions();
    renderArchitecture();
    renderStrictness();
    renderMappings();
    renderEventList();
    renderShims();
    renderRisks();
    renderBars("functionBars", data.audit.aggregate.function_inventory);
    renderBars("packetBars", data.audit.aggregate.packet_family_inventory);
    renderCorpus();
    renderSources();

    document.getElementById("eventFilter").addEventListener("input", renderEventList);
    document.getElementById("eventPosition").addEventListener("change", renderEventList);
    ["riskLens", "riskSeverity", "riskDisposition"].forEach((id) => document.getElementById(id).addEventListener("change", renderRisks));
    document.getElementById("riskFilter").addEventListener("input", renderRisks);
    document.getElementById("corpusFilter").addEventListener("input", renderCorpus);
    document.getElementById("corpusAcceptance").addEventListener("change", renderCorpus);
    installSort("riskTable", riskSort, renderRisks);
    installSort("corpusTable", corpusSort, renderCorpus);
  }

  initialize();
  </script>
</body>
</html>
"""


def render_report(data: Mapping[str, Any], generated_at: str) -> str:
    """Render one dependency-free HTML document."""

    return (
        HTML_TEMPLATE.replace("__REPORT_DATA__", safe_json(data))
        .replace("__GENERATED_AT__", html.escape(generated_at, quote=True))
        .replace("__WORKSPACE_URL__", html.escape(WORKSPACE_URL, quote=True))
    )


TIMESTAMP_PATTERN = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")


def normalize_timestamp(report: str) -> str:
    """Remove the only allowed nondeterministic report value."""

    return TIMESTAMP_PATTERN.sub("<GENERATED_AT>", report)


def write_report(path: Path, report: str) -> bool:
    """Write a report, preserving its prior timestamp when content is unchanged."""

    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_file():
        previous = path.read_text(encoding="utf-8")
        if normalize_timestamp(previous) == normalize_timestamp(report):
            return False
    path.write_text(report, encoding="utf-8")
    return True


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse report inputs and output."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--certificate", type=Path, default=DEFAULT_CERTIFICATE)
    parser.add_argument("--audit", type=Path, default=DEFAULT_AUDIT)
    parser.add_argument(
        "--canonical-report",
        type=Path,
        default=DEFAULT_CANONICAL_REPORT,
    )
    parser.add_argument(
        "--canonical-output",
        type=Path,
        default=DEFAULT_CANONICAL_OUTPUT,
    )
    parser.add_argument("--context-report", type=Path, default=DEFAULT_CONTEXT_REPORT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--generated-at",
        help="fixed UTC timestamp for deterministic checks",
    )
    return parser.parse_args(argv)


def generation_time(value: str | None) -> str:
    """Return the supplied UTC timestamp or the current UTC second."""

    if value is None:
        return (
            dt.datetime.now(dt.timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        )
    require(
        bool(TIMESTAMP_PATTERN.fullmatch(value)),
        "--generated-at must use YYYY-MM-DDTHH:MM:SSZ",
    )
    return value


def main(argv: Sequence[str] | None = None) -> int:
    """Generate the critique report."""

    args = parse_args(argv)
    try:
        generated_at = generation_time(args.generated_at)
        data = build_report_data(args, generated_at)
        report = render_report(data, generated_at)
        changed = write_report(args.output, report)
    except (OSError, ReportError, UnicodeError, json.JSONDecodeError) as error:
        print(f"reduction critique report failed: {error}", file=sys.stderr)
        return 1
    print(
        f"report={args.output.resolve()} "
        f"bytes={len(report.encode('utf-8'))} "
        f"risks={data['riskCounts']['total']} "
        f"changed={str(changed).lower()}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
