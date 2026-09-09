#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Generate a source-linked, three-pane explorer for a checked trace run."""

from __future__ import annotations

import argparse
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from urllib.parse import quote

from refine_checked import refine_checked_core
from Shared.smt import SmtEncodingError, parse_unsat_core
from Shared.solver import ValidationError
from validate_checked import (
    SYMBOLIC_CERTIFICATE_SCHEMA,
    _mapping,
    _sequence,
    read_constraint_map,
)

ROOT = Path(__file__).resolve().parent
TEMPLATE = ROOT / "Report" / "explorer.html"
REMOTE = "vscode://vscode-remote/ssh-remote+20.91.249.202"


def read_object(path: Path) -> Mapping[str, object]:
    try:
        return _mapping(json.loads(path.read_text(encoding="utf-8")), str(path))
    except json.JSONDecodeError as error:
        raise ValidationError(f"invalid JSON in {path}: {error}") from error


def build_explorer_data(
    source_directory: Path,
    *,
    raw_trace: Path | None,
    refinement_directory: Path | None,
    cvc5: Path | None,
    workspace_uri: str,
) -> dict[str, object]:
    """Load a group-level run and optionally precompute action refinements."""

    result = read_object(source_directory / "result.json")
    assurance = _mapping(result.get("assurance"), "assurance")
    gate = _mapping(result.get("proof_gate"), "proof gate")
    if (
        assurance.get("granularity") != "group"
        or assurance.get("backend") != "lean-checked trace encoder"
        or gate.get("checked") is not True
        or result.get("status") not in ("sat", "unsat", "unknown")
    ):
        raise ValidationError("the explorer requires a checked group-level run")
    constraint_map = read_constraint_map(
        source_directory / "constraint-map.json", inspect_group=None
    )
    core: tuple[str, ...] = ()
    if result["status"] == "unsat":
        core = parse_unsat_core(
            (source_directory / "unsat-core.txt").read_text(encoding="utf-8")
        )
    groups = [
        _mapping(group, "group")
        for group in _sequence(constraint_map["groups"], "groups")
    ]
    if set(core) - {group["name"] for group in groups}:
        raise ValidationError("the reduced core contains unknown groups")
    raw_lines = (
        raw_trace.read_text(encoding="utf-8").splitlines()
        if raw_trace is not None
        else []
    )
    for group in groups:
        if group.get("instruction") is None:
            continue
        instruction = _mapping(group["instruction"], "instruction")
        if "provenance" not in instruction:
            continue
        for item in _sequence(instruction["provenance"], "instruction provenance"):
            line = _mapping(item, "provenance entry").get("line")
            if type(line) is not int or line < 1:
                raise ValidationError("provenance line must be a positive integer")
            if raw_trace is not None and line > len(raw_lines):
                raise ValidationError("provenance refers beyond the supplied raw trace")
    refinements: dict[str, object] = {}
    if refinement_directory is not None:
        for group in groups:
            if group["name"] in core and group["kind"] == "action":
                output = refinement_directory / group["name"]
                refined = refine_checked_core(
                    source_directory,
                    output,
                    inspect_group=group["index"],
                    cvc5=cvc5,
                )
                refinements[group["name"]] = {
                    "result": refined,
                    "diagnosis": read_object(output / "diagnosis.json"),
                }
    raw_url = (
        workspace_uri.rstrip("/")
        + "/"
        + quote(raw_trace.resolve().relative_to(ROOT.parent).as_posix())
        if raw_trace is not None and raw_trace.resolve().is_relative_to(ROOT.parent)
        else None
    )
    return {
        "result": result,
        "certificate_schema": constraint_map["certificate_schema"],
        "groups": groups,
        "core": list(core),
        "refinements": refinements,
        "raw_lines": raw_lines,
        "raw_name": str(raw_trace) if raw_trace is not None else None,
        "raw_url": raw_url,
        "workspace_uri": workspace_uri,
        "run_name": source_directory.name,
    }


def generate_explorer(
    source_directory: Path,
    output: Path,
    *,
    raw_trace: Path | None = None,
    cvc5: Path | None = None,
    refine: bool = True,
    workspace_uri: str = REMOTE + str(ROOT.parent),
) -> Path:
    """Write a standalone report with no external scripts or network requests."""

    if output.suffix != ".html" or output.resolve() == TEMPLATE.resolve():
        raise ValidationError(
            "choose an HTML output path other than the report template"
        )
    if not workspace_uri.startswith("vscode://vscode-remote/"):
        raise ValidationError("workspace URI must use vscode://vscode-remote/")
    output.unlink(missing_ok=True)
    data = build_explorer_data(
        source_directory,
        raw_trace=raw_trace,
        refinement_directory=(
            output.parent / f"{output.stem}-refinements" if refine else None
        ),
        cvc5=cvc5,
        workspace_uri=workspace_uri,
    )
    contract = ROOT / (
        "BoundedSymbolicTrace.lean"
        if data["certificate_schema"] == SYMBOLIC_CERTIFICATE_SCHEMA
        else "BoundedTrace.lean"
    )
    contract_lines = contract.read_text(encoding="utf-8").splitlines()
    contract_line = next(
        (
            number
            for number, line in enumerate(contract_lines, 1)
            if line.startswith("def Follows ")
        ),
        None,
    )
    if contract_line is None:
        raise ValidationError(f"{contract.name} has no Follows execution contract")
    data["source_url"] = (
        workspace_uri.rstrip("/")
        + "/"
        + quote(contract.relative_to(ROOT.parent).as_posix())
        + f":{contract_line}:1"
    )
    encoded = json.dumps(data, ensure_ascii=True).replace("<", "\\u003c")
    document = TEMPLATE.read_text(encoding="utf-8").replace(
        "__EXPLORER_DATA__", encoded, 1
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(document, encoding="utf-8")
    return output


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source_directory", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--raw-trace", type=Path)
    parser.add_argument("--cvc5", type=Path)
    parser.add_argument("--no-refine", action="store_true")
    parser.add_argument("--workspace-uri", default=REMOTE + str(ROOT.parent))
    args = parser.parse_args(argv)
    try:
        output = generate_explorer(
            args.source_directory,
            args.output,
            raw_trace=args.raw_trace,
            cvc5=args.cvc5,
            refine=not args.no_refine,
            workspace_uri=args.workspace_uri,
        )
    except (
        SmtEncodingError,
        ValidationError,
        OSError,
    ) as error:
        parser.exit(2, f"explorer generation failed: {error}\n")
    print(output.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
