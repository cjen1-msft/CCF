# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Project a retained native run into aligned event, instruction, and core rows."""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import quote

from native_run import NativeRun

ROOT = Path(__file__).resolve().parent
TEMPLATE = ROOT / "Report" / "native_explorer.html"
REMOTE = "vscode://vscode-remote/ssh-remote+20.91.249.202"


def aligned_rows(records: list[dict], instructions: list[dict]) -> list[dict]:
    """Preserve both orders; link earlier sources rather than moving their rows."""
    rows = {
        0: {"line": None, "record": None, "instructions": []},
        **{
            record["line"]: {
                "line": record["line"],
                "record": record,
                "instructions": [],
            }
            for record in records
        },
    }
    anchor = 0
    for instruction in instructions:
        sources = instruction["source_lines"]
        if any(line not in rows or line == 0 for line in sources):
            raise ValueError("instruction refers to an absent raw event")
        # Reordered or many-to-many reductions cannot align every edge vertically.
        # Keep both sequences intact and display the exact source links instead.
        anchor = max([anchor, *sources])
        rows[anchor]["instructions"].append(instruction)
    return list(rows.values())


def build_view(run: NativeRun, directory: Path | None = None) -> dict:
    """Use validated clause ownership and provenance, never inferred causality."""
    instructions = []
    for group in run.details["groups"]:
        index = group["instruction"]
        step = (
            run.origin.trace.steps[index]
            if run.origin is not None and index is not None
            else None
        )
        instructions.append(
            {
                "index": index,
                "instruction": (
                    run.document["instructions"][index] if index is not None else None
                ),
                "kind": step["kind"] if step else "instruction",
                "rule": step.get("rule") if step else None,
                "source_lines": (
                    sorted({entry["line"] for entry in step["provenance"]})
                    if step
                    else []
                ),
                "clause_count": group["stop"] - group["start"],
                "core": [
                    run.constraint(position)
                    for position in range(group["start"], group["stop"])
                    if run.details["clauses"][position]["name"] in run.core
                ],
            }
        )
    records = (
        [
            {"line": record.line_number, "raw": record.raw, "value": record.value}
            for record in run.origin.records
        ]
        if run.origin
        else []
    )
    return {
        "status": run.result["status"],
        "run_name": str(directory) if directory is not None else "Retained native run",
        "instruction_count": len(run.document["instructions"]),
        "event_count": len(records),
        "core_count": len(run.core),
        "rows": aligned_rows(records, instructions),
        "workspace_url": REMOTE + quote(str(ROOT.parent)),
        "raw_url": (
            REMOTE + quote(str(directory.resolve() / "raw.ndjson"))
            if directory is not None and run.origin is not None
            else None
        ),
    }


def render_explorer(run: NativeRun, directory: Path | None = None) -> str:
    """Embed the snapshot as inert JSON; trace text cannot terminate its element."""
    payload = json.dumps(build_view(run, directory), ensure_ascii=True).replace(
        "<", "\\u003c"
    )
    return TEMPLATE.read_text(encoding="utf-8").replace(
        "__NATIVE_EXPLORER_DATA__", payload, 1
    )
