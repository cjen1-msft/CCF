#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Index six checked raw runs and generate their existing three-pane explorers."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
import html
import json
import os
from pathlib import Path
from urllib.parse import quote

import explore_checked as explorer
from Shared.smt import SmtEncodingError
from Shared.solver import ValidationError

ROOT = Path(__file__).resolve().parent
RUNS = (
    ("bad_network", "Captured"),
    ("soft_rollback", "Captured"),
    ("bad_network-direct", "Mutated"),
    ("bad_network-indirect", "Mutated"),
    ("soft_rollback-direct", "Mutated"),
    ("soft_rollback-indirect", "Mutated"),
)


def source_line(path: Path, declaration: str) -> int:
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if line.startswith(declaration):
            return number
    raise ValidationError(f"{path} has no {declaration!r} declaration")


def link(url: str, label: str) -> str:
    return f'<a href="{html.escape(url, quote=True)}">{html.escape(label)}</a>'


def file_link(path: Path, output: Path, label: str) -> str:
    return link(quote(os.path.relpath(path, output.parent)), label)


def generate_report(
    runs_directory: Path = ROOT / "Artifacts/runs",
    output: Path = ROOT / "Report/index.html",
    *,
    cvc5: Path | None = None,
    refine: bool = True,
) -> Path:
    """Publish an index only after every run passes the existing explorer checks."""
    if output.suffix != ".html" or output.resolve() == explorer.TEMPLATE.resolve():
        raise ValidationError(
            "choose an HTML index path other than the explorer template"
        )
    output.unlink(missing_ok=True)
    workspace = explorer.REMOTE + quote(str(ROOT.parent))
    rows = []
    for stem, directory in RUNS:
        source = runs_directory / stem
        raw = ROOT / "Traces" / directory / f"{stem}.ndjson"
        page = output.parent / f"{output.stem}-runs" / f"{stem}.html"
        explorer.generate_explorer(
            source,
            page,
            raw_trace=raw,
            cvc5=cvc5,
            refine=refine,
            workspace_uri=workspace,
        )
        explorer.read_object(source / "certificate.json")
        result = explorer.read_object(source / "result.json")
        assurance = explorer._mapping(result.get("assurance"), "assurance")
        bounds = explorer._mapping(assurance.get("bounds"), f"{stem} bounds")
        rows.append(
            "<li>"
            f"<h2>{file_link(page, output, stem)} "
            f"<code>{html.escape(str(result['status']))}</code></h2>"
            f"<p>Declared bounds <code>{html.escape(json.dumps(bounds, sort_keys=True))}</code></p>"
            f"<p>{file_link(raw, output, 'Raw trace')} | "
            f"{file_link(source / 'certificate.json', output, 'Certificate')} | "
            f"{file_link(source / 'result.json', output, 'Result')}</p>"
            "</li>"
        )
    contract = ROOT / "BoundedSymbolicTrace.lean"
    line = source_line(contract, "def Follows ")
    contract_relative = quote(contract.relative_to(ROOT.parent).as_posix())
    contract_url = f"{workspace}/{contract_relative}:{line}:1"
    document = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Checked CCFRaft raw traces</title>
<style>
:root {{ color-scheme: light dark; font-family: system-ui, sans-serif; }}
body {{ max-width: 64rem; margin: auto; padding: 2rem 1rem; line-height: 1.5; }}
a {{ color: light-dark(#0758a5, #8bc5ff); }}
a:focus-visible {{ outline: 2px solid currentColor; outline-offset: 3px; }}
h1 {{ margin-bottom: .5rem; }}
h2 {{ font-size: 1.1rem; }}
h2 code {{ margin-left: .75rem; }}
ol {{ list-style: none; padding: 0; }}
li {{ border-top: 1px solid #888; padding: .5rem 0; }}
code {{ overflow-wrap: anywhere; }}
footer {{ border-top: 1px solid #888; margin-top: 2rem; padding-top: 1rem; }}
</style>
</head>
<body>
<main>
<h1>Checked CCFRaft raw traces</h1>
<p>Open a run to inspect raw events, ordered instructions, and checked constraints.</p>
<p>{link(workspace, "Open workspace")}</p>
<ol aria-label="Checked runs">
{''.join(rows)}
</ol>
</main>
<footer>
<p>SAT means some execution fits the trace within its declared bounds.
UNSAT means none does. Unknown is inconclusive.
These are not reachability or implementation-correctness claims.</p>
<p>{link(contract_url, "Bounded symbolic execution contract")}. Raw reduction, saved artifacts,
serialization, and the solver remain trusted. A reduced core is not a replayable trace.</p>
</footer>
</body>
</html>
"""
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(document, encoding="utf-8")
    return output


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs-dir", type=Path, default=ROOT / "Artifacts/runs")
    parser.add_argument("--output", type=Path, default=ROOT / "Report/index.html")
    parser.add_argument("--cvc5", type=Path)
    parser.add_argument("--no-refine", action="store_true")
    args = parser.parse_args(argv)
    try:
        output = generate_report(
            args.runs_dir, args.output, cvc5=args.cvc5, refine=not args.no_refine
        )
    except (
        SmtEncodingError,
        ValidationError,
        OSError,
    ) as error:
        parser.exit(2, f"report generation failed: {error}\n")
    print(output.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
