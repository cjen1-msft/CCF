#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Generate the source-linked CCFRaft trace validation report."""

from __future__ import annotations

import difflib
import html
import json
import subprocess
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
REPO_ROOT = ROOT.parent
REPORT = ROOT / "Report" / "index.html"
ARTIFACTS = ROOT / "Artifacts" / "runs"
WORKSPACE_URL = "vscode://vscode-remote/wsl+AzureLinux3.0/home/cjen1-msft/"
FILE_URL_PREFIX = (
    "vscode://vscode-remote/wsl+AzureLinux3.0"
    "/home/cjen1-msft/CCF/.worktrees/veil-consistency/"
)
GITHUB_ROOT = "https://github.com/cjen1-msft/CCF/blob"

RUNS = (
    ("bad_network", "Captured", "valid"),
    ("soft_rollback", "Captured", "valid"),
    ("bad_network-direct", "Mutated", "direct"),
    ("bad_network-indirect", "Mutated", "indirect"),
    ("soft_rollback-direct", "Mutated", "direct"),
    ("soft_rollback-indirect", "Mutated", "indirect"),
)


def git_ref() -> str:
    return subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def source_line(path: Path, needle: str) -> int:
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if needle in line:
            return number
    return 1


def source_links(relative: str, line: int = 1) -> str:
    vscode = f"{FILE_URL_PREFIX}{relative}:{line}:1"
    github = f"{GITHUB_ROOT}/{git_ref()}/{relative}#L{line}"
    return (
        f'<a href="{html.escape(vscode)}">editor</a>'
        f' <a href="{html.escape(github)}">GitHub</a>'
    )


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} is not a JSON object")
    return value


def mutation_diff(stem: str) -> str:
    scenario = stem.removesuffix("-direct").removesuffix("-indirect")
    original = (
        (ROOT / "Traces" / "Captured" / f"{scenario}.ndjson")
        .read_text(encoding="utf-8")
        .splitlines()
    )
    mutated = (
        (ROOT / "Traces" / "Mutated" / f"{stem}.ndjson")
        .read_text(encoding="utf-8")
        .splitlines()
    )
    return "\n".join(
        difflib.unified_diff(
            original,
            mutated,
            fromfile=f"{scenario}.ndjson",
            tofile=f"{stem}.ndjson",
            lineterm="",
            n=2,
        )
    )


def run_rows() -> tuple[str, str]:
    rows: list[str] = []
    details: list[str] = []
    for stem, directory, mutation in RUNS:
        result = read_json(ARTIFACTS / stem / "result.json")
        certificate = read_json(ARTIFACTS / stem / "certificate.json")
        status = str(result["status"])
        counts = certificate["counts"]
        trace_relative = f"lean-tracing-demo-ccfraft/Traces/{directory}/{stem}.ndjson"
        result_href = f"../Artifacts/runs/{stem}/result.json"
        rows.append(
            "<tr>"
            f'<td><a href="#run-{html.escape(stem)}">{html.escape(stem)}</a></td>'
            f'<td data-sort="{status}"><code>{status}</code></td>'
            f"<td>{html.escape(mutation)}</td>"
            f"<td>{counts['raw_records']}</td>"
            f"<td>{counts['actions']}</td>"
            f"<td>{counts['observations']}</td>"
            f"<td>{source_links(trace_relative)}</td>"
            f'<td><a href="{html.escape(result_href)}">artifact</a></td>'
            "</tr>"
        )

        evidence = ""
        if status == "unsat":
            core = (ARTIFACTS / stem / "unsat-core.txt").read_text(encoding="utf-8")
            proof_path = ARTIFACTS / stem / "proof.txt"
            proof = proof_path.read_text(encoding="utf-8")
            proof_preview = "\n".join(proof.splitlines()[:80])
            evidence = (
                "<h4>Unsat core</h4>"
                f"<pre>{html.escape(core)}</pre>"
                "<details><summary>"
                f"cvc5 proof, {proof_path.stat().st_size:,} bytes"
                "</summary>"
                f'<p><a href="../Artifacts/runs/{html.escape(stem)}/proof.txt">'
                "Open the complete proof</a>.</p>"
                f"<pre>{html.escape(proof_preview)}</pre>"
                "</details>"
            )
        diff = ""
        if mutation != "valid":
            diff = (
                "<h4>Raw trace diff</h4>"
                f"<pre>{html.escape(mutation_diff(stem))}</pre>"
            )
        details.append(
            f'<article id="run-{html.escape(stem)}">'
            f"<h3>{html.escape(stem)}</h3>"
            f"<p>cvc5 returned <code>{html.escape(status)}</code>.</p>"
            f"{diff}{evidence}</article>"
        )
    return "\n".join(rows), "\n".join(details)


def main() -> int:
    rows, details = run_rows()
    audit_files = (
        ("Model.lean", "inductive Action"),
        ("Properties.lean", "structure ConsensusSafety"),
        ("Reduction.lean", "def preprocess"),
        ("reduction.py", "def preprocess"),
        ("TraceProperties.lean", "theorem lowerTrace_correct"),
    )
    audit_rows = []
    for name, needle in audit_files:
        path = ROOT / name
        line = source_line(path, needle)
        relative = f"lean-tracing-demo-ccfraft/{name}"
        audit_rows.append(
            "<tr>"
            f"<td><code>{html.escape(name)}</code></td>"
            f"<td>{source_links(relative, line)}</td>"
            "</tr>"
        )

    document = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CCFRaft trace validation demo</title>
<style>
:root {{
  color-scheme: dark;
  font-family: ui-sans-serif, system-ui, sans-serif;
  background: #0d1117;
  color: #e6edf3;
}}
body {{ margin: 0 auto; max-width: 1180px; padding: 2rem; }}
a {{ color: #58a6ff; }}
code, pre {{ font-family: ui-monospace, SFMono-Regular, monospace; }}
pre {{
  background: #161b22;
  border: 1px solid #30363d;
  border-radius: .4rem;
  max-height: 32rem;
  overflow: auto;
  padding: 1rem;
  white-space: pre-wrap;
}}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border-bottom: 1px solid #30363d; padding: .6rem; text-align: left; }}
th {{ cursor: pointer; }}
article {{ border-top: 1px solid #30363d; margin-top: 2rem; padding-top: 1rem; }}
.warning {{
  background: #2d2200;
  border: 1px solid #9e6a03;
  border-radius: .4rem;
  padding: 1rem;
}}
.pass {{ color: #3fb950; }}
.fail {{ color: #f85149; }}
input {{
  background: #0d1117;
  border: 1px solid #30363d;
  color: #e6edf3;
  margin: 0 0 1rem;
  padding: .5rem;
  width: 20rem;
}}
</style>
</head>
<body>
<h1>CCFRaft trace validation demo</h1>
<p>
This report puts the five audited files beside two valid traces and four
single-edit negative traces. Open the
<a href="{WORKSPACE_URL}">workspace</a>.
</p>

<div class="warning">
<strong>Current blocker.</strong>
<code>lowerTrace_correct</code> proves the typed Lean lowering.
<code>Shared/smt.py</code> is a separate user-reviewed projection of terms,
roles, log lengths, commit indices, allocation, and join state. The report's
<code>sat</code> and <code>unsat</code> results do not yet establish
<code>MidtraceSatisfiable</code> for the complete model.
</div>

<h2>Results</h2>
<input id="filter" placeholder="Filter traces">
<table id="results">
<thead>
<tr>
<th>Trace</th><th>cvc5</th><th>Case</th><th>Raw</th>
<th>Actions</th><th>Observations</th><th>Trace</th><th>Result</th>
</tr>
</thead>
<tbody>{rows}</tbody>
</table>

<h2>Manual review boundary</h2>
<table>
<thead><tr><th>File</th><th>Source</th></tr></thead>
<tbody>{''.join(audit_rows)}</tbody>
</table>

<h2>Mechanically checked boundary</h2>
<p>
<code>lake build Demo</code> compiles the consensus proof, all ten action
lowerings, <code>lowerTrace_correct</code>, and the forbidden-axiom audit.
The Python integration tests regenerate each formula and ask cvc5 to check
the proof and unsat core for every negative trace.
</p>

<h2>Run evidence</h2>
{details}

<script>
const table = document.querySelector("#results");
const body = table.querySelector("tbody");
document.querySelector("#filter").addEventListener("input", event => {{
  const query = event.target.value.toLowerCase();
  for (const row of body.rows) {{
    row.hidden = !row.textContent.toLowerCase().includes(query);
  }}
}});
for (const [column, header] of [...table.querySelectorAll("th")].entries()) {{
  header.addEventListener("click", () => {{
    const rows = [...body.rows];
    rows.sort((left, right) =>
      left.cells[column].textContent.localeCompare(
        right.cells[column].textContent,
        undefined,
        {{numeric: true}}
      )
    );
    body.replaceChildren(...rows);
  }});
}}
</script>
</body>
</html>
"""
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(document, encoding="utf-8")
    print(REPORT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
