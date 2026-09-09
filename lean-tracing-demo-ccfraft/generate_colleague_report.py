#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Generate the self-contained colleague overview of CCFRaft trace validation."""

from __future__ import annotations

import html
import json
import subprocess
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
REPO_ROOT = ROOT.parent
REPORT = ROOT / "Report" / "colleague-overview.html"
MEASUREMENTS = ROOT / "Measurements" / "pipeline.json"
ARTIFACTS = ROOT / "Artifacts" / "benchmark"
WORKSPACE_URL = "vscode://vscode-remote/wsl+AzureLinux3.0/home/cjen1-msft/"
EDITOR_PREFIX = (
    "vscode://vscode-remote/wsl+AzureLinux3.0"
    "/home/cjen1-msft/CCF/.worktrees/veil-consistency/"
)
GITHUB_PREFIX = "https://github.com/cjen1-msft/CCF/blob"
RUNS = (
    ("bad_network", "Captured"),
    ("soft_rollback", "Captured"),
    ("bad_network-direct", "Mutated"),
    ("bad_network-indirect", "Mutated"),
    ("soft_rollback-direct", "Mutated"),
    ("soft_rollback-indirect", "Mutated"),
)


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def git_ref() -> str:
    return subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def line_number(path: Path, needle: str) -> int:
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if needle in line:
            return number
    return 1


def source_link(path: str, line: int, label: str) -> str:
    editor = f"{EDITOR_PREFIX}{path}:{line}:1"
    github = f"{GITHUB_PREFIX}/{git_ref()}/{path}#L{line}"
    return (
        f'<a href="{html.escape(editor)}">{html.escape(label)}</a>'
        f' <a class="quiet" href="{html.escape(github)}">GitHub</a>'
    )


def code_excerpt(path: Path, start: int, end: int) -> str:
    lines = path.read_text(encoding="utf-8").splitlines()
    return "\n".join(
        f"{number:>4}  {lines[number - 1]}"
        for number in range(start, min(end, len(lines)) + 1)
    )


def compact_instruction(step: dict[str, Any]) -> str:
    if step["kind"] == "observation":
        value = json.dumps(step["value"], sort_keys=True)
        return f"observe n{step['node']}.{step['variable']} = {value}"
    fields = [
        f"{key}={json.dumps(value, sort_keys=True)}"
        for key, value in step.items()
        if key
        not in {
            "action",
            "evidence",
            "kind",
            "node",
            "provenance",
            "rule",
        }
    ]
    suffix = f" {', '.join(fields)}" if fields else ""
    return f"action n{step['node']}.{step['action']}{suffix}"


def report_data(measurements: dict[str, Any]) -> dict[str, Any]:
    runs: dict[str, Any] = {}
    for name, directory in RUNS:
        trace_path = ROOT / "Traces" / directory / f"{name}.ndjson"
        certificate_path = ROOT / "Traces" / "Certificates" / f"{name}.json"
        artifact_dir = ARTIFACTS / name
        raw = [
            {
                "line": number,
                "value": json.loads(line),
            }
            for number, line in enumerate(
                trace_path.read_text(encoding="utf-8").splitlines(),
                1,
            )
        ]
        certificate = read_json(certificate_path)
        result = read_json(artifact_dir / "result.json")
        run: dict[str, Any] = {
            "raw": raw,
            "steps": certificate["steps"],
            "counts": certificate["counts"],
            "result": result,
            "timing": measurements["validations"][name],
        }
        if result["status"] == "unsat":
            run["diagnosis"] = read_json(artifact_dir / "diagnosis.json")
            run["originalCore"] = (artifact_dir / "unsat-core-original.txt").read_text(
                encoding="utf-8"
            )
            run["reducedCore"] = (artifact_dir / "unsat-core.txt").read_text(
                encoding="utf-8"
            )
            run["reducedFormula"] = (artifact_dir / "formula-reduced.smt2").read_text(
                encoding="utf-8"
            )
            run["proof"] = (artifact_dir / "proof.txt").read_text(encoding="utf-8")
            run["reducedFormula"] = (artifact_dir / "formula-reduced.smt2").read_text(
                encoding="utf-8"
            )
            run["proof"] = (artifact_dir / "proof.txt").read_text(encoding="utf-8")
        runs[name] = run
    return {"runs": runs}


def milliseconds(value: float) -> str:
    if value >= 60_000:
        return f"{value / 60_000:.1f} min"
    if value >= 1_000:
        return f"{value / 1_000:.2f} s"
    return f"{value:.1f} ms"


def timing_rows(measurements: dict[str, Any]) -> str:
    rows = []
    for name, _ in RUNS:
        run = measurements["validations"][name]
        phases = run["phase_wall_ms"]
        rows.append(
            "<tr>"
            f"<td><code>{html.escape(name)}</code></td>"
            f"<td>{run['states']}</td>"
            f"<td>{run['actions']}</td>"
            f"<td>{run['observations']}</td>"
            f"<td>{milliseconds(phases['ndjson_parse'])}</td>"
            f"<td>{milliseconds(phases['preprocess'])}</td>"
            f"<td>{milliseconds(phases['reduction'])}</td>"
            f"<td>{milliseconds(phases['certificate_write'])}</td>"
            f"<td>{milliseconds(phases['smt_build'])}</td>"
            f"<td>{milliseconds(phases['smt_write'])}</td>"
            f"<td>{milliseconds(run['decision_wall_ms'])}</td>"
            f"<td>{milliseconds(run['decision_wall_ms_p90'])}</td>"
            f"<td>{milliseconds(run.get('unsat_core_wall_ms', 0))}</td>"
            f"<td>{milliseconds(run.get('core_reduction_wall_ms', 0))}</td>"
            f"<td>{milliseconds(run.get('proof_wall_ms', 0))}</td>"
            f"<td>{milliseconds(run['validation_wall_ms'])}</td>"
            f"<td>{milliseconds(run['validation_wall_ms_p90'])}</td>"
            "</tr>"
        )
    return "\n".join(rows)


def reduction_rule_rows(data: dict[str, Any]) -> str:
    rules: dict[str, dict[str, set[str]]] = {}
    for run in data["runs"].values():
        for step in run["steps"]:
            rule = step["rule"]
            item = rules.setdefault(rule, {"actions": set(), "observations": set()})
            if step["kind"] == "action":
                item["actions"].add(step["action"])
            else:
                item["observations"].add(step["variable"])
    rows = []
    for rule, emitted in sorted(rules.items()):
        rows.append(
            "<tr>"
            f"<td><code>{html.escape(rule)}</code></td>"
            f"<td>{html.escape(', '.join(sorted(emitted['actions'])) or '-')}</td>"
            f"<td>{html.escape(', '.join(sorted(emitted['observations'])) or '-')}</td>"
            "</tr>"
        )
    return "\n".join(rows)


def main() -> int:
    measurements = read_json(MEASUREMENTS)
    data = report_data(measurements)
    validations = measurements["validations"]
    valid_runs = [validations["bad_network"], validations["soft_rollback"]]
    max_states = max(run["states"] for run in valid_runs)
    max_valid_ms = max(run["decision_wall_ms"] for run in valid_runs)
    max_valid_p90_ms = max(run["decision_wall_ms_p90"] for run in valid_runs)
    issue_runs = [
        validations[name]
        for name in (
            "bad_network-direct",
            "bad_network-indirect",
            "soft_rollback-direct",
            "soft_rollback-indirect",
        )
    ]
    max_issue_ms = max(run["validation_wall_ms"] for run in issue_runs)
    max_issue_p90_ms = max(run["validation_wall_ms_p90"] for run in issue_runs)
    max_core = max(run["reduced_unsat_core_assertions"] for run in issue_runs)
    cold_build = measurements["lean"]["cold_build_wall_ms"]
    warm_build = measurements["lean"]["warm_build_wall_ms"]
    capture_max = max(item["wall_time_ms"] for item in measurements["capture"].values())
    capture_sample_max = max(
        max(item["samples_wall_ms"]) for item in measurements["capture"].values()
    )
    cold_example_total = (
        measurements["capture"]["bad_network"]["wall_time_ms"]
        + cold_build
        + validations["bad_network"]["validation_wall_ms"]
    )
    cold_compile_percent = 100 * cold_build / cold_example_total

    reduction_path = ROOT / "reduction.py"
    reduction_start = line_number(
        reduction_path,
        "def _reduce_receive_with_optional_term_update",
    )
    reduction_snippet = code_excerpt(
        reduction_path,
        reduction_start,
        reduction_start + 42,
    )
    trace_properties_path = ROOT / "TraceProperties.lean"
    theorem_start = line_number(trace_properties_path, "theorem lowerTrace_correct")
    theorem_snippet = code_excerpt(
        trace_properties_path,
        theorem_start,
        theorem_start + 13,
    )
    example_steps = read_json(ROOT / "Traces/Certificates/soft_rollback-direct.json")[
        "steps"
    ]
    larger_raw = data["runs"]["bad_network"]["raw"]
    command_records = sum("cmd" in item["value"] for item in larger_raw)
    raft_records = sum(
        str(item["value"].get("file", "")).endswith("/raft.h") for item in larger_raw
    )
    driver_records = len(larger_raw) - command_records - raft_records
    timeout_index = next(
        index
        for index, step in enumerate(example_steps)
        if step.get("action") == "timeout" and step["provenance"][0]["line"] == 112
    )
    transform_example = "\n".join(
        compact_instruction(step)
        for step in example_steps[timeout_index : timeout_index + 7]
    )
    raw_timeout = next(
        item["value"]
        for item in data["runs"]["soft_rollback-direct"]["raw"]
        if item["line"] == 112
    )
    raw_timeout_excerpt = json.dumps(
        {
            "function": raw_timeout["msg"]["function"],
            "state": {
                "current_view": raw_timeout["msg"]["state"]["current_view"],
                "leadership_state": raw_timeout["msg"]["state"]["leadership_state"],
                "node_id": raw_timeout["msg"]["state"]["node_id"],
            },
        },
        indent=2,
    )
    soft_direct = validations["soft_rollback-direct"]
    reduced_formula_lines = [
        line
        for line in (ARTIFACTS / "soft_rollback-direct/formula-reduced.smt2")
        .read_text(encoding="utf-8")
        .splitlines()
        if line.startswith("(assert (!")
    ]
    reduced_formula_excerpt = "\n".join(reduced_formula_lines)
    embedded = json.dumps(data, separators=(",", ":")).replace("</", "<\\/")

    document = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Prototype: checking CCF Raft traces against an encoded model</title>
<style>
:root {{
  color-scheme: dark;
  --bg: #090d12;
  --panel: #111821;
  --panel-2: #17212d;
  --line: #29384a;
  --text: #e7edf5;
  --muted: #9fb0c3;
  --blue: #62a8ff;
  --green: #42d392;
  --amber: #f4bd61;
  --red: #ff6b72;
  --purple: #bc8cff;
  font-family: Inter, ui-sans-serif, system-ui, sans-serif;
}}
* {{ box-sizing: border-box; }}
html {{ scroll-behavior: smooth; }}
body {{ margin: 0; background: var(--bg); color: var(--text); }}
a {{ color: var(--blue); }}
code, pre {{ font-family: "SFMono-Regular", Consolas, monospace; }}
.nav {{
  position: sticky; top: 0; z-index: 20; display: flex; gap: .4rem;
  align-items: center; overflow-x: auto; padding: .7rem 1.2rem;
  border-bottom: 1px solid var(--line); background: #090d12ee;
  backdrop-filter: blur(12px);
}}
.nav a {{ color: var(--muted); text-decoration: none; white-space: nowrap; }}
.nav a:hover {{ color: var(--text); }}
.crumb {{ color: var(--text); font-weight: 700; margin-right: .6rem; }}
.sep {{ color: #52657a; }}
main {{ max-width: 1240px; margin: auto; padding: 2rem 1.4rem 5rem; }}
section {{ scroll-margin-top: 4.5rem; margin: 0 0 4.5rem; }}
h1 {{ font-size: clamp(2.4rem, 6vw, 5.5rem); line-height: .96; margin: 1rem 0; }}
h2 {{ font-size: clamp(1.7rem, 3vw, 2.6rem); margin: 0 0 .5rem; }}
h3 {{ margin-top: 1.5rem; }}
.lede {{ max-width: 760px; color: var(--muted); font-size: 1.18rem; line-height: 1.6; }}
.eyebrow {{ color: var(--green); font-weight: 750; letter-spacing: .08em; text-transform: uppercase; }}
.cards {{ display: grid; grid-template-columns: repeat(auto-fit,minmax(220px,1fr)); gap: 1rem; margin-top: 2rem; }}
.card, .panel {{
  background: linear-gradient(145deg,var(--panel),#0d131b);
  border: 1px solid var(--line); border-radius: 14px; padding: 1.2rem;
}}
.metric {{ font-size: 2.25rem; font-weight: 800; color: var(--green); }}
.metric.red {{ color: var(--red); }}
.metric.amber {{ color: var(--amber); }}
.caption, .quiet {{ color: var(--muted); font-size: .9rem; }}
.section-conceit {{ color: var(--muted); max-width: 780px; margin: 0 0 1.6rem; }}
.grid-2 {{ display: grid; grid-template-columns: repeat(auto-fit,minmax(min(320px,100%),1fr)); gap: 1rem; }}
.flow {{ display: grid; grid-template-columns: repeat(4,1fr); gap: .6rem; align-items: stretch; }}
.flow-step {{
  position: relative; min-height: 150px; padding: 1rem; border-radius: 12px;
  border: 1px solid var(--line); background: var(--panel);
}}
.flow-step:not(:last-child)::after {{
  content: "›"; position: absolute; right: -.58rem; top: 42%;
  color: var(--blue); font-size: 2rem; z-index: 2;
}}
.flow strong {{ display: block; color: var(--blue); margin-bottom: .4rem; }}
.split {{ display: flex; height: 12px; border-radius: 99px; overflow: hidden; margin-top: 1rem; }}
.split span:first-child {{ background: var(--purple); }}
.split span:last-child {{ background: var(--green); }}
pre {{
  background: #080c11; border: 1px solid var(--line); border-radius: 10px;
  padding: 1rem; overflow: auto; max-height: 34rem; white-space: pre-wrap;
}}
.contract {{ border-left: 4px solid var(--green); }}
.warning {{ border-left: 4px solid var(--amber); }}
.story {{ border-top: 3px solid var(--green); }}
.story.unsat {{ border-color: var(--red); }}
.status {{ display: inline-block; border-radius: 99px; padding: .2rem .6rem; font-weight: 800; }}
.sat {{ color: #062a1b; background: var(--green); }}
.unsat {{ color: #39080c; background: var(--red); }}
table {{ width: 100%; border-collapse: collapse; font-size: .9rem; }}
th, td {{ text-align: left; padding: .65rem; border-bottom: 1px solid var(--line); }}
th {{ color: var(--muted); cursor: pointer; position: sticky; top: 3rem; background: var(--panel); }}
th:focus {{ outline: 2px solid var(--blue); outline-offset: -2px; }}
.table-wrap {{ overflow: auto; max-height: 32rem; border: 1px solid var(--line); border-radius: 10px; }}
.tabs {{ display: flex; gap: .4rem; flex-wrap: wrap; margin: 1rem 0; }}
button, select, input {{
  color: var(--text); background: var(--panel-2); border: 1px solid var(--line);
  border-radius: 8px; padding: .55rem .8rem;
}}
button {{ cursor: pointer; }}
button.active {{ border-color: var(--blue); color: var(--blue); }}
summary {{ cursor: pointer; color: var(--blue); }}
.toolbar {{ display: flex; gap: .7rem; flex-wrap: wrap; align-items: center; }}
.explorer-output {{ min-height: 24rem; }}
.instruction {{ display: grid; grid-template-columns: 5rem 1fr 11rem; gap: .7rem; padding: .55rem; border-bottom: 1px solid var(--line); }}
.instruction.action {{ border-left: 3px solid var(--green); }}
.instruction.observation {{ border-left: 3px solid var(--purple); }}
.bar {{ display: flex; height: 28px; overflow: hidden; border-radius: 6px; background: #080c11; }}
.bar span {{ min-width: 2px; }}
.bar .reduce {{ background: var(--purple); }}
.bar .smt {{ background: var(--blue); }}
.bar .solve {{ background: var(--green); }}
.bar .explain {{ background: var(--amber); }}
.callout {{ font-size: 1.08rem; line-height: 1.55; }}
@media (max-width: 760px) {{
  .flow {{ grid-template-columns: 1fr; }}
  .flow-step:not(:last-child)::after {{ content: "↓"; right: 50%; top: auto; bottom: -.95rem; }}
  .instruction {{ grid-template-columns: 4rem 1fr; }}
  .instruction .rule {{ display: none; }}
}}
</style>
</head>
<body>
<nav class="nav">
  <span class="crumb">CCF / Raft trace validation</span>
  <span class="sep">/</span><a href="#results">results</a>
  <span class="sep">/</span><a href="#mental-model">terms</a>
  <span class="sep">/</span><a href="#pipeline">pipeline</a>
  <span class="sep">/</span><a href="#reduction">reduction</a>
  <span class="sep">/</span><a href="#solver">solver</a>
  <span class="sep">/</span><a href="#stories">examples</a>
  <span class="sep">/</span><a href="#timing">timing</a>
  <span class="sep">/</span><a href="#limits">limits</a>
</nav>
<main>
<section id="results">
  <div class="eyebrow">Executable prototype</div>
  <h1>Does this Raft run fit the model?</h1>
  <p class="callout"><strong>2 captured 3-node traces, up to 177 symbolic
  state boundaries, returned SAT in under 2 seconds per trace at p90.</strong></p>
  <p class="lede">
    CCF is a replicated service framework. Its Raft implementation keeps
    nodes in agreement about an ordered ledger. We reduce implementation
    traces to actions and observations, then ask cvc5 whether the Python
    projected-state formula is satisfiable. SAT means that projection has a
    satisfying state sequence. UNSAT means its constraints are inconsistent.
  </p>
  <div class="panel warning">
    <strong>Scope today.</strong> Neither result is yet proved equivalent to
    <code>MidtraceSatisfiable</code>. The executable solver checks role, term,
    log length, commit index, allocation, and join state. Two correspondences
    remain unproved: decoding the Python reduction certificate into the typed
    Lean trace, and emitted Python SMT against the typed Lean formula.
    Queue-message observations are recorded but lower to <code>true</code>.
  </div>
  <div class="cards">
    <div class="card">
      <div class="metric">{len(valid_runs)}</div>
      <strong>captured test traces checked</strong>
      <p class="caption">Up to {max_states} symbolic states and
      {max(run['observations'] for run in valid_runs):,} observations.
      A state boundary is the entry point plus one state after each action.</p>
    </div>
    <div class="card">
      <div class="metric">&lt; {max_valid_ms / 1000:.2f}s</div>
      <strong>projected SAT decision per trace</strong>
      <p class="caption">After compilation: parse, reduce, emit SMT, and
      decide SAT. Median of 5 interleaved runs; worst p90
      {max_valid_p90_ms / 1000:.2f}s.</p>
    </div>
    <div class="card">
      <div class="metric red">{len(issue_runs)}</div>
      <strong>inconsistent variants rejected</strong>
      <p class="caption">Direct and delayed failures across both traces.</p>
    </div>
    <div class="card">
      <div class="metric amber">2–{max_core}</div>
      <strong>steps in the final contradictions</strong>
      <p class="caption">Automatically reduced and proved UNSAT in at most
      {max_issue_ms / 1000:.2f}s median, {max_issue_p90_ms / 1000:.2f}s p90.</p>
    </div>
  </div>
</section>

<section id="mental-model">
  <h2>The 30-second mental model</h2>
  <p class="section-conceit">
    CCF nodes use Raft rules to agree on one ordered ledger. This report asks
    whether a recorded implementation segment satisfies the current Python
    projected-state encoding.
  </p>
  <div class="cards">
    <div class="card"><strong>Trace</strong>
      <p class="caption">A time-ordered record from <code>raft.h</code>, with
      events, messages, and reported node state.</p></div>
    <div class="card"><strong>Action</strong>
      <p class="caption">A state change allowed by the model, such as timeout,
      receive, or become leader.</p></div>
    <div class="card"><strong>Observation</strong>
      <p class="caption">A value reported by the implementation at the current
      point, such as node 1's term or role.</p></div>
    <div class="card"><strong>SAT / UNSAT</strong>
      <p class="caption">SAT means one encoded execution fits. UNSAT means the
      encoded constraints cannot all hold.</p></div>
  </div>
</section>

<section id="pipeline">
  <h2>One trace becomes one satisfiability question</h2>
  <p class="section-conceit">
    The pipeline preserves source locations for actions, scalar observations,
    and message evidence. State-domain and valid-entry constraints are
    infrastructure assertions without raw-event provenance.
  </p>
  <div class="flow">
    <div class="flow-step"><strong>1. raft_trace</strong>
      NDJSON produced by <code>raft_driver</code>: {raft_records}
      <code>raft.h</code> events, {driver_records} test-driver events, and
      {command_records} command markers.<div class="metric">319</div>
      <span class="caption">records in the larger trace</span>
    </div>
    <div class="flow-step"><strong>2. reduce</strong>
      Python preprocessing, grouping, correlation, and reduction helpers emit
      the executable flat instruction stream.
      <div class="split"><span style="width:14%">&nbsp;</span><span style="width:86%">&nbsp;</span></div>
      <span class="caption">176 actions / 1,093 observations</span>
    </div>
    <div class="flow-step"><strong>3. lower</strong>
      Actions advance symbolic state. Observations constrain the current
      state. Each assertion gets a stable provenance name.
    </div>
    <div class="flow-step"><strong>4. solve</strong>
      cvc5 returns <code>sat</code>, <code>unsat</code>, or
      <code>unknown</code>. UNSAT triggers core reduction and proof output.
    </div>
  </div>
  <div class="grid-2" style="margin-top:1rem">
    <div class="panel">
      <strong>Raw event, line 112</strong>
      <pre>{html.escape(raw_timeout_excerpt)}</pre>
    </div>
    <div class="panel">
      <strong>Reduced instructions</strong>
      <pre>{html.escape(transform_example)}</pre>
    </div>
  </div>
  <p class="caption">This deliberately broken event says
  <code>become_candidate</code> but reports the resulting role as leader.
  The reducer keeps the action and the observations separate. The solver can
  therefore reject the pair instead of accepting the reported state as part
  of the action definition.</p>
</section>

<section id="reduction">
  <h2>Reduction maps implementation events to model instructions</h2>
  <p class="section-conceit">
    Reduction is deliberately ordinary Python. It groups normalized events,
    emits actions and observations in order, and rejects unsupported shapes.
  </p>
  <div class="grid-2">
    <details class="panel">
      <summary><strong>Python receive rule</strong></summary>
      <pre>{html.escape(reduction_snippet)}</pre>
      <p>{source_link(
          "lean-tracing-demo-ccfraft/reduction.py",
          reduction_start,
          "Open reduction.py",
      )}</p>
    </details>
    <div class="panel">
      <h3>Why observations are explicit</h3>
      <p class="callout">
        An action says what the model does. An observation says what the
        implementation reported at that point. Putting both in one ordered
        list makes disagreements visible instead of folding implementation
        state into the transition.
      </p>
      <pre>observe n2.currentTerm = 6
observe n2.firstMessageFrom(source=1) = RequestVote(term=7)
action  n2.receive(source=1)
observe n2.currentTerm = 7</pre>
      <p class="caption">
        CCFRaft selects the first queued message from the chosen source.
        The certificate records that message. The current Python SMT projection
        shape-checks it, then lowers it to <code>true</code>.
      </p>
    </div>
  </div>
  <details class="panel" style="margin-top:1rem">
    <summary><strong>All current reduction rules</strong></summary>
    <div class="table-wrap">
      <table>
        <thead><tr><th>rule</th><th>actions</th><th>observations</th></tr></thead>
        <tbody>{reduction_rule_rows(data)}</tbody>
      </table>
    </div>
  </details>
</section>

<section id="solver">
  <h2>The solver answers existence, not similarity</h2>
  <p class="section-conceit">
    The typed Lean formula asks whether an entry state and enabled
    <code>CCFRaft.next</code> transitions satisfy every observation. The
    executable Python formula checks an over-approximate projection instead.
  </p>
  <div class="grid-2">
    <div class="panel contract">
      <h3>SAT</h3>
      <p>Some projected state sequence satisfies the Python SMT formula.</p>
      <p class="caption">It does not prove implementation correctness or full
      agreement with the Lean model.</p>
    </div>
    <div class="panel contract">
      <h3>UNSAT</h3>
      <p>No projected state sequence satisfies the Python SMT formula.</p>
      <p class="caption">The tool reduces the solver core, maps it back to raw
      events, and asks cvc5 for a proof of the reduced formula.</p>
    </div>
  </div>
  <details class="panel" style="margin-top:1rem">
    <summary><strong>The audited lowering contract</strong></summary>
    <pre>{html.escape(theorem_snippet)}</pre>
    <p>{source_link(
        "lean-tracing-demo-ccfraft/TraceProperties.lean",
        theorem_start,
        "Open lowerTrace_correct",
    )}</p>
  </details>
  <div class="flow" style="margin-top:1rem">
    <div class="flow-step"><strong>Model.lean</strong>
      Defines the canonical <code>Action</code>, <code>Enabled</code>, and
      <code>next</code>.
    </div>
    <div class="flow-step"><strong>Typed Lean formula</strong>
      <code>Lowering.lean</code> translates every action and observation.
    </div>
    <div class="flow-step"><strong>Lean proof</strong>
      <code>lowerTrace_correct</code> proves satisfiability equivalence for
      every successfully lowered trace.
    </div>
    <div class="flow-step"><strong>Executable SMT today</strong>
      Python emits a projected cvc5 formula. Its connection to the typed Lean
      formula remains the open proof obligation.
    </div>
  </div>
  <div class="grid-2" style="margin-top:1rem">
    <div class="panel">
      <h3>Why the theorem has two directions</h3>
      <p><code>FormulaSatisfiable → MidtraceSatisfiable</code> means a solver
      witness denotes a model segment. The reverse direction means every model
      segment has a symbolic witness. That reverse direction is what would
      make SMT UNSAT exclude model segments.</p>
    </div>
    <div class="panel">
      <h3>What still needs proof</h3>
      <p>The theorem covers the typed Lean formula. The executable path emits
      a different Python formula. Until those formulas are connected, cvc5
      proves facts only about the Python projection.</p>
    </div>
  </div>
  <details class="panel" style="margin-top:1rem">
    <summary><strong>From full UNSAT result to a readable contradiction</strong></summary>
    <p>The direct <code>soft_rollback</code> formula contains
    {soft_direct['original_named_assertions']:,} named assertions. cvc5
    returns a core of {soft_direct['original_unsat_core_assertions']:,}.
    Automatic deletion checks reduce that core to
    {soft_direct['reduced_unsat_core_assertions']} assertions.</p>
    <pre>{html.escape(reduced_formula_excerpt)}</pre>
    <p>One assertion says that <code>timeout</code> produces candidate role
    <code>2</code>. The other says that the trace observed leader role
    <code>3</code> at the same action boundary.</p>
    <ol>
      <li>cvc5 replays the full formula and returns an initial UNSAT core.</li>
      <li>The core reducer tries deleting large deterministic chunks.</li>
      <li>It keeps a deletion only when another cvc5 run remains UNSAT.</li>
      <li>It tries individual deletions, then asks cvc5 to prove the reduced
      formula.</li>
    </ol>
  </details>
</section>

<section id="stories">
  <h2>Two reviewer workflows</h2>
  <p class="section-conceit">
    Use the explorer to follow a trace through raw events, reduced
    instructions, the solver result, and the contradiction when one exists.
  </p>
  <div class="grid-2">
    <div class="panel story">
      <span class="status sat">SAT</span>
      <h3>Validate a compatible change</h3>
      <p>Run the changed <code>raft.h</code> or model, capture a trace, and
      check it. SAT means only that the Python projection admits a state
      sequence.</p>
    </div>
    <div class="panel" style="margin-top:1rem">
      <h3>Paired example</h3>
      <p>
        In the captured <code>soft_rollback</code> trace, raw line 112 records
        <code>become_candidate</code> and reports candidate. The trace is SAT.
        The direct variant changes only that reported role to leader. The
        reducer still emits <code>timeout(node 1)</code>, which must produce a
        candidate. The two-step contradiction is UNSAT.
      </p>
      <pre>python3 validate.py \
    Traces/Captured/soft_rollback.ndjson \
    Artifacts/review/soft_rollback \
    --cvc5 /path/to/cvc5
# sat

python3 validate.py \
    Traces/Mutated/soft_rollback-direct.ndjson \
    Artifacts/review/soft_rollback-direct \
    --cvc5 /path/to/cvc5
# unsat</pre>
      <p class="caption">For UNSAT, inspect <code>diagnosis.json</code>,
      <code>formula-reduced.smt2</code>, and <code>proof.txt</code> in the
      output directory.</p>
    </div>
    <div class="panel story unsat">
      <span class="status unsat">UNSAT</span>
      <h3>Investigate a mismatch</h3>
      <p>The same command returns a reduced contradiction. The reviewer sees
      the remaining named constraints, raw lines, and reduction rules.</p>
    </div>
  </div>
  <div class="panel" style="margin-top:1rem">
    <div class="toolbar">
      <label>Example <select id="run-select"></select></label>
      <label>Filter <input id="explorer-filter" placeholder="text or number"></label>
    </div>
    <div class="tabs" role="tablist" aria-label="Trace artifacts">
      <button role="tab" aria-selected="false" data-tab="raw">raw trace</button>
      <button role="tab" aria-selected="false" data-tab="steps">actions + observations</button>
      <button role="tab" aria-selected="false" data-tab="result">SAT / UNSAT</button>
      <button role="tab" aria-selected="true" data-tab="core" class="active">reduced contradiction</button>
    </div>
    <div id="explorer-output" class="explorer-output" role="tabpanel"></div>
  </div>
</section>

<section id="timing">
  <h2>Solver checks are fast; a clean proof build is not</h2>
  <p class="section-conceit">
    The headline uses the normal validation path after the Lean model has
    compiled. The cold accounting below removes this package's build outputs
    while retaining the pinned dependency cache.
  </p>
  <div class="cards">
    <div class="card"><div class="metric">{milliseconds(capture_max)}</div>
      <strong>largest median scenario + capture time</strong>
      <p class="caption">Slowest sample: {milliseconds(capture_sample_max)}.</p></div>
    <div class="card"><div class="metric amber">{milliseconds(cold_build)}</div>
      <strong>clean project Lean build</strong></div>
    <div class="card"><div class="metric">{milliseconds(warm_build)}</div>
      <strong>no-change Lean build</strong></div>
  </div>
  <div class="panel" style="margin-top:1rem">
    <h3>Constructed project-clean gate estimate</h3>
    <p class="callout">
      Adding the median <code>bad_network</code> scenario and capture time,
      one clean project build, and the median Python validation time gives
      <strong>{milliseconds(cold_example_total)}</strong>.
      Lean compilation took {cold_compile_percent:.1f}% of that time.
      These stages were measured separately. The Lean build is a separate
      gate and is shared by later traces.
    </p>
    <div class="bar">
      <span class="reduce" title="trace emission"
        style="width:{100 * capture_max / cold_example_total:.3f}%">&nbsp;</span>
      <span class="explain" title="Lean compilation"
        style="width:{100 * cold_build / cold_example_total:.3f}%">&nbsp;</span>
      <span class="solve" title="trace validation"
        style="width:{100 * max_valid_ms / cold_example_total:.3f}%">&nbsp;</span>
    </div>
  </div>
  <details class="panel" style="margin-top:1rem">
    <summary><strong>Per-phase timing table</strong></summary>
    <div class="table-wrap">
    <table id="timing-table">
      <thead><tr><th>trace</th><th>states</th><th>actions</th><th>observations</th>
      <th>parse</th><th>preprocess</th><th>reduce</th><th>certificate write</th>
      <th>SMT build</th><th>SMT write</th><th>decision median</th>
      <th>decision p90</th><th>core replay</th><th>minimise</th><th>proof</th>
      <th>full median</th><th>full p90</th></tr></thead>
      <tbody>{timing_rows(measurements)}</tbody>
    </table>
    </div>
  </details>
</section>

<section id="limits">
  <h2>What is proved, trusted, and still missing</h2>
  <p class="section-conceit">
    The prototype separates the small model-specific review from shared and
    mechanically checked code, but one important connection remains open.
  </p>
  <div class="grid-2">
    <div class="panel">
      <h3>Checked now</h3>
      <ul>
        <li>The CCFRaft model and consensus proof compile in Lean.</li>
        <li>All ten action constructors have typed lowerings.</li>
        <li><code>lowerTrace_correct</code> equates typed formula
        satisfiability with model-segment satisfiability.</li>
        <li>cvc5 checks each emitted UNSAT proof.</li>
      </ul>
      <p class="caption">cvc5 performs that proof check internally. This demo
      does not run a second independent proof checker.</p>
    </div>
    <div class="panel warning">
      <h3>Current gap</h3>
      <p>The executable Python SMT backend is still a projection of roles,
      terms, log lengths, commit indices, allocation, and join state. The
      certificate records queue-message observations, but this backend does
      not encode queues or message contents yet.</p>
      <p>The next proof obligation is to connect the emitted SMT formula to
      the typed Lean formula covered by <code>lowerTrace_correct</code>.</p>
      <p>The Python certificate decoder still needs a proved correspondence
      with the typed Lean trace.</p>
      <p>The executable path trusts trace instrumentation, <code>raft_driver</code>,
      Python parsing and reduction, <code>ccfraft_projection.py</code>, cvc5, and the
      report generator.</p>
    </div>
  </div>
  <p class="caption">Measurements come from
  {source_link(
      "lean-tracing-demo-ccfraft/benchmark_pipeline.py",
      line_number(ROOT / "benchmark_pipeline.py", "def main"),
      "benchmark_pipeline.py",
  )}. Five validation and capture samples were interleaved. Clean and
  no-change Lean builds were measured once. Environment:
  {html.escape(measurements['environment']['platform'])},
  {html.escape(measurements['environment']['cvc5'])},
  Python {html.escape(measurements['environment']['python'])}. Open the
  <a href="{WORKSPACE_URL}">workspace</a>.</p>
</section>
</main>
<script>
const DATA = {embedded};
const select = document.querySelector("#run-select");
const output = document.querySelector("#explorer-output");
const filter = document.querySelector("#explorer-filter");
let tab = "core";
let page = 0;
let focusRaw = null;
let focusStep = null;
const PAGE_SIZE = 100;
for (const name of Object.keys(DATA.runs)) {{
  const option = document.createElement("option");
  option.value = name;
  option.textContent = name;
  select.append(option);
}}
select.value = "soft_rollback-direct";
function esc(value) {{
  return String(value).replace(/[&<>"']/g, ch => ({{
    "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"
  }}[ch]));
}}
function pager(total) {{
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  page = Math.min(page, pages - 1);
  return `<div class="toolbar"><button data-page="-1" ${{page === 0 ? "disabled" : ""}}>previous</button>` +
    `<span class="caption">page ${{page + 1}} of ${{pages}}, ${{total}} matches</span>` +
    `<button data-page="1" ${{page + 1 >= pages ? "disabled" : ""}}>next</button></div>`;
}}
function setTab(next) {{
  tab = next;
  page = 0;
  document.querySelectorAll("[data-tab]").forEach(item => {{
    const selected = item.dataset.tab === tab;
    item.classList.toggle("active", selected);
    item.setAttribute("aria-selected", selected ? "true" : "false");
  }});
}}
function initializeHeaders(scope = document) {{
  scope.querySelectorAll("th").forEach(header => {{
    header.tabIndex = 0;
    header.setAttribute("role", "button");
    if (!header.hasAttribute("aria-sort")) header.setAttribute("aria-sort", "none");
  }});
}}
function render() {{
  const run = DATA.runs[select.value];
  const query = filter.value.toLowerCase();
  if (tab === "raw") {{
    const rows = run.raw.filter(row =>
      (focusRaw === null || row.line === focusRaw) &&
      `${{row.line}} ${{JSON.stringify(row.value)}}`.toLowerCase().includes(query)
    );
    const visible = rows.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);
    output.innerHTML = `<div class="table-wrap"><table><thead><tr><th>line</th><th>event</th></tr></thead><tbody>${{
      visible.map(row => `<tr><td>${{row.line}}</td><td><code>${{esc(JSON.stringify(row.value))}}</code></td></tr>`).join("")
    }}</tbody></table></div>${{pager(rows.length)}}`;
  }} else if (tab === "steps") {{
    const rows = run.steps.map((step,index) => ({{step,index:index+1}}))
      .filter(row =>
        (focusStep === null || row.index === focusStep) &&
        `${{row.index}} ${{JSON.stringify(row.step)}}`.toLowerCase().includes(query)
      );
    const visible = rows.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);
    output.innerHTML = visible.map(row => {{
      const step = row.step;
      const body = step.kind === "action"
        ? `${{step.action}} on node ${{step.node}}`
        : `${{step.variable}}(${{step.node}}) = ${{JSON.stringify(step.value)}}`;
      return `<div class="instruction ${{step.kind}}"><code>#${{row.index}}</code><code>${{esc(body)}}</code><span class="rule">${{esc(step.rule)}}</span></div>`;
    }}).join("") + pager(rows.length);
  }} else if (tab === "result") {{
    output.innerHTML = `<h3>Result metadata</h3><pre>${{esc(JSON.stringify(run.result,null,2))}}</pre>` +
      (run.reducedFormula ? `<details><summary>Reduced SMT formula</summary><pre>${{esc(run.reducedFormula)}}</pre></details>` : "") +
      (run.proof ? `<details><summary>Complete checked cvc5 proof</summary><pre>${{esc(run.proof)}}</pre></details>` : "");
  }} else {{
    if (!run.diagnosis) {{
      output.innerHTML = `<p class="callout">SAT has no contradiction core.</p>`;
    }} else {{
      const items = run.diagnosis.items.filter(item =>
        JSON.stringify(item).toLowerCase().includes(query)
      );
      output.innerHTML = `<p><strong>${{run.diagnosis.core_kind}}</strong></p>` +
        items.map(item => `<div class="instruction ${{item.category === "transition" ? "action" : "observation"}}"><code>#${{item.instruction_index}}</code><div><code>${{esc(item.name)}}</code><br><button data-jump-step="${{item.instruction_index}}">instruction</button> <button data-jump-raw="${{item.raw_line}}">raw line ${{item.raw_line}}</button><br><span class="caption">${{esc(JSON.stringify(item.parameters || item.value || {{}}))}}</span></div><span class="rule">${{esc(item.reduction_rule || item.category)}}</span></div>`).join("") +
        `<details><summary>Full initial cvc5 core</summary><pre>${{esc(run.originalCore)}}</pre></details>` +
        `<details open><summary>Reduced core</summary><pre>${{esc(run.reducedCore)}}</pre></details>`;
    }}
  }}
  initializeHeaders(output);
}}
document.querySelectorAll("[data-tab]").forEach(button => {{
  button.addEventListener("click", () => {{
    focusRaw = null;
    focusStep = null;
    setTab(button.dataset.tab);
    render();
  }});
}});
select.addEventListener("change", () => {{
  page = 0; focusRaw = null; focusStep = null; render();
}});
filter.addEventListener("input", () => {{
  page = 0; focusRaw = null; focusStep = null; render();
}});
output.addEventListener("click", event => {{
  const pageButton = event.target.closest("[data-page]");
  if (pageButton) {{
    page += Number(pageButton.dataset.page);
    render();
    return;
  }}
  const rawButton = event.target.closest("[data-jump-raw]");
  if (rawButton) {{
    focusRaw = Number(rawButton.dataset.jumpRaw);
    focusStep = null;
    filter.value = "";
    setTab("raw");
    render();
    return;
  }}
  const stepButton = event.target.closest("[data-jump-step]");
  if (stepButton) {{
    focusStep = Number(stepButton.dataset.jumpStep);
    focusRaw = null;
    filter.value = "";
    setTab("steps");
    render();
  }}
}});
function sortableValue(text) {{
  const value = text.trim().replaceAll(",", "");
  if (/^-?[0-9.]+ ms$/.test(value)) return parseFloat(value);
  if (/^-?[0-9.]+ s$/.test(value)) return parseFloat(value) * 1000;
  if (/^-?[0-9.]+ min$/.test(value)) return parseFloat(value) * 60000;
  if (/^-?[0-9.]+$/.test(value)) return parseFloat(value);
  return value.toLowerCase();
}}
function sortTable(header) {{
  const table = header.closest("table");
  const body = table.tBodies[0];
  if (!body) return;
  const column = [...header.parentElement.children].indexOf(header);
  const direction = header.dataset.direction === "asc" ? "desc" : "asc";
  table.querySelectorAll("th").forEach(item => {{
    item.dataset.direction = "";
    item.setAttribute("aria-sort", "none");
  }});
  header.dataset.direction = direction;
  header.setAttribute("aria-sort", direction === "asc" ? "ascending" : "descending");
  const rows = [...body.rows];
  rows.sort((left,right) => {{
    const a = sortableValue(left.cells[column].textContent);
    const b = sortableValue(right.cells[column].textContent);
    const order = typeof a === "number" && typeof b === "number"
      ? a - b : String(a).localeCompare(String(b));
    return direction === "asc" ? order : -order;
  }});
  body.replaceChildren(...rows);
}}
document.addEventListener("click", event => {{
  const header = event.target.closest("th");
  if (header) sortTable(header);
}});
document.addEventListener("keydown", event => {{
  if ((event.key === "Enter" || event.key === " ") && event.target.matches("th")) {{
    event.preventDefault();
    sortTable(event.target);
  }}
}});
initializeHeaders();
setTab("core");
render();
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
