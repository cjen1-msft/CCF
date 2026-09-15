#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Prepare a fixed trace corpus and compare isolated SMT encoding experiments."""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import html
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))

from native_lean import encode_details
from native_origin import reduce_raw
from native_reduction import native_document
from native_run import validate_encoding
from Shared.smt import parse_unsat_core

FULL_CYCLE = "(check-sat-using (then simplify propagate-values solve-eqs simplify smt))\n"
DEFAULT_OUTPUT = PROJECT / "Measurements/encoding-study/results"


def save(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def prepare(output: Path) -> None:
    specifications = [
        ("callback-22", "Controls/configuration_callback", 22, None),
        *[(f"bad-prefix-{n}", "Captured/bad_network", n, None)
          for n in (34, 37, 40, 52, 110)],
        ("soft-middle-1", "Captured/soft_rollback", None, (451, 1)),
        ("soft-middle-4", "Captured/soft_rollback", None, (451, 4)),
        ("bad-middle-4", "Captured/bad_network", None, (900, 4)),
        ("bad-late-5", "Captured/bad_network", None, (1400, 5)),
    ]
    manifest = []
    for name, relative, count, window in specifications:
        directory = output / "inputs" / name
        directory.mkdir(parents=True, exist_ok=False)
        path = PROJECT / "Traces" / f"{relative}.ndjson"
        raw = path.read_bytes()
        selected = b"".join(raw.splitlines(keepends=True)[:count]) if count else raw
        origin = reduce_raw(selected)
        full = native_document(origin.trace, ["0"])
        steps = origin.trace.steps
        evidence = origin.certificate["steps"]
        start, stop = 0, len(steps)
        if window:
            start, target = window
            first_line = min(p["line"] for p in evidence[start]["provenance"])
            while start and any(p["line"] >= first_line for p in evidence[start - 1]["provenance"]):
                start -= 1
            seen = 0
            for index in range(start, len(steps)):
                if steps[index]["kind"] != "action":
                    continue
                if seen == target:
                    next_line = min(p["line"] for p in evidence[index]["provenance"])
                    stop = index
                    while stop > start and any(
                        p["line"] >= next_line for p in evidence[stop - 1]["provenance"]
                    ):
                        stop -= 1
                    if stop <= start or sum(
                        item["kind"] == "receiveAppendEntries"
                        for item in full["instructions"][start:stop]
                    ) != target:
                        raise ValueError(f"Receive target splits an event: {name}")
                    break
                if full["instructions"][index]["kind"] == "receiveAppendEntries":
                    seen += 1
            else:
                raise ValueError(f"Cannot complete window: {name}")
        document = {**full, "instructions": full["instructions"][start:stop]}
        kinds = [
            item["kind"] if step["kind"] == "action" else None
            for step, item in zip(steps[start:stop], document["instructions"], strict=True)
        ]
        actions = Counter(kind for kind in kinds if kind is not None)
        if sum(actions.values()) > 80:
            raise ValueError(f"Window exceeds the action budget: {name}")
        started = time.perf_counter()
        details = encode_details(document)
        metadata = {
            "name": name, "source": str(path.relative_to(PROJECT)),
            "case_kind": "relaxed_window" if window else "raw_prefix",
            "source_sha256": digest(raw), "selected_source_sha256": digest(selected),
            "raw_records": count,
            "start_instruction": start, "stop_instruction": stop,
            "instructions": len(kinds), "action_kinds": kinds,
            "actions": dict(actions), "actions_total": sum(actions.values()),
            "document_sha256": digest(json.dumps(document, sort_keys=True).encode()),
            "smt_sha256": digest(details["script"].encode()),
            "encoding_seconds": time.perf_counter() - started,
            "selected_provenance": evidence[start:stop],
        }
        save(directory / "encoding.json", details)
        save(directory / "case.json", metadata)
        save(directory / "full-reduction.json", origin.certificate)
        (directory / "source.ndjson").write_bytes(selected)
        (directory / "original.smt2").write_text(details["script"], encoding="ascii")
        manifest.append(metadata)
        save(output / "manifest.json", manifest)
        print("PREPARED", name, dict(actions), flush=True)
    hashes = [case["document_sha256"] for case in manifest]
    if len(hashes) != len(set(hashes)):
        raise ValueError("Corpus has duplicate documents")


def assertion_chunks(details: dict, kinds: list[str | None], incremental: bool) -> list[str]:
    script = details["script"]
    if script.count("(check-sat)\n") != 1 or not script.endswith("(check-sat)\n"):
        raise ValueError("Expected exactly one trailing check-sat")
    body = "".join(
        f'(assert (! {clause["expression"]} :named {clause["name"]}))\n'
        for clause in details["clauses"]
    )
    suffix = body + "(check-sat)\n"
    if not body or not script.endswith(suffix):
        raise ValueError("Clause metadata does not reproduce original assertions")
    head = script[:-len(suffix)]
    if not incremental:
        return [head + body]
    groups = {group["instruction"]: group for group in details["groups"]}
    cuts = [
        groups[index]["start"] for index, kind in enumerate(kinds)
        if kind is not None
    ][1:]
    chunks = []
    previous = 0
    clauses = body.splitlines(keepends=True)
    if len(clauses) != len(details["clauses"]):
        raise ValueError("Expected one line per original assertion")
    for cut in cuts + [len(clauses)]:
        chunks.append(("".join(clauses[previous:cut])))
        previous = cut
    chunks[0] = head + chunks[0]
    if "".join(chunks) != head + body:
        raise ValueError("Incremental scheduling changed the assertion stream")
    return chunks


def prepare_variant(args: argparse.Namespace) -> None:
    manifest = json.loads((args.output / "manifest.json").read_text())
    documents = [
        json.loads((args.output / "inputs" / case["name"] / "encoding.json").read_text())["input"]
        for case in manifest
    ]
    started = time.perf_counter()
    completed = subprocess.run(
        ["lake", "env", "lean", "--run", f"Prototype/{args.prepare_variant}.lean", "--batch",
         *args.variant_arguments],
        cwd=PROJECT, input=json.dumps(documents, sort_keys=True, separators=(",", ":")),
        text=True, capture_output=True, check=True,
    )
    variants = json.loads(completed.stdout)
    if len(variants) != len(documents):
        raise ValueError("Prototype batch length mismatch")
    for case, document, details in zip(manifest, documents, variants, strict=True):
        validate_encoding(document, details)
        directory = args.output / "variants" / args.variant / case["name"]
        directory.mkdir(parents=True, exist_ok=False)
        save(directory / "encoding.json", details)
        (directory / "original.smt2").write_text(details["script"])
    save(args.output / "variants" / args.variant / "preparation.json", {
        "module": args.prepare_variant, "wall_seconds": time.perf_counter() - started,
        "source_sha256": digest((PROJECT / "Prototype" / f"{args.prepare_variant}.lean").read_bytes()),
        "arguments": args.variant_arguments,
        "cases": [case["name"] for case in manifest],
    })


def load_variant(args: argparse.Namespace, case: dict, original: dict, variant=None) -> dict:
    root = args.output / "variants" / (variant or args.variant)
    preparation = json.loads((root / "preparation.json").read_text())
    source = (PROJECT / preparation["source_path"] if "source_path" in preparation else
              PROJECT / "Prototype" / f'{preparation["module"]}.lean')
    if digest(source.read_bytes()) != preparation["source_sha256"]:
        raise ValueError("Prototype source changed after preparing the variant")
    for relative, expected in preparation.get("dependencies", {}).items():
        if digest((PROJECT / relative).read_bytes()) != expected:
            raise ValueError(f"Prototype dependency changed: {relative}")
    encoded = json.loads((root / case["name"] / "encoding.json").read_text())
    validate_encoding(original["input"], encoded)
    if "evidence_files" in preparation:
        evidence = preparation["evidence_files"][case["name"]]
        path = args.output / evidence["path"]
        if digest(path.read_bytes()) != evidence["sha256"]:
            raise ValueError("Source evidence changed after preparing the variant")
        if json.loads(path.read_text())["envelope"]["input"] != original["input"]:
            raise ValueError("Source evidence belongs to a different input")
    if "source_variant" in preparation:
        parent = args.output / "variants" / preparation["source_variant"]
        parent_preparation = json.loads((parent / "preparation.json").read_text())
        if parent_preparation != preparation["source_preparation"] or "source_variant" in parent_preparation:
            raise ValueError("Derived variant source metadata changed or has unsupported nesting")
        parent_encoding = load_variant(args, case, original, preparation["source_variant"])
        if encoded["clauses"] != parent_encoding["clauses"] or encoded["groups"] != parent_encoding["groups"]:
            raise ValueError("Cell exposure changed source clauses")
    return encoded


def worker(request_path: Path) -> None:
    request = json.loads(request_path.read_text())
    directory = request_path.parent
    command = [
        request["z3"], "-in", "-st", "unsat_core=true",
        "smt.ematching=false", "smt.mbqi=true",
    ]
    if request["profile"]:
        command += ["smt.qi.profile=true", "smt.mbqi.trace=true"]
        command += [f'-t:{request["native_timeout_ms"]}']
    started = time.perf_counter()
    responses = []
    with (directory / "solver.stderr").open("w") as stderr, (
        directory / "solver.stdout"
    ).open("w") as stdout, subprocess.Popen(
        command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=stderr, text=True
    ) as process:
        for index, chunk in enumerate(request["chunks"]):
            process.stdin.write(chunk + request["query"])
            process.stdin.flush()
            verdict = process.stdout.readline()
            stdout.write(verdict)
            stdout.flush()
            status = verdict.strip()
            responses.append({
                "query": index, "verdict": status,
                "cumulative_seconds": time.perf_counter() - started,
            })
            save(directory / "queries.json", responses)
            if status == "unknown":
                process.stdin.write('(get-info :reason-unknown)\n(echo "STUDY_REASON_END")\n')
                process.stdin.flush()
                reason = []
                while True:
                    line = process.stdout.readline()
                    if not line:
                        raise RuntimeError("EOF reading reason-unknown")
                    if line.strip().strip('"') == "STUDY_REASON_END":
                        break
                    reason.append(line)
                    stdout.write(line)
                responses[-1]["reason_unknown"] = "".join(reason).strip()
                save(directory / "queries.json", responses)
            elif status != "sat":
                break
        extra = {
            "sat": "", "unsat": "(get-unsat-core)\n",
            "unknown": "",
        }.get(status, "")
        rest, _ = process.communicate(input=extra)
        stdout.write(rest)
    output = (directory / "solver.stdout").read_text()
    if process.returncode != 0 or status not in {"sat", "unsat", "unknown"} or "(error" in output:
        raise RuntimeError(f"Solver protocol failed; see {directory}")
    save(directory / "completed.json", {
        "status": status, "solver_seconds": time.perf_counter() - started,
        "command": command, "queries": responses,
        "all_queries_completed": len(responses) == len(request["chunks"]),
        "stats": {key: float(value) for key, value in
                  re.findall(r":([a-z0-9-]+)\s+([0-9.e+]+)", rest)},
        "core": list(parse_unsat_core(rest.split("(:", 1)[0])) if status == "unsat" else None,
    })


def solve(directory: Path, chunks: list[str], query: str, z3: str,
          limit: float, profile: bool) -> dict:
    directory.mkdir(parents=True, exist_ok=False)
    request = {
        "chunks": chunks, "query": query, "z3": z3, "profile": profile,
        "native_timeout_ms": max(1, int((limit - 1) * 1000)) if profile else None,
    }
    request_path = directory / "request.json"
    save(request_path, request)
    (directory / "query.smt2").write_text("".join(chunk + query for chunk in chunks))
    started = time.perf_counter()
    with (directory / "worker.stdout").open("w") as stdout, (
        directory / "worker.stderr"
    ).open("w") as stderr:
        process = subprocess.Popen(
            [sys.executable, str(Path(__file__).resolve()), "--worker", str(request_path)],
            stdout=stdout, stderr=stderr, start_new_session=True,
        )
        try:
            process.wait(timeout=limit)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            result = {"status": "external_cutoff", "solver_seconds": None}
        else:
            result = json.loads((directory / "completed.json").read_text()) if process.returncode == 0 else {
                "status": "error", "returncode": process.returncode,
            }
    result.update(wall_seconds=time.perf_counter() - started, limit_seconds=limit,
                  profile=profile, process_reaped=True)
    if result["status"] == "external_cutoff" and (directory / "queries.json").exists():
        result["queries"] = json.loads((directory / "queries.json").read_text())
        result["all_queries_completed"] = False
    save(directory / "result.json", result)
    return result


def plot(rows: list[dict], path: Path) -> None:
    colors = {"full-cycle": "#1768ac", "ordinary": "#666666", "incremental": "#bf3b25"}
    for row in rows:
        colors.setdefault(row["mode"], "#7750a0")
    colors = {mode: color for mode, color in colors.items() if any(row["mode"] == mode for row in rows)}
    max_receives = max([1] + [row["receives"] for row in rows])
    xscale = 700 / max_receives
    svg = [
        '<svg xmlns="http://www.w3.org/2000/svg" width="860" height="440" viewBox="0 0 860 440">',
        '<rect width="860" height="440" fill="white"/>',
        '<text x="65" y="25" font-family="sans-serif" font-size="16">Z3 process wall time; triangles are cutoffs (not measurements)</text>',
        '<path d="M65 50V365H820" fill="none" stroke="black"/>',
        '<text x="280" y="425" font-family="sans-serif">Received AppendEntries (different trace regions)</text>',
    ]
    maximum = max([60] + [row["result"]["limit_seconds"] for row in rows])
    scale = 300 / maximum
    for tick in (0, maximum / 4, maximum / 2, maximum * 3 / 4, maximum):
        y = 365 - tick * scale
        svg.append(f'<text x="8" y="{y}" font-family="sans-serif">{tick}s</text>')
    for tick in sorted(set(row["receives"] for row in rows)):
        svg.append(f'<text x="{65 + tick * xscale}" y="385" font-family="sans-serif">{tick}</text>')
    for row in rows:
        if row["profile"]:
            continue
        result = row["result"]
        seconds = result.get("solver_seconds")
        if result["status"] not in {"sat", "external_cutoff"}:
            continue
        x = 65 + row["receives"] * xscale
        y = 365 - (seconds if seconds is not None else row["result"]["limit_seconds"]) * scale
        color = colors.get(row["mode"], "#7750a0")
        title = html.escape(f'{row["case"]} {row["mode"]}: {result["status"]}, {seconds}')
        shape = f'<circle cx="{x}" cy="{y}" r="4" fill="{color}"><title>{title}</title></circle>' if seconds is not None else (
            f'<path d="M{x} {y-5}l-5 9h10z" fill="{color}"><title>{title}</title></path>'
        )
        svg.append(shape)
    for i, (mode, color) in enumerate(colors.items()):
        reference = next((row.get("reference_variant") for row in rows if row["mode"] == mode), None)
        label = reference if mode == "full-cycle" and reference else mode
        svg.append(f'<text x="{80 + i * 230}" y="405" fill="{color}" font-family="sans-serif">{html.escape(label)}</text>')
    svg.append("</svg>")
    path.write_text("\n".join(svg))


def run_a(args: argparse.Namespace) -> None:
    manifest = json.loads((args.output / "manifest.json").read_text())
    selected = [case for case in manifest if not args.cases or case["name"] in args.cases]
    root = args.output / args.experiment / args.label
    root.mkdir(parents=True, exist_ok=False)
    version = subprocess.run([args.z3, "--version"], capture_output=True, text=True, check=True).stdout.strip()
    save(root / "environment.json", {"z3": version, "python": sys.version, "host": os.uname().nodename})
    rows = []
    for sample in range(args.samples):
        modes = args.modes if sample % 2 == 0 else list(reversed(args.modes))
        for case in selected:
            details = json.loads((args.output / "inputs" / case["name"] / "encoding.json").read_text())
            validate_encoding(details["input"], details)
            if (digest(details["script"].encode()) != case["smt_sha256"] or
                digest(json.dumps(details["input"], sort_keys=True).encode()) != case["document_sha256"] or
                len(case["action_kinds"]) != len(details["input"]["instructions"])):
                raise ValueError(f"Stale corpus metadata: {case['name']}")
            for mode in modes:
                if mode not in {"full-cycle", "ordinary", "incremental", args.variant}:
                    raise ValueError(f"Unknown mode: {mode}")
                if args.reference_variant:
                    reference = load_variant(args, case, details, args.reference_variant)
                else:
                    reference = details
                encoded = reference if mode != args.variant else load_variant(args, case, details)
                validate_encoding(details["input"], encoded)
                chunks = assertion_chunks(encoded, case["action_kinds"], mode == "incremental")
                query = "(check-sat)\n" if mode in {"ordinary", "incremental"} else FULL_CYCLE
                result = solve(root / f'{case["name"]}-{mode}-{sample}', chunks, query,
                               args.z3, args.limit, args.profile)
                row = {
                    "case": case["name"], "mode": mode, "sample": sample,
                    "profile": args.profile, "receives": case["actions"].get("receiveAppendEntries", 0),
                    "actions": case["actions"], "result": result,
                    "reference_variant": args.reference_variant,
                    "encoding_variant": args.variant if mode == args.variant else args.reference_variant or "original",
                    "query_mode": "ordinary" if mode == "ordinary" else "incremental" if mode == "incremental" else "full-cycle",
                    "encoding_sha256": digest(encoded["script"].encode()),
                }
                rows.append(row)
                if mode == args.variant:
                    preparation = json.loads(
                        (args.output / "variants" / args.variant / "preparation.json").read_text()
                    )
                    if "evidence_files" in preparation:
                        row["evidence_plans"] = preparation["evidence_files"][case["name"]]["plans"]
                save(root / "summary.json", rows)
                plot(rows, root / "scaling.svg")
                print(case["name"], mode, sample, result["status"],
                      result.get("solver_seconds"), flush=True)
                if result["status"] in {"error", "unsat"}:
                    raise RuntimeError(f"Unexpected result: {row}")


def controls(args: argparse.Namespace) -> None:
    root = args.output / args.experiment / args.label
    root.mkdir(parents=True, exist_ok=False)
    case = json.loads((args.output / "inputs/bad-prefix-34/case.json").read_text())
    details = json.loads((args.output / "inputs/bad-prefix-34/encoding.json").read_text())
    validate_encoding(details["input"], details)
    if args.reference_variant:
        details = load_variant(args, case, details, args.reference_variant)
    if case["action_kinds"][-1] is not None:
        raise ValueError("The late control requires a final observation")
    expression = details["clauses"][details["groups"][-1]["start"]]["expression"]
    extra = f"(assert (! (not {expression}) :named study_conflict))\n"
    names = {clause["name"]: clause["expression"] for clause in details["clauses"]}
    names["study_conflict"] = f"(not {expression})"
    results = []
    for mode in args.modes:
        encoded = details if mode != args.variant else load_variant(args, case, details)
        if encoded["groups"] != details["groups"] or [
            c["name"] for c in encoded["clauses"]
        ] != [c["name"] for c in details["clauses"]]:
            raise ValueError("This control requires an explicit map for changed clause groups")
        chunks = assertion_chunks(encoded, case["action_kinds"], mode == "incremental")
        chunks[-1] += extra
        result = solve(root / mode, chunks, "(check-sat)\n" if mode in {"ordinary", "incremental"} else FULL_CYCLE,
                       args.z3, args.limit, False)
        if result["status"] != "unsat":
            raise ValueError(f"Negative control did not complete UNSAT: {mode}: {result}")
        core = result["core"]
        if not core or not set(core) <= names.keys() or "study_conflict" not in core:
            raise ValueError(f"Invalid source core: {core}")
        candidate_names = {clause["name"]: clause["expression"] for clause in encoded["clauses"]}
        candidate_names["study_conflict"] = f"(not {expression})"
        candidate_body = "".join(
            f'(assert (! {clause["expression"]} :named {clause["name"]}))\n' for clause in encoded["clauses"]
        )
        candidate_head = encoded["script"].removesuffix(candidate_body + "(check-sat)\n")
        candidate_script = candidate_head + "".join(
            f"(assert (! {candidate_names[name]} :named {name}))\n" for name in core
        )
        candidate_replay = solve(root / f"{mode}-candidate-replay", [candidate_script], "(check-sat)\n",
                                 args.z3, args.limit, False)
        if candidate_replay["status"] != "unsat":
            raise ValueError(f"Candidate core replay failed: {candidate_replay}")
        head = details["script"].split("(assert ", 1)[0]
        script = head + "".join(f"(assert (! {names[name]} :named {name}))\n" for name in core)
        replay = solve(root / f"{mode}-replay", [script], "(check-sat)\n",
                       args.z3, args.limit, False)
        if replay["status"] != "unsat":
            raise ValueError(f"Core replay failed: {replay}")
        results.append({
            "mode": mode, "negative": result, "candidate_clause_replay": candidate_replay,
            "reference_clause_replay": replay, "reference_variant": args.reference_variant or "original",
        })
        save(root / "summary.json", results)
        print("CONTROL", mode, "UNSAT; original core replay UNSAT", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", type=Path)
    parser.add_argument("--prepare", action="store_true")
    parser.add_argument("--controls", action="store_true")
    parser.add_argument("--prepare-variant")
    parser.add_argument("--variant", default="store")
    parser.add_argument("--variant-arguments", nargs="*", default=[])
    parser.add_argument("--reference-variant")
    parser.add_argument("--experiment", default="a")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--z3", default="z3")
    parser.add_argument("--label", default="screen")
    parser.add_argument("--cases", nargs="*")
    parser.add_argument("--modes", nargs="+",
                        default=["full-cycle", "ordinary", "incremental"])
    parser.add_argument("--samples", type=int, default=1)
    parser.add_argument("--limit", type=float, default=60)
    parser.add_argument("--profile", action="store_true")
    args = parser.parse_args()
    if args.worker:
        worker(args.worker)
    elif args.prepare:
        prepare(args.output)
    elif args.prepare_variant:
        prepare_variant(args)
    elif args.controls:
        controls(args)
    else:
        if args.limit <= 0 or args.samples < 1:
            parser.error("Positive limits and sample counts required")
        run_a(args)


if __name__ == "__main__":
    main()
