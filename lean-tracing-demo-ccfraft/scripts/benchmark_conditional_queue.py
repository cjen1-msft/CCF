#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Build the native conditional-queue fixture, then measure one case per invocation.

Requires the pinned Lean toolchain and existing package Lean/native artifacts.
No dependency installation, cache download, package rebuild, or full Sparse native
build is requested. --build checks cached Mathlib first, builds only the fixture's
Lean target, compiles its 35 project C modules, and reuses package native objects.
Use a fresh --output for each baseline; build and case evidence is not overwritten.

The fixture forces one warm emission before measuring formula/command/text phases.
Solver medians use three separate cvc5 processes, not three warmed solver queries.
--audit checks the predefined 54-case matrix; missing, emitted-only, and interrupted
cases are incomplete. --require-complete makes incomplete coverage an error.
Even 54 completed cases cover only these empty-initial source-local conditional
send/pop/length fixtures, not full Model traces or general queue completion.

Source/C hashes and cached-object size/mtime records detect changes to recorded
inputs. Package sources are not rebuilt, package objects are not content-hashed,
and the toolchain/system libraries are not hermetically captured.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import statistics
import subprocess
import sys
import time

PROJECT = Path(__file__).resolve().parents[1]
MODULE = "Sparse.ConditionalQueueScaleMain"
NATIVE_MODULES = (
    "Model",
    "Shared.ExecutableTransitionSystem",
    "Sparse.ArrayLog",
    "Sparse.BijectiveIntegerLog",
    "Sparse.ConditionalQueueAccounting",
    "Sparse.ConditionalQueueEncoding",
    "Sparse.ConditionalQueueScaleMain",
    "Sparse.ConditionalQueueTraceEncoding",
    "Sparse.CountedQueue",
    "Sparse.EntrySelectorSemantics",
    "Sparse.EntryValue",
    "Sparse.IntegerLog",
    "Sparse.IntegerQueue",
    "Sparse.NodeSetCodec",
    "Sparse.QueueAccounting",
    "Sparse.QueueClause",
    "Sparse.QueueCounts",
    "Sparse.QueueEncoding",
    "Sparse.QueueInitialEncoding",
    "Sparse.QueuePlan",
    "Sparse.QueueReadback",
    "Sparse.QueueScalarEncoding",
    "Sparse.QueueStream",
    "Sparse.QueueTraceEncoding",
    "Sparse.Readback",
    "Sparse.SignedQueue",
    "Sparse.Smt",
    "Sparse.SmtExpressionText",
    "Sparse.SmtNodes",
    "Sparse.SmtNumerals",
    "Sparse.SmtScript",
    "Sparse.SmtScriptText",
    "Sparse.SmtText",
    "Sparse.SymbolBounds",
    "Sparse.SymbolCollection",
)

sys.dont_write_bytecode = True
sys.path.insert(0, str(PROJECT))
from Shared.solver import ValidationError, find_cvc5, run_solver


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n", encoding="ascii")


def git_output(directory: Path, *arguments: str) -> str:
    return subprocess.check_output(
        ["git", "--no-optional-locks", "-C", str(directory), *arguments],
        text=True,
    ).strip()


def installed_lake(project: Path) -> Path:
    """Resolve an installed toolchain without allowing an elan shim to install it."""
    located = shutil.which("lake")
    require(located is not None, "Missing lake; install tooling outside this benchmark")
    lake = Path(located).resolve()
    if lake.name == "elan":
        pinned = (project / "lean-toolchain").read_text().strip()
        installed = subprocess.check_output(
            [str(lake), "toolchain", "list"], text=True, cwd=project
        )
        require(
            pinned in {line.split()[0] for line in installed.splitlines() if line},
            f"Toolchain {pinned} is not installed; no downloads permitted",
        )
        environment = dict(os.environ, ELAN_TOOLCHAIN=pinned)
        lake = Path(
            subprocess.check_output(
                [str(lake), "which", "lake"],
                text=True,
                cwd=project,
                env=environment,
            ).strip()
        ).resolve()
    require(lake.is_file(), f"Missing installed Lake executable: {lake}")
    require(shutil.which("nice") is not None, "Missing nice")
    return lake


def package_roots(project: Path) -> dict[str, Path]:
    manifest = json.loads((project / "lake-manifest.json").read_text())
    roots = {}
    for package in manifest["packages"]:
        root = (project / manifest["packagesDir"] / package["name"]).resolve()
        require(root.is_dir(), f"Missing package {root}; no downloads permitted")
        require(package["type"] == "git", "This baseline requires pinned git packages")
        require(
            git_output(root, "rev-parse", "HEAD") == package["rev"],
            f"Package revision differs from manifest: {root}; no updates permitted",
        )
        require(
            not git_output(root, "status", "--porcelain", "--untracked-files=no"),
            f"Tracked package sources changed: {root}; no package rebuilds permitted",
        )
        roots[package["name"]] = root
    return roots


def object_stamp(path: Path) -> dict[str, int]:
    stat = path.stat()
    return {"size": stat.st_size, "mtime_ns": stat.st_mtime_ns}


def build(project: Path, output: Path) -> None:
    """Build only project native objects after a no-build package freshness gate."""
    lake = installed_lake(project)
    packages = package_roots(project)
    require(
        not any(output.is_relative_to(root) for root in packages.values()),
        "Output must not be inside a shared package",
    )
    require(
        not output.exists() or not any(output.iterdir()),
        f"Refusing to overwrite build evidence in {output}; choose a fresh --output",
    )
    output.mkdir(parents=True, exist_ok=True)
    source_paths = [Path(*name.split(".")).with_suffix(".lean") for name in NATIVE_MODULES] + [
        Path("scripts/benchmark_conditional_queue.py"),
        Path("Shared/solver.py"),
        Path("lean-toolchain"),
        Path("lake-manifest.json"),
        Path("lakefile.toml"),
    ]
    sources = {str(path): digest(project / path) for path in source_paths}
    head = git_output(project, "rev-parse", "HEAD")
    command = ["nice", "-n", "10", str(lake)]
    with (output / "build.log").open("x") as log:
        # Mathlib imports the package modules used by this fixed fixture closure.
        # A stale dependency must fail here, before the project build can run.
        subprocess.run(
            [*command, "--no-cache", "--no-build", "build", "+Mathlib"],
            cwd=project,
            stdout=log,
            stderr=subprocess.STDOUT,
            check=True,
        )
        subprocess.run(
            [*command, "--no-cache", "build", MODULE],
            cwd=project,
            stdout=log,
            stderr=subprocess.STDOUT,
            check=True,
        )
        setup_path = (
            project / ".lake/build/ir/Sparse/ConditionalQueueScaleMain.setup.json"
        )
        setup = json.loads(setup_path.read_text())
        modules = dict(setup["importArts"])
        project_build = (project / ".lake/build").resolve()
        modules[MODULE] = [
            str(project_build / "lib/lean/Sparse/ConditionalQueueScaleMain.olean")
        ]
        package_builds = {(root / ".lake/build").resolve() for root in packages.values()}
        project_c = {}
        cached_objects = {}
        objects = []
        for name, artifacts in sorted(modules.items()):
            olean = (project / artifacts[0]).resolve()
            relative = Path(*name.split("."))
            root = olean.parents[len(relative.parts) + 1]
            c_file = root / "ir" / relative.with_suffix(".c")
            require(c_file.is_file(), f"Missing generated C for {name}: {c_file}")
            if root == project_build:
                project_c[name] = c_file
                target = output / (name + ".o")
            else:
                require(root in package_builds, f"Unexpected import build root: {root}")
                target = Path(str(c_file) + ".o.export")
                require(
                    target.is_file(),
                    f"Missing cached package native object: {target}; no downloads permitted",
                )
                cached_objects[str(target)] = object_stamp(target)
            objects.append(target)
        require(
            set(project_c) == set(NATIVE_MODULES),
            f"Native closure changed; expected exactly {len(NATIVE_MODULES)} modules. "
            f"Added: {sorted(set(project_c) - set(NATIVE_MODULES))}; "
            f"missing: {sorted(set(NATIVE_MODULES) - set(project_c))}",
        )
        generated_c = {
            str(path.relative_to(project)): digest(path) for path in project_c.values()
        }
        for name, c_file in sorted(project_c.items()):
            print("COMPILE", name, flush=True)
            subprocess.run(
                [
                    *command, "env", "leanc", "-O3", "-c", str(c_file),
                    "-o", str(output / (name + ".o")),
                ],
                cwd=project,
                stdout=log,
                stderr=subprocess.STDOUT,
                check=True,
            )
        (output / "objects.txt").write_text(
            "\n".join(map(str, objects)) + "\n", encoding="utf-8"
        )
        binary = output / "conditional-queue-scale"
        subprocess.run(
            [
                *command, "env", "leanc", "-O3", "-o", str(binary),
                *map(str, objects), "-lLean", "-lStd",
            ],
            cwd=project,
            stdout=log,
            stderr=subprocess.STDOUT,
            check=True,
        )
    baseline = {
        "version": 1,
        "git_head_before": head,
        "git_head_after": git_output(project, "rev-parse", "HEAD"),
        "sources": sources,
        "generated_c": generated_c,
        "setup_sha256": digest(setup_path),
        "package_objects": cached_objects,
        "binary_sha256": digest(binary),
        "lake": str(lake),
        "lake_version": subprocess.check_output(
            [str(lake), "--version"], text=True, cwd=project
        ).strip(),
        "native_modules": list(NATIVE_MODULES),
        "limits": "Incremental Lake source check; reused package objects are size/mtime "
        "checked, not content-hashed or source rebuilt. Toolchain/system libraries "
        "are not hermetically captured. No full Model or full-matrix claim.",
    }
    write_json(output / "baseline-sha256.json", baseline)
    verify_baseline(project, output)
    print(
        json.dumps(
            {
                "binary": str(binary),
                "project_modules": len(project_c),
                "package_objects": len(cached_objects),
                "log": str(output / "build.log"),
            }
        )
    )


def verify_baseline(project: Path, output: Path) -> dict:
    baseline = json.loads((output / "baseline-sha256.json").read_text())
    require(baseline.get("version") == 1, "Unsupported or legacy baseline manifest")
    require(baseline["native_modules"] == list(NATIVE_MODULES), "Native closure changed")
    for group in ("sources", "generated_c"):
        for name, expected in baseline[group].items():
            require(digest(project / name) == expected, f"Baseline input changed: {name}")
    require(
        digest(project / ".lake/build/ir/Sparse/ConditionalQueueScaleMain.setup.json")
        == baseline["setup_sha256"],
        "Fixture setup changed since build",
    )
    for name, expected in baseline["package_objects"].items():
        require(object_stamp(Path(name)) == expected, f"Cached object changed: {name}")
    require(
        digest(output / "conditional-queue-scale") == baseline["binary_sha256"],
        "Native runner changed since build",
    )
    return baseline


def expected_case(size: int, shape: str, keys_mode: str, guards: str, verdict: str) -> dict:
    """Replay a concrete SAT witness; use an alias-safe upper bound for UNSAT."""
    require(
        verdict != "alias" or (keys_mode == "symbolic" and guards == "alternating"),
        "alias requires symbolic keys and alternating guards",
    )
    cycle = shape != "send"
    key_count = 4 if shape == "cycle4" else (size - 1) // 2 if cycle else size - 1
    queue = []
    tracked = set()
    active_writes = 0
    active_keys = set()
    for index in range(size - 1):
        key = (index // 2 if cycle else index) % key_count
        tracked.add(key)
        if guards == "alternating" and index % 2:
            continue
        active_writes += 1
        active_keys.add(key)
        value = 0 if verdict == "alias" else key
        if cycle and index % 2:
            require(bool(queue) and queue[0] == value, "Replay pop disagrees with head")
            queue.pop(0)
        elif value not in queue:
            queue.append(value)
    bound = 1 if cycle and guards == "all" else len(active_keys)
    final = bound + 1 if verdict == "unsat" else 1 if verdict == "alias" else bound
    require(
        final > bound if verdict == "unsat" else len(queue) == final,
        "Replay witness or alias-safe bound disagrees with final demand",
    )
    return {
        "original_events": size,
        "static_writes": size - 1,
        "active_writes": active_writes,
        "inactive_writes": size - 1 - active_writes,
        "tracked_keys": len(tracked),
        "grid_rows": (size - 1) * len(tracked),
        "histogram_rows": (((size - 1) // 2 if cycle else 0) + 1) * len(tracked),
        "initial_length": 0,
        "final_length": final,
        "expected": "unsat" if verdict == "unsat" else "sat",
    }


def check_emission(case: dict, parameters: tuple, script: Path) -> None:
    stem = "-".join(map(str, parameters))
    size, shape, keys, guards, verdict = parameters
    native_shape = f"cycle{(size - 1) // 2}" if shape == "cycleDistinct" else shape
    native_name = "-".join(map(str, (size, native_shape, keys, guards, verdict)))
    require(case["case"] == native_name, f"Wrong fixture case: {case['case']}")
    for field, value in expected_case(*parameters).items():
        require(case[field] == value, f"{stem}: {field}: {case[field]} != {value}")
    text = script.read_bytes()
    require(text.isascii() and len(text) == case["bytes"], f"{stem}: invalid script bytes")
    require(digest(script) == case["script_sha256"], f"{stem}: script hash changed")
    for field in (
        "formula_ns", "commands_ns", "text_ns", "encoding_ns", "warm_encoding_ns",
    ):
        require(type(case[field]) is int and case[field] >= 0, f"{stem}: invalid {field}")
    require(
        case["encoding_ns"] == case["formula_ns"] + case["commands_ns"] + case["text_ns"],
        f"{stem}: phase timing sum disagrees",
    )


def run_case(project: Path, output: Path, args: argparse.Namespace) -> None:
    baseline = verify_baseline(project, output)
    cvc5 = None if args.emit_only else find_cvc5(args.cvc5).resolve()
    directory = output / str(args.events)
    directory.mkdir(parents=True, exist_ok=True)
    parameters = (args.events, args.shape, args.keys, args.guards, args.verdict)
    stem = "-".join(map(str, parameters))
    require(not any(directory.glob(f"{stem}*")), f"Refusing to overwrite case: {stem}")
    start = time.perf_counter_ns()
    with (directory / f"{stem}.generator.stderr").open("x") as error:
        completed = subprocess.run(
            [
                "nice", "-n", "10", str(output / "conditional-queue-scale"),
                *map(str, parameters),
            ],
            cwd=project,
            stdout=subprocess.PIPE,
            stderr=error,
            text=True,
            check=True,
        )
    process_ms = (time.perf_counter_ns() - start) / 1_000_000
    case = json.loads(completed.stdout)
    script = case.pop("script")
    require(script.isascii(), f"{stem}: native fixture emitted non-ASCII text")
    script_path = directory / f"{stem}.smt2"
    script_path.write_text(script, encoding="ascii")
    case.update(
        fixture_process_ms=process_ms,
        script_sha256=digest(script_path),
        runner_sha256=baseline["binary_sha256"],
        baseline_sha256=digest(output / "baseline-sha256.json"),
        emit_only=args.emit_only,
    )
    check_emission(case, parameters, script_path)
    if cvc5 is not None:
        case.update(
            solver=str(cvc5),
            solver_sha256=digest(cvc5),
            solver_version=subprocess.check_output([str(cvc5), "--version"], text=True),
            solver_runs_ms=[],
        )
    metadata = directory / f"{stem}.json"
    write_json(metadata, case)
    print(json.dumps({"phase": "emitted", **case}), flush=True)
    if cvc5 is None:
        return
    timings = []
    for repetition in range(3):
        result = run_solver(cvc5, script_path, directory, f"{stem}-{repetition}")
        require(
            result.status == case["expected"]
            and result.stdout.strip() == case["expected"]
            and not result.stderr,
            f"{stem}: unexpected solver output; see repetition {repetition} evidence",
        )
        timings.append(result.wall_time_ms)
        case["solver_runs_ms"] = timings
        write_json(metadata, case)
        print(
            json.dumps(
                {
                    "phase": "solver",
                    "case": stem,
                    "repetition": repetition,
                    "status": result.status,
                    "ms": result.wall_time_ms,
                }
            ),
            flush=True,
        )
    check_emission(case, parameters, script_path)
    verify_baseline(project, output)
    require(digest(cvc5) == case["solver_sha256"], "Solver changed during this case")
    case["solver_median_ms"] = statistics.median(timings)
    write_json(metadata, case)
    with (output / "results.jsonl").open("a", encoding="ascii") as summary:
        summary.write(json.dumps(case, sort_keys=True) + "\n")
    print(json.dumps({"phase": "complete", **case}), flush=True)


def matrix_cases():
    """Enumerate the audit domain, never execute a matrix implicitly."""
    for size in (40, 400):
        for shape in ("cycle4", "cycleDistinct", "send"):
            for keys in ("literal", "symbolic"):
                for guards in ("alternating", "all"):
                    for verdict in ("sat", "unsat"):
                        yield size, shape, keys, guards, verdict
            yield size, shape, "symbolic", "alternating", "alias"


def audit(project: Path, output: Path, require_complete: bool) -> None:
    baseline = verify_baseline(project, output)
    baseline_sha256 = digest(output / "baseline-sha256.json")
    rows = []
    missing = []
    complete = emitted_only = partial = 0
    for parameters in matrix_cases():
        stem = "-".join(map(str, parameters))
        metadata = output / str(parameters[0]) / f"{stem}.json"
        if not metadata.is_file():
            missing.append(stem)
            continue
        row = json.loads(metadata.read_text())
        check_emission(row, parameters, metadata.with_suffix(".smt2"))
        require(row["runner_sha256"] == baseline["binary_sha256"], f"{stem}: wrong runner")
        require(row["baseline_sha256"] == baseline_sha256, f"{stem}: wrong baseline")
        timings = row.get("solver_runs_ms", [])
        require(
            len(timings) <= 3 and all(math.isfinite(t) and t >= 0 for t in timings),
            f"{stem}: invalid solver timings",
        )
        unrecorded = False
        for repetition in range(3):
            stdout = metadata.parent / f"{stem}-{repetition}.stdout"
            stderr = metadata.parent / f"{stem}-{repetition}.stderr"
            if repetition < len(timings):
                require(
                    stdout.read_text().strip() == row["expected"],
                    f"Bad result: {stdout}",
                )
                require(not stderr.read_text(), f"Solver diagnostics: {stderr}")
            elif stdout.exists() or stderr.exists():
                unrecorded = True
        if "solver_median_ms" in row:
            require(
                len(timings) == 3
                and not row["emit_only"]
                and statistics.median(timings) == row["solver_median_ms"],
                f"{stem}: incomplete or incorrect solver median",
            )
            complete += 1
        elif row["emit_only"] and not timings and not unrecorded:
            emitted_only += 1
        else:
            partial += 1
        rows.append(row)
    summary = {
        "status": "complete" if complete == 54 else "incomplete",
        "expected_cases": 54,
        "native_emissions": len(rows),
        "three_process_solver_cases": complete,
        "emission_only_cases": emitted_only,
        "partial_solver_cases": partial,
        "missing_cases": missing,
        "limits": "Only the fixed empty-initial conditional queue fixture matrix; "
        "not full Model trace completion. Reused package objects are not source "
        "rebuilt or content-hashed. Stored solver evidence is not re-solved by audit.",
    }
    write_json(output / "index.json", {"summary": summary, "cases": rows})
    print(json.dumps(summary), flush=True)
    print("| Case | Bytes | Formula ms | Commands ms | Text ms | cvc5 median ms |")
    print("| --- | ---: | ---: | ---: | ---: | ---: |")
    for row in rows:
        if row["original_events"] == 400:
            median = (
                f'{row["solver_median_ms"]:.3f}'
                if "solver_median_ms" in row
                else "incomplete"
            )
            print(
                f'| {row["case"][4:]} | {row["bytes"]} | {row["formula_ns"] / 1e6:.3f} | '
                f'{row["commands_ns"] / 1e6:.3f} | {row["text_ns"] / 1e6:.3f} | {median} |'
            )
    require(
        not require_complete or complete == 54,
        f"Incomplete matrix: {complete}/54 cases have three successful solver runs",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--build", action="store_true")
    mode.add_argument("--audit", action="store_true")
    parser.add_argument(
        "--output",
        type=Path,
        default=PROJECT / ".lake/build/conditional-queue-benchmark",
        help="artifact directory; default: project .lake/build/conditional-queue-benchmark",
    )
    parser.add_argument(
        "--require-complete", action="store_true", help="require all 54 solver cases"
    )
    parser.add_argument("--emit-only", action="store_true", help="emit one case without cvc5")
    parser.add_argument("--events", type=int, choices=[40, 400], default=40)
    parser.add_argument(
        "--shape", choices=["cycle4", "cycleDistinct", "send"], default="cycle4"
    )
    parser.add_argument("--keys", choices=["literal", "symbolic"], default="literal")
    parser.add_argument("--guards", choices=["alternating", "all"], default="alternating")
    parser.add_argument("--verdict", choices=["sat", "unsat", "alias"], default="sat")
    parser.add_argument(
        "--cvc5", type=Path, help="existing solver executable; otherwise search PATH"
    )
    args = parser.parse_args()
    if args.require_complete and not args.audit:
        parser.error("--require-complete requires --audit")
    if args.emit_only and (args.build or args.audit):
        parser.error("--emit-only applies only to a case invocation")
    if args.verdict == "alias" and (
        args.keys != "symbolic" or args.guards != "alternating"
    ):
        parser.error("alias requires symbolic keys and alternating guards")
    output = args.output.expanduser().resolve()
    if args.build:
        build(PROJECT, output)
    elif args.audit:
        audit(PROJECT, output, args.require_complete)
    else:
        run_case(PROJECT, output, args)


if __name__ == "__main__":
    try:
        main()
    except (
        ValidationError,
        OSError,
        subprocess.CalledProcessError,
        json.JSONDecodeError,
    ) as error:
        sys.exit(f"error: {error}")
