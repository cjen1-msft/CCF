#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
"""Check the split_rel marking of the consensus proof.

Usage, from the root of a checkout:

    python3 lean/consensus-coverage/scripts/check.py chunk K
    python3 lean/consensus-coverage/scripts/check.py range FILE FIRST LAST
    python3 lean/consensus-coverage/scripts/check.py final
    python3 lean/consensus-coverage/scripts/check.py baseline   (setup only)

`chunk K` checks chunk K of `lean/consensus-coverage/marking/chunks.tsv`. `range` checks the
theorems of FILE (for example `SafetyInvariant` or `Direct`) from declaration FIRST to
declaration LAST (full names, as in chunks.tsv). Both:

1. build `Consensus` with the project's options (out of tree);
2. compare every `Consensus.*` declaration's elaborated type (and, for definitions, value)
   with `marking/baseline-decls.tsv`: nothing changed, added or removed;
3. check the text: no forbidden words in added lines, and (for a chunk) no line changed
   outside the chunk;
4. list the case splits still unmarked in the chunk, per theorem, and count the marked ones.

`final` does 1 to 3 for the whole proof, compares the axioms of the four public theorems with
`marking/baseline-axioms.tsv`, and requires zero unmarked splits in their closure except inside
theorems that have no source text: auxiliary `_proof_N` theorems made by automation and
lemmas Lean generates (listed).

The last line is `RESULT: PASS ...` or `RESULT: FAIL ...`; the exit code is 0 or 1.
"""

import os
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
LEAN = ROOT / "lean"
MARKING = LEAN / "consensus-coverage" / "marking"
CHECK_LEAN = LEAN / "consensus-coverage" / "scripts" / "check.lean"
PROOFS = "lean/consensus/Consensus/Proofs"
# the unmarked proof: the text checks of `final` compare with it
ORIGIN = "66ddc19a8"
FORBIDDEN = [
    r"\bsorry\b",
    r"\badmit\b",
    r"\bnative_decide\b",
    r"\bset_option\b",
    r"\baxiom\b",
    r"\bunsafe\b",
    r"implemented_by",
    r"#exit",
    r"^\s*(public\s+)?(meta\s+)?import\b(?!\s+Relevance\.Split\s*$)",
    r"\bopaque\b",
]


def threads() -> int:
    return max(1, ((os.cpu_count() or 2) + 1) // 2)


def run(cmd, env=None, cwd=ROOT):
    return subprocess.run(
        cmd, cwd=cwd, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    )


def workspace() -> Path:
    out = run(
        [sys.executable, str(LEAN / "relevance/scripts/workspace.py"), "consensus", "consensus-coverage"]
    )
    if out.returncode != 0:
        sys.exit(out.stdout)
    return Path(out.stdout.strip().splitlines()[-1])


def short(text: str) -> str:
    text = text.replace("\u271d", "")
    for prefix in ["Consensus.Proofs.Safety.", "Consensus.Proofs.Direct.", "Consensus.Proofs.",
                   "Consensus.Model.Node.", "Consensus.Model.", "Consensus."]:
        text = text.replace(prefix, "")
    return re.sub(r"\s+", " ", text)


def read_tsv(path: Path):
    lines = path.read_text().splitlines()
    head = lines[0].split("\t")
    return [dict(zip(head, line.split("\t"))) for line in lines[1:] if line]


def build(ws: Path) -> list[str]:
    env = dict(os.environ, LEAN_NUM_THREADS=str(threads()))
    for target in [["-d", str(ws / "consensus"), "build", "Consensus"],
                   ["-d", str(ws / "relevance"), "build", "Relevance"]]:
        out = run(["nice", "lake", *target], env=env)
        if out.returncode != 0:
            errors = [l for l in out.stdout.splitlines() if "error" in l.lower()]
            return errors[:40] or out.stdout.splitlines()[-40:]
    return []


def facts(ws: Path, mode: str, out: Path, module="", first="", last="") -> str:
    out.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, CHECK_OUT=str(out), CHECK_MODE=mode, CHECK_MODULE=module,
               CHECK_FROM=first, CHECK_TO=last, LEAN_NUM_THREADS=str(threads()))
    res = run(["lake", "-d", str(ws / "consensus-coverage"), "env", "lean", str(CHECK_LEAN)], env=env)
    return "" if res.returncode == 0 else res.stdout[-3000:]


def compare_decls(now: Path) -> list[str]:
    # private names repeat across files: a declaration is its module and name
    base = {(r["module"], r["name"]): r for r in read_tsv(MARKING / "baseline-decls.tsv")}
    cur = {(r["module"], r["name"]): r for r in read_tsv(now)}
    problems = []
    for name in sorted(base.keys() - cur.keys()):
        problems.append(f"removed declaration: {name[1]} ({name[0]})")
    for name in sorted(cur.keys() - base.keys()):
        problems.append(f"added declaration: {name[1]} ({name[0]}, line {cur[name]['first']})")
    for name in sorted(base.keys() & cur.keys()):
        b, c = base[name], cur[name]
        if (b["kind"], b["module"], b["fingerprint"]) != (c["kind"], c["module"], c["fingerprint"]):
            what = "statement" if c["kind"] == "theorem" else "statement or definition"
            problems.append(f"changed {what}: {name[1]} ({name[0]}, line {c['first']})")
    return problems


def added_lines(base: str, paths: list[str]):
    diff = run(["git", "diff", "-U0", base, "--", *paths]).stdout
    file, hunks, added = None, [], []
    for line in diff.splitlines():
        if line.startswith("+++ "):
            file = line[6:] if line.startswith("+++ b/") else None
        elif line.startswith("@@") and file:
            m = re.match(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", line)
            start, count = int(m.group(1)), int(m.group(2) or "1")
            hunks.append((file, start, start + max(count, 1) - 1))
        elif line.startswith("+") and not line.startswith("+++") and file:
            added.append((file, line[1:]))
    return hunks, added


def text_problems(base: str, chunk_file=None, lo=0, hi=0) -> list[str]:
    hunks, added = added_lines(base, ["lean/consensus"])
    problems = []
    for file, text in added:
        for pat in FORBIDDEN:
            if re.search(pat, text):
                problems.append(f"forbidden in added line of {file}: {text.strip()}")
    if chunk_file:
        for file, start, end in hunks:
            if file != chunk_file or start < lo or end > hi:
                problems.append(
                    f"changed lines outside the chunk: {file} lines {start}-{end} "
                    f"(chunk: {chunk_file} lines {lo}-{hi} at the start commit)")
    return problems


def report_walk(out: Path, aux_ok: bool):
    selected = read_tsv(out / "selected.tsv")
    rows = read_tsv(out / "walk.tsv")
    unmarked = defaultdict(list)
    splits, branches = defaultdict(int), defaultdict(int)
    for r in rows:
        key = (r["module"], r["decl"])
        if r["row"] == "unmarked":
            unmarked[key].append(r)
        elif r["row"] == "split":
            splits[key] += 1
        elif r["row"] == "branch":
            branches[key] += 1
    order = sorted(selected, key=lambda r: (r["module"], int(r["first"] or 0)))
    line = {(r["module"], r["name"]): r["first"] for r in selected}
    # theorems with no source text: made by automation (`omega`, ...) or generated by Lean
    auto = [d for d in unmarked if line.get(d, "0") == "0"]
    left = sum(len(v) for d, v in unmarked.items() if not (aux_ok and d in auto))
    print(f"\n== Splits ({len(order)} theorems)")
    print(f"marked: {sum(splits.values())} splits, {sum(branches.values())} cases; "
          f"unmarked: {sum(len(v) for v in unmarked.values())} "
          f"({sum(len(unmarked[d]) for d in auto)} inside automation or generated code)")
    for r in order:
        d = (r["module"], r["name"])
        n = len(unmarked.get(d, []))
        if n == 0 and not splits[d]:
            continue
        status = "done" if n == 0 else f"{n} unmarked"
        where = r["module"].split(".")[-1]
        print(f"- {short(r['name'])} ({where} line {r['first']}): {splits[d]} marked, {status}")
        for u in unmarked.get(d, []):
            print(f"    unmarked {short(u['name'])} ({u['tag']} cases, {u['flag']}): "
                  f"{short(u['text'])[:220]}")
    return left, auto


def lean_file(name: str) -> tuple[str, str]:
    stem = name.removesuffix(".lean").split("/")[-1].split(".")[-1]
    return f"{PROOFS}/{stem}.lean", f"Consensus.Proofs.{stem}"


def main() -> None:
    args = sys.argv[1:]
    if not args:
        sys.exit(__doc__)
    mode = args[0]
    ws = workspace()
    out = ws / "check" / mode
    failures = []
    print(f"== Build (workspace {ws})")
    errors = build(ws)
    if errors:
        print("\n".join(errors))
        print("RESULT: FAIL (the build failed; fix the errors above, or restore the theorem)")
        sys.exit(1)
    print("ok")
    if mode == "baseline":
        err = facts(ws, "final", out)
        if err:
            sys.exit(err)
        (MARKING / "baseline-decls.tsv").write_text((out / "decls.tsv").read_text())
        (MARKING / "baseline-axioms.tsv").write_text((out / "axioms.tsv").read_text())
        print("RESULT: PASS (baseline written)")
        return
    chunk_file, lo, hi = None, 0, 0
    if mode in ("chunk", "range"):
        if mode == "chunk":
            chunks = {r["chunk"]: r for r in read_tsv(MARKING / "chunks.tsv")}
            c = chunks.get(args[1])
            if c is None:
                sys.exit(f"no chunk {args[1]} in marking/chunks.tsv")
            file, first, last = c["file"], c["first"], c["last"]
            lo, hi = int(c["start_line"]), int(c["end_line"])
            chunk_file = lean_file(file)[0]
        else:
            file, first, last = args[1], args[2], args[3]
        module = lean_file(file)[1]
        err = facts(ws, "range", out, module, first, last)
        base = run(["git", "merge-base", "HEAD", "consensus-proof-coverage"]).stdout.strip()
    else:
        err = facts(ws, "final", out)
        base = ORIGIN
    if err:
        print(err)
        print("RESULT: FAIL (the checker could not read the proof; see above)")
        sys.exit(1)
    print("\n== Statements")
    problems = compare_decls(out / "decls.tsv")
    print("\n".join(problems) or "ok: every declaration unchanged")
    failures += problems
    print("\n== Text")
    problems = text_problems(base, chunk_file, lo, hi)
    print("\n".join(problems) or "ok")
    failures += problems
    if mode == "final":
        print("\n== Axioms")
        base_ax = {r["theorem"]: r["axioms"] for r in read_tsv(MARKING / "baseline-axioms.tsv")}
        for r in read_tsv(out / "axioms.tsv"):
            ok = base_ax.get(r["theorem"]) == r["axioms"]
            print(f"{'ok' if ok else 'CHANGED'}: {r['theorem']}: {r['axioms']}")
            if not ok:
                failures.append(f"axioms changed: {r['theorem']}")
    left, auto = report_walk(out, aux_ok=True)
    if auto:
        print("left inside automation (list them in the hand-back note): "
              + ", ".join(short(d[1]) for d in auto))
    if mode == "final" and left:
        failures.append(f"{left} unmarked splits")
    if failures:
        more = f" and {len(failures) - 3} more; see above" if len(failures) > 3 else ""
        print(f"RESULT: FAIL ({'; '.join(failures[:3])}{more})")
        sys.exit(1)
    if mode == "final" or left == 0:
        print("RESULT: PASS (complete: no unmarked splits left)")
    else:
        print(f"RESULT: PASS (safe to commit; {left} unmarked splits left)")


if __name__ == "__main__":
    main()
