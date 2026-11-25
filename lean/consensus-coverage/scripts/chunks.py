#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
"""Partition the unmarked case splits of the consensus proof into chunks for workers.

Usage, from the root of a checkout, after `check.py final` has run at the current commit:

    python3 lean/consensus-coverage/scripts/chunks.py [TARGET]

Reads `check/final/{selected,walk}.tsv` of this checkout's workspace and writes
`lean/consensus-coverage/marking/chunks.tsv` (read by `check.py chunk K`) and
`lean/consensus-coverage/marking/chunks.md` (the theorem list of each chunk).

A chunk is a contiguous line range of one file holding about TARGET (default 60) unmarked
splits as compiled. Theorems with no source text (automation, generated) are skipped, and so
are Direct.lean theorems that were identical to a SafetyInvariant.lean theorem of the same
name in the unmarked proof: `twins.py --apply` copies their marking after the merge. Chunks
holding the theorems where the coverage classes are (`Ctx.*`, the `summary` lemmas, the
state-role theorems) are numbered first.
"""

import subprocess
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check  # noqa: E402
import twins  # noqa: E402

PRIORITY = ("Ctx.", "summary", "election_safety", "committed_logs", "primary_eq_of_reachable",
            "inv_of_reachable", "leader_led")
ALONE = 40
GUIDE = "/root/.cache/paxos-bisim/research/proof-relevance/ccf/marking-guide.md"
WORKER = """You are a marking worker for a Lean 4 proof. You work alone and cannot ask questions.
First read this guide in full, then follow it literally: {guide}

Your chunk: `{k}`. File: `lean/consensus/Consensus/Proofs/{stem}.lean`, from theorem `{first}`
(line {lo}) to theorem `{last}` (ends line {hi}); line numbers at the start commit. Theorems
with unmarked splits (number of splits as compiled):
""".replace("{guide}", GUIDE)
AFTER = """
Set up once (creates your worktree and branch; the checker makes your own build directory
`/root/.cache/ccf-consensus-coverage/ws-<hash>/` from the worktree path on its first run):

    git -C /workspaces/ccf-consensus-coverage worktree add -b consensus-mark-{k} /workspaces/ccf-mark-{k} consensus-proof-coverage

Edit files only in `/workspaces/ccf-mark-{k}`. Run every command from there.
Check (after every one to three splits; it builds the proof first):

    cd /workspaces/ccf-mark-{k} && python3 lean/consensus-coverage/scripts/check.py chunk {k}

Commit (only after a `RESULT: PASS`):

    cd /workspaces/ccf-mark-{k} && git commit -qam "mark <theorem name>"

Never push. Never touch another worktree or `/workspaces/CCF`. Do not write files to /tmp.
Do not run `lake update` or `lake clean`. When finished, reply with the hand-back note of
section 10 of the guide; in "guide problems", quote the guide sentence that was unclear or
wrong and say what happened.
"""


def identical_twins() -> set[str]:
    base = {f: twins.blocks(subprocess.check_output(
        ["git", "show", f"{twins.ORIGIN}:{twins.DIR / f}"], text=True, cwd=check.ROOT))[1]
        for f in twins.FILES}
    a, b = twins.FILES
    return {n for n in set(base[a]) & set(base[b])
            if len(base[a][n]) == 1 and len(base[b][n]) == 1
            and base[a][n][0][2] == base[b][n][0][2]}


def main() -> None:
    target = int(sys.argv[1]) if len(sys.argv) > 1 else 60
    out = check.workspace() / "check" / "final"
    selected = check.read_tsv(out / "selected.tsv")
    unmarked = defaultdict(int)
    for r in check.read_tsv(out / "walk.tsv"):
        if r["row"] == "unmarked":
            unmarked[(r["module"], r["decl"])] += 1
    twin_names = identical_twins()
    files = defaultdict(list)
    skipped = []
    for r in selected:
        key = (r["module"], r["name"])
        n = unmarked.get(key, 0)
        if n == 0 or r["first"] in ("", "0"):
            continue
        stem = r["module"].split(".")[-1]
        if stem == "Direct" and any(r["name"].endswith("." + t) for t in twin_names):
            skipped.append((r["name"], n))
            continue
        files[stem].append((int(r["first"]), int(r["last"]), r["name"], n))
    chunks = []
    for stem, rows in files.items():
        rows.sort()
        groups, cur = [], []
        total = sum(r[3] for r in rows)
        count = max(1, round(total / target))
        size = total / count
        acc = 0
        for row in rows:
            n = row[3]
            alone = n >= ALONE
            if cur and (alone or abs(acc + n - size) > abs(acc - size) and acc >= size / 2):
                groups.append(cur)
                cur, acc = [], 0
            cur.append(row)
            acc += n
            if alone:
                groups.append(cur)
                cur, acc = [], 0
        if cur:
            if groups and sum(r[3] for r in cur) < size / 3 and groups[-1][-1][3] < ALONE:
                groups[-1] += cur
            else:
                groups.append(cur)
        for g in groups:
            prio = any(p in row[2] for row in g for p in PRIORITY)
            chunks.append((not prio, stem, g))
    chunks.sort(key=lambda c: (c[0], c[1] != "SafetyInvariant", c[2][0][0]))
    tsv = ["chunk\tfile\tfirst\tlast\tstart_line\tend_line\tsplits\ttheorems\tnotes"]
    md = ["# Chunks", "", f"Made by `chunks.py {target}` at commit "
          + check.run(["git", "rev-parse", "--short", "HEAD"]).stdout.strip() + ".", ""]
    for k, (low, stem, g) in enumerate(chunks, 1):
        splits = sum(r[3] for r in g)
        notes = [] if low else ["classes"]
        if any(r[3] >= ALONE for r in g):
            notes.append("large theorem")
        tsv.append("\t".join(map(str, [k, stem, g[0][2], g[-1][2], g[0][0], g[-1][1], splits,
                                       len(g), ",".join(notes) or "-"])))
        md += [f"## Chunk {k}: {stem}.lean lines {g[0][0]}-{g[-1][1]}, {len(g)} theorems, "
               f"{splits} splits" + (f" ({', '.join(notes)})" if notes else ""), ""]
        md += WORKER.format(k=k, stem=stem, first=check.short(g[0][2]), last=check.short(g[-1][2]),
                            lo=g[0][0], hi=g[-1][1]).split("\n")
        md += [f"- `{check.short(r[2])}` (line {r[0]}): {r[3]}" for r in g] + [""]
        md += AFTER.format(k=k).split("\n")
    md += ["## Not in any chunk: Direct.lean twins (copied by `twins.py --apply`)", ""]
    md += [f"- `{check.short(n)}`: {c}" for n, c in sorted(skipped)] + [""]
    (check.MARKING / "chunks.tsv").write_text("\n".join(tsv) + "\n")
    (check.MARKING / "chunks.md").write_text("\n".join(md))
    print("\n".join(tsv))
    print(f"skipped twins: {len(skipped)} theorems, {sum(c for _, c in skipped)} splits")


if __name__ == "__main__":
    main()
