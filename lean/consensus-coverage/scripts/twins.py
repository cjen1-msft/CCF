#!/usr/bin/env python3
"""Copy split markings between twin theorems of Direct.lean and SafetyInvariant.lean.

Usage (from the worktree root):
  python3 lean/consensus-coverage/scripts/twins.py          # report only
  python3 lean/consensus-coverage/scripts/twins.py --apply  # copy markings

Twins are top-level theorems with the same name in both files whose text was
identical at the unmarked commit ORIGIN. If exactly one twin has changed since
ORIGIN, --apply replaces the other twin's text with the changed one. A theorem's
text runs from its `theorem` line to the line before the next line that starts
in column 0 (blank lines and comments directly before that line excluded).
"""
import re
import subprocess
import sys
from pathlib import Path

ORIGIN = "66ddc19a8"
DIR = Path("lean/consensus/Consensus/Proofs")
FILES = ["Direct.lean", "SafetyInvariant.lean"]
HEAD = re.compile(r"^(?:private )?theorem ([^\s(:{\[]+)")


def blocks(text):
    lines = text.split("\n")
    starts = [(i, m.group(1)) for i, l in enumerate(lines) if (m := HEAD.match(l))]
    out = {}
    for i, name in starts:
        j = i + 1
        while j < len(lines) and not (lines[j] and not lines[j][0].isspace()):
            j += 1
        while j > i + 1 and (not lines[j - 1].strip() or lines[j - 1].startswith("--")):
            j -= 1
        out.setdefault(name, []).append((i, j, "\n".join(lines[i:j])))
    return lines, out


def main():
    apply = "--apply" in sys.argv[1:]
    base = {f: blocks(subprocess.check_output(
        ["git", "show", f"{ORIGIN}:{DIR / f}"], text=True))[1] for f in FILES}
    cur = {f: blocks((DIR / f).read_text()) for f in FILES}
    a, b = FILES
    edits = {f: [] for f in FILES}
    counts = {"identical twins": 0, "copied": 0, "both changed": 0, "unchanged": 0}
    for name in sorted(set(base[a]) & set(base[b])):
        if len(base[a][name]) != 1 or len(base[b][name]) != 1:
            continue
        if base[a][name][0][2] != base[b][name][0][2]:
            continue
        if name not in cur[a][1] or name not in cur[b][1]:
            continue
        counts["identical twins"] += 1
        old = base[a][name][0][2]
        ta, tb = cur[a][1][name][0], cur[b][1][name][0]
        if ta[2] == tb[2]:
            counts["unchanged" if ta[2] == old else "copied"] += 1
            continue
        if ta[2] != old and tb[2] != old:
            counts["both changed"] += 1
            print(f"both changed, left as is: {name}")
            continue
        src, (dst, t) = (ta, (b, tb)) if ta[2] != old else (tb, (a, ta))
        print(f"{'copy' if apply else 'would copy'} {name} -> {dst}")
        edits[dst].append((t[0], t[1], src[2]))
        counts["copied"] += 1
    if apply:
        for f in FILES:
            lines = cur[f][0]
            for i, j, text in sorted(edits[f], reverse=True):
                lines[i:j] = text.split("\n")
            (DIR / f).write_text("\n".join(lines))
    print(", ".join(f"{k}: {v}" for k, v in counts.items()))


if __name__ == "__main__":
    main()
