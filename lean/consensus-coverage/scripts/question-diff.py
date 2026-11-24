# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Compare two shared Classes.table dumps and their print-defs.lean dumps.

Supply every name from column 2 of the corresponding table's 'class' rows in
DEFS. Use the same rendering (for example, DEFS_FORMAT=raw) for both dumps.
Predicate strings are compared verbatim, including generated reach names.
"""

import argparse
import gzip
import re
import zlib
from collections import Counter
from pathlib import Path

HYGIENE_SALT = re.compile(
    rb"(\._@\.ConsensusCoverage\.Classes\.)[0-9]+(\._hygCtx\._hyg\.)"
)


def read_classes(path):
    classes = {}
    splits = set()
    unrecorded = Counter()
    for line in path.read_text(encoding="utf-8").splitlines():
        row = line.split("\t")
        if row[0] == "class":
            _, name, level, *_ = row
            if name in classes:
                raise ValueError(f"{path}: duplicate class {name}")
            classes[name] = level
        elif row[0] == "branch":
            splits.add(tuple(row[i] for i in (1, 3, 4, 5, 8, 9)))
        elif row[0] == "unrecorded":
            unrecorded[row[9]] += 1
    return classes, splits, unrecorded


def read_predicates(path, classes):
    seen = set()
    name = None
    body = []
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rb") as stream:
        for line in stream:
            if line.startswith(b"== "):
                if name is not None:
                    yield name, b"".join(body)
                name = line[3:].rstrip(b"\n").decode("utf-8")
                if name not in classes or name in seen:
                    raise ValueError(
                        f"{path}: unexpected or duplicate predicate {name}"
                    )
                seen.add(name)
                body = []
            elif name is None:
                raise ValueError(f"{path}: expected a predicate header")
            else:
                body.append(line)
    if seen != classes.keys():
        raise ValueError(f"{path}: does not contain exactly the table's classes")
    if name is not None:
        yield name, b"".join(body)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--ignore-hygiene-salt",
        action="store_true",
        help="ignore only the module macro-hygiene salt in raw expression strings",
    )
    for name in (
        "before_table",
        "after_table",
        "before_predicates",
        "after_predicates",
    ):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    before, splits_before, unrecorded_before = read_classes(args.before_table)
    after, splits_after, unrecorded_after = read_classes(args.after_table)

    def normalize(body):
        if args.ignore_hygiene_salt:
            return HYGIENE_SALT.sub(rb"\g<1>0\2", body)
        return body

    # Keep losslessly compressed copies rather than holding the full baseline dump in memory.
    before_preds = {
        name: zlib.compress(normalize(body), level=1)
        for name, body in read_predicates(args.before_predicates, before)
        if name in after
    }
    changed = set()
    for name, body in read_predicates(args.after_predicates, after):
        value = before_preds.pop(name, None)
        if value is not None and zlib.decompress(value) != normalize(body):
            changed.add(name)
    before_counts, after_counts = Counter(before.values()), Counter(after.values())
    for level in ("step", "state"):
        print(f"{level} questions: {before_counts[level]} -> {after_counts[level]}")
    print(f"unrecorded: {dict(unrecorded_before)} -> {dict(unrecorded_after)}")
    changed_label = "CHANGED PREDICATE STRING"
    if args.ignore_hygiene_salt:
        changed_label += " (ignoring module hygiene salt)"
    for label, names in (
        ("NEW", after.keys() - before.keys()),
        ("REMOVED", before.keys() - after.keys()),
        (changed_label, changed),
    ):
        print(f"\n{label} ({len(names)})")
        for name in sorted(names):
            print(name)
    print(
        "\nADDED OR CHANGED SPLIT OCCURRENCE "
        "(root, path, declaration, split, counts, reason)"
    )
    for split in sorted(splits_after - splits_before):
        print("\t".join(split))


if __name__ == "__main__":
    main()
