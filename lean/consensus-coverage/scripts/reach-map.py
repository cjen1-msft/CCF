#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
"""Suggest structural paths for legacy reach references using two reach-graph dumps."""

import argparse
import collections
import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Node:
    type_hash: str
    body_hash: str
    digest: str
    children: list[str]


def load_graph(path: Path) -> dict[str, Node]:
    graph = {}
    for line in path.read_text().splitlines():
        name, typ, body, digest, edges = line.split("\t")
        graph[name] = Node(typ, body, digest, edges.split(",") if edges else [])
    return graph


def named_paths(graph: dict[str, Node]) -> dict[str, tuple[str, tuple[int, ...]]]:
    # Multi-source BFS: prefer a direct use and use names to break ties.
    paths = {}
    queue = collections.deque(
        (n, n, ()) for n in sorted(graph) if ".reach_" not in n
    )
    while queue:
        node, root, indices = queue.popleft()
        if node in paths:
            continue
        paths[node] = root, indices
        ns = node.rsplit(".", 1)[0]
        for i, child in enumerate(graph[node].children):
            queue.append((f"{ns}.{child}", root, (*indices, i)))
    return paths


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("old", type=Path)
    parser.add_argument("new", type=Path)
    parser.add_argument("sources", type=Path, nargs="+")
    args = parser.parse_args()
    old, new = load_graph(args.old), load_graph(args.new)
    paths = named_paths(new)
    exact = collections.defaultdict(list)
    shallow = collections.defaultdict(list)
    for n, node in new.items():
        ns = n.rsplit(".", 1)[0]
        if n in paths and ".reach_" in n:
            exact[ns, node.digest].append(n)
            shallow[ns, node.type_hash, node.body_hash].append(n)

    used = set()
    for source in args.sources:
        for ns, ref in re.findall(
            r"\b(?:(SolvedWitnesses|PinnedClasses)\.)?(reach_\d+)\b", source.read_text()
        ):
            used.add(f"ConsensusCoverage.{ns or 'SolvedWitnesses'}.{ref}")
    for ref in sorted(used):
        node = old[ref]
        ns = ref.rsplit(".", 1)[0]
        matches = exact.get((ns, node.digest))
        kind = "transitive"
        if not matches:
            matches = shallow.get((ns, node.type_hash, node.body_hash), [])
            kind = "local"
        if not matches:
            print(f"{ref}\tmissing")
        for match in sorted(matches):
            root, indices = paths[match]
            path = f"{root}[{','.join(map(str, indices))}]"
            print(f"{ref}\t{kind}\t{match}\t{path}")


if __name__ == "__main__":
    main()
