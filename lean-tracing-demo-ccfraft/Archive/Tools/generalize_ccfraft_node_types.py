#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import argparse
import re
from pathlib import Path

REPLACEMENTS = (
    (
        "(initialState (TxId :=",
        "(initialState (Node := Node) (TxId :=",
    ),
    ("AppendEntriesRequest TxId", "AppendEntriesRequest Node TxId"),
    ("NodeState TxId", "NodeState Node TxId"),
    ("Message TxId", "Message Node TxId"),
    ("Entry TxId", "Entry Node TxId"),
    ("State TxId", "State Node TxId"),
    ("Action TxId", "Action Node TxId"),
    ("[Bootstrap]", "[Bootstrap Node]"),
)

NODE_ONLY_TYPES = (
    "AppendEntriesResponse",
    "RequestVoteRequest",
    "RequestVoteResponse",
    "Configuration",
)

PROOF_TXID_TYPES = (
    "ElectionRecord",
    "ElectionHistory",
    "ActivationRecord",
    "ActivationHistory",
    "ProcessedAckSnapshot",
    "ProcessedAckHistory",
    "CommitEvidence",
    "NodeCommitEvidence",
    "RequestCommitEvidence",
)

PROOF_NODE_TYPES = (
    "VoteHistory",
    "TermOwners",
    "ActivationKey",
)

DEFAULT_FILES = (
    "CCFRaft/Model.lean",
    "CCFRaft/HandlerProofs.lean",
    "CCFRaft/Properties.lean",
    "CCFRaft/ReconfigurationPreservation.lean",
    "CCFRaft/Proofs.lean",
    "CCFRaft/ConfigurationCoverage.lean",
    "CCFRaft/VotedForFrame.lean",
    "CCFRaft/UpdateTermAuthority.lean",
)


def transformed(source: str) -> str:
    for old, new in REPLACEMENTS:
        source = source.replace(old, new)
    for name in NODE_ONLY_TYPES:
        source = source.replace(
            f"List {name} Node",
            f"List ({name} Node)",
        )
        source = source.replace(
            f"List {name}",
            f"List ({name} Node)",
        )
        source = re.sub(
            rf"(?P<prefix>: |\u00d7 ){name}\b(?! Node)",
            rf"\g<prefix>{name} Node",
            source,
        )
        source = source.replace(
            f"{name} ->",
            f"{name} Node ->",
        )
    for name in PROOF_TXID_TYPES:
        source = source.replace(
            f"{name} (TxId : Type)",
            f"{name} (Node TxId : Type)",
        )
        source = source.replace(
            f"{name} TxId",
            f"{name} Node TxId",
        )
    for name in PROOF_NODE_TYPES:
        while f"{name} Node Node" in source:
            source = source.replace(
                f"{name} Node Node",
                f"{name} Node",
            )
        source = source.replace(
            f"{name} :=",
            f"{name} (Node : Type) :=",
        )
        source = source.replace(
            f"{name} where",
            f"{name} (Node : Type) where",
        )
        source = re.sub(
            rf"\b{name}\b(?! Node\b)(?!\s*\()(?!\.)",
            f"{name} Node",
            source,
        )
    return source


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Add the abstract Node parameter to canonical CCFRaft types."
    )
    parser.add_argument("--check", action="store_true")
    parser.add_argument("files", nargs="*", default=DEFAULT_FILES)
    args = parser.parse_args()

    root = Path(__file__).resolve().parent
    changed = []
    for relative in args.files:
        path = root / relative
        source = path.read_text()
        updated = transformed(source)
        if updated != source:
            changed.append(relative)
            if not args.check:
                path.write_text(updated)

    if changed:
        print("\n".join(changed))
        return 1 if args.check else 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
