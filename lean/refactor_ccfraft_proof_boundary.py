#!/usr/bin/env python3

import argparse
import re
import subprocess
from pathlib import Path


REFERENCE_COMMIT = "6521df226"
ROOT = Path(__file__).resolve().parent
PROPERTIES = ROOT / "CCFRaft" / "Properties.lean"
PROOFS = ROOT / "CCFRaft" / "Proofs.lean"
PRESERVATION = ROOT / "CCFRaft" / "FixedMembershipPreservation.lean"

DELTA_START = "/-- Monotone runtime facts shared by preservation deltas. -/"
DELTA_END = "/-- Core public safety mirrors committed-log, signature, and election safety. -/"
SEND_START = "/-- The exact runtime and ghost delta of one AppendEntries send. -/"
SEND_END = "/-- Sending AppendEntries updates one cursor and enqueues one snapshot. -/"
API_MARKER = "/-! ## Component invariant API -/"
OLD_INVARIANT_START = "/--\nThe arbitrary-term invariant stores only primitive safety evidence."
COMPONENT_START = "/-- Runtime-local bounds and role obligations. -/"
CONVERSION_START = "/-- Repackage the fixed-witness facts into named causal components. -/"
COMPONENT_SYSTEM_START = "/-- Existential packaging of the named component invariant. -/"
EXISTENTIAL_EQ_START = "/-- The positional and named existential invariants denote the same states. -/"
SYSTEM_START = "/-- The canonical inductive invariant uses named ghost state and components. -/"
FIXED_IFF_START = "/-- Convert between the fixed-membership proof package and the canonical invariant. -/"
GENERIC_PRESERVATION_START = (
    "/-- Every enabled arbitrary-term action preserves the supporting invariant. -/"
)


def git_file(path: str) -> str:
    return subprocess.run(
        ["git", "show", f"{REFERENCE_COMMIT}:{path}"],
        cwd=ROOT,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    ).stdout


def section(text: str, start: str, end: str) -> str:
    start_index = text.index(start)
    end_index = text.index(end, start_index)
    return text[start_index:end_index]


def replace_section(text: str, start: str, end: str, replacement: str) -> str:
    start_index = text.index(start)
    end_index = text.index(end, start_index)
    return text[:start_index] + replacement + text[end_index:]


def fixed_membership_names(text: str) -> str:
    text = text.replace("Legacy", "FixedMembership").replace(
        "legacy", "fixedMembership"
    )
    return (
        text.replace("fixed fixedMembership", "fixed fixed-membership")
        .replace("fixed fixed-membership facts", "fixed-witness facts")
        .replace("fixedMembership invariant", "fixed-membership invariant")
        .replace("fixedMembership proof package", "fixed-membership proof package")
        .replace(
            "fixedMembership preservation theorem",
            "fixed-membership preservation theorem",
        )
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Make the component invariant canonical and split its base proof."
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="write the transformed Lean sources",
    )
    args = parser.parse_args()

    current_properties = PROPERTIES.read_text()
    proof_source = PRESERVATION if PRESERVATION.exists() else PROOFS
    current_proofs = proof_source.read_text()

    delta = section(current_properties, DELTA_START, DELTA_END)
    send_delta = section(current_proofs, SEND_START, SEND_END)

    properties = git_file("lean/CCFRaft/Properties.lean")
    properties = replace_section(properties, DELTA_START, DELTA_END, delta)
    properties = fixed_membership_names(properties)

    old_start = properties.index(OLD_INVARIANT_START)
    component_start = properties.index(COMPONENT_START, old_start)
    conversion_start = properties.index(CONVERSION_START, component_start)
    component_system_start = properties.index(
        COMPONENT_SYSTEM_START, conversion_start
    )
    existential_eq_start = properties.index(
        EXISTENTIAL_EQ_START, component_system_start
    )
    system_start = properties.index(SYSTEM_START, existential_eq_start)
    fixed_iff_start = properties.index(FIXED_IFF_START, system_start)
    delta_start = properties.index(DELTA_START, fixed_iff_start)

    fixed_invariant = (
        properties[old_start:component_start]
        + properties[conversion_start:component_system_start]
        + properties[existential_eq_start:system_start]
        + properties[fixed_iff_start:delta_start]
    )
    properties = (
        properties[:old_start]
        + properties[component_start:conversion_start]
        + properties[component_system_start:existential_eq_start]
        + properties[system_start:fixed_iff_start]
        + properties[delta_start:]
    )

    proofs = git_file("lean/CCFRaft/Proofs.lean")
    proofs = replace_section(proofs, SEND_START, SEND_END, send_delta)
    proofs = fixed_membership_names(proofs)

    prefix, suffix = proofs.split(API_MARKER, maxsplit=1)
    prefix = prefix[: prefix.index(GENERIC_PRESERVATION_START)]
    insertion = prefix.index(
        "variable [DecidableEq TxId]"
    ) + len("variable [DecidableEq TxId]")
    preservation = (
        prefix[:insertion]
        + "\n\n"
        + fixed_invariant.rstrip()
        + "\n\n"
        + prefix[insertion:].lstrip()
        + "\nend CCFRaft\n"
    )
    preservation = re.sub(
        r"\bInvariantFacts\b", "PositionalInvariantFacts", preservation
    )
    preservation = preservation.replace(
        "The fixed-membership invariant with every existential witness fixed by one ghost value.\n"
        "This view exists only to prove that componentization preserves the predicate.",
        "This view fixes every positional witness with one ghost value. It exists\n"
        "only to prove that componentization preserves the predicate.",
    )
    public_proofs = """-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.FixedMembershipPreservation

set_option autoImplicit false

/-!
# CCFRaft component invariant API

The fixed-membership preservation proof is isolated behind the checked
equivalence between its positional witnesses and the named component
invariant. New invariant components preserve themselves alongside this base.
-/

namespace CCFRaft

variable {TxId : Type}
variable [DecidableEq TxId]

""" + API_MARKER + suffix

    outputs = {
        PROPERTIES: properties,
        PRESERVATION: preservation,
        PROOFS: public_proofs,
    }

    changed = [
        path
        for path, content in outputs.items()
        if not path.exists() or path.read_text() != content
    ]
    if not args.apply:
        for path in changed:
            print(path.relative_to(ROOT))
        raise SystemExit(1 if changed else 0)

    for path, content in outputs.items():
        path.write_text(content)


if __name__ == "__main__":
    main()
