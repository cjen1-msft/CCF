#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

from argparse import ArgumentParser
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parent
PROPERTIES = ROOT / "CCFRaft" / "Properties.lean"
PRESERVATION = ROOT / "CCFRaft" / "ReconfigurationPreservation.lean"
INVARIANT_DOC = ROOT / "CCFRaft" / "INVARIANT.md"
OBSOLETE_FILES = (
    ROOT / "CCFRaft" / "FixedMembershipPreservation.lean",
    ROOT / "refactor_ccfraft_proof_boundary.py",
    ROOT / "check_ccfraft_signature_refactor.sh",
)
REMOVALS = (
    (
        "/-- Runtime-local bounds and role obligations. -/\n"
        "structure LocalWF",
        "def LeadersHaveElectionWitness",
    ),
    (
        "/-- Monotone runtime facts shared by preservation deltas. -/\n"
        "structure CommonProgress",
        "/-- Core public safety mirrors committed-log, signature, and "
        "election safety. -/",
    ),
)
FORBIDDEN = (
    "structure GhostState",
    "structure LocalWF",
    "structure ComponentInvariantFacts",
    "def ComponentSystemInductiveInvariant",
    "structure CommonProgress",
    "structure AppendEntriesSendGhostDelta",
    "structure AppendEntriesSendDelta",
    "def CommitEvidence.supportedAuthority",
    "def SignatureAppendActivationProof",
    "def LeadersHaveElectionMajority",
    "theorem commitEvidencePrefix",
    "def FutureMemberFrameResult",
    "leadersHaveElectionMajority",
    "historicalSafetyEvidence",
)
REQUIRED = (
    "structure HistoricalSafetyFacts",
    "structure InvariantFacts",
    "def SystemInductiveInvariant",
)
EXPECTED_FIELDS = {
    "InvariantFacts": {
        "commitIndicesBounded",
        "currentTermsPositive",
        "entriesDoNotExceedCurrentTerm",
        "candidatesSelfVote",
        "leadersHaveElectionWitness",
        "leaderProgressBounded",
        "voteHistory",
        "networkHistory",
        "historicalSafety",
        "grantedVoteSnapshots",
        "processedAckHistory",
    },
    "HistoricalSafetyFacts": {
        "termOwnership",
        "electionHistory",
        "electionConfigurations",
        "grantedVoteCanonical",
        "ackerCurrent",
        "ackerVotes",
        "activationVotes",
        "ackerElections",
        "ackerActivations",
        "queuedElections",
        "activationProgress",
        "activationQuorums",
        "commitEvidence",
        "prospectiveCommits",
        "activationEvidence",
        "activationCanonical",
        "activationElections",
        "configurationCoverage",
    },
    "ActivationQuorumFacts": {
        "history",
        "recordBridge",
        "candidateBridge",
        "committedBridge",
        "potentialBridge",
        "queuedComparable",
        "committedCoverage",
        "queuedCoverage",
    },
    "ActivationEvidenceFacts": {
        "authorityRecorded",
        "authorityIndexUnique",
        "authorityBridge",
        "supportedPrefixesComparable",
        "candidateBridge",
    },
}
DOCUMENTATION_SECTIONS = {
    "InvariantFacts": ("## Runtime-local facts", "## Historical safety facts"),
    "HistoricalSafetyFacts": (
        "## Historical safety facts",
        "### Activation quorum bridges",
    ),
    "ActivationQuorumFacts": (
        "### Activation quorum bridges",
        "### Commit authority evidence",
    ),
    "ActivationEvidenceFacts": (
        "### Commit authority evidence",
        "## Safety derivation",
    ),
}


def remove_between(source: str, start_marker: str, end_marker: str) -> str:
    if start_marker not in source:
        return source
    start = source.index(start_marker)
    end = source.index(end_marker, start)
    return source[:start] + source[end:]


def migrated(source: str) -> str:
    for start, end in REMOVALS:
        source = remove_between(source, start, end)
    source = source.replace(
        "leadersHaveElectionMajority",
        "leadersHaveElectionWitness",
    )
    source = source.replace(
        "historicalSafetyEvidence",
        "historicalSafety",
    )
    return source


def structure_fields(source: str, structure: str) -> set[str]:
    start = source.index(f"structure {structure}")
    end = source.find("\n/--", start)
    if end == -1:
        end = len(source)
    block = source[start:end]
    return set(re.findall(r"(?m)^  ([A-Za-z][A-Za-z0-9_]*)\s*:", block))


def check() -> int:
    source = PROPERTIES.read_text() + PRESERVATION.read_text()
    properties = PROPERTIES.read_text()
    documentation = INVARIANT_DOC.read_text() if INVARIANT_DOC.exists() else ""
    errors = [symbol for symbol in FORBIDDEN if symbol in source]
    errors.extend(f"missing {symbol}" for symbol in REQUIRED if symbol not in source)
    for structure, expected_fields in EXPECTED_FIELDS.items():
        source_fields = structure_fields(properties, structure)
        errors.extend(
            f"{structure} missing field {field}"
            for field in sorted(expected_fields - source_fields)
        )
        errors.extend(
            f"{structure} has unexpected field {field}"
            for field in sorted(source_fields - expected_fields)
        )
        section_start, section_end = DOCUMENTATION_SECTIONS[structure]
        start = documentation.find(section_start)
        end = documentation.find(section_end, start + len(section_start))
        section = documentation[start:end] if start != -1 and end != -1 else ""
        errors.extend(
            f"{structure}.{field} is undocumented"
            for field in sorted(expected_fields)
            if f"`{field}`" not in section
        )
    errors.extend(str(path.relative_to(ROOT)) for path in OBSOLETE_FILES if path.exists())
    if errors:
        print("obsolete reconfiguration invariant artifacts remain:")
        for error in errors:
            print(f"- {error}")
        return 1
    return 0


def main() -> int:
    parser = ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    if args.check:
        return check()

    source = PROPERTIES.read_text()
    updated = migrated(source)
    if updated != source:
        PROPERTIES.write_text(updated)
    preservation = PRESERVATION.read_text()
    updated_preservation = migrated(preservation)
    if updated_preservation != preservation:
        PRESERVATION.write_text(updated_preservation)
    for path in OBSOLETE_FILES:
        if path.exists():
            path.unlink()
    return check()


if __name__ == "__main__":
    raise SystemExit(main())
