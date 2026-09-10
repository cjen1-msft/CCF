# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Export reviewed sparse proofs and check their namespace-only correspondence."""

import argparse
import hashlib
import json
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parent
SOURCES = {
    "SparseQueuePrototype": (
        "Sparse.Queue",
        "27ee040556106a6aa9ef23b4ab022dfa1aa6d36e42262c88ba86b3125c21b2d6",
    ),
    "SparseQueueModelPrototype": (
        "Sparse.QueueModel",
        "0dd4018017b53fdae9fa0478b32bb3e5930e60ac9623247b99bdac5d0d73a40a",
    ),
    "SparseArrayLogPrototype": (
        "Sparse.ArrayLog",
        "ae26118d386afdeb376c889a079ea67fc4ad17ffe154ac8721ba4f8b0ce258b2",
    ),
    "SparseQueueCountsPrototype": (
        "Sparse.QueueCounts",
        "49006cf5832108dd0a452a5d060191302e516c5154269ae2859c5f09249c7147",
    ),
    "SparseQueueStreamPrototype": (
        "Sparse.QueueStream",
        "8d962bc743449a7b5965f39c14c4a6e99205799e59720fec0c12f6403cb58b0a",
    ),
    "SparseCountedQueuePrototype": (
        "Sparse.CountedQueue",
        "5945377c6c7d649b40da2f06dd75536b757ac3c26c4f90d1b596b9820cfa441c",
    ),
    "SparseIntegerQueuePrototype": (
        "Sparse.IntegerQueue",
        "318bad16a6a9c739d5c94a0b959aec01d988860c9429546a05e873a9dbbcee2d",
    ),
    "SparseSignedQueuePrototype": (
        "Sparse.SignedQueue",
        "eb86670e48e018dedac76834780d21ecf024f1ad04fb04babd01806dd23a0c5b",
    ),
    "SparseQueueClausePrototype": (
        "Sparse.QueueClause",
        "27ffec6aa02ff7d55154b3fac5f9c36709a77af8c10f2719db5069e36822a1e6",
    ),
    "SparseIntegerLogPrototype": (
        "Sparse.IntegerLog",
        "4f039ea2137f6619c3553d6286e1dddfefc660696288a6cb2a82770341034bd8",
    ),
    "SparseBijectiveIntegerLogPrototype": (
        "Sparse.BijectiveIntegerLog",
        "315640dc5ec836dafd4d710237c797d9050365dbba39de78f0d73f078cbc3ac4",
    ),
    "SparseQueueAccountingPrototype": (
        "Sparse.QueueAccounting",
        "98d947ae3c631dae3cb6be75c34f25ed00bf09de22596f9f05493d8184c3ebef",
    ),
    "SparseMessageCodecPrototype": (
        "Sparse.MessageCodec",
        "083c6b227381b069575596efb985855e5bf672fb15d783cae858b0f3c86768f8",
    ),
    "SparsePartialQueuePrototype": (
        "Sparse.PartialQueue",
        "726242a1bbed853a11a09f576c3cfc4c42696664ed9a9b7904b5c294241cf3f9",
    ),
    "SparseConfigurationPrototype": (
        "Sparse.Configuration",
        "ef20cff92bc93704da0e29db79d820a2c37091862700fc7c754b09531f79dada",
    ),
    "SparseIntervalCompletionPrototype": (
        "Sparse.IntervalCompletion",
        "eeefd5a543fe1a52f9bbca7d49ea549328679b3db167a87132b5401095299b1a",
    ),
    "SparseConfigSignaturePrototype": (
        "Sparse.ConfigSignature",
        "106294c8f31223d3bfce2d6c9fb7ba8f3924a301d1859cc2b46da0c7442ca88b",
    ),
    "SparseReadbackPrototype": (
        "Sparse.Readback",
        "de78919fafb386056c618cd8d5bb887ba3dba09003e807be6f8910dff219c12a",
    ),
    "SparseNodeSetCodecPrototype": (
        "Sparse.NodeSetCodec",
        "bd6966c1f8db6653ce4f49407f53a4213e52cdf3e95c30d4a1d6f0f826f86b26",
    ),
    "SparsePacketQueuePrototype": (
        "Sparse.PacketQueue",
        "d4caaf15f98665a0b18b46521a1de3ac918fb61919a515f0faa50a0664e12319",
    ),
    "SparseQueueCountBoundsPrototype": (
        "Sparse.QueueCountBounds",
        "e2847bce96b0785dcd09f154c486ea20dde33dfadc7c53eaf478365b6c65379c",
    ),
    "SparseFoundationAudit": (
        "Sparse.FoundationAudit",
        "c5591eb20c02512db090c39985179fd707bbf59cb3b0d3bf1b724812c4c81e7e",
    ),
}


def sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def proof_body(source: str) -> str:
    """Remove diagnostic printing and the historical session command log."""
    source = source.partition("\n/-!\nCommand log,")[0]
    return "\n".join(
        line for line in source.splitlines() if not line.startswith("#print axioms ")
    ).rstrip() + "\n"


def rename(source: str, replacements: dict[str, str]) -> str:
    pattern = re.compile(
        r"(?<![A-Za-z0-9_])("
        + "|".join(re.escape(name) for name in replacements)
        + r")(?![A-Za-z0-9_])"
    )
    return pattern.sub(lambda match: replacements[match.group(0)], source)


def export(source_directory: Path, destination_root: Path) -> None:
    replacements = {name: target for name, (target, _) in SOURCES.items()}
    records = []
    pending = []
    for name, (target, expected_hash) in SOURCES.items():
        source = (source_directory / f"{name}.lean").read_bytes()
        if sha256(source) != expected_hash:
            raise ValueError(f"reviewed source changed: {name}")
        body = proof_body(source.decode("ascii"))
        content = rename(body, replacements).encode("ascii")
        destination = destination_root / (target.replace(".", "/") + ".lean")
        if destination.exists() and destination.read_bytes() != content:
            raise ValueError(f"refusing to overwrite a changed destination: {destination}")
        pending.append((destination, content))
        records.append(
            {
                "source": name,
                "source_sha256": expected_hash,
                "target": target,
                "proof_body_sha256": sha256(body.encode("ascii")),
            }
        )
    manifest = destination_root / "Sparse" / "provenance.json"
    manifest_text = (json.dumps(records, indent=2) + "\n").encode("ascii")
    if manifest.exists():
        previous = json.loads(manifest.read_text(encoding="ascii"))
        if not previous or previous != records[:len(previous)]:
            raise ValueError("refusing to overwrite changed proof provenance")
    for destination, content in pending:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)
    manifest.write_bytes(manifest_text)
    check(destination_root)


def check(destination_root: Path) -> None:
    records = json.loads(
        (destination_root / "Sparse" / "provenance.json").read_text(encoding="ascii")
    )
    if [record["source"] for record in records] != list(SOURCES):
        raise ValueError("proof provenance has unexpected source modules")
    replacements = {target: name for name, (target, _) in SOURCES.items()}
    for record in records:
        target, expected_source = SOURCES[record["source"]]
        if record["target"] != target or record["source_sha256"] != expected_source:
            raise ValueError(f"proof provenance changed: {record['source']}")
        destination = destination_root / (target.replace(".", "/") + ".lean")
        restored = rename(destination.read_text(encoding="ascii"), replacements)
        if sha256(restored.encode("ascii")) != record["proof_body_sha256"]:
            raise ValueError(f"exported proof changed: {target}")
    print(f"Reviewed proof bodies preserved: {len(records)} modules.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--source-dir", type=Path)
    group.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.check:
        check(ROOT)
    else:
        export(args.source_dir, ROOT)


if __name__ == "__main__":
    main()
