#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Create the CCFRaft tracing demo from its reviewed checkpoint."""

from __future__ import annotations

import argparse
import pathlib
import subprocess

CHECKPOINT = "73292060d"
REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
TARGET = pathlib.Path(__file__).resolve().parent
SOURCE_PREFIX = "lean/CCFRaft/"

PROOF_MODULES = {
    "BootstrapExamples.lean",
    "ConfigurationCoverage.lean",
    "HandlerProofs.lean",
    "Proofs.lean",
    "ReconfigurationPreservation.lean",
    "UpdateTermAuthority.lean",
    "VotedForFrame.lean",
}

RUNTIME_MODULES = {
    "LongTraceSmtProbe.lean",
    "NaiveFullStateWitness.lean",
    "Simulation.lean",
    "TraceValidation.lean",
}

ARCHIVE_FILES = {
    "CORRESPONDENCE.md",
    "INVARIANT.md",
    "ISSUES.md",
    "README.md",
    "TRACE_VALIDATION.md",
    "audit_reduction_corpus.py",
    "cheap_full_state_lean.py",
    "cheap_full_state_smt.py",
    "full_trace_prototype.py",
    "generate_reduction_critique_report.py",
    "generate_trace_validation_pipeline_report.py",
    "long_trace_smt_probe.py",
    "naive_full_state_lean.py",
    "naive_full_state_smt.py",
    "reduction-critique-report.html",
    "symbolic-sequence-prototype.html",
    "symbolic_array_prototype.py",
    "symbolic_sequence_prototype.py",
    "trace-validation-pipeline-report.html",
    "trace_alignment_smt_probe.smt2",
    "trace_fifo_parser_prototype.html",
}


def git_text(path: str) -> str:
    result = subprocess.run(
        ["git", "show", f"{CHECKPOINT}:{path}"],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


def git_bytes(path: str) -> bytes:
    result = subprocess.run(
        ["git", "show", f"{CHECKPOINT}:{path}"],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
    )
    return result.stdout


def checkpoint_files() -> list[str]:
    result = subprocess.run(
        ["git", "ls-tree", "-r", "--name-only", CHECKPOINT, "lean/CCFRaft"],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return [
        path for path in result.stdout.splitlines() if path.startswith(SOURCE_PREFIX)
    ]


def rewrite_imports(text: str) -> str:
    replacements = {
        "import CCFRaft.ExecutableTransitionSystem": (
            "import Shared.ExecutableTransitionSystem"
        ),
        "import CCFRaft.Model": "import Model",
        "import CCFRaft.Properties": "import MachineGenerated.Invariant",
        "import CCFRaft.HandlerProofs": "import MachineGenerated.HandlerProofs",
        "import CCFRaft.UpdateTermAuthority": (
            "import MachineGenerated.UpdateTermAuthority"
        ),
        "import CCFRaft.VotedForFrame": "import MachineGenerated.VotedForFrame",
        "import CCFRaft.ConfigurationCoverage": (
            "import MachineGenerated.ConfigurationCoverage"
        ),
        "import CCFRaft.ReconfigurationPreservation": (
            "import MachineGenerated.ReconfigurationPreservation"
        ),
        "import CCFRaft.Proofs": "import MachineGenerated.Proof",
        "import CCFRaft.BootstrapExamples": (
            "import MachineGenerated.BootstrapExamples"
        ),
        "import CCFRaft.Simulation": "import MachineGenerated.Runtime.Simulation",
        "import CCFRaft.TraceValidation": (
            "import MachineGenerated.Runtime.TraceValidation"
        ),
    }
    for old, new in replacements.items():
        text = text.replace(old, new)
    return text


def extract_block(text: str, start: str, end: str) -> str:
    start_index = text.index(start)
    end_index = text.index(end, start_index)
    return text[start_index:end_index].rstrip() + "\n"


def generate_properties(source: str) -> tuple[str, str]:
    copyright_header = "\n".join(source.splitlines()[:3])
    variables = """\
set_option autoImplicit false

namespace CCFRaft

variable {Node TxId : Type}
variable [DecidableEq Node] [DecidableEq TxId]

"""
    committed_frontier = extract_block(
        source,
        "/-- Every positive node commit frontier",
        "/-- No two distinct nodes lead",
    )
    election_safety = extract_block(
        source,
        "/-- No two distinct nodes lead",
        "/-- Any two node-local committed logs",
    )
    committed_logs = extract_block(
        source,
        "/-- Any two node-local committed logs",
        "/-- Equal index and term",
    )
    consensus = extract_block(
        source,
        "/-- Core public safety mirrors",
        "\nend CCFRaft",
    )
    audited = (
        f"{copyright_header}\n\n"
        "import Model\n\n"
        f"{variables}"
        f"{committed_frontier}\n"
        f"{election_safety}\n"
        f"{committed_logs}\n"
        f"{consensus}\n"
        "end CCFRaft\n"
    )

    commit_indices = extract_block(
        source,
        "/-- Every node's commit index",
        "/-- Every positive node commit frontier",
    )
    log_matching = extract_block(
        source,
        "/-- Equal index and term",
        "/-- Entry terms do not decrease",
    )
    mono_log = extract_block(
        source,
        "/-- Entry terms do not decrease",
        "\nend CCFRaft",
    )
    proof_start = source.index("/-!\n# Arbitrary-term Raft proof properties")
    proof_end = source.index("/-- Core public safety mirrors", proof_start)
    proof_body = source[proof_start:proof_end].rstrip()
    invariant = (
        f"{copyright_header}\n\n"
        "import Properties\n\n"
        f"{variables}"
        f"{commit_indices}\n"
        f"{log_matching}\n"
        f"{mono_log}\n"
        "end CCFRaft\n\n"
        f"{proof_body}\n\n"
        "end CCFRaft\n"
    )
    return audited, invariant


def write(path: pathlib.Path, content: str | bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8")


def bootstrap() -> None:
    files = checkpoint_files()
    expected = {
        SOURCE_PREFIX + "Model.lean",
        SOURCE_PREFIX + "Properties.lean",
        SOURCE_PREFIX + "ExecutableTransitionSystem.lean",
    }
    missing = expected.difference(files)
    if missing:
        raise RuntimeError(f"checkpoint is missing required files: {sorted(missing)}")

    model = rewrite_imports(git_text(SOURCE_PREFIX + "Model.lean"))
    properties, invariant = generate_properties(
        git_text(SOURCE_PREFIX + "Properties.lean")
    )
    executable = git_text(SOURCE_PREFIX + "ExecutableTransitionSystem.lean")
    write(TARGET / "Model.lean", model)
    write(TARGET / "Properties.lean", properties)
    write(TARGET / "Shared" / "ExecutableTransitionSystem.lean", executable)
    write(TARGET / "MachineGenerated" / "Invariant.lean", invariant)

    for name in sorted(PROOF_MODULES):
        content = rewrite_imports(git_text(SOURCE_PREFIX + name))
        target_name = "Proof.lean" if name == "Proofs.lean" else name
        write(TARGET / "MachineGenerated" / target_name, content)

    for name in sorted(RUNTIME_MODULES):
        content = rewrite_imports(git_text(SOURCE_PREFIX + name))
        write(TARGET / "MachineGenerated" / "Runtime" / name, content)

    for name in sorted(ARCHIVE_FILES):
        path = SOURCE_PREFIX + name
        if path in files:
            write(TARGET / "Archive" / name, git_bytes(path))

    for path in files:
        relative = path.removeprefix(SOURCE_PREFIX)
        if relative.startswith("traces/"):
            write(
                TARGET / "Traces" / "Legacy" / relative.removeprefix("traces/"),
                git_bytes(path),
            )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--generate",
        action="store_true",
        help="replace files generated from the checkpoint",
    )
    args = parser.parse_args()
    if not args.generate:
        parser.error("pass --generate to replace generated migration files")
    bootstrap()
    print(f"bootstrapped_from={CHECKPOINT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
