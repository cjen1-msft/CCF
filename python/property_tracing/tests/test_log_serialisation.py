# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

from pathlib import Path

import pytest

from log_serialisation import CCFTTYLogSource, MergeTimeSource


DATA_DIR = Path(__file__).resolve().parent / "data" / "merge_snapshot"
NODE_LOGS = ("node0.out", "node1.out", "node2.out")


def _format_entry(entry) -> str:
    msg = "\n".join(entry.message)
    return f"{entry.timestamp} {entry.node_id} {msg}"


def _drain(source) -> list:
    return list(source)


@pytest.fixture
def node_log_paths() -> dict[str, Path]:
    return {name.removesuffix(".out"): DATA_DIR / name for name in NODE_LOGS}


def test_per_node_entry_counts(node_log_paths):
    # Sanity check: each individual source parses without raising and produces
    # the expected number of entries.  These counts are derived from running
    # the parser on the captured fixtures and pin the parser's behaviour.
    expected = {"node0": 3, "node1": 3, "node2": 3}
    for tag, path in node_log_paths.items():
        entries = _drain(CCFTTYLogSource(str(path)))
        assert len(entries) == expected[tag], (
            f"{tag}: expected {expected[tag]} entries, got {len(entries)}"
        )


def test_merge_is_time_ordered(node_log_paths):
    sources = {tag: CCFTTYLogSource(str(p)) for tag, p in node_log_paths.items()}
    merged = MergeTimeSource(sources, "tag")

    entries = _drain(merged)
    timestamps = [e.timestamp for e in entries]

    # Total entries equals the sum of the per-source counts.
    assert len(entries) == 3 + 3 + 3

    # Merged stream is non-decreasing in time.
    assert timestamps == sorted(timestamps)


def test_merge_snapshot(node_log_paths, tmp_path):
    sources = {tag: CCFTTYLogSource(str(p)) for tag, p in node_log_paths.items()}
    merged = MergeTimeSource(sources, "tag")

    output_file = tmp_path / "merged.txt"
    with output_file.open("w") as f:
        for entry in _drain(merged):
            f.write(_format_entry(entry))
            f.write("\n")

    snapshot_file = DATA_DIR / "merged_snapshot.txt"
    assert output_file.read_text() == snapshot_file.read_text(), (
        f"Merged output diverged from snapshot.  "
        f"Compare {output_file} against {snapshot_file}."
    )
