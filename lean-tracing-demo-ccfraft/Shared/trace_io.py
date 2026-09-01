# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Model-independent, lossless NDJSON input handling."""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class NDJSONError(ValueError):
    """Report malformed NDJSON without interpreting the parsed objects."""


@dataclass(frozen=True)
class NDJSONRecord:
    """One JSON object and the input line from which it was parsed."""

    line_number: int
    raw: str
    value: dict[str, Any]


def _line_text(line: str) -> str:
    if line.endswith("\n"):
        line = line[:-1]
        line = line.removesuffix("\r")
    return line


def parse_ndjson(
    lines: Iterable[str],
    *,
    source: str = "<input>",
) -> list[NDJSONRecord]:
    """Parse non-empty NDJSON lines while retaining objects and provenance."""

    records: list[NDJSONRecord] = []
    for line_number, line in enumerate(lines, 1):
        raw = _line_text(line)
        if not raw.strip():
            raise NDJSONError(f"{source}:{line_number}: empty NDJSON record")
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as error:
            raise NDJSONError(
                f"{source}:{line_number}: invalid JSON: {error.msg}"
            ) from error
        if not isinstance(value, dict):
            raise NDJSONError(f"{source}:{line_number}: NDJSON record is not an object")
        records.append(NDJSONRecord(line_number, raw, value))
    return records


def loads_ndjson(text: str, *, source: str = "<input>") -> list[NDJSONRecord]:
    """Parse an NDJSON string."""

    return parse_ndjson(text.splitlines(keepends=True), source=source)


def read_ndjson(path: Path) -> list[NDJSONRecord]:
    """Read and parse an NDJSON file."""

    with path.open("r", encoding="utf-8", newline="") as stream:
        return parse_ndjson(stream, source=str(path))
