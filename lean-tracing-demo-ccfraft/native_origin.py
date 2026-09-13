# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Bind native instructions to retained raw records and reduction decisions."""

from __future__ import annotations

from dataclasses import dataclass

from native_input import canonical_json
from native_reduction import native_document
from raw_normalization import NormalizedTrace, normalize
from reduction import build_certificate
from Shared.solver import ValidationError
from Shared.trace_io import NDJSONRecord, loads_ndjson

RAW_ARTIFACTS = ("raw.ndjson", "reduction.json")


@dataclass(frozen=True)
class RawOrigin:
    records: tuple[NDJSONRecord, ...]
    certificate: dict
    trace: NormalizedTrace

    def instruction(self, index: int) -> dict:
        step = self.trace.steps[index]
        records = []
        for item in step["provenance"]:
            record = self.records[item["line"] - 1]
            records.append(
                {"line": record.line_number, "raw": record.raw, "value": record.value}
            )
        return {
            "step": step,
            "evidence": self.trace.evidence.get(index + 1),
            "records": records,
        }


def reduce_raw(data: bytes) -> RawOrigin:
    """Run the untrusted reducer without historical bounds or identity slots."""
    records = tuple(loads_ndjson(data.decode("utf-8"), source="raw.ndjson"))
    certificate = build_certificate(records)
    return RawOrigin(records, certificate, normalize(certificate, native_ids=True))


def validate_raw_origin(data: bytes, certificate: object, document: dict) -> RawOrigin:
    """Recompute once at load time, before serving an immutable snapshot."""
    origin = reduce_raw(data)
    if canonical_json(origin.certificate) != canonical_json(certificate):
        raise ValidationError("retained reduction does not match the raw capture")
    projected = native_document(origin.trace, document["bootstrap"])
    if canonical_json(projected) != canonical_json(document):
        raise ValidationError("raw reduction belongs to different Model input")
    return origin
