# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Lossless JSON object decoding for native encoder inputs."""

from __future__ import annotations

from Shared.solver import ValidationError


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    """Reject duplicate keys instead of discarding recorded facts."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError(f"duplicate JSON field: {key}")
        result[key] = value
    return result
