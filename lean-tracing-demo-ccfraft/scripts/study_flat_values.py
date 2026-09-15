#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Replace stored entry or packet constants with flat fields and reconstruction."""

import argparse
import json
from pathlib import Path
import re
import time

from encoding_study import DEFAULT_OUTPUT, PROJECT, digest, save


def parse_sort(text):
    tokens = re.findall(r"\(|\)|[^\s()]+", text)
    position = 0

    def parse():
        nonlocal position
        token = tokens[position]
        position += 1
        if token != "(":
            return token
        items = []
        while tokens[position] != ")":
            items.append(parse())
        position += 1
        return items

    result = parse()
    if position != len(tokens):
        raise ValueError("Trailing sort tokens")
    return result


def render(sort):
    return "(" + " ".join(map(render, sort)) + ")" if isinstance(sort, list) else sort


def target_sort(width, kind):
    bits = ["_", "BitVec", str(width)]
    pair = lambda a, b: ["NativePair", a, b]
    summation = lambda a, b: ["NativeSum", a, b]
    entry = pair("Int", summation("NativeUnit", summation("Int", summation(bits, bits))))
    if kind == "entry":
        return entry
    log = pair("Int", ["Array", "Int", entry])
    append = pair("Int", pair("Int", pair("Int", log)))
    payload = summation(append, summation(pair("Bool", "Int"), summation(pair("Int", "Int"),
                summation("Bool", summation(pair("Int", "Int"), summation("Bool", "NativeUnit"))))))
    return pair(pair("Int", pair("Int", "Int")), payload)


def split_array(sort):
    indices = []
    while isinstance(sort, list) and sort[0] == "Array":
        indices.append(sort[1])
        sort = sort[2]
    return indices, sort


def array_sort(indices, value):
    for index in reversed(indices):
        value = ["Array", index, value]
    return value


def flatten_constant(name, sort, method="lambda"):
    indices, value_sort = split_array(sort)
    bound = [f"study_index_{i}" for i in range(len(indices))]
    declarations = []
    fields = []

    def field(field_sort, route):
        field_name = f"study_flat_{name}_{len(fields)}"
        declarations.append(f"(declare-const {field_name} {render(array_sort(indices, field_sort))})\n")
        fields.append({"name": field_name, "sort": field_sort, "route": route})
        expression = field_name
        for index in bound:
            expression = f"(select {expression} {index})"
        return expression

    def pack(value, route):
        if value == "NativeUnit":
            return "native_unit"
        if isinstance(value, list) and value[0] == "NativePair":
            first = pack(value[1], route + ["fst"])
            second = pack(value[2], route + ["snd"])
            return f"((as native_pair {render(value)}) {first} {second})"
        if isinstance(value, list) and value[0] == "NativeSum":
            tag = field("Bool", route + ["is_left"])
            left = pack(value[1], route + ["left"])
            right = pack(value[2], route + ["right"])
            return (
                f"(ite {tag} ((as native_left {render(value)}) {left}) "
                f"((as native_right {render(value)}) {right}))"
            )
        return field(value, route)

    expression = pack(value_sort, [])
    if method == "bridge":
        selected = name
        for index in bound:
            selected = f"(select {selected} {index})"
        relation = f"(= {selected} {expression})"
        for index, index_sort in reversed(list(zip(bound, indices, strict=True))):
            relation = f"(forall (({index} {render(index_sort)})) {relation})"
        return (
            f"(declare-const {name} {render(sort)})\n" + "".join(declarations)
            + f"(assert {relation})\n",
            fields,
        )
    for index, index_sort in reversed(list(zip(bound, indices, strict=True))):
        expression = f"(lambda (({index} {render(index_sort)})) {expression})"
    return "".join(declarations) + f"(define-fun {name} () {render(sort)} {expression})\n", fields


def transform(script, width, kind, method="lambda"):
    if "study_flat_" in script:
        raise ValueError("Flat symbol prefix already occurs")
    target = target_sort(width, kind)
    output = []
    changed = []
    for line in script.splitlines(keepends=True):
        match = re.fullmatch(r"\(declare-const (\S+) (.+)\)\n", line)
        if not match:
            if line.lstrip().startswith(("(declare-const", "(declare-fun")):
                raise ValueError("Only canonical native declare-const syntax is supported")
            output.append(line)
            continue
        name, text = match.groups()
        if not re.fullmatch(r"c_[A-Za-z0-9_]+", name):
            raise ValueError("Expected a native c_ constant name")
        sort = parse_sort(text)
        _, value = split_array(sort)
        if value != target:
            output.append(line)
            continue
        replacement, fields = flatten_constant(name, sort, method)
        output.append(replacement)
        changed.append({"original": name, "sort": sort, "fields": fields})
    result = "".join(output)
    if not changed:
        raise ValueError(f"No {kind} constants found")
    if not result.endswith("(assert " + script.split("(assert ", 1)[1]):
        raise ValueError("Flattening changed an original assertion")
    return result, changed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--kind", choices=["entry", "packet"], required=True)
    parser.add_argument("--method", choices=["lambda", "bridge"], default="bridge")
    parser.add_argument("--variant")
    args = parser.parse_args()
    manifest = json.loads((args.output / "manifest.json").read_text())
    variant = args.variant or f"flat-{args.kind}-{args.method}"
    started = time.perf_counter()
    for case in manifest:
        details = json.loads((args.output / "inputs" / case["name"] / "encoding.json").read_text())
        script, mapping = transform(details["script"], len(details["input"]["nodes"]), args.kind, args.method)
        directory = args.output / "variants" / variant / case["name"]
        directory.mkdir(parents=True, exist_ok=False)
        save(directory / "encoding.json", {**details, "script": script})
        save(directory / "fields.json", mapping)
        (directory / "original.smt2").write_text(script)
    source = Path(__file__).read_bytes()
    (args.output / "variants" / variant / "source.py").write_bytes(source)
    save(args.output / "variants" / variant / "preparation.json", {
        "source_path": str(Path(__file__).resolve().relative_to(PROJECT)),
        "source_sha256": digest(source),
        "kind": args.kind, "method": args.method, "wall_seconds": time.perf_counter() - started,
        "cases": [case["name"] for case in manifest],
    })


if __name__ == "__main__":
    main()
