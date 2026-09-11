# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Native FIFO storage commands corresponding to Sparse.NativeArrayQueue.

Names, sorts, and terms are trusted, caller-generated SMT expressions. This is
not an input parser or a compiler for Model actions. Each queue needs a unique
name within its enclosing script.
"""


class QueueArray:
    """Keep named array versions; never copy a queue or compare pending values."""

    def __init__(self, name: str, element_sort: str):
        self.name = name
        self.sort = f"(Array Int {element_sort})"
        self.version = 0
        self.cells = f"{name}_cells_0"
        self.head = f"{name}_head_0"
        self.length = f"{name}_length_0"
        self.commands = [
            f"(declare-const {self.cells} {self.sort})",
            f"(declare-const {self.head} Int)",
            f"(declare-const {self.length} Int)",
            f"(assert (<= 0 {self.head}))",
            f"(assert (<= 0 {self.length}))",
        ]

    def _define(self, field: str, sort: str, expression: str) -> str:
        symbol = f"{self.name}_{field}_{self.version}"
        self.commands.extend(
            [f"(declare-const {symbol} {sort})", f"(assert (= {symbol} {expression}))"]
        )
        return symbol

    def send(self, value: str) -> None:
        self.version += 1
        self.cells = self._define(
            "cells",
            self.sort,
            f"(store {self.cells} (+ {self.head} {self.length}) {value})",
        )
        self.length = self._define("length", "Int", f"(+ {self.length} 1)")

    def receive(self, expected: str) -> None:
        self.commands.extend(
            [
                f"(assert (< 0 {self.length}))",
                f"(assert (= (select {self.cells} {self.head}) {expected}))",
            ]
        )
        self.version += 1
        self.head = self._define("head", "Int", f"(+ {self.head} 1)")
        self.length = self._define("length", "Int", f"(- {self.length} 1)")

    def observe_length(self, expected: str) -> None:
        self.commands.append(f"(assert (= {self.length} {expected}))")

    def point(self, index: str, expected: str) -> None:
        self.commands.extend(
            [
                f"(assert (and (<= 0 {index}) (< {index} {self.length})))",
                f"(assert (= (select {self.cells} (+ {self.head} {index})) {expected}))",
            ]
        )
