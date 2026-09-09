# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Group reduction precedes clause refinement, with unchanged reduced context."""

from __future__ import annotations

import copy
import json
import unittest

from tests.test_client_request_encoding import (
    CVC5,
    SOLVER_TESTS,
    ClientRequestSliceTestCase,
    _observation,
    _request,
)
from tests.test_leader_writes import trace
from tests.test_replication_encoding import send
from refine_checked import refine_checked_core, refine_formula
from Shared.smt import SmtEncodingError
from Shared.solver import ValidationError


def formula_fixture() -> tuple[str, dict[str, object]]:
    groups = []
    assertions = []
    for index, expressions in enumerate(
        [("true",), ("(= x 0)", "(>= x 0)"), ("(= x 1)",), ("(<= x 3)",)]
    ):
        name = f"group_{index}"
        expression = (
            expressions[0]
            if len(expressions) == 1
            else "(and " + " ".join(expressions) + ")"
        )
        assertions.append(f"(assert (! {expression} :named {name}))")
        groups.append(
            {
                "index": index,
                "name": name,
                "kind": "action" if index == 1 else "observation",
                "clauses": [
                    {
                        "name": f"{name}_clause_{clause_index}",
                        "expression": clause,
                    }
                    for clause_index, clause in enumerate(expressions)
                ],
            }
        )
    return (
        "(set-logic QF_LIA)\n(declare-const x Int)\n"
        + "\n".join(assertions)
        + "\n(check-sat)\n",
        {"groups": groups},
    )


class RefinementFormulaTests(unittest.TestCase):
    def test_discarded_groups_stay_discarded(self) -> None:
        formula, mapping = formula_fixture()
        refined, fixed = refine_formula(formula, mapping, ("group_1", "group_2"), 1)
        self.assertEqual(fixed, ("group_2",))
        self.assertIn(":named group_1_clause_0", refined)
        self.assertIn(":named group_1_clause_1", refined)
        self.assertIn(":named group_2)", refined)
        self.assertNotIn(":named group_1)", refined)
        self.assertNotIn(":named group_0)", refined)
        self.assertNotIn(":named group_3)", refined)
        self.assertIn("(declare-const x Int)", refined)

    def test_only_actions_in_the_reduced_core_can_be_selected(self) -> None:
        formula, mapping = formula_fixture()
        for core, selected in [
            (("group_2",), 1),
            (("group_1", "group_2"), 2),
            (("group_0", "group_1"), 0),
            (("group_1", "group_2"), 20),
        ]:
            with self.subTest(core=core, selected=selected), self.assertRaises(
                ValidationError
            ):
                refine_formula(formula, mapping, core, selected)

    def test_changed_constraint_map_is_rejected(self) -> None:
        formula, mapping = formula_fixture()
        changed = copy.deepcopy(mapping)
        changed["groups"][1]["clauses"][0]["expression"] = "(= x 2)"
        with self.assertRaisesRegex(ValidationError, "disagree"):
            refine_formula(formula, changed, ("group_1", "group_2"), 1)

    def test_missing_or_duplicate_formula_group_is_rejected(self) -> None:
        formula, mapping = formula_fixture()
        assertion = "(assert (! (<= x 3) :named group_3))\n"
        for changed in (formula.replace(assertion, ""), formula + assertion):
            with self.subTest(changed=changed), self.assertRaises(ValidationError):
                refine_formula(changed, mapping, ("group_1", "group_2"), 1)

    def test_clause_names_and_core_names_are_validated(self) -> None:
        formula, mapping = formula_fixture()
        changed = copy.deepcopy(mapping)
        changed["groups"][1]["clauses"][0]["name"] = "group_2"
        with self.assertRaisesRegex(ValidationError, "clause name"):
            refine_formula(formula, changed, ("group_1", "group_2"), 1)
        with self.assertRaises(SmtEncodingError):
            refine_formula(formula, mapping, ("group_1", "group_1", "group_2"), 1)


@SOLVER_TESTS
class CheckedCoreRefinementTests(ClientRequestSliceTestCase):
    def test_send_refines_inside_the_previously_reduced_core(self) -> None:
        status, source = self.run_runner(
            trace(
                [_request(0), send(), _observation("queueLength", 0, node=1)],
                queue_capacity=1,
            )
        )
        self.assertEqual(status, "unsat")
        source_core = self._core_names(source / "unsat-core.txt")
        output = self.workspace / "refined"
        result = refine_checked_core(source, output, inspect_group=2, cvc5=CVC5)
        self.assertEqual(result["status"], "unsat")
        self.assertEqual(
            set(result["core_fixed_context_names"]), source_core - {"group_2"}
        )
        final = self._core_names(output / "unsat-core.txt")
        self.assertTrue((source_core - {"group_2"}).issubset(final))
        self.assertTrue(any(name.startswith("group_2_clause_") for name in final))
        formula = (output / "formula.smt2").read_text(encoding="utf-8")
        self.assertNotIn(":named group_1)", formula)
        self.assertEqual(source_core, self._core_names(source / "unsat-core.txt"))

    def test_source_cannot_be_overwritten_or_refined_twice(self) -> None:
        _, source = self.run_runner(trace([_request(0), send()], queue_capacity=0))
        original = (source / "result.json").read_bytes()
        with self.assertRaisesRegex(ValidationError, "differ"):
            refine_checked_core(source, source, inspect_group=2, cvc5=CVC5)
        self.assertEqual(original, (source / "result.json").read_bytes())
        refined = self.workspace / "refined"
        refine_checked_core(source, refined, inspect_group=2, cvc5=CVC5)
        rejected = self.workspace / "rejected"
        with self.assertRaisesRegex(ValidationError, "group-level"):
            refine_checked_core(refined, rejected, inspect_group=2, cvc5=CVC5)
        self.assertFalse((rejected / "result.json").exists())
        self.assertTrue((rejected / "error.json").exists())

    def test_every_prior_context_group_survives_solver_core_selection(self) -> None:
        _, source = self.run_runner(
            trace(
                [_request(0), send(), _observation("queueLength", 0, node=1)],
                queue_capacity=1,
            )
        )
        # A budget-limited group reduction may retain an irrelevant group.
        (source / "unsat-core.txt").write_text(
            "(group_0 group_2 group_3)\n", encoding="utf-8"
        )
        output = self.workspace / "refined"
        result = refine_checked_core(source, output, inspect_group=2, cvc5=CVC5)
        self.assertEqual(
            set(result["core_fixed_context_names"]), {"group_0", "group_3"}
        )
        self.assertTrue(
            {"group_0", "group_3"}.issubset(self._core_names(output / "unsat-core.txt"))
        )
        diagnosis = json.loads((output / "diagnosis.json").read_text(encoding="utf-8"))
        self.assertIn("group_0", diagnosis["named_assertions"])


if __name__ == "__main__":
    unittest.main()
