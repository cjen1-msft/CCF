-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeInitialEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem entry_observation_correct {width : PNat} (assignment : Assignment)
    (columns : NodeColumns) (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat)
    (rep : NodeColumnsRep assignment columns arrays)
    (domains : forall node : Fin width, NodeDomain width assignment node.val)
    (node : Fin width) (index : Nat) (expected : Entry (Fin width) Nat) :
    Holds [lt (.integer index) (length node.val),
      .equal (entryAt width node.val (.integer index)) (entryTerm expected)] assignment <->
      (index < (NativeArrayCheckQuorum.get arrays node).log.length /\
        (NativeArrayCheckQuorum.get arrays node).log.entries index = expected) := by
  have live : (lt (.integer index) (length node.val) : Expr .bool).eval assignment Locals.empty = true <->
      index < (NativeArrayCheckQuorum.get arrays node).log.length := by
    simp [lt, Term.eval, rep.length node]
  simp only [Holds, List.mem_cons, List.not_mem_nil, or_false, or_imp, forall_and, forall_eq]
  rw [live]
  apply and_congr_right
  intro within
  have valid := (domains node).entries (index : Int) ⟨Int.natCast_nonneg _, by
    change (index : Int) < (length node.val : Expr .int).eval assignment Locals.empty
    rw [rep.length node]
    exact Int.ofNat_lt.mpr within⟩
  rw [entry_literal_eq_correct _ expected assignment Locals.empty
    ((entry_domain_correct _ assignment Locals.empty).mpr (by
      simpa only [entryAt, Term.eval] using valid))]
  rw [rep.entries node index within]

theorem observation_correct {width : PNat} [Bootstrap (Fin width)] (assignment : Assignment)
    (columns : NodeColumns) (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat)
    (rep : NodeColumnsRep assignment columns arrays)
    (domains : forall node : Fin width, NodeDomain width assignment node.val)
    (item : NativeArrayCheckQuorum.Instruction (Fin width) Nat) (clauses : List (Expr .bool))
    (emitted : observationClauses columns item = .ok clauses) :
    Holds clauses assignment <-> NativeArrayCheckQuorum.follows arrays [item] := by
  cases item <;> simp [observationClauses] at emitted
  all_goals subst clauses
  case entry node index expected =>
    simpa only [NativeArrayCheckQuorum.follows, and_true] using
      entry_observation_correct assignment columns arrays rep domains node index expected
  case retirementIndex node expected =>
    simp only [Holds, List.mem_cons, List.not_mem_nil, or_false, forall_eq]
    rw [optional_nat_literal_correct, rep.retirementIndex node,
      optional_decode_value Nat.cast naturalValue? natural_value_round_trip]
    simp [NativeArrayCheckQuorum.follows]
  case retirementCommittableIndex node expected =>
    simp only [Holds, List.mem_cons, List.not_mem_nil, or_false, forall_eq]
    rw [optional_nat_literal_correct, rep.retirementCommittableIndex node,
      optional_decode_value Nat.cast naturalValue? natural_value_round_trip]
    simp [NativeArrayCheckQuorum.follows]
  case retiredCommittedIndex node expected =>
    simp only [Holds, List.mem_cons, List.not_mem_nil, or_false, forall_eq]
    rw [optional_nat_literal_correct, rep.retiredCommittedIndex node,
      optional_decode_value Nat.cast naturalValue? natural_value_round_trip]
    simp [NativeArrayCheckQuorum.follows]
  all_goals
    simp [Holds, NativeArrayCheckQuorum.follows, Term.eval, rep.allocated, rep.role,
      rep.newFollower, rep.currentTerm, rep.commit, rep.length, role_code_eq]

theorem observation_model_correct {width : PNat} [Bootstrap (Fin width)]
    (assignment : Assignment) (columns : NodeColumns)
    (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat) (model : State (Fin width) Nat)
    (columnRep : NodeColumnsRep assignment columns arrays)
    (represented : NativeArrayCheckQuorum.Rep arrays model)
    (domains : forall node : Fin width, NodeDomain width assignment node.val)
    (item : NativeArrayCheckQuorum.Instruction (Fin width) Nat) (clauses : List (Expr .bool))
    (emitted : observationClauses columns item = .ok clauses) :
    Holds clauses assignment <-> NativeArrayCheckQuorum.modelFollows model [item] :=
  (observation_correct assignment columns arrays columnRep domains item clauses emitted).trans
    (NativeArrayCheckQuorum.follows_correct [item] arrays model represented)

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
