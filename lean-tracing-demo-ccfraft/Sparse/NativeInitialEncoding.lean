-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeNodeEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def scalarValue (assignment : Assignment) (column node : Nat) : Int :=
  if assignment (.array .int .bool) 0 node then assignment (.array .int .int) column node else 0

structure NodeDomain (width : PNat) (assignment : Assignment) (node : Nat) : Prop where
  role : 0 <= scalarValue assignment 1 node /\ scalarValue assignment 1 node <= 4
  length : 0 <= scalarValue assignment 3 node
  commit : 0 <= scalarValue assignment 4 node
  term : 0 <= scalarValue assignment 5 node
  entries : forall index : Int, 0 <= index /\ index < scalarValue assignment 3 node ->
    EntryValid (assignment (.array .int (.array .int (entryTy width))) 6 node index)

theorem initial_node_domains_correct (width : PNat) (assignment : Assignment) (node : Nat) :
    Holds (initialNodeDomains width node) assignment <-> NodeDomain width assignment node := by
  have logDomain :
      (Term.forall_ .int (implies
        (.and (.le (.integer 0) (.bound .here)) (lt (.bound .here) (length node)))
        (entryDomain (entryAt width node (.bound .here))))).eval assignment Locals.empty = true <->
      (forall index : Int, 0 <= index /\ index < scalarValue assignment 3 node ->
        EntryValid (assignment (.array .int (.array .int (entryTy width))) 6 node index)) := by
    simp only [Term.eval, decide_eq_true_eq]
    conv_lhs =>
      intro index
      rw [implies_eval, entry_domain_correct]
    simp [lt, length, read, allocated, scalarValue, entryAt, Term.eval, Locals.cons]
  simp only [initialNodeDomains, Holds, List.mem_cons, List.not_mem_nil, or_false,
    or_imp, forall_and, forall_eq]
  rw [logDomain]
  simp only [all, List.foldr_cons, List.foldr_nil,
    Term.eval, Bool.and_eq_true, decide_eq_true_eq, and_true]
  change ((0 <= scalarValue assignment 1 node /\ scalarValue assignment 1 node <= 4) /\
    0 <= scalarValue assignment 3 node /\ 0 <= scalarValue assignment 4 node /\
    0 <= scalarValue assignment 5 node /\
    (forall index : Int, 0 <= index /\ index < scalarValue assignment 3 node ->
      EntryValid (assignment (.array .int (.array .int (entryTy width))) 6 node index))) <->
    NodeDomain width assignment node
  constructor
  · rintro ⟨role, len, commit, term, entries⟩
    exact ⟨role, len, commit, term, entries⟩
  · intro domain
    exact ⟨domain.role, domain.length, domain.commit, domain.term, domain.entries⟩

noncomputable def initialRow (width : PNat) (assignment : Assignment) (node : Fin width)
    (domain : NodeDomain width assignment node.val) : NativeArrayCheckQuorum.Local (Fin width) Nat :=
  { (NativeArrayCheckQuorum.Local.fresh : NativeArrayCheckQuorum.Local (Fin width) Nat) with
    role := decodeRole ⟨(scalarValue assignment 1 node.val).toNat, by
      have within := domain.role.2
      have nonnegative := Int.toNat_of_nonneg domain.role.1
      omega⟩
    isNewFollower := (read 2 node.val (.boolean true)).eval assignment Locals.empty
    currentTerm := (scalarValue assignment 5 node.val).toNat
    commit := (scalarValue assignment 4 node.val).toNat
    log := {
      length := (scalarValue assignment 3 node.val).toNat
      entries := fun index => modelEntry
        ((entryAt width node.val (.integer index) : Expr (entryTy width)).eval assignment Locals.empty) } }

noncomputable def initialArrays (width : PNat) (assignment : Assignment)
    (domains : forall node : Fin width, NodeDomain width assignment node.val) :
    NativeArrayCheckQuorum.Arrays (Fin width) Nat :=
  fun node => if assignment (.array .int .bool) 0 node.val then
    some (initialRow width assignment node (domains node)) else none

theorem initial_arrays_rep (width : PNat) (assignment : Assignment)
    (domains : forall node : Fin width, NodeDomain width assignment node.val) :
    NodeColumnsRep assignment 1 2 (initialArrays width assignment domains) := by
  constructor
  · intro node
    cases present : assignment (.array .int .bool) 0 node.val <;>
      simp [allocated, Term.eval, initialArrays, present]
  · intro node
    by_cases present : assignment (.array .int .bool) 0 node.val = true
    · simp [initialArrays, NativeArrayCheckQuorum.get, present, initialRow,
        role_code_decode, scalarValue, read, allocated, Term.eval]
      simpa [scalarValue, present] using (domains node).role.1
    · simp [initialArrays, NativeArrayCheckQuorum.get, present, read, allocated,
        Term.eval, NativeArrayCheckQuorum.Local.fresh, NativeArrayCheckQuorum.Local.ofModel,
        freshNodeState, roleCode]
  · intro node
    by_cases present : assignment (.array .int .bool) 0 node.val = true
    · simp [initialArrays, NativeArrayCheckQuorum.get, present, initialRow]
    · simp [initialArrays, NativeArrayCheckQuorum.get, present, read, allocated, Term.eval,
        NativeArrayCheckQuorum.Local.fresh, NativeArrayCheckQuorum.Local.ofModel, freshNodeState]
  · intro node
    by_cases present : assignment (.array .int .bool) 0 node.val = true
    · simp [initialArrays, NativeArrayCheckQuorum.get, present, initialRow,
        scalarValue, read, allocated, Term.eval]
      simpa [scalarValue, present] using (domains node).term
    · simp [initialArrays, NativeArrayCheckQuorum.get, present, read, allocated,
        Term.eval, NativeArrayCheckQuorum.Local.fresh, NativeArrayCheckQuorum.Local.ofModel, freshNodeState]
  · intro node
    by_cases present : assignment (.array .int .bool) 0 node.val = true
    · simp [initialArrays, NativeArrayCheckQuorum.get, present, initialRow,
        scalarValue, commit, read, allocated, Term.eval]
      simpa [scalarValue, present] using (domains node).commit
    · simp [initialArrays, NativeArrayCheckQuorum.get, present, commit, read, allocated,
        Term.eval, NativeArrayCheckQuorum.Local.fresh, NativeArrayCheckQuorum.Local.ofModel, freshNodeState]
  · intro node
    by_cases present : assignment (.array .int .bool) 0 node.val = true
    · simp [initialArrays, NativeArrayCheckQuorum.get, present, initialRow,
        scalarValue, length, read, allocated, Term.eval]
      simpa [scalarValue, present] using (domains node).length
    · simp [initialArrays, NativeArrayCheckQuorum.get, present, length, read, allocated,
        Term.eval, NativeArrayCheckQuorum.Local.fresh, NativeArrayCheckQuorum.Local.ofModel,
        freshNodeState, NativeArrayCheckQuorum.Log.ofList]
  · intro node index within
    by_cases present : assignment (.array .int .bool) 0 node.val = true
    · simp [initialArrays, NativeArrayCheckQuorum.get, present, initialRow]
    · simp [initialArrays, NativeArrayCheckQuorum.get, present,
        NativeArrayCheckQuorum.Local.fresh, NativeArrayCheckQuorum.Local.ofModel,
        freshNodeState, NativeArrayCheckQuorum.Log.ofList] at within

theorem initial_assertions_domains (width : PNat) (assignment : Assignment) :
    Holds (initialAssertions width) assignment <->
      (forall node : Fin width, NodeDomain width assignment node.val) := by
  constructor
  · intro holds node
    apply (initial_node_domains_correct width assignment node.val).mp
    intro formula member
    apply holds formula
    exact List.mem_flatMap.mpr ⟨node.val, List.mem_range.mpr node.isLt, member⟩
  · intro domains formula member
    obtain ⟨node, within, clause⟩ := List.mem_flatMap.mp member
    exact (initial_node_domains_correct width assignment node).mpr
      (domains ⟨node, List.mem_range.mp within⟩) formula clause

theorem initial_assertions_model (width : PNat) [Bootstrap (Fin width)] (assignment : Assignment)
    (holds : Holds (initialAssertions width) assignment) :
    exists (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat) (model : State (Fin width) Nat),
      NodeColumnsRep assignment 1 2 arrays /\ NativeArrayCheckQuorum.Rep arrays model := by
  let domains := (initial_assertions_domains width assignment).mp holds
  let arrays := initialArrays width assignment domains
  exact ⟨arrays, NativeArrayCheckQuorum.realize arrays, initial_arrays_rep width assignment domains,
    NativeArrayCheckQuorum.realize_rep arrays⟩

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
