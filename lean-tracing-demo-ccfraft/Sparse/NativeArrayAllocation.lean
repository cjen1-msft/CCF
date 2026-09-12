-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayCheckQuorum

set_option autoImplicit false

namespace CCFRaft.NativeArrayAllocation

open NativeArrayCheckQuorum

variable {N T : Type} [DecidableEq N] [DecidableEq T] [Bootstrap N]

def allocate (arrays : Arrays N T) (added : Finset N) : Arrays N T :=
  fun node => match arrays node with
    | some row => some row
    | none => if node ∈ added then some Local.fresh else none

omit [DecidableEq T] [Bootstrap N] in
theorem allocated_correct (arrays : Arrays N T) (added : Finset N) (node : N) :
    (allocate arrays added node).isSome = true <-> (arrays node).isSome = true \/ node ∈ added := by
  cases found : arrays node <;> simp [allocate, found]

omit [DecidableEq T] [Bootstrap N] in
theorem get_allocate (arrays : Arrays N T) (added : Finset N) (node : N) :
    get (allocate arrays added) node = get arrays node := by
  cases found : arrays node with
  | none =>
    by_cases member : node ∈ added <;> simp [allocate, NativeArrayCheckQuorum.get, found, member]
  | some row => simp [allocate, NativeArrayCheckQuorum.get, found]

omit [DecidableEq T] [Bootstrap N] in
theorem node_store_missing (nodes : NodeStore N T) (added : Finset N) (node : N)
    (missing : nodes.node? node = none) (notAdded : node ∉ added) :
    (nodes.allocate added).node? node = none := by
  have notIn : node ∉ nodes.entries := by
    rw [<- Finmap.lookup_eq_none]
    exact missing
  simp only [NodeStore.node?, NodeStore.allocate]
  rw [Finmap.lookup_union_right notIn]
  exact NodeStore.node?_ofFinset_of_not_mem added (fun _ => freshNodeState) node notAdded

theorem allocate_rep (arrays : Arrays N T) (state : State N T) (rep : Rep arrays state) (added : Finset N) :
    Rep (allocate arrays added) { state with nodes := state.nodes.allocate added } := by
  intro node
  have related := rep node
  cases found : arrays node with
  | some row =>
    have present : state.nodes.allocated node :=
      (allocated_rep arrays state rep node).mp (by simp [found])
    simpa only [allocate, found, State.node?, NodeStore.node?_allocate_of_allocated _ _ _ present] using related
  | none =>
    have missing : state.nodes.node? node = none := by
      cases right : state.node? node <;> simp_all [State.node?]
    have absent : Not (state.nodes.allocated node) := by simp [NodeStore.allocated, missing]
    by_cases member : node ∈ added
    · simp [allocate, found, member, State.node?,
        NodeStore.node?_allocate_of_not_allocated_of_mem _ _ _ absent member,
        Local.Rep, Local.fresh, Local.ofModel, Local.toModel]
    · simp [allocate, found, member, State.node?, node_store_missing _ _ _ missing member]

end CCFRaft.NativeArrayAllocation

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeArrayAllocation).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
