-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicTransitionProposal

set_option autoImplicit false

namespace CCFRaft.SymbolicTransition

open Symbolic SymbolicModel

-- Active-configuration intersections already exclude inactive nodes.
def replicationSupport (state : State Node Nat) (leader : Node) (index : Nat) : Finset Node :=
  Finset.univ.filter (fun node => node = leader ∨ index ≤ (state.nodes leader).matchIndex node)

def replicationSupportExpr (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty) (leader : Expr nodeCodec.ty) (index : Expr .nat) :
    Expr nodeSetCodec.ty :=
  let value := readLocal bounds.transactionCount state leader
  filterNodeSet (nodeSetCodec.literal Finset.univ) fun node =>
    .or (.eq node leader) (index.le (matchedTo value node))

theorem replicationSupportExpr_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (leader : Expr nodeCodec.ty) (index : Expr .nat) :
    nodeSetCodec.decode ρ (replicationSupportExpr bounds state leader index) =
      replicationSupport (evalEntry bounds ρ state) (nodeCodec.decode ρ leader) (index.eval ρ) := by
  let p := fun node : Node => decide (node = nodeCodec.decode ρ leader ∨ index.eval ρ ≤
    ((evalEntry bounds ρ state).nodes (nodeCodec.decode ρ leader)).matchIndex node)
  have predicate (node : Expr nodeCodec.ty) :
      (Expr.or (.eq node leader) (index.le (matchedTo (readLocal bounds.transactionCount state leader) node))).eval ρ =
        p (nodeCodec.decode ρ node) := by
    apply Bool.eq_iff_iff.mpr
    simp only [boolOr_true ρ, nodeCodec.equal_correct ρ node leader, eval_le,
      matchedTo_correct, readLocal_correct, p, decide_eq_true_eq]
  rw [replicationSupportExpr, filterNodeSet_correct ρ _ _ p predicate, Codec.decode_literal]
  simp only [p, replicationSupport, decide_eq_true_eq]

theorem configuration_fold_contains (configurations : List (Configuration Node)) (initial : Finset Node) :
    initial ⊆ configurations.foldl (fun nodes configuration => nodes ∪ configuration.nodes) initial := by
  induction configurations generalizing initial with
  | nil => exact Finset.Subset.refl _
  | cons head tail ih => exact Finset.Subset.trans Finset.subset_union_left (ih _)

theorem active_configuration_subset (value : NodeState Node Nat) (configuration : Configuration Node)
    (member : configuration ∈ activeConfigurations value) :
    configuration.nodes ⊆ activeNodeUnion value := by
  have included (configurations : List (Configuration Node)) (initial : Finset Node)
      (found : configuration ∈ configurations) :
      configuration.nodes ⊆ configurations.foldl
        (fun nodes configuration => nodes ∪ configuration.nodes) initial := by
    induction configurations generalizing initial with
    | nil => simp at found
    | cons head tail ih =>
        rcases List.mem_cons.mp found with same | later
        · subst head
          exact Finset.Subset.trans Finset.subset_union_right (configuration_fold_contains tail _)
        · exact ih _ later
  exact included (activeConfigurations value) ∅ member

theorem replicationSupport_majority (state : State Node Nat) (leader : Node) (index : Nat)
    (configuration : Configuration Node) (member : configuration ∈ activeConfigurations (state.nodes leader)) :
    hasConfigurationMajority (replicationSupport state leader index) configuration ↔
      hasConfigurationMajority (acknowledgingNodes state leader index) configuration := by
  have subset := active_configuration_subset (state.nodes leader) configuration member
  have intersection :
      replicationSupport state leader index ∩ configuration.nodes =
        acknowledgingNodes state leader index ∩ configuration.nodes := by
    ext node
    simp only [Finset.mem_inter, replicationSupport, acknowledgingNodes, Finset.mem_filter,
      Finset.mem_univ, true_and]
    constructor
    · rintro ⟨supported, configured⟩
      exact ⟨⟨subset configured, supported⟩, configured⟩
    · rintro ⟨⟨_, supported⟩, configured⟩
      exact ⟨supported, configured⟩
  unfold hasConfigurationMajority
  rw [intersection]

theorem hasMajorityAt_replicationSupport (state : State Node Nat) (leader : Node) (index : Nat) :
    ((activeConfigurations (state.nodes leader)).all fun configuration =>
      decide (configuration.index ≤ index →
        hasConfigurationMajority (replicationSupport state leader index) configuration)) = true ↔
      hasMajorityAt state leader index := by
  simp only [hasMajorityAt, List.all_eq_true, decide_eq_true_eq]
  constructor
  · intro supported configuration member earlier
    exact (replicationSupport_majority state leader index configuration member).mp
      (supported configuration member earlier)
  · intro supported configuration member earlier
    exact (replicationSupport_majority state leader index configuration member).mpr
      (supported configuration member earlier)

end CCFRaft.SymbolicTransition
