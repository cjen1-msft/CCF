-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicTransitionAllocation
import MachineGenerated.SymbolicTransitionSignature

set_option autoImplicit false

namespace CCFRaft.SymbolicTransition

open Symbolic SymbolicModel

theorem boolAnd_true (ρ : Assignment) (a b : Expr .bool) :
    (Expr.and a b).eval ρ = true ↔ a.eval ρ = true ∧ b.eval ρ = true := by simp [Expr.eval]

theorem boolOr_true (ρ : Assignment) (a b : Expr .bool) :
    (Expr.or a b).eval ρ = true ↔ a.eval ρ = true ∨ b.eval ρ = true := by simp [Expr.or, Expr.eval]

theorem boolNot_true (ρ : Assignment) (a : Expr .bool) :
    (Expr.not a).eval ρ = true ↔ ¬a.eval ρ = true := by simp [Expr.eval]

theorem all_decode {α : Type} (c : Codec α) (ρ : Assignment) (capacity : Nat)
    (p : Expr c.ty → Expr .bool) (q : α → Bool)
    (correct : ∀ x, (p x).eval ρ = q (c.decode ρ x))
    (values : Expr c.list.ty) (bound : (c.list.decode ρ values).length ≤ capacity) :
    (Container.all capacity p values).eval ρ = (c.list.decode ρ values).all q := by
  have hb : (values.eval ρ).length ≤ capacity := by simpa [Codec.decode, Codec.list] using bound
  rw [Container.all_correct ρ capacity p (fun x => q (c.equiv x)) correct values hb]
  change (values.eval ρ).all (fun x => q (c.equiv x)) = ((values.eval ρ).map c.equiv).all q
  induction values.eval ρ <;> simp_all

def anyExpr {a : Ty} (capacity : Nat) (p : Expr a → Expr .bool) (values : Expr (.seq a)) : Expr .bool :=
  Container.foldr (fun x rest => (p x).or rest) (.bool false) capacity values

theorem any_decode {α : Type} (c : Codec α) (ρ : Assignment) (capacity : Nat)
    (p : Expr c.ty → Expr .bool) (q : α → Bool)
    (correct : ∀ x, (p x).eval ρ = q (c.decode ρ x))
    (values : Expr c.list.ty) (bound : (c.list.decode ρ values).length ≤ capacity) :
    (anyExpr capacity p values).eval ρ = (c.list.decode ρ values).any q := by
  have hb : (values.eval ρ).length ≤ capacity := by simpa [Codec.decode, Codec.list] using bound
  rw [anyExpr, Container.foldr_correct ρ _ _
    (fun x rest => q (c.equiv x) || rest)
    (fun x rest => by simp [Expr.or, Expr.eval, correct, Codec.decode]) capacity values hb]
  change (values.eval ρ).foldr (fun x rest => q (c.equiv x) || rest) false =
    ((values.eval ρ).map c.equiv).any q
  induction values.eval ρ <;> simp_all

def localConfigurations (capacity : Nat) (value : Expr localCodec.ty) : Expr configurationCodec.list.ty :=
  (activeConfigurationExpr capacity value.snd.snd.fst.normalizeMemo value.snd.snd.snd.fst).normalizeMemo

theorem localConfigurations_correct (ρ : Assignment) (capacity : Nat) (value : Expr localCodec.ty)
    (bound : (localCodec.decode ρ value).log.length ≤ capacity) :
    configurationCodec.list.decode ρ (localConfigurations capacity value) =
      activeConfigurations (BoundedState.decodeLocal (localCodec.decode ρ value)) := by
  rw [localConfigurations, decode_normalizeMemo]
  exact activeConfigurationExpr_correct ρ capacity _ _
    (BoundedState.decodeLocal (localCodec.decode ρ value))
    (by rw [decode_normalizeMemo]; rfl) rfl bound

theorem localConfigurations_bound (ρ : Assignment) (capacity : Nat) (value : Expr localCodec.ty)
    (bound : (localCodec.decode ρ value).log.length ≤ capacity) :
    (configurationCodec.list.decode ρ (localConfigurations capacity value)).length ≤ capacity + 1 := by
  rw [localConfigurations_correct ρ capacity value bound]
  have hb := Nat.succ_le_succ ((configurations_length 1 (localCodec.decode ρ value).log).trans bound)
  exact (List.length_filter_le _ _).trans (by simpa [allConfigurations, configurationsInLog] using hb)

def localActiveNodes (capacity : Nat) (value : Expr localCodec.ty) : Expr nodeSetCodec.ty :=
  (activeNodeUnionExpr capacity value.snd.snd.fst.normalizeMemo value.snd.snd.snd.fst).normalizeMemo

theorem localActiveNodes_correct (ρ : Assignment) (capacity : Nat) (value : Expr localCodec.ty)
    (bound : (localCodec.decode ρ value).log.length ≤ capacity) :
    nodeSetCodec.decode ρ (localActiveNodes capacity value) =
      activeNodeUnion (BoundedState.decodeLocal (localCodec.decode ρ value)) := by
  rw [localActiveNodes, decode_normalizeMemo]
  exact activeNodeUnionExpr_correct ρ capacity _ _
    (BoundedState.decodeLocal (localCodec.decode ρ value))
    (by rw [decode_normalizeMemo]; rfl) rfl bound

def campaignExpr (capacity : Nat) (node : Expr nodeCodec.ty) (value : Expr localCodec.ty) : Expr .bool :=
  let frontier := (maxCommittableExpr capacity value.snd.snd.fst.normalizeMemo).normalizeMemo
  anyExpr (capacity + 1) (fun configuration =>
    .and (nodeSetContains configuration.snd node) (configuration.fst.le frontier))
    (localConfigurations capacity value)

theorem campaignExpr_correct (ρ : Assignment) (capacity : Nat) (node : Expr nodeCodec.ty)
    (value : Expr localCodec.ty) (bound : (localCodec.decode ρ value).log.length ≤ capacity) :
    (campaignExpr capacity node value).eval ρ = true ↔
      campaignEligible (nodeCodec.decode ρ node) (BoundedState.decodeLocal (localCodec.decode ρ value)) := by
  have hb : (logCodec.decode ρ value.snd.snd.fst.normalizeMemo).length ≤ capacity := by
    rw [decode_normalizeMemo]; exact bound
  have frontier : (maxCommittableExpr capacity value.snd.snd.fst.normalizeMemo).normalizeMemo.eval ρ =
      maxCommittableIndex (localCodec.decode ρ value).log := by
    rw [Expr.normalizeMemo_correct, maxCommittableExpr_correct ρ capacity _ hb, decode_normalizeMemo]
    rfl
  have predicate (configuration : Expr configurationCodec.ty) :
      (Expr.and (nodeSetContains configuration.snd node)
        (configuration.fst.le (maxCommittableExpr capacity value.snd.snd.fst.normalizeMemo).normalizeMemo)).eval ρ =
      decide (nodeCodec.decode ρ node ∈ (configurationCodec.decode ρ configuration).nodes ∧
        (configurationCodec.decode ρ configuration).index ≤ maxCommittableIndex (localCodec.decode ρ value).log) := by
    apply Bool.eq_iff_iff.mpr
    simp only [boolAnd_true ρ, nodeSetContains_correct ρ configuration.snd node,
      eval_le, frontier, decide_eq_true_eq]
    rfl
  have h := any_decode configurationCodec ρ (capacity + 1) _
    (fun configuration => decide (nodeCodec.decode ρ node ∈ configuration.nodes ∧
      configuration.index ≤ maxCommittableIndex (localCodec.decode ρ value).log)) predicate _
    (localConfigurations_bound ρ capacity value bound)
  rw [localConfigurations_correct ρ capacity value bound] at h
  exact Bool.eq_iff_iff.mp h

def configurationMajorities (capacity : Nat) (support : Expr nodeSetCodec.ty) (value : Expr localCodec.ty) :
    Expr .bool :=
  Container.all (capacity + 1) (fun configuration => majority support configuration.snd)
    (localConfigurations capacity value)

theorem configurationMajorities_correct (ρ : Assignment) (capacity : Nat)
    (support : Expr nodeSetCodec.ty) (value : Expr localCodec.ty)
    (bound : (localCodec.decode ρ value).log.length ≤ capacity) :
    (configurationMajorities capacity support value).eval ρ =
      (activeConfigurations (BoundedState.decodeLocal (localCodec.decode ρ value))).all
        (fun configuration => decide (hasConfigurationMajority (nodeSetCodec.decode ρ support) configuration)) := by
  have predicate (configuration : Expr configurationCodec.ty) :
      (majority support configuration.snd).eval ρ =
      decide (hasConfigurationMajority (nodeSetCodec.decode ρ support) (configurationCodec.decode ρ configuration)) := by
    apply Bool.eq_iff_iff.mpr
    rw [majority_correct, decide_eq_true_eq]
    rfl
  have h := all_decode configurationCodec ρ (capacity + 1) _
    (fun configuration => decide (hasConfigurationMajority (nodeSetCodec.decode ρ support) configuration)) predicate _
    (localConfigurations_bound ρ capacity value bound)
  rw [localConfigurations_correct ρ capacity value bound] at h
  exact h

def readPreVote (transactions : Nat) (state : Expr (stateCodec transactions).ty) (node : Expr nodeCodec.ty) :
    Expr preVoteCodec.ty := tableSelect state.snd.snd.snd.snd.fst node

theorem readPreVote_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty) :
    preVoteCodec.decode ρ (readPreVote bounds.transactionCount state node) =
      (evalEntry bounds ρ state).preVoteStatus (nodeCodec.decode ρ node) :=
  nodeTableSelect_correct preVoteCodec ρ state.snd.snd.snd.snd.fst node

def readCompleted (transactions : Nat) (state : Expr (stateCodec transactions).ty) (node : Expr nodeCodec.ty) :
    Expr nodeSetCodec.ty := tableSelect state.snd.snd.snd.snd.snd node

theorem readCompleted_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty) :
    nodeSetCodec.decode ρ (readCompleted bounds.transactionCount state node) =
      (evalEntry bounds ρ state).retirementCompleted (nodeCodec.decode ρ node) :=
  nodeTableSelect_correct nodeSetCodec ρ state.snd.snd.snd.snd.snd node

def campaignSupport (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty) : Expr .bool :=
  let value := readLocal bounds.transactionCount state node
  (Expr.and (nodeSetContains (localActiveNodes bounds.logCapacity value) node)
    (campaignExpr bounds.logCapacity node value)).or
    (nodeSetContains (readCompleted bounds.transactionCount state node) node)

theorem campaignSupport_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty)
    (within : BoundedState.WithinBounds bounds (evalEntry bounds ρ state)) :
    (campaignSupport bounds state node).eval ρ = true ↔
      (nodeCodec.decode ρ node ∈ activeNodeUnion ((evalEntry bounds ρ state).nodes (nodeCodec.decode ρ node)) ∧
        campaignEligible (nodeCodec.decode ρ node) ((evalEntry bounds ρ state).nodes (nodeCodec.decode ρ node))) ∨
        nodeCodec.decode ρ node ∈ (evalEntry bounds ρ state).retirementCompleted (nodeCodec.decode ρ node) := by
  have hb := readLocal_log_bound bounds ρ state node within
  simp only [campaignSupport, boolOr_true ρ, boolAnd_true ρ, nodeSetContains_correct ρ,
    localActiveNodes_correct ρ bounds.logCapacity _ hb, campaignExpr_correct ρ bounds.logCapacity node _ hb,
    readCompleted_correct bounds ρ state node, readLocal_correct bounds ρ state node]

end CCFRaft.SymbolicTransition
