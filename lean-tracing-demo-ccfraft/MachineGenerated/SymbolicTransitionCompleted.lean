-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicTransitionRetirement
import MachineGenerated.SymbolicTransitionNormalize

set_option autoImplicit false

namespace CCFRaft.SymbolicTransition

open Symbolic SymbolicModel

def filterNodeSet (nodes : Expr nodeSetCodec.ty) (predicate : Expr nodeCodec.ty → Expr .bool) :
    Expr nodeSetCodec.ty :=
  tableExpr (fun node => andLazy (tableGet nodes node) (fun _ => predicate (nodeCodec.literal node)))

theorem filterNodeSet_correct (ρ : Assignment) (nodes : Expr nodeSetCodec.ty)
    (predicate : Expr nodeCodec.ty → Expr .bool) (p : Node → Bool)
    (correct : ∀ node, (predicate node).eval ρ = p (nodeCodec.decode ρ node)) :
    nodeSetCodec.decode ρ (filterNodeSet nodes predicate) =
      (nodeSetCodec.decode ρ nodes).filter (fun node => p node) := by
  ext node
  have hp := correct (nodeCodec.literal node)
  rw [Codec.decode_literal] at hp
  simp [filterNodeSet, Codec.decode, Codec.finset, Codec.transport, Codec.table, Codec.bool,
    andLazy_correct, Expr.eval, hp]

def previouslyConfiguredStep (current : Expr .nat)
    (nodes : Expr nodeSetCodec.ty) (configuration : Expr configurationCodec.ty) : Expr nodeSetCodec.ty :=
  (Expr.ite (.lt configuration.fst current) (setUnion nodes configuration.snd) nodes).normalizeMemo

theorem previouslyConfiguredStep_correct (ρ : Assignment) (current : Expr .nat)
    (nodes : Expr nodeSetCodec.ty) (configuration : Expr configurationCodec.ty) :
    nodeSetCodec.decode ρ (previouslyConfiguredStep current nodes configuration) =
      if (configurationCodec.decode ρ configuration).index < current.eval ρ then
        nodeSetCodec.decode ρ nodes ∪ (configurationCodec.decode ρ configuration).nodes
      else nodeSetCodec.decode ρ nodes := by
  rw [previouslyConfiguredStep, decode_normalizeMemo, decode_choose, setUnion_correct]
  simp only [Expr.eval, decide_eq_true_eq]
  rfl

def previouslyConfiguredExpr (capacity : Nat) (log : Expr logCodec.ty) (current : Expr .nat) :
    Expr nodeSetCodec.ty :=
  foldl (previouslyConfiguredStep current) (capacity + 1) (nodeSetCodec.literal ∅)
    (allConfigurationExpr capacity log).normalizeMemo

theorem previouslyConfiguredExpr_correct (ρ : Assignment) (capacity : Nat)
    (log : Expr logCodec.ty) (current : Expr .nat)
    (bound : (logCodec.decode ρ log).length ≤ capacity) :
    nodeSetCodec.decode ρ (previouslyConfiguredExpr capacity log current) =
      (allConfigurations (logCodec.decode ρ log)).foldl
        (fun nodes configuration =>
          if configuration.index < current.eval ρ then nodes ∪ configuration.nodes else nodes) ∅ := by
  have hb := allConfigurationExpr_bound ρ capacity log bound
  have h := foldl_correct ρ configurationCodec.equiv nodeSetCodec.equiv
    (previouslyConfiguredStep current)
    (fun nodes configuration =>
      if configuration.index < current.eval ρ then nodes ∪ configuration.nodes else nodes)
    (previouslyConfiguredStep_correct ρ current) (capacity + 1) (nodeSetCodec.literal ∅)
    (allConfigurationExpr capacity log).normalizeMemo
    (by simpa [Codec.decode, Codec.list, Expr.normalizeMemo_correct] using hb)
  change nodeSetCodec.decode ρ (previouslyConfiguredExpr capacity log current) =
    (configurationCodec.list.decode ρ (allConfigurationExpr capacity log).normalizeMemo).foldl _
      (nodeSetCodec.decode ρ (nodeSetCodec.literal ∅)) at h
  simpa only [decode_normalizeMemo, allConfigurationExpr_correct ρ capacity log bound,
    Codec.decode_literal] using h

def retirementCompletedNodesExpr (capacity : Nat) (log : Expr logCodec.ty) (commit : Expr .nat) :
    Expr nodeSetCodec.ty :=
  let current := (currentConfigurationExpr capacity log commit).normalizeMemo
  let previous := (previouslyConfiguredExpr capacity log current.fst).normalizeMemo
  let retired := (committedRetiredNodesExpr capacity commit (.nat 1) log).normalizeMemo
  let candidates := (setDifference (setDifference previous current.snd) retired).normalizeMemo
  let logPrefix := takeCompact commit log
  filterNodeSet candidates (fun node => isSome (retirementIndexExpr capacity node logPrefix))

theorem retirementCompletedNodesExpr_correct (ρ : Assignment) (capacity : Nat)
    (log : Expr logCodec.ty) (commit : Expr .nat)
    (bound : (logCodec.decode ρ log).length ≤ capacity) :
    nodeSetCodec.decode ρ (retirementCompletedNodesExpr capacity log commit) =
      retirementCompletedNodes (logCodec.decode ρ log) (commit.eval ρ) := by
  have hprefix : logCodec.decode ρ (takeCompact commit log) =
      (logCodec.decode ρ log).take (commit.eval ρ) := by
    simp [Codec.decode, Codec.list, takeCompact_correct, List.map_take]
  have hb : (logCodec.decode ρ (takeCompact commit log)).length ≤ capacity := by
    rw [hprefix]
    simp only [List.length_take]
    exact (Nat.min_le_right _ _).trans bound
  have predicate (node : Expr nodeCodec.ty) :
      (isSome (retirementIndexExpr capacity node (takeCompact commit log))).eval ρ =
        (retirementIndexInLog (nodeCodec.decode ρ node)
          ((logCodec.decode ρ log).take (commit.eval ρ))).isSome := by
    rw [isSome_value, retirementIndexExpr_correct ρ capacity node _ hb, hprefix]
  have current := currentConfigurationExpr_correct ρ capacity log commit bound
  have hindex : (currentConfigurationExpr capacity log commit).normalizeMemo.fst.eval ρ =
      (currentConfigurationAt (logCodec.decode ρ log) (commit.eval ρ)).index := by
    simpa only [Expr.eval, Expr.normalizeMemo_correct] using congrArg Configuration.index current
  simp only [Expr.eval] at hindex
  have hnodes : nodeSetCodec.decode ρ (currentConfigurationExpr capacity log commit).normalizeMemo.snd =
      (currentConfigurationAt (logCodec.decode ρ log) (commit.eval ρ)).nodes := by
    simpa only [Codec.decode, Expr.eval, Expr.normalizeMemo_correct] using
      congrArg Configuration.nodes current
  rw [retirementCompletedNodesExpr, filterNodeSet_correct ρ _ _
    (fun node => (retirementIndexInLog node ((logCodec.decode ρ log).take (commit.eval ρ))).isSome)
    predicate]
  simp only [decode_normalizeMemo, setDifference_correct,
    previouslyConfiguredExpr_correct ρ capacity log _ bound,
    committedRetiredNodesExpr_correct ρ capacity commit (.nat 1) log bound, hindex, hnodes, Expr.eval]
  rfl

def setCompletedData {transactions : Nat} (state : EntryData transactions)
    (node : Node) (nodes : Finset Node) : EntryData transactions :=
  (state.1, state.2.1, state.2.2.1, state.2.2.2.1, state.2.2.2.2.1,
    Vector.ofFn (fun candidate => if node = candidate then nodes else state.2.2.2.2.2.get candidate))

theorem setCompletedData_correct {transactions : Nat} (state : EntryData transactions)
    (node : Node) (nodes : Finset Node) :
    BoundedState.decode (setCompletedData state node nodes).toData =
      { BoundedState.decode state.toData with
        retirementCompleted := Function.update (BoundedState.decode state.toData).retirementCompleted node nodes } := by
  apply state_ext
  · intro candidate
    simp [State.node?, BoundedState.decode, EntryData.toData, setCompletedData]
  · rfl
  · rfl
  · rfl
  · rfl
  · funext candidate
    simp [BoundedState.decode, EntryData.toData, setCompletedData, BoundedState.NodeTable.get,
      Function.update_apply, eq_comm]

def setCompletedExpr (transactions : Nat) (state : Expr (stateCodec transactions).ty)
    (node : Expr nodeCodec.ty) (nodes : Expr nodeSetCodec.ty) : Expr (stateCodec transactions).ty :=
  .pair state.fst (.pair state.snd.fst (.pair state.snd.snd.fst
    (.pair state.snd.snd.snd.fst (.pair state.snd.snd.snd.snd.fst
      (tableStore state.snd.snd.snd.snd.snd (finValue node) nodes)))))

theorem setCompletedExpr_decode (transactions : Nat) (ρ : Assignment)
    (state : Expr (stateCodec transactions).ty) (node : Expr nodeCodec.ty) (nodes : Expr nodeSetCodec.ty) :
    (stateCodec transactions).decode ρ (setCompletedExpr transactions state node nodes) =
      setCompletedData ((stateCodec transactions).decode ρ state)
        (nodeCodec.decode ρ node) (nodeSetCodec.decode ρ nodes) := by
  apply Prod.ext
  · rfl
  apply Prod.ext
  · rfl
  apply Prod.ext
  · rfl
  apply Prod.ext
  · rfl
  apply Prod.ext
  · rfl
  apply Vector.ext
  intro i hi
  have h := nodeTableStore_correct nodeSetCodec ρ state.snd.snd.snd.snd.snd node nodes ⟨i, hi⟩
  simpa only [setCompletedData, BoundedState.NodeTable.get, Vector.get, Vector.getElem_ofFn] using h

theorem setCompletedExpr_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty)
    (node : Expr nodeCodec.ty) (nodes : Expr nodeSetCodec.ty) :
    evalEntry bounds ρ (setCompletedExpr bounds.transactionCount state node nodes) =
      { evalEntry bounds ρ state with
        retirementCompleted := Function.update (evalEntry bounds ρ state).retirementCompleted
          (nodeCodec.decode ρ node) (nodeSetCodec.decode ρ nodes) } := by
  unfold evalEntry
  rw [setCompletedExpr_decode]
  exact setCompletedData_correct _ _ _

def refreshCompletedExpr (bounds : BoundedState.Bounds) (capacity : Nat)
    (state : Expr (stateCodec bounds.transactionCount).ty)
    (node : Expr nodeCodec.ty) (value : Expr localCodec.ty) : Expr (stateCodec bounds.transactionCount).ty :=
  setCompletedExpr bounds.transactionCount state node
    (retirementCompletedNodesExpr capacity value.snd.snd.fst.normalizeMemo value.snd.snd.snd.fst).normalizeMemo

theorem refreshCompletedExpr_correct (bounds : BoundedState.Bounds) (ρ : Assignment) (capacity : Nat)
    (state : Expr (stateCodec bounds.transactionCount).ty)
    (node : Expr nodeCodec.ty) (value : Expr localCodec.ty)
    (bound : (localCodec.decode ρ value).log.length ≤ capacity) :
    evalEntry bounds ρ (refreshCompletedExpr bounds capacity state node value) =
      { evalEntry bounds ρ state with
        retirementCompleted := refreshRetirementCompleted (evalEntry bounds ρ state).retirementCompleted
          (nodeCodec.decode ρ node) (BoundedState.decodeLocal (localCodec.decode ρ value)) } := by
  have hb : (logCodec.decode ρ value.snd.snd.fst.normalizeMemo).length ≤ capacity := by
    rw [decode_normalizeMemo]
    exact bound
  rw [refreshCompletedExpr, setCompletedExpr_correct, decode_normalizeMemo,
    retirementCompletedNodesExpr_correct ρ capacity _ _ hb]
  simp only [decode_normalizeMemo]
  rfl

end CCFRaft.SymbolicTransition
