-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicTransitionReplication
import MachineGenerated.SymbolicTransitionNormalize

set_option autoImplicit false

namespace CCFRaft.SymbolicTransition

open Symbolic SymbolicModel

theorem natLt_true (ρ : Assignment) (a b : Expr .nat) :
    (Expr.lt a b).eval ρ = true ↔ a.eval ρ < b.eval ρ := by simp [Expr.eval]

def acknowledgingExpr (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty) (leader : Expr nodeCodec.ty) (index : Expr .nat) :
    Expr nodeSetCodec.ty :=
  let value := readLocal bounds.transactionCount state leader
  filterNodeSet (localActiveNodes bounds.logCapacity value) fun node =>
    .or (.eq node leader) (index.le (matchedTo value node))

theorem acknowledgingExpr_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (leader : Expr nodeCodec.ty) (index : Expr .nat)
    (within : BoundedState.WithinBounds bounds (evalEntry bounds ρ state)) :
    nodeSetCodec.decode ρ (acknowledgingExpr bounds state leader index) =
      acknowledgingNodes (evalEntry bounds ρ state) (nodeCodec.decode ρ leader) (index.eval ρ) := by
  let p := fun node : Node => decide (node = nodeCodec.decode ρ leader ∨ index.eval ρ ≤
    ((evalEntry bounds ρ state).nodes (nodeCodec.decode ρ leader)).matchIndex node)
  have predicate (node : Expr nodeCodec.ty) :
      (Expr.or (.eq node leader) (index.le (matchedTo (readLocal bounds.transactionCount state leader) node))).eval ρ =
        p (nodeCodec.decode ρ node) := by
    apply Bool.eq_iff_iff.mpr
    simp only [boolOr_true ρ, nodeCodec.equal_correct ρ node leader, eval_le,
      matchedTo_correct, readLocal_correct, p, decide_eq_true_eq]
  rw [acknowledgingExpr, filterNodeSet_correct ρ _ _ p predicate,
    localActiveNodes_correct ρ bounds.logCapacity _ (readLocal_log_bound bounds ρ state leader within),
    readLocal_correct]
  dsimp only [p]
  generalize evalEntry bounds ρ state = before
  generalize nodeCodec.decode ρ leader = actor
  generalize index.eval ρ = position
  simp only [acknowledgingNodes, decide_eq_true_eq]

def majorityAtExpr (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty) (leader : Expr nodeCodec.ty) (index : Expr .nat) :
    Expr .bool :=
  let support := replicationSupportExpr bounds state leader index
  Container.all (bounds.logCapacity + 1) (fun configuration =>
    .or (.not (configuration.fst.le index)) (majority support configuration.snd))
    (localConfigurations bounds.logCapacity (readLocal bounds.transactionCount state leader))

theorem majorityAtExpr_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (leader : Expr nodeCodec.ty) (index : Expr .nat)
    (within : BoundedState.WithinBounds bounds (evalEntry bounds ρ state)) :
    (majorityAtExpr bounds state leader index).eval ρ = true ↔
      hasMajorityAt (evalEntry bounds ρ state) (nodeCodec.decode ρ leader) (index.eval ρ) := by
  let p := fun configuration : Configuration Node => decide (configuration.index ≤ index.eval ρ →
    hasConfigurationMajority (replicationSupport (evalEntry bounds ρ state) (nodeCodec.decode ρ leader) (index.eval ρ))
      configuration)
  have predicate (configuration : Expr configurationCodec.ty) :
      (Expr.or (.not (configuration.fst.le index))
        (majority (replicationSupportExpr bounds state leader index) configuration.snd)).eval ρ =
          p (configurationCodec.decode ρ configuration) := by
    apply Bool.eq_iff_iff.mpr
    rw [boolOr_true, boolNot_true, eval_le, decide_eq_true_eq,
      majority_correct, replicationSupportExpr_correct bounds ρ state leader index]
    simp only [p, decide_eq_true_eq]
    change (¬(configurationCodec.decode ρ configuration).index ≤ index.eval ρ ∨
      hasConfigurationMajority (replicationSupport (evalEntry bounds ρ state) (nodeCodec.decode ρ leader) (index.eval ρ))
        (configurationCodec.decode ρ configuration)) ↔ _
    constructor
    · intro either antecedent
      exact either.elim (fun absent => False.elim (absent antecedent)) (fun conclusion => conclusion)
    · intro implication
      by_cases antecedent : (configurationCodec.decode ρ configuration).index ≤ index.eval ρ
      · exact Or.inr (implication antecedent)
      · exact Or.inl antecedent
  have hb := readLocal_log_bound bounds ρ state leader within
  have h := all_decode configurationCodec ρ (bounds.logCapacity + 1) _ p predicate _
    (localConfigurations_bound ρ bounds.logCapacity _ hb)
  rw [localConfigurations_correct ρ bounds.logCapacity _ hb, readLocal_correct] at h
  exact (Bool.eq_iff_iff.mp h).trans
    (hasMajorityAt_replicationSupport (evalEntry bounds ρ state) (nodeCodec.decode ρ leader) (index.eval ρ))

def commitCandidateExpr (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty) (leader : Expr nodeCodec.ty) (index : Expr .nat) :
    Expr .bool :=
  let value := readLocal bounds.transactionCount state leader
  andLazy (.and (.lt value.snd.snd.snd.fst index)
    (.and (signatureAtExpr value.snd.snd.fst index)
      (.eq (termAtExpr value.snd.snd.fst index) value.snd.fst)))
    (fun _ => majorityAtExpr bounds state leader index)

theorem commitCandidateExpr_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (leader : Expr nodeCodec.ty) (index : Expr .nat)
    (within : BoundedState.WithinBounds bounds (evalEntry bounds ρ state)) :
    (commitCandidateExpr bounds state leader index).eval ρ = true ↔
      let before := (evalEntry bounds ρ state).nodes (nodeCodec.decode ρ leader)
      index.eval ρ > before.commitIndex ∧ isSignatureAt before.log (index.eval ρ) = true ∧
        termAt before.log (index.eval ρ) = before.currentTerm ∧
          hasMajorityAt (evalEntry bounds ρ state) (nodeCodec.decode ρ leader) (index.eval ρ) := by
  let value := readLocal bounds.transactionCount state leader
  have logeq := congrArg NodeState.log (readLocal_correct bounds ρ state leader)
  have term := congrArg NodeState.currentTerm (readLocal_correct bounds ρ state leader)
  have commit := congrArg NodeState.commitIndex (readLocal_correct bounds ρ state leader)
  change logCodec.decode ρ value.snd.snd.fst = _ at logeq
  change value.snd.fst.eval ρ = _ at term
  change value.snd.snd.snd.fst.eval ρ = _ at commit
  have newer : (Expr.lt value.snd.snd.snd.fst index).eval ρ = true ↔
      ((evalEntry bounds ρ state).nodes (nodeCodec.decode ρ leader)).commitIndex < index.eval ρ := by
    rw [natLt_true, commit]
  have sameTerm : (Expr.eq (termAtExpr value.snd.snd.fst index) value.snd.fst).eval ρ = true ↔
      termAt ((evalEntry bounds ρ state).nodes (nodeCodec.decode ρ leader)).log (index.eval ρ) =
        ((evalEntry bounds ρ state).nodes (nodeCodec.decode ρ leader)).currentTerm := by
    change decide ((termAtExpr value.snd.snd.fst index).eval ρ = value.snd.fst.eval ρ) = true ↔ _
    rw [termAtExpr_correct, logeq, term, decide_eq_true_eq]
  change (andLazy (.and (.lt value.snd.snd.snd.fst index)
    (.and (signatureAtExpr value.snd.snd.fst index)
      (.eq (termAtExpr value.snd.snd.fst index) value.snd.fst)))
    (fun _ => majorityAtExpr bounds state leader index)).eval ρ = true ↔ _
  rw [andLazy_correct, Bool.and_eq_true]
  simp only [boolAnd_true ρ, newer, sameTerm, signatureAtExpr_correct, logeq,
    majorityAtExpr_correct bounds ρ state leader index within, and_assoc]

def commitScanStep (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty) (leader : Expr nodeCodec.ty)
    (best index : Expr .nat) : Expr .nat :=
  let index := SymbolicReceive.compact index
  SymbolicReceive.compact (.ite (commitCandidateExpr bounds state leader index) (maximumExpr best index) best)

theorem commitScanStep_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (leader : Expr nodeCodec.ty)
    (best index : Expr .nat) (within : BoundedState.WithinBounds bounds (evalEntry bounds ρ state)) :
    (commitScanStep bounds state leader best index).eval ρ =
      let before := (evalEntry bounds ρ state).nodes (nodeCodec.decode ρ leader)
      if index.eval ρ > before.commitIndex ∧ isSignatureAt before.log (index.eval ρ) = true ∧
          termAt before.log (index.eval ρ) = before.currentTerm ∧
          hasMajorityAt (evalEntry bounds ρ state) (nodeCodec.decode ρ leader) (index.eval ρ) then
        max (best.eval ρ) (index.eval ρ) else best.eval ρ := by
  simp only [commitScanStep, SymbolicReceive.compact_correct, Expr.eval, maximumExpr_correct]
  have h := commitCandidateExpr_correct bounds ρ state leader (SymbolicReceive.compact index) within
  simp only [SymbolicReceive.compact_correct] at h
  by_cases yes : (commitCandidateExpr bounds state leader (SymbolicReceive.compact index)).eval ρ = true
  · simp only [if_pos yes, if_pos (h.mp yes)]
  · simp only [if_neg yes, if_neg (fun actual => yes (h.mpr actual))]

def highestCommitExpr (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty) (leader : Expr nodeCodec.ty) : Expr .nat :=
  SymbolicReceive.rangeFold (bounds.logCapacity + 1)
    (.add (readLocal bounds.transactionCount state leader).snd.snd.fst.length (.nat 1))
    (commitScanStep bounds state leader) (.nat 0)

theorem highestCommitExpr_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (leader : Expr nodeCodec.ty)
    (within : BoundedState.WithinBounds bounds (evalEntry bounds ρ state)) :
    (highestCommitExpr bounds state leader).eval ρ =
      highestCommittableIndex (evalEntry bounds ρ state) (nodeCodec.decode ρ leader) := by
  have logeq := congrArg NodeState.log (readLocal_correct bounds ρ state leader)
  change logCodec.decode ρ (readLocal bounds.transactionCount state leader).snd.snd.fst = _ at logeq
  have length : ((readLocal bounds.transactionCount state leader).snd.snd.fst.eval ρ).length =
      ((evalEntry bounds ρ state).nodes (nodeCodec.decode ρ leader)).log.length := by
    simpa [Codec.decode, Codec.list] using congrArg List.length logeq
  have hb : (Expr.add (readLocal bounds.transactionCount state leader).snd.snd.fst.length (.nat 1)).eval ρ ≤
      bounds.logCapacity + 1 := by
    change ((readLocal bounds.transactionCount state leader).snd.snd.fst.eval ρ).length + 1 ≤ _
    rw [length]
    exact Nat.succ_le_succ (model_log_bound bounds _ _ within)
  have h := SymbolicReceive.rangeFold_correct Codec.nat ρ (bounds.logCapacity + 1)
    (.add (readLocal bounds.transactionCount state leader).snd.snd.fst.length (.nat 1))
    (commitScanStep bounds state leader) (.nat 0)
    (fun best index =>
      let before := (evalEntry bounds ρ state).nodes (nodeCodec.decode ρ leader)
      if index > before.commitIndex ∧ isSignatureAt before.log index = true ∧
          termAt before.log index = before.currentTerm ∧
          hasMajorityAt (evalEntry bounds ρ state) (nodeCodec.decode ρ leader) index then max best index else best)
    (fun best index => commitScanStep_correct bounds ρ state leader best index within) hb
  change (highestCommitExpr bounds state leader).eval ρ =
    (List.range (((readLocal bounds.transactionCount state leader).snd.snd.fst.eval ρ).length + 1)).foldl _ 0 at h
  rw [length] at h
  exact h

end CCFRaft.SymbolicTransition
