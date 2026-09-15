-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicTransitionQuorum
import MachineGenerated.SymbolicTransitionVoteSend

set_option autoImplicit false

namespace CCFRaft.SymbolicTransition

open Symbolic SymbolicModel

def matchedTo (value : Expr localCodec.ty) (node : Expr nodeCodec.ty) : Expr .nat :=
  tableSelect value.snd.snd.snd.snd.snd.fst node

theorem matchedTo_correct (ρ : Assignment) (value : Expr localCodec.ty) (node : Expr nodeCodec.ty) :
    (matchedTo value node).eval ρ =
      (BoundedState.decodeLocal (localCodec.decode ρ value)).matchIndex (nodeCodec.decode ρ node) :=
  nodeTableSelect_correct Codec.nat ρ value.snd.snd.snd.snd.snd.fst node

def highestConfigurationStep (node : Expr nodeCodec.ty) (best : Expr .nat)
    (configuration : Expr configurationCodec.ty) : Expr .nat :=
  (Expr.ite (nodeSetContains configuration.snd node) (maximumExpr best configuration.fst) best).normalizeMemo

theorem highestConfigurationStep_correct (ρ : Assignment) (node : Expr nodeCodec.ty)
    (best : Expr .nat) (configuration : Expr configurationCodec.ty) :
    (highestConfigurationStep node best configuration).eval ρ =
      if nodeCodec.decode ρ node ∈ (configurationCodec.decode ρ configuration).nodes then
        max (best.eval ρ) (configurationCodec.decode ρ configuration).index else best.eval ρ := by
  simp only [highestConfigurationStep, Expr.normalizeMemo_correct, Expr.eval,
    maximumExpr_correct]
  have member := nodeSetContains_correct ρ configuration.snd node
  change (nodeSetContains configuration.snd node).eval ρ = true ↔
    nodeCodec.decode ρ node ∈ (configurationCodec.decode ρ configuration).nodes at member
  by_cases h : nodeCodec.decode ρ node ∈ (configurationCodec.decode ρ configuration).nodes
  · rw [if_pos (member.mpr h), if_pos h]
    rfl
  · rw [if_neg (fun present => h (member.mp present)), if_neg h]

def highestConfigurationExpr (capacity : Nat) (value : Expr localCodec.ty) (node : Expr nodeCodec.ty) :
    Expr .nat :=
  foldl (highestConfigurationStep node) (capacity + 1) (.nat 0) (localConfigurations capacity value)

theorem highestConfigurationExpr_correct (ρ : Assignment) (capacity : Nat)
    (value : Expr localCodec.ty) (node : Expr nodeCodec.ty)
    (bound : (localCodec.decode ρ value).log.length ≤ capacity) :
    (highestConfigurationExpr capacity value node).eval ρ =
      highestActiveConfigurationWithNode (BoundedState.decodeLocal (localCodec.decode ρ value))
        (nodeCodec.decode ρ node) := by
  have hb := localConfigurations_bound ρ capacity value bound
  have h := foldl_correct ρ configurationCodec.equiv id (highestConfigurationStep node)
    (fun best configuration =>
      if nodeCodec.decode ρ node ∈ configuration.nodes then max best configuration.index else best)
    (highestConfigurationStep_correct ρ node) (capacity + 1) (.nat 0)
    (localConfigurations capacity value) (by simpa [Codec.decode, Codec.list] using hb)
  change (highestConfigurationExpr capacity value node).eval ρ =
    (configurationCodec.list.decode ρ (localConfigurations capacity value)).foldl _ 0 at h
  rw [localConfigurations_correct ρ capacity value bound] at h
  exact h

def allNodeSet (nodes : Expr nodeSetCodec.ty) (predicate : Expr nodeCodec.ty → Expr .bool) : Expr .bool :=
  .eq (filterNodeSet nodes (fun node => .not (predicate node))) (nodeSetCodec.literal ∅)

theorem allNodeSet_correct (ρ : Assignment) (nodes : Expr nodeSetCodec.ty)
    (predicate : Expr nodeCodec.ty → Expr .bool) (p : Node → Bool)
    (correct : ∀ node, (predicate node).eval ρ = p (nodeCodec.decode ρ node)) :
    (allNodeSet nodes predicate).eval ρ = true ↔
      ∀ node ∈ nodeSetCodec.decode ρ nodes, p node = true := by
  rw [allNodeSet, nodeSetCodec.equal_correct, filterNodeSet_correct ρ nodes _ (fun node => !(p node))
    (by intro node; simp [Expr.eval, correct]), Codec.decode_literal]
  simp [Finset.filter_eq_empty_iff]

def rankComparison (candidateMatch destinationMatch candidateConfiguration destinationConfiguration : Expr .nat) :
    Expr .bool :=
  .and (candidateMatch.le destinationMatch)
    (.or (.not (.eq candidateMatch destinationMatch))
      (candidateConfiguration.le destinationConfiguration))

theorem rankComparison_correct (ρ : Assignment) (a b c d : Expr .nat) :
    (rankComparison a b c d).eval ρ = true ↔
      a.eval ρ ≤ b.eval ρ ∧ (a.eval ρ = b.eval ρ → c.eval ρ ≤ d.eval ρ) := by
  simp [rankComparison, Expr.or, Expr.eval, eval_le]
  tauto

def successorRank (capacity : Nat) (value : Expr localCodec.ty)
    (destination candidate : Expr nodeCodec.ty) : Expr .bool :=
  rankComparison (matchedTo value candidate) (matchedTo value destination)
    (highestConfigurationExpr capacity value candidate) (highestConfigurationExpr capacity value destination)

theorem successorRank_correct (ρ : Assignment) (capacity : Nat) (value : Expr localCodec.ty)
    (destination candidate : Expr nodeCodec.ty) (bound : (localCodec.decode ρ value).log.length ≤ capacity) :
    (successorRank capacity value destination candidate).eval ρ = true ↔
      let before := BoundedState.decodeLocal (localCodec.decode ρ value)
      before.matchIndex (nodeCodec.decode ρ candidate) ≤ before.matchIndex (nodeCodec.decode ρ destination) ∧
        (before.matchIndex (nodeCodec.decode ρ candidate) = before.matchIndex (nodeCodec.decode ρ destination) →
          highestActiveConfigurationWithNode before (nodeCodec.decode ρ candidate) ≤
            highestActiveConfigurationWithNode before (nodeCodec.decode ρ destination)) := by
  rw [successorRank, rankComparison_correct]
  simp only [matchedTo_correct,
    highestConfigurationExpr_correct ρ capacity value candidate bound,
    highestConfigurationExpr_correct ρ capacity value destination bound]

def plausibleSuccessorExpr (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty) (source destination : Expr nodeCodec.ty) : Expr .bool :=
  let value := readLocal bounds.transactionCount state source
  let candidates := setErase (localActiveNodes bounds.logCapacity value) (finValue source)
  .and (nodeSetContains candidates destination)
    (allNodeSet candidates (successorRank bounds.logCapacity value destination))

theorem plausibleSuccessorExpr_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (source destination : Expr nodeCodec.ty)
    (within : BoundedState.WithinBounds bounds (evalEntry bounds ρ state)) :
    (plausibleSuccessorExpr bounds state source destination).eval ρ = true ↔
      plausibleSuccessor (evalEntry bounds ρ state) (nodeCodec.decode ρ source) (nodeCodec.decode ρ destination) := by
  let value := readLocal bounds.transactionCount state source
  have hb := readLocal_log_bound bounds ρ state source within
  let p := fun candidate : Node => decide (
    ((evalEntry bounds ρ state).nodes (nodeCodec.decode ρ source)).matchIndex candidate ≤
      ((evalEntry bounds ρ state).nodes (nodeCodec.decode ρ source)).matchIndex (nodeCodec.decode ρ destination) ∧
    (((evalEntry bounds ρ state).nodes (nodeCodec.decode ρ source)).matchIndex candidate =
      ((evalEntry bounds ρ state).nodes (nodeCodec.decode ρ source)).matchIndex (nodeCodec.decode ρ destination) →
      highestActiveConfigurationWithNode ((evalEntry bounds ρ state).nodes (nodeCodec.decode ρ source)) candidate ≤
        highestActiveConfigurationWithNode ((evalEntry bounds ρ state).nodes (nodeCodec.decode ρ source))
          (nodeCodec.decode ρ destination)))
  have predicate (candidate : Expr nodeCodec.ty) :
      (successorRank bounds.logCapacity value destination candidate).eval ρ = p (nodeCodec.decode ρ candidate) := by
    apply Bool.eq_iff_iff.mpr
    rw [successorRank_correct ρ bounds.logCapacity value destination candidate hb]
    simp only [value, readLocal_correct, p, decide_eq_true_eq]
  change (Expr.and
    (nodeSetContains (setErase (localActiveNodes bounds.logCapacity value) (finValue source)) destination)
    (allNodeSet (setErase (localActiveNodes bounds.logCapacity value) (finValue source))
      (successorRank bounds.logCapacity value destination))).eval ρ = true ↔ _
  simp only [boolAnd_true ρ, nodeSetContains_correct ρ,
    allNodeSet_correct ρ _ _ p predicate, eraseNode_correct, localActiveNodes_correct ρ bounds.logCapacity value hb,
    value,
    readLocal_correct, p, decide_eq_true_eq, plausibleSuccessor]

def proposalEnabled (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty) (source destination : Expr nodeCodec.ty) : Expr .bool :=
  .and (allocated bounds.transactionCount state source)
    (.and (allocated bounds.transactionCount state destination)
      (.and (.eq (readLocal bounds.transactionCount state source).fst (roleCodec.literal .leader))
        (plausibleSuccessorExpr bounds state source destination)))

theorem proposalEnabled_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (source destination : Expr nodeCodec.ty)
    (within : BoundedState.WithinBounds bounds (evalEntry bounds ρ state)) :
    (proposalEnabled bounds state source destination).eval ρ = true ↔
      Enabled (evalEntry bounds ρ state) (.proposeVote (nodeCodec.decode ρ source) (nodeCodec.decode ρ destination)) := by
  have role := congrArg NodeState.role (readLocal_correct bounds ρ state source)
  change roleCodec.decode ρ (readLocal bounds.transactionCount state source).fst = _ at role
  simp only [proposalEnabled, boolAnd_true ρ, allocated_correct bounds ρ,
    roleCodec.equal_correct ρ (readLocal bounds.transactionCount state source).fst (roleCodec.literal .leader),
    Codec.decode_literal, role, plausibleSuccessorExpr_correct bounds ρ state source destination within, Enabled]

def proposalMessage (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty) (source destination : Expr nodeCodec.ty) : Expr messageCodec.ty :=
  .inr (.inr (.inr (.inr (.inr (.inr
    (.pair (readLocal bounds.transactionCount state source).snd.fst (.pair source destination)))))))

theorem proposalMessage_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (source destination : Expr nodeCodec.ty) :
    messageCodec.decode ρ (proposalMessage bounds state source destination) =
      .proposeVoteRequest (makeProposeVoteRequest (evalEntry bounds ρ state)
        (nodeCodec.decode ρ source) (nodeCodec.decode ρ destination)) := by
  have term := congrArg NodeState.currentTerm (readLocal_correct bounds ρ state source)
  change (readLocal bounds.transactionCount state source).snd.fst.eval ρ = _ at term
  change Message.proposeVoteRequest
    (ProposeVoteRequest.mk ((readLocal bounds.transactionCount state source).snd.fst.eval ρ)
      (nodeCodec.decode ρ source) (nodeCodec.decode ρ destination)) = _
  rw [term]
  rfl

def proposalNext (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty) (source destination : Expr nodeCodec.ty) :
    Expr (stateCodec bounds.transactionCount).ty :=
  (SymbolicReceive.enqueue bounds.transactionCount state (proposalMessage bounds state source destination).normalizeMemo).normalizeMemo

theorem proposalNext_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (source destination : Expr nodeCodec.ty) :
    evalEntry bounds ρ (proposalNext bounds state source destination) =
      next (evalEntry bounds ρ state) (.proposeVote (nodeCodec.decode ρ source) (nodeCodec.decode ρ destination)) := by
  rw [proposalNext, evalEntry_normalizeMemo, SymbolicReceive.enqueue_correct, decode_normalizeMemo, proposalMessage_correct]
  rfl

def proposalAccepted (bounds : BoundedState.Bounds)
    (state : Expr (stateCodec bounds.transactionCount).ty) (source destination : Expr nodeCodec.ty) : Expr .bool :=
  .and (proposalEnabled bounds state source destination) (stateWithin bounds (proposalNext bounds state source destination))

theorem proposalAccepted_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (state : Expr (stateCodec bounds.transactionCount).ty) (source destination : Expr nodeCodec.ty)
    (within : BoundedState.WithinBounds bounds (evalEntry bounds ρ state)) :
    (proposalAccepted bounds state source destination).eval ρ = true ↔
      Enabled (evalEntry bounds ρ state) (.proposeVote (nodeCodec.decode ρ source) (nodeCodec.decode ρ destination)) ∧
      BoundedState.WithinBounds bounds
        (next (evalEntry bounds ρ state) (.proposeVote (nodeCodec.decode ρ source) (nodeCodec.decode ρ destination))) := by
  simp only [proposalAccepted, boolAnd_true ρ, proposalEnabled_correct bounds ρ state source destination within,
    stateWithin_correct bounds ρ, proposalNext_correct]

end CCFRaft.SymbolicTransition
