-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicReceiveRetirement

set_option autoImplicit false
set_option maxHeartbeats 1000000

namespace CCFRaft.SymbolicReceive

open Symbolic SymbolicModel SymbolicTransition

theorem nodeMember_correct (ρ : Assignment) (nodes : Expr nodeSetCodec.ty) (node : Expr nodeCodec.ty) :
    (tableSelect nodes node).eval ρ = true ↔ nodeCodec.decode ρ node ∈ nodeSetCodec.decode ρ nodes := by
  simp [tableSelect_correct, Codec.decode, Codec.finset, Codec.transport, Codec.table, Codec.bool, Codec.fin]
  rfl

def activeConfigs (capacity : Nat) (state : Local) : Expr configurationCodec.list.ty :=
  let current := currentConfig capacity state.log state.commitIndex
  Container.filter (capacity + 1) (fun cfg => current.fst.le cfg.fst) (configurations capacity state.log)

theorem activeConfigs_correct (ρ : Assignment) (capacity : Nat) (state : Local)
    (bound : (logCodec.decode ρ state.log).length ≤ capacity) :
    configurationCodec.list.decode ρ (activeConfigs capacity state) = activeConfigurations (state.eval ρ) := by
  let current := currentConfig capacity state.log state.commitIndex
  let predicate := fun cfg : Configuration Node =>
    decide ((currentConfigurationAt (logCodec.decode ρ state.log) (state.commitIndex.eval ρ)).index ≤ cfg.index)
  have currentCorrect : current.fst.eval ρ =
      (currentConfigurationAt (logCodec.decode ρ state.log) (state.commitIndex.eval ρ)).index :=
    congrArg Configuration.index (currentConfig_correct ρ capacity state.log state.commitIndex bound)
  have h := Container.filter_correct ρ (capacity + 1) (fun cfg => current.fst.le cfg.fst)
    (fun value => predicate (configurationCodec.equiv value)) (by
      intro cfg
      simp only [eval_le, currentCorrect]
      rfl) (configurations capacity state.log) (by
      have h := configurations_bound ρ capacity state.log bound
      simpa [Codec.decode, Codec.list] using h)
  have filtered : (activeConfigs capacity state).eval ρ =
      ((configurations capacity state.log).eval ρ).filter
        (fun value => predicate (configurationCodec.equiv value)) := h
  have mapped : ((configurationCodec.list.decode ρ (configurations capacity state.log)).filter predicate) =
      (((configurations capacity state.log).eval ρ).filter
        (fun value => predicate (configurationCodec.equiv value))).map configurationCodec.equiv := by
    simp [Codec.decode, Codec.list, List.filter_map, Function.comp_def]
  calc
    configurationCodec.list.decode ρ (activeConfigs capacity state) =
        (((configurations capacity state.log).eval ρ).filter
          (fun value => predicate (configurationCodec.equiv value))).map configurationCodec.equiv :=
      congrArg configurationCodec.list.equiv filtered
    _ = (configurationCodec.list.decode ρ (configurations capacity state.log)).filter predicate := mapped.symm
    _ = activeConfigurations (state.eval ρ) := by
      rw [configurations_correct ρ capacity state.log bound]
      rfl

theorem activeConfigs_bound (ρ : Assignment) (capacity : Nat) (state : Local)
    (bound : (logCodec.decode ρ state.log).length ≤ capacity) :
    (configurationCodec.list.decode ρ (activeConfigs capacity state)).length ≤ capacity + 1 := by
  rw [activeConfigs_correct ρ capacity state bound]
  apply le_trans (List.length_filter_le _ _)
  simp only [allConfigurations, configurationsInLog, List.length_cons, Local.eval]
  exact Nat.add_le_add_right (le_trans (configurations_length _ _) bound) 1

def activeUnion (capacity : Nat) (state : Local) : Expr nodeSetCodec.ty :=
  foldl (fun nodes cfg => setUnion nodes cfg.snd) (capacity + 1)
    (nodeSetCodec.literal ∅) (activeConfigs capacity state)

theorem activeUnion_correct (ρ : Assignment) (capacity : Nat) (state : Local)
    (bound : (logCodec.decode ρ state.log).length ≤ capacity) :
    nodeSetCodec.decode ρ (activeUnion capacity state) = activeNodeUnion (state.eval ρ) := by
  have h := decode_foldl configurationCodec nodeSetCodec ρ (capacity + 1)
    (fun nodes cfg => setUnion nodes cfg.snd) (nodeSetCodec.literal ∅) (activeConfigs capacity state)
    (fun nodes cfg => nodes ∪ cfg.nodes) (by intro nodes cfg; rw [setUnion_correct]; rfl)
    (activeConfigs_bound ρ capacity state bound)
  simpa only [activeUnion, activeNodeUnion, activeConfigs_correct ρ capacity state bound,
    Codec.decode_literal] using h

def campaign (capacity : Nat) (state : Local) (node : Expr nodeCodec.ty) : Expr .bool :=
  foldl (fun acc cfg => acc.or
    ((tableSelect cfg.snd node).and (cfg.fst.le (maxCommittable capacity state.log))))
    (capacity + 1) (.bool false) (activeConfigs capacity state)

theorem campaign_correct (ρ : Assignment) (capacity : Nat) (state : Local) (node : Expr nodeCodec.ty)
    (bound : (logCodec.decode ρ state.log).length ≤ capacity) :
    (campaign capacity state node).eval ρ = true ↔ campaignEligible (nodeCodec.decode ρ node) (state.eval ρ) := by
  let predicate := fun cfg : Configuration Node =>
    decide (nodeCodec.decode ρ node ∈ cfg.nodes ∧ cfg.index ≤ maxCommittableIndex (logCodec.decode ρ state.log))
  have step (acc : Expr .bool) (cfg : Expr configurationCodec.ty) :
      (acc.or ((tableSelect cfg.snd node).and (cfg.fst.le (maxCommittable capacity state.log)))).eval ρ =
        (acc.eval ρ || predicate (configurationCodec.decode ρ cfg)) := by
    apply Bool.eq_iff_iff.mpr
    simp only [eval_or, eval_and, Bool.or_eq_true, Bool.and_eq_true, nodeMember_correct ρ,
      eval_le, maxCommittable_correct ρ capacity state.log bound, decide_eq_true_eq]
    simp only [predicate, decide_eq_true_eq]
    rfl
  have h := decode_foldl configurationCodec Codec.bool ρ (capacity + 1)
    (fun acc cfg => acc.or ((tableSelect cfg.snd node).and (cfg.fst.le (maxCommittable capacity state.log))))
    (.bool false) (activeConfigs capacity state) (fun acc cfg => acc || predicate cfg)
    step (activeConfigs_bound ρ capacity state bound)
  have scan (xs : List (Configuration Node)) (base : Bool) :
      xs.foldl (fun acc cfg => acc || predicate cfg) base = (base || xs.any predicate) := by
    induction xs generalizing base with
    | nil => simp
    | cons x xs ih => simp [ih, Bool.or_assoc]
  have result : (campaign capacity state node).eval ρ =
      (configurationCodec.list.decode ρ (activeConfigs capacity state)).foldl
        (fun acc cfg => acc || predicate cfg) false := h
  rw [result, scan, activeConfigs_correct ρ capacity state bound]
  simp only [Codec.decode, Codec.bool, Expr.eval, Equiv.refl_apply, Bool.false_or]
  rfl

def candidacy (bounds : BoundedState.Bounds) (entry : Expr (stateCodec bounds.transactionCount).ty)
    (node : Expr nodeCodec.ty) : Expr .bool :=
  let state := Local.unpack (readLocal bounds.transactionCount entry node)
  (allocated bounds.transactionCount entry node).and
    (((Expr.eq state.role (roleCodec.literal .follower)).or
      ((Expr.eq state.role (roleCodec.literal .preVoteCandidate)).or
        (.eq state.role (roleCodec.literal .candidate)))).and
      ((((tableSelect (activeUnion bounds.logCapacity state) node).and (campaign bounds.logCapacity state node)).or
        (tableSelect (tableSelect entry.snd.snd.snd.snd.snd node) node)).and
        (.not (.eq state.membershipState (membershipCodec.literal .retiredCommitted)))))

theorem candidacy_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (entry : Expr (stateCodec bounds.transactionCount).ty) (node : Expr nodeCodec.ty)
    (bound : ((evalEntry bounds ρ entry).nodes (nodeCodec.decode ρ node)).log.length ≤ bounds.logCapacity) :
    (candidacy bounds entry node).eval ρ = true ↔
      candidateTransitionEnabled (evalEntry bounds ρ entry) (nodeCodec.decode ρ node) := by
  let state := Local.unpack (readLocal bounds.transactionCount entry node)
  have localCorrect : state.eval ρ = (evalEntry bounds ρ entry).nodes (nodeCodec.decode ρ node) :=
    (Local.unpack_correct ρ _).trans (readLocal_correct bounds ρ entry node)
  have logBound : (logCodec.decode ρ state.log).length ≤ bounds.logCapacity := by
    change (state.eval ρ).log.length ≤ bounds.logCapacity
    rw [localCorrect]
    exact bound
  have completed : nodeSetCodec.decode ρ (tableSelect entry.snd.snd.snd.snd.snd node) =
      (evalEntry bounds ρ entry).retirementCompleted (nodeCodec.decode ρ node) :=
    nodeTableSelect_correct nodeSetCodec ρ _ node
  have active := activeUnion_correct ρ bounds.logCapacity
    (Local.unpack (readLocal bounds.transactionCount entry node)) logBound
  have eligible := campaign_correct ρ bounds.logCapacity
    (Local.unpack (readLocal bounds.transactionCount entry node)) node logBound
  unfold candidacy
  simp only [eval_and, eval_or, eval_not,
    equal_decide membershipCodec ρ
      (Local.unpack (readLocal bounds.transactionCount entry node)).membershipState
      (membershipCodec.literal .retiredCommitted), Codec.decode_literal]
  simp only [Bool.and_eq_true, eval_and, eval_or, eval_not, Bool.or_eq_true,
    allocated_correct bounds ρ entry node, equal_decide roleCodec, Codec.decode_literal,
    nodeMember_correct ρ, active, eligible, completed]
  change _ ↔ candidateTransitionEnabled _ _
  simp only [candidateTransitionEnabled, ← localCorrect]
  simp [Local.eval, state]

def candidateState (state : Local) (node : Expr nodeCodec.ty) : Local :=
  { state with
    role := roleCodec.literal .candidate
    currentTerm := .add state.currentTerm (.nat 1)
    votedFor := .inr node
    votesGranted := setInsert (nodeSetCodec.literal ∅) (finValue node)
    preVotesGranted := nodeSetCodec.literal ∅ }

theorem candidateState_correct (ρ : Assignment) (state : Local) (node : Expr nodeCodec.ty) :
    (candidateState state node).eval ρ = becomeCandidateNodeState (state.eval ρ) (nodeCodec.decode ρ node) := by
  simp only [candidateState, Local.eval, nodeInsert_correct, Codec.decode_literal, decode_some, Expr.eval]
  rfl

def proposal (bounds : BoundedState.Bounds) (entry : Expr (stateCodec bounds.transactionCount).ty)
    (destination : Expr nodeCodec.ty) (request : Expr proposeCodec.ty) : Expr nodeStateCodec.option.ty :=
  let state := Local.unpack (readLocal bounds.transactionCount entry destination)
  .ite (.lt state.currentTerm request.fst) (.inl .unit) <|
  .ite ((Expr.eq request.fst state.currentTerm).and (candidacy bounds entry destination))
    (.inr (candidateState state destination).pack) (.inr state.pack)

theorem proposal_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (entry : Expr (stateCodec bounds.transactionCount).ty) (destination : Expr nodeCodec.ty)
    (request : Expr proposeCodec.ty)
    (bound : ((evalEntry bounds ρ entry).nodes (nodeCodec.decode ρ destination)).log.length ≤ bounds.logCapacity) :
    nodeStateCodec.option.decode ρ (proposal bounds entry destination request) =
      handleProposeVoteRequest? (evalEntry bounds ρ entry) (nodeCodec.decode ρ destination)
        (proposeCodec.decode ρ request) := by
  simp only [proposal, decode_choose, decode_none, decode_some, Local.pack_correct,
    candidateState_correct, eval_and, Bool.and_eq_true, candidacy_correct bounds ρ entry destination bound,
    Local.unpack_correct]
  have localCorrect : nodeStateCodec.decode ρ (readLocal bounds.transactionCount entry destination) =
      (evalEntry bounds ρ entry).nodes (nodeCodec.decode ρ destination) :=
    readLocal_correct bounds ρ entry destination
  have term : (Local.unpack (readLocal bounds.transactionCount entry destination)).currentTerm.eval ρ =
      ((evalEntry bounds ρ entry).nodes (nodeCodec.decode ρ destination)).currentTerm :=
    congrArg NodeState.currentTerm ((Local.unpack_correct ρ _).trans localCorrect)
  simp only [Expr.eval, term, decide_eq_true_eq, localCorrect]
  rfl

end CCFRaft.SymbolicReceive
