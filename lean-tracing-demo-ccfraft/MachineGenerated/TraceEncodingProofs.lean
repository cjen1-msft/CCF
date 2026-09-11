-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.TraceEncoding
import MachineGenerated.LeaderWriteMappingProofs
import MachineGenerated.HandlerProofs

set_option autoImplicit false

namespace CCFRaft.TraceEncoding

open TraceSmt BoundedTrace
open TransactionMapping

@[simp]
theorem minValue_eval {holes : Nat} (assignment : Fin holes -> Nat)
    (left right : Value holes) :
    (minValue left right).eval assignment = min (left.eval assignment) (right.eval assignment) := by
  simp only [minValue, NatTerm.eval]
  omega

@[simp]
theorem maxValue_eval {holes : Nat} (assignment : Fin holes -> Nat)
    (left right : Value holes) :
    (maxValue left right).eval assignment = max (left.eval assignment) (right.eval assignment) := by
  simp only [maxValue, NatTerm.eval]
  omega

@[simp]
theorem leValue_eval {holes : Nat} (assignment : Fin holes -> Nat)
    (left right : Value holes) :
    (leValue left right).eval assignment =
      if left.eval assignment ≤ right.eval assignment then 1 else 0 := by
  simp only [leValue, minValue_eval, NatTerm.eval]
  split_ifs <;> omega

@[simp]
theorem controlValue_eval {holes : Nat}
    (assignment : Fin holes -> Nat) (tracking : Tracking holes)
    (node : Node) (slot : Nat) (label : String) (value : Nat) :
    (controlValue tracking node slot label value).eval assignment = value := by
  unfold controlValue
  split <;> rfl

@[simp]
theorem roleCode_inj (left right : Role) :
    roleCode left = roleCode right ↔ left = right := by
  cases left <;> cases right <;> decide

theorem roleCases_correct {holes : Nat}
    (assignment : Fin holes -> Nat) (value : Value holes) (role : Role)
    (correct : value.eval assignment = roleCode role)
    (predicate : Role -> Prop) [DecidablePred predicate] :
    (roleCases value predicate).Holds assignment ↔ predicate role := by
  cases role <;>
    simp [roleCases, Expr.Holds, NatTerm.eval, correct, roleCode]

theorem roleGuard_correct {holes : Nat}
    (assignment : Fin holes -> Nat) (state : Template holes)
    (tracking : Tracking holes) (node : Node)
    (predicate : Template holes -> Prop) [DecidablePred predicate] :
    (roleGuard state tracking node predicate).Holds assignment ↔ predicate state := by
  unfold roleGuard
  rw [roleCases_correct assignment _ (state.nodes node).role (by simp)]
  simp [withRole]

def ClausesHold {holes : Nat}
    (assignment : Fin holes -> Nat) (clauses : List (Clause holes)) : Prop :=
  ∀ clause, clause ∈ clauses -> clause.expression.Holds assignment

@[simp]
theorem clausesHold_nil {holes : Nat}
    (assignment : Fin holes -> Nat) :
    ClausesHold assignment [] := by
  simp [ClausesHold]

@[simp]
theorem clausesHold_append {holes : Nat}
    (assignment : Fin holes -> Nat)
    (left right : List (Clause holes)) :
    ClausesHold assignment (left ++ right) ↔
      ClausesHold assignment left /\ ClausesHold assignment right := by
  simp only [ClausesHold, List.mem_append]
  constructor
  · intro holds
    constructor
    · intro clause member
      exact holds clause (Or.inl member)
    · intro clause member
      exact holds clause (Or.inr member)
  · rintro ⟨leftHolds, rightHolds⟩ clause (member | member)
    · exact leftHolds clause member
    · exact rightHolds clause member

theorem guardClauses_correct {holes : Nat}
    (assignment : Fin holes -> Nat)
    (condition : Expr holes)
    (clauses : List (Clause holes)) :
    ClausesHold assignment (guardClauses condition clauses) <->
      (condition.Holds assignment -> ClausesHold assignment clauses) := by
  constructor
  · intro guarded conditionHolds clause member
    have holds := guarded
      { clause with expression := condition.implies clause.expression }
      (List.mem_map.mpr ⟨clause, member, rfl⟩)
    exact (Expr.implies_holds assignment _ _).mp holds conditionHolds
  · intro conditional clause member
    rcases List.mem_map.mp member with ⟨original, originalMember, rfl⟩
    exact (Expr.implies_holds assignment _ _).mpr fun conditionHolds =>
      conditional conditionHolds original originalMember

theorem guardedClauses_correct {holes : Nat} {α : Type}
    (assignment : Fin holes -> Nat)
    (tree : Guarded holes α)
    (clauses : α -> List (Clause holes)) :
    ClausesHold assignment (guardedClauses tree clauses) <->
      ClausesHold assignment (clauses (tree.eval assignment)) := by
  induction tree with
  | pure => rfl
  | branch condition thenTree elseTree thenCorrect elseCorrect =>
      simp only [guardedClauses, clausesHold_append,
        guardClauses_correct, Guarded.eval]
      by_cases holds : condition.Holds assignment <;>
        simp [holds, Expr.Holds, thenCorrect, elseCorrect]

theorem guardedGroup_correct {holes : Nat}
    (assignment : Fin holes -> Nat)
    (label : String)
    (frames : Guarded holes (Frame holes))
    (clauses : Frame holes -> List (Clause holes)) :
    (guardedGroup label frames clauses).Holds assignment <->
      ClausesHold assignment
        (clauses (frames.eval assignment)) := by
  exact guardedClauses_correct assignment frames clauses

@[simp]
theorem constantClause_correct {holes : Nat}
    (assignment : Fin holes -> Nat)
    (label : String)
    (condition : Prop)
    [Decidable condition] :
    ClausesHold assignment [constantClause label condition] ↔ condition := by
  simp [ClausesHold, constantClause, Expr.Holds]

@[simp]
theorem lessClause_correct {holes : Nat}
    (assignment : Fin holes -> Nat)
    (label : String)
    (value : Value holes)
    (bound : Nat) :
    ClausesHold assignment [lessClause label value bound] ↔
      value.eval assignment < bound := by
  simp [ClausesHold, lessClause, Expr.Holds, NatTerm.eval]

@[simp]
theorem atMostClause_correct {holes : Nat}
    (assignment : Fin holes -> Nat)
    (label : String)
    (value : Value holes)
    (bound : Nat) :
    ClausesHold assignment [atMostClause label value bound] ↔
      value.eval assignment ≤ bound := by
  simp [ClausesHold, atMostClause, Expr.Holds, NatTerm.eval]

theorem fresh_correct {holes : Nat}
    (assignment : Fin holes -> Nat)
    (transaction : Value holes)
    (prior : List (Value holes)) :
    (fresh transaction prior).Holds assignment ↔
      transaction.eval assignment ∉ prior.map (NatTerm.eval assignment) := by
  induction prior with
  | nil => simp [fresh, Expr.Holds]
  | cons previous prior inductionHypothesis =>
      simpa [fresh, Expr.Holds] using
        and_congr_right (fun _ => inductionHypothesis)

theorem fresh_submitted_correct {holes : Nat}
    (assignment : Fin holes -> Nat)
    (transaction : Value holes)
    (state : Template holes) :
    (fresh transaction (submittedTerms state)).Holds assignment ↔
      transaction.eval assignment ∉
        state.submittedTxIds.image (NatTerm.eval assignment) := by
  rw [fresh_correct]
  simp [submittedTerms, Finset.mem_image]

theorem clausesHold_flatMap {holes : Nat} {α : Type}
    (assignment : Fin holes -> Nat)
    (values : List α)
    (clauses : α -> List (Clause holes)) :
    ClausesHold assignment (values.flatMap clauses) ↔
      ∀ value ∈ values, ClausesHold assignment (clauses value) := by
  induction values with
  | nil => simp
  | cons value values inductionHypothesis =>
      simp only [List.flatMap_cons, clausesHold_append, inductionHypothesis,
        List.mem_cons, forall_eq_or_imp]

theorem trackedEntryBoundsClauses_correct {holes : Nat}
    (bounds : Bounds)
    (assignment : Fin holes -> Nat)
    (entry : Entry Node (Value holes))
    (term : Value holes) (termCorrect : term.eval assignment = entry.term) :
    ClausesHold assignment (entryBoundsClauses bounds entry term) ↔
      BoundedState.EntryWithin bounds
        (mapEntry (NatTerm.eval assignment) entry) := by
  cases entry with
  | mk entryTerm content =>
      cases content <;>
        simp [entryBoundsClauses, ClausesHold, constantClause, lessClause,
          Expr.Holds, NatTerm.eval, BoundedState.EntryWithin, mapEntry,
          mapEntryContent, termCorrect]

theorem entryBoundsClauses_correct {holes : Nat}
    (bounds : Bounds) (assignment : Fin holes -> Nat) (entry : Entry Node (Value holes)) :
    ClausesHold assignment (entryBoundsClauses bounds entry) ↔
      BoundedState.EntryWithin bounds (mapEntry (NatTerm.eval assignment) entry) :=
  trackedEntryBoundsClauses_correct bounds assignment entry (.literal entry.term) rfl

theorem entryListBoundsClauses_correct {holes : Nat}
    (bounds : Bounds)
    (assignment : Fin holes -> Nat)
    (entries : List (Entry Node (Value holes))) :
    ClausesHold assignment (entries.flatMap (fun entry => entryBoundsClauses bounds entry)) ↔
      (entries.map (mapEntry (NatTerm.eval assignment))).Forall
        (BoundedState.EntryWithin bounds) := by
  rw [clausesHold_flatMap]
  rw [List.forall_iff_forall_mem]
  simp [entryBoundsClauses_correct]

theorem logBoundsClauses_correct {holes : Nat}
    (bounds : Bounds) (assignment : Fin holes -> Nat)
    (terms : Nat -> Nat -> Value holes)
    (termsCorrect : ∀ index term, (terms index term).eval assignment = term)
    (index : Nat) (entries : List (Entry Node (Value holes))) :
    ClausesHold assignment (logBoundsClauses bounds terms index entries) ↔
      (entries.map (mapEntry (NatTerm.eval assignment))).Forall
        (BoundedState.EntryWithin bounds) := by
  induction entries generalizing index with
  | nil => simp [logBoundsClauses]
  | cons entry rest ih =>
      simp only [logBoundsClauses, clausesHold_append, List.map_cons, List.forall_cons]
      rw [trackedEntryBoundsClauses_correct bounds assignment entry _ (termsCorrect index entry.term), ih]

theorem messageBoundsClauses_correct {holes : Nat}
    (bounds : Bounds)
    (assignment : Fin holes -> Nat)
    (packetTerms : Message Node (Value holes) -> Value holes)
    (termsCorrect : ∀ message, (packetTerms message).eval assignment = message.term)
    (packetFields : Message Node (Value holes) -> Nat -> Nat -> Value holes)
    (fieldsCorrect : ∀ message field value, (packetFields message field value).eval assignment = value)
    (message : Message Node (Value holes)) :
    ClausesHold assignment (messageBoundsClauses bounds packetTerms packetFields message) ↔
      BoundedState.MessageWithin bounds
        (mapMessage (NatTerm.eval assignment) message) := by
  cases message with
  | appendEntriesRequest request =>
      simp only [messageBoundsClauses, mapMessage, clausesHold_append,
        logBoundsClauses_correct bounds assignment _ (fun index => fieldsCorrect _ (6 + index))]
      simp [ClausesHold, constantClause, lessClause, atMostClause, Expr.Holds, NatTerm.eval,
        fieldsCorrect,
        termsCorrect, Message.term,
        BoundedState.MessageWithin]
      tauto
  | appendEntriesResponse response =>
      simp [messageBoundsClauses, mapMessage, ClausesHold, constantClause,
        lessClause, NatTerm.eval, termsCorrect, fieldsCorrect, Message.term,
        Expr.Holds, BoundedState.MessageWithin]
  | requestVoteRequest request =>
      simp [messageBoundsClauses, mapMessage, ClausesHold, constantClause,
        lessClause, NatTerm.eval, termsCorrect, fieldsCorrect, Message.term,
        Expr.Holds, BoundedState.MessageWithin]
  | requestVoteResponse response =>
      simp [messageBoundsClauses, mapMessage, ClausesHold, constantClause,
        lessClause, NatTerm.eval, termsCorrect, fieldsCorrect, Message.term,
        Expr.Holds, BoundedState.MessageWithin]
  | requestPreVote request =>
      simp [messageBoundsClauses, mapMessage, ClausesHold, constantClause,
        lessClause, NatTerm.eval, termsCorrect, fieldsCorrect, Message.term,
        Expr.Holds, BoundedState.MessageWithin]
  | requestPreVoteResponse response =>
      simp [messageBoundsClauses, mapMessage, ClausesHold, constantClause,
        lessClause, NatTerm.eval, termsCorrect, fieldsCorrect, Message.term,
        Expr.Holds, BoundedState.MessageWithin]
  | proposeVoteRequest request =>
      simp [messageBoundsClauses, mapMessage, ClausesHold, constantClause,
        lessClause, NatTerm.eval, termsCorrect, fieldsCorrect, Message.term,
        Expr.Holds, BoundedState.MessageWithin]

theorem messageListBoundsClauses_correct {holes : Nat}
    (bounds : Bounds)
    (assignment : Fin holes -> Nat)
    (packetTerms : Message Node (Value holes) -> Value holes)
    (termsCorrect : ∀ message, (packetTerms message).eval assignment = message.term)
    (packetFields : Message Node (Value holes) -> Nat -> Nat -> Value holes)
    (fieldsCorrect : ∀ message field value, (packetFields message field value).eval assignment = value)
    (messages : List (Message Node (Value holes))) :
    ClausesHold assignment
        (messages.flatMap (messageBoundsClauses bounds packetTerms packetFields)) ↔
      (messages.map (mapMessage (NatTerm.eval assignment))).Forall
        (BoundedState.MessageWithin bounds) := by
  rw [clausesHold_flatMap]
  rw [List.forall_iff_forall_mem]
  simp [messageBoundsClauses_correct bounds assignment packetTerms termsCorrect packetFields fieldsCorrect]

theorem optionalIndexClauses_correct {holes : Nat}
    (bounds : Bounds)
    (assignment : Fin holes -> Nat)
    (positions : Nat -> Value holes)
    (correct : ∀ index, (positions index).eval assignment = index)
    (writer : Option (Nat × Nat))
    (slot : Nat)
    (label : String)
    (index : Option Nat) :
    ClausesHold assignment
        (optionalIndexClauses bounds positions writer slot label index) ↔
      BoundedState.OptionalIndexWithin bounds index := by
  cases writer <;> cases index <;>
    simp [optionalIndexClauses, ClausesHold, lessClause, Expr.Holds,
      NatTerm.eval, correct, BoundedState.OptionalIndexWithin]

theorem peerIndexClauses_correct {holes : Nat}
    (bounds : Bounds)
    (assignment : Fin holes -> Nat)
    (tracking : Tracking holes)
    (node : Node)
    (state : NodeState Node (Value holes)) :
    ClausesHold assignment
        ((List.finRange NODE_COUNT).flatMap fun peer =>
          [lessClause "sent index domain"
             (tracking.sentIndex node peer) bounds.indexCount,
           lessClause "match index domain"
             (controlValue tracking node
               (MATCH_SLOT_BASE + node.val * NODE_COUNT + peer.val)
               s!"match index {peer.val}" (state.matchIndex peer))
             bounds.indexCount]) ↔
      (∀ peer,
        (tracking.sentIndex node peer).eval assignment <
          bounds.indexCount) /\
        (∀ peer, state.matchIndex peer < bounds.indexCount) := by
  rw [clausesHold_flatMap]
  simp only [List.mem_finRange, true_implies]
  simp [ClausesHold, constantClause, lessClause, Expr.Holds, NatTerm.eval]
  constructor
  · intro both
    exact ⟨fun peer => (both peer).1, fun peer => (both peer).2⟩
  · rintro ⟨sent, matched⟩ peer
    exact ⟨sent peer, matched peer⟩

theorem localBoundsClauses_correct {holes : Nat}
    (bounds : Bounds)
    (assignment : Fin holes -> Nat)
    (tracking : Tracking holes)
    (node : Node)
    (state : NodeState Node (Value holes))
    (logLength :
      (tracking.logLengths node).eval assignment =
        (mapNodeState (NatTerm.eval assignment) state).log.length)
    (currentTerm :
      (tracking.currentTerms node).eval assignment = state.currentTerm)
    (commitIndices : ∀ index, (tracking.commitIndices node index).eval assignment = index)
    (logPositions : ∀ index, (tracking.logPositions node index).eval assignment = index)
    (logTerms : ∀ index term, (tracking.logTerms node index term).eval assignment = term) :
    (sentIndices :
      ∀ peer,
        (tracking.sentIndex node peer).eval assignment =
          (mapNodeState (NatTerm.eval assignment) state).sentIndex peer) ->
    ClausesHold assignment
        (localBoundsClauses bounds tracking node state) ↔
      BoundedState.LocalWithin bounds
        (mapNodeState (NatTerm.eval assignment) state) := by
  intro sentIndices
  simp only [localBoundsClauses, clausesHold_append,
    logBoundsClauses_correct bounds assignment (tracking.logTerms node) logTerms,
    peerIndexClauses_correct bounds assignment tracking node state,
    optionalIndexClauses_correct bounds assignment (tracking.logPositions node) logPositions]
  simp [ClausesHold, constantClause, lessClause, atMostClause, Expr.Holds, NatTerm.eval,
    BoundedState.LocalWithin, mapNodeState, logLength, sentIndices, currentTerm, commitIndices]
  tauto

structure TrackingCorrect {holes : Nat}
    (assignment : Fin holes -> Nat)
    (state : Template holes)
    (tracking : Tracking holes) : Prop where
  logLengths : ∀ node,
    (tracking.logLengths node).eval assignment =
      ((mapState (NatTerm.eval assignment) state).nodes node).log.length
  allocated : ∀ node,
    (tracking.allocated node).eval assignment =
      if (mapState (NatTerm.eval assignment) state).allocated node then 1 else 0
  joined : ∀ node,
    (tracking.joined node).eval assignment =
      if node ∈ (mapState (NatTerm.eval assignment) state).hasJoined then 1 else 0
  sentIndex : ∀ node peer,
    (tracking.sentIndex node peer).eval assignment =
      ((mapState (NatTerm.eval assignment) state).nodes node).sentIndex peer
  queueLengths : ∀ node,
    (tracking.queueLengths node).eval assignment =
      ((mapState (NatTerm.eval assignment) state).network node).length
  currentTerms : ∀ node,
    (tracking.currentTerms node).eval assignment = (state.nodes node).currentTerm
  packetTerms : ∀ message,
    (tracking.packetTerms message).eval assignment = message.term
  logPositions : ∀ node index,
    (tracking.logPositions node index).eval assignment = index
  commitIndices : ∀ node index,
    (tracking.commitIndices node index).eval assignment = index
  logTerms : ∀ node index term,
    (tracking.logTerms node index term).eval assignment = term
  packetFields : ∀ message field value,
    (tracking.packetFields message field value).eval assignment = value
  voteMembers : ∀ node preVote peer value,
    (tracking.voteMembers node preVote peer value).eval assignment = if value then 1 else 0
  configurations : ∀ node values,
    ControlTraceConfigurations.Correct assignment values (tracking.configurations node values)
  completedMembers : ∀ node peer value,
    (tracking.completedMembers node peer value).eval assignment = if value then 1 else 0

theorem allExpr_correct {holes : Nat} (assignment : Fin holes -> Nat) (values : List (Expr holes)) :
    (allExpr values).Holds assignment ↔ ∀ value ∈ values, value.Holds assignment := by
  induction values with
  | nil => simp [allExpr, Expr.Holds]
  | cons first rest ih => simpa [allExpr, Expr.Holds] using and_congr_right (fun _ => ih)

theorem allExpr_map_correct {holes : Nat} {α : Type}
    (assignment : Fin holes -> Nat) (values : List α) (expression : α -> Expr holes) :
    (allExpr (values.map expression)).Holds assignment ↔
      ∀ value ∈ values, (expression value).Holds assignment := by
  simp only [allExpr_correct, List.mem_map, forall_exists_index, and_imp, forall_apply_eq_imp_iff₂]

theorem anyExpr_correct {holes : Nat} (assignment : Fin holes -> Nat) (values : List (Expr holes)) :
    (anyExpr values).Holds assignment ↔ ∃ value ∈ values, value.Holds assignment := by
  induction values with
  | nil => simp [anyExpr, Expr.Holds]
  | cons first rest ih =>
      simp only [anyExpr, List.foldr_cons, orExpr, Expr.Holds,
        List.mem_cons, exists_eq_or_imp] at *
      simp only [not_and_or, not_not, ih]

theorem snapshot_forall {holes : Nat} (assignment : Fin holes -> Nat)
    (values : List (Configuration Node)) (snapshots : List (ControlTraceConfigurations.Snapshot holes))
    (correct : ControlTraceConfigurations.Correct assignment values snapshots)
    (predicate : Configuration Node -> Prop) :
    (∀ snapshot ∈ snapshots, snapshot.present.eval assignment = 1 → predicate snapshot.configuration) ↔
      ∀ configuration ∈ values, predicate configuration := by
  rw [← correct.selected]
  simp only [ControlTraceConfigurations.selected, List.mem_map, List.mem_filter, beq_iff_eq,
    forall_exists_index, and_imp, forall_apply_eq_imp_iff₂]
  constructor
  · intro holds _ snapshot member present rfl
    exact holds snapshot member present
  · intro holds snapshot member present
    exact holds _ snapshot member present rfl

theorem snapshot_exists {holes : Nat} (assignment : Fin holes -> Nat)
    (values : List (Configuration Node)) (snapshots : List (ControlTraceConfigurations.Snapshot holes))
    (correct : ControlTraceConfigurations.Correct assignment values snapshots)
    (predicate : Configuration Node -> Prop) :
    (∃ snapshot ∈ snapshots, snapshot.present.eval assignment = 1 ∧ predicate snapshot.configuration) ↔
      ∃ configuration ∈ values, predicate configuration := by
  rw [← correct.selected]
  simp only [ControlTraceConfigurations.selected, List.mem_map, List.mem_filter, beq_iff_eq,
    exists_exists_and_eq_and, and_assoc]
  constructor
  · rintro ⟨snapshot, member, present, holds⟩
    exact ⟨snapshot.configuration, ⟨snapshot, member, present, rfl⟩, holds⟩
  · rintro ⟨_, ⟨snapshot, member, present, rfl⟩, holds⟩
    exact ⟨snapshot, member, present, holds⟩

theorem allSnapshots_correct {holes : Nat} (assignment : Fin holes -> Nat)
    (values : List (Configuration Node)) (snapshots : List (ControlTraceConfigurations.Snapshot holes))
    (correct : ControlTraceConfigurations.Correct assignment values snapshots)
    (expression : ControlTraceConfigurations.Snapshot holes -> Expr holes)
    (predicate : Configuration Node -> Prop)
    (equivalent : ∀ snapshot ∈ snapshots, (expression snapshot).Holds assignment ↔ predicate snapshot.configuration) :
    (allExpr (snapshots.map fun snapshot => (configurationPresent snapshot).implies (expression snapshot))).Holds assignment ↔
      ∀ configuration ∈ values, predicate configuration := by
  simp only [allExpr_map_correct, Expr.implies_holds, configurationPresent, Expr.Holds, NatTerm.eval]
  rw [← snapshot_forall assignment values snapshots correct predicate]
  apply forall_congr'
  intro snapshot
  apply forall_congr'
  intro member
  exact imp_congr_right (fun _ => equivalent snapshot member)

theorem anySnapshots_correct {holes : Nat} (assignment : Fin holes -> Nat)
    (values : List (Configuration Node)) (snapshots : List (ControlTraceConfigurations.Snapshot holes))
    (correct : ControlTraceConfigurations.Correct assignment values snapshots)
    (expression : ControlTraceConfigurations.Snapshot holes -> Expr holes)
    (predicate : Configuration Node -> Prop)
    (equivalent : ∀ snapshot ∈ snapshots, (expression snapshot).Holds assignment ↔ predicate snapshot.configuration) :
    (anyExpr (snapshots.map fun snapshot => .and (configurationPresent snapshot) (expression snapshot))).Holds assignment ↔
      ∃ configuration ∈ values, predicate configuration := by
  simp only [anyExpr_correct, List.mem_map, exists_exists_and_eq_and,
    configurationPresent, Expr.Holds, NatTerm.eval]
  rw [← snapshot_exists assignment values snapshots correct predicate]
  apply exists_congr
  intro snapshot
  apply and_congr_right
  intro member
  exact and_congr_right (fun _ => equivalent snapshot member)

theorem latestConfigurationValue_correct {holes : Nat}
    (assignment : Fin holes -> Nat) (state : Template holes) (tracking : Tracking holes)
    (correct : TrackingCorrect assignment state tracking) (node : Node)
    (predicate : Configuration Node -> Bool) :
    (latestConfigurationValue state tracking node predicate).eval assignment =
      if predicate (latestConfiguration (state.nodes node)) then 1 else 0 := by
  have history := correct.configurations node (allConfigurations (state.nodes node).log)
  have result := ControlTraceConfigurations.lastValue_correct assignment _ history.presence predicate
    implicitConfiguration (boolValue (predicate implicitConfiguration)) (by rfl)
  rw [history.selected] at result
  simpa [latestConfigurationValue, configurationSnapshots, allConfigurations, latestConfiguration] using result

theorem currentConfigurationIndexValue_correct {holes : Nat}
    (assignment : Fin holes -> Nat) (state : Template holes) (tracking : Tracking holes)
    (correct : TrackingCorrect assignment state tracking) (node : Node) :
    (currentConfigurationIndexValue state tracking node).eval assignment =
      (currentConfiguration (state.nodes node)).index := by
  have history := ControlTraceConfigurations.truncatePure_correct assignment _ _
    (correct.configurations node (allConfigurations (state.nodes node).log))
    (tracking.commitIndices node (state.nodes node).commitIndex)
  have result := ControlTraceConfigurations.lastIndexValue_correct assignment _ history.positions history.presence
    implicitConfiguration (.literal 0) (by rfl)
  rw [history.selected, correct.commitIndices,
    ControlTraceConfigurations.currentConfiguration_filtered] at result
  exact result

theorem currentConfigurationMemberValue_correct {holes : Nat}
    (assignment : Fin holes -> Nat) (state : Template holes) (tracking : Tracking holes)
    (correct : TrackingCorrect assignment state tracking) (node peer : Node) :
    (currentConfigurationMemberValue state tracking node peer).eval assignment =
      if peer ∈ (currentConfiguration (state.nodes node)).nodes then 1 else 0 := by
  have history := ControlTraceConfigurations.truncatePure_correct assignment _ _
    (correct.configurations node (allConfigurations (state.nodes node).log))
    (tracking.commitIndices node (state.nodes node).commitIndex)
  have result := ControlTraceConfigurations.lastValue_correct assignment _ history.presence
    (fun cfg => decide (peer ∈ cfg.nodes)) implicitConfiguration
    (boolValue (decide (peer ∈ implicitConfiguration.nodes))) (by rfl)
  rw [history.selected, correct.commitIndices,
    ControlTraceConfigurations.currentConfiguration_filtered] at result
  simpa [currentConfigurationMemberValue, configurationSnapshots] using result

theorem addedConfigurationMemberValue_correct {holes : Nat}
    (assignment : Fin holes -> Nat) (state : Template holes) (tracking : Tracking holes)
    (correct : TrackingCorrect assignment state tracking) (source : Node)
    (configuration : Finset Node) (peer : Node) :
    (addedConfigurationMemberValue state tracking source configuration peer).eval assignment =
      if peer ∈ configuration \ (latestConfiguration (state.nodes source)).nodes then 1 else 0 := by
  by_cases requested : peer ∈ configuration <;>
    by_cases previous : peer ∈ (latestConfiguration (state.nodes source)).nodes <;>
      simp [addedConfigurationMemberValue, requested, previous, NatTerm.eval,
        latestConfigurationValue_correct assignment state tracking correct]

theorem refreshedCompletedValue_correct {holes : Nat}
    (assignment : Fin holes -> Nat) (state : Template holes) (tracking : Tracking holes)
    (correct : TrackingCorrect assignment state tracking) (node peer : Node) :
    (refreshedCompletedValue state tracking node peer).eval assignment =
      if peer ∈ retirementCompletedNodes (state.nodes node).log (state.nodes node).commitIndex then 1 else 0 :=
  ControlTraceRetirement.completedValue_correct assignment peer (state.nodes node) _
    (correct.configurations node _) _ (correct.logPositions node) _ _ _ (correct.commitIndices node _)
    (currentConfigurationIndexValue_correct assignment state tracking correct node)
    (currentConfigurationMemberValue_correct assignment state tracking correct node peer)

theorem refreshCompletedTracking_correct {holes : Nat}
    (assignment : Fin holes -> Nat) (position pathId : Nat) (state : Template holes) (tracking : Tracking holes)
    (correct : TrackingCorrect assignment state tracking) (node : Node) :
    TrackingCorrect assignment state (refreshCompletedTracking position pathId state tracking node) := by
  exact { correct with
    completedMembers := by
      intro candidate peer value
      simp only [refreshCompletedTracking, Function.update_apply, ite_apply]
      split_ifs <;> simp_all [NatTerm.eval,
        refreshedCompletedValue_correct assignment state tracking correct, correct.completedMembers] }

theorem completedMemberExpr_correct {holes : Nat}
    (assignment : Fin holes -> Nat) (state : Template holes) (tracking : Tracking holes)
    (correct : TrackingCorrect assignment state tracking) (node peer : Node) :
    (completedMemberExpr state tracking node peer).Holds assignment ↔ peer ∈ state.retirementCompleted node := by
  simp [completedMemberExpr, Expr.Holds, NatTerm.eval, correct.completedMembers]

theorem pendingRetirementExpr_correct {holes : Nat}
    (assignment : Fin holes -> Nat) (state : Template holes) (tracking : Tracking holes)
    (correct : TrackingCorrect assignment state tracking) (node : Node) :
    (pendingRetirementExpr state tracking node).Holds assignment ↔ (pendingRetiredCommittedNodes state node).Nonempty := by
  simp [pendingRetirementExpr, anyExpr_correct, exists_exists_and_eq_and, Expr.Holds, NatTerm.eval,
    completedMemberExpr_correct assignment state tracking correct,
    ControlTraceRetirement.recordedValue_correct assignment _ _ _ (correct.logPositions node),
    correct.logLengths, mapState_nodes_get, mapNodeState, pendingRetiredCommittedNodes,
    Finset.Nonempty, allRetiredCommittedNodes, retiredCommittedNodesUpTo]

theorem activeConfigurationExpr_correct {holes : Nat}
    (assignment : Fin holes -> Nat) (state : Template holes) (tracking : Tracking holes)
    (correct : TrackingCorrect assignment state tracking)
    (node : Node) (configuration : Configuration Node) :
    (activeConfigurationExpr state tracking node configuration).Holds assignment ↔
      (currentConfiguration (state.nodes node)).index ≤ configuration.index := by
  unfold activeConfigurationExpr configurationSnapshots
  rw [allSnapshots_correct assignment _ _
    (correct.configurations node (allConfigurations (state.nodes node).log)) _
    (fun later => configuration.index < later.index → (state.nodes node).commitIndex < later.index)
    (by
      intro later member
      have index := (correct.configurations node _).positions later member
      split_ifs <;> simp_all [Expr.Holds, correct.commitIndices])]
  constructor
  · intro condition
    by_contra smaller
    have less : configuration.index < (currentConfiguration (state.nodes node)).index := by omega
    have selected := condition _ (currentConfiguration_mem_allConfigurations (state.nodes node)) less
    have committed := currentConfiguration_index_le_commitIndex (state.nodes node)
    omega
  · intro le later member
    have greatest := configuration_index_le_currentConfiguration (state.nodes node) later member
    omega

theorem supportCount_correct {holes : Nat}
    (assignment : Fin holes -> Nat) (membership : Node -> Value holes)
    (votes members : Finset Node)
    (correct : ∀ peer, (membership peer).eval assignment = if peer ∈ votes then 1 else 0) :
    ((members.sort (· ≤ ·)).foldl
      (fun total peer => NatTerm.add total (membership peer))
      (NatTerm.literal 0)).eval assignment = (votes ∩ members).card := by
  have fold (peers : List Node) (total : Value holes) :
      (peers.foldl (fun total peer => .add total (membership peer)) total).eval assignment =
      total.eval assignment + (peers.map (fun peer => if peer ∈ votes then 1 else 0)).sum := by
    induction peers generalizing total with
    | nil => simp
    | cons peer peers ih =>
        simp [ih, NatTerm.eval, correct, Nat.add_assoc]
  rw [fold]
  simp only [NatTerm.eval, Nat.zero_add]
  rw [← Multiset.sum_coe, ← Multiset.map_coe, Finset.sort_eq]
  change (∑ peer ∈ members, if peer ∈ votes then 1 else 0) = (votes ∩ members).card
  simp [Finset.inter_comm, Finset.filter_mem_eq_inter]

theorem voteCount_correct {holes : Nat}
    (assignment : Fin holes -> Nat) (tracking : Tracking holes)
    (correct : ∀ node preVote peer value,
      (tracking.voteMembers node preVote peer value).eval assignment = if value then 1 else 0)
    (node : Node) (preVote : Bool) (votes members : Finset Node) :
    ((members.sort (· ≤ ·)).foldl
      (fun total peer => NatTerm.add total (tracking.voteMembers node preVote peer (decide (peer ∈ votes))))
      (NatTerm.literal 0)).eval assignment = (votes ∩ members).card := by
  apply supportCount_correct
  intro peer
  simp [correct]

theorem voteMajorityExpr_correct {holes : Nat}
    (assignment : Fin holes -> Nat) (state : Template holes) (tracking : Tracking holes)
    (correct : TrackingCorrect assignment state tracking) (node : Node) (preVote : Bool) :
    (voteMajorityExpr state tracking node preVote).Holds assignment ↔
      if preVote then hasPreVoteMajority state node else hasElectionMajority state node := by
  unfold voteMajorityExpr configurationSnapshots
  rw [allSnapshots_correct assignment _ _
    (correct.configurations node (allConfigurations (state.nodes node).log)) _
    (fun cfg => (currentConfiguration (state.nodes node)).index ≤ cfg.index →
      hasConfigurationMajority
        (if preVote then (state.nodes node).preVotesGranted else (state.nodes node).votesGranted) cfg)
    (by
      intro snapshot _
      simp [Expr.implies_holds, activeConfigurationExpr_correct assignment state tracking correct,
        Expr.Holds, NatTerm.eval, voteCount_correct assignment tracking correct.voteMembers,
        hasConfigurationMajority, Nat.mul_two])]
  cases preVote <;> simp [hasPreVoteMajority, hasElectionMajority,
    activeConfigurations, List.all_eq_true]
  all_goals
    apply forall_congr'
    intro configuration
    apply forall_congr'
    intro member
    by_cases active : (currentConfiguration (state.nodes node)).index ≤ configuration.index
    · simp [active, Nat.not_lt_of_ge active]
    · simp [active, Nat.lt_of_not_ge active]

theorem mem_activeUnion_iff {holes : Nat}
    (state : NodeState Node (Value holes)) (peer : Node) :
    peer ∈ activeNodeUnion state ↔
      ∃ configuration ∈ activeConfigurations state, peer ∈ configuration.nodes := by
  have fold (configurations : List (Configuration Node)) (initial : Finset Node) (peer : Node) :
      peer ∈ configurations.foldl (fun nodes cfg => nodes ∪ cfg.nodes) initial ↔
        peer ∈ initial ∨ ∃ cfg ∈ configurations, peer ∈ cfg.nodes := by
    induction configurations generalizing initial with
    | nil => simp
    | cons cfg rest ih =>
        simp only [List.foldl_cons, ih, Finset.mem_union, List.mem_cons, exists_eq_or_imp]
        tauto
  simp [activeNodeUnion, fold]

theorem configuration_member_activeUnion {holes : Nat}
    (state : NodeState Node (Value holes)) (configuration : Configuration Node)
    (active : configuration ∈ activeConfigurations state) :
    configuration.nodes ⊆ activeNodeUnion state := by
  intro peer member
  exact (mem_activeUnion_iff _ peer).2 ⟨configuration, active, member⟩

theorem replicationMajorityExpr_correct {holes : Nat}
    (assignment : Fin holes -> Nat) (state : Template holes) (tracking : Tracking holes)
    (correct : TrackingCorrect assignment state tracking) (node : Node) (index : Nat) :
    (replicationMajorityExpr state tracking node index).Holds assignment ↔
      hasMajorityAt state node index := by
  let support := Finset.univ.filter fun peer : Node => peer = node ∨ index ≤ (state.nodes node).matchIndex peer
  have count (members : Finset Node) :
      ((members.sort (· ≤ ·)).foldl (fun total peer => NatTerm.add total
        (if peer = node then .literal 1 else
          leValue (tracking.logPositions node index)
            (controlValue tracking node (MATCH_SLOT_BASE + node.val * NODE_COUNT + peer.val)
              s!"match index {peer.val}" ((state.nodes node).matchIndex peer)))) (.literal 0)).eval assignment =
        (support ∩ members).card := by
    apply supportCount_correct
    intro peer
    by_cases same : peer = node <;>
      simp [same, support, NatTerm.eval, leValue_eval, correct.logPositions]
  have intersection (configuration : Configuration Node)
      (active : configuration ∈ activeConfigurations (state.nodes node)) :
      support ∩ configuration.nodes = acknowledgingNodes state node index ∩ configuration.nodes := by
    ext peer
    have included := configuration_member_activeUnion (state.nodes node) configuration active
    simp only [support, acknowledgingNodes, Finset.mem_inter, Finset.mem_filter, Finset.mem_univ, true_and]
    constructor
    · rintro ⟨replicated, member⟩
      exact ⟨⟨included member, replicated⟩, member⟩
    · tauto
  unfold replicationMajorityExpr configurationSnapshots
  rw [allSnapshots_correct assignment _ _
    (correct.configurations node (allConfigurations (state.nodes node).log)) _
    (fun cfg => (currentConfiguration (state.nodes node)).index ≤ cfg.index →
      cfg.index ≤ index → hasConfigurationMajority support cfg)
    (by
      intro snapshot member
      have position := (correct.configurations node _).positions snapshot member
      simp [Expr.implies_holds, activeConfigurationExpr_correct assignment state tracking correct,
        Expr.Holds, NatTerm.eval, correct.logPositions, count, position,
        hasConfigurationMajority, Nat.mul_two])]
  simp only [hasMajorityAt, List.all_eq_true, decide_eq_true_eq]
  constructor
  · intro condition cfg active
    have known := List.mem_filter.mp active
    simpa [hasConfigurationMajority, Nat.mul_two, ← intersection cfg active] using
      condition cfg known.1 (by simpa using known.2)
  · intro condition cfg known current
    have active : cfg ∈ activeConfigurations (state.nodes node) := by
      simp [activeConfigurations, known, current]
    simpa [hasConfigurationMajority, Nat.mul_two, ← intersection cfg active] using condition cfg active

theorem committableAtExpr_correct {holes : Nat}
    (assignment : Fin holes -> Nat) (state : Template holes) (tracking : Tracking holes)
    (correct : TrackingCorrect assignment state tracking) (node : Node) (index : Nat) :
    (committableAtExpr state tracking node index).Holds assignment ↔
      index > (state.nodes node).commitIndex ∧ isSignatureAt (state.nodes node).log index = true ∧
        termAt (state.nodes node).log index = (state.nodes node).currentTerm ∧ hasMajorityAt state node index := by
  simp only [committableAtExpr, Expr.Holds, correct.commitIndices, correct.logPositions,
    correct.logTerms, correct.currentTerms, replicationMajorityExpr_correct assignment state tracking correct]
  tauto

theorem highestCommittableValue_correct {holes : Nat}
    (assignment : Fin holes -> Nat) (state : Template holes) (tracking : Tracking holes)
    (correct : TrackingCorrect assignment state tracking) (node : Node) :
    (highestCommittableValue state tracking node).eval assignment = highestCommittableIndex state node := by
  let qualifies := fun index =>
    index > (state.nodes node).commitIndex ∧ isSignatureAt (state.nodes node).log index = true ∧
      termAt (state.nodes node).log index = (state.nodes node).currentTerm ∧ hasMajorityAt state node index
  have bounded (count : Nat) :
      (List.range count).foldl (fun best index => if qualifies index then max best index else best) 0 ≤ count := by
    apply (ControlTraceConfigurations.maximum_le _ qualifies id 0 count).2
    constructor
    · omega
    · intro index member _
      have smaller := List.mem_range.mp member
      change index ≤ count
      omega
  have fold (count : Nat) :
      ((List.range count).foldl (fun previous index =>
        (committableAtExpr state tracking node index).ite (tracking.logPositions node index) previous)
        (.literal 0)).eval assignment =
      (List.range count).foldl (fun best index => if qualifies index then max best index else best) 0 := by
    induction count with
    | zero => rfl
    | succ count ih =>
        simp only [List.range_succ, List.foldl_append, List.foldl_cons, List.foldl_nil,
          Expr.ite_eval, committableAtExpr_correct assignment state tracking correct,
          correct.logPositions, ih]
        change (if qualifies count then count else _) = if qualifies count then max _ count else _
        split_ifs
        · exact (max_eq_right (bounded count)).symm
        · rfl
  exact fold _

theorem committableExpr_correct {holes : Nat}
    (assignment : Fin holes -> Nat) (state : Template holes) (tracking : Tracking holes)
    (correct : TrackingCorrect assignment state tracking) (node : Node) :
    (committableExpr state tracking node).Holds assignment ↔
      (state.nodes node).commitIndex < highestCommittableIndex state node := by
  let qualifies := fun index =>
    index > (state.nodes node).commitIndex ∧ isSignatureAt (state.nodes node).log index = true ∧
      termAt (state.nodes node).log index = (state.nodes node).currentTerm ∧ hasMajorityAt state node index
  have fold (indices : List Nat) (best : Nat) :
      (state.nodes node).commitIndex <
        indices.foldl (fun best index => if qualifies index then max best index else best) best ↔
      (state.nodes node).commitIndex < best ∨ ∃ index ∈ indices, qualifies index := by
    induction indices generalizing best with
    | nil => simp
    | cons index rest ih =>
        simp only [List.foldl_cons, ih, List.mem_cons, exists_eq_or_imp]
        by_cases accepted : qualifies index
        · have advances := accepted.1
          simp only [accepted, if_true, lt_max_iff, true_or]
          tauto
        · simp [accepted]
  simp only [committableExpr, committableAtExpr, anyExpr_correct, List.mem_map, exists_exists_and_eq_and,
    Expr.Holds, correct.commitIndices, correct.logPositions, correct.logTerms, correct.currentTerms,
    replicationMajorityExpr_correct assignment state tracking correct]
  change _ ↔ (state.nodes node).commitIndex <
    (List.range ((state.nodes node).log.length + 1)).foldl
      (fun best index => if qualifies index then max best index else best) 0
  rw [fold]
  simp only [Nat.not_lt_zero, false_or, qualifies]
  apply exists_congr
  intro index
  tauto

theorem activeMemberExpr_correct {holes : Nat}
    (assignment : Fin holes -> Nat) (state : Template holes) (tracking : Tracking holes)
    (correct : TrackingCorrect assignment state tracking) (node peer : Node) :
    (activeMemberExpr state tracking node peer).Holds assignment ↔
      peer ∈ activeNodeUnion (state.nodes node) := by
  unfold activeMemberExpr configurationSnapshots
  rw [anySnapshots_correct assignment _ _
    (correct.configurations node (allConfigurations (state.nodes node).log)) _
    (fun cfg => (currentConfiguration (state.nodes node)).index ≤ cfg.index ∧ peer ∈ cfg.nodes)
    (by
      intro snapshot _
      simp [Expr.Holds, activeConfigurationExpr_correct assignment state tracking correct])]
  simp only [mem_activeUnion_iff, activeConfigurations, List.mem_filter]
  simp only [decide_eq_true_eq, and_assoc]

theorem campaignExpr_correct {holes : Nat}
    (assignment : Fin holes -> Nat) (state : Template holes) (tracking : Tracking holes)
    (correct : TrackingCorrect assignment state tracking) (node : Node) :
    (campaignExpr state tracking node).Holds assignment ↔ campaignEligible node (state.nodes node) := by
  unfold campaignExpr configurationSnapshots
  rw [anySnapshots_correct assignment _ _
    (correct.configurations node (allConfigurations (state.nodes node).log)) _
    (fun cfg => (currentConfiguration (state.nodes node)).index ≤ cfg.index ∧
      node ∈ cfg.nodes ∧ cfg.index ≤ maxCommittableIndex (state.nodes node).log)
    (by
      intro snapshot member
      have position := (correct.configurations node _).positions snapshot member
      simp [Expr.Holds, activeConfigurationExpr_correct assignment state tracking correct,
        correct.logPositions, position])]
  simp [campaignEligible, activeConfigurations, List.any_eq_true, and_assoc]

theorem configurationRank_le_iff {holes : Nat} (state : NodeState Node (Value holes))
    (candidate destination : Node) :
    highestActiveConfigurationWithNode state candidate ≤ highestActiveConfigurationWithNode state destination ↔
      ∀ cfg ∈ activeConfigurations state, candidate ∈ cfg.nodes →
        cfg.index = 0 ∨ ∃ next ∈ activeConfigurations state,
          destination ∈ next.nodes ∧ cfg.index ≤ next.index := by
  unfold highestActiveConfigurationWithNode
  rw [ControlTraceConfigurations.maximum_le]
  simp only [Nat.zero_le, true_and, true_or, ControlTraceConfigurations.le_maximum, Nat.le_zero_eq]

theorem configurationRankLeExpr_correct {holes : Nat}
    (assignment : Fin holes -> Nat) (state : Template holes) (tracking : Tracking holes)
    (correct : TrackingCorrect assignment state tracking) (node candidate destination : Node) :
    (configurationRankLeExpr state tracking node candidate destination).Holds assignment ↔
      highestActiveConfigurationWithNode (state.nodes node) candidate ≤
        highestActiveConfigurationWithNode (state.nodes node) destination := by
  have history := correct.configurations node (allConfigurations (state.nodes node).log)
  unfold configurationRankLeExpr configurationSnapshots
  rw [allSnapshots_correct assignment _ _ history _
    (fun cfg => (currentConfiguration (state.nodes node)).index ≤ cfg.index →
      candidate ∈ cfg.nodes → cfg.index = 0 ∨
        ∃ next ∈ allConfigurations (state.nodes node).log,
          (currentConfiguration (state.nodes node)).index ≤ next.index ∧
            destination ∈ next.nodes ∧ cfg.index ≤ next.index)
    (by
      intro origin member
      have originIndex := history.positions origin member
      simp only [Expr.implies_holds, activeConfigurationExpr_correct assignment state tracking correct,
        orExpr, Expr.Holds, NatTerm.eval, decide_eq_true_eq, originIndex]
      rw [anySnapshots_correct assignment _ _ history _
        (fun next => (currentConfiguration (state.nodes node)).index ≤ next.index ∧
          destination ∈ next.nodes ∧ origin.configuration.index ≤ next.index)
        (by
          intro next member
          have nextIndex := history.positions next member
          simp [Expr.Holds, activeConfigurationExpr_correct assignment state tracking correct,
            originIndex, nextIndex])]
      simp only [not_and_or, not_not])]
  rw [configurationRank_le_iff]
  simp [activeConfigurations, and_assoc]

theorem successorExpr_correct {holes : Nat}
    (assignment : Fin holes -> Nat) (state : Template holes) (tracking : Tracking holes)
    (correct : TrackingCorrect assignment state tracking) (source destination : Node) :
    (successorExpr state tracking source destination).Holds assignment ↔
      plausibleSuccessor state source destination := by
  simp [successorExpr, allExpr_map_correct, Expr.implies_holds, Expr.Holds, NatTerm.eval,
    activeMemberExpr_correct assignment state tracking correct,
    configurationRankLeExpr_correct assignment state tracking correct,
    matchValue, plausibleSuccessor, and_imp]

theorem membershipRequirementsExpr_correct {holes : Nat}
    (assignment : Fin holes -> Nat) (state : Template holes) (tracking : Tracking holes)
    (correct : TrackingCorrect assignment state tracking) (action : Action Node (Value holes)) :
    (membershipRequirementsExpr state tracking action).Holds assignment ↔ membershipRequirements state action := by
  cases action <;>
    simp [membershipRequirementsExpr, membershipRequirements, orExpr, Expr.Holds,
      activeMemberExpr_correct assignment state tracking correct,
      campaignExpr_correct assignment state tracking correct, anyExpr_correct,
      successorExpr_correct assignment state tracking correct,
      completedMemberExpr_correct assignment state tracking correct,
      exists_exists_and_eq_and, hasOtherActiveReplica, Finset.Nonempty]
  all_goals first | tauto | (apply exists_congr; intro peer; tauto)

theorem allocatedExpr_correct {holes : Nat}
    (assignment : Fin holes -> Nat) (state : Template holes) (tracking : Tracking holes)
    (correct : TrackingCorrect assignment state tracking) (node : Node) :
    (allocatedExpr tracking node).Holds assignment ↔ state.allocated node := by
  simp [allocatedExpr, Expr.Holds, NatTerm.eval, correct.allocated, mapState_allocated]

theorem refreshedRetiredExpr_correct {holes : Nat}
    (assignment : Fin holes -> Nat) (state : Template holes) (tracking : Tracking holes)
    (correct : TrackingCorrect assignment state tracking) (node : Node) :
    (refreshedRetiredExpr state tracking node).Holds assignment ↔
      (refreshRetirementState node (state.nodes node)).membershipState = .retiredCommitted :=
  ControlTraceRetirement.retiredExpr_correct assignment node (state.nodes node) _
    (correct.configurations node _) _ (correct.logPositions node) _ (correct.commitIndices node _)

theorem retiredStateExpr_correct {holes : Nat}
    (assignment : Fin holes -> Nat) (state : Template holes) (tracking : Tracking holes)
    (correct : TrackingCorrect assignment state tracking) (node : Node) :
    (retiredStateExpr state tracking node).Holds assignment ↔
      (state.nodes node).membershipState = .retiredCommitted := by
  unfold retiredStateExpr
  split_ifs with agrees
  · simpa [agrees] using refreshedRetiredExpr_correct assignment state tracking correct node
  · simp [Expr.Holds]

theorem appendConfigurationSnapshots_correct {holes : Nat}
    (assignment : Fin holes -> Nat) (state : Template holes) (tracking : Tracking holes)
    (correct : TrackingCorrect assignment state tracking) (node : Node)
    (content : EntryContent Node (Value holes)) :
    ControlTraceConfigurations.Correct assignment
      (allConfigurations ((state.nodes node).log ++ [{ term := (state.nodes node).currentTerm, content }]))
      (appendConfigurationSnapshots state tracking node content) := by
  have history := correct.configurations node (allConfigurations (state.nodes node).log)
  cases content with
  | reconfiguration nodes =>
      have result := ControlTraceConfigurations.appendPure_correct assignment _ _ history
        { index := (state.nodes node).log.length + 1, nodes }
        (.add (tracking.logLengths node) (.literal 1))
        (by simp [NatTerm.eval, correct.logLengths, mapState_nodes_get, mapNodeState])
      simpa [appendConfigurationSnapshots, configurationSnapshots, allConfigurations, configurationsInLog,
        configurationsInLogFrom_append, configurationsInLogFrom, List.append_assoc, Nat.add_comm] using result
  | _ =>
      simpa [appendConfigurationSnapshots, configurationSnapshots, allConfigurations, configurationsInLog,
        configurationsInLogFrom_append, configurationsInLogFrom] using history

theorem appendRetiredExpr_correct {holes : Nat}
    (assignment : Fin holes -> Nat) (state : Template holes) (tracking : Tracking holes)
    (correct : TrackingCorrect assignment state tracking) (node : Node)
    (content : EntryContent Node (Value holes)) :
    (appendRetiredExpr state tracking node content).Holds assignment ↔
      (refreshRetirementState node { state.nodes node with
        log := (state.nodes node).log ++ [{ term := (state.nodes node).currentTerm, content }] }).membershipState =
          .retiredCommitted := by
  apply ControlTraceRetirement.retiredExpr_correct assignment node
    { state.nodes node with log := (state.nodes node).log ++
      [{ term := (state.nodes node).currentTerm, content }] }
  · exact appendConfigurationSnapshots_correct assignment state tracking correct node content
  · intro index
    simp only [Function.update_apply]
    split_ifs with appended
    · simp [NatTerm.eval, correct.logLengths, mapState_nodes_get, mapNodeState, appended]
    · exact correct.logPositions node index
  · exact correct.commitIndices node _

theorem structuralClientExpr_correct {holes : Nat}
    (assignment : Fin holes -> Nat) (state : Template holes) (tracking : Tracking holes)
    (correct : TrackingCorrect assignment state tracking) (node : Node) (transaction : Value holes) :
    (structuralClientExpr state tracking node transaction).Holds assignment ↔
      structuralClientRequestEnabled state node transaction := by
  simp [structuralClientExpr, Expr.Holds,
    allocatedExpr_correct assignment state tracking correct,
    retiredStateExpr_correct assignment state tracking correct,
    appendRetiredExpr_correct assignment state tracking correct, NatTerm.eval,
    structuralClientRequestEnabled]

theorem promotedRetiredExpr_correct {holes : Nat}
    (assignment : Fin holes -> Nat) (state : Template holes) (tracking : Tracking holes)
    (correct : TrackingCorrect assignment state tracking) (node : Node) :
    (promotedRetiredExpr state tracking node).Holds assignment ↔
      (refreshRetirementState node
        { state.nodes node with
          log := (state.nodes node).log.take (maxCommittableIndex (state.nodes node).log) }).membershipState = .retiredCommitted := by
  have history := ControlTraceConfigurations.truncatePure_correct assignment _ _
    (correct.configurations node (allConfigurations (state.nodes node).log))
    (tracking.logPositions node (maxCommittableIndex (state.nodes node).log))
  rw [correct.logPositions, ← ControlTraceConfigurations.allConfigurations_take] at history
  exact ControlTraceRetirement.retiredExpr_correct assignment node
    { state.nodes node with log := (state.nodes node).log.take (maxCommittableIndex (state.nodes node).log) }
    _ history _ (correct.logPositions node) _ (correct.commitIndices node _)

theorem terminalRetiredExpr_correct {holes : Nat}
    (assignment : Fin holes -> Nat) (state : Template holes) (tracking : Tracking holes)
    (correct : TrackingCorrect assignment state tracking) (node : Node) :
    (terminalRetiredExpr state tracking node).Holds assignment ↔ terminalRetirementCommit state node :=
  ControlTraceRetirement.retiredExpr_correct assignment node
    { state.nodes node with commitIndex := highestCommittableIndex state node }
    _ (correct.configurations node _) _ (correct.logPositions node)
    _ (highestCommittableValue_correct assignment state tracking correct node)

theorem retirementRequirementsExpr_correct {holes : Nat}
    (assignment : Fin holes -> Nat) (state : Template holes) (tracking : Tracking holes)
    (correct : TrackingCorrect assignment state tracking) (action : Action Node (Value holes)) :
    (retirementRequirementsExpr state tracking action).Holds assignment ↔ retirementRequirements state action := by
  cases action <;> simp [retirementRequirementsExpr, retirementRequirements, Expr.Holds,
    retiredStateExpr_correct assignment state tracking correct,
    appendRetiredExpr_correct assignment state tracking correct,
    promotedRetiredExpr_correct assignment state tracking correct,
    terminalRetiredExpr_correct assignment state tracking correct]

theorem sourceAllowedExpr_correct {holes : Nat}
    (assignment : Fin holes -> Nat) (state : Template holes) (tracking : Tracking holes)
    (correct : TrackingCorrect assignment state tracking) (message : Message Node (Value holes)) :
    (sourceAllowedExpr tracking message).Holds assignment ↔ messageSourceAllowed state message := by
  cases message <;> simp [sourceAllowedExpr, messageSourceAllowed, Expr.Holds,
    allocatedExpr_correct assignment state tracking correct]

theorem newerMessageExpr_correct {holes : Nat}
    (assignment : Fin holes -> Nat) (state : Template holes) (tracking : Tracking holes)
    (correct : TrackingCorrect assignment state tracking) (source destination : Node) :
    (newerMessageExpr state tracking source destination).Holds assignment ↔
      (newerMessage? state source destination).isSome := by
  cases selected : takeFirstFrom source (state.network destination) with
  | none => simp [newerMessageExpr, newerMessage?, selected, Expr.Holds]
  | some pair =>
      rcases pair with ⟨message, rest⟩
      simp [newerMessageExpr, newerMessage?, selected, Expr.Holds,
        sourceAllowedExpr_correct assignment state tracking correct,
        correct.currentTerms, correct.packetTerms]

theorem actionRequirementsExpr_correct {holes : Nat}
    (assignment : Fin holes -> Nat) (state : Template holes) (tracking : Tracking holes)
    (correct : TrackingCorrect assignment state tracking) (action : Action Node (Value holes)) :
    (actionRequirementsExpr state tracking action).Holds assignment ↔
      actionRequirements state action := by
  cases action <;>
    simp [actionRequirementsExpr, actionRequirements, allExpr_map_correct, Expr.Holds,
      allocatedExpr_correct assignment state tracking correct, NatTerm.eval,
      voteMajorityExpr_correct assignment state tracking correct,
      committableExpr_correct assignment state tracking correct,
      latestConfigurationValue_correct assignment state tracking correct,
      retiredStateExpr_correct assignment state tracking correct,
      pendingRetirementExpr_correct assignment state tracking correct,
      newerMessageExpr_correct assignment state tracking correct, minValue_eval,
      correct.sentIndex, correct.logLengths, correct.joined, mapState_nodes_get,
      mapNodeState, mapState, List.length_pos_iff, orExpr]
  all_goals tauto

theorem enabled_actionRequirements {holes : Nat}
    (state : Template holes) (action : Action Node (Value holes)) :
    Enabled state action → actionRequirements state action := by
  cases action <;> simp only [Enabled, actionRequirements, allocationNodes, actionRoleNode,
    List.mem_cons, List.not_mem_nil, or_false, forall_eq_or_imp, forall_eq]
  all_goals tauto

theorem enabled_membershipRequirements {holes : Nat}
    (state : Template holes) (action : Action Node (Value holes)) :
    Enabled state action → membershipRequirements state action := by
  cases action <;> simp only [Enabled, membershipRequirements]
  all_goals tauto

theorem enabled_retirementRequirements {holes : Nat}
    (state : Template holes) (action : Action Node (Value holes)) :
    Enabled state action → retirementRequirements state action := by
  cases action <;> simp only [Enabled, retirementRequirements, actionRoleNode]
  all_goals tauto

theorem actionGuard_correct {holes : Nat}
    (assignment : Fin holes -> Nat) (state : Template holes) (tracking : Tracking holes)
    (correct : TrackingCorrect assignment state tracking) (action : Action Node (Value holes)) :
    (actionGuard state tracking action).Holds assignment ↔ Enabled state action := by
  simp only [actionGuard, Expr.Holds,
    actionRequirementsExpr_correct assignment state tracking correct,
    membershipRequirementsExpr_correct assignment state tracking correct,
    retirementRequirementsExpr_correct assignment state tracking correct, roleGuard_correct]
  exact ⟨fun ⟨requirements, enabled⟩ => enabled requirements,
    fun enabled => ⟨⟨enabled_actionRequirements state action enabled,
      enabled_membershipRequirements state action enabled,
      enabled_retirementRequirements state action enabled⟩, fun _ => enabled⟩⟩

def FrameCorrect {holes : Nat}
    (assignment : Fin holes -> Nat)
    (frame : Frame holes) : Prop :=
  TrackingCorrect assignment frame.state frame.tracking

theorem finishFrame_correct {holes : Nat} (assignment : Fin holes -> Nat)
    (position : Nat) (node : Node) (frame : Frame holes) (correct : FrameCorrect assignment frame) :
    FrameCorrect assignment (finishFrame position node frame) :=
  refreshCompletedTracking_correct assignment position frame.pathId frame.state frame.tracking correct node

@[simp]
theorem controlSuccessor_eq_next {holes : Nat} (state : Template holes) (action : Action Node (Value holes)) :
    controlSuccessor state action = next state action := by
  rfl

@[simp]
theorem controlFrame_state {holes : Nat} (position : Nat) (action : Action Node (Value holes)) (frame : Frame holes) :
    (controlFrame position action frame).state = next frame.state action := by
  cases action <;> simp [controlFrame, controlSendFrame, rawControlFrame, finishFrame, apply_ite]

theorem nodeBoundsClauses_correct {holes : Nat}
    (bounds : Bounds)
    (assignment : Fin holes -> Nat)
    (state : Template holes)
    (tracking : Tracking holes)
    (trackingCorrect : TrackingCorrect assignment state tracking)
    (node : Node) :
    ClausesHold assignment
        (nodeBoundsClauses bounds state tracking node) ↔
      BoundedState.OptionalLocalWithin bounds
        ((mapState (NatTerm.eval assignment) state).node? node) := by
  cases found : state.nodes.node? node with
  | none =>
      have mappedMissing :
          (mapState (NatTerm.eval assignment) state).nodes.node? node =
            none := by
        change (mapNodeStore
          (NatTerm.eval assignment) state.nodes).node? node = none
        rw [mapNodeStore_node?, found]
        rfl
      simp [nodeBoundsClauses, found, mappedMissing,
        State.node?, BoundedState.OptionalLocalWithin, ClausesHold]
  | some localState =>
      have mappedFound :
          (mapState (NatTerm.eval assignment) state).nodes.node? node =
            some (mapNodeState (NatTerm.eval assignment) localState) := by
        change (mapNodeStore
          (NatTerm.eval assignment) state.nodes).node? node =
          some (mapNodeState (NatTerm.eval assignment) localState)
        rw [mapNodeStore_node?, found]
        rfl
      simp only [nodeBoundsClauses, State.node?, found, mappedFound]
      simp only [BoundedState.OptionalLocalWithin]
      apply localBoundsClauses_correct
      · have correct := trackingCorrect.logLengths node
        rw [mapState_nodes_get] at correct
        have sourceGet : state.nodes node = localState := by
          simp [NodeStore.get, found]
        rw [sourceGet] at correct
        exact correct
      · have sourceGet : state.nodes node = localState := by
          simp [NodeStore.get, found]
        simpa [sourceGet] using trackingCorrect.currentTerms node
      · exact trackingCorrect.commitIndices node
      · exact trackingCorrect.logPositions node
      · exact trackingCorrect.logTerms node
      · intro peer
        have correct := trackingCorrect.sentIndex node peer
        rw [mapState_nodes_get] at correct
        have sourceGet : state.nodes node = localState := by
          simp [NodeStore.get, found]
        rw [sourceGet] at correct
        exact correct

theorem queueBoundsClauses_correct {holes : Nat}
    (bounds : Bounds)
    (assignment : Fin holes -> Nat)
    (state : Template holes)
    (tracking : Tracking holes)
    (trackingCorrect : TrackingCorrect assignment state tracking)
    (node : Node) :
    ClausesHold assignment
        (queueBoundsClauses bounds state tracking node) ↔
      ((mapState (NatTerm.eval assignment) state).network node).length ≤
          bounds.queueCapacity /\
        ((mapState (NatTerm.eval assignment) state).network node).Forall
          (BoundedState.MessageWithin bounds) := by
  unfold queueBoundsClauses
  rw [show
    atMostClause "queue capacity"
          (tracking.queueLengths node) bounds.queueCapacity ::
        (state.network node).flatMap (messageBoundsClauses bounds tracking.packetTerms tracking.packetFields) =
    [atMostClause "queue capacity"
          (tracking.queueLengths node) bounds.queueCapacity] ++
        (state.network node).flatMap (messageBoundsClauses bounds tracking.packetTerms tracking.packetFields) by rfl]
  rw [clausesHold_append, messageListBoundsClauses_correct bounds assignment
    tracking.packetTerms trackingCorrect.packetTerms tracking.packetFields trackingCorrect.packetFields]
  simp [ClausesHold, atMostClause, Expr.Holds, NatTerm.eval,
    trackingCorrect.queueLengths node, mapState]

theorem submittedBoundsClauses_correct {holes : Nat}
    (bounds : Bounds)
    (assignment : Fin holes -> Nat)
    (state : Template holes) :
    ClausesHold assignment
        ((submittedTerms state).map fun transaction =>
          lessClause "submitted transaction domain" transaction
            bounds.transactionCount) ↔
      BoundedState.TransactionsWithin bounds
        (state.submittedTxIds.image (NatTerm.eval assignment)) := by
  simp only [ClausesHold, List.mem_map, forall_exists_index, and_imp,
    forall_apply_eq_imp_iff₂]
  simp [lessClause, Expr.Holds, NatTerm.eval, submittedTerms,
    BoundedState.TransactionsWithin]

theorem allNodeBoundsClauses_correct {holes : Nat}
    (bounds : Bounds)
    (assignment : Fin holes -> Nat)
    (state : Template holes)
    (tracking : Tracking holes)
    (trackingCorrect : TrackingCorrect assignment state tracking) :
    ClausesHold assignment
        ((List.finRange NODE_COUNT).flatMap
          (nodeBoundsClauses bounds state tracking)) ↔
      ∀ node,
        BoundedState.OptionalLocalWithin bounds
          ((mapState (NatTerm.eval assignment) state).node? node) := by
  rw [clausesHold_flatMap]
  simp only [List.mem_finRange, true_implies]
  exact forall_congr' fun node =>
    nodeBoundsClauses_correct bounds assignment state tracking
      trackingCorrect node

theorem allQueueBoundsClauses_correct {holes : Nat}
    (bounds : Bounds)
    (assignment : Fin holes -> Nat)
    (state : Template holes)
    (tracking : Tracking holes)
    (trackingCorrect : TrackingCorrect assignment state tracking) :
    ClausesHold assignment
        ((List.finRange NODE_COUNT).flatMap
          (queueBoundsClauses bounds state tracking)) ↔
      ∀ node,
        ((mapState (NatTerm.eval assignment) state).network node).length ≤
            bounds.queueCapacity /\
          ((mapState (NatTerm.eval assignment) state).network node).Forall
            (BoundedState.MessageWithin bounds) := by
  rw [clausesHold_flatMap]
  simp only [List.mem_finRange, true_implies]
  exact forall_congr' fun node =>
    queueBoundsClauses_correct bounds assignment state tracking
      trackingCorrect node

theorem stateBoundsClauses_correct {holes : Nat}
    (bounds : Bounds)
    (assignment : Fin holes -> Nat)
    (state : Template holes)
    (tracking : Tracking holes)
    (trackingCorrect : TrackingCorrect assignment state tracking) :
    ClausesHold assignment
        (stateBoundsClauses bounds state tracking) ↔
      BoundedState.WithinBounds bounds
        (mapState (NatTerm.eval assignment) state) := by
  simp only [stateBoundsClauses, clausesHold_append,
    allNodeBoundsClauses_correct bounds assignment state tracking
      trackingCorrect,
    allQueueBoundsClauses_correct bounds assignment state tracking
      trackingCorrect, submittedBoundsClauses_correct]
  unfold BoundedState.WithinBounds
  tauto

def ObservedValueHolds {holes : Nat}
    (assignment : Fin holes -> Nat)
    (state : State Node Nat) :
    TraceInstructions.Observation holes -> Prop
  | .role node value => (state.nodes node).role = value
  | .currentTerm node value => (state.nodes node).currentTerm = value
  | .logLength node value => (state.nodes node).log.length = value
  | .queueLength node value => (state.network node).length = value
  | .commitIndex node value => (state.nodes node).commitIndex = value
  | .allocated node value => decide (state.allocated node) = value
  | .joined node value => decide (node ∈ state.hasJoined) = value
  | .submitted transaction value =>
      decide (transaction.eval assignment ∈ state.submittedTxIds) = value

theorem observationExpression_correct {holes : Nat}
    (assignment : Fin holes -> Nat)
    (state : Template holes)
    (tracking : Tracking holes)
    (trackingCorrect : TrackingCorrect assignment state tracking)
    (observation : TraceInstructions.Observation holes) :
    (observationExpression state tracking observation).Holds assignment ↔
      ObservedValueHolds assignment
        (mapState (NatTerm.eval assignment) state) observation := by
  cases observation with
  | role node value =>
      simp [observationExpression, ObservedValueHolds,
        Expr.Holds, NatTerm.eval, mapState_nodes_get, mapNodeState]
  | currentTerm node value =>
      simp [observationExpression, ObservedValueHolds,
        Expr.Holds, NatTerm.eval, trackingCorrect.currentTerms,
        mapState_nodes_get, mapNodeState]
  | logLength node value =>
      simp only [observationExpression, Expr.Holds,
        ObservedValueHolds, NatTerm.eval]
      rw [trackingCorrect.logLengths node]
  | queueLength node value =>
      simp only [observationExpression, Expr.Holds,
        ObservedValueHolds, NatTerm.eval]
      rw [trackingCorrect.queueLengths node]
  | commitIndex node value =>
      simp [observationExpression, ObservedValueHolds,
        Expr.Holds, NatTerm.eval, trackingCorrect.commitIndices, mapState_nodes_get, mapNodeState]
  | allocated node value =>
      cases value <;>
        simp [observationExpression, ObservedValueHolds, Expr.Holds,
          boolValue, NatTerm.eval, trackingCorrect.allocated]
  | joined node value =>
      cases value <;>
        simp [observationExpression, ObservedValueHolds, Expr.Holds,
          boolValue, NatTerm.eval, trackingCorrect.joined]
  | submitted transaction value =>
      cases value <;>
        simp [observationExpression, ObservedValueHolds, Expr.Holds,
          fresh_submitted_correct, mapState]

theorem observationClauses_correct {holes : Nat}
    (bounds : Bounds)
    (assignment : Fin holes -> Nat)
    (state : Template holes)
    (tracking : Tracking holes)
    (trackingCorrect : TrackingCorrect assignment state tracking)
    (observation : TraceInstructions.Observation holes) :
    ClausesHold assignment
        (observationClauses bounds state tracking observation) ↔
      observation.Holds (observationBounds bounds) assignment
        (mapState (NatTerm.eval assignment) state) := by
  cases observation with
  | submitted transaction value =>
      cases value <;>
        simp only [observationClauses, ClausesHold, List.mem_cons,
          forall_eq_or_imp, lessClause, Expr.Holds, NatTerm.eval]
      · rw [observationExpression_correct assignment state tracking
          trackingCorrect
          (.submitted transaction false)]
        simp [ObservedValueHolds, observationBounds,
          TraceInstructions.Observation.Holds, mapState]
      · rw [observationExpression_correct assignment state tracking
          trackingCorrect
          (.submitted transaction true)]
        simp [ObservedValueHolds, observationBounds,
          TraceInstructions.Observation.Holds, mapState]
  | role node value
  | currentTerm node value
  | logLength node value
  | queueLength node value
  | commitIndex node value
  | allocated node value
  | joined node value =>
      simp [observationClauses, ClausesHold,
        observationExpression_correct assignment state tracking
          trackingCorrect, ObservedValueHolds,
        TraceInstructions.Observation.Holds]

theorem observationGroup_correct {holes : Nat}
    (bounds : Bounds)
    (assignment : Fin holes -> Nat)
    (state : Template holes)
    (tracking : Tracking holes)
    (trackingCorrect : TrackingCorrect assignment state tracking)
    (observation : TraceInstructions.Observation holes) :
    (observationGroup bounds state tracking observation).Holds
        assignment ↔
      BoundedState.WithinBounds bounds
          (mapState (NatTerm.eval assignment) state) /\
        observation.Holds (observationBounds bounds) assignment
          (mapState (NatTerm.eval assignment) state) := by
  simp only [observationGroup, Group.Holds,
    List.mem_append, or_imp, forall_and]
  rw [← stateBoundsClauses_correct bounds assignment state tracking
    trackingCorrect]
  rw [← observationClauses_correct bounds assignment state tracking
    trackingCorrect observation]
  rfl

theorem clientRequestGroup_correct {holes : Nat}
    (bounds : Bounds)
    (assignment : Fin holes -> Nat)
    (state : Template holes)
    (tracking : Tracking holes)
    (trackingCorrect : TrackingCorrect assignment state tracking)
    (node : Node)
    (transaction : Value holes) :
    (clientRequestGroup bounds state tracking node transaction).Holds
        assignment ↔
      BoundedState.WithinBounds bounds
          (mapState (NatTerm.eval assignment) state) /\
        transaction.eval assignment < bounds.transactionCount /\
          Enabled (mapState (NatTerm.eval assignment) state)
            (.clientRequest node (transaction.eval assignment)) := by
  simp only [clientRequestGroup, Group.Holds, List.mem_append, or_imp, forall_and]
  rw [show
    (∀ clause ∈ stateBoundsClauses bounds state tracking,
      clause.expression.Holds assignment) ↔
      BoundedState.WithinBounds bounds
        (mapState (NatTerm.eval assignment) state) from
    stateBoundsClauses_correct bounds assignment state tracking
      trackingCorrect]
  simp only [List.mem_cons, forall_eq_or_imp,
    lessClause, structuralClientExpr_correct assignment state tracking trackingCorrect, Expr.Holds, NatTerm.eval,
    decide_eq_true_eq, fresh_submitted_correct]
  rw [enabled_mapState_clientRequest_iff
    (NatTerm.eval assignment) state node transaction]
  tauto

theorem leaderWriteGroup_correct {holes : Nat}
    (label : String)
    (bounds : Bounds)
    (assignment : Fin holes -> Nat)
    (state : Template holes)
    (tracking : Tracking holes)
    (trackingCorrect : TrackingCorrect assignment state tracking)
    (action : Action Node (Value holes))
    (targetEnabled : Prop)
    (mappedEnabled : Enabled state action ↔ targetEnabled) :
    (leaderWriteGroup label bounds state tracking action).Holds assignment ↔
      BoundedState.WithinBounds bounds
          (mapState (NatTerm.eval assignment) state) /\
        targetEnabled := by
  simp only [leaderWriteGroup, Group.Holds, List.mem_append, or_imp,
    forall_and]
  rw [show
    (∀ clause ∈ stateBoundsClauses bounds state tracking,
      clause.expression.Holds assignment) ↔
      BoundedState.WithinBounds bounds
        (mapState (NatTerm.eval assignment) state) from
    stateBoundsClauses_correct bounds assignment state tracking
      trackingCorrect]
  simp [actionGuard_correct assignment state tracking trackingCorrect, mappedEnabled]

theorem initialTracking_correct {holes : Nat}
    (assignment : Fin holes -> Nat)
    (state : Template holes) :
    TrackingCorrect assignment state (initialTracking state) := by
  constructor
  · intro node
    simp [initialTracking, NatTerm.eval]
  · intro node
    simp [initialTracking, boolValue, NatTerm.eval, mapState_allocated]
  · intro node
    simp [initialTracking, boolValue, NatTerm.eval, mapState]
  · intro node peer
    simp [initialTracking, NatTerm.eval, mapState_nodes_get, mapNodeState]
  · intro node
    simp [initialTracking, NatTerm.eval, mapState]
  · intro node
    rfl
  · intro message
    rfl
  · intro node index
    rfl
  · intro node index
    rfl
  · intro node index term
    rfl
  · intro message field value
    rfl
  · intro node preVote peer value
    rfl
  · intro node values
    exact ControlTraceConfigurations.literals_correct assignment values
  · intro node peer value
    rfl

theorem nextWriteTracking_positions_correct {holes : Nat}
    (assignment : Fin holes -> Nat) (position pathId : Nat)
    (state : Template holes) (tracking : Tracking holes)
    (correct : TrackingCorrect assignment state tracking) (node : Node) :
    ∀ candidate index,
      ((nextWriteTracking position pathId tracking node (state.nodes node).log.length
        (state.nodes node).currentTerm).logPositions
        candidate index).eval assignment = index := by
  intro candidate index
  by_cases same : candidate = node
  · subst candidate
    by_cases frontier : index = (state.nodes node).log.length + 1
    · subst index
      simp [nextWriteTracking, nextLogLengths, NatTerm.eval, correct.logLengths,
        mapState_nodes_get, mapNodeState]
    · simp [nextWriteTracking, frontier, correct.logPositions]
  · simp [nextWriteTracking, same, correct.logPositions]

theorem nextWriteTracking_terms_correct {holes : Nat}
    (assignment : Fin holes -> Nat) (position pathId : Nat)
    (state : Template holes) (tracking : Tracking holes)
    (correct : TrackingCorrect assignment state tracking) (node : Node) :
    ∀ candidate index term,
      ((nextWriteTracking position pathId tracking node (state.nodes node).log.length
        (state.nodes node).currentTerm).logTerms candidate index term).eval assignment = term := by
  intro candidate index term
  by_cases same : candidate = node
  · subst candidate
    by_cases frontier : index = (state.nodes node).log.length + 1
    · subst index
      by_cases sameTerm : term = (state.nodes node).currentTerm
      · subst term
        simp [nextWriteTracking, NatTerm.eval, correct.currentTerms]
      · simp [nextWriteTracking, sameTerm, NatTerm.eval]
    · simp [nextWriteTracking, frontier, correct.logTerms]
  · simp [nextWriteTracking, same, correct.logTerms]

theorem nextWriteTracking_clientRequest_correct {holes : Nat}
    (assignment : Fin holes -> Nat)
    (position : Nat)
    (pathId : Nat)
    (state : Template holes)
    (tracking : Tracking holes)
    (correct : TrackingCorrect assignment state tracking)
    (node : Node)
    (transaction : Value holes)
    (allocated : state.allocated node) :
    TrackingCorrect assignment
      (next state
        (.clientRequest node
          (.named position 0 "accepted transaction" transaction)))
      (nextWriteTracking position pathId tracking node (state.nodes node).log.length
        (state.nodes node).currentTerm) := by
  have commutes :=
    mapState_clientRequest (NatTerm.eval assignment) state node
      (.named position 0 "accepted transaction" transaction)
  simp only [NatTerm.eval] at commutes
  constructor
  · intro candidate
    rw [commutes]
    by_cases same : candidate = node
    · subst candidate
      simp [nextWriteTracking, nextLogLengths, NatTerm.eval, next,
        mapState_nodes_get, mapNodeState]
      simpa [mapState_nodes_get, mapNodeState] using correct.logLengths node
    · simp [nextWriteTracking, nextLogLengths, NatTerm.eval, next, same,
        mapState_nodes_get, mapNodeState]
      simpa [mapState_nodes_get, mapNodeState] using
        correct.logLengths candidate
  · intro candidate
    rw [commutes]
    simp only [nextWriteTracking]
    by_cases same : candidate = node
    · subst candidate
      have mappedAllocated :
          (mapState (NatTerm.eval assignment) state).allocated node :=
        (mapState_allocated _ _ _).2 allocated
      have nextAllocated :
          (next (mapState (NatTerm.eval assignment) state)
            (.clientRequest node (transaction.eval assignment))).allocated node := by
        simp [next, State.allocated, updateNode, NodeStore.allocated]
      simpa [mappedAllocated, nextAllocated] using correct.allocated node
    · have preserved :
          (next (mapState (NatTerm.eval assignment) state)
                (.clientRequest node (transaction.eval assignment))).allocated
              candidate ↔
            (mapState (NatTerm.eval assignment) state).allocated candidate := by
        simp only [next, State.allocated, updateNode]
        unfold NodeStore.allocated
        rw [NodeStore.node?_set_of_ne _ node candidate _ same]
      simpa [preserved] using correct.allocated candidate
  · intro candidate
    rw [commutes]
    simpa [nextWriteTracking, next] using correct.joined candidate
  · intro candidate peer
    rw [commutes]
    simp only [nextWriteTracking]
    calc
      (tracking.sentIndex candidate peer).eval assignment =
          ((mapState (NatTerm.eval assignment) state).nodes candidate).sentIndex
            peer := correct.sentIndex candidate peer
      _ = ((next (mapState (NatTerm.eval assignment) state)
          (.clientRequest node (transaction.eval assignment))).nodes
            candidate).sentIndex peer := by
        by_cases same : candidate = node <;> simp [next, same]
  · intro candidate
    rw [commutes]
    simpa [nextWriteTracking, next, mapState] using
      correct.queueLengths candidate
  · intro candidate
    by_cases same : candidate = node <;>
      simpa [nextWriteTracking, next, same] using correct.currentTerms candidate
  · exact correct.packetTerms
  · exact nextWriteTracking_positions_correct assignment position pathId state tracking correct node
  · exact correct.commitIndices
  · exact nextWriteTracking_terms_correct assignment position pathId state tracking correct node
  · exact correct.packetFields
  · exact correct.voteMembers
  · exact correct.configurations
  · exact correct.completedMembers

theorem nextWriteTracking_signature_correct {holes : Nat}
    (assignment : Fin holes -> Nat)
    (position : Nat)
    (pathId : Nat)
    (state : Template holes)
    (tracking : Tracking holes)
    (correct : TrackingCorrect assignment state tracking)
    (node : Node)
    (allocated : state.allocated node) :
    TrackingCorrect assignment
      (next state (.signCommittableMessages node))
      (nextWriteTracking position pathId tracking node (state.nodes node).log.length
        (state.nodes node).currentTerm) := by
  have commutes :=
    mapState_signCommittableMessages
      (NatTerm.eval assignment) state node
  constructor
  · intro candidate
    rw [commutes]
    by_cases same : candidate = node
    · subst candidate
      simp [nextWriteTracking, nextLogLengths, NatTerm.eval, next,
        mapState_nodes_get, mapNodeState]
      simpa [mapState_nodes_get, mapNodeState] using correct.logLengths node
    · simp [nextWriteTracking, nextLogLengths, NatTerm.eval, next, same,
        mapState_nodes_get, mapNodeState]
      simpa [mapState_nodes_get, mapNodeState] using
        correct.logLengths candidate
  · intro candidate
    rw [commutes]
    simp only [nextWriteTracking]
    by_cases same : candidate = node
    · subst candidate
      have mappedAllocated :
          (mapState (NatTerm.eval assignment) state).allocated node :=
        (mapState_allocated _ _ _).2 allocated
      have nextAllocated :
          (next (mapState (NatTerm.eval assignment) state)
            (.signCommittableMessages node)).allocated node := by
        simp [next, State.allocated, updateNode, NodeStore.allocated]
      simpa [mappedAllocated, nextAllocated] using correct.allocated node
    · have preserved :
          (next (mapState (NatTerm.eval assignment) state)
              (.signCommittableMessages node)).allocated candidate ↔
            (mapState (NatTerm.eval assignment) state).allocated candidate := by
        simp only [next, State.allocated, updateNode]
        unfold NodeStore.allocated
        rw [NodeStore.node?_set_of_ne _ node candidate _ same]
      simpa [preserved] using correct.allocated candidate
  · intro candidate
    rw [commutes]
    simpa [nextWriteTracking, next] using correct.joined candidate
  · intro candidate peer
    rw [commutes]
    simp only [nextWriteTracking]
    calc
      (tracking.sentIndex candidate peer).eval assignment =
          ((mapState (NatTerm.eval assignment) state).nodes candidate).sentIndex
            peer := correct.sentIndex candidate peer
      _ = ((next (mapState (NatTerm.eval assignment) state)
          (.signCommittableMessages node)).nodes candidate).sentIndex peer := by
        by_cases same : candidate = node <;> simp [next, same]
  · intro candidate
    rw [commutes]
    simpa [nextWriteTracking, next, mapState] using
      correct.queueLengths candidate
  · intro candidate
    by_cases same : candidate = node <;>
      simpa [nextWriteTracking, next, same] using correct.currentTerms candidate
  · exact correct.packetTerms
  · exact nextWriteTracking_positions_correct assignment position pathId state tracking correct node
  · exact correct.commitIndices
  · exact nextWriteTracking_terms_correct assignment position pathId state tracking correct node
  · exact correct.packetFields
  · exact correct.voteMembers
  · exact correct.configurations
  · exact correct.completedMembers

theorem nextWriteTracking_retiredCommitted_correct {holes : Nat}
    (assignment : Fin holes -> Nat)
    (position : Nat)
    (pathId : Nat)
    (state : Template holes)
    (tracking : Tracking holes)
    (correct : TrackingCorrect assignment state tracking)
    (node : Node)
    (allocated : state.allocated node) :
    TrackingCorrect assignment
      (next state (.appendRetiredCommitted node))
      (nextWriteTracking position pathId tracking node (state.nodes node).log.length
        (state.nodes node).currentTerm) := by
  have commutes :=
    mapState_appendRetiredCommitted
      (NatTerm.eval assignment) state node
  constructor
  · intro candidate
    rw [commutes]
    by_cases same : candidate = node
    · subst candidate
      simp [nextWriteTracking, nextLogLengths, NatTerm.eval, next,
        mapState_nodes_get, mapNodeState]
      simpa [mapState_nodes_get, mapNodeState] using correct.logLengths node
    · simp [nextWriteTracking, nextLogLengths, NatTerm.eval, next, same,
        mapState_nodes_get, mapNodeState]
      simpa [mapState_nodes_get, mapNodeState] using
        correct.logLengths candidate
  · intro candidate
    rw [commutes]
    simp only [nextWriteTracking]
    by_cases same : candidate = node
    · subst candidate
      have mappedAllocated :
          (mapState (NatTerm.eval assignment) state).allocated node :=
        (mapState_allocated _ _ _).2 allocated
      have nextAllocated :
          (next (mapState (NatTerm.eval assignment) state)
            (.appendRetiredCommitted node)).allocated node := by
        simp [next, State.allocated, updateNode, NodeStore.allocated]
      simpa [mappedAllocated, nextAllocated] using correct.allocated node
    · have preserved :
          (next (mapState (NatTerm.eval assignment) state)
              (.appendRetiredCommitted node)).allocated candidate ↔
            (mapState (NatTerm.eval assignment) state).allocated candidate := by
        simp only [next, State.allocated, updateNode]
        unfold NodeStore.allocated
        rw [NodeStore.node?_set_of_ne _ node candidate _ same]
      simpa [preserved] using correct.allocated candidate
  · intro candidate
    rw [commutes]
    simpa [nextWriteTracking, next] using correct.joined candidate
  · intro candidate peer
    rw [commutes]
    simp only [nextWriteTracking]
    calc
      (tracking.sentIndex candidate peer).eval assignment =
          ((mapState (NatTerm.eval assignment) state).nodes candidate).sentIndex
            peer := correct.sentIndex candidate peer
      _ = ((next (mapState (NatTerm.eval assignment) state)
          (.appendRetiredCommitted node)).nodes candidate).sentIndex peer := by
        by_cases same : candidate = node <;> simp [next, same]
  · intro candidate
    rw [commutes]
    simpa [nextWriteTracking, next, mapState] using
      correct.queueLengths candidate
  · intro candidate
    by_cases same : candidate = node <;>
      simpa [nextWriteTracking, next, same] using correct.currentTerms candidate
  · exact correct.packetTerms
  · exact nextWriteTracking_positions_correct assignment position pathId state tracking correct node
  · exact correct.commitIndices
  · exact nextWriteTracking_terms_correct assignment position pathId state tracking correct node
  · exact correct.packetFields
  · exact correct.voteMembers
  · exact correct.configurations
  · exact correct.completedMembers

@[simp]
theorem NodeStore.get_allocate
    {TxId : Type}
    (nodes : NodeStore Node TxId)
    (added : Finset Node)
    (node : Node) :
    nodes.allocate added node = nodes node := by
  by_cases allocated : nodes.allocated node
  · simp [NodeStore.get,
      NodeStore.node?_allocate_of_allocated nodes added node allocated]
  · by_cases member : node ∈ added
    · have missing : nodes.node? node = none := by
        cases found : nodes.node? node <;>
          simp_all [NodeStore.allocated]
      simp [NodeStore.get, missing,
        NodeStore.node?_allocate_of_not_allocated_of_mem
          nodes added node allocated member]
    · have missing : nodes.node? node = none := by
        cases found : nodes.node? node <;>
          simp_all [NodeStore.allocated]
      simp [NodeStore.get, missing,
        NodeStore.node?_allocate_of_not_allocated_of_not_mem
          nodes added node allocated member]

theorem changeConfiguration_allocated_iff
    {TxId : Type}
    [DecidableEq TxId]
    (state : State Node TxId)
    (source candidate : Node)
    (configuration : Finset Node) :
    (next state (.changeConfiguration source configuration)).allocated candidate ↔
      state.allocated candidate \/
        candidate = source \/
          candidate ∈
            configuration \ (latestConfiguration (state.nodes source)).nodes := by
  let added :=
    configuration \ (latestConfiguration (state.nodes source)).nodes
  change
    (next state (.changeConfiguration source configuration)).allocated
        candidate ↔
      state.allocated candidate \/ candidate = source \/ candidate ∈ added
  by_cases same : candidate = source
  · subst candidate
    simp [next, State.allocated, updateNode, NodeStore.allocated]
  · simp only [next]
    simp only [State.allocated, updateNode, NodeStore.allocated]
    rw [NodeStore.node?_set_of_ne _ source candidate _ same]
    by_cases allocated : state.nodes.allocated candidate
    · rw [NodeStore.node?_allocate_of_allocated _ _ _ allocated]
      constructor
      · exact fun present => Or.inl present
      · exact fun _ => allocated
    · by_cases member : candidate ∈ added
      · rw [NodeStore.node?_allocate_of_not_allocated_of_mem
          _ _ _ allocated member]
        simp [State.allocated, NodeStore.allocated, allocated, same, member]
      · rw [NodeStore.node?_allocate_of_not_allocated_of_not_mem
          _ _ _ allocated member]
        have missing : state.nodes.node? candidate = none := by
          cases found : state.nodes.node? candidate <;>
            simp_all [NodeStore.allocated]
        simp [missing, same, member]

theorem changeConfiguration_get_of_ne
    {TxId : Type}
    [DecidableEq TxId]
    (state : State Node TxId)
    (source candidate : Node)
    (configuration : Finset Node)
    (different : Not (candidate = source)) :
    (next state (.changeConfiguration source configuration)).nodes candidate =
      state.nodes candidate := by
  simp only [next]
  rw [updateNode_of_ne _ source candidate _ different]
  exact NodeStore.get_allocate state.nodes
    (configuration \ (latestConfiguration (state.nodes source)).nodes)
    candidate

theorem nextConfigurationTracking_correct {holes : Nat}
    (assignment : Fin holes -> Nat)
    (position : Nat)
    (pathId : Nat)
    (state : Template holes)
    (tracking : Tracking holes)
    (correct : TrackingCorrect assignment state tracking)
    (source : Node)
    (configuration : Finset Node) :
    TrackingCorrect assignment
      (next state (.changeConfiguration source configuration))
      (nextConfigurationTracking position pathId state tracking source
        configuration) := by
  have commutes :=
    mapState_changeConfiguration
      (NatTerm.eval assignment) state source configuration
  let added :=
    configuration \ (latestConfiguration (state.nodes source)).nodes
  constructor
  · intro candidate
    rw [commutes]
    by_cases same : candidate = source
    · subst candidate
      simp [nextConfigurationTracking, nextLogLengths, NatTerm.eval, next,
        added, mapState_nodes_get, mapNodeState]
      simpa [mapState_nodes_get, mapNodeState] using
        correct.logLengths source
    · rw [changeConfiguration_get_of_ne _ _ _ _ same]
      simp [nextConfigurationTracking, nextLogLengths, same, NatTerm.eval]
      simpa [mapState_nodes_get, mapNodeState] using
        correct.logLengths candidate
  · intro candidate
    simp only [nextConfigurationTracking, NatTerm.eval, maxValue_eval,
      addedConfigurationMemberValue_correct assignment state tracking correct,
      correct.allocated, mapState_allocated, changeConfiguration_allocated_iff]
    split_ifs <;> simp_all [NatTerm.eval, maxValue_eval,
      addedConfigurationMemberValue_correct assignment state tracking correct,
      correct.allocated, mapState_allocated]
    all_goals split_ifs <;> simp_all
  · intro candidate
    simp only [nextConfigurationTracking, NatTerm.eval, maxValue_eval,
      addedConfigurationMemberValue_correct assignment state tracking correct, correct.joined]
    simp only [mapState, next, Finset.mem_union]
    split_ifs <;> simp_all
  · intro candidate peer
    rw [commutes]
    by_cases same : candidate = source
    · subst candidate
      simp [nextConfigurationTracking, Expr.ite_eval, Expr.Holds, NatTerm.eval,
        addedConfigurationMemberValue_correct assignment state tracking correct,
        correct.logLengths, correct.sentIndex, next, mapState_nodes_get, mapNodeState,
        latestConfiguration_mapNodeState, NodeStore.get_allocate]
      simp only [latestConfiguration, configurationsInLog_map]
    · rw [changeConfiguration_get_of_ne _ _ _ _ same]
      simp [nextConfigurationTracking, same, NatTerm.eval]
      simpa [mapState_nodes_get, mapNodeState] using
        correct.sentIndex candidate peer
  · intro candidate
    rw [commutes]
    simpa [nextConfigurationTracking, next, mapState] using
      correct.queueLengths candidate
  · intro candidate
    by_cases same : candidate = source
    · subst candidate
      simpa [nextConfigurationTracking, next, NodeStore.get_allocate] using
        correct.currentTerms source
    · simpa [nextConfigurationTracking,
        changeConfiguration_get_of_ne state source candidate configuration same] using
        correct.currentTerms candidate
  · exact correct.packetTerms
  · exact nextWriteTracking_positions_correct assignment position pathId state tracking correct source
  · exact correct.commitIndices
  · exact nextWriteTracking_terms_correct assignment position pathId state tracking correct source
  · exact correct.packetFields
  · exact correct.voteMembers
  · intro node values
    simp only [nextConfigurationTracking, Function.update_apply, ite_apply]
    split_ifs with same desired
    · subst node
      subst values
      have appended := ControlTraceConfigurations.append_correct assignment
        (allConfigurations (state.nodes source).log)
        (tracking.configurations source (allConfigurations (state.nodes source).log))
        (correct.configurations source _) { index := (state.nodes source).log.length + 1, nodes := configuration }
        ((nextLogLengths position pathId tracking.logLengths source) source)
        position (pathSlot pathId CONFIGURATION_SLOT)
        (by simp [nextLogLengths, NatTerm.eval, correct.logLengths, mapState_nodes_get, mapNodeState])
      simpa [allConfigurations, configurationsInLog, configurationsInLogFrom_append,
        configurationsInLogFrom, List.append_assoc, Nat.add_comm] using appended
    · exact correct.configurations _ _
    · exact correct.configurations _ _
  · exact correct.completedMembers

theorem attachAppendFrame_eval_state {holes : Nat}
    (assignment : Fin holes -> Nat)
    (position priorLength : Nat)
    (tracking : Tracking holes)
    (source destination : Node)
    (batchEnd pathId : Nat)
    (tree : Guarded holes (Template holes)) :
    ((attachAppendFrame position priorLength tracking source destination
      batchEnd pathId tree).eval assignment).state =
        tree.eval assignment := by
  induction tree generalizing pathId with
  | pure => rfl
  | branch condition thenTree elseTree thenCorrect elseCorrect =>
      simp only [attachAppendFrame, Guarded.eval_branchSmart, Guarded.eval]
      by_cases holds : condition.Holds assignment
      · simp [holds, thenCorrect]
      · simp [holds, elseCorrect]

theorem guardedAppendEntries_queue_length {holes : Nat}
    (assignment : Fin holes -> Nat)
    (state : Template holes)
    (source destination : Node)
    (batchEnd : Nat) :
    let successor :=
      (GuardedAppendEntries.step state source destination batchEnd).eval
        assignment
    (successor.network destination).length =
        (state.network destination).length \/
      (successor.network destination).length =
        (state.network destination).length + 1 := by
  simp [GuardedAppendEntries.step, Guarded.eval, next, enqueue,
    updateQueue, makeAppendEntriesRequest, Message.destination]

theorem attachAppendFrame_correct {holes : Nat}
    (bounds : Bounds)
    (assignment : Fin holes -> Nat)
    (position priorLength : Nat)
    (state : Template holes)
    (tracking : Tracking holes)
    (trackingCorrect : TrackingCorrect assignment state tracking)
    (source destination : Node)
    (sourceAllocated : state.allocated source)
    (batchEnd pathId : Nat)
    (tree : Guarded holes (Template holes))
    (priorLengthCorrect :
      priorLength = (state.network destination).length)
    (stateCorrect :
      mapState (NatTerm.eval assignment) (tree.eval assignment) =
        next (mapState (NatTerm.eval assignment) state)
          (.appendEntries source destination batchEnd))
    (queueShape :
      ((tree.eval assignment).network destination).length =
          (state.network destination).length \/
        ((tree.eval assignment).network destination).length =
          (state.network destination).length + 1) :
    FrameCorrect assignment
      ((attachAppendFrame position priorLength tracking source destination
        batchEnd pathId tree).eval assignment) := by
  induction tree generalizing pathId with
  | branch condition thenTree elseTree thenCorrect elseCorrect =>
      simp only [attachAppendFrame, Guarded.eval_branchSmart, Guarded.eval]
      by_cases holds : condition.Holds assignment
      · simp only [holds, if_true]
        simp only [Guarded.eval, holds, if_true] at stateCorrect queueShape
        apply thenCorrect
        · exact stateCorrect
        · exact queueShape
      · simp only [holds, if_false]
        simp only [Guarded.eval, holds, if_false] at stateCorrect queueShape
        apply elseCorrect
        · exact stateCorrect
        · exact queueShape
  | pure successor =>
      simp only [attachAppendFrame, Guarded.eval, FrameCorrect]
      simp only [Guarded.eval] at stateCorrect queueShape
      subst priorLength
      constructor
      · intro node
        rw [stateCorrect]
        by_cases same : node = source
        · subst node
          simpa [nextAppendEntriesTracking, next, mapState_nodes_get,
            mapNodeState] using trackingCorrect.logLengths source
        · simpa [nextAppendEntriesTracking, next, same,
            mapState_nodes_get, mapNodeState] using
              trackingCorrect.logLengths node
      · intro node
        rw [stateCorrect]
        by_cases same : node = source
        · subst node
          have sourceMarker :
              (tracking.allocated source).eval assignment = 1 := by
            simpa only [mapState_allocated, sourceAllocated, if_true] using
              trackingCorrect.allocated source
          simpa [nextAppendEntriesTracking, next, State.allocated,
            updateNode, NodeStore.allocated] using sourceMarker
        · simpa [nextAppendEntriesTracking, next, same, mapState_allocated,
            State.allocated, updateNode, NodeStore.allocated] using
              trackingCorrect.allocated node
      · intro node
        rw [stateCorrect]
        simpa [nextAppendEntriesTracking, next, mapState] using
          trackingCorrect.joined node
      · intro node peer
        rw [stateCorrect]
        by_cases sourceNode : node = source
        · subst node
          by_cases targetPeer : peer = destination
          · subst peer
            simp [nextAppendEntriesTracking, next, NatTerm.eval]
          · simp [nextAppendEntriesTracking, next, targetPeer,
              trackingCorrect.sentIndex]
        · simp [nextAppendEntriesTracking, next, sourceNode,
            trackingCorrect.sentIndex]
      · intro node
        by_cases targetNode : node = destination
        · subst node
          simp only [nextAppendEntriesTracking, Function.update_self]
          by_cases grew :
              (state.network destination).length <
                (successor.network destination).length
          · have successorLength :
                (successor.network destination).length =
                  (state.network destination).length + 1 := by
              rcases queueShape with same | added
              · omega
              · exact added
            simp [grew, NatTerm.eval, trackingCorrect.queueLengths,
              mapState, successorLength]
          · have successorLength :
                (successor.network destination).length =
                  (state.network destination).length := by
              rcases queueShape with same | added
              · exact same
              · omega
            simp [grew, trackingCorrect.queueLengths, mapState,
              successorLength]
        · simp [nextAppendEntriesTracking, targetNode,
            trackingCorrect.queueLengths, mapState]
          have lengths := congrArg
            (fun current => (current.network node).length) stateCorrect
          simp only [next, enqueue] at lengths
          simpa [mapState, targetNode, updateQueue,
            makeAppendEntriesRequest, Message.destination] using lengths.symm
      · intro node
        have preserved := congrArg (fun current => (current.nodes node).currentTerm)
          stateCorrect
        simp only [mapState_nodes_get, mapNodeState] at preserved
        by_cases same : node = source
        · subst node
          simpa [nextAppendEntriesTracking, preserved, next] using
            trackingCorrect.currentTerms source
        · simpa [nextAppendEntriesTracking, preserved, next, same,
            mapState_nodes_get, mapNodeState] using trackingCorrect.currentTerms node
      · exact trackingCorrect.packetTerms
      · exact trackingCorrect.logPositions
      · exact trackingCorrect.commitIndices
      · exact trackingCorrect.logTerms
      · exact trackingCorrect.packetFields
      · exact trackingCorrect.voteMembers
      · exact trackingCorrect.configurations
      · exact trackingCorrect.completedMembers

theorem rememberPacketTerm_correct {holes : Nat}
    (assignment : Fin holes -> Nat) (position pathId : Nat)
    (state : Template holes) (tracking : Tracking holes)
    (correct : TrackingCorrect assignment state tracking)
    (source : Node) (message : Message Node (Value holes))
    (termCorrect : message.term = (state.nodes source).currentTerm) :
    ∀ packet, (rememberPacketTerm position pathId state tracking source message packet).eval
      assignment = packet.term := by
  intro packet
  unfold rememberPacketTerm
  split
  · exact correct.packetTerms packet
  · by_cases same : packet = message
    · subst packet
      simp [NatTerm.eval, correct.currentTerms, termCorrect]
    · simp [Function.update_of_ne same, correct.packetTerms]

theorem fieldOrigin_correct {holes : Nat}
    (assignment : Fin holes -> Nat) (position pathId field expected : Nat)
    (term : Value holes) (correct : term.eval assignment = expected) :
    ∀ value, (fieldOrigin position pathId field expected term value).eval assignment = value := by
  intro value
  by_cases same : value = expected
  · subst value
    simp [fieldOrigin, NatTerm.eval, correct]
  · simp [fieldOrigin, same, NatTerm.eval]

theorem votePacketFields_correct {holes : Nat}
    (assignment : Fin holes -> Nat) (position pathId : Nat)
    (state : Template holes) (tracking : Tracking holes)
    (correct : TrackingCorrect assignment state tracking) (source : Node) :
    ∀ field value, (votePacketFields position pathId state tracking source field value).eval
      assignment = value := by
  intro field
  unfold votePacketFields
  split
  · apply fieldOrigin_correct
    simp [electionFrontier, correct.commitIndices, correct.logPositions, lastCommittableIndex]
  · apply fieldOrigin_correct
    exact correct.logTerms source _ _
  · intro value
    rfl

theorem appendPacketFields_correct {holes : Nat}
    (assignment : Fin holes -> Nat) (position pathId : Nat)
    (state : Template holes) (tracking : Tracking holes)
    (correct : TrackingCorrect assignment state tracking)
    (source destination : Node) (batchEnd : Nat) :
    ∀ field value, (appendPacketFields position pathId state tracking source destination batchEnd
      field value).eval assignment = value := by
  intro field
  unfold appendPacketFields
  split
  · apply fieldOrigin_correct
    simpa [mapState_nodes_get, mapNodeState] using correct.sentIndex source destination
  · apply fieldOrigin_correct
    exact correct.logTerms source _ _
  · apply fieldOrigin_correct
    exact correct.commitIndices source _
  · apply fieldOrigin_correct
    simp [NatTerm.eval, correct.logLengths, correct.sentIndex, messageEntries,
      mapState_nodes_get, mapNodeState, Nat.min_comm]
  · split
    · intro term
      simp [NatTerm.eval, correct.logTerms]
    · intro term
      rfl

theorem rememberPacketFields_correct {holes : Nat}
    (assignment : Fin holes -> Nat) (state : Template holes) (tracking : Tracking holes)
    (correct : TrackingCorrect assignment state tracking)
    (message : Message Node (Value holes)) (fields : Nat -> Nat -> Value holes)
    (fieldsCorrect : ∀ field value, (fields field value).eval assignment = value) :
    ∀ packet field value, (rememberPacketFields state tracking message fields packet field value).eval
      assignment = value := by
  intro packet field value
  unfold rememberPacketFields
  split
  · exact correct.packetFields packet field value
  · by_cases same : packet = message
    · subst packet
      simpa using fieldsCorrect field value
    · simp [same, correct.packetFields]

theorem appendQueueLength_correct {holes : Nat}
    (assignment : Fin holes -> Nat) (position pathId : Nat)
    (state : Template holes) (tracking : Tracking holes) (correct : TrackingCorrect assignment state tracking)
    (source destination : Node) (batchEnd : Nat) :
    (appendQueueLength position pathId state tracking source destination batchEnd).eval assignment =
      ((next (mapState (NatTerm.eval assignment) state) (.appendEntries source destination batchEnd)).network destination).length := by
  simp [appendQueueLength, NatTerm.eval, correct.queueLengths, next,
    enqueue, updateQueue, makeAppendEntriesRequest, Message.destination]

theorem rememberAppendPacketFrame_correct {holes : Nat}
    (assignment : Fin holes -> Nat) (position : Nat)
    (before current : Frame holes)
    (beforeCorrect : FrameCorrect assignment before)
    (currentCorrect : FrameCorrect assignment current)
    (source destination : Node) (batchEnd : Nat)
    (stateCorrect : mapState (NatTerm.eval assignment) current.state =
      next (mapState (NatTerm.eval assignment) before.state) (.appendEntries source destination batchEnd)) :
    FrameCorrect assignment
      (rememberAppendPacketFrame position before current source destination batchEnd) := by
  exact { currentCorrect with
    queueLengths := by
      intro node
      change ((Function.update current.tracking.queueLengths destination
        (appendQueueLength position current.pathId before.state before.tracking source destination batchEnd)) node).eval assignment =
          ((mapState (NatTerm.eval assignment) current.state).network node).length
      by_cases same : node = destination
      · subst node
        simp only [Function.update_self]
        rw [appendQueueLength_correct assignment position current.pathId before.state before.tracking beforeCorrect, stateCorrect]
      · simpa [Function.update_of_ne same] using currentCorrect.queueLengths node
    packetTerms := by
      change ∀ message, ((if (before.state.network destination).length <
          (current.state.network destination).length then rememberPacketTerm position current.pathId
        before.state before.tracking source
          (.appendEntriesRequest (makeAppendEntriesRequest before.state source destination batchEnd))
        else current.tracking.packetTerms) message).eval assignment = message.term
      split
      · exact rememberPacketTerm_correct assignment position current.pathId
          before.state before.tracking beforeCorrect source _ rfl
      · exact currentCorrect.packetTerms
    packetFields := by
      change ∀ message field value,
        ((if (before.state.network destination).length < (current.state.network destination).length then
          rememberPacketFields before.state before.tracking
            (.appendEntriesRequest (makeAppendEntriesRequest before.state source destination batchEnd))
            (appendPacketFields position current.pathId before.state before.tracking source destination batchEnd)
        else current.tracking.packetFields) message field value).eval assignment = value
      split
      · apply rememberPacketFields_correct assignment before.state before.tracking beforeCorrect
        exact appendPacketFields_correct assignment position current.pathId
          before.state before.tracking beforeCorrect source destination batchEnd
      · exact currentCorrect.packetFields }

theorem appendFrames_correct {holes : Nat}
    (bounds : Bounds)
    (assignment : Fin holes -> Nat)
    (position : Nat)
    (frame : Frame holes)
    (frameCorrect : FrameCorrect assignment frame)
    (source destination : Node)
    (sourceAllocated : frame.state.allocated source)
    (batchEnd : Nat) :
    FrameCorrect assignment
      ((appendFrames position frame source destination batchEnd).eval
        assignment) := by
  simp only [appendFrames, Guarded.eval_map]
  apply rememberAppendPacketFrame_correct assignment position frame _
    frameCorrect
  · apply attachAppendFrame_correct bounds assignment position
      (frame.state.network destination).length frame.state frame.tracking
      frameCorrect source destination sourceAllocated batchEnd frame.pathId
      (GuardedAppendEntries.step frame.state source destination batchEnd)
      rfl
    · exact GuardedAppendEntries.step_correct assignment frame.state
        source destination batchEnd
    · exact guardedAppendEntries_queue_length assignment frame.state
        source destination batchEnd
  · rw [attachAppendFrame_eval_state]
    exact GuardedAppendEntries.step_correct assignment frame.state
      source destination batchEnd

theorem appendFrames_state_correct {holes : Nat}
    (assignment : Fin holes -> Nat)
    (position : Nat)
    (frame : Frame holes)
    (source destination : Node)
    (batchEnd : Nat) :
    mapState (NatTerm.eval assignment)
        ((appendFrames position frame source destination batchEnd).eval
          assignment).state =
      next (mapState (NatTerm.eval assignment) frame.state)
        (.appendEntries source destination batchEnd) := by
  simp only [appendFrames, Guarded.eval_map, rememberAppendPacketFrame]
  rw [attachAppendFrame_eval_state]
  exact GuardedAppendEntries.step_correct assignment frame.state
    source destination batchEnd

theorem nextControlTracking_correct {holes : Nat}
    (assignment : Fin holes -> Nat) (position pathId : Nat)
    (before after : Template holes) (tracking : Tracking holes)
    (correct : TrackingCorrect assignment before tracking) :
    TrackingCorrect assignment after
      (nextControlTracking position pathId before after tracking) := by
  constructor
  · intro node
    simp only [nextControlTracking]
    split
    · rename_i equal
      simpa [mapState_nodes_get, mapNodeState, equal] using correct.logLengths node
    · simp only [NatTerm.eval]
      split <;>
        simp only [NatTerm.eval, correct.logLengths, mapState_nodes_get,
          mapNodeState, List.length_map] <;> omega
  · intro node
    simp only [nextControlTracking]
    split
    · rename_i equal
      have equivalent : before.allocated node ↔ after.allocated node := by
        by_cases h : before.allocated node <;> by_cases h' : after.allocated node <;>
          simp_all
      simpa [mapState_allocated, equivalent] using
        correct.allocated node
    · simp [NatTerm.eval, boolValue, mapState_allocated]
  · intro node
    simp only [nextControlTracking]
    split
    · rename_i equal
      have equivalent : node ∈ before.hasJoined ↔ node ∈ after.hasJoined := by
        by_cases h : node ∈ before.hasJoined <;>
          by_cases h' : node ∈ after.hasJoined <;> simp_all
      simpa [mapState, equivalent] using correct.joined node
    · simp [NatTerm.eval, boolValue, mapState]
  · intro node peer
    simp only [nextControlTracking]
    split
    · rename_i equal
      simpa [mapState_nodes_get, mapNodeState, equal] using correct.sentIndex node peer
    · simp [NatTerm.eval, mapState_nodes_get, mapNodeState]
  · intro node
    simp only [nextControlTracking]
    split
    · rename_i equal
      simpa [mapState, equal] using correct.queueLengths node
    · simp only [NatTerm.eval]
      split
      · rename_i le
        simp only [NatTerm.eval, correct.queueLengths, mapState, List.length_map]
        omega
      · simp only [NatTerm.eval, correct.queueLengths, mapState, List.length_map]
        omega
  · intro node
    simp only [nextControlTracking]
    split
    · rename_i equal
      simpa [equal] using correct.currentTerms node
    · simp only [NatTerm.eval]
      split
      · rename_i le
        simp only [NatTerm.eval, correct.currentTerms]
        omega
      · simp only [NatTerm.eval, correct.currentTerms]
        omega
  · exact correct.packetTerms
  · exact correct.logPositions
  · exact correct.commitIndices
  · exact correct.logTerms
  · exact correct.packetFields
  · exact correct.voteMembers
  · exact correct.configurations
  · exact correct.completedMembers

theorem controlPacketTerms_correct {holes : Nat}
    (assignment : Fin holes -> Nat) (position pathId : Nat)
    (state : Template holes) (tracking : Tracking holes)
    (correct : TrackingCorrect assignment state tracking)
    (action : Action Node (Value holes)) :
    ∀ message, (controlPacketTerms position pathId state tracking action message).eval
      assignment = message.term := by
  cases action <;> simp only [controlPacketTerms]
  all_goals first
    | exact correct.packetTerms
    | apply rememberPacketTerm_correct assignment position pathId state tracking correct
      rfl

theorem controlQueueLength_correct {holes : Nat}
    (assignment : Fin holes -> Nat) (position pathId : Nat)
    (state : Template holes) (tracking : Tracking holes) (correct : TrackingCorrect assignment state tracking)
    (source : Node) (message : Message Node (Value holes)) (fields : Nat -> Nat -> Value holes)
    (term : message.term = (state.nodes source).currentTerm)
    (fieldsCorrect : ∀ field value, (fields field value).eval assignment = value) :
    (controlQueueLength position pathId state tracking source message fields).eval assignment =
      (enqueue state.network message message.destination).length := by
  simp [controlQueueLength, NatTerm.eval, correct.queueLengths, mapState, enqueue, updateQueue]

theorem controlQueueUpdate_correct {holes : Nat}
    (assignment : Fin holes -> Nat) (position pathId : Nat)
    (state : Template holes) (tracking : Tracking holes) (correct : TrackingCorrect assignment state tracking)
    (source : Node) (message : Message Node (Value holes)) (fields : Nat -> Nat -> Value holes)
    (term : message.term = (state.nodes source).currentTerm)
    (fieldsCorrect : ∀ field value, (fields field value).eval assignment = value) (node : Node) :
    ((Function.update tracking.queueLengths message.destination
      (controlQueueLength position pathId state tracking source message fields)) node).eval assignment =
      (enqueue state.network message node).length := by
  by_cases same : node = message.destination
  · subst node
    simpa using controlQueueLength_correct assignment position pathId state tracking correct source message fields term fieldsCorrect
  · simp [Function.update_apply, same, enqueue, updateQueue, apply_ite, ite_apply, correct.queueLengths, mapState]

theorem controlQueueLengths_correct {holes : Nat}
    (assignment : Fin holes -> Nat) (position pathId : Nat)
    (state : Template holes) (tracking : Tracking holes) (correct : TrackingCorrect assignment state tracking)
    (action : Action Node (Value holes)) :
    ∀ node, (controlQueueLengths position pathId state tracking action node).eval assignment =
      ((mapState (NatTerm.eval assignment) (next state action)).network node).length := by
  have base := nextControlTracking_correct assignment position pathId state (next state action) tracking correct
  cases action with
  | requestVote source destination =>
      intro node
      have result := controlQueueUpdate_correct assignment position pathId state tracking correct source
        (.requestVoteRequest (makeRequestVoteRequest state source destination))
        (votePacketFields position pathId state tracking source) (by rfl)
        (votePacketFields_correct assignment position pathId state tracking correct source) node
      simpa [controlQueueLengths, mapState, next] using result
  | requestPreVote source destination =>
      intro node
      have result := controlQueueUpdate_correct assignment position pathId state tracking correct source
        (.requestPreVote (makeRequestPreVote state source destination))
        (votePacketFields position pathId state tracking source) (by rfl)
        (votePacketFields_correct assignment position pathId state tracking correct source) node
      simpa [controlQueueLengths, mapState, next] using result
  | proposeVote source destination | advanceCommitIndexAndProposeVote source destination =>
      intro node
      have result := controlQueueUpdate_correct assignment position pathId state tracking correct source
        (.proposeVoteRequest (makeProposeVoteRequest state source destination))
        (fun _ value => .literal value) (by rfl) (by intros; rfl) node
      simpa [controlQueueLengths, mapState, next, demoteRetiredCommitted, advanceCommitState, stepDownState, apply_ite] using result
  | _ => exact base.queueLengths

theorem termAt_take {holes : Nat} (log : List (Entry Node (Value holes))) (count index : Nat) :
    termAt (log.take count) index = if count < index then 0 else termAt log index := by
  by_cases zero : index = 0
  · subst index
    simp [termAt, entryAt?]
  · by_cases beyond : count < index
    · have outside : ¬index - 1 < count := by omega
      simp [termAt, entryAt?, zero, List.getElem?_take, outside, beyond]
    · have within : index - 1 < count := by omega
      simp [termAt, entryAt?, zero, List.getElem?_take, within, beyond]

theorem controlLogTerms_correct {holes : Nat}
    (assignment : Fin holes -> Nat) (position pathId : Nat)
    (state : Template holes) (tracking : Tracking holes)
    (correct : TrackingCorrect assignment state tracking)
    (action : Action Node (Value holes)) :
    ∀ node index term,
      (controlLogTerms position pathId state tracking action node index term).eval assignment = term := by
  cases action <;> simp only [controlLogTerms]
  all_goals first
    | exact correct.logTerms
    | (rename_i source
       intro node index term
       by_cases same : node = source
       · subst node
         simp only [Function.update_self]
         split_ifs with selected
         · simp only [NatTerm.eval, Expr.ite_eval, Expr.Holds,
             correct.logPositions, correct.logTerms]
           rw [← termAt_take]
           exact selected.1.symm
         · exact correct.logTerms source index term
       · simpa [Function.update_apply, same] using correct.logTerms node index term)

theorem controlLogLengths_correct {holes : Nat}
    (assignment : Fin holes -> Nat) (position pathId : Nat)
    (state : Template holes) (tracking : Tracking holes)
    (correct : TrackingCorrect assignment state tracking)
    (action : Action Node (Value holes)) :
    ∀ node, (controlLogLengths position pathId state tracking action node).eval assignment =
      ((mapState (NatTerm.eval assignment) (next state action)).nodes node).log.length := by
  have base := nextControlTracking_correct assignment position pathId state (next state action)
    tracking correct
  cases action <;> simp only [controlLogLengths]
  all_goals first
    | exact base.logLengths
    | (rename_i source
       intro node
       by_cases same : node = source
       · subst node
         simp [NatTerm.eval, correct.logLengths, correct.logPositions,
           mapState_nodes_get, mapNodeState, next]
         omega
       · simpa [same, mapState_nodes_get, mapNodeState, next] using correct.logLengths node)

theorem controlSentIndices_correct {holes : Nat}
    (assignment : Fin holes -> Nat) (position pathId : Nat)
    (state : Template holes) (tracking : Tracking holes)
    (correct : TrackingCorrect assignment state tracking)
    (action : Action Node (Value holes)) :
    ∀ node peer, (controlSentIndices position pathId state tracking action node peer).eval assignment =
      ((mapState (NatTerm.eval assignment) (next state action)).nodes node).sentIndex peer := by
  have base := nextControlTracking_correct assignment position pathId state (next state action)
    tracking correct
  cases action <;> simp only [controlSentIndices]
  all_goals first
    | exact base.sentIndex
    | (rename_i source
       intro node peer
       by_cases same : node = source
       · subst node
         simp only [Function.update_self, NatTerm.eval]
         rw [controlLogLengths_correct assignment position pathId state tracking correct]
         simp [mapState_nodes_get, mapNodeState, next]
       · simpa [same, mapState_nodes_get, mapNodeState, next] using correct.sentIndex node peer)

theorem controlCommitIndices_correct {holes : Nat}
    (assignment : Fin holes -> Nat) (position pathId : Nat)
    (state : Template holes) (tracking : Tracking holes)
    (correct : TrackingCorrect assignment state tracking)
    (action : Action Node (Value holes)) :
    ∀ node index, (controlCommitIndices position pathId state tracking action node index).eval
      assignment = index := by
  cases action with
  | advanceCommitIndex source
  | advanceCommitIndexAndProposeVote source destination =>
      intro node index
      by_cases same : node = source
      · subst node
        by_cases frontier : index = highestCommittableIndex state source
        · subst index
          simp [controlCommitIndices, NatTerm.eval, highestCommittableValue_correct assignment state tracking correct]
        · simp [controlCommitIndices, frontier, correct.commitIndices]
      · simp [controlCommitIndices, same, correct.commitIndices]
  | _ => exact correct.commitIndices

theorem rawControlFrame_correct {holes : Nat}
    (assignment : Fin holes -> Nat) (position : Nat)
    (action : Action Node (Value holes)) (frame : Frame holes)
    (correct : FrameCorrect assignment frame) :
    FrameCorrect assignment (rawControlFrame position action frame) := by
  simp only [rawControlFrame, controlSuccessor_eq_next]
  have base := nextControlTracking_correct assignment position frame.pathId
    frame.state (next frame.state action) frame.tracking correct
  exact { base with
    queueLengths := controlQueueLengths_correct assignment position frame.pathId frame.state frame.tracking correct action
    configurations := by
      change ∀ node values, ControlTraceConfigurations.Correct assignment values
        (controlConfigurations position frame.pathId frame.state frame.tracking action node values)
      cases action <;> simp only [controlConfigurations]
      all_goals first
        | exact correct.configurations
        | (rename_i source
           intro node values
           simp only [Function.update_apply, ite_apply]
           split_ifs with same desired
           · subst node
             subst values
             have truncated := ControlTraceConfigurations.truncate_correct assignment
               (allConfigurations (frame.state.nodes source).log)
               (frame.tracking.configurations source (allConfigurations (frame.state.nodes source).log))
               (correct.configurations source _)
               (controlLogLengths position frame.pathId frame.state frame.tracking (.becomeLeader source) source)
               position (fun index => pathSlot (Nat.pair frame.pathId index) CONFIGURATION_SLOT)
             rw [controlLogLengths_correct assignment position frame.pathId frame.state frame.tracking correct,
               ← ControlTraceConfigurations.allConfigurations_take] at truncated
             simpa [mapState_nodes_get, mapNodeState, next, ← List.take_take] using truncated
           · exact correct.configurations _ _
           · exact correct.configurations _ _)
    voteMembers := by
      change ∀ node preVote peer value,
        (controlVoteMembers position frame.pathId frame.state frame.tracking action node preVote peer value).eval
          assignment = if value then 1 else 0
      cases action <;> simp only [controlVoteMembers]
      all_goals first
        | exact correct.voteMembers
        | (intro node preVote peer value
           cases preVote <;> cases value <;>
             try simp only [Function.update_apply]
           all_goals split_ifs <;> simp_all [Function.update_apply, apply_ite, ite_apply,
             NatTerm.eval, boolValue, correct.voteMembers])
    packetFields := by
      change ∀ message field value,
        (controlPacketFields position frame.pathId frame.state frame.tracking action message field value).eval
          assignment = value
      cases action <;> simp only [controlPacketFields]
      all_goals first
        | exact correct.packetFields
        | (apply rememberPacketFields_correct assignment frame.state frame.tracking correct
           exact votePacketFields_correct assignment position frame.pathId frame.state frame.tracking correct _)
    logLengths := controlLogLengths_correct assignment position frame.pathId
      frame.state frame.tracking correct action
    sentIndex := controlSentIndices_correct assignment position frame.pathId
      frame.state frame.tracking correct action
    logTerms := controlLogTerms_correct assignment position frame.pathId
      frame.state frame.tracking correct action
    commitIndices := controlCommitIndices_correct assignment position frame.pathId
      frame.state frame.tracking correct action
    packetTerms := controlPacketTerms_correct assignment position frame.pathId
      frame.state frame.tracking correct action
    currentTerms := by
      change ∀ node, (controlCurrentTerms position frame.pathId frame.state
        frame.tracking action node).eval assignment =
          ((next frame.state action).nodes node).currentTerm
      cases action <;> simp only [controlCurrentTerms]
      all_goals first
        | exact base.currentTerms
        | (rename_i source destination
           cases selected : newerMessage? frame.state source destination with
           | none => simpa [selected, next] using correct.currentTerms
           | some message =>
               intro node
               by_cases same : node = destination
               · subst node
                 simp [selected, next, NatTerm.eval, correct.packetTerms]
               · simp [selected, next, same, correct.currentTerms]) }

theorem controlSendFrame_correct {holes : Nat}
    (assignment : Fin holes -> Nat) (position : Nat) (action : Action Node (Value holes))
    (destination : Node) (frame : Frame holes) (correct : FrameCorrect assignment frame)
    (packet : Message Node (Value holes)) (routed : packet.destination = destination)
    (shape : next frame.state action =
      { frame.state with network := enqueue frame.state.network packet }) :
    FrameCorrect assignment (controlSendFrame position action destination frame) := by
  have rawCorrect := rawControlFrame_correct assignment position action frame correct
  have stateEq : (rawControlFrame position action frame).state =
      { frame.state with network := enqueue frame.state.network packet } := by
    simpa [rawControlFrame] using shape
  have queues : ∀ node,
      (Function.update frame.tracking.queueLengths destination
        ((rawControlFrame position action frame).tracking.queueLengths destination) node).eval assignment =
      ((mapState (NatTerm.eval assignment) (rawControlFrame position action frame).state).network node).length := by
    intro node
    by_cases same : node = destination
    · subst node
      simpa using rawCorrect.queueLengths destination
    · simpa [Function.update_apply, same, stateEq, mapState, enqueue, updateQueue, routed, ite_apply]
        using correct.queueLengths node
  dsimp only [controlSendFrame]
  split_ifs
  all_goals
    change TrackingCorrect assignment (rawControlFrame position action frame).state _
    rw [stateEq]
    refine { correct with queueLengths := ?_, packetTerms := ?_, packetFields := ?_ }
    · simpa [stateEq] using queues
    · first | exact correct.packetTerms | exact rawCorrect.packetTerms
    · first | exact correct.packetFields | exact rawCorrect.packetFields

set_option maxHeartbeats 800000 in
theorem controlFrame_correct {holes : Nat}
    (assignment : Fin holes -> Nat) (position : Nat)
    (action : Action Node (Value holes)) (frame : Frame holes) (correct : FrameCorrect assignment frame) :
    FrameCorrect assignment (controlFrame position action frame) := by
  cases action with
  | requestVote source destination =>
      exact controlSendFrame_correct assignment position _ destination frame correct
        (.requestVoteRequest (makeRequestVoteRequest frame.state source destination)) rfl rfl
  | requestPreVote source destination =>
      exact controlSendFrame_correct assignment position _ destination frame correct
        (.requestPreVote (makeRequestPreVote frame.state source destination)) rfl rfl
  | proposeVote source destination =>
      exact controlSendFrame_correct assignment position _ destination frame correct
        (.proposeVoteRequest (makeProposeVoteRequest frame.state source destination)) rfl rfl
  | _ =>
      simp only [controlFrame]
      first
        | exact rawControlFrame_correct assignment position _ frame correct
        | (apply finishFrame_correct
           exact rawControlFrame_correct assignment position _ frame correct)

theorem encodeFrom_correct {holes : Nat}
    (bounds : Bounds)
    (assignment : Fin holes -> Nat)
    (position : Nat)
    (frames : Guarded holes (Frame holes))
    (frameCorrect : FrameCorrect assignment (frames.eval assignment))
    (trace : List (TraceInstructions.Instruction holes)) :
    (encodeFrom bounds position frames trace).Holds assignment ↔
      Follows bounds assignment
        (mapState (NatTerm.eval assignment)
          (frames.eval assignment).state) trace := by
  induction trace generalizing position frames with
  | nil =>
      simp only [encodeFrom, Formula.holds_cons, Formula.holds_nil, and_true,
        Group.Holds]
      change
        ClausesHold assignment
            (guardedClauses frames fun current =>
              stateBoundsClauses bounds current.state current.tracking) <->
          BoundedState.WithinBounds bounds
            (mapState (NatTerm.eval assignment)
              (frames.eval assignment).state)
      rw [guardedClauses_correct]
      exact stateBoundsClauses_correct bounds assignment
        (frames.eval assignment).state (frames.eval assignment).tracking
        frameCorrect
  | cons instruction trace inductionHypothesis =>
      let frame := frames.eval assignment
      cases instruction with
      | observation observation =>
          simp only [encodeFrom, Formula.holds_cons, Follows]
          rw [guardedGroup_correct]
          change
            (observationGroup bounds frame.state frame.tracking
              observation).Holds assignment /\
              (encodeFrom bounds (position + 1) frames trace).Holds
                assignment ↔ _
          rw [observationGroup_correct bounds assignment frame.state
            frame.tracking frameCorrect observation]
          rw [inductionHypothesis (position + 1) frames frameCorrect]
          tauto
      | clientRequest node transaction =>
          let accepted : Value holes :=
            .named position 0 "accepted transaction" transaction
          by_cases mappedEnabled :
              Enabled (mapState (NatTerm.eval assignment) frame.state)
                (.clientRequest node (transaction.eval assignment))
          · have allocated : frame.state.allocated node :=
              (mapState_allocated _ _ _).1 mappedEnabled.1
            have nextCorrect :
                FrameCorrect assignment
                  ((frames.map
                    (clientRequestFrame position node accepted)).eval
                      assignment) := by
              simp only [Guarded.eval_map, clientRequestFrame]
              apply finishFrame_correct
              exact nextWriteTracking_clientRequest_correct assignment
                position frame.pathId frame.state frame.tracking frameCorrect
                node transaction allocated
            simp only [encodeFrom, Formula.holds_cons, Follows]
            rw [guardedGroup_correct]
            change
              (clientRequestGroup bounds frame.state frame.tracking
                node transaction).Holds assignment /\
                _ ↔ _
            rw [clientRequestGroup_correct bounds assignment frame.state
              frame.tracking frameCorrect node transaction]
            rw [inductionHypothesis (position + 1)
              (frames.map (clientRequestFrame position node accepted))
              nextCorrect]
            have commutes :=
              mapState_clientRequest (NatTerm.eval assignment) frame.state
                node accepted
            simp only [accepted, NatTerm.eval] at commutes
            simp only [Guarded.eval_map, clientRequestFrame, finishFrame]
            rw [commutes]
            tauto
          ·
            simp only [encodeFrom, Formula.holds_cons, Follows]
            rw [guardedGroup_correct]
            change
              (clientRequestGroup bounds frame.state frame.tracking
                node transaction).Holds assignment /\
                _ ↔ _
            rw [clientRequestGroup_correct bounds assignment frame.state
              frame.tracking frameCorrect node transaction]
            dsimp only [frame] at mappedEnabled
            simp [frame, mappedEnabled]
      | signCommittableMessages node =>
          by_cases enabled :
              Enabled frame.state (.signCommittableMessages node)
          · have nextCorrect :=
              nextWriteTracking_signature_correct assignment position
                frame.pathId frame.state frame.tracking frameCorrect
                node enabled.1
            simp only [encodeFrom, Formula.holds_cons, Follows]
            rw [guardedGroup_correct]
            change
              (leaderWriteGroup "signCommittableMessages" bounds
                frame.state frame.tracking
                (.signCommittableMessages node)).Holds assignment /\
                _ ↔ _
            rw [leaderWriteGroup_correct "signCommittableMessages" bounds
              assignment frame.state frame.tracking frameCorrect
              (.signCommittableMessages node)
              (Enabled (mapState (NatTerm.eval assignment) frame.state)
                (.signCommittableMessages node))
              (enabled_mapState_signCommittableMessages_iff
                (NatTerm.eval assignment) frame.state node).symm]
            rw [inductionHypothesis (position + 1)
              (frames.map (signatureFrame position node))
              (by
                simp only [Guarded.eval_map, signatureFrame]
                apply finishFrame_correct
                exact nextCorrect)]
            simp only [Guarded.eval_map, signatureFrame, finishFrame]
            rw [mapState_signCommittableMessages]
            tauto
          · have mappedDisabled :=
              mt (enabled_mapState_signCommittableMessages_iff
                (NatTerm.eval assignment) frame.state node).mp enabled
            simp only [encodeFrom, Formula.holds_cons, Follows]
            rw [guardedGroup_correct]
            change
              (leaderWriteGroup "signCommittableMessages" bounds
                frame.state frame.tracking
                (.signCommittableMessages node)).Holds assignment /\
                _ ↔ _
            rw [leaderWriteGroup_correct "signCommittableMessages" bounds
              assignment frame.state frame.tracking frameCorrect
              (.signCommittableMessages node)
              (Enabled (mapState (NatTerm.eval assignment) frame.state)
                (.signCommittableMessages node))
              (enabled_mapState_signCommittableMessages_iff
                (NatTerm.eval assignment) frame.state node).symm]
            dsimp only [frame] at mappedDisabled
            simp [frame, mappedDisabled]
      | changeConfiguration node configuration =>
          have nextCorrect :=
            nextConfigurationTracking_correct assignment position
              frame.pathId frame.state frame.tracking frameCorrect node
              configuration
          simp only [encodeFrom, Formula.holds_cons, Follows]
          rw [guardedGroup_correct]
          change
            (leaderWriteGroup "changeConfiguration" bounds
              frame.state frame.tracking
              (.changeConfiguration node configuration)).Holds assignment /\
              _ ↔ _
          rw [leaderWriteGroup_correct "changeConfiguration" bounds
            assignment frame.state frame.tracking frameCorrect
            (.changeConfiguration node configuration)
            (Enabled (mapState (NatTerm.eval assignment) frame.state)
              (.changeConfiguration node configuration))
            (enabled_mapState_changeConfiguration_iff
              (NatTerm.eval assignment) frame.state node configuration).symm]
          rw [inductionHypothesis (position + 1)
            (frames.map (configurationFrame position node configuration))
            (by
              simp only [Guarded.eval_map, configurationFrame]
              apply finishFrame_correct
              exact nextCorrect)]
          simp only [Guarded.eval_map, configurationFrame, finishFrame]
          rw [mapState_changeConfiguration]
          tauto
      | appendRetiredCommitted node =>
          by_cases enabled :
              Enabled frame.state (.appendRetiredCommitted node)
          · have nextCorrect :=
              nextWriteTracking_retiredCommitted_correct assignment position
                frame.pathId frame.state frame.tracking frameCorrect
                node enabled.1
            simp only [encodeFrom, Formula.holds_cons, Follows]
            rw [guardedGroup_correct]
            change
              (leaderWriteGroup "appendRetiredCommitted" bounds
                frame.state frame.tracking
                (.appendRetiredCommitted node)).Holds assignment /\
                _ ↔ _
            rw [leaderWriteGroup_correct "appendRetiredCommitted" bounds
              assignment frame.state frame.tracking frameCorrect
              (.appendRetiredCommitted node)
              (Enabled (mapState (NatTerm.eval assignment) frame.state)
                (.appendRetiredCommitted node))
              (enabled_mapState_appendRetiredCommitted_iff
                (NatTerm.eval assignment) frame.state node).symm]
            rw [inductionHypothesis (position + 1)
              (frames.map (retiredCommittedFrame position node))
              (by
                simp only [Guarded.eval_map, retiredCommittedFrame]
                apply finishFrame_correct
                exact nextCorrect)]
            simp only [Guarded.eval_map, retiredCommittedFrame, finishFrame]
            rw [mapState_appendRetiredCommitted]
            tauto
          · have mappedDisabled :=
              mt (enabled_mapState_appendRetiredCommitted_iff
                (NatTerm.eval assignment) frame.state node).mp enabled
            simp only [encodeFrom, Formula.holds_cons, Follows]
            rw [guardedGroup_correct]
            change
              (leaderWriteGroup "appendRetiredCommitted" bounds
                frame.state frame.tracking
                (.appendRetiredCommitted node)).Holds assignment /\
                _ ↔ _
            rw [leaderWriteGroup_correct "appendRetiredCommitted" bounds
              assignment frame.state frame.tracking frameCorrect
              (.appendRetiredCommitted node)
              (Enabled (mapState (NatTerm.eval assignment) frame.state)
                (.appendRetiredCommitted node))
              (enabled_mapState_appendRetiredCommitted_iff
                (NatTerm.eval assignment) frame.state node).symm]
            dsimp only [frame] at mappedDisabled
            simp [frame, mappedDisabled]
      | appendEntries source destination batchEnd =>
          simp only [encodeFrom, Formula.holds_cons, Follows]
          rw [guardedGroup_correct]
          change
            (leaderWriteGroup "appendEntries" bounds frame.state
              frame.tracking
              (.appendEntries source destination batchEnd)).Holds assignment /\
              _ ↔ _
          rw [leaderWriteGroup_correct "appendEntries" bounds assignment
            frame.state frame.tracking frameCorrect
            (.appendEntries source destination batchEnd)
            (Enabled (mapState (NatTerm.eval assignment) frame.state)
              (.appendEntries source destination batchEnd))
            (enabled_mapState_appendEntries_iff
              (NatTerm.eval assignment) frame.state source destination
              batchEnd).symm]
          by_cases enabled :
              Enabled frame.state (.appendEntries source destination batchEnd)
          · rw [inductionHypothesis (position + 1)
              (frames.bind fun current =>
                appendFrames position current source destination batchEnd)
              (by
                simp only [Guarded.eval_bind]
                exact appendFrames_correct bounds assignment position frame
                  frameCorrect source destination enabled.1 batchEnd)]
            rw [Guarded.eval_bind, appendFrames_state_correct]
            tauto
          · have mappedDisabled :=
              mt (enabled_mapState_appendEntries_iff
                (NatTerm.eval assignment) frame.state source destination
                  batchEnd).mp enabled
            dsimp only [frame] at mappedDisabled
            simp [frame, mappedDisabled]
      | timeout node =>
          simp only [encodeFrom, Formula.holds_cons, Follows]
          rw [guardedGroup_correct]
          change (leaderWriteGroup "timeout" bounds frame.state frame.tracking
            (.timeout node)).Holds assignment /\ _ ↔ _
          rw [leaderWriteGroup_correct "timeout" bounds assignment
            frame.state frame.tracking frameCorrect _ _
            (enabled_mapState_timeout_iff (NatTerm.eval assignment) frame.state node).symm]
          rw [inductionHypothesis (position + 1)
            (frames.map (controlFrame position (.timeout node)))
            (by simpa only [Guarded.eval_map] using
              controlFrame_correct assignment position (.timeout node) frame frameCorrect)]
          simp only [Guarded.eval_map, controlFrame_state, mapState_timeout]
          tauto
      | becomePreVoteCandidate node =>
          simp only [encodeFrom, Formula.holds_cons, Follows]
          rw [guardedGroup_correct]
          change (leaderWriteGroup "becomePreVoteCandidate" bounds frame.state frame.tracking
            (.becomePreVoteCandidate node)).Holds assignment /\ _ ↔ _
          rw [leaderWriteGroup_correct "becomePreVoteCandidate" bounds assignment
            frame.state frame.tracking frameCorrect _ _
            (enabled_mapState_becomePreVoteCandidate_iff
              (NatTerm.eval assignment) frame.state node).symm]
          rw [inductionHypothesis (position + 1)
            (frames.map (controlFrame position (.becomePreVoteCandidate node)))
            (by simpa only [Guarded.eval_map] using
              controlFrame_correct assignment position (.becomePreVoteCandidate node) frame frameCorrect)]
          simp only [Guarded.eval_map, controlFrame_state, mapState_becomePreVoteCandidate]
          tauto
      | becomeCandidate node =>
          simp only [encodeFrom, Formula.holds_cons, Follows]
          rw [guardedGroup_correct]
          change (leaderWriteGroup "becomeCandidate" bounds frame.state frame.tracking
            (.becomeCandidate node)).Holds assignment /\ _ ↔ _
          rw [leaderWriteGroup_correct "becomeCandidate" bounds assignment
            frame.state frame.tracking frameCorrect _ _
            (enabled_mapState_becomeCandidate_iff
              (NatTerm.eval assignment) frame.state node).symm]
          rw [inductionHypothesis (position + 1)
            (frames.map (controlFrame position (.becomeCandidate node)))
            (by simpa only [Guarded.eval_map] using
              controlFrame_correct assignment position (.becomeCandidate node) frame frameCorrect)]
          simp only [Guarded.eval_map, controlFrame_state, mapState_becomeCandidate]
          tauto
      | advanceCommitIndex node =>
          simp only [encodeFrom, Formula.holds_cons, Follows]
          rw [guardedGroup_correct]
          change (leaderWriteGroup "advanceCommitIndex" bounds frame.state frame.tracking
            (.advanceCommitIndex node)).Holds assignment /\ _ ↔ _
          rw [leaderWriteGroup_correct "advanceCommitIndex" bounds assignment
            frame.state frame.tracking frameCorrect _ _
            (enabled_mapState_advanceCommitIndex_iff
              (NatTerm.eval assignment) frame.state node).symm]
          rw [inductionHypothesis (position + 1)
            (frames.map (controlFrame position (.advanceCommitIndex node)))
            (by simpa only [Guarded.eval_map] using
              controlFrame_correct assignment position (.advanceCommitIndex node) frame frameCorrect)]
          simp only [Guarded.eval_map, controlFrame_state, mapState_advanceCommitIndex]
          tauto
      | checkQuorum node =>
          simp only [encodeFrom, Formula.holds_cons, Follows]
          rw [guardedGroup_correct]
          change (leaderWriteGroup "checkQuorum" bounds frame.state frame.tracking
            (.checkQuorum node)).Holds assignment /\ _ ↔ _
          rw [leaderWriteGroup_correct "checkQuorum" bounds assignment
            frame.state frame.tracking frameCorrect _ _
            (enabled_mapState_checkQuorum_iff (NatTerm.eval assignment) frame.state node).symm]
          rw [inductionHypothesis (position + 1)
            (frames.map (controlFrame position (.checkQuorum node)))
            (by simpa only [Guarded.eval_map] using
              controlFrame_correct assignment position (.checkQuorum node) frame frameCorrect)]
          simp only [Guarded.eval_map, controlFrame_state, mapState_checkQuorum]
          tauto
      | updateTerm source destination =>
          simp only [encodeFrom, Formula.holds_cons, Follows]
          rw [guardedGroup_correct]
          change (leaderWriteGroup "updateTerm" bounds frame.state frame.tracking
            (.updateTerm source destination)).Holds assignment /\ _ ↔ _
          rw [leaderWriteGroup_correct "updateTerm" bounds assignment
            frame.state frame.tracking frameCorrect _ _
            (enabled_mapState_updateTerm_iff
              (NatTerm.eval assignment) frame.state source destination).symm]
          rw [inductionHypothesis (position + 1)
            (frames.map (controlFrame position (.updateTerm source destination)))
            (by simpa only [Guarded.eval_map] using
              controlFrame_correct assignment position (.updateTerm source destination) frame frameCorrect)]
          simp only [Guarded.eval_map, controlFrame_state, mapState_updateTerm]
          tauto
      | becomeLeader node =>
          simp only [encodeFrom, Formula.holds_cons, Follows]
          rw [guardedGroup_correct]
          change (leaderWriteGroup "becomeLeader" bounds frame.state frame.tracking
            (.becomeLeader node)).Holds assignment /\ _ ↔ _
          rw [leaderWriteGroup_correct "becomeLeader" bounds assignment
            frame.state frame.tracking frameCorrect _ _
            (enabled_mapState_becomeLeader_iff
              (NatTerm.eval assignment) frame.state node).symm]
          rw [inductionHypothesis (position + 1)
            (frames.map (controlFrame position (.becomeLeader node)))
            (by simpa only [Guarded.eval_map] using
              controlFrame_correct assignment position (.becomeLeader node) frame frameCorrect)]
          simp only [Guarded.eval_map, controlFrame_state, mapState_becomeLeader]
          tauto
      | requestVote source destination =>
          simp only [encodeFrom, Formula.holds_cons, Follows]
          rw [guardedGroup_correct]
          change (leaderWriteGroup "requestVote" bounds frame.state frame.tracking
            (.requestVote source destination)).Holds assignment /\ _ ↔ _
          rw [leaderWriteGroup_correct "requestVote" bounds assignment
            frame.state frame.tracking frameCorrect _ _
            (enabled_mapState_requestVote_iff
              (NatTerm.eval assignment) frame.state source destination).symm]
          rw [inductionHypothesis (position + 1)
            (frames.map (controlFrame position (.requestVote source destination)))
            (by simpa only [Guarded.eval_map] using
              controlFrame_correct assignment position (.requestVote source destination) frame frameCorrect)]
          simp only [Guarded.eval_map, controlFrame_state, mapState_requestVote]
          tauto
      | requestPreVote source destination =>
          simp only [encodeFrom, Formula.holds_cons, Follows]
          rw [guardedGroup_correct]
          change (leaderWriteGroup "requestPreVote" bounds frame.state frame.tracking
            (.requestPreVote source destination)).Holds assignment /\ _ ↔ _
          rw [leaderWriteGroup_correct "requestPreVote" bounds assignment
            frame.state frame.tracking frameCorrect _ _
            (enabled_mapState_requestPreVote_iff
              (NatTerm.eval assignment) frame.state source destination).symm]
          rw [inductionHypothesis (position + 1)
            (frames.map (controlFrame position (.requestPreVote source destination)))
            (by simpa only [Guarded.eval_map] using
              controlFrame_correct assignment position (.requestPreVote source destination) frame frameCorrect)]
          simp only [Guarded.eval_map, controlFrame_state, mapState_requestPreVote]
          tauto
      | proposeVote source destination =>
          simp only [encodeFrom, Formula.holds_cons, Follows]
          rw [guardedGroup_correct]
          change (leaderWriteGroup "proposeVote" bounds frame.state frame.tracking
            (.proposeVote source destination)).Holds assignment /\ _ ↔ _
          rw [leaderWriteGroup_correct "proposeVote" bounds assignment
            frame.state frame.tracking frameCorrect _ _
            (enabled_mapState_proposeVote_iff
              (NatTerm.eval assignment) frame.state source destination).symm]
          rw [inductionHypothesis (position + 1)
            (frames.map (controlFrame position (.proposeVote source destination)))
            (by simpa only [Guarded.eval_map] using
              controlFrame_correct assignment position (.proposeVote source destination) frame frameCorrect)]
          simp only [Guarded.eval_map, controlFrame_state, mapState_proposeVote]
          tauto
      | advanceCommitIndexAndProposeVote source destination =>
          simp only [encodeFrom, Formula.holds_cons, Follows]
          rw [guardedGroup_correct]
          change (leaderWriteGroup "advanceCommitIndexAndProposeVote" bounds frame.state frame.tracking
            (.advanceCommitIndexAndProposeVote source destination)).Holds assignment /\ _ ↔ _
          rw [leaderWriteGroup_correct "advanceCommitIndexAndProposeVote" bounds assignment
            frame.state frame.tracking frameCorrect _ _
            (enabled_mapState_advanceCommitIndexAndProposeVote_iff
              (NatTerm.eval assignment) frame.state source destination).symm]
          rw [inductionHypothesis (position + 1)
            (frames.map (controlFrame position (.advanceCommitIndexAndProposeVote source destination)))
            (by simpa only [Guarded.eval_map] using
              controlFrame_correct assignment position (.advanceCommitIndexAndProposeVote source destination) frame frameCorrect)]
          simp only [Guarded.eval_map, controlFrame_state, mapState_advanceCommitIndexAndProposeVote]
          tauto

theorem unknownDomains_correct {holes : Nat}
    (bounds : Bounds)
    (assignment : Fin holes -> Nat) :
    ({ label := "unknown transaction domains"
       clauses := (List.finRange holes).map fun index =>
         lessClause s!"unknown {index.val} domain" (.unknown index)
           bounds.transactionCount } : Group holes).Holds assignment ↔
      ∀ index, assignment index < bounds.transactionCount := by
  simp [Group.Holds, lessClause, Expr.Holds, NatTerm.eval]

theorem encode_holds_correct {holes : Nat}
    (bounds : Bounds)
    (entry : Template holes)
    (trace : List (TraceInstructions.Instruction holes))
    (assignment : Fin holes -> Nat) :
    (encode bounds entry trace).Holds assignment <->
      (forall index, assignment index < bounds.transactionCount) /\
        Follows bounds assignment (mapState (NatTerm.eval assignment) entry) trace := by
  simp only [encode, Formula.holds_cons, unknownDomains_correct]
  rw [encodeFrom_correct bounds assignment 1
    (.pure { state := entry, tracking := initialTracking entry, pathId := 0 })
    (initialTracking_correct assignment entry) trace]
  rfl

theorem encode_correct {holes : Nat}
    (bounds : Bounds)
    (entry : Template holes)
    (trace : List (TraceInstructions.Instruction holes)) :
    (encode bounds entry trace).Satisfiable <->
      BoundedTrace.Satisfiable bounds entry trace := by
  unfold Formula.Satisfiable BoundedTrace.Satisfiable
  exact exists_congr (encode_holds_correct bounds entry trace)

def checkedEncoder (holes : Nat) :
    BoundedTrace.VerifiedEncoder holes :=
  { encode := encode
    correct := encode_holds_correct }

end CCFRaft.TraceEncoding
