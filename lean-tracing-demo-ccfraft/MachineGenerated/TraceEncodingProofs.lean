-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.TraceEncoding
import MachineGenerated.LeaderWriteMappingProofs

set_option autoImplicit false

namespace CCFRaft.TraceEncoding

open TraceSmt BoundedTrace
open TransactionMapping

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

theorem entryBoundsClauses_correct {holes : Nat}
    (bounds : Bounds)
    (assignment : Fin holes -> Nat)
    (entry : Entry Node (Value holes)) :
    ClausesHold assignment (entryBoundsClauses bounds entry) ↔
      BoundedState.EntryWithin bounds
        (mapEntry (NatTerm.eval assignment) entry) := by
  cases entry with
  | mk term content =>
      cases content <;>
        simp [entryBoundsClauses, ClausesHold, constantClause, lessClause,
          Expr.Holds, NatTerm.eval, BoundedState.EntryWithin, mapEntry,
          mapEntryContent]

theorem entryListBoundsClauses_correct {holes : Nat}
    (bounds : Bounds)
    (assignment : Fin holes -> Nat)
    (entries : List (Entry Node (Value holes))) :
    ClausesHold assignment (entries.flatMap (entryBoundsClauses bounds)) ↔
      (entries.map (mapEntry (NatTerm.eval assignment))).Forall
        (BoundedState.EntryWithin bounds) := by
  rw [clausesHold_flatMap]
  rw [List.forall_iff_forall_mem]
  simp [entryBoundsClauses_correct]

theorem messageBoundsClauses_correct {holes : Nat}
    (bounds : Bounds)
    (assignment : Fin holes -> Nat)
    (message : Message Node (Value holes)) :
    ClausesHold assignment (messageBoundsClauses bounds message) ↔
      BoundedState.MessageWithin bounds
        (mapMessage (NatTerm.eval assignment) message) := by
  cases message with
  | appendEntriesRequest request =>
      simp only [messageBoundsClauses, mapMessage, clausesHold_append,
        entryListBoundsClauses_correct]
      simp [ClausesHold, constantClause, Expr.Holds,
        BoundedState.MessageWithin]
      tauto
  | appendEntriesResponse response =>
      simp [messageBoundsClauses, mapMessage, ClausesHold, constantClause,
        Expr.Holds, BoundedState.MessageWithin]
  | requestVoteRequest request =>
      simp [messageBoundsClauses, mapMessage, ClausesHold, constantClause,
        Expr.Holds, BoundedState.MessageWithin]
  | requestVoteResponse response =>
      simp [messageBoundsClauses, mapMessage, ClausesHold, constantClause,
        Expr.Holds, BoundedState.MessageWithin]
  | requestPreVote request =>
      simp [messageBoundsClauses, mapMessage, ClausesHold, constantClause,
        Expr.Holds, BoundedState.MessageWithin]
  | requestPreVoteResponse response =>
      simp [messageBoundsClauses, mapMessage, ClausesHold, constantClause,
        Expr.Holds, BoundedState.MessageWithin]
  | proposeVoteRequest request =>
      simp [messageBoundsClauses, mapMessage, ClausesHold, constantClause,
        Expr.Holds, BoundedState.MessageWithin]

theorem messageListBoundsClauses_correct {holes : Nat}
    (bounds : Bounds)
    (assignment : Fin holes -> Nat)
    (messages : List (Message Node (Value holes))) :
    ClausesHold assignment
        (messages.flatMap (messageBoundsClauses bounds)) ↔
      (messages.map (mapMessage (NatTerm.eval assignment))).Forall
        (BoundedState.MessageWithin bounds) := by
  rw [clausesHold_flatMap]
  rw [List.forall_iff_forall_mem]
  simp [messageBoundsClauses_correct]

theorem optionalIndexClauses_correct {holes : Nat}
    (bounds : Bounds)
    (assignment : Fin holes -> Nat)
    (writer : Option Nat)
    (slot : Nat)
    (label : String)
    (index : Option Nat) :
    ClausesHold assignment
        (optionalIndexClauses bounds writer slot label index) ↔
      BoundedState.OptionalIndexWithin bounds index := by
  cases writer <;> cases index <;>
    simp [optionalIndexClauses, ClausesHold, lessClause, Expr.Holds,
      NatTerm.eval, BoundedState.OptionalIndexWithin]

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
           constantClause "match index domain"
             (state.matchIndex peer < bounds.indexCount)]) ↔
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
        (mapNodeState (NatTerm.eval assignment) state).log.length) :
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
    entryListBoundsClauses_correct,
    peerIndexClauses_correct bounds assignment tracking node state,
    optionalIndexClauses_correct]
  simp [ClausesHold, constantClause, atMostClause, Expr.Holds, NatTerm.eval,
    BoundedState.LocalWithin, mapNodeState, logLength, sentIndices]
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
    (node : Node) :
    ClausesHold assignment (queueBoundsClauses bounds state node) ↔
      ((mapState (NatTerm.eval assignment) state).network node).length ≤
          bounds.queueCapacity /\
        ((mapState (NatTerm.eval assignment) state).network node).Forall
          (BoundedState.MessageWithin bounds) := by
  unfold queueBoundsClauses
  rw [show
    constantClause "queue capacity"
          ((state.network node).length ≤ bounds.queueCapacity) ::
        (state.network node).flatMap (messageBoundsClauses bounds) =
    [constantClause "queue capacity"
          ((state.network node).length ≤ bounds.queueCapacity)] ++
        (state.network node).flatMap (messageBoundsClauses bounds) by rfl]
  rw [clausesHold_append, messageListBoundsClauses_correct]
  simp [ClausesHold, constantClause, Expr.Holds, mapState]

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
    (state : Template holes) :
    ClausesHold assignment
        ((List.finRange NODE_COUNT).flatMap
          (queueBoundsClauses bounds state)) ↔
      ∀ node,
        ((mapState (NatTerm.eval assignment) state).network node).length ≤
            bounds.queueCapacity /\
          ((mapState (NatTerm.eval assignment) state).network node).Forall
            (BoundedState.MessageWithin bounds) := by
  rw [clausesHold_flatMap]
  simp only [List.mem_finRange, true_implies]
  exact forall_congr' fun node =>
    queueBoundsClauses_correct bounds assignment state node

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
    allQueueBoundsClauses_correct, submittedBoundsClauses_correct]
  unfold BoundedState.WithinBounds
  tauto

def ObservedValueHolds {holes : Nat}
    (assignment : Fin holes -> Nat)
    (state : State Node Nat) :
    TraceInstructions.Observation holes -> Prop
  | .role node value => (state.nodes node).role = value
  | .currentTerm node value => (state.nodes node).currentTerm = value
  | .logLength node value => (state.nodes node).log.length = value
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
        Expr.Holds, mapState_nodes_get, mapNodeState]
  | currentTerm node value =>
      simp [observationExpression, ObservedValueHolds,
        Expr.Holds, mapState_nodes_get, mapNodeState]
  | logLength node value =>
      simp only [observationExpression, Expr.Holds,
        ObservedValueHolds, NatTerm.eval]
      rw [trackingCorrect.logLengths node]
  | commitIndex node value =>
      simp [observationExpression, ObservedValueHolds,
        Expr.Holds, mapState_nodes_get, mapNodeState]
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
    constantClause, lessClause, Expr.Holds, NatTerm.eval,
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
    (enabled : Prop)
    [Decidable enabled]
    (targetEnabled : Prop)
    (mappedEnabled : enabled ↔ targetEnabled) :
    (leaderWriteGroup label bounds state tracking enabled).Holds assignment ↔
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
  simp [constantClause, Expr.Holds, mappedEnabled]

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

theorem nextWriteTracking_clientRequest_correct {holes : Nat}
    (assignment : Fin holes -> Nat)
    (position : Nat)
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
      (nextWriteTracking position tracking node) := by
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

theorem nextWriteTracking_signature_correct {holes : Nat}
    (assignment : Fin holes -> Nat)
    (position : Nat)
    (state : Template holes)
    (tracking : Tracking holes)
    (correct : TrackingCorrect assignment state tracking)
    (node : Node)
    (allocated : state.allocated node) :
    TrackingCorrect assignment
      (next state (.signCommittableMessages node))
      (nextWriteTracking position tracking node) := by
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

theorem nextWriteTracking_retiredCommitted_correct {holes : Nat}
    (assignment : Fin holes -> Nat)
    (position : Nat)
    (state : Template holes)
    (tracking : Tracking holes)
    (correct : TrackingCorrect assignment state tracking)
    (node : Node)
    (allocated : state.allocated node) :
    TrackingCorrect assignment
      (next state (.appendRetiredCommitted node))
      (nextWriteTracking position tracking node) := by
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
    (state : Template holes)
    (tracking : Tracking holes)
    (correct : TrackingCorrect assignment state tracking)
    (source : Node)
    (configuration : Finset Node) :
    TrackingCorrect assignment
      (next state (.changeConfiguration source configuration))
      (nextConfigurationTracking position state tracking source configuration) := by
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
    by_cases allocated : state.allocated candidate
    · simp [nextConfigurationTracking, allocated, correct.allocated,
        mapState_allocated, changeConfiguration_allocated_iff]
    · by_cases same : candidate = source
      · subst candidate
        simp [nextConfigurationTracking, allocated, mapState_allocated,
          changeConfiguration_allocated_iff, NatTerm.eval]
      · by_cases member : candidate ∈ added
        · have member' :
              candidate ∈ configuration ∧
                candidate ∉
                  (latestConfiguration (state.nodes source)).nodes := by
            simpa [added] using member
          simp [nextConfigurationTracking, allocated, same, member', added,
            mapState_allocated, changeConfiguration_allocated_iff,
            NatTerm.eval]
        · have member' :
              ¬(candidate ∈ configuration ∧
                candidate ∉
                  (latestConfiguration (state.nodes source)).nodes) := by
            simpa [added] using member
          simpa [nextConfigurationTracking, allocated, same, member', added,
            mapState_allocated, changeConfiguration_allocated_iff] using
              correct.allocated candidate
  · intro candidate
    rw [commutes]
    simp only [nextConfigurationTracking, NatTerm.eval, next]
    by_cases joined : candidate ∈ state.hasJoined
    · simp [joined, correct.joined, mapState]
    · by_cases addedMember : candidate ∈ added
      · simp [joined, addedMember, added, mapState, NatTerm.eval]
      · simp [joined, addedMember, added, correct.joined, mapState]
  · intro candidate peer
    rw [commutes]
    by_cases same : candidate = source
    · subst candidate
      simp only [nextConfigurationTracking, NatTerm.eval, if_pos, next]
      rw [mapState_nodes_get, latestConfiguration_mapNodeState]
      by_cases member : peer ∈ added
      · have member' :
            peer ∈ configuration ∧
              peer ∉ (latestConfiguration (state.nodes source)).nodes := by
          simpa [added] using member
        simp [member, member', added, updateNode, NodeStore.get_allocate,
          mapNodeState, NatTerm.eval]
        simpa [mapState_nodes_get, mapNodeState] using
          correct.logLengths source
      · have member' :
            ¬(peer ∈ configuration ∧
              peer ∉ (latestConfiguration (state.nodes source)).nodes) := by
          simpa [added] using member
        simp [member, member', added, updateNode, NodeStore.get_allocate,
          mapNodeState]
        simpa [mapState_nodes_get, mapNodeState] using
          correct.sentIndex source peer
    · rw [changeConfiguration_get_of_ne _ _ _ _ same]
      simp [nextConfigurationTracking, same, NatTerm.eval]
      simpa [mapState_nodes_get, mapNodeState] using
        correct.sentIndex candidate peer

theorem encodeFrom_correct {holes : Nat}
    (bounds : Bounds)
    (assignment : Fin holes -> Nat)
    (position : Nat)
    (state : Template holes)
    (tracking : Tracking holes)
    (trackingCorrect : TrackingCorrect assignment state tracking)
    (trace : List (TraceInstructions.Instruction holes)) :
    (encodeFrom bounds position state tracking trace).Holds assignment ↔
      Follows bounds assignment
        (mapState (NatTerm.eval assignment) state) trace := by
  induction trace generalizing position state tracking with
  | nil =>
      simp only [encodeFrom, Formula.holds_cons, Formula.holds_nil, and_true,
        Group.Holds]
      exact stateBoundsClauses_correct bounds assignment state tracking
        trackingCorrect
  | cons instruction trace inductionHypothesis =>
      cases instruction with
      | observation observation =>
          simp only [encodeFrom, Formula.holds_cons, Follows]
          rw [observationGroup_correct bounds assignment state tracking
            trackingCorrect observation]
          rw [inductionHypothesis (position + 1) state tracking
            trackingCorrect]
          tauto
      | clientRequest node transaction =>
          let accepted : Value holes :=
            .named position 0 "accepted transaction" transaction
          by_cases mappedEnabled :
              Enabled (mapState (NatTerm.eval assignment) state)
                (.clientRequest node (transaction.eval assignment))
          · have allocated : state.allocated node :=
              (mapState_allocated _ _ _).1 mappedEnabled.1
            have nextCorrect :
                TrackingCorrect assignment
                  (next state (.clientRequest node accepted))
                  (nextWriteTracking position tracking node) :=
              nextWriteTracking_clientRequest_correct assignment position state
                tracking trackingCorrect node transaction allocated
            simp only [encodeFrom, Formula.holds_cons, Follows]
            rw [clientRequestGroup_correct bounds assignment state tracking
              trackingCorrect node transaction]
            rw [inductionHypothesis (position + 1)
              (next state (.clientRequest node accepted))
              (nextWriteTracking position tracking node) nextCorrect]
            have commutes :=
              mapState_clientRequest (NatTerm.eval assignment) state node accepted
            simp only [accepted, NatTerm.eval] at commutes
            rw [commutes]
            tauto
          ·
            simp only [encodeFrom, Formula.holds_cons, Follows]
            rw [clientRequestGroup_correct bounds assignment state tracking
              trackingCorrect node transaction]
            simp [mappedEnabled]
      | signCommittableMessages node =>
          by_cases enabled : Enabled state (.signCommittableMessages node)
          · have nextCorrect :=
              nextWriteTracking_signature_correct assignment position state
                tracking trackingCorrect node enabled.1
            simp only [encodeFrom, Formula.holds_cons, Follows]
            rw [leaderWriteGroup_correct "signCommittableMessages" bounds
              assignment state tracking trackingCorrect
              (Enabled state (.signCommittableMessages node))
              (Enabled (mapState (NatTerm.eval assignment) state)
                (.signCommittableMessages node))
              (enabled_mapState_signCommittableMessages_iff
                (NatTerm.eval assignment) state node).symm]
            rw [inductionHypothesis (position + 1)
              (next state (.signCommittableMessages node))
              (nextWriteTracking position tracking node) nextCorrect]
            rw [mapState_signCommittableMessages]
            tauto
          · have mappedDisabled :=
              mt (enabled_mapState_signCommittableMessages_iff
                (NatTerm.eval assignment) state node).mp enabled
            simp only [encodeFrom, Formula.holds_cons, Follows]
            rw [leaderWriteGroup_correct "signCommittableMessages" bounds
              assignment state tracking trackingCorrect
              (Enabled state (.signCommittableMessages node))
              (Enabled (mapState (NatTerm.eval assignment) state)
                (.signCommittableMessages node))
              (enabled_mapState_signCommittableMessages_iff
                (NatTerm.eval assignment) state node).symm]
            simp [mappedDisabled]
      | changeConfiguration node configuration =>
          have nextCorrect :=
            nextConfigurationTracking_correct assignment position state
              tracking trackingCorrect node configuration
          simp only [encodeFrom, Formula.holds_cons, Follows]
          rw [leaderWriteGroup_correct "changeConfiguration" bounds
            assignment state tracking trackingCorrect
            (Enabled state (.changeConfiguration node configuration))
            (Enabled (mapState (NatTerm.eval assignment) state)
              (.changeConfiguration node configuration))
            (enabled_mapState_changeConfiguration_iff
              (NatTerm.eval assignment) state node configuration).symm]
          rw [inductionHypothesis (position + 1)
            (next state (.changeConfiguration node configuration))
            (nextConfigurationTracking position state tracking node
              configuration) nextCorrect]
          rw [mapState_changeConfiguration]
          tauto
      | appendRetiredCommitted node =>
          by_cases enabled : Enabled state (.appendRetiredCommitted node)
          · have nextCorrect :=
              nextWriteTracking_retiredCommitted_correct assignment position
                state tracking trackingCorrect node enabled.1
            simp only [encodeFrom, Formula.holds_cons, Follows]
            rw [leaderWriteGroup_correct "appendRetiredCommitted" bounds
              assignment state tracking trackingCorrect
              (Enabled state (.appendRetiredCommitted node))
              (Enabled (mapState (NatTerm.eval assignment) state)
                (.appendRetiredCommitted node))
              (enabled_mapState_appendRetiredCommitted_iff
                (NatTerm.eval assignment) state node).symm]
            rw [inductionHypothesis (position + 1)
              (next state (.appendRetiredCommitted node))
              (nextWriteTracking position tracking node) nextCorrect]
            rw [mapState_appendRetiredCommitted]
            tauto
          · have mappedDisabled :=
              mt (enabled_mapState_appendRetiredCommitted_iff
                (NatTerm.eval assignment) state node).mp enabled
            simp only [encodeFrom, Formula.holds_cons, Follows]
            rw [leaderWriteGroup_correct "appendRetiredCommitted" bounds
              assignment state tracking trackingCorrect
              (Enabled state (.appendRetiredCommitted node))
              (Enabled (mapState (NatTerm.eval assignment) state)
                (.appendRetiredCommitted node))
              (enabled_mapState_appendRetiredCommitted_iff
                (NatTerm.eval assignment) state node).symm]
            simp [mappedDisabled]

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
  rw [encodeFrom_correct bounds assignment 1 entry
    (initialTracking entry) (initialTracking_correct assignment entry) trace]

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
