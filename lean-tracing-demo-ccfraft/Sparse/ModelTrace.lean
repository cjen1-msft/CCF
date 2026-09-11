-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.QueueModel
import Shared.TraceSpec
import TraceStateObservation
import TraceMessageSummary
import MachineGenerated.ModelProofs

set_option autoImplicit false

/-!
Unbounded ordered traces of the actual Model, from one arbitrary initial state.
Input functions share one Nat assignment. They are semantic parameters, not an
SMT language or decoder. Only actual Action constructors advance state.

Configuration snapshots contain the positive-index active configurations in
their original order. They are not raw C++ callback snapshots. Raw send attempts
and ConfigurationPublication's separate callback semantics are outside scope.
-/

namespace CCFRaft.Sparse.ModelTrace

abbrev ModelState := State Node Nat
abbrev UnknownNatAssignment := Nat -> Nat

inductive Observation where
  | allocated (node : Node) (value : Bool)
  | joined (node : Node) (value : Bool)
  | role (node : Node) (value : Role)
  | currentTerm (node : Node) (value : Nat)
  | commitIndex (node : Node) (value : Nat)
  | logLength (node : Node) (value : Nat)
  | submitted (transaction : Nat) (value : Bool)
  | state (value : TraceStateObservation.Observation Node)
  | firstMessage (source destination : Node) (value : Option (Message Node Nat))
  | messageSummary (value : TraceMessageSummary.Summary Node)
  | queueLength (destination : Node) (value : Nat)
  | configurationSnapshot (node : Node) (value : List (Configuration Node))

variable [Bootstrap Node]

def Observation.Holds (observation : Observation) (state : ModelState) : Prop :=
  match observation with
  | .allocated node value => decide (state.allocated node) = value
  | .joined node value => decide (Membership.mem state.hasJoined node) = value
  | .role node value => (state.nodes node).role = value
  | .currentTerm node value => (state.nodes node).currentTerm = value
  | .commitIndex node value => (state.nodes node).commitIndex = value
  | .logLength node value => (state.nodes node).log.length = value
  | .submitted transaction value => decide (Membership.mem state.submittedTxIds transaction) = value
  | .state value => value.Holds state
  | .firstMessage source destination value =>
      (takeFirstFrom source (state.network destination)).map Prod.fst = value
  | .messageSummary value => value.matchesFirst state = true
  | .queueLength destination value => (state.network destination).length = value
  | .configurationSnapshot node value =>
      (activeConfigurations (state.nodes node)).filter
        (fun configuration => 0 < configuration.index) = value

abbrev Instruction := _root_.TraceValidation.Instruction (Action Node Nat) Observation
abbrev Trace := List Instruction
abbrev InputInstruction := _root_.TraceValidation.Instruction
  (UnknownNatAssignment -> Action Node Nat) (UnknownNatAssignment -> Observation)
abbrev InputTrace := List InputInstruction

def instantiate (assignment : UnknownNatAssignment) (trace : InputTrace) : Trace :=
  trace.map fun
    | .action action => .action (action assignment)
    | .observation observation => .observation (observation assignment)

def ConcreteFollows (state : ModelState) (trace : Trace) : Prop :=
  _root_.TraceValidation.follows Enabled CCFRaft.next Observation.Holds state trace

def Follows (assignment : UnknownNatAssignment) (state : ModelState)
    (trace : InputTrace) : Prop :=
  ConcreteFollows state (instantiate assignment trace)

def Satisfiable (trace : InputTrace) : Prop :=
  exists assignment : UnknownNatAssignment,
    _root_.TraceValidation.Satisfiable (fun _ : ModelState => True)
      Enabled CCFRaft.next Observation.Holds (instantiate assignment trace)

theorem satisfiable_iff (trace : InputTrace) :
    Satisfiable trace <->
      exists assignment state, Follows assignment state trace := by
  simp only [Satisfiable, _root_.TraceValidation.Satisfiable, Follows,
    ConcreteFollows, true_and]

theorem follows_observation (assignment : UnknownNatAssignment) (state : ModelState)
    (observation : UnknownNatAssignment -> Observation) (rest : InputTrace) :
    Follows assignment state (.observation observation :: rest) <->
      (observation assignment).Holds state /\ Follows assignment state rest :=
  Iff.rfl

theorem follows_action (assignment : UnknownNatAssignment) (state : ModelState)
    (action : UnknownNatAssignment -> Action Node Nat) (rest : InputTrace) :
    Follows assignment state (.action action :: rest) <->
      Enabled state (action assignment) /\
        Follows assignment (CCFRaft.next state (action assignment)) rest :=
  Iff.rfl

omit [Bootstrap Node] in
theorem partition_congr {left right : ModelState} (related : QueueModel.Related left right)
    (source destination : Node) :
    Queue.partition source (left.network destination) =
      Queue.partition source (right.network destination) :=
  congrFun (congrFun (QueueModel.related_network related) destination) source

omit [Bootstrap Node] in
theorem queue_length_congr {left right : ModelState} (related : QueueModel.Related left right)
    (destination : Node) :
    (left.network destination).length = (right.network destination).length := by
  rw [<- Queue.sum_partition_length (left.network destination),
    <- Queue.sum_partition_length (right.network destination)]
  exact Finset.sum_congr rfl fun source _ =>
    congrArg List.length (partition_congr related source destination)

omit [Bootstrap Node] in
theorem summary_partition (summary : TraceMessageSummary.Summary Node) (state : ModelState) :
    summary.matchesFirst state =
      ((Queue.partition summary.source (state.network summary.destination)).head?.map
        (fun message => decide (TraceMessageSummary.ofMessage message = summary))).getD false := by
  unfold TraceMessageSummary.Summary.matchesFirst
  rw [<- Queue.first_correct]
  cases takeFirstFrom summary.source (state.network summary.destination) <;> rfl

theorem observation_congr {left right : ModelState} (related : QueueModel.Related left right)
    (observation : Observation) :
    observation.Holds left <-> observation.Holds right := by
  cases observation <;> try (rw [QueueModel.related_reconstruct related]; rfl)
  case firstMessage source destination value =>
    simp only [Observation.Holds, Queue.first_correct,
      partition_congr related source destination]
  case messageSummary value =>
    simp only [Observation.Holds, summary_partition,
      partition_congr related value.source value.destination]
  case queueLength destination value =>
    simp only [Observation.Holds, queue_length_congr related destination]

theorem concrete_follows_congr {left right : ModelState}
    (related : QueueModel.Related left right) (trace : Trace) :
    ConcreteFollows left trace <-> ConcreteFollows right trace := by
  induction trace generalizing left right with
  | nil => rfl
  | cons instruction rest ih =>
    cases instruction with
    | observation observation =>
      exact and_congr (observation_congr related observation) (ih related)
    | action action =>
      have step := QueueModel.actual_action_bisimulation related action
      exact and_congr step.1 (ih step.2)

theorem follows_congr (assignment : UnknownNatAssignment) {left right : ModelState}
    (related : QueueModel.Related left right) (trace : InputTrace) :
    Follows assignment left trace <-> Follows assignment right trace :=
  concrete_follows_congr related (instantiate assignment trace)

theorem adjacent_observations (assignment : UnknownNatAssignment) (state : ModelState)
    (first second : UnknownNatAssignment -> Observation) (rest : InputTrace) :
    Follows assignment state (.observation first :: .observation second :: rest) <->
      (first assignment).Holds state /\ (second assignment).Holds state /\
        Follows assignment state rest :=
  Iff.rfl

theorem adjacent_commit_disagreement (node : Node) (first second : Nat)
    (different : Not (first = second)) :
    Not (Satisfiable [
      .observation (fun _ => .commitIndex node first),
      .observation (fun _ => .commitIndex node second)]) := by
  rw [satisfiable_iff]
  intro witness
  cases witness with
  | intro assignment witness =>
    cases witness with
    | intro state follows =>
      have observations := (adjacent_observations assignment state _ _ []).mp follows
      exact different (observations.1.symm.trans observations.2.1)

theorem client_request_shared_unknown (assignment : UnknownNatAssignment) (state : ModelState)
    (node : Node) (id : Nat) (enabled : Enabled state (.clientRequest node (assignment id))) :
    Follows assignment state [
      .action (fun values => .clientRequest node (values id)),
      .observation (fun values => .submitted (values id) true)] := by
  refine (follows_action assignment state _ _).mpr (And.intro enabled ?_)
  apply (follows_observation assignment _ _ []).mpr
  exact And.intro (by simp [Observation.Holds, CCFRaft.next])
    True.intro

theorem client_request_cannot_forget_unknown (node : Node) (id : Nat) :
    Not (Satisfiable [
      .action (fun values => .clientRequest node (values id)),
      .observation (fun values => .submitted (values id) false)]) := by
  rw [satisfiable_iff]
  intro witness
  cases witness with
  | intro assignment witness =>
    cases witness with
    | intro state follows =>
      have action := (follows_action assignment state _ _).mp follows
      have observed := (follows_observation assignment _ _ []).mp action.2
      simpa [Observation.Holds, CCFRaft.next] using observed.1

theorem empty_log_snapshot (state : ModelState) (node : Node)
    (empty : (state.nodes node).log = []) :
    (Observation.configurationSnapshot node []).Holds state := by
  simp [Observation.Holds, activeConfigurations, List.filter_filter, allConfigurations,
    configurationsInLog, configurationsInLogFrom, empty, implicitConfiguration]

-- All four allocation/joined combinations, arbitrary commit, and arbitrary queues.
theorem arbitrary_entry_fields (node : Node) (allocated joined : Bool) (commit : Nat)
    (packets : List (Message Node Nat)) :
    Satisfiable [
      .observation (fun _ => .allocated node allocated),
      .observation (fun _ => .joined node joined),
      .observation (fun _ => .commitIndex node (if allocated then commit else 0)),
      .observation (fun _ => .logLength node 0),
      .observation (fun _ => .queueLength node packets.length)] := by
  rw [satisfiable_iff]
  refine Exists.intro (fun _ => 0) (Exists.intro
    { nodes := if allocated then
        NodeStore.empty.set node { freshNodeState with commitIndex := commit }
      else NodeStore.empty
      network := Function.update (fun _ => []) node packets
      submittedTxIds := {}
      hasJoined := if joined then {node} else {} } ?_)
  cases allocated <;> cases joined <;>
    simp [Follows, ConcreteFollows, instantiate, _root_.TraceValidation.follows,
      Observation.Holds, State.allocated, NodeStore.allocated, NodeStore.get,
      NodeStore.node?, NodeStore.empty, NodeStore.set, freshNodeState]

def regressionPacket (source destination : Node) : Message Node Nat :=
  .proposeVoteRequest { term := 0, source, destination }

theorem malformed_self_duplicates (source other : Node) (different : Not (source = other)) :
    exists state : ModelState,
      state.network source =
        [regressionPacket source other, regressionPacket source other,
          regressionPacket source source, regressionPacket source source] /\
      Not ((regressionPacket source other).destination = source) /\
      Follows (fun _ => 0) state [
        .observation (fun _ => .allocated source false),
        .observation (fun _ => .queueLength source 4),
        .observation (fun _ => .firstMessage source source
          (some (regressionPacket source other)))] := by
  refine Exists.intro
    { nodes := NodeStore.empty
      network := fun _ =>
        [regressionPacket source other, regressionPacket source other,
          regressionPacket source source, regressionPacket source source]
      submittedTxIds := {}
      hasJoined := {} } (And.intro rfl (And.intro ?_ ?_))
  next => simpa [regressionPacket, Message.destination, eq_comm] using different
  next =>
    simp [Follows, ConcreteFollows, instantiate, _root_.TraceValidation.follows,
      Observation.Holds, State.allocated, NodeStore.allocated, NodeStore.node?,
      NodeStore.empty, takeFirstFrom, regressionPacket, Message.source]

end CCFRaft.Sparse.ModelTrace

run_cmd do
  let mut checked := 0
  for (name, info) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.Sparse.ModelTrace).isPrefixOf name then
      match info with
      | .axiomInfo _ => throwError "explicit ModelTrace axiom: {name}"
      | _ =>
        checked := checked + 1
        for axiomName in (<- Lean.collectAxioms name) do
          unless axiomName == ``propext || axiomName == ``Classical.choice ||
              axiomName == ``Quot.sound do
            throwError "unexpected axiom in {name}: {axiomName}"
  Lean.logInfo m!"ModelTrace: {checked} declarations passed the allowed-axiom gate."
