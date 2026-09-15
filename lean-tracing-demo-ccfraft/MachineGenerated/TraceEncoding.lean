-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import BoundedTrace
import Shared.SmtOrder
import MachineGenerated.GuardedAppendEntries
import MachineGenerated.GuardedReceive
import MachineGenerated.ReceiveTraceQueue
import MachineGenerated.ReceiveTraceGuards
import MachineGenerated.ReceiveTraceValues
import MachineGenerated.ReceiveTraceReplication
import MachineGenerated.ReceiveTraceEffects
import MachineGenerated.ReceiveTraceConfigurations
import MachineGenerated.ReceiveTracePackets
import MachineGenerated.ReceiveTraceBranching
import MachineGenerated.ControlActionMappingProofs
import MachineGenerated.ControlTraceConfigurations
import MachineGenerated.ControlTraceRetirement
import MachineGenerated.ControlTracePackets

set_option autoImplicit false

/-!
# Full-template guarded trace encoding

The encoder executes the reviewed model transition over the symbolic template.
Transaction identifiers may be unknown. Named derived values preserve causal
links in diagnostic cores; structural control fields come from the template.
Guarded frames retain assignment-dependent queue alternatives after a send.
-/

namespace CCFRaft.TraceEncoding

open TraceSmt BoundedTrace
open TransactionMapping

abbrev Value := TraceSmt.NatTerm

def boolValue {holes : Nat} (value : Bool) : Value holes :=
  .literal (if value then 1 else 0)

def markerSlot (base : Nat) (node : Node) : Nat :=
  base + node.val

def ALLOCATED_SLOT_BASE : Nat := 10
def JOINED_SLOT_BASE : Nat := 30
def SENT_INDEX_SLOT_BASE : Nat := 50
def QUEUE_LENGTH_SLOT_BASE : Nat := 70
def ROLE_SLOT_BASE : Nat := 90
def TERM_SLOT_BASE : Nat := 110
def COMMIT_SLOT_BASE : Nat := 130
def MATCH_SLOT_BASE : Nat := 150
def PACKET_TERM_SLOT : Nat := 380
def LOG_TERM_SLOT : Nat := 381
def PACKET_FIELD_SLOT_BASE : Nat := 382
def PAYLOAD_TERM_SLOT : Nat := 390
def VOTE_SLOT_BASE : Nat := 400
def PRE_VOTE_SLOT_BASE : Nat := 420
def CONFIGURATION_SLOT : Nat := 440
def COMPLETED_SLOT_BASE : Nat := 450
def QUEUE_ARCHIVE_SLOT : Nat := 470
def PAYLOAD_POSITION_SLOT : Nat := 471
def LOCAL_FIELD_SLOT_BASE : Nat := 480
def PATH_SLOT_STRIDE : Nat := 560

#guard 4 < ALLOCATED_SLOT_BASE &&
  ALLOCATED_SLOT_BASE + NODE_COUNT ≤ JOINED_SLOT_BASE &&
  JOINED_SLOT_BASE + NODE_COUNT ≤ SENT_INDEX_SLOT_BASE &&
  SENT_INDEX_SLOT_BASE + NODE_COUNT ≤ QUEUE_LENGTH_SLOT_BASE &&
  QUEUE_LENGTH_SLOT_BASE + NODE_COUNT ≤ ROLE_SLOT_BASE &&
  ROLE_SLOT_BASE + NODE_COUNT ≤ TERM_SLOT_BASE &&
  TERM_SLOT_BASE + NODE_COUNT ≤ COMMIT_SLOT_BASE &&
  COMMIT_SLOT_BASE + NODE_COUNT ≤ MATCH_SLOT_BASE &&
  MATCH_SLOT_BASE + NODE_COUNT * NODE_COUNT ≤ PACKET_TERM_SLOT &&
  PACKET_TERM_SLOT < LOG_TERM_SLOT && LOG_TERM_SLOT < PACKET_FIELD_SLOT_BASE &&
  PACKET_FIELD_SLOT_BASE + 8 ≤ PAYLOAD_TERM_SLOT && PAYLOAD_TERM_SLOT < VOTE_SLOT_BASE &&
  VOTE_SLOT_BASE + NODE_COUNT ≤ PRE_VOTE_SLOT_BASE &&
  PRE_VOTE_SLOT_BASE + NODE_COUNT ≤ CONFIGURATION_SLOT &&
  CONFIGURATION_SLOT < COMPLETED_SLOT_BASE &&
  COMPLETED_SLOT_BASE + NODE_COUNT ≤ QUEUE_ARCHIVE_SLOT &&
  QUEUE_ARCHIVE_SLOT < PAYLOAD_POSITION_SLOT && PAYLOAD_POSITION_SLOT < LOCAL_FIELD_SLOT_BASE &&
  LOCAL_FIELD_SLOT_BASE + 4 * NODE_COUNT ≤ PATH_SLOT_STRIDE

def pathSlot (pathId base : Nat) : Nat :=
  pathId * PATH_SLOT_STRIDE + base

structure Tracking (holes : Nat) where
  logLengths : Node -> Value holes
  retirementWriters : Node -> Option (Nat × Nat)
  allocated : Node -> Value holes
  joined : Node -> Value holes
  sentIndex : Node -> Node -> Value holes
  queueLengths : Node -> Value holes
  controlWriters : Node -> Nat -> Option (Nat × Nat) := fun _ _ => none
  currentTerms : Node -> Value holes
  packetTerms : Message Node (Value holes) -> Value holes
  logPositions : Node -> Nat -> Value holes
  commitIndices : Node -> Nat -> Value holes
  logTerms : Node -> Nat -> Nat -> Value holes
  packetFields : Message Node (Value holes) -> Nat -> Nat -> Value holes
  voteMembers : Node -> Bool -> Node -> Bool -> Value holes
  configurations : Node -> List (Configuration Node) -> List (ControlTraceConfigurations.Snapshot holes)
  completedMembers : Node -> Node -> Bool -> Value holes
  queues : Node -> List (Message Node (Value holes)) -> List (ReceiveTraceQueue.Snapshot holes)
  matchIndices : Node -> Node -> Nat -> Value holes
  localFields : Node -> Nat -> Nat -> Value holes
  packetPositions : Message Node (Value holes) -> Nat -> Nat -> Value holes

def roleCode : Role -> Nat
  | .none => 0
  | .follower => 1
  | .preVoteCandidate => 2
  | .candidate => 3
  | .leader => 4

def localField {holes : Nat} (state : NodeState Node (Value holes)) : Nat -> Nat
  | 0 => if state.isNewFollower then 1 else 0
  | 1 => (state.votedFor.map fun node => node.val + 1).getD 0
  | 2 => roleCode state.role
  | 3 => if state.role = .follower ∨ state.role = .preVoteCandidate ∨ state.role = .candidate then 1 else 0
  | _ => 0

def minValue {holes : Nat} (left right : Value holes) : Value holes :=
  .sub left (.sub left right)

def maxValue {holes : Nat} (left right : Value holes) : Value holes :=
  .add left (.sub right left)

def leValue {holes : Nat} (left right : Value holes) : Value holes :=
  minValue (.literal 1) (.sub (.add right (.literal 1)) left)

def packetFieldLabel : Nat -> String
  | 0 => "previous log index"
  | 1 => "previous log term"
  | 2 => "leader commit"
  | 3 => "last committable index"
  | 4 => "last committable term"
  | 5 => "payload length"
  | _ => "payload entry term"

def fieldOrigin {holes : Nat}
    (position pathId field expected : Nat) (value : Value holes) : Nat -> Value holes :=
  Function.update (fun input => .literal input) expected
    (.named position (pathSlot pathId (PACKET_FIELD_SLOT_BASE + field))
      (packetFieldLabel field) value)

def logTermValue {holes : Nat} (state : Template holes) (tracking : Tracking holes)
    (node : Node) (index : ReceiveTraceValues.Scalar holes) : ReceiveTraceValues.Scalar holes :=
  ReceiveTraceReplication.lookupTerm (state.nodes node).log index (tracking.logLengths node)
    (tracking.logPositions node) (tracking.logTerms node)

def indexedLogTerm {holes : Nat} (state : Template holes) (tracking : Tracking holes)
    (node : Node) (index : ReceiveTraceValues.Scalar holes) (term : Nat) : Value holes :=
  if term = termAt (state.nodes node).log index.actual then
    (logTermValue state tracking node index).expression
  else tracking.logTerms node index.actual term

def electionFrontier {holes : Nat}
    (state : Template holes) (tracking : Tracking holes) (source : Node) : Value holes :=
  maxValue (tracking.commitIndices source (state.nodes source).commitIndex)
    (tracking.logPositions source (maxCommittableIndex (state.nodes source).log))

def votePacketFields {holes : Nat}
    (position pathId : Nat) (state : Template holes) (tracking : Tracking holes)
    (source : Node) : Nat -> Nat -> Value holes
  | 3 => fieldOrigin position pathId 3 (lastCommittableIndex (state.nodes source))
      (electionFrontier state tracking source)
  | 4 => fieldOrigin position pathId 4 (lastCommittableTerm (state.nodes source))
      (logTermValue state tracking source
        ⟨lastCommittableIndex (state.nodes source), electionFrontier state tracking source⟩).expression
  | _ => fun value => .literal value

def appendPacketFields {holes : Nat}
    (position pathId : Nat) (state : Template holes) (tracking : Tracking holes)
    (source destination : Node) (batchEnd : Nat) : Nat -> Nat -> Value holes :=
  let localState := state.nodes source
  let previous := localState.sentIndex destination
  let sent := tracking.sentIndex source destination
  fun field =>
    match field with
    | 0 => fieldOrigin position pathId 0 previous sent
    | 1 => fieldOrigin position pathId 1 (termAt localState.log previous)
        (logTermValue state tracking source ⟨previous, sent⟩).expression
    | 2 => fieldOrigin position pathId 2 localState.commitIndex
        (tracking.commitIndices source localState.commitIndex)
    | 5 => fieldOrigin position pathId 5 (messageEntries localState.log previous batchEnd).length
        (minValue (.sub (tracking.logLengths source) sent) (.sub (.literal batchEnd) sent))
    | _ =>
        if 6 ≤ field then
          fun term => .named position (pathSlot (Nat.pair pathId (field - 6)) PAYLOAD_TERM_SLOT)
            s!"payload entry term {field - 6}"
            (indexedLogTerm state tracking source
              ⟨previous + (field - 6), .add sent (.literal (field - 6))⟩ term)
        else fun value => .literal value

def appendPacketPositions {holes : Nat} (position pathId : Nat) (state : Template holes) (tracking : Tracking holes)
    (source destination : Node) (offset value : Nat) : Value holes :=
  let index := (state.nodes source).sentIndex destination + offset
  if value = index then
    .named position (pathSlot (Nat.pair pathId offset) PAYLOAD_POSITION_SLOT) s!"payload log position {offset}"
      (tracking.logPositions source index)
  else .literal value

def controlValue {holes : Nat}
    (tracking : Tracking holes) (node : Node) (slot : Nat)
    (label : String) (value : Nat) : Value holes :=
  match tracking.controlWriters node slot with
  | none => .literal value
  | some (position, pathId) =>
      .named position (pathSlot pathId slot) label (.literal value)

def roleCases {holes : Nat}
    (value : Value holes) (predicate : Role -> Prop)
    [DecidablePred predicate] : Expr holes :=
  [.none, .follower, .preVoteCandidate, .candidate, .leader].foldr
    (fun role rest =>
      .not (.and
        (.not (.and (.equal value (.literal (roleCode role)))
          (.boolean (decide (predicate role)))))
        (.not rest)))
    (.boolean false)

def withRole {holes : Nat}
    (state : Template holes) (node : Node) (role : Role) : Template holes :=
  if (state.nodes node).role = role then state
  else
    match state.node? node with
    | none => state
    | some localState =>
        { state with nodes := updateNode state.nodes node { localState with role } }

def actionRoleNode {holes : Nat} : Action Node (Value holes) -> Node
  | .clientRequest node _ | .signCommittableMessages node
  | .changeConfiguration node _ | .appendRetiredCommitted node
  | .appendEntries node _ _ | .receive _ node | .advanceCommitIndex node
  | .timeout node | .becomePreVoteCandidate node | .becomeCandidate node
  | .requestVote node _ | .requestPreVote node _ | .checkQuorum node
  | .updateTerm _ node | .becomeLeader node | .proposeVote node _
  | .advanceCommitIndexAndProposeVote node _ => node

def roleGuard {holes : Nat}
    (state : Template holes) (tracking : Tracking holes) (node : Node)
    (predicate : Template holes -> Prop) [DecidablePred predicate] : Expr holes :=
  roleCases
    (tracking.localFields node 2 (roleCode (state.nodes node).role))
    (fun role => predicate (withRole state node role))

def allExpr {holes : Nat} (values : List (Expr holes)) : Expr holes :=
  values.foldr .and (.boolean true)

def orExpr {holes : Nat} (left right : Expr holes) : Expr holes :=
  .not (.and (.not left) (.not right))

def anyExpr {holes : Nat} (values : List (Expr holes)) : Expr holes :=
  values.foldr orExpr (.boolean false)

def appendQueueLength {holes : Nat}
    (position pathId : Nat) (state : Template holes) (tracking : Tracking holes)
    (source destination : Node) (batchEnd : Nat) : Value holes :=
  .add (tracking.queueLengths destination)
    (.named position (pathSlot pathId (markerSlot QUEUE_LENGTH_SLOT_BASE destination))
      s!"queue growth {destination.val}" (.literal 1))

def configurationSnapshots {holes : Nat}
    (state : Template holes) (tracking : Tracking holes) (node : Node) :
    List (ControlTraceConfigurations.Snapshot holes) :=
  tracking.configurations node (allConfigurations (state.nodes node).log)

def configurationPresent {holes : Nat} (snapshot : ControlTraceConfigurations.Snapshot holes) : Expr holes :=
  .equal snapshot.present (.literal 1)

def latestConfigurationValue {holes : Nat}
    (state : Template holes) (tracking : Tracking holes) (node : Node)
    (predicate : Configuration Node -> Bool) : Value holes :=
  ControlTraceConfigurations.lastValue (configurationSnapshots state tracking node) predicate
    (boolValue (predicate implicitConfiguration))

def currentConfigurationIndexValue {holes : Nat}
    (state : Template holes) (tracking : Tracking holes) (node : Node) : Value holes :=
  ControlTraceConfigurations.lastIndexValue
    (ControlTraceConfigurations.truncatePure (configurationSnapshots state tracking node)
      (tracking.commitIndices node (state.nodes node).commitIndex)) (.literal 0)

def addedConfigurationMemberValue {holes : Nat}
    (state : Template holes) (tracking : Tracking holes) (source : Node)
    (configuration : Finset Node) (peer : Node) : Value holes :=
  if peer ∈ configuration then
    .sub (.literal 1) (latestConfigurationValue state tracking source
      (fun previous => decide (peer ∈ previous.nodes)))
  else .literal 0

def currentConfigurationMemberValue {holes : Nat}
    (state : Template holes) (tracking : Tracking holes) (node peer : Node) : Value holes :=
  let predicate := fun cfg : Configuration Node => decide (peer ∈ cfg.nodes)
  ControlTraceConfigurations.lastValue
    (ControlTraceConfigurations.truncatePure (configurationSnapshots state tracking node)
      (tracking.commitIndices node (state.nodes node).commitIndex))
    predicate (boolValue (predicate implicitConfiguration))

def refreshedCompletedValue {holes : Nat}
    (state : Template holes) (tracking : Tracking holes) (node peer : Node) : Value holes :=
  ControlTraceRetirement.completedValue peer (configurationSnapshots state tracking node)
    (state.nodes node).log (tracking.logPositions node)
    (tracking.commitIndices node (state.nodes node).commitIndex)
    (currentConfigurationIndexValue state tracking node)
    (currentConfigurationMemberValue state tracking node peer)

def refreshCompletedTracking {holes : Nat}
    (position pathId : Nat) (state : Template holes) (tracking : Tracking holes) (node : Node) : Tracking holes :=
  { tracking with
    completedMembers := Function.update tracking.completedMembers node (fun peer =>
      Function.update (tracking.completedMembers node peer)
        (decide (peer ∈ retirementCompletedNodes (state.nodes node).log (state.nodes node).commitIndex))
        (.named position (pathSlot pathId (markerSlot COMPLETED_SLOT_BASE peer))
          "retirement completed membership" (refreshedCompletedValue state tracking node peer))) }

def completedMemberExpr {holes : Nat}
    (state : Template holes) (tracking : Tracking holes) (node peer : Node) : Expr holes :=
  .equal (tracking.completedMembers node peer (decide (peer ∈ state.retirementCompleted node))) (.literal 1)

def pendingRetirementExpr {holes : Nat}
    (state : Template holes) (tracking : Tracking holes) (node : Node) : Expr holes :=
  anyExpr ((List.finRange NODE_COUNT).map fun peer =>
    .and (completedMemberExpr state tracking node peer)
      (.equal (ControlTraceRetirement.recordedValue peer (tracking.logPositions node)
        (tracking.logLengths node) 1 (state.nodes node).log) (.literal 0)))

def refreshedRetiredExpr {holes : Nat}
    (state : Template holes) (tracking : Tracking holes) (node : Node) : Expr holes :=
  ControlTraceRetirement.retiredExpr node (configurationSnapshots state tracking node)
    (state.nodes node).log (tracking.logPositions node)
    (tracking.commitIndices node (state.nodes node).commitIndex)

def retiredStateExpr {holes : Nat}
    (state : Template holes) (tracking : Tracking holes) (node : Node) : Expr holes :=
  -- Explicit entries may supply retirement metadata independently of their logs.
  if (state.nodes node).membershipState =
      (refreshRetirementState node (state.nodes node)).membershipState then
    refreshedRetiredExpr state tracking node
  else
    .boolean (decide ((state.nodes node).membershipState = .retiredCommitted))

def appendConfigurationSnapshots {holes : Nat}
    (state : Template holes) (tracking : Tracking holes) (node : Node)
    (content : EntryContent Node (Value holes)) : List (ControlTraceConfigurations.Snapshot holes) :=
  match content with
  | .reconfiguration nodes =>
      ControlTraceConfigurations.appendPure (configurationSnapshots state tracking node)
        { index := (state.nodes node).log.length + 1, nodes }
        (.add (tracking.logLengths node) (.literal 1))
  | _ => configurationSnapshots state tracking node

def appendRetiredExpr {holes : Nat}
    (state : Template holes) (tracking : Tracking holes) (node : Node)
    (content : EntryContent Node (Value holes)) : Expr holes :=
  let localState := state.nodes node
  ControlTraceRetirement.retiredExpr node (appendConfigurationSnapshots state tracking node content)
    (localState.log ++ [{ term := localState.currentTerm, content }])
    (Function.update (tracking.logPositions node) (localState.log.length + 1)
      (.add (tracking.logLengths node) (.literal 1)))
    (tracking.commitIndices node localState.commitIndex)

def promotedRetiredExpr {holes : Nat}
    (state : Template holes) (tracking : Tracking holes) (node : Node) : Expr holes :=
  let localState := state.nodes node
  let frontier := maxCommittableIndex localState.log
  ControlTraceRetirement.retiredExpr node
    (ControlTraceConfigurations.truncatePure (configurationSnapshots state tracking node)
      (tracking.logPositions node frontier))
    (localState.log.take frontier) (tracking.logPositions node)
    (tracking.commitIndices node localState.commitIndex)

def activeConfigurationExpr {holes : Nat}
    (state : Template holes) (tracking : Tracking holes)
    (node : Node) (configuration : Configuration Node) : Expr holes :=
  allExpr ((configurationSnapshots state tracking node).map fun later =>
    (configurationPresent later).implies
      (if configuration.index < later.configuration.index then
        .lessThan (tracking.commitIndices node (state.nodes node).commitIndex) later.position
      else .boolean true))

def voteMajorityExpr {holes : Nat}
    (state : Template holes) (tracking : Tracking holes) (node : Node) (preVote : Bool) :
    Expr holes :=
  let votes := if preVote then (state.nodes node).preVotesGranted else (state.nodes node).votesGranted
  allExpr ((configurationSnapshots state tracking node).map fun snapshot =>
    let configuration := snapshot.configuration
    let count := (configuration.nodes.sort (· ≤ ·)).foldl
      (fun total peer => .add total (tracking.voteMembers node preVote peer (decide (peer ∈ votes))))
      (.literal 0)
    (configurationPresent snapshot).implies
      ((activeConfigurationExpr state tracking node configuration).implies
        (.lessThan (.literal configuration.nodes.card) (.add count count))))

def replicationMajorityExpr {holes : Nat}
    (state : Template holes) (tracking : Tracking holes) (node : Node) (index : Nat) : Expr holes :=
  let position := tracking.logPositions node index
  allExpr ((configurationSnapshots state tracking node).map fun snapshot =>
    let configuration := snapshot.configuration
    let count : Value holes := (configuration.nodes.sort (· ≤ ·)).foldl (fun total peer =>
      .add total (if peer = node then .literal 1 else
        leValue position
          (tracking.matchIndices node peer ((state.nodes node).matchIndex peer)))) (.literal 0)
    (configurationPresent snapshot).implies
      ((activeConfigurationExpr state tracking node configuration).implies
        ((Expr.not (.lessThan position snapshot.position)).implies
          (.lessThan (.literal configuration.nodes.card) (.add count count)))))

def committableAtExpr {holes : Nat}
    (state : Template holes) (tracking : Tracking holes) (node : Node) (index : Nat) : Expr holes :=
  .and (.boolean (isSignatureAt (state.nodes node).log index))
    (.and (.lessThan (tracking.commitIndices node (state.nodes node).commitIndex)
      (tracking.logPositions node index))
      (.and (.equal (tracking.logTerms node index (termAt (state.nodes node).log index))
        (tracking.currentTerms node))
        (replicationMajorityExpr state tracking node index)))

def committableExpr {holes : Nat}
    (state : Template holes) (tracking : Tracking holes) (node : Node) : Expr holes :=
  anyExpr ((List.range ((state.nodes node).log.length + 1)).map (committableAtExpr state tracking node))

def highestCommittableValue {holes : Nat}
    (state : Template holes) (tracking : Tracking holes) (node : Node) : Value holes :=
  (List.range ((state.nodes node).log.length + 1)).foldl
    (fun previous index =>
      (committableAtExpr state tracking node index).ite (tracking.logPositions node index) previous)
    (.literal 0)

def terminalRetiredExpr {holes : Nat}
    (state : Template holes) (tracking : Tracking holes) (node : Node) : Expr holes :=
  ControlTraceRetirement.retiredExpr node (configurationSnapshots state tracking node)
    (state.nodes node).log (tracking.logPositions node) (highestCommittableValue state tracking node)

def activeMemberExpr {holes : Nat}
    (state : Template holes) (tracking : Tracking holes) (node peer : Node) : Expr holes :=
  anyExpr ((configurationSnapshots state tracking node).map fun snapshot =>
    .and (configurationPresent snapshot)
      (.and (activeConfigurationExpr state tracking node snapshot.configuration)
        (.boolean (decide (peer ∈ snapshot.configuration.nodes)))))

def campaignExpr {holes : Nat}
    (state : Template holes) (tracking : Tracking holes) (node : Node) : Expr holes :=
  anyExpr ((configurationSnapshots state tracking node).map fun snapshot =>
    .and (configurationPresent snapshot)
      (.and (activeConfigurationExpr state tracking node snapshot.configuration)
        (.and (.boolean (decide (node ∈ snapshot.configuration.nodes)))
          (.not (.lessThan (tracking.logPositions node (maxCommittableIndex (state.nodes node).log))
            snapshot.position)))))

def configurationRankLeExpr {holes : Nat}
    (state : Template holes) (tracking : Tracking holes) (node candidate destination : Node) : Expr holes :=
  let snapshots := configurationSnapshots state tracking node
  allExpr (snapshots.map fun origin =>
    (configurationPresent origin).implies
      ((activeConfigurationExpr state tracking node origin.configuration).implies
        ((Expr.boolean (decide (candidate ∈ origin.configuration.nodes))).implies
          (orExpr (.equal origin.position (.literal 0))
            (anyExpr (snapshots.map fun target =>
              .and (configurationPresent target)
                (.and (activeConfigurationExpr state tracking node target.configuration)
                  (.and (.boolean (decide (destination ∈ target.configuration.nodes)))
                    (.not (.lessThan target.position origin.position))))))))))

def matchValue {holes : Nat}
    (state : Template holes) (tracking : Tracking holes) (node peer : Node) : Value holes :=
  tracking.matchIndices node peer ((state.nodes node).matchIndex peer)

def successorExpr {holes : Nat}
    (state : Template holes) (tracking : Tracking holes) (source destination : Node) : Expr holes :=
  .and (.and (.boolean (decide (destination ≠ source))) (activeMemberExpr state tracking source destination))
    (allExpr ((List.finRange NODE_COUNT).map fun candidate =>
      (Expr.and (.boolean (decide (candidate ≠ source)))
        (activeMemberExpr state tracking source candidate)).implies
        (.and (.not (.lessThan (matchValue state tracking source destination)
          (matchValue state tracking source candidate)))
          ((Expr.equal (matchValue state tracking source candidate)
            (matchValue state tracking source destination)).implies
              (configurationRankLeExpr state tracking source candidate destination)))))

def membershipRequirements {holes : Nat}
    (state : Template holes) (action : Action Node (Value holes)) : Prop :=
  match action with
  | .timeout node | .becomePreVoteCandidate node | .becomeCandidate node =>
      (node ∈ activeNodeUnion (state.nodes node) ∧ campaignEligible node (state.nodes node)) ∨
        node ∈ state.retirementCompleted node
  | .requestVote source destination | .requestPreVote source destination =>
      destination ∈ activeNodeUnion (state.nodes source)
  | .appendEntries source destination _ =>
      destination ∈ activeNodeUnion (state.nodes source) ∨ destination ∈ state.retirementCompleted source
  | .checkQuorum node => hasOtherActiveReplica state node
  | .proposeVote source destination | .advanceCommitIndexAndProposeVote source destination =>
      plausibleSuccessor state source destination
  | _ => True

instance {holes : Nat} (state : Template holes) (action : Action Node (Value holes)) :
    Decidable (membershipRequirements state action) := by
  cases action <;> unfold membershipRequirements <;> infer_instance

def membershipRequirementsExpr {holes : Nat}
    (state : Template holes) (tracking : Tracking holes) (action : Action Node (Value holes)) : Expr holes :=
  match action with
  | .timeout node | .becomePreVoteCandidate node | .becomeCandidate node =>
      orExpr (.and (activeMemberExpr state tracking node node) (campaignExpr state tracking node))
        (completedMemberExpr state tracking node node)
  | .requestVote source destination | .requestPreVote source destination =>
      activeMemberExpr state tracking source destination
  | .appendEntries source destination _ =>
      orExpr (activeMemberExpr state tracking source destination)
        (completedMemberExpr state tracking source destination)
  | .checkQuorum node =>
      anyExpr ((List.finRange NODE_COUNT).map fun peer =>
        .and (.boolean (decide (peer ≠ node))) (activeMemberExpr state tracking node peer))
  | .proposeVote source destination | .advanceCommitIndexAndProposeVote source destination =>
      successorExpr state tracking source destination
  | _ => .boolean true

def allocationNodes {holes : Nat} (action : Action Node (Value holes)) : List Node :=
  match action with
  | .appendEntries source destination _ | .requestVote source destination
  | .requestPreVote source destination | .proposeVote source destination
  | .advanceCommitIndexAndProposeVote source destination => [source, destination]
  | _ => [actionRoleNode action]

def allocatedExpr {holes : Nat} (tracking : Tracking holes) (node : Node) : Expr holes :=
  .equal (tracking.allocated node) (.literal 1)

def structuralClientExpr {holes : Nat}
    (state : Template holes) (tracking : Tracking holes) (node : Node)
    (transaction : Value holes) : Expr holes :=
  .and (allocatedExpr tracking node)
    (.and (.equal (tracking.localFields node 2 (roleCode (state.nodes node).role)) (.literal (roleCode .leader)))
      (.and (.not (retiredStateExpr state tracking node))
        (.not (appendRetiredExpr state tracking node (.transaction transaction)))))

def retirementRequirements {holes : Nat}
    (state : Template holes) (action : Action Node (Value holes)) : Prop :=
  let node := actionRoleNode action
  let localState := state.nodes node
  let active := localState.membershipState ≠ .retiredCommitted
  let appendAllowed := fun content =>
    (refreshRetirementState node { localState with
      log := localState.log ++ [{ term := localState.currentTerm, content }] }).membershipState ≠ .retiredCommitted
  match action with
  | .clientRequest _ transaction => active ∧ appendAllowed (.transaction transaction)
  | .signCommittableMessages _ => active ∧ appendAllowed .signature
  | .changeConfiguration _ configuration => active ∧ appendAllowed (.reconfiguration configuration)
  | .appendRetiredCommitted _ =>
      active ∧ appendAllowed (.retiredCommitted (pendingRetiredCommittedNodes state node))
  | .timeout _ | .becomePreVoteCandidate _ | .becomeCandidate _ => active
  | .becomeLeader _ =>
      active ∧ (refreshRetirementState node { localState with
        log := localState.log.take (maxCommittableIndex localState.log) }).membershipState ≠ .retiredCommitted
  | .advanceCommitIndex _ => ¬terminalRetirementCommit state node
  | .advanceCommitIndexAndProposeVote _ _ => terminalRetirementCommit state node
  | _ => True

instance {holes : Nat} (state : Template holes) (action : Action Node (Value holes)) :
    Decidable (retirementRequirements state action) := by
  cases action <;> unfold retirementRequirements <;> infer_instance

def retirementRequirementsExpr {holes : Nat}
    (state : Template holes) (tracking : Tracking holes) (action : Action Node (Value holes)) : Expr holes :=
  let node := actionRoleNode action
  let active := Expr.not (retiredStateExpr state tracking node)
  match action with
  | .clientRequest _ transaction => .and active (.not (appendRetiredExpr state tracking node (.transaction transaction)))
  | .signCommittableMessages _ => .and active (.not (appendRetiredExpr state tracking node .signature))
  | .changeConfiguration _ configuration => .and active (.not (appendRetiredExpr state tracking node (.reconfiguration configuration)))
  | .appendRetiredCommitted _ =>
      .and active (.not (appendRetiredExpr state tracking node (.retiredCommitted (pendingRetiredCommittedNodes state node))))
  | .timeout _ | .becomePreVoteCandidate _ | .becomeCandidate _ => active
  | .becomeLeader _ => .and active (.not (promotedRetiredExpr state tracking node))
  | .advanceCommitIndex _ => .not (terminalRetiredExpr state tracking node)
  | .advanceCommitIndexAndProposeVote _ _ => terminalRetiredExpr state tracking node
  | _ => .boolean true

def sourceAllowedExpr {holes : Nat}
    (tracking : Tracking holes) (message : Message Node (Value holes)) : Expr holes :=
  match message with
  | .appendEntriesResponse response => allocatedExpr tracking response.source
  | .requestVoteResponse response => allocatedExpr tracking response.source
  | .requestPreVoteResponse response => allocatedExpr tracking response.source
  | _ => .boolean true

def firstPacketTerm {holes : Nat} (state : Template holes) (tracking : Tracking holes)
    (source destination : Node) : Value holes :=
  ReceiveTraceQueue.firstValue source tracking.packetTerms (.literal 0)
    (tracking.queues destination (state.network destination))

def packetFieldNumber {holes : Nat} (message : Message Node (Value holes)) (field : Nat) : Nat :=
  match message with
  | .appendEntriesRequest request =>
      match field with
      | 0 => request.prevLogIndex
      | 1 => request.prevLogTerm
      | 2 => request.leaderCommit
      | 5 => request.entries.length
      | _ => if 7 ≤ field then ((request.entries[field - 7]?).map Entry.term).getD 0 else 0
  | .appendEntriesResponse response =>
      if field = 3 then response.lastLogIndex else if field = 6 then (if response.success then 1 else 0) else 0
  | .requestVoteRequest request =>
      if field = 3 then request.lastCommittableIndex else if field = 4 then request.lastCommittableTerm else 0
  | .requestPreVote request =>
      if field = 3 then request.lastCommittableIndex else if field = 4 then request.lastCommittableTerm else 0
  | .requestVoteResponse response =>
      if field = 7 then (if response.voteGranted then 1 else 0) else 0
  | .requestPreVoteResponse response =>
      if field = 7 then (if response.voteGranted then 1 else 0) else 0
  | .proposeVoteRequest _ => 0

def firstPacketField {holes : Nat} (state : Template holes) (tracking : Tracking holes)
    (source destination : Node) (field : Nat) : Value holes :=
  ReceiveTraceQueue.firstValue source
    (fun packet => tracking.packetFields packet field (packetFieldNumber packet field)) (.literal 0)
    (tracking.queues destination (state.network destination))

def voteFreshExpr {holes : Nat} (state : Template holes) (tracking : Tracking holes)
    (source destination : Node) : Expr holes :=
  let log := (state.nodes destination).log
  let index := maxCommittableIndex log
  let localTerm := tracking.logTerms destination index (maxCommittableTerm log)
  let offeredTerm := firstPacketField state tracking source destination 4
  let offeredIndex := firstPacketField state tracking source destination 3
  orExpr (.lessThan localTerm offeredTerm)
    (.and (.equal localTerm offeredTerm)
      (.not (.lessThan offeredIndex (tracking.logPositions destination index))))

def voteGrantExpr {holes : Nat} (state : Template holes) (tracking : Tracking holes)
    (source destination : Node) (preVote : Bool) : Expr holes :=
  let votedFor := tracking.localFields destination 1 (localField (state.nodes destination) 1)
  .and (.equal (firstPacketTerm state tracking source destination) (tracking.currentTerms destination))
    (.and (voteFreshExpr state tracking source destination)
      (if preVote then .boolean true else
        orExpr (.equal votedFor (.literal 0)) (.equal votedFor (.literal (source.val + 1)))))

def voteGrantCondition {holes : Nat} (state : Template holes) (source destination : Node)
    (preVote : Bool) (message : Message Node (Value holes)) : Prop :=
  message.term = (state.nodes destination).currentTerm ∧
    (packetFieldNumber message 4 > maxCommittableTerm (state.nodes destination).log ∨
      packetFieldNumber message 4 = maxCommittableTerm (state.nodes destination).log ∧
        packetFieldNumber message 3 ≥ maxCommittableIndex (state.nodes destination).log) ∧
    (preVote = true ∨ (state.nodes destination).votedFor = none ∨
      (state.nodes destination).votedFor = some source)

instance {holes : Nat} (state : Template holes) (source destination : Node)
    (preVote : Bool) (message : Message Node (Value holes)) :
    Decidable (voteGrantCondition state source destination preVote message) := by
  unfold voteGrantCondition
  infer_instance

def voteGrantValue {holes : Nat} (state : Template holes) (tracking : Tracking holes)
    (source destination : Node) (preVote : Bool) (message : Message Node (Value holes)) :
    ReceiveTraceValues.Scalar holes :=
  { actual := if voteGrantCondition state source destination preVote message then 1 else 0
    expression := (voteGrantExpr state tracking source destination preVote).ite (.literal 1) (.literal 0) }

def receiveVoteCondition {holes : Nat} (state : Template holes) (source destination : Node)
    (preVote : Bool) (message : Message Node (Value holes)) : Prop :=
  state.allocated source ∧
    (state.nodes destination).role = (if preVote then .preVoteCandidate else .candidate) ∧
    message.term = (state.nodes destination).currentTerm ∧ packetFieldNumber message 7 = 1

instance {holes : Nat} (state : Template holes) (source destination : Node)
    (preVote : Bool) (message : Message Node (Value holes)) :
    Decidable (receiveVoteCondition state source destination preVote message) := by
  unfold receiveVoteCondition
  infer_instance

def receiveVoteExpr {holes : Nat} (state : Template holes) (tracking : Tracking holes)
    (source destination : Node) (preVote : Bool) : Expr holes :=
  .and (allocatedExpr tracking source)
    (.and (roleGuard state tracking destination fun current =>
      (current.nodes destination).role = (if preVote then .preVoteCandidate else .candidate))
      (.and (.equal (firstPacketTerm state tracking source destination) (tracking.currentTerms destination))
        (.equal (firstPacketField state tracking source destination 7) (.literal 1))))

def candidateEligibilityExpr {holes : Nat} (state : Template holes) (tracking : Tracking holes)
    (node : Node) : Expr holes :=
  .and (allocatedExpr tracking node)
    (.and (.equal (tracking.localFields node 3 (localField (state.nodes node) 3)) (.literal 1))
      (.and (membershipRequirementsExpr state tracking (.timeout node))
        (.not (retiredStateExpr state tracking node))))

def proposalEffectCondition {holes : Nat} (state : Template holes) (destination : Node)
    (request : ProposeVoteRequest Node) : Prop :=
  request.destination = destination ∧ request.term = (state.nodes destination).currentTerm ∧
    candidateTransitionEnabled state destination

instance {holes : Nat} (state : Template holes) (destination : Node) (request : ProposeVoteRequest Node) :
    Decidable (proposalEffectCondition state destination request) := by
  unfold proposalEffectCondition
  infer_instance

def proposalEffectExpr {holes : Nat} (state : Template holes) (tracking : Tracking holes)
    (source destination : Node) (request : ProposeVoteRequest Node) : Expr holes :=
  .and (.boolean (decide (request.destination = destination)))
    (.and (.equal (firstPacketTerm state tracking source destination) (tracking.currentTerms destination))
      (candidateEligibilityExpr state tracking destination))

def responseAckCondition {holes : Nat} (state : Template holes) (source destination : Node)
    (response : AppendEntriesResponse Node) : Prop :=
  response.destination = destination ∧ state.allocated source ∧ response.success = true ∧
    response.term = (state.nodes destination).currentTerm ∧ (state.nodes destination).role = .leader

def responseNackCondition {holes : Nat} (state : Template holes) (source destination : Node)
    (response : AppendEntriesResponse Node) : Prop :=
  response.destination = destination ∧ state.allocated source ∧ response.success = false

instance {holes : Nat} (state : Template holes) (source destination : Node) (response : AppendEntriesResponse Node) :
    Decidable (responseAckCondition state source destination response) := by
  unfold responseAckCondition
  infer_instance

instance {holes : Nat} (state : Template holes) (source destination : Node) (response : AppendEntriesResponse Node) :
    Decidable (responseNackCondition state source destination response) := by
  unfold responseNackCondition
  infer_instance

def responseAckExpr {holes : Nat} (state : Template holes) (tracking : Tracking holes)
    (source destination : Node) (response : AppendEntriesResponse Node) : Expr holes :=
  .and (.boolean (decide (response.destination = destination)))
    (.and (allocatedExpr tracking source)
      (.and (.equal (firstPacketField state tracking source destination 6) (.literal 1))
        (.and (.equal (firstPacketTerm state tracking source destination) (tracking.currentTerms destination))
          (roleGuard state tracking destination fun current => (current.nodes destination).role = .leader))))

def responseNackExpr {holes : Nat} (state : Template holes) (tracking : Tracking holes)
    (source destination : Node) (response : AppendEntriesResponse Node) : Expr holes :=
  .and (.boolean (decide (response.destination = destination)))
    (.and (allocatedExpr tracking source)
      (.equal (firstPacketField state tracking source destination 6) (.literal 0)))

def highestPossibleValue {holes : Nat} (state : Template holes) (tracking : Tracking holes) (node : Node)
    (limit term : ReceiveTraceValues.Scalar holes) : ReceiveTraceValues.Scalar holes :=
  ReceiveTraceReplication.highestPossible (state.nodes node).log limit term
    (tracking.logLengths node) (tracking.logPositions node) (tracking.logTerms node)

def sourcePresentExpr {holes : Nat} (state : Template holes) (tracking : Tracking holes)
    (source destination : Node) : Expr holes :=
  .equal (ReceiveTraceQueue.firstValue source (fun _ => .literal 1) (.literal 0)
    (tracking.queues destination (state.network destination))) (.literal 1)

def receiveEntryAllowed {holes : Nat} (state : Template holes) (source destination : Node) : Bool :=
  ReceiveTraceGuards.allowed state source destination

def appendLogOkExpr {holes : Nat} (state : Template holes) (tracking : Tracking holes)
    (destination : Node) (request : AppendEntriesRequest Node (Value holes)) : Expr holes :=
  let packet := Message.appendEntriesRequest request
  let previous := tracking.packetFields packet 0 request.prevLogIndex
  orExpr (.equal previous (.literal 0))
    (.and (.not (.lessThan (tracking.logLengths destination) previous))
      (.equal (logTermValue state tracking destination ⟨request.prevLogIndex, previous⟩).expression
        (tracking.packetFields packet 1 request.prevLogTerm)))

open ReceiveTraceValues in
def appendFailureValues {holes : Nat} (state : Template holes) (tracking : Tracking holes)
    (destination : Node) (request : AppendEntriesRequest Node (Value holes)) : Scalar holes × Scalar holes :=
  let packet := Message.appendEntriesRequest request
  let current : Scalar holes := ⟨(state.nodes destination).currentTerm, tracking.currentTerms destination⟩
  let length : Scalar holes := ⟨(state.nodes destination).log.length, tracking.logLengths destination⟩
  let previous : Scalar holes := ⟨request.prevLogIndex, tracking.packetFields packet 0 request.prevLogIndex⟩
  let offered : Scalar holes := ⟨request.term, tracking.packetTerms packet⟩
  let previousTerm := choose (equal previous (literal 0)) (literal 0)
    (choose (less length previous) (literal 0) (logTermValue state tracking destination length))
  let ordinary := orCondition (less offered current) (equal previousTerm (literal 0))
  let possible := highestPossibleValue state tracking destination previous
    ⟨request.prevLogTerm, tracking.packetFields packet 1 request.prevLogTerm⟩
  (choose ordinary current
    (choose (equal possible (literal 0)) (literal TERM_ONE)
      (logTermValue state tracking destination possible)),
   choose ordinary length possible)

def appendRejected {holes : Nat} (state : Template holes) (destination : Node)
    (request : AppendEntriesRequest Node (Value holes)) : Prop :=
  request.term < (state.nodes destination).currentTerm ∨
    (request.term = (state.nodes destination).currentTerm ∧
      (state.nodes destination).role = .follower ∧ ¬ logOk (state.nodes destination) request)

instance {holes : Nat} (state : Template holes) (destination : Node)
    (request : AppendEntriesRequest Node (Value holes)) : Decidable (appendRejected state destination request) := by
  unfold appendRejected
  infer_instance

def appendRejectedExpr {holes : Nat} (state : Template holes) (tracking : Tracking holes)
    (destination : Node) (request : AppendEntriesRequest Node (Value holes)) : Expr holes :=
  let term := tracking.packetTerms (.appendEntriesRequest request)
  let current := tracking.currentTerms destination
  orExpr (.lessThan term current)
    (.and (.equal term current)
      (.and (roleGuard state tracking destination fun current => (current.nodes destination).role = .follower)
        (.not (appendLogOkExpr state tracking destination request))))

def appendAlreadyExpr {holes : Nat} (state : Template holes) (tracking : Tracking holes)
    (destination : Node) (request : AppendEntriesRequest Node (Value holes)) : Expr holes :=
  let packet := Message.appendEntriesRequest request
  let previous := tracking.packetFields packet 0 request.prevLogIndex
  let count := tracking.packetFields packet 5 request.entries.length
  orExpr (.equal count (.literal 0))
    (.and (.not (.lessThan (tracking.logLengths destination) (.add previous count)))
      (.and (.equal (minValue (.sub (tracking.logLengths destination) previous) count) count)
        (ReceiveTracePackets.termsEqual
          (fun offset => indexedLogTerm state tracking destination
            ⟨request.prevLogIndex + offset, .add previous (.literal offset)⟩)
          (fun offset => tracking.packetFields packet (6 + offset)) 1
          (((state.nodes destination).log.drop request.prevLogIndex).take request.entries.length) request.entries)))

def appendConflictExpr {holes : Nat} (state : Template holes) (tracking : Tracking holes)
    (destination : Node) (request : AppendEntriesRequest Node (Value holes)) : Expr holes :=
  let packet := Message.appendEntriesRequest request
  let previous := tracking.packetFields packet 0 request.prevLogIndex
  let count := tracking.packetFields packet 5 request.entries.length
  let suffix := NatTerm.sub (tracking.logLengths destination) previous
  let overlap := minValue count suffix
  .and (.not (.equal count (.literal 0)))
    (.not (.and (.equal (minValue suffix overlap) (minValue count overlap))
      (ReceiveTracePackets.termsEqual
        (fun offset => indexedLogTerm state tracking destination
          ⟨request.prevLogIndex + offset, .add previous (.literal offset)⟩)
        (fun offset => tracking.packetFields packet (6 + offset)) 1
        (((state.nodes destination).log.drop request.prevLogIndex).take (overlapLength (state.nodes destination) request))
        (request.entries.take (overlapLength (state.nodes destination) request)))))

def appendProgressExpr {holes : Nat} (state : Template holes) (tracking : Tracking holes)
    (destination : Node) (request : AppendEntriesRequest Node (Value holes)) : Expr holes :=
  let packet := Message.appendEntriesRequest request
  let previous := tracking.packetFields packet 0 request.prevLogIndex
  let count := tracking.packetFields packet 5 request.entries.length
  orExpr (appendAlreadyExpr state tracking destination request)
    (orExpr (.and (.not (.equal count (.literal 0)))
        (.and (.not (.lessThan (tracking.logLengths destination) previous))
          (.and (.lessThan (tracking.logLengths destination) (.add previous count))
            (.not (appendConflictExpr state tracking destination request)))))
      (.and (appendConflictExpr state tracking destination request)
        (.equal (tracking.localFields destination 0 (localField (state.nodes destination) 0)) (.literal 1))))

def receiveHeaderExpr {holes : Nat} (state : Template holes) (tracking : Tracking holes)
    (destination : Node) (message : Message Node (Value holes)) : Expr holes :=
  let current := tracking.currentTerms destination
  let term := tracking.packetTerms message
  .and (.boolean (decide (message.destination = destination)))
    (match message with
    | .appendEntriesRequest request =>
        orExpr (.lessThan term current)
          (.and (.equal term current)
            (orExpr (roleGuard state tracking destination fun current =>
                (current.nodes destination).role = .candidate ∨
                  (current.nodes destination).role = .preVoteCandidate)
              (.and (roleGuard state tracking destination fun current => (current.nodes destination).role = .follower)
                (orExpr (.not (appendLogOkExpr state tracking destination request))
                  (.and (.not (.lessThan (tracking.packetFields message 0 request.prevLogIndex)
                    (tracking.commitIndices destination (state.nodes destination).commitIndex)))
                    (appendProgressExpr state tracking destination request))))))
    | .appendEntriesResponse response =>
        orExpr (.not (allocatedExpr tracking response.source))
          (orExpr (.equal (tracking.packetFields message 6 (if response.success then 1 else 0)) (.literal 0))
            (orExpr (roleGuard state tracking destination fun current => (current.nodes destination).role ≠ .leader)
              (.not (.lessThan current term))))

    | .requestVoteRequest _ | .requestPreVote _ | .proposeVoteRequest _ =>
        .not (.lessThan current term)
    | .requestVoteResponse response =>
        orExpr (.not (allocatedExpr tracking response.source))
          (orExpr (roleGuard state tracking destination fun current => (current.nodes destination).role ≠ .candidate)
            (.not (.lessThan current term)))
    | .requestPreVoteResponse response =>
        orExpr (.not (allocatedExpr tracking response.source))
          (orExpr (roleGuard state tracking destination fun current => (current.nodes destination).role ≠ .preVoteCandidate)
            (.not (.lessThan current term))))

def appendPrefixExpr {holes : Nat} (state : Template holes) (tracking : Tracking holes)
    (destination : Node) (request : AppendEntriesRequest Node (Value holes)) : Expr holes :=
  let packet := Message.appendEntriesRequest request
  let suffix := NatTerm.sub (tracking.logLengths destination) (tracking.packetFields packet 0 request.prevLogIndex)
  let count := tracking.packetFields packet 5 request.entries.length
  .and (.equal suffix (minValue count suffix))
    (ReceiveTraceBranching.prefixExpr suffix (fun index => .literal index)
      (fun offset => indexedLogTerm state tracking destination
        ⟨request.prevLogIndex + offset,
          .add (tracking.packetFields packet 0 request.prevLogIndex) (.literal offset)⟩)
      (fun offset => tracking.packetFields packet (6 + offset)) 1
      (((state.nodes destination).log.drop request.prevLogIndex).take
        ((state.nodes destination).log.length - request.prevLogIndex))
      (request.entries.take ((state.nodes destination).log.length - request.prevLogIndex)))

def receiveEntryExpr {holes : Nat} (state : Template holes) (tracking : Tracking holes)
    (source destination : Node) : Expr holes :=
  .and (allocatedExpr tracking destination)
    (.equal (ReceiveTraceQueue.firstValue source
      (fun packet => (receiveHeaderExpr state tracking destination packet).ite (.literal 1) (.literal 0))
      (.literal 0) (tracking.queues destination (state.network destination))) (.literal 1))

def newerMessageExpr {holes : Nat}
    (state : Template holes) (tracking : Tracking holes) (source destination : Node) : Expr holes :=
  match takeFirstFrom source (state.network destination) with
  | none => sourcePresentExpr state tracking source destination
  | some (message, _) =>
      .and (sourcePresentExpr state tracking source destination)
        (.and (sourceAllowedExpr tracking message)
          (.lessThan (tracking.currentTerms destination) (firstPacketTerm state tracking source destination)))

def actionRequirements {holes : Nat}
    (state : Template holes) (action : Action Node (Value holes)) : Prop :=
  (∀ node ∈ allocationNodes action, state.allocated node) ∧
    match action with
    | .signCommittableMessages node => (state.nodes node).log ≠ []
    | .becomeLeader node => hasElectionMajority state node
    | .becomeCandidate node => hasPreVoteMajority state node
    | .appendRetiredCommitted node => (pendingRetiredCommittedNodes state node).Nonempty
    | .updateTerm source destination => (newerMessage? state source destination).isSome
    | .advanceCommitIndex node | .advanceCommitIndexAndProposeVote node _ =>
        (state.nodes node).commitIndex < highestCommittableIndex state node
    | .appendEntries source destination batchEnd =>
        batchEnd = min ((state.nodes source).sentIndex destination + 1)
          (state.nodes source).log.length ∧
        ((state.nodes source).membershipState ≠ .retiredCommitted ∨
          (state.nodes source).sentIndex destination < batchEnd)
    | .changeConfiguration source configuration =>
        configuration ≠ (latestConfiguration (state.nodes source)).nodes ∧
          ∀ node ∈ configuration \ (latestConfiguration (state.nodes source)).nodes,
            node ∉ state.hasJoined
    | _ => True

instance {holes : Nat} (state : Template holes) (action : Action Node (Value holes)) :
    Decidable (actionRequirements state action) := by
  unfold actionRequirements
  cases action <;> infer_instance

def actionRequirementsExpr {holes : Nat}
    (state : Template holes) (tracking : Tracking holes) (action : Action Node (Value holes)) :
    Expr holes :=
  .and (allExpr ((allocationNodes action).map (allocatedExpr tracking)))
    (match action with
    | .signCommittableMessages node => .lessThan (.literal 0) (tracking.logLengths node)
    | .becomeLeader node => voteMajorityExpr state tracking node false
    | .becomeCandidate node => voteMajorityExpr state tracking node true
    | .appendRetiredCommitted node => pendingRetirementExpr state tracking node
    | .updateTerm source destination => newerMessageExpr state tracking source destination
    | .advanceCommitIndex node | .advanceCommitIndexAndProposeVote node _ =>
        committableExpr state tracking node
    | .appendEntries source destination batchEnd =>
        .and (.equal (.literal batchEnd)
          (minValue (.add (tracking.sentIndex source destination) (.literal 1))
            (tracking.logLengths source)))
          (orExpr (.not (retiredStateExpr state tracking source))
            (.lessThan (tracking.sentIndex source destination) (.literal batchEnd)))
    | .changeConfiguration source configuration =>
        .and (.equal (latestConfigurationValue state tracking source
            (fun previous => decide (configuration = previous.nodes))) (.literal 0))
          (allExpr ((configuration.sort (· ≤ ·)).map fun node =>
            orExpr (.equal (latestConfigurationValue state tracking source
                (fun previous => decide (node ∈ previous.nodes))) (.literal 1))
              (.equal (tracking.joined node) (.literal 0))))
    | _ => .boolean true)

def actionGuard {holes : Nat}
    (state : Template holes) (tracking : Tracking holes) (action : Action Node (Value holes)) :
    Expr holes :=
  .and (.and (actionRequirementsExpr state tracking action)
    (.and (membershipRequirementsExpr state tracking action) (retirementRequirementsExpr state tracking action)))
    (roleGuard state tracking (actionRoleNode action)
      (fun current =>
        actionRequirements current action ∧ membershipRequirements current action ∧ retirementRequirements current action →
          Enabled current action))

def constantClause {holes : Nat} (label : String) (condition : Prop)
    [Decidable condition] : Clause holes :=
  { label, expression := .boolean (decide condition) }

def lessClause {holes : Nat}
    (label : String) (value : Value holes) (bound : Nat) : Clause holes :=
  { label, expression := .lessThan value (.literal bound) }

def atMostClause {holes : Nat}
    (label : String) (value : Value holes) (bound : Nat) : Clause holes :=
  { label, expression := .not (.lessThan (.literal bound) value) }

def fresh {holes : Nat}
    (transaction : Value holes) (prior : List (Value holes)) : Expr holes :=
  prior.foldr
    (fun previous rest => .and (.not (.equal transaction previous)) rest)
    (.boolean true)

def submittedTerms {holes : Nat}
    (state : Template holes) : List (Value holes) :=
  state.submittedTxIds.sort (· ≤ ·)

def entryBoundsClauses {holes : Nat}
    (bounds : Bounds) (entry : Entry Node (Value holes))
    (term : Value holes := .literal entry.term) : List (Clause holes) :=
  lessClause "entry term domain" term bounds.termCount ::
    match entry.content with
    | .transaction transaction =>
        [lessClause "entry transaction domain" transaction bounds.transactionCount]
    | .signature | .reconfiguration _ | .retiredCommitted _ => []

def logBoundsClauses {holes : Nat}
    (bounds : Bounds) (terms : Nat -> Nat -> Value holes) :
    Nat -> List (Entry Node (Value holes)) -> List (Clause holes)
  | _, [] => []
  | index, entry :: rest =>
      entryBoundsClauses bounds entry (terms index entry.term) ++
        logBoundsClauses bounds terms (index + 1) rest

def messageBoundsClauses {holes : Nat}
    (bounds : Bounds) (packetTerms : Message Node (Value holes) -> Value holes)
    (packetFields : Message Node (Value holes) -> Nat -> Nat -> Value holes) :
    Message Node (Value holes) -> List (Clause holes)
  | .appendEntriesRequest request =>
      [lessClause "message term domain"
         (packetTerms (.appendEntriesRequest request)) bounds.termCount,
       lessClause "previous log index domain"
         (packetFields (.appendEntriesRequest request) 0 request.prevLogIndex) bounds.indexCount,
       lessClause "previous log term domain"
         (packetFields (.appendEntriesRequest request) 1 request.prevLogTerm) bounds.termCount,
       atMostClause "AppendEntries entry capacity"
         (packetFields (.appendEntriesRequest request) 5 request.entries.length) bounds.logCapacity,
       lessClause "leader commit domain"
         (packetFields (.appendEntriesRequest request) 2 request.leaderCommit) bounds.indexCount] ++
        logBoundsClauses bounds
          (fun index => packetFields (.appendEntriesRequest request) (6 + index)) 1 request.entries
  | .appendEntriesResponse response =>
      [lessClause "message term domain"
         (packetTerms (.appendEntriesResponse response)) bounds.termCount,
       lessClause "last log index domain"
         (packetFields (.appendEntriesResponse response) 3 response.lastLogIndex) bounds.indexCount]
  | .requestVoteRequest request =>
      [lessClause "message term domain"
         (packetTerms (.requestVoteRequest request)) bounds.termCount,
       lessClause "last committable term domain"
         (packetFields (.requestVoteRequest request) 4 request.lastCommittableTerm) bounds.termCount,
       lessClause "last committable index domain"
         (packetFields (.requestVoteRequest request) 3 request.lastCommittableIndex) bounds.indexCount]
  | .requestVoteResponse response =>
      [lessClause "message term domain"
         (packetTerms (.requestVoteResponse response)) bounds.termCount]
  | .requestPreVote request =>
      [lessClause "message term domain"
         (packetTerms (.requestPreVote request)) bounds.termCount,
       lessClause "last committable term domain"
         (packetFields (.requestPreVote request) 4 request.lastCommittableTerm) bounds.termCount,
       lessClause "last committable index domain"
         (packetFields (.requestPreVote request) 3 request.lastCommittableIndex) bounds.indexCount]
  | .requestPreVoteResponse response =>
      [lessClause "message term domain"
         (packetTerms (.requestPreVoteResponse response)) bounds.termCount]
  | .proposeVoteRequest request =>
      [lessClause "message term domain"
         (packetTerms (.proposeVoteRequest request)) bounds.termCount]

def optionalIndexClauses {holes : Nat}
    (bounds : Bounds)
    (positions : Nat -> Value holes)
    (writer : Option (Nat × Nat))
    (slot : Nat)
    (label : String) :
    Option Nat -> List (Clause holes)
  | none => []
  | some index =>
      let value : Value holes :=
        match writer with
        | none => .literal index
        | some (group, pathId) =>
            .named group (pathSlot pathId slot) label (positions index)
      [lessClause s!"{label} domain" value bounds.indexCount]

def localBoundsClauses {holes : Nat}
    (bounds : Bounds)
    (tracking : Tracking holes)
    (node : Node)
    (state : NodeState Node (Value holes)) :
    List (Clause holes) :=
  [lessClause "current term domain" (tracking.currentTerms node) bounds.termCount,
   atMostClause "log capacity" (tracking.logLengths node) bounds.logCapacity,
   lessClause "commit index domain"
     (tracking.commitIndices node state.commitIndex) bounds.indexCount] ++
  logBoundsClauses bounds (tracking.logTerms node) 1 state.log ++
  ((List.finRange NODE_COUNT).flatMap fun peer =>
    [lessClause "sent index domain"
       (tracking.sentIndex node peer) bounds.indexCount,
     lessClause "match index domain"
       (tracking.matchIndices node peer (state.matchIndex peer))
       bounds.indexCount]) ++
  optionalIndexClauses bounds (tracking.logPositions node) (tracking.retirementWriters node) 2
      "retirement index" state.retirementIndex ++
  optionalIndexClauses bounds (tracking.logPositions node) (tracking.retirementWriters node) 3
      "retirement committable index" state.retirementCommittableIndex ++
  optionalIndexClauses bounds (tracking.logPositions node) (tracking.retirementWriters node) 4
      "retired committed index" state.retiredCommittedIndex

def nodeBoundsClauses {holes : Nat}
    (bounds : Bounds)
    (state : Template holes)
    (tracking : Tracking holes)
    (node : Node) :
    List (Clause holes) :=
  match state.node? node with
  | none => []
  | some localState =>
      localBoundsClauses bounds tracking node localState

def queueBoundsClauses {holes : Nat}
    (bounds : Bounds)
    (state : Template holes)
    (tracking : Tracking holes)
    (node : Node) :
    List (Clause holes) :=
  atMostClause "queue capacity"
      (tracking.queueLengths node) bounds.queueCapacity ::
    (state.network node).flatMap (messageBoundsClauses bounds tracking.packetTerms tracking.packetFields)

def stateBoundsClauses {holes : Nat}
    (bounds : Bounds)
    (state : Template holes)
    (tracking : Tracking holes) :
    List (Clause holes) :=
  (List.finRange NODE_COUNT).flatMap
      (nodeBoundsClauses bounds state tracking) ++
  (List.finRange NODE_COUNT).flatMap
      (queueBoundsClauses bounds state tracking) ++
  (submittedTerms state).map fun transaction =>
    lessClause "submitted transaction domain" transaction bounds.transactionCount

def observationExpression {holes : Nat}
    (assignmentState : Template holes)
    (tracking : Tracking holes) :
    TraceInstructions.Observation holes -> Expr holes
  | .role node value =>
      .equal
        (tracking.localFields node 2 (roleCode (assignmentState.nodes node).role))
        (.literal (roleCode value))
  | .currentTerm node value =>
      .equal (tracking.currentTerms node) (.literal value)
  | .logLength node value =>
      .equal (tracking.logLengths node) (.literal value)
  | .queueLength node value =>
      .equal (tracking.queueLengths node) (.literal value)
  | .commitIndex node value =>
      .equal
        (tracking.commitIndices node (assignmentState.nodes node).commitIndex)
        (.literal value)
  | .allocated node value =>
      .equal (tracking.allocated node) (boolValue value)
  | .joined node value =>
      .equal (tracking.joined node) (boolValue value)
  | .submitted transaction value =>
      if value then
        .not (fresh transaction (submittedTerms assignmentState))
      else
        fresh transaction (submittedTerms assignmentState)

def observationClauses {holes : Nat}
    (bounds : Bounds)
    (state : Template holes)
    (tracking : Tracking holes)
    (observation : TraceInstructions.Observation holes) :
    List (Clause holes) :=
  let observed : Clause holes :=
    { label := "observed value"
      expression := observationExpression state tracking observation }
  match observation with
  | .submitted transaction _ =>
      [lessClause "observed transaction domain"
        transaction bounds.transactionCount, observed]
  | _ => [observed]

def observationGroup {holes : Nat}
    (bounds : Bounds)
    (state : Template holes)
    (tracking : Tracking holes)
    (observation : TraceInstructions.Observation holes) :
    Group holes :=
  { label := "observation"
    clauses :=
      stateBoundsClauses bounds state tracking ++
        observationClauses bounds state tracking observation }

def clientRequestGroup {holes : Nat}
    (bounds : Bounds)
    (state : Template holes)
    (tracking : Tracking holes)
    (node : Node)
    (transaction : Value holes) :
    Group holes :=
  { label := "clientRequest"
    clauses :=
      stateBoundsClauses bounds state tracking ++
      [{ label := "structural clientRequest guard"
         expression := structuralClientExpr state tracking node transaction },
       lessClause "transaction domain" transaction bounds.transactionCount,
       { label := "transaction freshness"
         expression := fresh transaction (submittedTerms state) }] }

def leaderWriteGroup {holes : Nat}
    (label : String)
    (bounds : Bounds)
    (state : Template holes)
    (tracking : Tracking holes)
    (action : Action Node (Value holes)) :
    Group holes :=
  { label
    clauses :=
      stateBoundsClauses bounds state tracking ++
        [{ label := s!"structural {label} guard"
           expression := actionGuard state tracking action }] }

def initialTracking {holes : Nat} (state : Template holes) : Tracking holes where
  logLengths := fun node => .literal (state.nodes node).log.length
  retirementWriters := fun _ => none
  allocated := fun node => boolValue (decide (state.allocated node))
  joined := fun node => boolValue (decide (node ∈ state.hasJoined))
  sentIndex := fun node peer => .literal ((state.nodes node).sentIndex peer)
  queueLengths := fun node => .literal (state.network node).length
  currentTerms := fun node => .literal (state.nodes node).currentTerm
  packetTerms := fun message => .literal message.term
  logPositions := fun _ index => .literal index
  commitIndices := fun _ index => .literal index
  logTerms := fun _ _ term => .literal term
  packetFields := fun _ _ value => .literal value
  voteMembers := fun _ _ _ value => boolValue value
  configurations := fun _ values => ControlTraceConfigurations.literals values
  completedMembers := fun _ _ value => boolValue value
  queues := fun _ values => ReceiveTraceQueue.literals values
  matchIndices := fun _ _ value => .literal value
  localFields := fun _ _ value => .literal value
  packetPositions := fun _ _ value => .literal value

def controlVoteMembers {holes : Nat}
    (position pathId : Nat) (state : Template holes) (tracking : Tracking holes) :
    Action Node (Value holes) -> Node -> Bool -> Node -> Bool -> Value holes
  | .timeout node | .becomeCandidate node =>
      Function.update tracking.voteMembers node (fun preVote peer value =>
        let expected := !preVote && decide (peer = node)
        if value = expected then
          .named position
            (pathSlot pathId (markerSlot (if preVote then PRE_VOTE_SLOT_BASE else VOTE_SLOT_BASE) peer))
            (if preVote then "pre-vote membership" else "vote membership") (boolValue expected)
        else boolValue value)
  | .becomePreVoteCandidate node =>
      Function.update tracking.voteMembers node (fun preVote peer value =>
        if preVote then
          let expected := decide (peer = node)
          if value = expected then
            .named position (pathSlot pathId (markerSlot PRE_VOTE_SLOT_BASE peer))
              "pre-vote membership" (boolValue expected)
          else boolValue value
        else tracking.voteMembers node preVote peer value)
  | .updateTerm source destination =>
      if (newerMessage? state source destination).isSome then
        Function.update tracking.voteMembers destination (fun preVote peer value =>
          if preVote && !value then
            .named position (pathSlot pathId (markerSlot PRE_VOTE_SLOT_BASE peer))
              "pre-vote membership" (.literal 0)
          else tracking.voteMembers destination preVote peer value)
      else tracking.voteMembers
  | _ => tracking.voteMembers

def rememberPacketFields {holes : Nat}
    (state : Template holes) (tracking : Tracking holes)
    (message : Message Node (Value holes)) (fields : Nat -> Nat -> Value holes) :
    Message Node (Value holes) -> Nat -> Nat -> Value holes :=
  if message ∈ state.network message.destination then tracking.packetFields
  else Function.update tracking.packetFields message fields

def controlPacketFields {holes : Nat}
    (position pathId : Nat) (state : Template holes) (tracking : Tracking holes) :
    Action Node (Value holes) -> Message Node (Value holes) -> Nat -> Nat -> Value holes
  | .requestVote source destination =>
      rememberPacketFields state tracking
        (.requestVoteRequest (makeRequestVoteRequest state source destination))
        (votePacketFields position pathId state tracking source)
  | .requestPreVote source destination =>
      rememberPacketFields state tracking
        (.requestPreVote (makeRequestPreVote state source destination))
        (votePacketFields position pathId state tracking source)
  | _ => tracking.packetFields

def rememberPacketTerm {holes : Nat}
    (position pathId : Nat) (state : Template holes) (tracking : Tracking holes)
    (source : Node) (message : Message Node (Value holes)) :
    Message Node (Value holes) -> Value holes :=
  if message ∈ state.network message.destination then tracking.packetTerms
  else Function.update tracking.packetTerms message
    (.named position (pathSlot pathId PACKET_TERM_SLOT) "message term"
      (tracking.currentTerms source))

def controlPacketTerms {holes : Nat}
    (position pathId : Nat) (state : Template holes) (tracking : Tracking holes) :
    Action Node (Value holes) -> Message Node (Value holes) -> Value holes
  | .requestVote source destination =>
      rememberPacketTerm position pathId state tracking source
        (.requestVoteRequest (makeRequestVoteRequest state source destination))
  | .requestPreVote source destination =>
      rememberPacketTerm position pathId state tracking source
        (.requestPreVote (makeRequestPreVote state source destination))
  | .proposeVote source destination
  | .advanceCommitIndexAndProposeVote source destination =>
      rememberPacketTerm position pathId state tracking source
        (.proposeVoteRequest (makeProposeVoteRequest state source destination))
  | _ => tracking.packetTerms

def nextLogLengths {holes : Nat}
    (position : Nat)
    (pathId : Nat)
    (logLengths : Node -> Value holes)
    (node : Node) :
    Node -> Value holes :=
  Function.update logLengths node
    (.named position (pathSlot pathId 1) "next log length"
      (.add (logLengths node) (.literal 1)))

def nextRetirementWriters
    (position : Nat)
    (pathId : Nat)
    (retirementWriters : Node -> Option (Nat × Nat))
    (node : Node) :
    Node -> Option (Nat × Nat) :=
  Function.update retirementWriters node (some (position, pathId))

def nextWriteTracking {holes : Nat}
    (position pathId : Nat) (tracking : Tracking holes) (node : Node)
    (priorLength currentTerm : Nat) :
    Tracking holes :=
  { tracking with
    logLengths := nextLogLengths position pathId tracking.logLengths node
    retirementWriters :=
      nextRetirementWriters position pathId tracking.retirementWriters node
    logPositions := Function.update tracking.logPositions node
      (Function.update (tracking.logPositions node) (priorLength + 1)
        ((nextLogLengths position pathId tracking.logLengths node) node))
    logTerms := Function.update tracking.logTerms node
      (Function.update (tracking.logTerms node) (priorLength + 1)
        (Function.update (fun term => .literal term) currentTerm
          (.named position (pathSlot pathId LOG_TERM_SLOT) "entry term"
            (tracking.currentTerms node)))) }

def nextConfigurationTracking {holes : Nat}
    (position : Nat)
    (pathId : Nat)
    (state : Template holes)
    (tracking : Tracking holes)
    (source : Node)
    (configuration : Finset Node) :
    Tracking holes :=
  let allocated := fun node =>
    .named position
      (pathSlot pathId (markerSlot ALLOCATED_SLOT_BASE node))
      s!"allocated node {node.val}"
      (if node = source then .literal 1 else
        maxValue (tracking.allocated node)
          (addedConfigurationMemberValue state tracking source configuration node))
  let joined := fun node =>
    .named position
      (pathSlot pathId (markerSlot JOINED_SLOT_BASE node))
      s!"joined node {node.val}"
      (maxValue (tracking.joined node)
        (addedConfigurationMemberValue state tracking source configuration node))
  let sentIndex := fun node peer =>
    if node = source then
      .named position
        (pathSlot pathId (markerSlot SENT_INDEX_SLOT_BASE peer))
        s!"sent index {peer.val}"
        ((Expr.equal (addedConfigurationMemberValue state tracking source configuration peer) (.literal 1)).ite
          (tracking.logLengths source) (tracking.sentIndex source peer))
    else
      tracking.sentIndex node peer
  let oldLog := (state.nodes source).log
  let newEntry : Entry Node (Value holes) :=
    { term := (state.nodes source).currentTerm, content := .reconfiguration configuration }
  let configurations :=
    Function.update tracking.configurations source
      (Function.update (tracking.configurations source) (allConfigurations (oldLog ++ [newEntry]))
        (ControlTraceConfigurations.append
          (tracking.configurations source (allConfigurations oldLog))
          { index := oldLog.length + 1, nodes := configuration }
          ((nextLogLengths position pathId tracking.logLengths source) source)
          position (pathSlot pathId CONFIGURATION_SLOT)))
  { tracking with
    logLengths := nextLogLengths position pathId tracking.logLengths source
    retirementWriters :=
      nextRetirementWriters position pathId tracking.retirementWriters source
    allocated
    joined
    sentIndex
    queueLengths := tracking.queueLengths
    configurations
    logPositions := (nextWriteTracking position pathId tracking source
      (state.nodes source).log.length (state.nodes source).currentTerm).logPositions
    logTerms := (nextWriteTracking position pathId tracking source
      (state.nodes source).log.length (state.nodes source).currentTerm).logTerms }

def nextControlTracking {holes : Nat}
    (position pathId : Nat) (before after : Template holes)
    (tracking : Tracking holes) : Tracking holes :=
  { logLengths := fun node =>
      if (before.nodes node).log.length = (after.nodes node).log.length then
        tracking.logLengths node
      else
        .named position (pathSlot pathId 1) "next log length"
          (if (before.nodes node).log.length ≤ (after.nodes node).log.length then
            .add (tracking.logLengths node)
              (.literal ((after.nodes node).log.length - (before.nodes node).log.length))
           else
            .sub (tracking.logLengths node)
              (.literal ((before.nodes node).log.length - (after.nodes node).log.length)))
    retirementWriters := fun node =>
      if (before.nodes node).retirementIndex = (after.nodes node).retirementIndex ∧
          (before.nodes node).retirementCommittableIndex =
            (after.nodes node).retirementCommittableIndex ∧
          (before.nodes node).retiredCommittedIndex = (after.nodes node).retiredCommittedIndex
      then tracking.retirementWriters node
      else some (position, pathId)
    allocated := fun node =>
      if decide (before.allocated node) = decide (after.allocated node) then
        tracking.allocated node
      else
        .named position (pathSlot pathId (markerSlot ALLOCATED_SLOT_BASE node))
          s!"allocated node {node.val}" (boolValue (decide (after.allocated node)))
    joined := fun node =>
      if decide (node ∈ before.hasJoined) = decide (node ∈ after.hasJoined) then
        tracking.joined node
      else
        .named position (pathSlot pathId (markerSlot JOINED_SLOT_BASE node))
          s!"joined node {node.val}" (boolValue (decide (node ∈ after.hasJoined)))
    sentIndex := fun node peer =>
      if (before.nodes node).sentIndex peer = (after.nodes node).sentIndex peer then
        tracking.sentIndex node peer
      else
        .named position
          (pathSlot pathId (markerSlot SENT_INDEX_SLOT_BASE peer))
          s!"sent index {peer.val}" (.literal ((after.nodes node).sentIndex peer))
    queueLengths := fun node =>
      if (before.network node).length = (after.network node).length then
        tracking.queueLengths node
      else
        .named position (pathSlot pathId (markerSlot QUEUE_LENGTH_SLOT_BASE node))
          s!"queue length {node.val}"
          (if (before.network node).length ≤ (after.network node).length then
            .add (tracking.queueLengths node)
              (.literal ((after.network node).length - (before.network node).length))
           else
            .sub (tracking.queueLengths node)
              (.literal ((before.network node).length - (after.network node).length)))
    controlWriters := fun node slot =>
      if (slot = markerSlot ROLE_SLOT_BASE node ∧
            (before.nodes node).role ≠ (after.nodes node).role) ∨
          (slot = markerSlot COMMIT_SLOT_BASE node ∧
            (before.nodes node).commitIndex ≠ (after.nodes node).commitIndex) ∨
          (∃ peer : Node, slot = MATCH_SLOT_BASE + node.val * NODE_COUNT + peer.val ∧
            (before.nodes node).matchIndex peer ≠ (after.nodes node).matchIndex peer)
      then some (position, pathId)
      else tracking.controlWriters node slot
    currentTerms := fun node =>
      if (before.nodes node).currentTerm = (after.nodes node).currentTerm then
        tracking.currentTerms node
      else
        .named position (pathSlot pathId (markerSlot TERM_SLOT_BASE node))
          "current term"
          (if (before.nodes node).currentTerm ≤ (after.nodes node).currentTerm then
            .add (tracking.currentTerms node)
              (.literal ((after.nodes node).currentTerm - (before.nodes node).currentTerm))
           else
            .sub (tracking.currentTerms node)
              (.literal ((before.nodes node).currentTerm - (after.nodes node).currentTerm)))
    packetTerms := tracking.packetTerms
    logPositions := tracking.logPositions
    commitIndices := tracking.commitIndices
    logTerms := tracking.logTerms
    packetFields := tracking.packetFields
    voteMembers := tracking.voteMembers
    configurations := tracking.configurations
    completedMembers := tracking.completedMembers
    queues := tracking.queues
    matchIndices := fun node peer value =>
      if value = (after.nodes node).matchIndex peer ∧ value ≠ (before.nodes node).matchIndex peer then
        .named position (pathSlot pathId (MATCH_SLOT_BASE + node.val * NODE_COUNT + peer.val))
          s!"match index {peer.val}" (.literal value)
      else tracking.matchIndices node peer value
    localFields := fun node field value =>
      if field < 4 ∧ value = localField (after.nodes node) field ∧ value ≠ localField (before.nodes node) field then
        .named position (pathSlot pathId (LOCAL_FIELD_SLOT_BASE + field * NODE_COUNT + node.val))
          (match field with | 0 => "new follower" | 1 => "voted for" | 2 => "role" | _ => "campaign role")
          (.literal value)
      else tracking.localFields node field value
    packetPositions := tracking.packetPositions }

def controlQueueLength {holes : Nat}
    (position pathId : Nat) (state : Template holes) (tracking : Tracking holes)
    (source : Node) (message : Message Node (Value holes)) (fields : Nat -> Nat -> Value holes) : Value holes :=
  .add (tracking.queueLengths message.destination)
    (.named position (pathSlot pathId (markerSlot QUEUE_LENGTH_SLOT_BASE message.destination))
      s!"queue growth {message.destination.val}" (.literal 1))

def controlQueueLengths {holes : Nat}
    (position pathId : Nat) (state : Template holes) (tracking : Tracking holes)
    (action : Action Node (Value holes)) : Node -> Value holes :=
  match action with
  | .requestVote source destination =>
      Function.update tracking.queueLengths destination
        (controlQueueLength position pathId state tracking source
          (.requestVoteRequest (makeRequestVoteRequest state source destination))
          (votePacketFields position pathId state tracking source))
  | .requestPreVote source destination =>
      Function.update tracking.queueLengths destination
        (controlQueueLength position pathId state tracking source
          (.requestPreVote (makeRequestPreVote state source destination))
          (votePacketFields position pathId state tracking source))
  | .proposeVote source destination | .advanceCommitIndexAndProposeVote source destination =>
      Function.update tracking.queueLengths destination
        (controlQueueLength position pathId state tracking source
          (.proposeVoteRequest (makeProposeVoteRequest state source destination))
          (fun _ value => .literal value))
  | _ => (nextControlTracking position pathId state (next state action) tracking).queueLengths

def controlCommitIndices {holes : Nat}
    (position pathId : Nat) (state : Template holes) (tracking : Tracking holes) :
    Action Node (Value holes) -> Node -> Nat -> Value holes
  | .advanceCommitIndex node | .advanceCommitIndexAndProposeVote node _ =>
      let frontier := highestCommittableIndex state node
      Function.update tracking.commitIndices node
        (Function.update (tracking.commitIndices node) frontier
          (.named position (pathSlot pathId (markerSlot COMMIT_SLOT_BASE node))
            "commit index" (highestCommittableValue state tracking node)))
  | _ => tracking.commitIndices

def controlLogLengths {holes : Nat}
    (position pathId : Nat) (state : Template holes) (tracking : Tracking holes)
    (action : Action Node (Value holes)) : Node -> Value holes :=
  match action with
  | .becomeLeader node =>
      let length := tracking.logLengths node
      let frontier := tracking.logPositions node (maxCommittableIndex (state.nodes node).log)
      Function.update tracking.logLengths node
        (.named position (pathSlot pathId 1) "next log length"
          (.sub length (.sub length frontier)))
  | _ => (nextControlTracking position pathId state (next state action) tracking).logLengths

def controlSentIndices {holes : Nat}
    (position pathId : Nat) (state : Template holes) (tracking : Tracking holes)
    (action : Action Node (Value holes)) : Node -> Node -> Value holes :=
  match action with
  | .becomeLeader node =>
      Function.update tracking.sentIndex node (fun peer =>
        .named position (pathSlot pathId (markerSlot SENT_INDEX_SLOT_BASE peer))
          s!"sent index {peer.val}" (controlLogLengths position pathId state tracking action node))
  | _ => (nextControlTracking position pathId state (next state action) tracking).sentIndex

def controlLogTerms {holes : Nat}
    (position pathId : Nat) (state : Template holes) (tracking : Tracking holes) :
    Action Node (Value holes) -> Node -> Nat -> Nat -> Value holes
  | .becomeLeader node =>
      let log := (state.nodes node).log
      let frontier := maxCommittableIndex log
      Function.update tracking.logTerms node (fun index term =>
        if term = termAt (log.take frontier) index ∧ termAt log index ≠ term then
          .named position (pathSlot (Nat.pair pathId index) LOG_TERM_SLOT) "truncated log term"
            ((Expr.lessThan (tracking.logPositions node frontier) (tracking.logPositions node index)).ite
              (.literal 0) (tracking.logTerms node index (termAt log index)))
        else tracking.logTerms node index term)
  | _ => tracking.logTerms

def controlConfigurations {holes : Nat}
    (position pathId : Nat) (state : Template holes) (tracking : Tracking holes)
    (action : Action Node (Value holes)) :
    Node -> List (Configuration Node) -> List (ControlTraceConfigurations.Snapshot holes) :=
  match action with
  | .becomeLeader node =>
      let oldLog := (state.nodes node).log
      let retained := oldLog.take (maxCommittableIndex oldLog)
      Function.update tracking.configurations node
        (Function.update (tracking.configurations node) (allConfigurations retained)
          (ControlTraceConfigurations.truncate
            (tracking.configurations node (allConfigurations oldLog))
            (controlLogLengths position pathId state tracking action node)
            position (fun index => pathSlot (Nat.pair pathId index) CONFIGURATION_SLOT)))
  | _ => tracking.configurations

def nextAppendEntriesTracking {holes : Nat}
    (position pathId : Nat)
    (tracking : Tracking holes)
    (source destination : Node)
    (batchEnd : Nat)
    (queueGrew : Bool) :
    Tracking holes :=
  let queueLengths :=
    Function.update tracking.queueLengths destination
      (if queueGrew then
        .named position
          (pathSlot pathId (markerSlot QUEUE_LENGTH_SLOT_BASE destination))
          s!"queue length {destination.val}"
          (.add (tracking.queueLengths destination) (.literal 1))
       else
        tracking.queueLengths destination)
  let sourceIndices :=
    Function.update (tracking.sentIndex source) destination
      (.named position
        (pathSlot pathId (markerSlot SENT_INDEX_SLOT_BASE destination))
        s!"sent index {destination.val}" (.literal batchEnd))
  { tracking with
    sentIndex := Function.update tracking.sentIndex source sourceIndices
    queueLengths }

def controlCurrentTerms {holes : Nat}
    (position pathId : Nat) (state : Template holes) (tracking : Tracking holes)
    (action : Action Node (Value holes)) : Node -> Value holes :=
  match action with
  | .updateTerm source destination =>
      match newerMessage? state source destination with
      | none => tracking.currentTerms
      | some message =>
          Function.update tracking.currentTerms destination
            (.named position (pathSlot pathId (markerSlot TERM_SLOT_BASE destination))
              "current term" (firstPacketTerm state tracking source destination))
  | _ =>
      (nextControlTracking position pathId state (next state action) tracking).currentTerms

structure Frame (holes : Nat) where
  state : Template holes
  tracking : Tracking holes
  pathId : Nat

def finishFrame {holes : Nat} (position : Nat) (node : Node) (frame : Frame holes) : Frame holes :=
  { frame with tracking := refreshCompletedTracking position frame.pathId frame.state frame.tracking node }

def rememberQueueFrame {holes : Nat} (position : Nat) (node : Node) (before after : Frame holes)
    (consumed : Value holes := .literal 1) : Frame holes :=
  let oldQueue := before.state.network node
  let queue := after.state.network node
  if oldQueue = queue then after
  else
    let snapshots := ReceiveTraceQueue.reconcile position
      (fun index => pathSlot (Nat.pair after.pathId (Nat.pair node.val index)) QUEUE_ARCHIVE_SLOT)
      consumed 0 (before.tracking.queues node oldQueue) queue
    { after with tracking := { after.tracking with
        queues := Function.update after.tracking.queues node
          (Function.update (after.tracking.queues node) queue snapshots) } }

def controlSuccessor {holes : Nat} (state : Template holes) (action : Action Node (Value holes)) :
    Template holes :=
  next state action

def rawControlFrame {holes : Nat}
    (position : Nat) (action : Action Node (Value holes))
    (frame : Frame holes) : Frame holes :=
  let successor := controlSuccessor frame.state action
  { state := successor
    tracking :=
      { nextControlTracking position frame.pathId
          frame.state successor frame.tracking with
        packetTerms := controlPacketTerms position frame.pathId
          frame.state frame.tracking action
        currentTerms := controlCurrentTerms position frame.pathId
          frame.state frame.tracking action
        commitIndices := controlCommitIndices position frame.pathId
          frame.state frame.tracking action
        logLengths := controlLogLengths position frame.pathId
          frame.state frame.tracking action
        sentIndex := controlSentIndices position frame.pathId
          frame.state frame.tracking action
        logTerms := controlLogTerms position frame.pathId
          frame.state frame.tracking action
        packetFields := controlPacketFields position frame.pathId
          frame.state frame.tracking action
        voteMembers := controlVoteMembers position frame.pathId frame.state frame.tracking action
        configurations := controlConfigurations position frame.pathId frame.state frame.tracking action
        queueLengths := controlQueueLengths position frame.pathId frame.state frame.tracking action }
    pathId := frame.pathId }

def controlSendFrame {holes : Nat} (position : Nat) (action : Action Node (Value holes))
    (destination : Node) (frame : Frame holes) : Frame holes :=
  let result := rawControlFrame position action frame
  -- Compute the queue expression once; retain unchanged tracking functions.
  let length := result.tracking.queueLengths destination
  let tracking := { frame.tracking with
    queueLengths := Function.update frame.tracking.queueLengths destination length }
  if result.state.network destination = frame.state.network destination then
    { result with tracking }
  else
    { result with tracking := { tracking with
        packetTerms := result.tracking.packetTerms
        packetFields := result.tracking.packetFields } }

def controlFrame {holes : Nat} (position : Nat) (action : Action Node (Value holes)) (frame : Frame holes) : Frame holes :=
  match action with
  | .requestVote _ destination | .requestPreVote _ destination | .proposeVote _ destination =>
      rememberQueueFrame position destination frame (controlSendFrame position action destination frame)
  | .advanceCommitIndexAndProposeVote node destination =>
      rememberQueueFrame position destination frame (finishFrame position node (rawControlFrame position action frame))
  | .advanceCommitIndex node | .becomeLeader node =>
      finishFrame position node (rawControlFrame position action frame)
  | _ => rawControlFrame position action frame

def clientRequestFrame {holes : Nat}
    (position : Nat)
    (node : Node)
    (accepted : Value holes)
    (frame : Frame holes) :
    Frame holes :=
  finishFrame position node
    { state := next frame.state (.clientRequest node accepted)
      tracking :=
        nextWriteTracking position frame.pathId frame.tracking node
          (frame.state.nodes node).log.length (frame.state.nodes node).currentTerm
      pathId := frame.pathId }

def signatureFrame {holes : Nat}
    (position : Nat)
    (node : Node)
    (frame : Frame holes) :
    Frame holes :=
  finishFrame position node
    { state := next frame.state (.signCommittableMessages node)
      tracking :=
        nextWriteTracking position frame.pathId frame.tracking node
          (frame.state.nodes node).log.length (frame.state.nodes node).currentTerm
      pathId := frame.pathId }

def configurationFrame {holes : Nat}
    (position : Nat)
    (node : Node)
    (configuration : Finset Node)
    (frame : Frame holes) :
    Frame holes :=
  finishFrame position node
    { state := next frame.state (.changeConfiguration node configuration)
      tracking :=
        nextConfigurationTracking position frame.pathId frame.state
          frame.tracking node configuration
      pathId := frame.pathId }

def retiredCommittedFrame {holes : Nat}
    (position : Nat)
    (node : Node)
    (frame : Frame holes) :
    Frame holes :=
  finishFrame position node
    { state := next frame.state (.appendRetiredCommitted node)
      tracking :=
        nextWriteTracking position frame.pathId frame.tracking node
          (frame.state.nodes node).log.length (frame.state.nodes node).currentTerm
      pathId := frame.pathId }

def guardClauses {holes : Nat}
    (condition : Expr holes)
    (clauses : List (Clause holes)) :
    List (Clause holes) :=
  clauses.map fun clause =>
    { clause with expression := condition.implies clause.expression }

def guardedClauses {holes : Nat} {α : Type}
    (tree : Guarded holes α)
    (clauses : α -> List (Clause holes)) :
    List (Clause holes) :=
  match tree with
  | .pure value => clauses value
  | .branch condition thenTree elseTree =>
      guardClauses condition (guardedClauses thenTree clauses) ++
        guardClauses (.not condition) (guardedClauses elseTree clauses)

def guardedGroup {holes : Nat}
    (label : String)
    (frames : Guarded holes (Frame holes))
    (clauses : Frame holes -> List (Clause holes)) :
    Group holes :=
  { label, clauses := guardedClauses frames clauses }

def childPath (pathId : Nat) (right : Bool) : Nat :=
  pathId * 2 + if right then 2 else 1

def attachAppendFrame {holes : Nat}
    (position priorLength : Nat)
    (tracking : Tracking holes)
    (source destination : Node)
    (batchEnd : Nat)
    (pathId : Nat) :
    Guarded holes (Template holes) -> Guarded holes (Frame holes)
  | .pure successor =>
      let queueGrew :=
        decide (priorLength < (successor.network destination).length)
      .pure {
        state := successor
        tracking :=
          nextAppendEntriesTracking position pathId tracking
            source destination batchEnd queueGrew
        pathId
      }
  | .branch condition thenTree elseTree =>
      Guarded.branchSmart condition
        (attachAppendFrame position priorLength tracking source destination
          batchEnd (childPath pathId false) thenTree)
        (attachAppendFrame position priorLength tracking source destination
          batchEnd (childPath pathId true) elseTree)

def rememberAppendPacketFrame {holes : Nat}
    (position : Nat) (before current : Frame holes)
    (source destination : Node) (batchEnd : Nat) : Frame holes :=
  let packetTerms :=
    if (before.state.network destination).length <
        (current.state.network destination).length then
      rememberPacketTerm position current.pathId before.state before.tracking source
        (.appendEntriesRequest (makeAppendEntriesRequest before.state source destination batchEnd))
    else current.tracking.packetTerms
  let packetFields :=
    if (before.state.network destination).length <
        (current.state.network destination).length then
      rememberPacketFields before.state before.tracking
        (.appendEntriesRequest (makeAppendEntriesRequest before.state source destination batchEnd))
        (appendPacketFields position current.pathId before.state before.tracking source destination batchEnd)
    else current.tracking.packetFields
  let packetPositions :=
    if (before.state.network destination).length < (current.state.network destination).length then
      Function.update current.tracking.packetPositions
        (.appendEntriesRequest (makeAppendEntriesRequest before.state source destination batchEnd))
        (appendPacketPositions position current.pathId before.state before.tracking source destination)
    else current.tracking.packetPositions
  { current with tracking := { current.tracking with
      packetTerms
      packetFields
      packetPositions
      queueLengths := Function.update current.tracking.queueLengths destination
        (appendQueueLength position current.pathId before.state before.tracking source destination batchEnd) } }

def appendFrames {holes : Nat}
    (position : Nat)
    (frame : Frame holes)
    (source destination : Node)
    (batchEnd : Nat) :
    Guarded holes (Frame holes) :=
  let priorLength := (frame.state.network destination).length
  (attachAppendFrame position priorLength frame.tracking source destination
    batchEnd frame.pathId
    (GuardedAppendEntries.step frame.state source destination batchEnd)).map
      (fun current => rememberQueueFrame position destination frame
        (rememberAppendPacketFrame position frame current source destination batchEnd))

def receiveVotedForValue {holes : Nat} (position pathId : Nat) (before : Frame holes)
    (source destination : Node) (message : Message Node (Value holes)) : ReceiveTraceValues.Scalar holes :=
  let old : ReceiveTraceValues.Scalar holes :=
    ⟨localField (before.state.nodes destination) 1,
      before.tracking.localFields destination 1 (localField (before.state.nodes destination) 1)⟩
  if old.actual = source.val + 1 then old
  else
    ReceiveTraceValues.choose
      ⟨decide (voteGrantCondition before.state source destination false message),
        voteGrantExpr before.state before.tracking source destination false⟩
      (ReceiveTraceValues.named position
        (pathSlot pathId (LOCAL_FIELD_SLOT_BASE + NODE_COUNT + destination.val))
        "voted for" (ReceiveTraceValues.literal (source.val + 1))) old

def assignLocalValue {holes : Nat} (node : Node) (field : Nat)
    (value : ReceiveTraceValues.Scalar holes) (frame : Frame holes) : Frame holes :=
  { frame with tracking := { frame.tracking with
      localFields := Function.update frame.tracking.localFields node
        (Function.update (frame.tracking.localFields node) field
          (ReceiveTraceValues.install (frame.tracking.localFields node field) value)) } }

def assignPacketField {holes : Nat} (packet : Message Node (Value holes)) (field : Nat)
    (value : ReceiveTraceValues.Scalar holes) (frame : Frame holes) : Frame holes :=
  { frame with tracking := { frame.tracking with
      packetFields := Function.update frame.tracking.packetFields packet
        (Function.update (frame.tracking.packetFields packet) field
          (ReceiveTraceValues.install (frame.tracking.packetFields packet field) value)) } }

def assignPacketTerm {holes : Nat} (packet : Message Node (Value holes))
    (value : ReceiveTraceValues.Scalar holes) (frame : Frame holes) : Frame holes :=
  { frame with tracking := { frame.tracking with
      packetTerms := Function.update frame.tracking.packetTerms packet value.expression } }

def assignCurrentTerm {holes : Nat} (node : Node) (value : ReceiveTraceValues.Scalar holes)
    (frame : Frame holes) : Frame holes :=
  { frame with tracking := { frame.tracking with
      currentTerms := Function.update frame.tracking.currentTerms node value.expression } }

def assignMatchIndex {holes : Nat} (node peer : Node) (value : ReceiveTraceValues.Scalar holes)
    (frame : Frame holes) : Frame holes :=
  { frame with tracking := { frame.tracking with
      matchIndices := Function.update frame.tracking.matchIndices node
        (Function.update (frame.tracking.matchIndices node) peer
          (ReceiveTraceValues.install (frame.tracking.matchIndices node peer) value)) } }

def assignSentIndex {holes : Nat} (node peer : Node) (value : ReceiveTraceValues.Scalar holes)
    (frame : Frame holes) : Frame holes :=
  { frame with tracking := { frame.tracking with
      sentIndex := Function.update frame.tracking.sentIndex node
        (Function.update (frame.tracking.sentIndex node) peer value.expression) } }

def responseMatchValue {holes : Nat} (position : Nat) (before after : Frame holes)
    (source destination : Node) (response : AppendEntriesResponse Node) : ReceiveTraceValues.Scalar holes :=
  let old : ReceiveTraceValues.Scalar holes :=
    ⟨(before.state.nodes destination).matchIndex source,
      before.tracking.matchIndices destination source ((before.state.nodes destination).matchIndex source)⟩
  let offered : ReceiveTraceValues.Scalar holes :=
    ⟨response.lastLogIndex, firstPacketField before.state before.tracking source destination 3⟩
  let offered := if (after.state.nodes destination).matchIndex source = old.actual then offered else
    ReceiveTraceValues.named position
      (pathSlot after.pathId (MATCH_SLOT_BASE + destination.val * NODE_COUNT + source.val)) "received match index" offered
  ReceiveTraceValues.maximum old (ReceiveTraceValues.choose
    ⟨decide (responseAckCondition before.state source destination response),
      responseAckExpr before.state before.tracking source destination response⟩ offered (ReceiveTraceValues.literal 0))

def responseSentValue {holes : Nat} (position : Nat) (before after : Frame holes)
    (source destination : Node) (response : AppendEntriesResponse Node) : ReceiveTraceValues.Scalar holes :=
  let old : ReceiveTraceValues.Scalar holes :=
    ⟨(before.state.nodes destination).sentIndex source, before.tracking.sentIndex destination source⟩
  let possible := highestPossibleValue before.state before.tracking destination
    ⟨response.lastLogIndex, firstPacketField before.state before.tracking source destination 3⟩
    ⟨response.term, firstPacketTerm before.state before.tracking source destination⟩
  let updated := ReceiveTraceValues.conditionalClamp
    ⟨decide (responseNackCondition before.state source destination response),
      responseNackExpr before.state before.tracking source destination response⟩ old
    ⟨(before.state.nodes destination).matchIndex source,
      before.tracking.matchIndices destination source ((before.state.nodes destination).matchIndex source)⟩ possible
  if (after.state.nodes destination).sentIndex source = old.actual then updated else
    ReceiveTraceValues.named position (pathSlot after.pathId (markerSlot SENT_INDEX_SLOT_BASE source))
      "received sent index" updated

def rememberReceiveResponse {holes : Nat} (position : Nat) (before after : Frame holes)
    (source destination : Node) : Frame holes :=
  match takeFirstFrom source (before.state.network destination) with
  | some (.appendEntriesResponse response, _) =>
      assignSentIndex destination source (responseSentValue position before after source destination response)
        (assignMatchIndex destination source (responseMatchValue position before after source destination response) after)
  | _ => after

def proposalTermValue {holes : Nat} (position : Nat) (before after : Frame holes)
    (source destination : Node) (request : ProposeVoteRequest Node) : ReceiveTraceValues.Scalar holes :=
  let old : ReceiveTraceValues.Scalar holes :=
    ⟨(before.state.nodes destination).currentTerm, before.tracking.currentTerms destination⟩
  let offered := ReceiveTraceValues.add
    ⟨request.term, firstPacketTerm before.state before.tracking source destination⟩ (ReceiveTraceValues.literal 1)
  let candidate := if (after.state.nodes destination).currentTerm = old.actual then offered else
    ReceiveTraceValues.named position (pathSlot after.pathId (markerSlot TERM_SLOT_BASE destination))
      "proposal term" offered
  ReceiveTraceValues.maximum old (ReceiveTraceValues.choose
    ⟨decide (candidateTransitionEnabled before.state destination),
      candidateEligibilityExpr before.state before.tracking destination⟩
    candidate (ReceiveTraceValues.literal 0))

def proposalLocalValue {holes : Nat} (position : Nat) (before after : Frame holes)
    (source destination : Node) (request : ProposeVoteRequest Node) (field desired : Nat) :
    ReceiveTraceValues.Scalar holes :=
  let old : ReceiveTraceValues.Scalar holes :=
    ⟨localField (before.state.nodes destination) field,
      before.tracking.localFields destination field (localField (before.state.nodes destination) field)⟩
  if old.actual = desired then old
  else ReceiveTraceValues.choose
    ⟨decide (proposalEffectCondition before.state destination request),
      proposalEffectExpr before.state before.tracking source destination request⟩
    (ReceiveTraceValues.named position
      (pathSlot after.pathId (LOCAL_FIELD_SLOT_BASE + field * NODE_COUNT + destination.val))
      (if field = 2 then "proposal role" else "proposal voted for") (ReceiveTraceValues.literal desired)) old

def proposalMemberValue {holes : Nat} (position : Nat) (before after : Frame holes)
    (source destination : Node) (request : ProposeVoteRequest Node) (preVote : Bool) (peer : Node) :
    ReceiveTraceValues.Scalar holes :=
  let old := decide (peer ∈ if preVote then (before.state.nodes destination).preVotesGranted
    else (before.state.nodes destination).votesGranted)
  let desired := !preVote && decide (peer = destination)
  let oldValue : ReceiveTraceValues.Scalar holes :=
    ⟨if old then 1 else 0, before.tracking.voteMembers destination preVote peer old⟩
  if old = desired then oldValue
  else ReceiveTraceValues.choose
    ⟨decide (proposalEffectCondition before.state destination request),
      proposalEffectExpr before.state before.tracking source destination request⟩
    (ReceiveTraceValues.named position
      (pathSlot after.pathId (markerSlot (if preVote then PRE_VOTE_SLOT_BASE else VOTE_SLOT_BASE) peer))
      "proposal vote membership" (ReceiveTraceValues.literal (if desired then 1 else 0))) oldValue

def rememberReceiveProposal {holes : Nat} (position : Nat) (before after : Frame holes)
    (source destination : Node) : Frame holes :=
  match takeFirstFrom source (before.state.network destination) with
  | some (.proposeVoteRequest request, _) =>
      if request.destination = destination ∧ request.term ≤ (before.state.nodes destination).currentTerm then
        let updated := assignCurrentTerm destination (proposalTermValue position before after source destination request) after
        let updated := assignLocalValue destination 2
          (proposalLocalValue position before after source destination request 2 (roleCode .candidate)) updated
        let updated := assignLocalValue destination 1
          (proposalLocalValue position before after source destination request 1 (destination.val + 1)) updated
        { updated with tracking := { updated.tracking with
            voteMembers := Function.update updated.tracking.voteMembers destination (fun preVote peer value =>
              let proposed := proposalMemberValue position before after source destination request preVote peer
              if (if value then 1 else 0) = proposed.actual then proposed.expression
              else updated.tracking.voteMembers destination preVote peer value) } }
      else after
  | _ => after

def assignVoteMember {holes : Nat} (node : Node) (preVote : Bool) (peer : Node) (present : Bool)
    (value : ReceiveTraceValues.Scalar holes) (frame : Frame holes) : Frame holes :=
  { frame with tracking := { frame.tracking with
      voteMembers := Function.update frame.tracking.voteMembers node (fun mode candidate input =>
        if mode = preVote ∧ candidate = peer ∧ input = present then value.expression
        else frame.tracking.voteMembers node mode candidate input) } }

def receivedVoteValue {holes : Nat} (position pathId : Nat) (before : Frame holes)
    (source destination : Node) (preVote : Bool) (message : Message Node (Value holes)) :
    ReceiveTraceValues.Scalar holes :=
  let old := decide (source ∈ if preVote then (before.state.nodes destination).preVotesGranted
    else (before.state.nodes destination).votesGranted)
  { actual := if receiveVoteCondition before.state source destination preVote message then 1 else if old then 1 else 0
    expression := (receiveVoteExpr before.state before.tracking source destination preVote).ite
      (.named position (pathSlot pathId (markerSlot (if preVote then PRE_VOTE_SLOT_BASE else VOTE_SLOT_BASE) source))
        "received vote membership" (.literal 1))
      (before.tracking.voteMembers destination preVote source old) }

def rememberReceivedVote {holes : Nat} (position : Nat) (before after : Frame holes)
    (source destination : Node) (preVote : Bool) (message : Message Node (Value holes)) : Frame holes :=
  if source ∈ (if preVote then (before.state.nodes destination).preVotesGranted
      else (before.state.nodes destination).votesGranted) then after
  else
    assignVoteMember destination preVote source
      (decide (receiveVoteCondition before.state source destination preVote message))
      (receivedVoteValue position after.pathId before source destination preVote message) after

def rememberReceiveVotes {holes : Nat} (position : Nat) (before after : Frame holes)
    (source destination : Node) : Frame holes :=
  match takeFirstFrom source (before.state.network destination) with
  | some (message@(.requestVoteResponse _), _) =>
      rememberReceivedVote position before after source destination false message
  | some (message@(.requestPreVoteResponse _), _) =>
      rememberReceivedVote position before after source destination true message
  | _ => after

def rememberVoteReply {holes : Nat} (position : Nat) (before after : Frame holes)
    (source destination : Node) (preVote : Bool) (message : Message Node (Value holes))
    (remaining : List (Message Node (Value holes))) : Frame holes :=
  let grant := voteGrantValue before.state before.tracking source destination preVote message
  let granted := decide (voteGrantCondition before.state source destination preVote message)
  let response : Message Node (Value holes) :=
    if preVote then .requestPreVoteResponse
      { term := (before.state.nodes destination).currentTerm, voteGranted := granted,
        source := destination, destination := source }
    else .requestVoteResponse
      { term := (before.state.nodes destination).currentTerm, voteGranted := granted,
        source := destination, destination := source }
  let votedFor := receiveVotedForValue position after.pathId before source destination message
  let updated : Frame holes :=
    if preVote then after else
      assignLocalValue destination 1 votedFor after
  let postDequeue := updateQueue before.state.network destination remaining
  if response ∈ postDequeue source ∨ response ∉ after.state.network source then updated
  else
    assignPacketField response 7
      (ReceiveTraceValues.named position (pathSlot after.pathId (PACKET_FIELD_SLOT_BASE + 7)) "vote granted" grant)
      (assignPacketTerm response
        (ReceiveTraceValues.named position (pathSlot after.pathId PACKET_TERM_SLOT) "message term"
          ⟨(before.state.nodes destination).currentTerm, before.tracking.currentTerms destination⟩)
        updated)

def selectedPacketFrame {holes : Nat} (before : Frame holes) (source destination : Node)
    (message : Message Node (Value holes)) : Frame holes :=
  { before with tracking := { before.tracking with
      packetTerms := Function.update before.tracking.packetTerms message
        (firstPacketTerm before.state before.tracking source destination)
      packetFields := Function.update before.tracking.packetFields message (fun field =>
        Function.update (before.tracking.packetFields message field) (packetFieldNumber message field)
          (firstPacketField before.state before.tracking source destination field))
      packetPositions := Function.update before.tracking.packetPositions message (fun offset =>
        Function.update (before.tracking.packetPositions message offset) (packetFieldNumber message 0 + offset)
          (ReceiveTraceQueue.firstValue source
            (fun packet => before.tracking.packetPositions packet offset (packetFieldNumber packet 0 + offset))
            (.literal 0) (before.tracking.queues destination (before.state.network destination)))) } }

structure ReceiveReplyValues (holes : Nat) where
  term : ReceiveTraceValues.Scalar holes
  index : ReceiveTraceValues.Scalar holes
  success : ReceiveTraceValues.Scalar holes

open ReceiveTraceValues in
def appendReplyValues {holes : Nat} (before : Frame holes) (destination : Node)
    (request : AppendEntriesRequest Node (Value holes)) : ReceiveReplyValues holes :=
  let packet := Message.appendEntriesRequest request
  let rejected : Condition holes := ⟨decide (appendRejected before.state destination request),
    appendRejectedExpr before.state before.tracking destination request⟩
  let failure := appendFailureValues before.state before.tracking destination request
  { term := choose rejected failure.1
      ⟨(before.state.nodes destination).currentTerm, before.tracking.currentTerms destination⟩
    index := choose rejected failure.2
      (add ⟨request.prevLogIndex, before.tracking.packetFields packet 0 request.prevLogIndex⟩
        ⟨request.entries.length, before.tracking.packetFields packet 5 request.entries.length⟩)
    success := boolean (notCondition rejected) }

def appendReplyPacket {holes : Nat} (before : Frame holes) (destination : Node)
    (request : AppendEntriesRequest Node (Value holes)) : Message Node (Value holes) :=
  .appendEntriesResponse (if appendRejected before.state destination request then
    failureResponse (before.state.nodes destination) request else
    successResponse (before.state.nodes destination) request (request.prevLogIndex + request.entries.length))

def rememberAppendReply {holes : Nat} (position : Nat) (before after : Frame holes)
    (source destination : Node) (request : AppendEntriesRequest Node (Value holes))
    (remaining : List (Message Node (Value holes))) : Frame holes :=
  let selected := selectedPacketFrame before source destination (.appendEntriesRequest request)
  let response := appendReplyPacket selected destination request
  let values := appendReplyValues selected destination request
  let postDequeue := updateQueue before.state.network destination remaining
  if response ∈ postDequeue source ∨ response ∉ after.state.network source then after
  else
    assignPacketField response 6
      (ReceiveTraceValues.named position (pathSlot after.pathId (PACKET_FIELD_SLOT_BASE + 6))
        "AppendEntries reply success" values.success)
      (assignPacketField response 3
        (ReceiveTraceValues.named position (pathSlot after.pathId (PACKET_FIELD_SLOT_BASE + 3))
          "AppendEntries reply index" values.index)
        (assignPacketTerm response
          (ReceiveTraceValues.named position (pathSlot after.pathId PACKET_TERM_SLOT)
            "AppendEntries reply term" values.term) after))

def rememberReceiveReply {holes : Nat} (position : Nat) (before after : Frame holes)
    (source destination : Node) : Frame holes :=
  match takeFirstFrom source (before.state.network destination) with
  | some (.appendEntriesRequest request, remaining) =>
      rememberAppendReply position before after source destination request remaining
  | some (message@(.requestVoteRequest _), remaining) =>
      rememberVoteReply position before after source destination false message remaining
  | some (message@(.requestPreVote _), remaining) =>
      rememberVoteReply position before after source destination true message remaining
  | _ => after

open ReceiveTraceValues in
def appendRetainedValue {holes : Nat} (before : Frame holes) (destination : Node)
    (request : AppendEntriesRequest Node (Value holes)) : Scalar holes :=
  minimum ⟨(before.state.nodes destination).log.length, before.tracking.logLengths destination⟩
    ⟨request.prevLogIndex, before.tracking.packetFields (.appendEntriesRequest request) 0 request.prevLogIndex⟩

def appendAcceptanceHeader {holes : Nat} (before : Frame holes) (destination : Node)
    (request : AppendEntriesRequest Node (Value holes)) : Prop :=
  request.destination = destination ∧ request.term = (before.state.nodes destination).currentTerm ∧
    (before.state.nodes destination).role = .follower ∧ logOk (before.state.nodes destination) request ∧
    (before.state.nodes destination).commitIndex ≤ request.prevLogIndex

instance {holes : Nat} (before : Frame holes) (destination : Node)
    (request : AppendEntriesRequest Node (Value holes)) : Decidable (appendAcceptanceHeader before destination request) := by
  unfold appendAcceptanceHeader
  infer_instance

def appendAcceptanceHeaderExpr {holes : Nat} (before : Frame holes) (destination : Node)
    (request : AppendEntriesRequest Node (Value holes)) : Expr holes :=
  let packet := Message.appendEntriesRequest request
  .and (.boolean (decide (request.destination = destination)))
    (.and (.equal (before.tracking.packetTerms packet) (before.tracking.currentTerms destination))
      (.and (roleGuard before.state before.tracking destination fun state => (state.nodes destination).role = .follower)
        (.and (appendLogOkExpr before.state before.tracking destination request)
          (.not (.lessThan (before.tracking.packetFields packet 0 request.prevLogIndex)
            (before.tracking.commitIndices destination (before.state.nodes destination).commitIndex))))))

open ReceiveTraceValues in
def appendLogLengthValue {holes : Nat} (position : Nat) (before after : Frame holes) (destination : Node)
    (request : AppendEntriesRequest Node (Value holes)) : Scalar holes :=
  if (after.state.nodes destination).log = (before.state.nodes destination).log then
    ⟨(before.state.nodes destination).log.length, before.tracking.logLengths destination⟩
  else
    let retained := appendRetainedValue before destination request
    let length := if (after.state.nodes destination).log =
        (before.state.nodes destination).log.take request.prevLogIndex then retained else
      add retained ⟨request.entries.length,
        before.tracking.packetFields (.appendEntriesRequest request) 5 request.entries.length⟩
    if (after.state.nodes destination).log.length = (before.state.nodes destination).log.length then length else
      named position (pathSlot after.pathId 1) "received log length" length

def appendLogPosition {holes : Nat} (position : Nat) (before after : Frame holes) (destination : Node)
    (request : AppendEntriesRequest Node (Value holes)) (index : Nat) : Value holes :=
  let retained := appendRetainedValue before destination request
  if (after.state.nodes destination).log ≠ (before.state.nodes destination).log ∧
      retained.actual < index ∧ index ≤ (after.state.nodes destination).log.length then
    let offset := index - retained.actual
    .named position (pathSlot (Nat.pair after.pathId index) PAYLOAD_POSITION_SLOT) "received entry position"
      (.add retained.expression
        (.sub (before.tracking.packetPositions (.appendEntriesRequest request) offset (request.prevLogIndex + offset))
          (before.tracking.packetFields (.appendEntriesRequest request) 0 request.prevLogIndex)))
  else before.tracking.logPositions destination index

def appendLogTerm {holes : Nat} (position : Nat) (before after : Frame holes) (destination : Node)
    (request : AppendEntriesRequest Node (Value holes)) (index term : Nat) : Value holes :=
  let retained := appendRetainedValue before destination request
  if (after.state.nodes destination).log = (before.state.nodes destination).log ∨ index ≤ retained.actual then
    before.tracking.logTerms destination index term
  else if index ≤ (after.state.nodes destination).log.length then
    let offset := index - retained.actual
    if term = termAt request.entries offset then
      .named position (pathSlot (Nat.pair after.pathId index) LOG_TERM_SLOT) "received entry term"
        (before.tracking.packetFields (.appendEntriesRequest request) (6 + offset) term)
    else before.tracking.logTerms destination index term
  else if term = 0 ∧ termAt (before.state.nodes destination).log index ≠ 0 then
    .named position (pathSlot (Nat.pair after.pathId index) LOG_TERM_SLOT) "received truncation term"
      ((Expr.lessThan (appendLogLengthValue position before after destination request).expression
        (before.tracking.logPositions destination index)).ite (.literal 0)
          (before.tracking.logTerms destination index (termAt (before.state.nodes destination).log index)))
  else before.tracking.logTerms destination index term

def rememberAppendLog {holes : Nat} (position : Nat) (before after : Frame holes) (source destination : Node)
    (request : AppendEntriesRequest Node (Value holes)) : Frame holes :=
  let selected := selectedPacketFrame before source destination (.appendEntriesRequest request)
  { after with tracking := { after.tracking with
      logLengths := Function.update after.tracking.logLengths destination
        (appendLogLengthValue position selected after destination request).expression
      logPositions := Function.update after.tracking.logPositions destination
        (appendLogPosition position selected after destination request)
      logTerms := Function.update after.tracking.logTerms destination
        (appendLogTerm position selected after destination request) } }

def rememberReceiveLog {holes : Nat} (position : Nat) (before after : Frame holes) (source destination : Node) : Frame holes :=
  match takeFirstFrom source (before.state.network destination) with
  | some (.appendEntriesRequest request, _) => rememberAppendLog position before after source destination request
  | _ => after

open ReceiveTraceValues in
def appendCommitValue {holes : Nat} (before after : Frame holes) (destination : Node)
    (request : AppendEntriesRequest Node (Value holes)) : Scalar holes :=
  let packet := Message.appendEntriesRequest request
  let extent := add ⟨request.prevLogIndex, before.tracking.packetFields packet 0 request.prevLogIndex⟩
    ⟨request.entries.length, before.tracking.packetFields packet 5 request.entries.length⟩
  let limit := minimum ⟨request.leaderCommit, before.tracking.packetFields packet 2 request.leaderCommit⟩ extent
  maximum ⟨(before.state.nodes destination).commitIndex,
      before.tracking.commitIndices destination (before.state.nodes destination).commitIndex⟩
    (ReceiveTraceReplication.signedFrontier (after.state.nodes destination).log limit
      (after.tracking.logLengths destination) (after.tracking.logPositions destination))

def rememberAppendCommit {holes : Nat} (position : Nat) (before after : Frame holes) (source destination : Node)
    (request : AppendEntriesRequest Node (Value holes)) : Frame holes :=
  if (after.state.nodes destination).commitIndex = (before.state.nodes destination).commitIndex then after
  else
    let selected := selectedPacketFrame before source destination (.appendEntriesRequest request)
    let value := appendCommitValue selected after destination request
    { after with tracking := { after.tracking with
        commitIndices := Function.update after.tracking.commitIndices destination
          (Function.update (after.tracking.commitIndices destination) (after.state.nodes destination).commitIndex
            (.named position (pathSlot after.pathId (markerSlot COMMIT_SLOT_BASE destination))
              "received commit index" value.expression)) } }

def unappliedAppendValues {holes : Nat} (before : Frame holes) (destination : Node)
    (request : AppendEntriesRequest Node (Value holes)) : Value holes × Value holes :=
  let packet := Message.appendEntriesRequest request
  let previous := before.tracking.packetFields packet 0 request.prevLogIndex
  let count := before.tracking.packetFields packet 5 request.entries.length
  let extent := NatTerm.add previous count
  let applies := appendAcceptanceHeaderExpr before destination request
  let already := appendAlreadyExpr before.state before.tracking destination request
  let retained := appendRetainedValue before destination request
  let candidate := (before.state.nodes destination).log.take request.prevLogIndex ++ request.entries
  let positions := fun index =>
    if index ≤ retained.actual then before.tracking.logPositions destination index
    else NatTerm.add retained.expression
      (.sub (before.tracking.packetPositions packet (index - retained.actual)
        (request.prevLogIndex + (index - retained.actual))) previous)
  let limit : ReceiveTraceValues.Scalar holes :=
    ⟨min request.leaderCommit (request.prevLogIndex + request.entries.length),
      .min (before.tracking.packetFields packet 2 request.leaderCommit) extent⟩
  let oldFrontier := ReceiveTraceReplication.signedFrontier (before.state.nodes destination).log limit
    (before.tracking.logLengths destination) (before.tracking.logPositions destination)
  let candidateFrontier := ReceiveTraceReplication.signedFrontier candidate limit
    (.add retained.expression count) positions
  ((Expr.and applies (.not already)).ite extent (before.tracking.logLengths destination),
    .max (before.tracking.commitIndices destination (before.state.nodes destination).commitIndex)
      (applies.ite (already.ite oldFrontier.expression candidateFrontier.expression) (.literal 0)))

def rememberUnappliedAppend {holes : Nat} (before after : Frame holes) (source destination : Node)
    (request : AppendEntriesRequest Node (Value holes)) : Frame holes :=
  if ¬appendAcceptanceHeader before destination request ∧
      (after.state.nodes destination).log = (before.state.nodes destination).log ∧
      (after.state.nodes destination).commitIndex = (before.state.nodes destination).commitIndex then
    let selected := selectedPacketFrame before source destination (.appendEntriesRequest request)
    let values := unappliedAppendValues selected destination request
    { after with tracking := { after.tracking with
        logLengths := Function.update after.tracking.logLengths destination values.1
        commitIndices := Function.update after.tracking.commitIndices destination
          (Function.update (after.tracking.commitIndices destination) (after.state.nodes destination).commitIndex values.2) } }
  else after

def rememberReceiveCommit {holes : Nat} (position : Nat) (before after : Frame holes) (source destination : Node) : Frame holes :=
  match takeFirstFrom source (before.state.network destination) with
  | some (.appendEntriesRequest request, _) =>
      rememberUnappliedAppend before (rememberAppendCommit position before after source destination request) source destination request
  | _ => after

def receiveConfigurationSnapshots {holes : Nat} (position : Nat) (before after : Frame holes) (destination : Node)
    (request : AppendEntriesRequest Node (Value holes)) : List (ControlTraceConfigurations.Snapshot holes) :=
  let old := before.tracking.configurations destination (allConfigurations (before.state.nodes destination).log)
  if (after.state.nodes destination).log = (before.state.nodes destination).log then old
  else
    let retained := appendRetainedValue before destination request
    let kept := ControlTraceConfigurations.truncate old retained.expression position
      (fun index => pathSlot (Nat.pair after.pathId (2 * index)) CONFIGURATION_SLOT)
    if (after.state.nodes destination).log = (before.state.nodes destination).log.take request.prevLogIndex then kept
    else kept ++ ReceiveTraceConfigurations.copied
      (configurationsInLogFrom (retained.actual + 1) request.entries)
      (after.tracking.logPositions destination) retained.expression (after.tracking.logLengths destination)
      position (fun index => pathSlot (Nat.pair after.pathId (2 * index + 1)) CONFIGURATION_SLOT)

def rememberAppendConfigurations {holes : Nat} (position : Nat) (before after : Frame holes) (source destination : Node)
    (request : AppendEntriesRequest Node (Value holes)) : Frame holes :=
  if allConfigurations (after.state.nodes destination).log = allConfigurations (before.state.nodes destination).log then after
  else
    let selected := selectedPacketFrame before source destination (.appendEntriesRequest request)
    { after with tracking := { after.tracking with
        configurations := Function.update after.tracking.configurations destination
          (Function.update (after.tracking.configurations destination) (allConfigurations (after.state.nodes destination).log)
            (receiveConfigurationSnapshots position selected after destination request)) } }

def rememberReceiveConfigurations {holes : Nat} (position : Nat) (before after : Frame holes) (source destination : Node) : Frame holes :=
  match takeFirstFrom source (before.state.network destination) with
  | some (.appendEntriesRequest request, _) => rememberAppendConfigurations position before after source destination request
  | _ => after

def appendStepdownExpr {holes : Nat} (before : Frame holes) (destination : Node)
    (request : AppendEntriesRequest Node (Value holes)) : Expr holes :=
  .and (.boolean (decide (request.destination = destination)))
    (.and (.equal (before.tracking.packetTerms (.appendEntriesRequest request)) (before.tracking.currentTerms destination))
      (roleGuard before.state before.tracking destination fun state =>
        (state.nodes destination).role = .candidate ∨ (state.nodes destination).role = .preVoteCandidate))

def appendStepdownCondition {holes : Nat} (before : Frame holes) (destination : Node)
    (request : AppendEntriesRequest Node (Value holes)) : Prop :=
  request.destination = destination ∧ request.term = (before.state.nodes destination).currentTerm ∧
    ((before.state.nodes destination).role = .candidate ∨ (before.state.nodes destination).role = .preVoteCandidate)

instance {holes : Nat} (before : Frame holes) (destination : Node)
    (request : AppendEntriesRequest Node (Value holes)) : Decidable (appendStepdownCondition before destination request) := by
  unfold appendStepdownCondition
  infer_instance

def appendStepdownValue {holes : Nat} (position : Nat) (before after : Frame holes) (destination : Node)
    (request : AppendEntriesRequest Node (Value holes)) (field desired : Nat) : ReceiveTraceValues.Scalar holes :=
  let old := localField (before.state.nodes destination) field
  if old = desired then ⟨old, before.tracking.localFields destination field old⟩ else
    ReceiveTraceValues.choose
      ⟨decide (appendStepdownCondition before destination request), appendStepdownExpr before destination request⟩
      (ReceiveTraceValues.named position (pathSlot after.pathId (LOCAL_FIELD_SLOT_BASE + field * NODE_COUNT + destination.val))
        "AppendEntries stepdown" (ReceiveTraceValues.literal desired))
      ⟨old, before.tracking.localFields destination field old⟩

def appendConflictAppliedExpr {holes : Nat} (before : Frame holes) (destination : Node)
    (request : AppendEntriesRequest Node (Value holes)) : Expr holes :=
  let packet := Message.appendEntriesRequest request
  .and (.boolean (decide (request.destination = destination)))
    (.and (.equal (before.tracking.packetTerms packet) (before.tracking.currentTerms destination))
      (.and (roleGuard before.state before.tracking destination fun state => (state.nodes destination).role = .follower)
        (.and (appendLogOkExpr before.state before.tracking destination request)
          (.and (.not (.lessThan (before.tracking.packetFields packet 0 request.prevLogIndex)
              (before.tracking.commitIndices destination (before.state.nodes destination).commitIndex)))
            (appendConflictExpr before.state before.tracking destination request)))))

def appendConflictAppliedCondition {holes : Nat} (before : Frame holes) (destination : Node)
    (request : AppendEntriesRequest Node (Value holes)) : Prop :=
  request.destination = destination ∧ request.term = (before.state.nodes destination).currentTerm ∧
    (before.state.nodes destination).role = .follower ∧ logOk (before.state.nodes destination) request ∧
    (before.state.nodes destination).commitIndex ≤ request.prevLogIndex ∧
    hasTermConflict (before.state.nodes destination) request

instance {holes : Nat} (before : Frame holes) (destination : Node)
    (request : AppendEntriesRequest Node (Value holes)) : Decidable (appendConflictAppliedCondition before destination request) := by
  unfold appendConflictAppliedCondition
  infer_instance

def appendConflictValue {holes : Nat} (position : Nat) (before after : Frame holes) (destination : Node)
    (request : AppendEntriesRequest Node (Value holes)) : ReceiveTraceValues.Scalar holes :=
  ReceiveTraceValues.choose
    ⟨decide (appendConflictAppliedCondition before destination request), appendConflictAppliedExpr before destination request⟩
    (ReceiveTraceValues.named position (pathSlot after.pathId (LOCAL_FIELD_SLOT_BASE + destination.val))
      "AppendEntries conflict applied" (ReceiveTraceValues.literal 0))
    ⟨localField (before.state.nodes destination) 0,
      before.tracking.localFields destination 0 (localField (before.state.nodes destination) 0)⟩

def rememberReceiveStepdown {holes : Nat} (position : Nat) (before after : Frame holes) (source destination : Node) : Frame holes :=
  match takeFirstFrom source (before.state.network destination) with
  | some (.appendEntriesRequest request, _) =>
      let selected := selectedPacketFrame before source destination (.appendEntriesRequest request)
      let role := appendStepdownValue position selected after destination request 2 (roleCode .follower)
      let updated := assignLocalValue destination 2 role after
      if (after.state.nodes destination).isNewFollower = true then
        assignLocalValue destination 0 (appendStepdownValue position selected after destination request 0 1) updated
      else if (before.state.nodes destination).isNewFollower = true then
        assignLocalValue destination 0 (appendConflictValue position selected after destination request) updated
      else updated
  | _ => after

def rememberReceiveRetirement {holes : Nat} (position : Nat) (before after : Frame holes) (destination : Node) : Frame holes :=
  let refreshed := finishFrame position destination after
  { after with tracking := { after.tracking with
      completedMembers := fun node peer =>
        if node = destination ∧
            decide (peer ∈ before.state.retirementCompleted node) ≠ decide (peer ∈ after.state.retirementCompleted node) then
          refreshed.tracking.completedMembers node peer
        else after.tracking.completedMembers node peer } }

def receiveReplyFrame {holes : Nat} (before : Frame holes) (source destination : Node)
    (message : Message Node (Value holes)) : Frame holes × Option (Message Node (Value holes)) :=
  match message with
  | .appendEntriesRequest request =>
      let selected := selectedPacketFrame before source destination message
      let response := appendReplyPacket selected destination request
      let values := appendReplyValues selected destination request
      (assignPacketField response 6 values.success
        (assignPacketField response 3 values.index (assignPacketTerm response values.term before)), some response)
  | .requestVoteRequest _ | .requestPreVote _ =>
      let preVote := match message with | .requestPreVote _ => true | _ => false
      let granted := decide (voteGrantCondition before.state source destination preVote message)
      let response : Message Node (Value holes) :=
        if preVote then .requestPreVoteResponse
          { term := (before.state.nodes destination).currentTerm, voteGranted := granted, source := destination, destination := source }
        else .requestVoteResponse
          { term := (before.state.nodes destination).currentTerm, voteGranted := granted, source := destination, destination := source }
      (assignPacketField response 7 (voteGrantValue before.state before.tracking source destination preVote message)
        (assignPacketTerm response ⟨(before.state.nodes destination).currentTerm, before.tracking.currentTerms destination⟩ before),
        some response)
  | _ => (before, none)

def receiveConsumptionAmount {holes : Nat} (before : Frame holes) (source destination : Node) : Value holes :=
  match takeFirstFrom source (before.state.network destination) with
  | some (.appendEntriesRequest request, _) =>
      if appendStepdownCondition before destination request then .literal 1 else
        let selected := selectedPacketFrame before source destination (.appendEntriesRequest request)
        (appendStepdownExpr selected destination request).ite (.literal 0) (.literal 1)
  | _ => .literal 1

def receiveQueueValue {holes : Nat} (position : Nat) (before after : Frame holes)
    (destination node : Node) (remaining : List (Message Node (Value holes)))
    (replyFrame : Frame holes) (response : Option (Message Node (Value holes)))
    (consumed : Value holes := .literal 1) : Value holes :=
  let base := if node = destination then
      .sub (before.tracking.queueLengths node)
        (.named position (pathSlot after.pathId (markerSlot QUEUE_LENGTH_SLOT_BASE node)) "dequeued packet" consumed)
    else before.tracking.queueLengths node
  match response with
  | none => base
  | some packet =>
      if packet.destination = node then
        .add base
          (.named position (pathSlot (childPath after.pathId true) (markerSlot QUEUE_LENGTH_SLOT_BASE node))
            "reply enqueued" (.literal 1))
      else base

def rememberReceiveQueues {holes : Nat} (position : Nat) (before after : Frame holes) (source destination : Node) : Frame holes :=
  match takeFirstFrom source (before.state.network destination) with
  | none => after
  | some (message, remaining) =>
      if before.state.network destination = after.state.network destination then after else
        let (replyFrame, response) := receiveReplyFrame before source destination message
        let dequeued := updateQueue before.state.network destination remaining
        let expected := match response with | none => dequeued | some packet => enqueue dequeued packet
        { after with tracking := { after.tracking with
            queueLengths := fun node =>
            if after.state.network node = expected node then
              receiveQueueValue position before after destination node remaining replyFrame response
                (receiveConsumptionAmount before source destination)
            else after.tracking.queueLengths node } }

def trackedReceiveStep {holes : Nat} (before : Frame holes) (source destination : Node) :
    Guarded holes (GuardedReceive.Result holes) :=
  match takeFirstFrom source (before.state.network destination) with
  | some (.appendEntriesRequest request, _) =>
      let selected := selectedPacketFrame before source destination (.appendEntriesRequest request)
      ReceiveTraceBranching.step before.state source destination
        (appendPrefixExpr selected.state selected.tracking destination request)
  | _ => GuardedReceive.step before.state source destination

def attachReceiveFrame {holes : Nat} (position pathId : Nat) (before : Frame holes) :
    Guarded holes (GuardedReceive.Result holes) -> Guarded holes (Frame holes)
  | .pure result =>
      .pure {
        state := result.successor
        tracking := nextControlTracking position pathId before.state result.successor before.tracking
        pathId }
  | .branch condition left right =>
      Guarded.branchSmart condition
        (attachReceiveFrame position (childPath pathId false) before left)
        (attachReceiveFrame position (childPath pathId true) before right)

def receiveFrames {holes : Nat} (position : Nat) (before : Frame holes) (source destination : Node) :
    Guarded holes (Frame holes) :=
  (attachReceiveFrame position before.pathId before (trackedReceiveStep before source destination)).map
    (fun after => rememberQueueFrame position source before (rememberQueueFrame position destination before
      (rememberReceiveQueues position before (rememberReceiveRetirement position before (rememberReceiveStepdown position before (rememberReceiveConfigurations position before (rememberReceiveCommit position before (rememberReceiveLog position before (rememberReceiveProposal position before
        (rememberReceiveResponse position before
          (rememberReceiveVotes position before (rememberReceiveReply position before after source destination) source destination)
          source destination)
        source destination) source destination) source destination) source destination) source destination) destination) source destination)
        (receiveConsumptionAmount before source destination)) (receiveConsumptionAmount before source destination))

def receiveGroup {holes : Nat} (bounds : Bounds) (before : Frame holes) (source destination : Node) :
    Group holes :=
  { label := "receive"
    clauses := stateBoundsClauses bounds before.state before.tracking ++
      [{ label := "receive enabled"
         expression := .and (receiveEntryExpr before.state before.tracking source destination)
           ((trackedReceiveStep before source destination).test fun result =>
             if receiveEntryAllowed before.state source destination then result.enabledExpr else .boolean true) }] }

def encodeFrom {holes : Nat}
    (bounds : Bounds)
    (position : Nat)
    (frames : Guarded holes (Frame holes)) :
    List (TraceInstructions.Instruction holes) -> Formula holes
  | [] =>
      [{ label := "final state bounds"
         clauses := guardedClauses frames fun frame =>
           stateBoundsClauses bounds frame.state frame.tracking }]
  | .observation observation :: rest =>
      (guardedGroup "observation" frames fun frame =>
        stateBoundsClauses bounds frame.state frame.tracking ++
          observationClauses bounds frame.state frame.tracking observation) ::
        encodeFrom bounds (position + 1) frames rest
  | .clientRequest node transaction :: rest =>
      let accepted :=
        .named position 0 "accepted transaction" transaction
      (guardedGroup "clientRequest" frames fun frame =>
        (clientRequestGroup bounds frame.state frame.tracking
          node transaction).clauses) ::
        encodeFrom bounds (position + 1)
          (frames.map (clientRequestFrame position node accepted)) rest
  | .signCommittableMessages node :: rest =>
      (guardedGroup "signCommittableMessages" frames fun frame =>
        (leaderWriteGroup "signCommittableMessages" bounds
          frame.state frame.tracking
          (.signCommittableMessages node)).clauses) ::
        encodeFrom bounds (position + 1)
          (frames.map (signatureFrame position node)) rest
  | .changeConfiguration node configuration :: rest =>
      (guardedGroup "changeConfiguration" frames fun frame =>
        (leaderWriteGroup "changeConfiguration" bounds
          frame.state frame.tracking
          (.changeConfiguration node configuration)).clauses) ::
        encodeFrom bounds (position + 1)
          (frames.map
            (configurationFrame position node configuration)) rest
  | .appendRetiredCommitted node :: rest =>
      (guardedGroup "appendRetiredCommitted" frames fun frame =>
        (leaderWriteGroup "appendRetiredCommitted" bounds
          frame.state frame.tracking
          (.appendRetiredCommitted node)).clauses) ::
        encodeFrom bounds (position + 1)
          (frames.map (retiredCommittedFrame position node)) rest
  | .appendEntries source destination batchEnd :: rest =>
      (guardedGroup "appendEntries" frames fun frame =>
        (leaderWriteGroup "appendEntries" bounds frame.state frame.tracking
          (.appendEntries source destination batchEnd)).clauses) ::
        encodeFrom bounds (position + 1)
          (frames.bind fun frame =>
            appendFrames position frame source destination batchEnd)
          rest
  | .timeout node :: rest =>
      (guardedGroup "timeout" frames fun frame =>
        (leaderWriteGroup "timeout" bounds frame.state frame.tracking
          (.timeout node)).clauses) ::
        encodeFrom bounds (position + 1)
          (frames.map (controlFrame position (.timeout node))) rest
  | .receive source destination :: rest =>
      (guardedGroup "receive" frames fun frame =>
        (receiveGroup bounds frame source destination).clauses) ::
        encodeFrom bounds (position + 1)
          (frames.bind fun frame => receiveFrames position frame source destination) rest
  | .becomePreVoteCandidate node :: rest =>
      (guardedGroup "becomePreVoteCandidate" frames fun frame =>
        (leaderWriteGroup "becomePreVoteCandidate" bounds frame.state frame.tracking
          (.becomePreVoteCandidate node)).clauses) ::
        encodeFrom bounds (position + 1)
          (frames.map (controlFrame position (.becomePreVoteCandidate node))) rest
  | .becomeCandidate node :: rest =>
      (guardedGroup "becomeCandidate" frames fun frame =>
        (leaderWriteGroup "becomeCandidate" bounds frame.state frame.tracking
          (.becomeCandidate node)).clauses) ::
        encodeFrom bounds (position + 1)
          (frames.map (controlFrame position (.becomeCandidate node))) rest
  | .advanceCommitIndex node :: rest =>
      (guardedGroup "advanceCommitIndex" frames fun frame =>
        (leaderWriteGroup "advanceCommitIndex" bounds frame.state frame.tracking
          (.advanceCommitIndex node)).clauses) ::
        encodeFrom bounds (position + 1)
          (frames.map (controlFrame position (.advanceCommitIndex node))) rest
  | .checkQuorum node :: rest =>
      (guardedGroup "checkQuorum" frames fun frame =>
        (leaderWriteGroup "checkQuorum" bounds frame.state frame.tracking
          (.checkQuorum node)).clauses) ::
        encodeFrom bounds (position + 1)
          (frames.map (controlFrame position (.checkQuorum node))) rest
  | .updateTerm source destination :: rest =>
      (guardedGroup "updateTerm" frames fun frame =>
        (leaderWriteGroup "updateTerm" bounds frame.state frame.tracking
          (.updateTerm source destination)).clauses) ::
        encodeFrom bounds (position + 1)
          (frames.map (controlFrame position (.updateTerm source destination))) rest
  | .becomeLeader node :: rest =>
      (guardedGroup "becomeLeader" frames fun frame =>
        (leaderWriteGroup "becomeLeader" bounds frame.state frame.tracking
          (.becomeLeader node)).clauses) ::
        encodeFrom bounds (position + 1)
          (frames.map (controlFrame position (.becomeLeader node))) rest
  | .requestVote source destination :: rest =>
      (guardedGroup "requestVote" frames fun frame =>
        (leaderWriteGroup "requestVote" bounds frame.state frame.tracking
          (.requestVote source destination)).clauses) ::
        encodeFrom bounds (position + 1)
          (frames.map (controlFrame position (.requestVote source destination))) rest
  | .requestPreVote source destination :: rest =>
      (guardedGroup "requestPreVote" frames fun frame =>
        (leaderWriteGroup "requestPreVote" bounds frame.state frame.tracking
          (.requestPreVote source destination)).clauses) ::
        encodeFrom bounds (position + 1)
          (frames.map (controlFrame position (.requestPreVote source destination))) rest
  | .proposeVote source destination :: rest =>
      (guardedGroup "proposeVote" frames fun frame =>
        (leaderWriteGroup "proposeVote" bounds frame.state frame.tracking
          (.proposeVote source destination)).clauses) ::
        encodeFrom bounds (position + 1)
          (frames.map (controlFrame position (.proposeVote source destination))) rest
  | .advanceCommitIndexAndProposeVote source destination :: rest =>
      (guardedGroup "advanceCommitIndexAndProposeVote" frames fun frame =>
        (leaderWriteGroup "advanceCommitIndexAndProposeVote" bounds frame.state frame.tracking
          (.advanceCommitIndexAndProposeVote source destination)).clauses) ::
        encodeFrom bounds (position + 1)
          (frames.map
            (controlFrame position (.advanceCommitIndexAndProposeVote source destination))) rest

def encode {holes : Nat}
    (bounds : Bounds)
    (entry : Template holes)
    (trace : List (TraceInstructions.Instruction holes)) :
    Formula holes :=
  { label := "unknown transaction domains"
    clauses := (List.finRange holes).map fun index =>
      lessClause s!"unknown {index.val} domain" (.unknown index)
        bounds.transactionCount } ::
  encodeFrom bounds 1
    (.pure { state := entry, tracking := initialTracking entry, pathId := 0 })
    trace

end CCFRaft.TraceEncoding
