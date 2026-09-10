-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import BoundedTrace
import Shared.SmtOrder
import MachineGenerated.GuardedAppendEntries
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
def PATH_SLOT_STRIDE : Nat := 480

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
  PACKET_FIELD_SLOT_BASE + 6 ≤ PAYLOAD_TERM_SLOT && PAYLOAD_TERM_SLOT < VOTE_SLOT_BASE &&
  VOTE_SLOT_BASE + NODE_COUNT ≤ PRE_VOTE_SLOT_BASE &&
  PRE_VOTE_SLOT_BASE + NODE_COUNT ≤ CONFIGURATION_SLOT &&
  CONFIGURATION_SLOT < COMPLETED_SLOT_BASE &&
  COMPLETED_SLOT_BASE + NODE_COUNT ≤ PATH_SLOT_STRIDE

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
      (tracking.logTerms source (lastCommittableIndex (state.nodes source))
        (lastCommittableTerm (state.nodes source)))
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
        (tracking.logTerms source previous (termAt localState.log previous))
    | 2 => fieldOrigin position pathId 2 localState.commitIndex
        (tracking.commitIndices source localState.commitIndex)
    | 5 => fieldOrigin position pathId 5 (messageEntries localState.log previous batchEnd).length
        (minValue (.sub (tracking.logLengths source) sent) (.sub (.literal batchEnd) sent))
    | _ =>
        if 6 ≤ field then
          fun term => .named position (pathSlot (Nat.pair pathId (field - 6)) PAYLOAD_TERM_SLOT)
            s!"payload entry term {field - 6}"
            (tracking.logTerms source (previous + (field - 6)) term)
        else fun value => .literal value

def roleCode : Role -> Nat
  | .none => 0
  | .follower => 1
  | .preVoteCandidate => 2
  | .candidate => 3
  | .leader => 4

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
    (controlValue tracking node (markerSlot ROLE_SLOT_BASE node)
      "role" (roleCode (state.nodes node).role))
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
  let request := makeAppendEntriesRequest state source destination batchEnd
  let term := tracking.currentTerms source
  let fields := fun field value => ControlTracePackets.snapshotValue
    (appendPacketFields position pathId state tracking source destination batchEnd field value)
  let duplicate := anyExpr ((state.network destination).map fun previous =>
    ControlTracePackets.appendEqualExpr term fields tracking.packetTerms tracking.packetFields request previous)
  .add (tracking.queueLengths destination)
    (duplicate.ite (.literal 0)
      (.named position (pathSlot pathId (markerSlot QUEUE_LENGTH_SLOT_BASE destination))
        s!"queue growth {destination.val}" (.literal 1)))

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
          (controlValue tracking node (MATCH_SLOT_BASE + node.val * NODE_COUNT + peer.val)
            s!"match index {peer.val}" ((state.nodes node).matchIndex peer)))) (.literal 0)
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
  controlValue tracking node (MATCH_SLOT_BASE + node.val * NODE_COUNT + peer.val)
    s!"match index {peer.val}" ((state.nodes node).matchIndex peer)

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
    (.and (.equal (controlValue tracking node (markerSlot ROLE_SLOT_BASE node)
        "role" (roleCode (state.nodes node).role)) (.literal (roleCode .leader)))
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

def newerMessageExpr {holes : Nat}
    (state : Template holes) (tracking : Tracking holes) (source destination : Node) : Expr holes :=
  match takeFirstFrom source (state.network destination) with
  | none => .boolean false
  | some (message, _) =>
      .and (sourceAllowedExpr tracking message)
        (.lessThan (tracking.currentTerms destination) (tracking.packetTerms message))

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
       (controlValue tracking node
         (MATCH_SLOT_BASE + node.val * NODE_COUNT + peer.val)
         s!"match index {peer.val}" (state.matchIndex peer))
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
        (controlValue tracking node (markerSlot ROLE_SLOT_BASE node)
          "role" (roleCode (assignmentState.nodes node).role))
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
    completedMembers := tracking.completedMembers }

def controlQueueLength {holes : Nat}
    (position pathId : Nat) (state : Template holes) (tracking : Tracking holes)
    (source : Node) (message : Message Node (Value holes)) (fields : Nat -> Nat -> Value holes) : Value holes :=
  let outgoingTerms := Function.update tracking.packetTerms message
    (tracking.currentTerms source)
  let outgoingFields := Function.update tracking.packetFields message
    (fun field value => ControlTracePackets.snapshotValue (fields field value))
  let duplicate := anyExpr ((state.network message.destination).map fun previous =>
    ControlTracePackets.equalExpr outgoingTerms tracking.packetTerms outgoingFields tracking.packetFields message previous)
  .add (tracking.queueLengths message.destination)
    (duplicate.ite (.literal 0)
      (.named position (pathSlot pathId (markerSlot QUEUE_LENGTH_SLOT_BASE message.destination))
        s!"queue growth {message.destination.val}" (.literal 1)))

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
              "current term" (tracking.packetTerms message))
  | _ =>
      (nextControlTracking position pathId state (next state action) tracking).currentTerms

structure Frame (holes : Nat) where
  state : Template holes
  tracking : Tracking holes
  pathId : Nat

def finishFrame {holes : Nat} (position : Nat) (node : Node) (frame : Frame holes) : Frame holes :=
  { frame with tracking := refreshCompletedTracking position frame.pathId frame.state frame.tracking node }

def controlSuccessor {holes : Nat} (state : Template holes) (action : Action Node (Value holes)) :
    Template holes :=
  let successor := next state action
  let packet : Option (Message Node (Value holes)) :=
    match action with
    | .requestVote source destination => some (.requestVoteRequest (makeRequestVoteRequest state source destination))
    | .requestPreVote source destination => some (.requestPreVote (makeRequestPreVote state source destination))
    | .proposeVote source destination | .advanceCommitIndexAndProposeVote source destination =>
        some (.proposeVoteRequest (makeProposeVoteRequest state source destination))
    | _ => none
  match packet with
  | none => successor
  | some message =>
      -- Reuse the function rather than replaying every earlier no-op enqueue on lookup.
      if message ∈ state.network message.destination then
        { successor with network := state.network }
      else successor

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
      controlSendFrame position action destination frame
  | .advanceCommitIndex node | .advanceCommitIndexAndProposeVote node _ | .becomeLeader node =>
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
  { current with tracking := { current.tracking with
      packetTerms
      packetFields
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
      (fun current => rememberAppendPacketFrame position frame current source destination batchEnd)

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
