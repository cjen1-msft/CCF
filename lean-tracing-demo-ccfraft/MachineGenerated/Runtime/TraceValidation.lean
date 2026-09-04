-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.Runtime.Simulation
import Lean.Data.Json

set_option autoImplicit false

/-!
# CCF Raft implementation-trace validation

This module maps a small, explicit subset of CCF `raft_trace` records to the
canonical executable CCFRaft model. The parser projects implementation ledger
indices past CCF's bootstrap prefix. The bounded search may insert only hidden
response deliveries. Every retained step still passes through `system.applyAction`.
-/

namespace CCFRaft.TraceValidation

open Lean
open CCFRaft
open CCFRaft.Simulation

def CCF_BOOTSTRAP_INDEX : Nat := 2

inductive EventKind where
  | bootstrap
  | replicate
  | addConfiguration
  | retiredCommitted
  | sendAppendEntries
  | recvAppendEntries
  | proposeVote
  | recvProposeVote
  | commit
  deriving BEq, DecidableEq, Inhabited, Repr

def EventKind.name : EventKind -> String
  | .bootstrap => "bootstrap"
  | .replicate => "replicate"
  | .addConfiguration => "add_configuration"
  | .retiredCommitted => "append_retired_committed"
  | .sendAppendEntries => "send_append_entries"
  | .recvAppendEntries => "recv_append_entries"
  | .proposeVote => "step_down_and_nominate_successor"
  | .recvProposeVote => "recv_propose_request_vote"
  | .commit => "commit"

def parseEventKind (raw : String) : Except String EventKind :=
  match raw with
  | "bootstrap" => .ok .bootstrap
  | "replicate" => .ok .replicate
  | "add_configuration" => .ok .addConfiguration
  | "append_retired_committed" => .ok .retiredCommitted
  | "retired_committed" => .ok .retiredCommitted
  | "send_append_entries" => .ok .sendAppendEntries
  | "recv_append_entries" => .ok .recvAppendEntries
  | "step_down_and_nominate_successor" => .ok .proposeVote
  | "recv_propose_request_vote" => .ok .recvProposeVote
  | "commit" => .ok .commit
  | _ => .error s!"unsupported raft_trace function: {raw}"

structure PacketObservation where
  term : Option Nat := none
  previousTerm : Option Nat := none
  leaderCommitIndex : Option Nat := none
  termOfIndex : Option Nat := none
  index : Option Nat := none
  previousIndex : Option Nat := none
  deriving DecidableEq

structure WirePacketObservation where
  term : Nat
  previousTerm : Nat
  leaderCommitIndex : Nat
  termOfIndex : Nat
  index : Nat
  previousIndex : Nat
  deriving DecidableEq

/--
Visible implementation fields in model coordinates. Ledger indices after the
bootstrap record have already had `bootstrapIndex` removed.
-/
structure Observation where
  line : Nat
  kind : EventKind
  node : Node
  peer : Option Node := none
  role : Option Role := none
  preVoteStatus : Option PreVoteStatus := none
  membershipState : Option MembershipState := none
  retirementIndex : Option Nat := none
  retirementCommittableIndex : Option Nat := none
  retiredCommittedIndex : Option Nat := none
  configuration : Option (Finset Node) := none
  currentTerm : Option Nat := none
  view : Option Nat := none
  logLength : Option Nat := none
  commitIndex : Option Nat := none
  targetIndex : Option Nat := none
  committable : Option Bool := none
  proposalTerm : Option Nat := none
  packet : Option PacketObservation := none
  wirePacket : Option WirePacketObservation := none
  sentIndex : Option Nat := none
  matchIndex : Option Nat := none
  deriving DecidableEq

instance : Inhabited Observation where
  default := {
    line := 0
    kind := .bootstrap
    node := INITIAL_LEADER
  }

structure Checkpoint where
  step : Nat
  observation : Observation
  coalescedReceive : Bool := false
  deriving DecidableEq

structure ParsedTrace where
  observations : Array Observation
  bootstrapIndex : Nat
  bootstrap : Bootstrap Node
  nodeIds : List String
  ignoredRecords : Nat

structure ParseContext where
  nodeIds : List String := []
  initialNodeIds : List String := []
  bootstrapIndex : Option Nat := none
  bootstrap : Option (Bootstrap Node) := none
  preVoteStatuses : Node -> Option PreVoteStatus := fun _ => none

def recordPreVoteStatus
    (context : ParseContext)
    (node : Node)
    (status : Option PreVoteStatus) :
    Except String ParseContext :=
  match status with
  | none => .ok context
  | some status =>
      match context.preVoteStatuses node with
      | none =>
          .ok {
            context with
            preVoteStatuses :=
              Function.update context.preVoteStatuses node (some status)
          }
      | some recorded =>
          if recorded = status then
            .ok context
          else
            .error
              s!"node {node.val} has inconsistent pre_vote_enabled values"

/-- Recording one node's status does not overwrite another interned node. -/
theorem recordPreVoteStatus_perNode :
    let node0 : Node := ⟨0, by decide⟩
    let node1 : Node := ⟨1, by decide⟩
    match recordPreVoteStatus {} node0 (some .enabled) with
    | .error _ => False
    | .ok first =>
        match recordPreVoteStatus first node1 (some .capable) with
        | .error _ => False
        | .ok second =>
            second.preVoteStatuses node0 = some .enabled /\
              second.preVoteStatuses node1 = some .capable := by
  simp [recordPreVoteStatus, Function.update]

def bootstrapWithRecordedPreVoteStatuses
    (context : ParseContext)
    (bootstrap : Bootstrap Node) :
    Bootstrap Node where
  configuration := bootstrap.configuration
  leader := bootstrap.leader
  leader_mem := bootstrap.leader_mem
  preVoteStatus := fun node =>
    (context.preVoteStatuses node).getD .capable

/-- Final bootstrap construction preserves distinct per-node statuses. -/
theorem bootstrapPreVoteStatus_perNode :
    let node0 : Node := ⟨0, by decide⟩
    let node1 : Node := ⟨1, by decide⟩
    match recordPreVoteStatus {} node0 (some .enabled) with
    | .error _ => False
    | .ok first =>
        match recordPreVoteStatus first node1 (some .capable) with
        | .error _ => False
        | .ok second =>
            let bootstrap :=
              bootstrapWithRecordedPreVoteStatuses
                second (inferInstanceAs (Bootstrap Node))
            bootstrap.preVoteStatus node0 = .enabled /\
              bootstrap.preVoteStatus node1 = .capable := by
  simp [
    recordPreVoteStatus,
    bootstrapWithRecordedPreVoteStatuses,
    Function.update
  ]

def requiredField (json : Json) (key : String) : Except String Json :=
  match json.getObjVal? key with
  | .ok value => .ok value
  | .error _ => .error s!"missing required field: {key}"

def optionalField (json : Json) (key : String) : Option Json :=
  match json.getObjVal? key with
  | .ok value => some value
  | .error _ => none

def jsonNat (json : Json) : Except String Nat :=
  match json.getNat? with
  | .ok value => .ok value
  | .error _ =>
      match json.getStr? with
      | .ok raw =>
          match raw.toNat? with
          | some value => .ok value
          | none => .error s!"expected a natural number, got {json.compress}"
      | .error _ =>
          .error s!"expected a natural number, got {json.compress}"

def optionalNatField
    (json : Json)
    (key : String) :
    Except String (Option Nat) :=
  match optionalField json key with
  | none => .ok none
  | some value => do
      let parsed <- jsonNat value
      pure (some parsed)

def optionalBoolField
    (json : Json)
    (key : String) :
    Except String (Option Bool) :=
  match optionalField json key with
  | none => .ok none
  | some value =>
      match value.getBool? with
      | .ok parsed => .ok (some parsed)
      | .error _ => .error s!"field {key} must be a Boolean"

def nodeIdText (json : Json) : Except String String :=
  match json.getStr? with
  | .ok value => .ok value
  | .error _ =>
      match json.getNat? with
      | .ok value => .ok (toString value)
      | .error _ =>
          .error s!"node ID must be a string or natural number, got {json.compress}"

def internNode
    (context : ParseContext)
    (raw : String) :
    Except String (Prod Node ParseContext) :=
  match context.nodeIds.findIdx? (fun candidate => candidate == raw) with
  | some index =>
      if within : index < NODE_COUNT then
        .ok (Fin.mk index within, context)
      else
        .error "internal node-map invariant failed"
  | none =>
      let index := context.nodeIds.length
      if within : index < NODE_COUNT then
        .ok (
          Fin.mk index within,
          { context with nodeIds := context.nodeIds ++ [raw] })
      else
        .error s!"trace contains more than {NODE_COUNT} distinct node IDs"

def parseNodeField
    (context : ParseContext)
    (json : Json)
    (key : String) :
    Except String (Prod Node ParseContext) := do
  let value <- requiredField json key
  let raw <- nodeIdText value
  internNode context raw

def internNodeSet
    (context : ParseContext)
    (rawIds : List String) :
    Except String (Prod (Finset Node) ParseContext) :=
  rawIds.foldlM
      (init := (Finset.empty, context)) fun (nodes, current) raw => do
    let (node, next) <- internNode current raw
    pure (insert node nodes, next)

def parseRole (raw : String) : Except String Role :=
  match raw.toLower with
  | "leader" => .ok .leader
  | "follower" => .ok .follower
  | "prevotecandidate" => .ok .preVoteCandidate
  | "pre_vote_candidate" => .ok .preVoteCandidate
  | "candidate" => .ok .candidate
  | "none" => .ok .none
  | _ => .error s!"unsupported leadership_state: {raw}"

def optionalRoleField
    (json : Json)
    (key : String) :
    Except String (Option Role) :=
  match optionalField json key with
  | none => .ok none
  | some value => do
      let raw <- value.getStr?
      pure (some (<- parseRole raw))

def parseMembershipState
    (state : Json) :
    Except String (Option MembershipState) := do
  match optionalField state "membership_state" with
  | none => pure none
  | some membership =>
      let raw <- membership.getStr?
      match raw.toLower with
      | "active" => pure (some .active)
      | "retired" =>
          let phase <- requiredField state "retirement_phase"
          let phase <- phase.getStr?
          match phase.toLower with
          | "ordered" => pure (some .retirementOrdered)
          | "signed" => pure (some .retirementSigned)
          | "completed" => pure (some .retirementCompleted)
          | "retiredcommitted" => pure (some .retiredCommitted)
          | _ => throw s!"unsupported retirement_phase: {phase}"
      | _ => throw s!"unsupported membership_state: {raw}"

def projectLedgerIndex
    (bootstrapIndex visible : Nat) :
    Except String Nat :=
  if bootstrapIndex <= visible then
    .ok (visible - bootstrapIndex)
  else
    .error s!"index {visible} precedes bootstrap index {bootstrapIndex}"

def projectOptionalLedgerIndex
    (bootstrapIndex : Nat)
    (visible : Option Nat) :
    Except String (Option Nat) := do
  match visible with
  | none => .ok none
  | some value => pure (some (<- projectLedgerIndex bootstrapIndex value))

/-- CCF uses zero as an unset commit, sent, or match index. -/
def projectSentinelIndex
    (bootstrapIndex visible : Nat) :
    Except String Nat :=
  if visible == 0 then
    .ok 0
  else
    projectLedgerIndex bootstrapIndex visible

def projectOptionalSentinelIndex
    (bootstrapIndex : Nat)
    (visible : Option Nat) :
    Except String (Option Nat) := do
  match visible with
  | none => .ok none
  | some value => pure (some (<- projectSentinelIndex bootstrapIndex value))

def configurationNodeIds (message : Json) : Except String (List String) := do
  let configurations <- requiredField message "configurations"
  let values <- configurations.getArr?
  if values.size != 1 then
    throw
      "this trace-validation slice requires exactly one active configuration"
  let some initial := values[0]?
    | throw "bootstrap configurations must not be empty"
  let nodes <- requiredField initial "nodes"
  match nodes.getArr? with
  | .ok array => array.toList.mapM nodeIdText
  | .error _ =>
      let object <- nodes.getObj?
      pure object.keys

def configurationArgument
    (message : Json) :
    Except String (Nat × List String) := do
  let args <- requiredField message "args"
  let configuration <- requiredField args "configuration"
  let index <- requiredField configuration "idx" >>= jsonNat
  let nodes <- requiredField configuration "nodes"
  let nodeIds <-
    match nodes.getArr? with
    | .ok array => array.toList.mapM nodeIdText
    | .error _ =>
        let object <- nodes.getObj?
        pure object.keys
  pure (index, nodeIds)

def sameNodeIds (left right : List String) : Bool :=
  let left := left.eraseDups
  let right := right.eraseDups
  left.length == right.length &&
    left.all fun node => right.contains node

def ignoredRecord (line : String) : Except String Bool := do
  let json <- Json.parse line
  let tag <- (requiredField json "tag") >>= Json.getStr?
  if tag != "raft_trace" then
    throw s!"expected tag raft_trace, got {tag}"
  let message <- requiredField json "msg"
  let functionName <- (requiredField message "function") >>= Json.getStr?
  if
      functionName == "execute_append_entries_sync" ||
      functionName == "send_append_entries_response" ||
      functionName == "recv_append_entries_response" ||
      functionName == "become_candidate" then
    pure true
  else if functionName == "commit" then
    let state <- requiredField message "state"
    let role <- (requiredField state "leadership_state") >>= Json.getStr?
    pure (role.toLower != "leader")
  else
    pure false

structure RawPacket where
  term : Option Nat
  previousTerm : Option Nat
  leaderCommitIndex : Option Nat
  termOfIndex : Option Nat
  index : Option Nat
  previousIndex : Option Nat

def parsePacket
    (message : Json)
    (bootstrapIndex : Nat) :
    Except String
      (Option (Prod PacketObservation WirePacketObservation)) :=
  match optionalField message "packet" with
  | none => .ok none
  | some packet => do
      let raw : RawPacket := {
        term := <- optionalNatField packet "term"
        previousTerm := <- optionalNatField packet "prev_term"
        leaderCommitIndex := <- optionalNatField packet "leader_commit_idx"
        termOfIndex := <- optionalNatField packet "term_of_idx"
        index := <- optionalNatField packet "idx"
        previousIndex := <- optionalNatField packet "prev_idx"
      }
      let some term := raw.term
        | throw "AppendEntries packet is missing term"
      let some rawPreviousTerm := raw.previousTerm
        | throw "AppendEntries packet is missing prev_term"
      let some rawLeaderCommitIndex := raw.leaderCommitIndex
        | throw "AppendEntries packet is missing leader_commit_idx"
      let some rawTermOfIndex := raw.termOfIndex
        | throw "AppendEntries packet is missing term_of_idx"
      let some rawIndex := raw.index
        | throw "AppendEntries packet is missing idx"
      let some rawPreviousIndex := raw.previousIndex
        | throw "AppendEntries packet is missing prev_idx"
      let previousTerm :=
        if rawPreviousIndex <= bootstrapIndex then
          none
        else
          some rawPreviousTerm
      let termOfIndex :=
        if rawIndex <= bootstrapIndex then none else some rawTermOfIndex
      let projected : PacketObservation := {
        term := some term
        previousTerm
        leaderCommitIndex :=
          some (<- projectSentinelIndex
            bootstrapIndex rawLeaderCommitIndex)
        termOfIndex
        index := some (<- projectLedgerIndex bootstrapIndex rawIndex)
        previousIndex :=
          some (<- projectLedgerIndex bootstrapIndex rawPreviousIndex)
      }
      let wire : WirePacketObservation := {
        term
        previousTerm := rawPreviousTerm
        leaderCommitIndex := rawLeaderCommitIndex
        termOfIndex := rawTermOfIndex
        index := rawIndex
        previousIndex := rawPreviousIndex
      }
      pure (some (projected, wire))

def requiredArgumentIndex (message : Json) : Except String Nat := do
  let args <- requiredField message "args"
  jsonNat (<- requiredField args "idx")

def parseObservation
    (lineIndex : Nat)
    (context : ParseContext)
    (line : String) :
    Except String (Prod Observation ParseContext) := do
  let json <- Json.parse line
  let tag <- (requiredField json "tag") >>= Json.getStr?
  if tag != "raft_trace" then
    throw s!"expected tag raft_trace, got {tag}"
  let message <- requiredField json "msg"
  let functionRaw <- (requiredField message "function") >>= Json.getStr?
  let kind <- parseEventKind functionRaw
  let state <- requiredField message "state"
  let (node, context) <- parseNodeField context state "node_id"
  let bootstrapIndex <-
    match kind, context.bootstrapIndex with
    | .bootstrap, none =>
        if lineIndex == 0 then
          let index <- requiredArgumentIndex message
          if index == CCF_BOOTSTRAP_INDEX then
            pure index
          else
            throw s!"bootstrap args.idx is {index}, expected {
              CCF_BOOTSTRAP_INDEX}"
        else
          throw "bootstrap must be the first observation"
    | .bootstrap, some _ => throw "trace contains more than one bootstrap"
    | _, some index => pure index
    | _, none => throw "the first observation must be bootstrap"
  let currentTerm <- optionalNatField state "current_view"
  let view <- optionalNatField message "view"
  let rawLastIndex <- optionalNatField state "last_idx"
  let rawCommitIndex <- optionalNatField state "commit_idx"
  let role <- optionalRoleField state "leadership_state"
  let membershipState <- parseMembershipState state
  let preVoteEnabled <- optionalBoolField state "pre_vote_enabled"
  let preVoteStatus :=
    preVoteEnabled.map fun enabled =>
      if enabled then PreVoteStatus.enabled else .capable
  let context <- recordPreVoteStatus context node preVoteStatus
  let retirementIndex <-
    projectOptionalSentinelIndex bootstrapIndex
      (<- optionalNatField state "retirement_idx")
  let retirementCommittableIndex <-
    projectOptionalSentinelIndex bootstrapIndex
      (<- optionalNatField state "retirement_committable_idx")
  let retiredCommittedIndex <-
    projectOptionalSentinelIndex bootstrapIndex
      (<- optionalNatField state "retired_committed_idx")
  if
      currentTerm.isNone ||
      rawLastIndex.isNone ||
      rawCommitIndex.isNone ||
      role.isNone then
    throw
      "state requires current_view, last_idx, commit_idx, and leadership_state"
  let logLength <-
    match kind with
    | .bootstrap =>
        match rawLastIndex with
        | none => pure none
        | some value =>
            if value == bootstrapIndex then pure (some 0)
            else
              throw s!"bootstrap state.last_idx is {value}, expected {
                bootstrapIndex}"
    | _ => projectOptionalLedgerIndex bootstrapIndex rawLastIndex
  let commitIndex <-
    match kind with
    | .bootstrap => pure rawCommitIndex
    | _ => projectOptionalSentinelIndex bootstrapIndex rawCommitIndex
  let mut context := context
  let mut peer : Option Node := none
  let mut configuration : Option (Finset Node) := none
  match kind with
  | .sendAppendEntries =>
      let (parsed, next) <- parseNodeField context message "to_node_id"
      peer := some parsed
      context := next
  | .recvAppendEntries =>
      let (parsed, next) <- parseNodeField context message "from_node_id"
      peer := some parsed
      context := next
  | .recvProposeVote =>
      let (parsed, next) <- parseNodeField context message "from_node_id"
      peer := some parsed
      context := next

  | .addConfiguration =>
      let (_, rawNodes) <- configurationArgument message
      let (parsed, next) <- internNodeSet context rawNodes
      configuration := some parsed
      context := next
  | _ => pure ()
  let committable <- optionalBoolField message "globally_committable"
  let targetIndex <-
    match kind with
    | .bootstrap => pure (some 0)
    | .replicate =>
        let raw <- optionalNatField message "seqno"
        projectOptionalLedgerIndex bootstrapIndex raw
    | .addConfiguration =>
        let (rawIndex, _) <- configurationArgument message
        pure (some (<- projectLedgerIndex bootstrapIndex rawIndex))
    | .retiredCommitted =>
        let raw <- optionalNatField message "seqno"
        projectOptionalLedgerIndex bootstrapIndex raw
    | .sendAppendEntries | .recvAppendEntries |
        .proposeVote | .recvProposeVote => pure none
    | .commit =>
        pure (some (<- projectLedgerIndex bootstrapIndex
          (<- requiredArgumentIndex message)))
  let proposalTerm <-
    match kind with
    | .recvProposeVote =>
        match optionalField message "packet" with
        | none => throw "recv_propose_request_vote is missing packet"
        | some packet =>
            pure (some (<- jsonNat (<- requiredField packet "term")))
    | _ => pure none
  let parsedPacket <-
    match kind with
    | .sendAppendEntries | .recvAppendEntries =>
        parsePacket message bootstrapIndex
    | _ => pure none
  let packet := parsedPacket.map Prod.fst
  let wirePacket := parsedPacket.map Prod.snd
  let sentIndex <-
    projectOptionalSentinelIndex bootstrapIndex
      (<- optionalNatField message "sent_idx")
  let matchIndex <-
    projectOptionalSentinelIndex bootstrapIndex
      (<- optionalNatField message "match_idx")
  if kind == .replicate &&
      (committable.isNone || targetIndex.isNone || view.isNone) then
    throw "replicate requires view, seqno, and globally_committable"
  if kind == .sendAppendEntries &&
      (peer.isNone ||
        (packet.bind fun value => value.index).isNone ||
        sentIndex.isNone ||
        matchIndex.isNone) then
    throw
      "send_append_entries requires packet, to_node_id, sent_idx, and match_idx"
  if kind == .recvAppendEntries &&
      (peer.isNone || packet.isNone) then
    throw "recv_append_entries requires packet and from_node_id"
  if kind == .recvProposeVote && peer.isNone then
    throw "recv_propose_request_vote requires from_node_id"
  match packet with
  | some packet =>
      let some previous := packet.previousIndex
        | throw "AppendEntries packet is missing prev_idx"
      let some index := packet.index
        | throw "AppendEntries packet is missing idx"
      if index != previous && index != previous + 1 then
        throw
          "this trace-validation slice supports only heartbeats and one-entry AppendEntries"
  | none => pure ()
  let finalContext <-
    match kind with
    | .bootstrap =>
        let initialIds <- configurationNodeIds message
        let distinctIds := initialIds.eraseDups
        let some leaderId := context.nodeIds[node.val]?
          | throw "internal bootstrap node-map invariant failed"
        if !distinctIds.contains leaderId then
          throw
            "bootstrap configuration must be nonempty and contain the observed leader"
        let (bootstrapConfiguration, seeded) <-
          internNodeSet context distinctIds
        if leaderMember : Membership.mem bootstrapConfiguration node then
          let bootstrap : Bootstrap Node := {
            configuration := bootstrapConfiguration
            leader := node
            leader_mem := leaderMember
          }
          pure {
            seeded with
            initialNodeIds := distinctIds
            bootstrapIndex := some bootstrapIndex
            bootstrap := some bootstrap
          }
        else
          throw
            "internal bootstrap membership invariant failed"
    | .commit =>
        pure context
    | _ => pure context
  pure ({
    line := lineIndex + 1
    kind
    node
    peer
    role
    preVoteStatus
    membershipState
    retirementIndex
    retirementCommittableIndex
    retiredCommittedIndex
    configuration
    currentTerm
    view
    logLength
    commitIndex
    targetIndex
    committable
    proposalTerm
    packet
    wirePacket
    sentIndex
    matchIndex
  }, finalContext)

/--
Mirror the reducer's callback grouping before canonical search:

* a leader `replicate` immediately followed by `add_configuration` is one
  `changeConfiguration` action;
* a follower `add_configuration` callback belongs to the preceding receive.
-/
def coalesceObservations :
    List Observation -> Except String (List Observation × Nat)
  | [] => .ok ([], 0)
  | [observation] => .ok ([observation], 0)
  | first :: second :: remaining =>
      match first.kind, second.kind, second.role with
      | .replicate, .addConfiguration, some .leader =>
          if _sameNode : first.node = second.node then
            if _noncommittable : first.committable = some false then
              if _sameIndex : first.targetIndex = second.targetIndex then
                coalesceObservations (second :: remaining) >>= fun result =>
                  .ok (result.1, result.2 + 1)
              else
                .error
                  s!"line {second.line}: configuration callback index differs from preceding replicate"
            else
              .error
                s!"line {second.line}: leader configuration callback lacks a noncommittable replicate"
          else
            coalesceObservations (second :: remaining) >>= fun result =>
              .ok (first :: result.1, result.2)
      | .recvAppendEntries, .addConfiguration, role =>
          if _followerCallback : role != some .leader then
            if _sameNode : first.node = second.node then
              if _sameIndex :
                  (first.packet.bind fun packet => packet.index) =
                    second.targetIndex then
                coalesceObservations remaining >>= fun result =>
                  .ok (first :: result.1, result.2 + 1)
              else
                .error
                  s!"line {second.line}: follower configuration callback index differs from received AppendEntries"
            else
              coalesceObservations (second :: remaining) >>= fun result =>
                .ok (first :: result.1, result.2)
          else
            coalesceObservations (second :: remaining) >>= fun result =>
              .ok (first :: result.1, result.2)
      | _, _, _ =>
          coalesceObservations (second :: remaining) >>= fun result =>
            .ok (first :: result.1, result.2)

def parseLines
    (lines : List String)
    (lineIndex : Nat := 0)
    (context : ParseContext := {})
    (observations : Array Observation := #[])
    (ignoredRecords : Nat := 0) :
    Except String ParsedTrace :=
  match lines with
  | [] =>
      match context.bootstrapIndex, context.bootstrap with
      | some bootstrapIndex, some bootstrap =>
          match coalesceObservations observations.toList with
          | .error message => .error message
          | .ok (coalesced, coalescedRecords) =>
              let bootstrap :=
                bootstrapWithRecordedPreVoteStatuses context bootstrap
              .ok {
                observations := coalesced.toArray
                bootstrapIndex
                bootstrap
                nodeIds := context.nodeIds
                ignoredRecords := ignoredRecords + coalescedRecords
              }
      | _, _ => .error "trace is empty or has no bootstrap observation"
  | line :: remaining =>
      if line.trimAscii.isEmpty then
        parseLines remaining (lineIndex + 1) context observations ignoredRecords
      else
        match ignoredRecord line with
        | .error message => .error s!"line {lineIndex + 1}: {message}"
        | .ok true =>
            parseLines remaining (lineIndex + 1) context observations
              (ignoredRecords + 1)
        | .ok false =>
            match parseObservation lineIndex context line with
            | .error message => .error s!"line {lineIndex + 1}: {message}"
            | .ok (observation, nextContext) =>
                parseLines remaining (lineIndex + 1) nextContext
                  (observations.push observation) ignoredRecords

def parseTraceFile (path : System.FilePath) : IO (Except String ParsedTrace) := do
  let content <- IO.FS.readFile path
  pure (parseLines (content.splitOn "\n"))

def check (condition : Bool) (message : String) : Except String Unit :=
  if condition then pure () else throw message

def requireSome {alpha : Type}
    (label : String)
    (value : Option alpha) :
    Except String alpha :=
  match value with
  | some present => pure present
  | none => throw s!"missing required field {label}"

def roleName : Role -> String
  | .none => "none"
  | .follower => "follower"
  | .preVoteCandidate => "pre-vote-candidate"
  | .candidate => "candidate"
  | .leader => "leader"

def checkOptional {alpha : Type} [BEq alpha] [ToString alpha]
    (label : String)
    (observed : Option alpha)
    (actual : alpha) :
    Except String Unit :=
  match observed with
  | none => pure ()
  | some expected =>
      check (expected == actual)
        s!"{label}: observed {expected}, model has {actual}"

def checkVisibleState
    (observation : Observation)
    (state : SimState) :
    Except String Unit := do
  let nodeState := state.nodes observation.node
  checkOptional "state.current_view" observation.currentTerm
    nodeState.currentTerm
  checkOptional "state.last_idx" observation.logLength
    nodeState.log.length
  checkOptional "state.commit_idx" observation.commitIndex
    nodeState.commitIndex
  match observation.role with
  | none => pure ()
  | some expected =>
      check (expected == nodeState.role)
        s!"state.leadership_state: observed {roleName expected}, model has {
          roleName nodeState.role}"
  match observation.preVoteStatus with
  | none => pure ()
  | some expected =>
      check (expected = state.preVoteStatus observation.node)
        "state.pre_vote_enabled disagrees with the model pre-vote status"
  match observation.membershipState with
  | none => pure ()
  | some expected =>
      check (expected = nodeState.membershipState)
        "state membership/retirement phase disagrees with the model"
  match observation.retirementIndex with
  | none => pure ()
  | some expected =>
      check (nodeState.retirementIndex = some expected)
        "state.retirement_idx disagrees with the model"
  match observation.retirementCommittableIndex with
  | none => pure ()
  | some expected =>
      check (nodeState.retirementCommittableIndex = some expected)
        "state.retirement_committable_idx disagrees with the model"
  match observation.retiredCommittedIndex with
  | none => pure ()
  | some expected =>
      check (nodeState.retiredCommittedIndex = some expected)
        "state.retired_committed_idx disagrees with the model"

def packetTailTerm (request : AppendEntriesRequest Node TxId) : Nat :=
  match request.entries.getLast? with
  | some entry => entry.term
  | none => request.prevLogTerm

section Bootstrap

variable [Bootstrap Node]

def checkPacket
    (packet : PacketObservation)
    (request : AppendEntriesRequest Node TxId) :
    Except String Unit := do
  checkOptional "packet.term" packet.term request.term
  checkOptional "packet.prev_term" packet.previousTerm request.prevLogTerm
  checkOptional "packet.leader_commit_idx" packet.leaderCommitIndex
    request.leaderCommit
  checkOptional "packet.term_of_idx" packet.termOfIndex
    (packetTailTerm request)
  checkOptional "packet.idx" packet.index
    (request.prevLogIndex + request.entries.length)
  checkOptional "packet.prev_idx" packet.previousIndex request.prevLogIndex

structure EventSpec where
  pre : Observation -> SimState -> Except String Unit
  candidateSteps :
    Observation -> SimState -> Except String (List (List SimAction))
  post : Observation -> SimState -> SimState -> Except String Unit

def bootstrapPre
    (observation : Observation)
    (state : SimState) :
    Except String Unit := do
  checkVisibleState observation state
  check (observation.node == INITIAL_LEADER)
    "bootstrap does not name the initial leader"

def bootstrapCandidates
    (_ : Observation)
    (_ : SimState) :
    Except String (List (List SimAction)) :=
  pure [[]]

def bootstrapPost
    (_ : Observation)
    (_ _ : SimState) :
    Except String Unit :=
  pure ()

def replicatePre
    (observation : Observation)
    (state : SimState) :
    Except String Unit := do
  checkVisibleState observation state
  let _ <- requireSome "msg.seqno" observation.targetIndex
  let _ <- requireSome "msg.globally_committable" observation.committable
  checkOptional "msg.view" observation.view
    (state.nodes observation.node).currentTerm
  pure ()

def replicateCandidates
    (observation : Observation)
    (state : SimState) :
    Except String (List (List SimAction)) := do
  let committable <-
    requireSome "msg.globally_committable" observation.committable
  if committable then
    pure [[.signCommittableMessages observation.node]]
  else if
      (state.nodes observation.node).membershipState =
        .retirementCompleted then
    pure [[.appendRetiredCommitted observation.node]]
  else
    let some txId :=
      allTxIds.find? fun candidate =>
        decide (Not (Membership.mem state.submittedTxIds candidate))
      | throw s!"trace needs more than {TX_COUNT} distinct transaction IDs"
    pure [[.clientRequest observation.node txId]]

def replicatePost
    (observation : Observation)
    (_ : SimState)
    (after : SimState) :
    Except String Unit := do
  let target <- requireSome "msg.seqno" observation.targetIndex
  check ((after.nodes observation.node).log.length == target)
    s!"replicate post-state log length is {
      (after.nodes observation.node).log.length}, expected {target}"

def addConfigurationPre
    (observation : Observation)
    (state : SimState) :
    Except String Unit := do
  checkVisibleState observation state
  let _ <- requireSome "msg.args.configuration" observation.configuration
  let _ <- requireSome "msg.args.configuration.idx" observation.targetIndex
  pure ()

def addConfigurationCandidates
    (observation : Observation)
    (_ : SimState) :
    Except String (List (List SimAction)) := do
  let configuration <-
    requireSome "msg.args.configuration" observation.configuration
  pure [[.changeConfiguration observation.node configuration]]

def addConfigurationPost
    (observation : Observation)
    (_ : SimState)
    (after : SimState) :
    Except String Unit := do
  let target <- requireSome "msg.args.configuration.idx" observation.targetIndex
  check ((after.nodes observation.node).log.length == target)
    s!"add_configuration post-state log length is {
      (after.nodes observation.node).log.length}, expected {target}"

def retiredCommittedPre
    (observation : Observation)
    (state : SimState) :
    Except String Unit :=
  checkVisibleState observation state

def retiredCommittedCandidates
    (observation : Observation)
    (_ : SimState) :
    Except String (List (List SimAction)) :=
  pure [[.appendRetiredCommitted observation.node]]

def retiredCommittedPost
    (observation : Observation)
    (_ : SimState)
    (after : SimState) :
    Except String Unit := do
  match observation.targetIndex with
  | none => pure ()
  | some target =>
      check ((after.nodes observation.node).log.length == target)
        s!"retired-committed post-state log length is {
          (after.nodes observation.node).log.length}, expected {target}"

def sendAppendPre
    (observation : Observation)
    (state : SimState) :
    Except String Unit := do
  checkVisibleState observation state
  let destination <- requireSome "msg.to_node_id" observation.peer
  let packet <- requireSome "msg.packet" observation.packet
  let batchEnd <- requireSome "msg.packet.idx" packet.index
  let request :=
    makeAppendEntriesRequest state observation.node destination batchEnd
  checkPacket packet request
  checkOptional "msg.sent_idx" observation.sentIndex
    ((state.nodes observation.node).sentIndex destination)
  checkOptional "msg.match_idx" observation.matchIndex
    ((state.nodes observation.node).matchIndex destination)

def sendAppendCandidates
    (observation : Observation)
    (_ : SimState) :
    Except String (List (List SimAction)) := do
  let destination <- requireSome "msg.to_node_id" observation.peer
  let packet <- requireSome "msg.packet" observation.packet
  let batchEnd <- requireSome "msg.packet.idx" packet.index
  pure [[.appendEntries observation.node destination batchEnd]]

def sendAppendPost
    (observation : Observation)
    (_ : SimState)
    (after : SimState) :
    Except String Unit := do
  let destination <- requireSome "msg.to_node_id" observation.peer
  let packet <- requireSome "msg.packet" observation.packet
  let batchEnd <- requireSome "msg.packet.idx" packet.index
  check ((after.nodes observation.node).sentIndex destination == batchEnd)
    s!"send_append_entries post-state sent index is {
      (after.nodes observation.node).sentIndex destination}, expected {batchEnd}"

def recvAppendPre
    (observation : Observation)
    (state : SimState) :
    Except String Unit := do
  checkVisibleState observation state
  let source <- requireSome "msg.from_node_id" observation.peer
  let packet <- requireSome "msg.packet" observation.packet
  match takeFirstFrom source (state.network observation.node) with
  | some (.appendEntriesRequest request, _) => checkPacket packet request
  | some _ =>
      throw "recv_append_entries: next queued message is not AppendEntries"
  | none =>
      throw "recv_append_entries: no queued model message from source"

def recvAppendCandidates
    (observation : Observation)
    (_ : SimState) :
    Except String (List (List SimAction)) := do
  let source <- requireSome "msg.from_node_id" observation.peer
  pure [[.receive source observation.node]]

def recvAppendPost
    (_ : Observation)
    (_ _ : SimState) :
    Except String Unit :=
  pure ()

def proposeVotePre
    (observation : Observation)
    (state : SimState) :
    Except String Unit :=
  checkVisibleState observation state

def proposeVoteCandidates
    (observation : Observation)
    (_ : SimState) :
    Except String (List (List SimAction)) :=
  pure
    (allNodes.map fun destination =>
      [.proposeVote observation.node destination])

def proposeVotePost
    (observation : Observation)
    (_ : SimState)
    (after : SimState) :
    Except String Unit :=
  check
    (allNodes.any fun destination =>
      (after.network destination).any fun message =>
        match message with
        | .proposeVoteRequest request =>
            request.source == observation.node
        | _ => false)
    "proposal post-state has no queued ProposeVoteRequest"

def recvProposeVotePre
    (observation : Observation)
    (state : SimState) :
    Except String Unit := do
  checkVisibleState observation state
  let source <- requireSome "msg.from_node_id" observation.peer
  let term <- requireSome "msg.packet.term" observation.proposalTerm
  match takeFirstFrom source (state.network observation.node) with
  | some (.proposeVoteRequest request, _) =>
      check (request.term == term)
        "recv_propose_request_vote packet term differs from queued proposal"
  | some _ =>
      throw "recv_propose_request_vote: next queued message is not proposal"
  | none =>
      throw "recv_propose_request_vote: no queued proposal from source"

def recvProposeVoteCandidates
    (observation : Observation)
    (_ : SimState) :
    Except String (List (List SimAction)) := do
  let source <- requireSome "msg.from_node_id" observation.peer
  pure [[.receive source observation.node]]

def recvProposeVotePost
    (_ : Observation)
    (_ _ : SimState) :
    Except String Unit :=
  pure ()

def coalescedRecvPre
    (observation : Observation)
    (state : SimState) :
    Except String Unit :=
  checkVisibleState observation state

def coalescedRecvCandidates
    (_ : Observation)
    (_ : SimState) :
    Except String (List (List SimAction)) :=
  pure [[]]

def coalescedRecvPost
    (_ : Observation)
    (_ _ : SimState) :
    Except String Unit :=
  pure ()

def coalescedRecvSpec : EventSpec := {
  pre := coalescedRecvPre
  candidateSteps := coalescedRecvCandidates
  post := coalescedRecvPost
}

def commitPre
    (observation : Observation)
    (state : SimState) :
    Except String Unit := do
  checkVisibleState observation state
  let _ <- requireSome "msg.args.idx" observation.targetIndex
  pure ()

def commitCandidates
    (observation : Observation)
    (state : SimState) :
    Except String (List (List SimAction)) :=
  if terminalRetirementCommit state observation.node then
    pure
      (allNodes.map fun destination =>
        [.advanceCommitIndexAndProposeVote observation.node destination])
  else
    pure [[.advanceCommitIndex observation.node]]

def commitPost
    (observation : Observation)
    (_ : SimState)
    (after : SimState) :
    Except String Unit := do
  let target <- requireSome "msg.args.idx" observation.targetIndex
  check ((after.nodes observation.node).commitIndex == target)
    s!"commit post-state index is {
      (after.nodes observation.node).commitIndex}, expected {target}"

def eventSpec : EventKind -> EventSpec
  | .bootstrap => {
      pre := bootstrapPre
      candidateSteps := bootstrapCandidates
      post := bootstrapPost
    }
  | .replicate => {
      pre := replicatePre
      candidateSteps := replicateCandidates
      post := replicatePost
    }
  | .addConfiguration => {
      pre := addConfigurationPre
      candidateSteps := addConfigurationCandidates
      post := addConfigurationPost
    }
  | .retiredCommitted => {
      pre := retiredCommittedPre
      candidateSteps := retiredCommittedCandidates
      post := retiredCommittedPost
    }
  | .sendAppendEntries => {
      pre := sendAppendPre
      candidateSteps := sendAppendCandidates
      post := sendAppendPost
    }
  | .recvAppendEntries => {
      pre := recvAppendPre
      candidateSteps := recvAppendCandidates
      post := recvAppendPost
    }
  | .proposeVote => {
      pre := proposeVotePre
      candidateSteps := proposeVoteCandidates
      post := proposeVotePost
    }
  | .recvProposeVote => {
      pre := recvProposeVotePre
      candidateSteps := recvProposeVoteCandidates
      post := recvProposeVotePost
    }
  | .commit => {
      pre := commitPre
      candidateSteps := commitCandidates
      post := commitPost
    }

def applyCanonical
    (start : SimState)
    (actions : List SimAction) :
    Except String SimState :=
  actions.foldlM (init := start) fun state action => do
    let some nextState :=
      (system (Node := Node) (TxId := TxId)).applyAction state action
      | throw s!"disabled canonical action: {renderAction action}"
    pure (compactState nextState)

def applyChecked
    (start : SimState)
    (actions : List SimAction) :
    Except String SimState :=
  actions.foldlM (init := start) fun state action => do
    let nextState <- applyCanonical state [action]
    check (stateChecks nextState)
      s!"state checks failed after canonical action: {renderAction action}"
    check (edgeChecks state nextState)
      s!"edge checks failed after canonical action: {renderAction action}"
    pure nextState

/-- Exact canonical enablement for every action in a witness. -/
def ExactRun : SimState -> List SimAction -> Prop
  | _, [] => True
  | state, action :: actions =>
      Enabled state action /\ ExactRun (next state action) actions

private def exactRunDecidable :
    (state : SimState) ->
      (actions : List SimAction) ->
        Decidable (ExactRun state actions)
  | _, [] => isTrue trivial
  | state, action :: actions =>
      match
        (inferInstanceAs (Decidable (Enabled state action))),
        exactRunDecidable (next state action) actions
      with
      | isTrue enabled, isTrue remaining =>
          isTrue (And.intro enabled remaining)
      | isFalse disabled, _ =>
          isFalse fun run => disabled run.1
      | _, isFalse invalidTail =>
          isFalse fun run => invalidTail run.2

instance (state : SimState) (actions : List SimAction) :
    Decidable (ExactRun state actions) :=
  exactRunDecidable state actions

def stateAfter
    (state : SimState)
    (actions : List SimAction) :
    SimState :=
  actions.foldl next state

def exceptSucceeded : Except String Unit -> Bool
  | .ok () => true
  | .error _ => false

def checkpointHolds
    (actions : List SimAction)
    (checkpoint : Checkpoint) :
    Bool :=
  if checkpoint.step > actions.length then
    false
  else
    let state :=
      stateAfter (initialState : SimState) (actions.take checkpoint.step)
    let spec :=
      if checkpoint.coalescedReceive then
        coalescedRecvSpec
      else
        eventSpec checkpoint.observation.kind
    exceptSucceeded (spec.pre checkpoint.observation state) &&
      match spec.candidateSteps checkpoint.observation state with
      | .error _ => false
      | .ok candidates =>
          candidates.any fun steps =>
            checkpoint.step + steps.length <= actions.length &&
              decide (
                (actions.drop checkpoint.step).take steps.length = steps) &&
              match applyCanonical state steps with
              | .error _ => false
              | .ok after =>
                  exceptSucceeded
                    (spec.post checkpoint.observation state after)

def checkpointsHold
    (actions : List SimAction)
    (checkpoints : List Checkpoint) :
    Bool :=
  checkpoints.all (checkpointHolds actions)

def CertificateValid
    (actions : List SimAction)
    (checkpoints : List Checkpoint) :
    Prop :=
  ExactRun (initialState : SimState) actions /\
    checkpointsHold actions checkpoints = true

theorem exactRunReachable
    {state : SimState}
    {actions : List SimAction}
    (reachable : Reachable state)
    (run : ExactRun state actions) :
    Reachable (actions.foldl next state) := by
  induction actions generalizing state with
  | nil =>
      simpa using reachable
  | cons action actions inductionHypothesis =>
      exact
        inductionHypothesis
          (Reachable.step reachable run.1)
          run.2

def nodeSetCode (nodes : Finset Node) : String :=
  String.intercalate "."
    ((allNodes.filter fun node => decide (Membership.mem nodes node)).map
      fun node => toString node.val)

def txSetCode (txIds : Finset TxId) : String :=
  String.intercalate "."
    ((allTxIds.filter fun txId => decide (Membership.mem txIds txId)).map
      fun txId => toString txId.val)

def entryCode : Entry Node TxId -> String
  | { term, content := .transaction txId } => s!"{term}:t{txId.val}"
  | { term, content := .signature } => s!"{term}:s"
  | { term, content := .reconfiguration nodes } =>
      s!"{term}:c[{nodeSetCode nodes}]"
  | { term, content := .retiredCommitted nodes } =>
      s!"{term}:r[{nodeSetCode nodes}]"

def messageCode : Message Node TxId -> String
  | .appendEntriesRequest request =>
      let entries := String.intercalate "." (request.entries.map entryCode)
      s!"aq:{request.source.val}:{request.destination.val}:{request.term}:{
        request.prevLogIndex}:{request.prevLogTerm}:{
        request.entries.length}:[{entries}]:{request.leaderCommit}"
  | .appendEntriesResponse response =>
      s!"ap:{response.source.val}:{response.destination.val}:{response.term}:{
        response.success}:{response.lastLogIndex}"
  | .requestVoteRequest request =>
      s!"vq:{request.source.val}:{request.destination.val}:{request.term}:{
        request.lastCommittableTerm}:{request.lastCommittableIndex}"
  | .requestVoteResponse response =>
      s!"vp:{response.source.val}:{response.destination.val}:{response.term}:{
        response.voteGranted}"
  | .requestPreVote request =>
      s!"pvq:{request.source.val}:{request.destination.val}:{request.term}:{
        request.lastCommittableTerm}:{request.lastCommittableIndex}"
  | .requestPreVoteResponse response =>
      s!"pvp:{response.source.val}:{response.destination.val}:{response.term}:{
        response.voteGranted}"
  | .proposeVoteRequest request =>
      s!"prv:{request.source.val}:{request.destination.val}:{request.term}"

def nodeStateCode (state : NodeState Node TxId) : String :=
  let sent :=
    String.intercalate "." (allNodes.map fun node => toString (state.sentIndex node))
  let matched :=
    String.intercalate "." (allNodes.map fun node => toString (state.matchIndex node))
  let log := String.intercalate "." (state.log.map entryCode)
  let votedFor := state.votedFor.map (fun node => toString node.val) |>.getD "-"
  let membership :=
    match state.membershipState with
    | .active => "active"
    | .retirementOrdered => "ordered"
    | .retirementSigned => "signed"
    | .retirementCompleted => "completed"
    | .retiredCommitted => "retired-committed"
  s!"{roleName state.role},{state.currentTerm},{state.commitIndex},[{log}],{
    sent},{matched},{state.isNewFollower},{votedFor},{
    nodeSetCode state.votesGranted},{nodeSetCode state.preVotesGranted},{
    membership},{state.retirementIndex},{state.retirementCommittableIndex},{
    state.retiredCommittedIndex}"

def stateKey (state : SimState) : String :=
  let nodes :=
    String.intercalate "|"
      (allNodes.map fun node => nodeStateCode (state.nodes node))
  let network :=
    String.intercalate "|"
      (allNodes.map fun node =>
        String.intercalate "." ((state.network node).map messageCode))
  let preVoteStatus :=
    String.intercalate "."
      (allNodes.map fun node =>
        match state.preVoteStatus node with
        | .capable => "c"
        | .enabled => "e")
  let retirementCompleted :=
    String.intercalate "|"
      (allNodes.map fun node => nodeSetCode (state.retirementCompleted node))
  s!"{nodes}#{network}#{txSetCode state.submittedTxIds}#{
    nodeSetCode state.hasJoined}#{preVoteStatus}#{retirementCompleted}"

/--
The five-event slice omits AppendEntries response records. Those response
deliveries are the only transitions the search may insert.
-/
def hiddenActions (state : SimState) : List SimAction :=
  allNodes.flatMap fun destination =>
    allNodes.filterMap fun source =>
      match takeFirstFrom source (state.network destination) with
      | some (.appendEntriesResponse _, _) =>
          some (.receive source destination)
      | _ => none

structure PendingSend where
  source : Node
  destination : Node
  packet : WirePacketObservation
  requiresModelReceive : Bool
  deriving DecidableEq

def pendingSendIndex
    (pending : List PendingSend)
    (observation : Observation) :
    Except String Nat := do
  let source <- requireSome "msg.from_node_id" observation.peer
  let packet <- requireSome "msg.packet" observation.wirePacket
  let some index :=
    pending.findIdx? fun candidate =>
      candidate.source == source &&
        candidate.destination == observation.node &&
        decide (candidate.packet = packet)
    | throw "recv_append_entries has no preceding unmatched send observation"
  pure index

def selectedEventSpec
    (pending : List PendingSend)
    (observation : Observation) :
    Except String (Prod EventSpec Bool) :=
  match observation.kind with
  | .recvAppendEntries => do
      let index <- pendingSendIndex pending observation
      let some send := pending[index]?
        | throw "internal pending-send index invariant failed"
      if send.requiresModelReceive then
        pure (eventSpec observation.kind, false)
      else
        pure (coalescedRecvSpec, true)
  | _ => pure (eventSpec observation.kind, false)

def updatePendingSends
    (pending : List PendingSend)
    (observation : Observation)
    (before after : SimState) :
    Except String (List PendingSend) :=
  match observation.kind with
  | .sendAppendEntries => do
      let destination <- requireSome "msg.to_node_id" observation.peer
      let packet <- requireSome "msg.packet" observation.wirePacket
      pure (pending ++ [{
        source := observation.node
        destination
        packet
        requiresModelReceive :=
          decide (before.network destination != after.network destination)
      }])
  | .recvAppendEntries => do
      let index <- pendingSendIndex pending observation
      pure (pending.eraseIdx index)
  | _ => pure pending

def pendingSendCode (send : PendingSend) : String :=
  s!"{send.source.val}:{send.destination.val}:{
    send.packet.term}:{send.packet.previousTerm}:{
    send.packet.leaderCommitIndex}:{send.packet.termOfIndex}:{
    send.packet.index}:{send.packet.previousIndex}:{
    send.requiresModelReceive}"

def pendingRequestsDrained (state : SimState) : Bool :=
  allNodes.all fun destination =>
    (state.network destination).all fun message =>
      match message with
      | .appendEntriesRequest _ => false
      | _ => true

structure SearchConfig where
  maxDepth : Nat
  maxGap : Nat
  maxStates : Nat

structure SearchStats where
  expanded : Nat := 0
  visibleCandidates : Nat := 0
  hiddenCandidates : Nat := 0
  deduplicated : Nat := 0
  depthPruned : Nat := 0
  gapPruned : Nat := 0
  assertionFailures : Nat := 0
  furthestObservation : Nat := 0
  deriving Repr

structure SearchNode where
  state : SimState
  observationIndex : Nat := 0
  gap : Nat := 0
  depth : Nat := 0
  traceRev : List SimAction := []
  checkpointsRev : List Checkpoint := []
  pendingSends : List PendingSend := []

structure SearchState where
  seen : Std.HashSet String := {}
  stats : SearchStats := {}
  limitHit : Bool := false
  stateLimitHit : Bool := false
  latestFailure : Option (Prod Nat String) := none

abbrev SearchM := StateM SearchState

def SearchNode.memoKey (node : SearchNode) : String :=
  let pending :=
    String.intercalate "|" (node.pendingSends.map pendingSendCode)
  s!"{node.observationIndex}/{node.gap}/{node.depth}/{pending}/{
    stateKey node.state}"

def recordFailure
    (observationIndex : Nat)
    (message : String) :
    SearchM Unit :=
  modify fun search =>
    let latestFailure :=
      match search.latestFailure with
      | some previous =>
          if observationIndex < previous.1 then
            search.latestFailure
          else
            some (observationIndex, message)
      | none => some (observationIndex, message)
    {
      search with
      latestFailure
      stats := {
        search.stats with
        assertionFailures := search.stats.assertionFailures + 1
      }
    }

inductive ExpansionResult where
  | expanded
  | duplicate
  | stateLimit

def recordExpanded
    (node : SearchNode)
    (maxStates : Nat) :
    SearchM ExpansionResult := do
  let search <- get
  if search.seen.contains node.memoKey then
    set {
      search with
      stats := {
        search.stats with
        deduplicated := search.stats.deduplicated + 1
      }
    }
    pure .duplicate
  else if search.stats.expanded >= maxStates then
    set { search with limitHit := true, stateLimitHit := true }
    pure .stateLimit
  else
    set {
      search with
      seen := search.seen.insert node.memoKey
      stats := {
        search.stats with
        expanded := search.stats.expanded + 1
        furthestObservation :=
          max search.stats.furthestObservation node.observationIndex
      }
    }
    pure .expanded

partial def searchNode
    (observations : Array Observation)
    (config : SearchConfig)
    (node : SearchNode) :
    SearchM (Option SearchNode) := do
  match <- recordExpanded node config.maxStates with
  | .duplicate | .stateLimit => return none
  | .expanded => pure ()
  if node.observationIndex >= observations.size then
    if node.pendingSends.isEmpty && pendingRequestsDrained node.state then
      return some node
    recordFailure node.observationIndex
      "trace ended before every observed AppendEntries send was received"
    return none
  let observation := observations[node.observationIndex]!
  let selection := selectedEventSpec node.pendingSends observation
  let some selected := selection.toOption
    | match selection with
      | .error message =>
          recordFailure node.observationIndex
            s!"line {observation.line} {
              observation.kind.name}: {message}"
      | .ok _ => pure ()
      return none
  let spec := selected.1
  let coalescedReceive := selected.2
  match spec.pre observation node.state with
  | .error message =>
      recordFailure node.observationIndex
        s!"line {observation.line} {observation.kind.name}: {message}"
  | .ok () =>
      match spec.candidateSteps observation node.state with
      | .error message =>
          recordFailure node.observationIndex
            s!"line {observation.line} {observation.kind.name}: {message}"
      | .ok candidates =>
          for steps in candidates do
            modify fun search => {
              search with
              stats := {
                search.stats with
                visibleCandidates := search.stats.visibleCandidates + 1
              }
            }
            if node.depth + steps.length > config.maxDepth then
              modify fun search => {
                search with
                limitHit := true
                stats := {
                  search.stats with
                  depthPruned := search.stats.depthPruned + 1
                }
              }
            else
              match applyChecked node.state steps with
              | .error message =>
                  recordFailure node.observationIndex
                    s!"line {observation.line} {
                      observation.kind.name}: {message}"
              | .ok after =>
                  match spec.post observation node.state after with
                  | .error message =>
                      recordFailure node.observationIndex
                        s!"line {observation.line} {
                          observation.kind.name}: {message}"
                  | .ok () =>
                      match
                        updatePendingSends
                          node.pendingSends observation node.state after
                      with
                      | .error message =>
                          recordFailure node.observationIndex
                            s!"line {observation.line} {
                              observation.kind.name}: {message}"
                      | .ok pendingSends =>
                          let result <- searchNode observations config {
                            state := after
                            observationIndex := node.observationIndex + 1
                            gap := 0
                            depth := node.depth + steps.length
                            traceRev := steps.reverse ++ node.traceRev
                            checkpointsRev := {
                              step := node.depth
                              observation
                              coalescedReceive
                            } :: node.checkpointsRev
                            pendingSends
                          }
                          if result.isSome then
                            return result
  if node.depth >= config.maxDepth then
    modify fun search => {
      search with
      limitHit := true
      stats := {
        search.stats with
        depthPruned := search.stats.depthPruned + 1
      }
    }
    return none
  if node.gap >= config.maxGap then
    modify fun search => {
      search with
      limitHit := true
      stats := {
        search.stats with
        gapPruned := search.stats.gapPruned + 1
      }
    }
    return none
  for action in hiddenActions node.state do
    modify fun search => {
      search with
      stats := {
        search.stats with
        hiddenCandidates := search.stats.hiddenCandidates + 1
      }
    }
    match applyChecked node.state [action] with
    | .error message => recordFailure node.observationIndex message
    | .ok after =>
        let result <- searchNode observations config {
          state := after
          observationIndex := node.observationIndex
          gap := node.gap + 1
          depth := node.depth + 1
          traceRev := action :: node.traceRev
          checkpointsRev := node.checkpointsRev
          pendingSends := node.pendingSends
        }
        if result.isSome then
          return result
  return none

structure SearchOutcome where
  witness : Option SearchNode
  stats : SearchStats
  limitHit : Bool
  stateLimitHit : Bool
  latestFailure : Option (Prod Nat String)

private def searchWithBootstrap
    (trace : ParsedTrace)
    (config : SearchConfig) :
    SearchOutcome :=
  let initial : SearchNode := {
    state := compactState (initialState : SimState)
  }
  let (witness, finalSearch) :=
    (searchNode trace.observations config initial).run {}
  {
    witness
    stats := finalSearch.stats
    limitHit := finalSearch.limitHit
    stateLimitHit := finalSearch.stateLimitHit
    latestFailure := finalSearch.latestFailure
  }

end Bootstrap

/--
Interpret a witness and its observation checkpoints under the bootstrap parsed
from the same implementation trace.
-/
def ParsedCertificateValid
    (trace : ParsedTrace)
    (actions : List SimAction)
    (checkpoints : List Checkpoint) :
    Prop :=
  @CertificateValid trace.bootstrap actions checkpoints

/-- Search a parsed trace under the bootstrap parsed from that same trace. -/
def search
    (trace : ParsedTrace)
    (config : SearchConfig) :
    SearchOutcome :=
  @searchWithBootstrap trace.bootstrap trace config

def renderStats (stats : SearchStats) : String :=
  s!"expanded={stats.expanded} visible_candidates={stats.visibleCandidates} " ++
    s!"hidden_candidates={stats.hiddenCandidates} deduplicated={
      stats.deduplicated} depth_pruned={stats.depthPruned} gap_pruned={
      stats.gapPruned} assertion_failures={stats.assertionFailures} " ++
    s!"furthest_observation={stats.furthestObservation}"

inductive MinimumBoundResult where
  | found (value probes : Nat)
  | inconclusive
      (config : SearchConfig)
      (outcome : SearchOutcome)
      (probes : Nat)
  deriving Nonempty

partial def minimumAcceptedBound
    (trace : ParsedTrace)
    (configAt : Nat -> SearchConfig)
    (lower upper probes : Nat) :
    MinimumBoundResult :=
  if lower >= upper then
    .found upper probes
  else
    let middle := (lower + upper) / 2
    let config := configAt middle
    let outcome := search trace config
    let nextProbes := probes + 1
    if outcome.witness.isSome then
      minimumAcceptedBound trace configAt lower middle nextProbes
    else if outcome.stateLimitHit then
      .inconclusive config outcome nextProbes
    else
      minimumAcceptedBound trace configAt (middle + 1) upper nextProbes

inductive MinimumBoundsResult where
  | found (config : SearchConfig) (probes : Nat)
  | rejected (outcome : SearchOutcome)
  | inconclusive
      (config : SearchConfig)
      (outcome : SearchOutcome)
      (probes : Nat)

/--
Find lexicographically minimum successful depth, gap, and state bounds below
the supplied ceilings. A state-limited probe cannot establish a minimum.
-/
def minimumBounds
    (trace : ParsedTrace)
    (ceilings : SearchConfig) :
    MinimumBoundsResult :=
  let ceilingOutcome := search trace ceilings
  if ceilingOutcome.witness.isNone then
    if ceilingOutcome.stateLimitHit then
      .inconclusive ceilings ceilingOutcome 1
    else
      .rejected ceilingOutcome
  else
    match
      minimumAcceptedBound trace
        (fun maxDepth => { ceilings with maxDepth })
        0 ceilings.maxDepth 1
    with
    | MinimumBoundResult.inconclusive config outcome probes =>
        MinimumBoundsResult.inconclusive config outcome probes
    | MinimumBoundResult.found maxDepth depthProbes =>
        match
          minimumAcceptedBound trace
            (fun maxGap => { ceilings with maxDepth, maxGap })
            0 ceilings.maxGap depthProbes
        with
        | MinimumBoundResult.inconclusive config outcome probes =>
            MinimumBoundsResult.inconclusive config outcome probes
        | MinimumBoundResult.found maxGap gapProbes =>
            let finalCeiling := { ceilings with maxDepth, maxGap }
            let finalOutcome := search trace finalCeiling
            match finalOutcome.witness with
            | none =>
                .inconclusive finalCeiling finalOutcome (gapProbes + 1)
            | some _ =>
                .found
                  { finalCeiling with
                    maxStates := finalOutcome.stats.expanded }
                  (gapProbes + 1)

def renderNodeMap (nodeIds : List String) : String :=
  String.intercalate ", "
    (nodeIds.zipIdx.map fun (raw, index) => s!"{raw}={index}")

def ordinaryReplicationCount (trace : ParsedTrace) : Nat :=
  trace.observations.foldl
    (fun count observation =>
      if
          observation.kind == .replicate &&
          observation.committable == some false &&
          observation.membershipState != some .retirementCompleted then
        count + 1
      else
        count)
    0

def writeWitness
    (path : System.FilePath)
    (bootstrap : Bootstrap Node)
    (actions : List SimAction) :
    IO Unit :=
  writeReplayTrace path bootstrap actions

def validate
    (inputPath witnessPath : System.FilePath)
    (config : SearchConfig) :
    IO UInt32 := do
  let parsed <- parseTraceFile inputPath
  match parsed with
  | .error message =>
      IO.eprintln s!"PARSE ERROR {message}"
      return 2
  | .ok trace =>
      IO.println s!"bounds max_depth={config.maxDepth} max_gap={
        config.maxGap} max_states={config.maxStates} tx_ids={TX_COUNT} nodes={
        NODE_COUNT}"
      IO.println s!"node_map {renderNodeMap trace.nodeIds}"
      let replicationCount := ordinaryReplicationCount trace
      if TX_COUNT < replicationCount then
        IO.eprintln (
          s!"INCONCLUSIVE transaction_id_bound={TX_COUNT} " ++
            s!"ordinary_replications={replicationCount}")
        return 4
      let outcome := search trace config
      let some found := outcome.witness
        | let failingIndex :=
            min outcome.stats.furthestObservation trace.observations.size
          let result := if outcome.limitHit then "INCONCLUSIVE" else "REJECT"
          if failingIndex < trace.observations.size then
            let failing := trace.observations[failingIndex]!
            IO.eprintln s!"{result} observation_index={failingIndex} line={
              failing.line} function={failing.kind.name}"
          else
            IO.eprintln s!"{result} after all observations"
          match outcome.latestFailure with
          | some (_, message) => IO.eprintln s!"reason={message}"
          | none => pure ()
          IO.eprintln s!"search {renderStats outcome.stats} limit_hit={
            outcome.limitHit}"
          return if outcome.limitHit then 4 else 1
      let actions := found.traceRev.reverse
      let checkpoints := found.checkpointsRev.reverse
      match @replayActions trace.bootstrap actions with
      | .error message =>
          IO.eprintln s!"INTERNAL ERROR canonical replay rejected witness: {message}"
          return 3
      | .ok finalState =>
          if !@checkpointsHold trace.bootstrap actions checkpoints then
            IO.eprintln "INTERNAL ERROR observation certificate check failed"
            return 3
          writeWitness witnessPath trace.bootstrap actions
          IO.println s!"ACCEPT observations={trace.observations.size} ignored={
            trace.ignoredRecords} actions={actions.length} bootstrap_index={
            trace.bootstrapIndex}"
          IO.println s!"search {renderStats outcome.stats} limit_hit={
            outcome.limitHit}"
          IO.println s!"witness={witnessPath}"
          IO.println "observation_constraints=ok"
          let maxTerm :=
            (allNodes.map fun node =>
              (finalState.nodes node).currentTerm).foldl max 0
          IO.println s!"canonical_replay=ok max_term={maxTerm}"
          return 0

def minimizeAndValidate
    (inputPath witnessPath : System.FilePath)
    (ceilings : SearchConfig) :
    IO UInt32 := do
  let parsed <- parseTraceFile inputPath
  match parsed with
  | .error message =>
      IO.eprintln s!"PARSE ERROR {message}"
      return 2
  | .ok trace =>
      let replicationCount := ordinaryReplicationCount trace
      if TX_COUNT < replicationCount then
        IO.eprintln (
          s!"INCONCLUSIVE transaction_id_bound={TX_COUNT} " ++
            s!"ordinary_replications={replicationCount}")
        return 4
      match minimumBounds trace ceilings with
      | .rejected outcome =>
          IO.eprintln "REJECT no witness exists within the supplied ceilings"
          IO.eprintln s!"search {renderStats outcome.stats} limit_hit={
            outcome.limitHit} state_limit_hit={outcome.stateLimitHit}"
          return 1
      | .inconclusive config outcome probes =>
          IO.eprintln (
            s!"INCONCLUSIVE minimum_bounds probes={probes} " ++
              s!"max_depth={config.maxDepth} max_gap={config.maxGap} " ++
              s!"max_states={config.maxStates}")
          IO.eprintln s!"search {renderStats outcome.stats} limit_hit={
            outcome.limitHit} state_limit_hit={outcome.stateLimitHit}"
          return 4
      | .found config probes =>
          IO.println s!"MINIMUM_BOUNDS max_depth={config.maxDepth} max_gap={
            config.maxGap} max_states={config.maxStates} probes={probes}"
          validate inputPath witnessPath config

def usage : String :=
  "usage: ccf-raft-trace-validator <input.ndjson> <witness.trace> " ++
    "[--minimize-bounds] [max-depth] [max-gap] [max-states]"

def parseConfig (raw : List String) : Except String SearchConfig := do
  let parseAt (index fallback : Nat) : Except String Nat :=
    match raw[index]? with
    | none => .ok fallback
    | some value =>
        match value.toNat? with
        | some parsed => .ok parsed
        | none => .error s!"invalid natural-number bound: {value}"
  pure {
    maxDepth := <- parseAt 0 64
    maxGap := <- parseAt 1 6
    maxStates := <- parseAt 2 50000
  }

def main (args : List String) : IO UInt32 := do
  match args with
  | inputPath :: witnessPath :: bounds =>
      let minimize := bounds.head? == some "--minimize-bounds"
      let rawBounds := if minimize then bounds.drop 1 else bounds
      if rawBounds.length > 3 then
        IO.eprintln usage
        return 2
      match parseConfig rawBounds with
      | .error message =>
          IO.eprintln message
          return 2
      | .ok config =>
          if minimize then
            minimizeAndValidate inputPath witnessPath config
          else
            validate inputPath witnessPath config
  | _ =>
      IO.eprintln usage
      return 2

end CCFRaft.TraceValidation
