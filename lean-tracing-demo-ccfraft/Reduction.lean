-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import TraceProperties

set_option autoImplicit false

namespace CCFRaft.Reduction

variable {Node TxId : Type}

/-!
The NDJSON reader is shared infrastructure. This file starts after JSON fields
have been decoded without interpretation. It contains only the model-specific
preprocessing and reduction rules.
-/

inductive RawFunction where
  | addConfiguration
  | becomeCandidate
  | becomeFollower
  | becomeLeader
  | commit
  | dropPending
  | executeAppendEntries
  | receiveAppendEntries
  | receiveAppendEntriesResponse
  | receiveRequestVote
  | receiveRequestVoteResponse
  | replicate
  | sendAppendEntries
  | sendAppendEntriesResponse
  | sendRequestVote
  deriving DecidableEq

structure RawEvent (Node TxId : Type) where
  line : Nat
  function : RawFunction
  node : Node
  peer : Option Node
  role : Role
  term : Nat
  logLength : Nat
  commitIndex : Nat
  globallyCommittable : Option Bool := none
  transaction : Option TxId := none
  configuration : Finset Node := {}
  batchEnds : List Nat := []

inductive PreprocessedEvent (Node TxId : Type) where
  | bootstrap (events : List (RawEvent Node TxId))
  | retained (event : RawEvent Node TxId)
  | newerTermReceive
      (receive follower : RawEvent Node TxId)

def isReceive : RawFunction -> Bool
  | .receiveAppendEntries
  | .receiveAppendEntriesResponse
  | .receiveRequestVote
  | .receiveRequestVoteResponse => true
  | _ => false

def isHelper : RawFunction -> Bool
  | .dropPending
  | .executeAppendEntries
  | .sendAppendEntriesResponse => true
  | _ => false

/--
Group the implementation events that jointly denote one model transition.
JSON parsing and field validation happen before this function.
-/
partial def preprocess [DecidableEq Node] :
    List (RawEvent Node TxId) -> List (PreprocessedEvent Node TxId)
  | leader :: configurationReplicate :: configuration ::
      signature :: commit :: rest =>
      if leader.function = .becomeLeader &&
          configurationReplicate.function = .replicate &&
          configurationReplicate.globallyCommittable = some false &&
          configuration.function = .addConfiguration &&
          signature.function = .replicate &&
          signature.globallyCommittable = some true &&
          commit.function = .commit then
        .bootstrap
            [leader, configurationReplicate, configuration, signature, commit] ::
          preprocess rest
      else
        preprocessPair
          leader
          (configurationReplicate :: configuration :: signature :: commit :: rest)
  | event :: rest => preprocessPair event rest
  | [] => []
where
  preprocessPair
      (event : RawEvent Node TxId)
      (rest : List (RawEvent Node TxId)) :
      List (PreprocessedEvent Node TxId) :=
    match rest with
    | next :: tail =>
        if event.function = .replicate &&
            event.globallyCommittable = some false &&
            next.function = .addConfiguration then
          .retained next :: preprocess tail
        else if isReceive event.function &&
            next.function = .becomeFollower &&
            decide (next.node = event.node) then
          .newerTermReceive event next :: preprocess tail
        else if isHelper event.function then
          preprocess rest
        else
          .retained event :: preprocess rest
    | [] =>
        if isHelper event.function then [] else [.retained event]

def requirePeer (event : RawEvent Node TxId) : Except String Node :=
  match event.peer with
  | some peer => .ok peer
  | none => .error s!"line {event.line}: peer is missing"

def repeatAction (count : Nat) (action : Action Node TxId) :
    List (Action Node TxId) :=
  List.replicate count action

/-- Convert one audited preprocessed event into canonical model actions. -/
def reduceEvent
    [DecidableEq Node]
    (event : PreprocessedEvent Node TxId) :
    Except String (List (Action Node TxId)) := do
  match event with
  | .bootstrap events =>
      match events.getLast? with
      | some commit => pure [.advanceCommitIndex commit.node]
      | none => throw "bootstrap group is empty"
  | .newerTermReceive receive _ =>
      let source <- requirePeer receive
      let count := max 1 receive.batchEnds.length
      pure
        (.updateTerm source receive.node ::
          repeatAction count (.receive source receive.node))
  | .retained raw =>
      match raw.function with
      | .replicate =>
          match raw.globallyCommittable, raw.transaction with
          | some true, _ => pure [.signCommittableMessages raw.node]
          | some false, some transaction =>
              pure [.clientRequest raw.node transaction]
          | _, _ => throw s!"line {raw.line}: incomplete replicate event"
      | .addConfiguration =>
          pure [.changeConfiguration raw.node raw.configuration]
      | .sendAppendEntries =>
          let destination <- requirePeer raw
          pure
            (raw.batchEnds.map fun batchEnd =>
              .appendEntries raw.node destination batchEnd)
      | .receiveAppendEntries
      | .receiveAppendEntriesResponse
      | .receiveRequestVote
      | .receiveRequestVoteResponse =>
          let source <- requirePeer raw
          pure
            (repeatAction
              (max 1 raw.batchEnds.length)
              (.receive source raw.node))
      | .commit => pure [.advanceCommitIndex raw.node]
      | .becomeCandidate => pure [.timeout raw.node]
      | .sendRequestVote =>
          let destination <- requirePeer raw
          pure [.requestVote raw.node destination]
      | .becomeLeader => pure [.becomeLeader raw.node]
      | .becomeFollower =>
          throw s!"line {raw.line}: ungrouped become_follower event"
      | .dropPending
      | .executeAppendEntries
      | .sendAppendEntriesResponse =>
          throw s!"line {raw.line}: helper event reached reduction"

end CCFRaft.Reduction
