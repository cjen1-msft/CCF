-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import TraceProperties

set_option autoImplicit false

namespace CCFRaft.Reduction

variable {Node TxId : Type}

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

/-- One normalized implementation event. JSON parsing is shared infrastructure. -/
structure Event (Node TxId : Type) where
  line : Nat
  timestamp : Nat
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
  messages : List (Message Node TxId) := []

structure SourceLocation where
  line : Nat
  timestamp : Nat
  function : RawFunction

abbrev Instruction (Node TxId : Type) :=
  TraceValidation.Instruction
    (Action Node TxId)
    (TraceValidation.Observation Node TxId)

/-- One certificate step with its audited rule and raw-event provenance. -/
structure Step (Node TxId : Type) where
  instruction : Instruction Node TxId
  rule : String
  provenance : List SourceLocation

def sourceLocation (event : Event Node TxId) : SourceLocation where
  line := event.line
  timestamp := event.timestamp
  function := event.function

def emit
    (rule : String)
    (events : List (Event Node TxId))
    (instruction : Instruction Node TxId) :
    Step Node TxId where
  instruction
  rule
  provenance := events.map sourceLocation

def observeState
    (rule : String)
    (event : Event Node TxId) :
    List (Step Node TxId) :=
  let observation (value : TraceValidation.Observation Node TxId) :=
    emit rule [event] (.observation value)
  [
    observation (.allocated event.node true),
    observation (.joined event.node true),
    observation (.role event.node event.role),
    observation (.currentTerm event.node event.term),
    observation (.commitIndex event.node event.commitIndex),
    observation (.logLength event.node event.logLength)
  ]

def requirePeer (event : Event Node TxId) : Except String Node :=
  match event.peer with
  | some peer => .ok peer
  | none => .error s!"line {event.line}: peer is missing"

def actionSteps
    (rule : String)
    (events : List (Event Node TxId))
    (actions : List (Action Node TxId)) :
    List (Step Node TxId) :=
  actions.map fun action => emit rule events (.action action)

def receiveSteps
    (rule : String)
    (event : Event Node TxId)
    (source : Node) :
    Except String (List (Step Node TxId)) := do
  if event.messages.isEmpty then
    throw s!"line {event.line}: selected messages are missing"
  let rec loop :
      List (Message Node TxId) ->
        List (Step Node TxId) ->
          Except String (List (Step Node TxId))
    | [], result => pure result
    | message :: rest, result =>
        loop
          rest
          (result ++
            [
              emit
                "observe-selected-message-before-receive"
                [event]
                (.observation
                  (.firstMessageFrom source event.node message)),
              emit rule [event] (.action (.receive source event.node))
            ])
  loop event.messages []

def isAppendSend (event : Event Node TxId) : Bool :=
  event.function = .sendAppendEntries

def receiveRuleName : RawFunction -> String
  | .receiveAppendEntries => "split-append-entries-receive"
  | .receiveAppendEntriesResponse =>
      "split-append-entries-response-receive"
  | .receiveRequestVote => "receive-request-vote"
  | .receiveRequestVoteResponse => "receive-request-vote-response"
  | _ => "unsupported-receive"

def takeAppendSends :
    List (Event Node TxId) ->
      List (Event Node TxId) × List (Event Node TxId)
  | event :: rest =>
      if isAppendSend event then
        let (sends, remaining) := takeAppendSends rest
        (event :: sends, remaining)
      else
        ([], event :: rest)
  | [] => ([], [])

def takeAppendReceiveHelpers :
    List (Event Node TxId) ->
      Option (Event Node TxId) × List (Event Node TxId)
  | event :: rest =>
      match event.function with
      | .sendAppendEntriesResponse => (some event, rest)
      | .executeAppendEntries => takeAppendReceiveHelpers rest
      | .addConfiguration
      | .commit =>
          if event.role = .leader then
            (none, event :: rest)
          else
            takeAppendReceiveHelpers rest
      | _ => (none, event :: rest)
  | [] => (none, [])

def semantics (steps : List (Step Node TxId)) :
    List (Instruction Node TxId) :=
  steps.map Step.instruction

/--
Reduce one normalized event stream by prefix destructuring.

Every branch emits a linear list of observations and actions, then recurses on
the unconsumed suffix. Unsupported shapes fail rather than dropping evidence.
-/
def reduceWithFuel [DecidableEq Node] :
    Nat -> List (Event Node TxId) -> Except String (List (Step Node TxId))
  | 0, [] => pure []
  | 0, event :: _ =>
      throw s!"line {event.line}: reduction exceeded its event bound"
  | _ + 1, [] => pure []
  | fuel + 1, event :: rest => do
      match event.function with
      | .becomeLeader =>
          match rest with
          | configurationReplicate :: configuration ::
              signature :: commit :: tail =>
              if configurationReplicate.function = .replicate &&
                  configurationReplicate.globallyCommittable = some false &&
                  configuration.function = .addConfiguration &&
                  signature.function = .replicate &&
                  signature.globallyCommittable = some true &&
                  commit.function = .commit then
                let remaining <- reduceWithFuel fuel tail
                pure <|
                  observeState "observe-bootstrap-entry-state" commit ++
                    actionSteps
                      "bootstrap-leader-commit"
                      [event, configurationReplicate, configuration, signature, commit]
                      [.advanceCommitIndex commit.node] ++
                    remaining
              else
                let remaining <- reduceWithFuel fuel rest
                pure <|
                  actionSteps
                      "candidate-became-leader"
                      [event]
                      [.becomeLeader event.node] ++
                    observeState "candidate-became-leader" event ++
                    remaining
          | _ =>
              let remaining <- reduceWithFuel fuel rest
              pure <|
                actionSteps
                    "candidate-became-leader"
                    [event]
                    [.becomeLeader event.node] ++
                  observeState "candidate-became-leader" event ++
                  remaining

      | .replicate =>
          match rest with
          | configuration :: tail =>
              if event.globallyCommittable = some false &&
                  configuration.function = .addConfiguration then
                let (sends, remainingEvents) := takeAppendSends tail
                let emittedSends <- reduceWithFuel fuel sends
                let remaining <- reduceWithFuel fuel remainingEvents
                pure <|
                  observeState "leader-add-configuration" configuration ++
                    emittedSends ++
                    actionSteps
                      "leader-add-configuration"
                      [event, configuration]
                      [.changeConfiguration
                        configuration.node
                        configuration.configuration] ++
                    remaining
              else
                match event.globallyCommittable, event.transaction with
                | some true, _ =>
                    let remaining <- reduceWithFuel fuel rest
                    pure <|
                      observeState "replicate-signature" event ++
                        actionSteps
                          "replicate-signature"
                          [event]
                          [.signCommittableMessages event.node] ++
                        remaining
                | some false, some transaction =>
                    let remaining <- reduceWithFuel fuel rest
                    pure <|
                      observeState "replicate-client-request" event ++
                        actionSteps
                          "replicate-client-request"
                          [event]
                          [.clientRequest event.node transaction] ++
                        remaining
                | _, _ =>
                    throw s!"line {event.line}: incomplete replicate event"
          | [] =>
              match event.globallyCommittable, event.transaction with
              | some true, _ =>
                  pure <|
                    observeState "replicate-signature" event ++
                      actionSteps
                        "replicate-signature"
                        [event]
                        [.signCommittableMessages event.node]
              | some false, some transaction =>
                  pure <|
                    observeState "replicate-client-request" event ++
                      actionSteps
                        "replicate-client-request"
                        [event]
                        [.clientRequest event.node transaction]
              | _, _ =>
                  throw s!"line {event.line}: incomplete replicate event"

      | .receiveAppendEntries =>
          let source <- requirePeer event
          match rest with
          | follower :: tail =>
              if follower.function = .becomeFollower &&
                  decide (follower.node = event.node) then
                let (response?, remainingEvents) :=
                  takeAppendReceiveHelpers tail
                let response <-
                  response?.map .ok |>.getD
                    (.error
                      s!"line {event.line}: AppendEntries response is missing")
                let receives <-
                  receiveSteps "split-append-entries-receive" event source
                let remaining <- reduceWithFuel fuel remainingEvents
                pure <|
                  observeState "split-append-entries-receive" event ++
                    actionSteps
                      "newer-term-receive-transition"
                      [event, follower]
                      [.updateTerm source event.node] ++
                    observeState
                      "newer-term-receive-transition"
                      follower ++
                    receives ++
                    observeState
                      "split-append-entries-receive"
                      response ++
                    remaining
              else
                let (response?, remainingEvents) :=
                  takeAppendReceiveHelpers rest
                let response <-
                  response?.map .ok |>.getD
                    (.error
                      s!"line {event.line}: AppendEntries response is missing")
                let receives <-
                  receiveSteps "split-append-entries-receive" event source
                let remaining <- reduceWithFuel fuel remainingEvents
                pure <|
                  observeState "split-append-entries-receive" event ++
                    receives ++
                    observeState
                      "split-append-entries-receive"
                      response ++
                    remaining
          | [] =>
              throw s!"line {event.line}: AppendEntries response is missing"

      | .receiveAppendEntriesResponse
      | .receiveRequestVote
      | .receiveRequestVoteResponse =>
          let source <- requirePeer event
          let rule := receiveRuleName event.function
          match rest with
          | follower :: tail =>
              if follower.function = .becomeFollower &&
                  decide (follower.node = event.node) then
                let receives <- receiveSteps rule event source
                let remaining <- reduceWithFuel fuel tail
                pure <|
                  observeState rule event ++
                    actionSteps
                      "newer-term-receive-transition"
                      [event, follower]
                      [.updateTerm source event.node] ++
                    observeState
                      "newer-term-receive-transition"
                      follower ++
                    receives ++
                    remaining
              else
                let receives <- receiveSteps rule event source
                let remaining <- reduceWithFuel fuel rest
                pure <|
                  observeState rule event ++
                    receives ++
                    remaining
          | [] =>
              let receives <- receiveSteps rule event source
              pure <|
                observeState rule event ++ receives

      | .sendAppendEntries =>
          let destination <- requirePeer event
          let remaining <- reduceWithFuel fuel rest
          pure <|
            observeState "split-append-entries-batch" event ++
              actionSteps
                "split-append-entries-batch"
                [event]
                (event.batchEnds.map fun batchEnd =>
                  .appendEntries event.node destination batchEnd) ++
              remaining

      | .commit =>
          if event.role = .leader then
            let remaining <- reduceWithFuel fuel rest
            pure <|
              observeState "leader-commit-callback" event ++
                actionSteps
                  "leader-commit-callback"
                  [event]
                  [.advanceCommitIndex event.node] ++
                remaining
          else
            reduceWithFuel fuel rest

      | .becomeCandidate =>
          let remaining <- reduceWithFuel fuel rest
          pure <|
            actionSteps "candidate-timeout" [event] [.timeout event.node] ++
              observeState "candidate-timeout" event ++
              remaining

      | .sendRequestVote =>
          let destination <- requirePeer event
          let remaining <- reduceWithFuel fuel rest
          pure <|
            observeState "send-request-vote" event ++
              actionSteps
                "send-request-vote"
                [event]
                [.requestVote event.node destination] ++
              remaining

      | .addConfiguration =>
          if event.role = .leader then
            throw s!"line {event.line}: configuration lacks its replicate event"
          else
            reduceWithFuel fuel rest

      | .becomeFollower =>
          throw s!"line {event.line}: ungrouped become_follower event"

      | .dropPending
      | .executeAppendEntries
      | .sendAppendEntriesResponse =>
          reduceWithFuel fuel rest

def reduce [DecidableEq Node]
    (events : List (Event Node TxId)) :
    Except String (List (Step Node TxId)) :=
  reduceWithFuel events.length events

end CCFRaft.Reduction
