module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import CCFRaft.Replay

public section

/-!
JSON encoding of a complete replay state: every declared node's state and the
messages in flight. Mid-trace validation searches for such a state, and
certifies it by replaying the trace suffix from it with `Replay.replayFrom`.
-/

namespace CCFRaft.MidTrace

open Lean Model.Node
open CCFRaft.Replay (Header ReplayState)

abbrev NodeState := Model.Node.NodeState String String
abbrev Entry := Model.Node.Entry String String
abbrev Message := Model.Node.Message String String
abbrev Envelope := Replay.Envelope

private def nodeSet (declared : List String) (nodes : Finset String) : Json :=
  toJson (declared.filter fun node => node ∈ nodes)

def effectJson (declared : List String) : TransactionEffect String → Json
  | .reconfiguration nodes =>
      Json.mkObj [("kind", "configuration"), ("nodes", nodeSet declared nodes)]
  | .retiredCommitted nodes =>
      Json.mkObj [("kind", "retiredCommitted"), ("nodes", nodeSet declared nodes)]

def entryJson (declared : List String) (entry : Entry) : Json :=
  match entry.content with
  | .signature => Json.mkObj [("term", toJson entry.term), ("kind", "signature")]
  | .transaction txId effects =>
      Json.mkObj
        [
          ("term", toJson entry.term),
          ("kind", "transaction"),
          ("transaction", toJson txId),
          ("effects", Json.arr (effects.map (effectJson declared)).toArray)
        ]

def roleText : Role → String
  | .none => "none"
  | .follower => "follower"
  | .preVoteCandidate => "preVoteCandidate"
  | .candidate => "candidate"
  | .leader => "leader"

def messageJson (declared : List String) : Message → Json
  | .appendEntriesRequest request =>
      Json.mkObj
        [
          ("type", "appendEntriesRequest"),
          ("term", toJson request.term),
          ("prevLogIndex", toJson request.prevLogIndex),
          ("prevLogTerm", toJson request.prevLogTerm),
          ("entries", Json.arr (request.entries.map (entryJson declared)).toArray),
          ("leaderCommit", toJson request.leaderCommit)
        ]
  | .appendEntriesResponse response =>
      Json.mkObj
        [
          ("type", "appendEntriesResponse"),
          ("term", toJson response.term),
          ("success", toJson response.success),
          ("lastLogIndex", toJson response.lastLogIndex)
        ]
  | .requestVoteRequest request =>
      Json.mkObj
        [
          ("type", "requestVoteRequest"),
          ("term", toJson request.term),
          ("lastCommittableTerm", toJson request.lastCommittableTerm),
          ("lastCommittableIndex", toJson request.lastCommittableIndex)
        ]
  | .requestPreVote request =>
      Json.mkObj
        [
          ("type", "requestPreVote"),
          ("term", toJson request.term),
          ("lastCommittableTerm", toJson request.lastCommittableTerm),
          ("lastCommittableIndex", toJson request.lastCommittableIndex)
        ]
  | .requestVoteResponse response =>
      Json.mkObj
        [
          ("type", "requestVoteResponse"),
          ("term", toJson response.term),
          ("voteGranted", toJson response.voteGranted)
        ]
  | .requestPreVoteResponse response =>
      Json.mkObj
        [
          ("type", "requestPreVoteResponse"),
          ("term", toJson response.term),
          ("voteGranted", toJson response.voteGranted)
        ]
  | .proposeVoteRequest term =>
      Json.mkObj [("type", "proposeVoteRequest"), ("term", toJson term)]

def envelopeJson (declared : List String) (envelope : Envelope) : Json :=
  Json.mkObj
    [
      ("source", toJson envelope.source),
      ("target", toJson envelope.target),
      ("message", messageJson declared envelope.payload)
    ]

def nodeStateJson (declared : List String) (state : NodeState) : Json :=
  Json.mkObj
    [
      ("role", toJson (roleText state.role)),
      ("currentTerm", toJson state.currentTerm),
      ("log", Json.arr (state.log.map (entryJson declared)).toArray),
      ("commitIndex", toJson state.commitIndex),
      (
        "sentIndex",
        Json.mkObj (declared.map fun node => (node, toJson (state.sentIndex node)))
      ),
      (
        "matchIndex",
        Json.mkObj (declared.map fun node => (node, toJson (state.matchIndex node)))
      ),
      ("isNewFollower", toJson state.isNewFollower),
      ("votedFor", toJson state.votedFor),
      ("leaderKnown", toJson state.leaderKnown),
      ("votesGranted", nodeSet declared state.votesGranted),
      ("preVotesGranted", nodeSet declared state.preVotesGranted),
      ("retiredCommittedIndex", toJson state.retiredCommittedIndex)
    ]

def replayStateJson (declared : List String) (replay : ReplayState) : Json :=
  Json.mkObj
    [
      (
        "nodes",
        Json.mkObj
          (replay.state.nodes.map fun (node, state) => (node, nodeStateJson declared state))
      ),
      ("network", Json.arr (replay.live.map (envelopeJson declared)).toArray)
    ]

private def getField (value : Json) (key : String) : Except String Json :=
  (value.getObjVal? key).mapError fun error => s!"{key}: {error}"

private def natOf (value : Json) (key : String) : Except String Nat := do
  (← getField value key).getNat?

private def strOf (value : Json) (key : String) : Except String String := do
  (← getField value key).getStr?

private def nodesOf (value : Json) (key : String) : Except String (Finset String) := do
  let nodes ← (← getField value key).getArr?
  return (← nodes.toList.mapM Json.getStr?).toFinset

def parseEffect (value : Json) : Except String (TransactionEffect String) := do
  match ← strOf value "kind" with
  | "configuration" => return .reconfiguration (← nodesOf value "nodes")
  | "retiredCommitted" => return .retiredCommitted (← nodesOf value "nodes")
  | kind => throw s!"unknown effect kind '{kind}'"

def parseEntry (value : Json) : Except String Entry := do
  let term ← natOf value "term"
  match ← strOf value "kind" with
  | "signature" => return { term, content := .signature }
  | "transaction" =>
      let effects ← (← getField value "effects").getArr?
      return {
        term
        content :=
          .transaction (← strOf value "transaction") (← effects.toList.mapM parseEffect)
      }
  | kind => throw s!"unknown entry kind '{kind}'"

def parseRole : String → Except String Role
  | "none" => pure .none
  | "follower" => pure .follower
  | "preVoteCandidate" => pure .preVoteCandidate
  | "candidate" => pure .candidate
  | "leader" => pure .leader
  | role => throw s!"unknown role '{role}'"

def parseMessage (value : Json) : Except String Message := do
  let term ← natOf value "term"
  match ← strOf value "type" with
  | "appendEntriesRequest" =>
      let entries ← (← getField value "entries").getArr?
      return .appendEntriesRequest
        {
          term
          prevLogIndex := ← natOf value "prevLogIndex"
          prevLogTerm := ← natOf value "prevLogTerm"
          entries := ← entries.toList.mapM parseEntry
          leaderCommit := ← natOf value "leaderCommit"
        }
  | "appendEntriesResponse" =>
      return .appendEntriesResponse
        {
          term
          success := ← (← getField value "success").getBool?
          lastLogIndex := ← natOf value "lastLogIndex"
        }
  | "requestVoteRequest" =>
      return .requestVoteRequest
        {
          term
          lastCommittableTerm := ← natOf value "lastCommittableTerm"
          lastCommittableIndex := ← natOf value "lastCommittableIndex"
        }
  | "requestPreVote" =>
      return .requestPreVote
        {
          term
          lastCommittableTerm := ← natOf value "lastCommittableTerm"
          lastCommittableIndex := ← natOf value "lastCommittableIndex"
        }
  | "requestVoteResponse" =>
      return .requestVoteResponse
        { term, voteGranted := ← (← getField value "voteGranted").getBool? }
  | "requestPreVoteResponse" =>
      return .requestPreVoteResponse
        { term, voteGranted := ← (← getField value "voteGranted").getBool? }
  | "proposeVoteRequest" => return .proposeVoteRequest term
  | kind => throw s!"unknown message type '{kind}'"

private def indexMap (value : Json) (key : String) : Except String (String → Nat) := do
  let entries ← (← getField value key).getObj?
  let pairs ← entries.toList.mapM fun (node, index) => do return (node, ← index.getNat?)
  return fun node => (pairs.lookup node).getD 0

def parseNodeState (value : Json) : Except String NodeState := do
  let log ← (← getField value "log").getArr?
  let votedFor ← getField value "votedFor"
  let retired ← getField value "retiredCommittedIndex"
  return {
    role := ← parseRole (← strOf value "role")
    currentTerm := ← natOf value "currentTerm"
    log := ← log.toList.mapM parseEntry
    commitIndex := ← natOf value "commitIndex"
    sentIndex := ← indexMap value "sentIndex"
    matchIndex := ← indexMap value "matchIndex"
    isNewFollower := ← (← getField value "isNewFollower").getBool?
    votedFor := ← if votedFor.isNull then pure none else some <$> votedFor.getStr?
    leaderKnown := ← (← getField value "leaderKnown").getBool?
    votesGranted := ← nodesOf value "votesGranted"
    preVotesGranted := ← nodesOf value "preVotesGranted"
    retiredCommittedIndex :=
      ← if retired.isNull then pure none else some <$> retired.getNat?
  }

def parseEnvelope (value : Json) : Except String Envelope := do
  return {
    source := ← strOf value "source"
    target := ← strOf value "target"
    payload := ← parseMessage (← getField value "message")
  }

/-- Every declared node must have a state; the network lists live messages. -/
def parseReplayState (header : Header) (value : Json) : Except String ReplayState := do
  let nodes ← (← getField value "nodes").getObj?
  let nodes ←
    nodes.toList.mapM fun (node, state) => do return (node, ← parseNodeState state)
  for node in header.declared do
    unless (nodes.lookup node).isSome do
      throw s!"no state for declared node '{node}'"
  let network ← (← getField value "network").getArr?
  return {
    state :=
      {
        nodes := header.declared.filterMap fun node => (nodes.lookup node).map (node, ·)
        active := header.declared
        network := ← network.toList.mapM parseEnvelope
      }
  }

end CCFRaft.MidTrace
