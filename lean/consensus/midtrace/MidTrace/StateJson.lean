module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.Replay.Interpreter
public import Lean.Data.Json

@[expose] public section

/-!
Replay-state JSON uses the header's node IDs. Sent and match frontiers are
tabulated on that finite universe (the decoder returns zero outside it).
The ordered header names prevent interpreting those tables with a different ID map.
-/

namespace Consensus.MidTrace

open Lean Model.Node

namespace StateJson

instance : ToJson (CCF.Finset NodeID) := ⟨fun nodes => toJson nodes.sort⟩
instance : FromJson (CCF.Finset NodeID) := ⟨fun j => CCF.Finset.ofList <$> fromJson? j⟩

deriving instance ToJson, FromJson
for
  Role, TransactionMetadata, EntryContent, Entry, AppendEntriesRequest, AppendEntriesResponse, RequestVoteRequest, RequestVoteResponse, Message

deriving instance ToJson, FromJson for CCF.Envelope

structure Local where
  id : NodeID
  role : Role
  currentTerm : Nat
  log : List Entry
  commitIndex : Nat
  sentIndex : Array Nat
  matchIndex : Array Nat
  isNewFollower : Bool
  votedFor : Option NodeID
  primaryKnown : Bool
  votesGranted : CCF.Finset NodeID
  preVotesGranted : CCF.Finset NodeID
  retiredCommittedIndex : Option Nat
deriving ToJson, FromJson

structure Snapshot where
  declared : List String
  nodes : List Local
  network : List Model.Envelope
deriving ToJson, FromJson

def Local.encode (ids : Array Nat) (id : NodeID) (s : NodeState) : Local :=
  ⟨
    id,
    s.role,
    s.currentTerm,
    s.log,
    s.commitIndex,
    ids.map s.sentIndex,
    ids.map s.matchIndex,
    s.isNewFollower,
    s.votedFor,
    s.primaryKnown,
    s.votesGranted,
    s.preVotesGranted,
    s.retiredCommittedIndex
  ⟩

def Local.decode (n : Nat) (s : Local) : Except String (NodeID × NodeState) := do
  unless s.sentIndex.size == n && s.matchIndex.size == n do
    throw s!"node {s.id}: expected {n} sentIndex and matchIndex values"
  return (
    s.id,
    ⟨
      s.role,
      s.currentTerm,
      s.log,
      s.commitIndex,
      (fun i => s.sentIndex[i]?.getD 0),
      (fun i => s.matchIndex[i]?.getD 0),
      s.isNewFollower,
      s.votedFor,
      s.primaryKnown,
      s.votesGranted,
      s.preVotesGranted,
      s.retiredCommittedIndex
    ⟩
  )

/-- The node IDs that entry `e` names. -/
def entryIds (e : Entry) : List NodeID :=
  let m := e.content.metadata
  (m.configuration.getD ∅ ∪ m.retirementConfirmations).sort

/-- Every node ID that `s` names, with where it names it. -/
def Local.ids (s : Local) : List (NodeID × String) :=
  (s.votedFor.toList.map (·, "votedFor"))
  ++ s.votesGranted.sort.map (·, "votesGranted")
  ++ s.preVotesGranted.sort.map (·, "preVotesGranted")
  ++ s.log.flatMap fun e => (entryIds e).map (·, "log entry")

/-- Every node ID that `e` names, with where it names it. -/
def envelopeIds (e : Model.Envelope) : List (NodeID × String) :=
  [(e.source, "envelope source"), (e.target, "envelope target")]
  ++ match e.payload with
      | .appendEntriesRequest r =>
          r.entries.flatMap fun e => (entryIds e).map (·, "envelope entry")
      | _ => []

end StateJson

def encodeState (header : Replay.Header) (state : Model.State) : Json :=
  let ids := Array.range header.declared.length
  toJson
    ({
        declared := header.declared
        nodes := state.nodes.map fun (i, s) => StateJson.Local.encode ids i s
        network := state.network
      }
      : StateJson.Snapshot)

def decodeState (header : Replay.Header) (json : Json) : Except String Model.State := do
  let snapshot : StateJson.Snapshot ← fromJson? json
  unless snapshot.declared == header.declared do
    throw "state node names differ from replay header"
  let n := header.declared.length
  unless snapshot.nodes.map (·.id) == List.range n do
    throw "expected one state per declared node in ID order"
  for s in snapshot.nodes do
    for (id, place) in s.ids do
      unless id < n do
        throw s!"undeclared node id {id} in node {s.id} {place}"
  for e in snapshot.network do
    for (id, place) in StateJson.envelopeIds e do
      unless id < n do
        throw s!"undeclared node id {id} in {place}"
  return {
    nodes := ← snapshot.nodes.mapM (StateJson.Local.decode n)
    network := snapshot.network
  }

end Consensus.MidTrace
