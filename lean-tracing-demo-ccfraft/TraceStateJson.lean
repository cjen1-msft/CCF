-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import TraceJson
import BoundedState

set_option autoImplicit false

namespace CCFRaft.TraceStateJson

open Lean TraceJson

def nodeTable {α : Type} (decode : Json -> Except String α) (json : Json) :
    Except String (BoundedState.NodeTable α) := do
  let values <- (← json.getArr?).mapM decode
  if size : values.size = NODE_COUNT then
    pure ⟨values, size⟩
  else
    throw s!"node table requires exactly {NODE_COUNT} entries, got {values.size}"

def optional {α : Type} (decode : Json -> Except String α) :
    Json -> Except String (Option α)
  | .null => pure none
  | value => some <$> decode value

def membershipValue (json : Json) : Except String MembershipState := do
  match ← json.getStr? with
  | "active" => pure .active
  | "retirementOrdered" => pure .retirementOrdered
  | "retirementSigned" => pure .retirementSigned
  | "retirementCompleted" => pure .retirementCompleted
  | "retiredCommitted" => pure .retiredCommitted
  | other => throw s!"unsupported membership state: {other}"

def preVoteValue (json : Json) : Except String PreVoteStatus := do
  match ← json.getStr? with
  | "capable" => pure .capable
  | "enabled" => pure .enabled
  | other => throw s!"unsupported pre-vote status: {other}"

def entryContent (unknowns : Array String) (json : Json) :
    Except String (EntryContent Node (TraceSmt.NatTerm unknowns.size)) := do
  match ← field json "kind" >>= Json.getStr? with
  | "transaction" =>
      checkKeys json ["kind", "transaction"]
      pure (.transaction (← field json "transaction" >>= transactionValue unknowns))
  | "signature" =>
      checkKeys json ["kind"]
      pure .signature
  | "reconfiguration" =>
      checkKeys json ["kind", "nodes"]
      pure (.reconfiguration (← field json "nodes" >>= nodeSet))
  | "retiredCommitted" =>
      checkKeys json ["kind", "nodes"]
      pure (.retiredCommitted (← field json "nodes" >>= nodeSet))
  | other => throw s!"unsupported entry content: {other}"

def entry (unknowns : Array String) (json : Json) :
    Except String (Entry Node (TraceSmt.NatTerm unknowns.size)) := do
  checkKeys json ["term", "content"]
  pure
    { term := ← field json "term" >>= Json.getNat?
      content := ← field json "content" >>= entryContent unknowns }

def log (unknowns : Array String) (json : Json) :
    Except String (List (Entry Node (TraceSmt.NatTerm unknowns.size))) := do
  (← json.getArr?).toList.mapM (entry unknowns)

def localState (unknowns : Array String) (json : Json) :
    Except String (BoundedState.LocalStateData (TraceSmt.NatTerm unknowns.size)) := do
  checkKeys json
    ["role", "currentTerm", "log", "commitIndex", "sentIndex", "matchIndex",
     "isNewFollower", "votedFor", "votesGranted", "preVotesGranted",
     "membershipState", "retirementIndex", "retirementCommittableIndex",
     "retiredCommittedIndex"]
  pure
    { role := ← field json "role" >>= roleValue
      currentTerm := ← field json "currentTerm" >>= Json.getNat?
      log := ← field json "log" >>= log unknowns
      commitIndex := ← field json "commitIndex" >>= Json.getNat?
      sentIndex := ← field json "sentIndex" >>= nodeTable Json.getNat?
      matchIndex := ← field json "matchIndex" >>= nodeTable Json.getNat?
      isNewFollower := ← field json "isNewFollower" >>= Json.getBool?
      votedFor := ← field json "votedFor" >>= optional nodeValue
      votesGranted := ← field json "votesGranted" >>= nodeSet
      preVotesGranted := ← field json "preVotesGranted" >>= nodeSet
      membershipState := ← field json "membershipState" >>= membershipValue
      retirementIndex := ← field json "retirementIndex" >>= optional Json.getNat?
      retirementCommittableIndex :=
        ← field json "retirementCommittableIndex" >>= optional Json.getNat?
      retiredCommittedIndex := ← field json "retiredCommittedIndex" >>= optional Json.getNat? }

def message (unknowns : Array String) (json : Json) :
    Except String (Message Node (TraceSmt.NatTerm unknowns.size)) := do
  let kind <- field json "kind" >>= Json.getStr?
  let term <- field json "term" >>= Json.getNat?
  let source <- field json "source" >>= nodeValue
  let destination <- field json "destination" >>= nodeValue
  match kind with
  | "appendEntriesRequest" =>
      checkKeys json ["kind", "term", "source", "destination", "prevLogIndex",
        "prevLogTerm", "entries", "leaderCommit"]
      pure (.appendEntriesRequest
        { term, source, destination
          prevLogIndex := ← field json "prevLogIndex" >>= Json.getNat?
          prevLogTerm := ← field json "prevLogTerm" >>= Json.getNat?
          entries := ← field json "entries" >>= log unknowns
          leaderCommit := ← field json "leaderCommit" >>= Json.getNat? })
  | "appendEntriesResponse" =>
      checkKeys json ["kind", "term", "source", "destination", "success", "lastLogIndex"]
      pure (.appendEntriesResponse
        { term, source, destination
          success := ← field json "success" >>= Json.getBool?
          lastLogIndex := ← field json "lastLogIndex" >>= Json.getNat? })
  | "requestVoteRequest" =>
      checkKeys json ["kind", "term", "source", "destination",
        "lastCommittableTerm", "lastCommittableIndex"]
      pure (.requestVoteRequest
        { term, source, destination
          lastCommittableTerm := ← field json "lastCommittableTerm" >>= Json.getNat?
          lastCommittableIndex := ← field json "lastCommittableIndex" >>= Json.getNat? })
  | "requestVoteResponse" =>
      checkKeys json ["kind", "term", "source", "destination", "voteGranted"]
      pure (.requestVoteResponse
        { term, source, destination
          voteGranted := ← field json "voteGranted" >>= Json.getBool? })
  | "requestPreVote" =>
      checkKeys json ["kind", "term", "source", "destination",
        "lastCommittableTerm", "lastCommittableIndex"]
      pure (.requestPreVote
        { term, source, destination
          lastCommittableTerm := ← field json "lastCommittableTerm" >>= Json.getNat?
          lastCommittableIndex := ← field json "lastCommittableIndex" >>= Json.getNat? })
  | "requestPreVoteResponse" =>
      checkKeys json ["kind", "term", "source", "destination", "voteGranted"]
      pure (.requestPreVoteResponse
        { term, source, destination
          voteGranted := ← field json "voteGranted" >>= Json.getBool? })
  | "proposeVoteRequest" =>
      checkKeys json ["kind", "term", "source", "destination"]
      pure (.proposeVoteRequest { term, source, destination })
  | other => throw s!"unsupported message kind: {other}"

/-- Decode a template, not a reachability claim. Evaluate transaction IDs before checking guards. -/
def decode (unknowns : Array String) (json : Json) :
    Except String (State Node (TraceSmt.NatTerm unknowns.size)) := do
  checkKeys json ["nodes", "network", "submittedTxIds", "hasJoined",
    "preVoteStatus", "retirementCompleted"]
  let data : BoundedState.Data (TraceSmt.NatTerm unknowns.size) :=
    { nodes := ← field json "nodes" >>= nodeTable (optional (localState unknowns))
      network := ← field json "network" >>= nodeTable
        (fun json => do (← json.getArr?).toList.mapM (message unknowns))
      submittedTxIds :=
        (← (← field json "submittedTxIds" >>= Json.getArr?).toList.mapM
          (transactionValue unknowns)).toFinset
      hasJoined := ← field json "hasJoined" >>= nodeSet
      preVoteStatus := ← field json "preVoteStatus" >>= nodeTable preVoteValue
      retirementCompleted := ← field json "retirementCompleted" >>= nodeTable nodeSet }
  pure (BoundedState.decode data)

end CCFRaft.TraceStateJson
