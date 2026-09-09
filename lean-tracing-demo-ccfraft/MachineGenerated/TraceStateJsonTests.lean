-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import TraceStateJson

set_option autoImplicit false

namespace CCFRaft.TraceStateJsonTests

open Lean

local instance : NeZero NODE_COUNT := ⟨by decide⟩

def table (value : Json) : Json :=
  toJson (Array.replicate NODE_COUNT value)

def transaction : Json := Json.mkObj
  [("term", toJson (6 : Nat)),
   ("content", Json.mkObj
     [("kind", toJson "transaction"),
      ("transaction", Json.mkObj [("unknown", toJson "tx")])])]

def localState : Json := Json.mkObj
  [("role", toJson "leader"),
   ("currentTerm", toJson (7 : Nat)),
   ("log", toJson [transaction]),
   ("commitIndex", toJson (9 : Nat)),
   ("sentIndex", table (toJson (12 : Nat))),
   ("matchIndex", table (toJson (11 : Nat))),
   ("isNewFollower", toJson false),
   ("votedFor", toJson (2 : Nat)),
   ("votesGranted", toJson [1, 2]),
   ("preVotesGranted", toJson [3]),
   ("membershipState", toJson "retirementOrdered"),
   ("retirementIndex", toJson (2 : Nat)),
   ("retirementCommittableIndex", toJson (3 : Nat)),
   ("retiredCommittedIndex", toJson (4 : Nat))]

def packet (kind : String) (fields : List (String × Json)) : Json :=
  Json.mkObj ([("kind", toJson kind), ("term", toJson (8 : Nat)),
    ("source", toJson (2 : Nat)), ("destination", toJson (1 : Nat))] ++ fields)

def queue : List Json :=
  [packet "appendEntriesRequest"
    [("prevLogIndex", toJson (7 : Nat)), ("prevLogTerm", toJson (6 : Nat)),
     ("entries", toJson [transaction]), ("leaderCommit", toJson (3 : Nat))],
   packet "appendEntriesResponse"
    [("success", toJson false), ("lastLogIndex", toJson (5 : Nat))],
   packet "requestVoteRequest"
    [("lastCommittableTerm", toJson (6 : Nat)), ("lastCommittableIndex", toJson (7 : Nat))],
   packet "requestVoteResponse" [("voteGranted", toJson true)],
   packet "requestPreVote"
    [("lastCommittableTerm", toJson (6 : Nat)), ("lastCommittableIndex", toJson (7 : Nat))],
   packet "requestPreVoteResponse" [("voteGranted", toJson false)],
   packet "proposeVoteRequest" []]

def stateJson : Json := Json.mkObj
  [("nodes", toJson ((Array.replicate NODE_COUNT Json.null).set! 1 localState)),
   ("network", toJson ((Array.replicate NODE_COUNT (toJson ([] : List Json))).set! 1 (toJson queue))),
   ("submittedTxIds", toJson [Json.mkObj [("unknown", toJson "tx")]]),
   ("hasJoined", toJson [1, 2]),
   ("preVoteStatus", table (toJson "enabled")),
   ("retirementCompleted", table (toJson [2, 3]))]

#guard match TraceStateJson.decode #["tx"] stateJson with
  | .error _ => false
  | .ok state =>
      !(state.nodes.node? 0).isSome &&
      (state.nodes.node? 1).isSome &&
      (state.nodes 1).role == .leader &&
      (state.nodes 1).currentTerm == 7 &&
      (state.nodes 1).commitIndex == 9 &&
      (state.nodes 1).sentIndex 2 == 12 &&
      (state.nodes 1).matchIndex 2 == 11 &&
      !(state.nodes 1).isNewFollower &&
      (state.nodes 1).votedFor == some 2 &&
      (state.nodes 1).votesGranted == {1, 2} &&
      (state.nodes 1).preVotesGranted == {3} &&
      (state.nodes 1).membershipState == .retirementOrdered &&
      (state.nodes 1).retirementIndex == some 2 &&
      (state.nodes 1).retirementCommittableIndex == some 3 &&
      (state.nodes 1).retiredCommittedIndex == some 4 &&
      (state.network 1).length == 7 &&
      (state.network 1).map Message.source == [2, 2, 2, 2, 2, 2, 2] &&
      (state.network 1).map Message.destination == [1, 1, 1, 1, 1, 1, 1] &&
      (state.network 1).map Message.term == [8, 8, 8, 8, 8, 8, 8] &&
      state.submittedTxIds == {TraceSmt.NatTerm.unknown ⟨0, by decide⟩} &&
      state.hasJoined == {1, 2} &&
      state.preVoteStatus 0 == .enabled &&
      state.retirementCompleted 1 == {2, 3}

#guard match TraceStateJson.decode #["tx"] stateJson with
  | .ok state =>
      match (state.network 1).head? with
      | some (Message.appendEntriesRequest request) =>
          request.prevLogIndex == 7 && request.prevLogTerm == 6 &&
          request.leaderCommit == 3 && request.entries == (state.nodes 1).log &&
          request.entries == [{ term := 6, content := .transaction (.unknown ⟨0, by decide⟩) }]
      | _ => false
  | .error _ => false

#guard match TraceStateJson.decode #[] stateJson with
  | .error error => error == "undeclared transaction unknown: tx"
  | .ok _ => false

#guard match TraceStateJson.nodeTable Json.getNat? (toJson [0, 1]) with
  | .error _ => true
  | .ok _ => false

#guard match TraceStateJson.localState #[] (Json.mkObj [("role", toJson "leader")]) with
  | .error _ => true
  | .ok _ => false

#guard match TraceStateJson.entryContent #[] (Json.mkObj
    [("kind", toJson "signature"), ("transaction", toJson (0 : Nat))]) with
  | .error _ => true
  | .ok _ => false

end CCFRaft.TraceStateJsonTests
