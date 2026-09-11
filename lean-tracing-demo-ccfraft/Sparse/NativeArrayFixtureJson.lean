-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Model
import Lean.Data.Json

set_option autoImplicit false

namespace CCFRaft.NativeArrayFixtures

open Lean

def roleName : Role -> String
  | .none => "none"
  | .follower => "follower"
  | .candidate => "candidate"
  | .preVoteCandidate => "preVoteCandidate"
  | .leader => "leader"

def nodeName (node : Fin 3) : String :=
  if node = 0 then "a" else if node = 1 then "b" else "c"

def nodeNames (nodes : Finset (Fin 3)) : List String :=
  ((List.finRange 3).filter fun node => node ∈ nodes).map nodeName

def contentJson : EntryContent (Fin 3) Nat -> Json
  | .signature => toJson "signature"
  | .transaction tx => Json.mkObj [("transaction", toJson tx)]
  | .reconfiguration nodes => Json.mkObj [("reconfiguration", toJson (nodeNames nodes))]
  | .retiredCommitted nodes => Json.mkObj [("retiredCommitted", toJson (nodeNames nodes))]

def entryJson (entry : Entry (Fin 3) Nat) : Json :=
  Json.mkObj [("term", toJson entry.term), ("content", contentJson entry.content)]

def messageJson (message : Message (Fin 3) Nat) : Json :=
  let fields := [("term", toJson message.term),
    ("source", toJson (nodeName message.source)), ("destination", toJson (nodeName message.destination))]
  let snapshot := fun term index => [("lastCommittableTerm", toJson term), ("lastCommittableIndex", toJson index)]
  let (kind, extra) : String × List (String × Json) := match message with
    | .appendEntriesRequest request =>
      ("appendEntriesRequest", [("prevLogIndex", toJson request.prevLogIndex),
        ("prevLogTerm", toJson request.prevLogTerm), ("entries", toJson (request.entries.map entryJson)),
        ("leaderCommit", toJson request.leaderCommit)])
    | .appendEntriesResponse response =>
      ("appendEntriesResponse", [("success", toJson response.success), ("lastLogIndex", toJson response.lastLogIndex)])
    | .requestVoteRequest request =>
      ("requestVoteRequest", snapshot request.lastCommittableTerm request.lastCommittableIndex)
    | .requestPreVote request =>
      ("requestPreVote", snapshot request.lastCommittableTerm request.lastCommittableIndex)
    | .requestVoteResponse response =>
      ("requestVoteResponse", [("voteGranted", toJson response.voteGranted)])
    | .requestPreVoteResponse response =>
      ("requestPreVoteResponse", [("voteGranted", toJson response.voteGranted)])
    | .proposeVoteRequest _ => ("proposeVoteRequest", [])
  Json.mkObj ([("kind", toJson kind)] ++ fields ++ extra)

end CCFRaft.NativeArrayFixtures
