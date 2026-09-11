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

def membershipName : MembershipState -> String
  | .active => "active"
  | .retirementOrdered => "retirementOrdered"
  | .retirementSigned => "retirementSigned"
  | .retirementCompleted => "retirementCompleted"
  | .retiredCommitted => "retiredCommitted"

def nodeObservations (node : Fin 3) (state : NodeState (Fin 3) Nat) : List Json :=
  let observation := fun kind value =>
    Json.mkObj [("kind", toJson kind), ("node", toJson (nodeName node)), ("value", value)]
  [observation "role" (toJson (roleName state.role)),
    observation "currentTerm" (toJson state.currentTerm),
    observation "newFollower" (toJson state.isNewFollower),
    observation "commit" (toJson state.commitIndex),
    observation "logLength" (toJson state.log.length),
    observation "votedFor" (toJson (state.votedFor.map nodeName)),
    observation "votesGranted" (toJson (nodeNames state.votesGranted)),
    observation "preVotesGranted" (toJson (nodeNames state.preVotesGranted)),
    observation "membershipState" (toJson (membershipName state.membershipState)),
    observation "retirementIndex" (toJson state.retirementIndex),
    observation "retirementCommittableIndex" (toJson state.retirementCommittableIndex),
    observation "retiredCommittedIndex" (toJson state.retiredCommittedIndex)] ++
    (List.finRange 3).flatMap (fun peer =>
      [("sentIndex", state.sentIndex peer), ("matchIndex", state.matchIndex peer)].map
        fun (kind, value) =>
          Json.mkObj [("kind", toJson kind), ("node", toJson (nodeName node)),
            ("peer", toJson (nodeName peer)), ("value", toJson value)]) ++
    state.log.zipIdx.map (fun (entry, index) =>
      Json.mkObj [("kind", toJson "entry"), ("node", toJson (nodeName node)),
        ("index", toJson index), ("value", entryJson entry)])

def globalObservations (state : State (Fin 3) Nat) (txIds : List Nat) : List Json :=
  [Json.mkObj [("kind", toJson "hasJoined"), ("value", toJson (nodeNames state.hasJoined))]] ++
    (List.finRange 3).flatMap (fun node =>
      [Json.mkObj [("kind", toJson "preVoteStatus"), ("node", toJson (nodeName node)),
        ("value", toJson (if state.preVoteStatus node = .enabled then "enabled" else "capable"))],
       Json.mkObj [("kind", toJson "retirementCompleted"), ("node", toJson (nodeName node)),
        ("value", toJson (nodeNames (state.retirementCompleted node)))]]) ++
    txIds.map (fun txId => Json.mkObj [("kind", toJson "submittedTxId"), ("txId", toJson txId),
      ("value", toJson (decide (txId ∈ state.submittedTxIds)))])

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
