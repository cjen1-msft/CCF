-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeEncode
import Sparse.NativeArrayVoteState

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open Lean

def decodePacket (width : PNat) (names : Array String) (value : Json) :
    Except String (Message (Fin width) Nat) := do
  let kind <- (<- field value "kind").getStr?
  let term <- natural (<- field value "term")
  let source <- resolve width names (<- field value "source")
  let destination <- resolve width names (<- field value "destination")
  match kind with
  | "appendEntriesRequest" =>
    fields value ["kind", "term", "source", "destination", "prevLogIndex", "prevLogTerm", "leaderCommit", "entries"]
    let prevLogIndex <- natural (<- field value "prevLogIndex")
    let prevLogTerm <- natural (<- field value "prevLogTerm")
    let leaderCommit <- natural (<- field value "leaderCommit")
    let entries <- (<- (<- field value "entries").getArr?).toList.mapM (decodeEntry width names)
    return .appendEntriesRequest { term, source, destination, prevLogIndex, prevLogTerm, leaderCommit, entries }
  | "appendEntriesResponse" =>
    fields value ["kind", "term", "source", "destination", "success", "lastLogIndex"]
    let success <- (<- field value "success").getBool?
    let lastLogIndex <- natural (<- field value "lastLogIndex")
    return .appendEntriesResponse { term, source, destination, success, lastLogIndex }
  | "requestVoteRequest" | "requestPreVote" =>
    fields value ["kind", "term", "source", "destination", "lastCommittableTerm", "lastCommittableIndex"]
    let lastCommittableTerm <- natural (<- field value "lastCommittableTerm")
    let lastCommittableIndex <- natural (<- field value "lastCommittableIndex")
    if kind = "requestVoteRequest" then
      return .requestVoteRequest { term, source, destination, lastCommittableTerm, lastCommittableIndex }
    else
      return .requestPreVote { term, source, destination, lastCommittableTerm, lastCommittableIndex }
  | "requestVoteResponse" | "requestPreVoteResponse" =>
    fields value ["kind", "term", "source", "destination", "voteGranted"]
    let voteGranted <- (<- field value "voteGranted").getBool?
    if kind = "requestVoteResponse" then
      return .requestVoteResponse { term, source, destination, voteGranted }
    else
      return .requestPreVoteResponse { term, source, destination, voteGranted }
  | "proposeVoteRequest" =>
    fields value ["kind", "term", "source", "destination"]
    return .proposeVoteRequest { term, source, destination }
  | _ => throw s!"unknown packet kind {kind}"

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
