-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativePacketJson
import Sparse.NativePacketPattern

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open Lean

private def patternFields (value : Json) (payloadFields : List String) : Except String Unit := do
  let actual := (<- value.getObj?).toList.map Prod.fst
  let allowed := ["kind", "term", "source", "destination"] ++ payloadFields
  unless actual.all allowed.contains do
    throw s!"allowed packet pattern fields {allowed}; got {actual}"

private def optionalPacketField {α : Type} (value : Json) (key : String)
    (decode : Json -> Except String α) : Except String (Option α) := do
  let object <- value.getObj?
  match object.toList.find? (fun item => item.1 == key) with
  | none => return none
  | some (_, value) => return some (<- decode value)

def decodePacketPattern (width : PNat) (names : Array String) (value : Json) :
    Except String (NativePacketPattern.Pattern (Fin width) Nat) := do
  let kind <- (<- field value "kind").getStr?
  let header : NativePacketPattern.Header (Fin width) := {
    term := <- optionalPacketField value "term" natural
    source := <- optionalPacketField value "source" (resolve width names)
    destination := <- optionalPacketField value "destination" (resolve width names) }
  let payload : NativePacketPattern.Payload (Fin width) Nat <- (match kind with
    | "appendEntriesRequest" => do
      patternFields value ["prevLogIndex", "prevLogTerm", "leaderCommit", "entriesLength", "entries"]
      return NativePacketPattern.Payload.appendEntriesRequest
        (<- optionalPacketField value "prevLogIndex" natural)
        (<- optionalPacketField value "prevLogTerm" natural)
        (<- optionalPacketField value "leaderCommit" natural)
        (<- optionalPacketField value "entriesLength" natural)
        (<- optionalPacketField value "entries" fun entries => do
          (<- entries.getArr?).toList.mapM (decodeEntry width names))
    | "appendEntriesResponse" => do
      patternFields value ["success", "lastLogIndex"]
      return .appendEntriesResponse
        (<- optionalPacketField value "success" Json.getBool?)
        (<- optionalPacketField value "lastLogIndex" natural)
    | "requestVoteRequest" | "requestPreVote" => do
      patternFields value ["lastCommittableTerm", "lastCommittableIndex"]
      let lastTerm <- optionalPacketField value "lastCommittableTerm" natural
      let lastIndex <- optionalPacketField value "lastCommittableIndex" natural
      return if kind = "requestVoteRequest" then .requestVoteRequest lastTerm lastIndex
        else .requestPreVote lastTerm lastIndex
    | "requestVoteResponse" | "requestPreVoteResponse" => do
      patternFields value ["voteGranted"]
      let granted <- optionalPacketField value "voteGranted" Json.getBool?
      return if kind = "requestVoteResponse" then .requestVoteResponse granted
        else .requestPreVoteResponse granted
    | "proposeVoteRequest" => do
      patternFields value []
      return .proposeVoteRequest
    | _ => throw s!"unknown packet pattern kind {kind}")
  return { header, payload }

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
