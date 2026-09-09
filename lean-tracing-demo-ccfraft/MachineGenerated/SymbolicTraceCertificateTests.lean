-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import SymbolicTraceCertificate

set_option autoImplicit false

namespace CCFRaft.SymbolicTraceCertificate.Tests

open Lean Symbolic SymbolicModel

private def limits : List (String × Json) :=
  [("transaction_count", toJson (2 : Nat)), ("term_count", toJson (3 : Nat)),
   ("index_count", toJson (4 : Nat)), ("log_capacity", toJson (1 : Nat)),
   ("queue_capacity", toJson (2 : Nat))]

private def root (steps : List Json := []) : List (String × Json) :=
  [("schema_version", .str "ccfraft-symbolic-trace/v1"), ("entry", .str "symbolic"),
   ("bounds", Json.mkObj limits), ("unknowns", toJson #["x", "y"]), ("steps", toJson steps)]

private def replace (fields : List (String × Json)) (key : String) (value : Json) :
    List (String × Json) :=
  (key, value) :: fields.filter (fun field => field.1 != key)

private def actionJson (name : String) (extra : List (String × Json) := []) : Json :=
  Json.mkObj ([("kind", .str "action"), ("action", .str name), ("node", toJson (2 : Nat))] ++ extra)

private def observationJson (name : String) (value : Json)
    (extra : List (String × Json) := [("node", toJson (2 : Nat))]) : Json :=
  Json.mkObj ([("kind", .str "observation"), ("variable", .str name), ("value", value)] ++ extra)

private def signature : Action -> String × List Nat
  | .clientRequest node tx => ("clientRequest", [node.val, tx.eval id])
  | .changeConfiguration node config =>
      ("changeConfiguration", node.val :: (config.sort (· ≤ ·)).map Fin.val)
  | .appendRetiredCommitted node => ("appendRetiredCommitted", [node.val])
  | .signCommittableMessages node => ("signCommittableMessages", [node.val])
  | .appendEntries source destination batch => ("appendEntries", [source.val, destination.val, batch])
  | .receive source destination => ("receive", [source.val, destination.val])
  | .advanceCommitIndex node => ("advanceCommitIndex", [node.val])
  | .timeout node => ("timeout", [node.val])
  | .becomePreVoteCandidate node => ("becomePreVoteCandidate", [node.val])
  | .becomeCandidate node => ("becomeCandidate", [node.val])
  | .requestVote source destination => ("requestVote", [source.val, destination.val])
  | .requestPreVote source destination => ("requestPreVote", [source.val, destination.val])
  | .checkQuorum node => ("checkQuorum", [node.val])
  | .updateTerm source destination => ("updateTerm", [source.val, destination.val])
  | .becomeLeader node => ("becomeLeader", [node.val])
  | .proposeVote source destination => ("proposeVote", [source.val, destination.val])
  | .advanceCommitIndexAndProposeVote source destination =>
      ("advanceCommitIndexAndProposeVote", [source.val, destination.val])

private def unary : List String :=
  ["appendRetiredCommitted", "signCommittableMessages", "advanceCommitIndex", "timeout",
   "becomePreVoteCandidate", "becomeCandidate", "checkQuorum", "becomeLeader"]
private def peer : List String :=
  ["receive", "requestVote", "requestPreVote", "updateTerm",
   "proposeVote", "advanceCommitIndexAndProposeVote"]
private def peerFields : List (String × Json) := [("destination", toJson (7 : Nat))]

#guard unary.length + peer.length + 3 == 17
#guard unary.all fun name =>
  match action 100 #[] (actionJson name) with
  | .ok result => signature result == (name, [2])
  | .error _ => false
#guard peer.all fun name =>
  match action 100 #[] (actionJson name peerFields) with
  | .ok result => signature result == (name, [2, 7])
  | .error _ => false
#guard match action 100 #[] (actionJson "appendEntries"
    (peerFields ++ [("batchEnd", toJson (3 : Nat))])) with
  | .ok result => signature result == ("appendEntries", [2, 7, 3])
  | .error _ => false
#guard match action 100 #[] (actionJson "clientRequest" [("transaction", toJson (5 : Nat))]) with
  | .ok result => signature result == ("clientRequest", [2, 5])
  | .error _ => false
#guard match action 100 #[] (actionJson "changeConfiguration"
    [("configuration", toJson ([3, 4] : List Nat))]) with
  | .ok result => signature result == ("changeConfiguration", [2, 3, 4])
  | .error _ => false

private def allActions : List Json :=
  (unary.map (fun name => actionJson name)) ++
    (peer.map (fun name => actionJson name peerFields)) ++
    [actionJson "appendEntries" (peerFields ++ [("batchEnd", toJson (3 : Nat))]),
     actionJson "clientRequest" [("transaction", toJson (5 : Nat))],
     actionJson "changeConfiguration" [("configuration", toJson ([3, 4] : List Nat))]]
#guard match decode (Json.mkObj (root allActions)) with
  | .ok input =>
      input.trace.length == 17 && input.trace.all (fun
        | .action _ => true
        | .observation _ => false)
  | .error _ => false

private def unknown (name : String) : Json := Json.mkObj [("unknown", .str name)]
private def namedSteps : List Json :=
  [actionJson "clientRequest" [("transaction", unknown "x"),
      ("provenance", Json.mkObj [("raw_index", toJson (99 : Nat))]), ("rule", .str "client")],
   observationJson "submitted" (.bool true) [("transaction", unknown "x")],
   actionJson "clientRequest" [("transaction", unknown "y")],
   actionJson "receive" peerFields]

-- Structural input slots and explicitly named transaction slots never overlap.
#guard match decode (Json.mkObj (root namedSteps)) with
  | .ok input =>
      match input.trace with
      | [.action (.clientRequest _ (.unknown first)),
         .observation (.submitted (.unknown repeated) true),
         .action (.clientRequest _ (.unknown second)),
         .action (.receive source destination)] =>
          first == entryWidth input.bounds && repeated == first && second == first + 1 &&
          source.val == 2 && destination.val == 7 && input.rawSteps == namedSteps.toArray &&
          input.unknowns == #["x", "y"] &&
          (Expr.eq input.entry (freshEntry input.bounds)).eval (fun _ => 3) &&
          ((evalEntry input.bounds (fun _ => 0) input.entry).node? source).isNone &&
          ((evalEntry input.bounds (fun _ => 1) input.entry).node? source).isSome
      | _ => false
  | .error _ => false

-- Distinct names may evaluate to the same value. Domains are an encoder obligation.
#guard match SymbolicTraceObservation.transactionValue 100 #["x", "y"] (unknown "x"),
    SymbolicTraceObservation.transactionValue 100 #["x", "y"] (unknown "y") with
  | .ok (.unknown x), .ok (.unknown y) =>
      x == 100 && y == 101 &&
        (Expr.eq (.unknown x) (.unknown y)).eval (fun _ => 999)
  | _, _ => false
#guard match decode (Json.mkObj (replace (root []) "bounds"
    (Json.mkObj (limits.map fun (key, _) => (key, toJson (0 : Nat)))))) with
  | .ok input => input.unknowns == #["x", "y"]
  | .error _ => false

-- Initial facts stay observations, rather than being materialized into the entry.
#guard match decode (Json.mkObj (root [observationJson "role" (.str "leader")])) with
  | .ok input =>
      match input.trace with
      | [.observation (.role node .leader)] =>
          node.val == 2 && ((evalEntry input.bounds (fun _ => 0) input.entry).node? node).isNone
      | _ => false
  | .error _ => false

#guard [("none", Role.none), ("follower", .follower), ("preVoteCandidate", .preVoteCandidate),
    ("candidate", .candidate), ("leader", .leader)].all fun (text, expected) =>
  match SymbolicTraceObservation.decode 100 #[] (observationJson "role" (.str text)) with
  | .ok (.role node value) => node.val == 2 && value == expected
  | _ => false
#guard ["currentTerm", "logLength", "queueLength", "commitIndex"].all fun name =>
  match SymbolicTraceObservation.decode 100 #[] (observationJson name (toJson (13 : Nat))) with
  | .ok (.currentTerm node value) => name == "currentTerm" && node.val == 2 && value == 13
  | .ok (.logLength node value) => name == "logLength" && node.val == 2 && value == 13
  | .ok (.queueLength node value) => name == "queueLength" && node.val == 2 && value == 13
  | .ok (.commitIndex node value) => name == "commitIndex" && node.val == 2 && value == 13
  | _ => false
#guard ["allocated", "joined"].all fun name => [true, false].all fun expected =>
  match SymbolicTraceObservation.decode 100 #[] (observationJson name (.bool expected)) with
  | .ok (.allocated node value) => name == "allocated" && node.val == 2 && value == expected
  | .ok (.joined node value) => name == "joined" && node.val == 2 && value == expected
  | _ => false

private def stateFacts : List Json :=
  [observationJson "preVoteStatus" (.str "enabled"),
   observationJson "membershipState" (.str "retirementCompleted"),
   observationJson "retirementIndex" .null,
   observationJson "retirementCommittableIndex" (toJson (0 : Nat)),
   observationJson "retiredCommittedIndex" (toJson (123 : Nat)),
   observationJson "retirementCompleted" (.bool true)
     [("observer", toJson (14 : Nat)), ("retired", toJson (2 : Nat))]]
#guard stateFacts.all fun json =>
  match SymbolicTraceObservation.decode 100 #[] json, TraceStateObservation.decode json with
  | .ok (.state observation), .ok expected => observation == expected
  | _, _ => false

private def packetJson : Json :=
  Json.mkObj [("kind", .str "appendEntriesRequest"), ("term", toJson (2 : Nat)),
    ("source", toJson (7 : Nat)), ("destination", toJson (2 : Nat)),
    ("prevLogIndex", toJson (1 : Nat)), ("entriesLength", toJson (3 : Nat)),
    ("leaderCommit", toJson (1 : Nat))]
#guard match SymbolicTraceObservation.decode 100 #[]
    (observationJson "firstMessageFrom" packetJson), TraceMessageSummary.decode packetJson with
  | .ok (.message summary), .ok expected => summary == expected
  | _, _ => false
#guard (SymbolicTraceObservation.decode 100 #[] (observationJson "firstMessageFrom" packetJson
  [("node", toJson (7 : Nat))])).toOption.isNone
#guard (SymbolicTraceObservation.decode 100 #[] (observationJson "firstMessageFrom" packetJson
  [])).toOption.isNone

private def invalidCounts : List Json :=
  [toJson (-1 : Int), .bool true, .bool false, .str "1", .null, .arr #[], Json.mkObj []]
#guard limits.all fun (key, _) => invalidCounts.all fun value =>
  (decode (Json.mkObj (replace (root []) "bounds"
    (Json.mkObj (replace limits key value))))).toOption.isNone
#guard limits.all fun (key, _) =>
  (decode (Json.mkObj (replace (root []) "bounds"
    (Json.mkObj (limits.filter (fun field => field.1 != key)))))).toOption.isNone
#guard (decode (Json.mkObj (replace (root []) "bounds"
  (Json.mkObj (("extra", .null) :: limits))))).toOption.isNone
#guard (root []).all fun (key, _) =>
  (decode (Json.mkObj ((root []).filter fun field => field.1 != key))).toOption.isNone
#guard (decode (Json.mkObj (("raw", .null) :: root []))).toOption.isNone
#guard ["bootstrap", "template", "", "Symbolic"].all fun profile =>
  (decode (Json.mkObj (replace (root []) "entry" (.str profile)))).toOption.isNone
#guard [Json.mkObj [], Json.null, Json.bool true].all fun profile =>
  (decode (Json.mkObj (replace (root []) "entry" profile))).toOption.isNone
#guard ["ccfraft-trace/v1", "ccfraft-client-request/v1", "ccfraft-symbolic-trace/v2"].all fun version =>
  (decode (Json.mkObj (replace (root []) "schema_version" (.str version)))).toOption.isNone
#guard [toJson #["x", "x"], toJson #[""], toJson #[1], Json.null, Json.str "x"].all fun names =>
  (decode (Json.mkObj (replace (root []) "unknowns" names))).toOption.isNone
#guard (decode (Json.mkObj (replace (root []) "unknowns" (toJson (#[] : Array String))))).toOption.isSome
#guard (decode (Json.mkObj (replace (root []) "steps" (Json.mkObj [])))).toOption.isNone

#guard (unary ++ peer ++ ["clientRequest", "changeConfiguration", "appendEntries"]).all fun name =>
  (action 100 #[] (actionJson name [("extra", .null)])).toOption.isNone
#guard (peer ++ ["appendEntries"]).all fun name =>
  (action 100 #[] (actionJson name)).toOption.isNone
#guard (action 100 #[] (actionJson "appendEntries" peerFields)).toOption.isNone
#guard invalidCounts.all fun count =>
  (action 100 #[] (actionJson "appendEntries" (peerFields ++ [("batchEnd", count)]))).toOption.isNone
#guard (action 100 #[] (actionJson "clientRequest")).toOption.isNone
#guard (action 100 #[] (actionJson "changeConfiguration")).toOption.isNone
#guard (action 100 #[] (actionJson "timeout" peerFields)).toOption.isNone
#guard (action 100 #[] (actionJson "receive" [("destination", toJson (15 : Nat))])).toOption.isNone
#guard (action 100 #[] (actionJson "receive" [("destination", .bool false)])).toOption.isNone
#guard (action 100 #[] (actionJson "unknownAction")).toOption.isNone
#guard (instruction 100 #[] (Json.mkObj [("kind", .str "rawState")])).toOption.isNone
#guard (instruction 100 #[] (Json.mkObj [("action", .str "timeout"), ("node", toJson (2 : Nat))])).toOption.isNone
#guard (action 100 #[] (Json.mkObj
  [("kind", .str "action"), ("action", .str "timeout"), ("node", toJson (15 : Nat))])).toOption.isNone
#guard (action 100 #[] (Json.mkObj [("kind", .str "action"), ("action", .str "timeout")])).toOption.isNone

#guard invalidCounts.all fun value =>
  (SymbolicTraceObservation.transactionValue 100 #["x"] value).toOption.isNone
#guard (SymbolicTraceObservation.transactionValue 100 #["x"] (unknown "y")).toOption.isNone
#guard (SymbolicTraceObservation.transactionValue 100 #["x"]
  (Json.mkObj [("unknown", .str "x"), ("extra", .null)])).toOption.isNone
#guard (SymbolicTraceObservation.transactionValue 100 #["x"]
  (Json.mkObj [("unknown", toJson (0 : Nat))])).toOption.isNone
#guard (decode (Json.mkObj (root [actionJson "clientRequest"
  [("transaction", unknown "undeclared")]]))).toOption.isNone
#guard (SymbolicTraceObservation.decode 100 #["x"]
  (observationJson "submitted" (.bool false) [("transaction", unknown "undeclared")])).toOption.isNone

#guard ["currentTerm", "logLength", "queueLength", "commitIndex"].all fun name =>
  invalidCounts.all fun value =>
    (SymbolicTraceObservation.decode 100 #[] (observationJson name value)).toOption.isNone
#guard ["allocated", "joined", "submitted"].all fun name =>
  (SymbolicTraceObservation.decode 100 #[] (observationJson name (toJson (0 : Nat))
    (if name == "submitted" then [("transaction", toJson (0 : Nat))]
      else [("node", toJson (2 : Nat))]))).toOption.isNone
#guard (SymbolicTraceObservation.decode 100 #[] (observationJson "role" (.str "Leader"))).toOption.isNone
#guard (SymbolicTraceObservation.decode 100 #[] (observationJson "unknownField" .null)).toOption.isNone
#guard (SymbolicTraceObservation.decode 100 #[] (observationJson "retirementIndex" .null
  [("node", toJson (2 : Nat)), ("extra", .null)])).toOption.isNone
#guard (SymbolicTraceObservation.decode 100 #[] (Json.mkObj
  [("kind", .str "observation"), ("variable", .str "retirementIndex"),
   ("node", toJson (2 : Nat))])).toOption.isNone

end CCFRaft.SymbolicTraceCertificate.Tests

private def decodeFile (path : String) : IO Unit := do
  let json <- match Lean.Json.parse (← IO.FS.readFile path) with
    | .ok value => pure value
    | .error message => throw (IO.userError s!"{path}: {message}")
  let input <- match CCFRaft.SymbolicTraceCertificate.decode json with
    | .ok value => pure value
    | .error message => throw (IO.userError s!"{path}: {message}")
  let start := CCFRaft.SymbolicModel.entryWidth input.bounds
  let mut references : Array Lean.Json := #[]
  for (instruction, index) in input.trace.zipIdx do
    let transaction := match instruction with
      | .action (.clientRequest _ value) => some value
      | .observation (.submitted value _) => some value
      | _ => none
    if let some value := transaction then
      let payload <- match value with
        | .unknown slot => pure ("unknown_index", Lean.toJson slot)
        | .nat value => pure ("literal", Lean.toJson value)
        | _ => throw (IO.userError s!"{path}: unexpected decoded transaction expression")
      references := references.push (Lean.Json.mkObj
        [("step", Lean.toJson (index + 1)), payload])
  let names := input.unknowns.toList.zipIdx.map fun (name, index) =>
    Lean.Json.mkObj [("name", .str name), ("index", Lean.toJson (start + index))]
  IO.println (Lean.Json.mkObj
    [("mode", .str "decode-only"), ("certificate", .str path),
     ("steps", Lean.toJson input.trace.length), ("entry_width", Lean.toJson start),
     ("unknowns", Lean.toJson names), ("transaction_references", .arr references),
     ("raw_steps_preserved", .bool ((json.getObjVal? "steps").toOption ==
       some (Lean.toJson input.rawSteps)))]).compress

def main (args : List String) : IO Unit :=
  match args with
  | "--decode" :: first :: rest => do
      for path in first :: rest do decodeFile path
  | _ => throw (IO.userError
      "usage: SymbolicTraceCertificateTests.lean --decode CERTIFICATE [CERTIFICATE ...] (decode only)")
