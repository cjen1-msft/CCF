-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicReceive
import MachineGenerated.SymbolicTransitionEvaluation
import Shared.SymbolicSmt
import Shared.SymbolicEvalMemo
import Lean

set_option autoImplicit false

namespace CCFRaft.SymbolicReceive.Tests

open Symbolic SymbolicModel

private def source : Node := ⟨0, by decide⟩
private def destination : Node := ⟨1, by decide⟩
private def other : Node := ⟨2, by decide⟩
private def absent : Node := ⟨14, by decide⟩
private def limits : BoundedState.Bounds := ⟨16, 4, 8, 2, 4⟩
private def aliasAssignment : Assignment := fun _ => 7
private def distinctAssignment : Assignment := fun i => if i = 0 then 7 else 8

private def fixture (bounds : BoundedState.Bounds) (role : Role)
    (sourceAllocated destinationAllocated : Bool) (queue : List (Message Node Nat)) :
    Expr (stateCodec bounds.transactionCount).ty :=
  let node : NodeState Node Nat :=
    { (freshNodeState : NodeState Node Nat) with
      role, currentTerm := 1, log := [⟨1, .transaction 7⟩] }
  (stateCodec bounds.transactionCount).literal
    (Vector.ofFn (fun n =>
        if (n = source ∧ sourceAllocated) ∨ (n = destination ∧ destinationAllocated) then
          some (BoundedState.encodeLocal node)
        else none),
      Vector.ofFn (fun n => if n = destination then queue else []),
      ∅, {other}, Vector.ofFn (fun n => if n = absent then .enabled else .capable),
      Vector.ofFn (fun n => if n = absent then {source, destination} else ∅))

private def tx (unknown : Nat) : Expr entryCodec.ty :=
  .pair (.nat 1) (.inl (.unknown unknown))

private def request (sender : Node := source) : Expr appendRequestCodec.ty :=
  .pair (.nat 1) (.pair (.nat 0) (.pair (.nat 0)
    (.pair (.cons (tx 1) (.cons (entryCodec.literal ⟨1, .signature⟩) .nil))
      (.pair (.nat 2) (.pair (nodeCodec.literal sender) (nodeCodec.literal destination))))))

private def aliasEntry : Expr (stateCodec limits.transactionCount).ty :=
  let base := fixture limits .follower true true []
  let state := Local.unpack (nodeStateCodec.literal
    { (freshNodeState : NodeState Node Nat) with role := .follower, currentTerm := 1 })
  let updated := SymbolicTransition.writeLocal limits.transactionCount base (nodeCodec.literal destination)
    { state with log := .cons (tx 0) .nil }.pack
  writeQueue limits.transactionCount updated (nodeCodec.literal destination) (.cons (.inl request) .nil)

private def enabledDecision (state : State Node Nat) (source destination : Node) : Bool :=
  @decide (Enabled state (.receive source destination)) (by unfold Enabled; infer_instance)

private def check (name : String) (bounds : BoundedState.Bounds)
    (entry : Expr (stateCodec bounds.transactionCount).ty) (ρ : Assignment)
    (sender : Node := source) (receiver : Node := destination)
    (diagnostics : Bool := false) : IO Unit := do
  let start ← IO.monoMsNow
  IO.eprintln s!"Symbolic receive: {name}"
  let (state, evaluation) := (SymbolicTransition.evalEntryMemoM bounds ρ entry).run {}
  unless decide (BoundedState.WithinBounds bounds state) do
    throw (IO.userError s!"{name}: invalid input fixture")
  let modelNext := next state (.receive sender receiver)
  if diagnostics then IO.eprintln "  constructing symbolic step"
  let transition := step bounds entry sender receiver
  if diagnostics then IO.eprintln "  evaluating symbolic successor"
  let (actual, evaluation) :=
    (SymbolicTransition.evalEntryMemoM bounds ρ transition.successor).run evaluation
  if diagnostics then IO.eprintln "  evaluating accepted guard"
  let accepted := ((transition.enabled.evalMemoM ρ).run evaluation).1
  let expected := enabledDecision state sender receiver &&
    decide (BoundedState.WithinBounds bounds modelNext)
  unless accepted == expected do
    throw (IO.userError s!"{name}: accepted guard differs from Enabled and successor bounds")
  unless decide (BoundedState.encode actual = BoundedState.encode modelNext) do
    throw (IO.userError s!"{name}: assigned successor differs from Model.next")
  IO.eprintln s!"  passed ({(← IO.monoMsNow) - start} ms)"

private def packets (term : Nat) : List (Message Node Nat) :=
  [ .appendEntriesRequest ⟨term, 0, 0, [⟨1, .transaction 7⟩, ⟨1, .signature⟩], 2, source, destination⟩,
    .appendEntriesResponse ⟨term, true, 1, source, destination⟩,
    .appendEntriesResponse ⟨term, false, 1, source, destination⟩,
    .requestVoteRequest ⟨term, 1, 1, source, destination⟩,
    .requestVoteResponse ⟨term, true, source, destination⟩,
    .requestVoteResponse ⟨term, false, source, destination⟩,
    .requestPreVote ⟨term, 1, 1, source, destination⟩,
    .requestPreVoteResponse ⟨term, true, source, destination⟩,
    .requestPreVoteResponse ⟨term, false, source, destination⟩,
    .proposeVoteRequest ⟨term, source, destination⟩ ]

def freshRegressions : IO Unit := do
  let bounds := { limits with logCapacity := 1, queueCapacity := 1 }
  let entry := Expr.named 0 0 (freshEntry bounds 0)
  for ρ in [(fun _ => 0), (fun _ => 1), (fun i => i % 2)] do
    check "arbitrary named fresh entry" bounds entry ρ absent absent true

private def phase {α : Type} (name : String) (build : Unit → α) : IO α := do
  IO.eprintln s!"  constructing {name}"
  let start ← IO.monoMsNow
  let cell ← IO.mkRef (build ())
  let value ← cell.get
  IO.eprintln s!"  constructed {name} ({(← IO.monoMsNow) - start} ms)"
  return value

def constructionRegressions : IO Unit := do
  let bounds := { limits with logCapacity := 1, queueCapacity := 1 }
  let entry ← phase "entry" fun _ => compact (.named 0 0 (freshEntry bounds 0))
  let node := nodeCodec.literal absent
  let queue ← phase "queue" fun _ => entryQueue bounds.transactionCount entry node
  let selected ← phase "selection" fun _ => SymbolicTransition.queueTakeFirstById bounds.queueCapacity node queue
  let selected ← phase "compact selection once" fun _ => compact selected
  let selected ← phase "compact selection twice" fun _ => compact selected
  let pair ← phase "selection payload" fun _ =>
    chooseOption (messageCodec.prod queueCodec) selected (defaultExpr (messageCodec.prod queueCodec).ty) id
  let nodeState ← phase "local" fun _ => Local.unpack (SymbolicTransition.readLocal bounds.transactionCount entry node)
  let request ← phase "append payload" fun _ => Expr.fromLeft pair.fst (defaultExpr appendRequestCodec.ty)
  let response ← phase "append handler" fun _ => appendRequest bounds.logCapacity nodeState (Append.unpack request)
  let result ← phase "append result payload" fun _ =>
    chooseOption (nodeStateCodec.prod appendResponseCodec) response
      (defaultExpr (nodeStateCodec.prod appendResponseCodec).ty) id
  let refreshed ← phase "retirement refresh" fun _ =>
    refresh (bounds.logCapacity * 2) node (Local.unpack result.fst)
  let _ ← phase "retirement completed" fun _ =>
    completedNodes (bounds.logCapacity * 2) refreshed.log refreshed.commitIndex
  let _ ← phase "dispatch" fun _ => dispatch bounds entry node pair.snd pair.fst
  let handled ← phase "handle" fun _ => handle bounds entry node node
  let successor ← phase "successor" fun _ => Expr.fromRight handled entry
  let enabled ← phase "enabled" fun _ =>
    (SymbolicTransition.allocated bounds.transactionCount entry node).and (SymbolicTransition.isSome handled)
  let post ← phase "postWithin" fun _ => postWithin bounds successor node node
  let _ ← phase "guard" fun _ => enabled.and post
  let _ ← phase "complete step" fun _ => step bounds entry absent absent

def writeSmtRegression (path : String) : IO Unit := do
  let bounds := { limits with logCapacity := 1, queueCapacity := 1 }
  let entry := Expr.named 0 0 (freshEntry bounds 0)
  let transition ← phase "fresh SMT step" fun _ => step bounds entry absent absent
  let query ← phase "fresh SMT serialization" fun _ =>
    Symbolic.script [stateWithin bounds entry, transition.enabled]
  match query with
  | .error message => throw (IO.userError message)
  | .ok text =>
    IO.FS.writeFile path text
    IO.eprintln s!"  wrote {text.utf8ByteSize} SMT bytes"

def sharingRegression : IO Unit := do
  for depth in [8, 12, 16] do
    let value := (List.range depth).foldl (fun value _ => Expr.add value value) (.unknown 0)
    let clause := Expr.eq value (.nat 0)
    let projection := Expr.fst (.pair (.nat 7) value)
    let projected ← phase s!"dead-field {depth}-level Shared normalization" fun _ => projection.normalizeMemo
    let compacted ← phase s!"dead-field {depth}-level receive compaction" fun _ => compact projection
    unless projected.eval (fun _ => 0) == 7 && compacted.eval (fun _ => 0) == 7 do
      throw (IO.userError "dead-field projection changed its value")
    let _ ← phase s!"shared {depth}-level normalization" fun _ => clause.normalizeMemo
    let result ← phase s!"shared {depth}-level serialization" fun _ => Symbolic.script [clause]
    match result with
    | .error message => throw (IO.userError message)
    | .ok text => IO.eprintln s!"  shared {depth}-level output: {text.utf8ByteSize} bytes"

def writeZeroSmtRegressions (pathPrefix : String) : IO Unit := do
  let bounds : BoundedState.Bounds := ⟨0, 0, 0, 0, 0⟩
  let entry := Expr.named 0 0 (freshEntry bounds 0)
  let transition := step bounds entry absent absent
  for (suffix, accepted) in [("sat", false), ("unsat", true)] do
    let query ← phase s!"zero-bound {suffix} serialization" fun _ =>
      Symbolic.script [stateWithin bounds entry, .eq transition.enabled (.bool accepted)]
    match query with
    | .error message => throw (IO.userError message)
    | .ok text =>
      IO.FS.writeFile s!"{pathPrefix}-{suffix}.smt2" text
      IO.eprintln s!"  wrote {text.utf8ByteSize} SMT bytes"

def fixtureRegressions : IO Unit := do
  IO.eprintln "Symbolic receive: checking alias-sensitive extension"
  check "alias extension" limits aliasEntry aliasAssignment
  check "distinct overlap" limits aliasEntry distinctAssignment
  unless (step limits aliasEntry source destination).enabled.evalMemo aliasAssignment do
    throw (IO.userError "alias assignment must enable the full-entry prefix extension")
  if (step limits aliasEntry source destination).enabled.evalMemo distinctAssignment then
    throw (IO.userError "distinct assignment must not enable the extension")
  let aliasNext := SymbolicTransition.evalEntryMemo limits aliasAssignment
    (step limits aliasEntry source destination).successor
  unless (aliasNext.nodes destination).log == [⟨1, .transaction 7⟩, ⟨1, .signature⟩] &&
      (aliasNext.nodes destination).commitIndex == 2 &&
      aliasNext.network destination == [] && (aliasNext.node? absent).isNone do
    throw (IO.userError "alias successor lost exact log, commit, queue, or absent slots")
  let unrelated : Message Node Nat := .proposeVoteRequest ⟨1, other, destination⟩
  let later : Message Node Nat := .proposeVoteRequest ⟨0, source, destination⟩
  let filtered := writeQueue limits.transactionCount aliasEntry (nodeCodec.literal destination)
    (.ofList [messageCodec.literal unrelated, .inl request, messageCodec.literal unrelated,
      messageCodec.literal later])
  check "first-source filtering" limits filtered aliasAssignment
  check "no matching source" limits filtered aliasAssignment absent
  let filteredNext := SymbolicTransition.evalEntryMemo limits aliasAssignment
    (step limits filtered source destination).successor
  unless filteredNext.network destination == [unrelated, unrelated, later] do
    throw (IO.userError "source selection reordered or removed another packet")
  for role in [Role.candidate, .preVoteCandidate] do
    let candidate := SymbolicTransition.writeLocal limits.transactionCount aliasEntry (nodeCodec.literal destination)
      { Local.unpack (SymbolicTransition.readLocal limits.transactionCount aliasEntry (nodeCodec.literal destination))
        with role := roleCodec.literal role }.pack
    check "queued candidate step-down" limits candidate distinctAssignment
    let before := SymbolicTransition.evalEntryMemo limits distinctAssignment candidate
    let after := SymbolicTransition.evalEntryMemo limits distinctAssignment
      (step limits candidate source destination).successor
    unless (after.nodes destination).role == .follower && (after.nodes destination).isNewFollower &&
        after.network destination == before.network destination && after.network source == [] do
      throw (IO.userError "candidate step-down consumed or replied to the queued request")
  let selfAck : Message Node Nat := .appendEntriesResponse ⟨1, true, 2, destination, destination⟩
  for withAck in [false, true] do
    let tail := if withAck then [messageCodec.literal selfAck] else []
    let selfEntry := writeQueue limits.transactionCount aliasEntry (nodeCodec.literal destination)
      (.ofList (.inl (request destination) :: tail))
    check "self-receive queue sequencing" limits selfEntry aliasAssignment destination
    let after := SymbolicTransition.evalEntryMemo limits aliasAssignment
      (step limits selfEntry destination destination).successor
    unless after.network destination == [selfAck] do
      throw (IO.userError "self-receive failed post-dequeue reply deduplication")
  IO.eprintln "Symbolic receive: checking packet variants"
  let packetBounds := { limits with queueCapacity := 1 }
  for term in [0, 1, 2] do
    for (packet, index) in (packets term).zipIdx do
      let activeRole :=
        match packet with
        | .appendEntriesResponse _ => Role.leader
        | .requestVoteResponse _ => .candidate
        | .requestPreVoteResponse _ => .preVoteCandidate
        | _ => .follower
      let roles := if term = 1 then
        [Role.none, .follower, .preVoteCandidate, .candidate, .leader] else [activeRole]
      for role in roles do
        let allocations := if term = 1 && role == activeRole then [false, true] else [true]
        for sourceAllocated in allocations do
          check s!"packet matrix {term} {repr role} {sourceAllocated} variant {index}" packetBounds
            (fixture packetBounds role sourceAllocated true [packet]) aliasAssignment
  for packet in packets 1 do
    check "absent destination actual next" packetBounds
      (fixture packetBounds .follower true false [packet]) aliasAssignment
  let wrong := fixture limits .follower true true
    [.proposeVoteRequest ⟨0, source, other⟩, later]
  check "misdirected first packet blocks later packet" limits wrong aliasAssignment
  let overflowBounds := { limits with logCapacity := 1 }
  let fullQueue := fixture overflowBounds .follower true true
    [.requestVoteRequest ⟨1, 0, 0, source, destination⟩]
  let fullSource := writeQueue overflowBounds.transactionCount fullQueue (nodeCodec.literal source)
    (queueCodec.literal (List.replicate overflowBounds.queueCapacity later))
  check "response queue overflow" overflowBounds fullSource aliasAssignment
  unless enabledDecision
      (SymbolicTransition.evalEntryMemo overflowBounds aliasAssignment fullSource) source destination do
    throw (IO.userError "overflow fixture must be enabled in the unbounded Model")
  if (step overflowBounds fullSource source destination).enabled.evalMemo aliasAssignment then
    throw (IO.userError "bounded receive accepted a response queue overflow")
  let zero : BoundedState.Bounds := ⟨0, 0, 0, 0, 0⟩
  let empty := (stateCodec 0).literal
    (Vector.ofFn (fun _ => none), Vector.ofFn (fun _ => []), ∅, ∅,
      Vector.ofFn (fun _ => .enabled), Vector.ofFn (fun _ => {absent}))
  check "zero bounds and absent global tables" zero empty (fun _ => 0) absent absent
  IO.println "Symbolic receive: alias, packet variants, queue order, self-receive, absent slots, and bounds passed"

def run : IO Unit := do
  fixtureRegressions
  freshRegressions
  IO.println "Symbolic receive: all correspondence regressions passed"

def smoke : IO Unit := do
  check "alias extension" limits aliasEntry aliasAssignment
  check "distinct overlap" limits aliasEntry distinctAssignment
  IO.eprintln "Symbolic receive: smoke passed"

run_cmd do
  for name in [
      ``step_accepted_correct, ``step_next_correct, ``enabled_correct, ``successor_correct,
      ``handle_correct, ``handleReceive_dispatch, ``dispatch_correct, ``receiveAppend_correct,
      ``appendRequest_correct, ``appendResponse_correct, ``returnToFollower_correct,
      ``voteRequest_correct, ``voteResponse_correct, ``preVoteRequest_correct, ``preVoteResponse_correct,
      ``proposal_correct, ``refresh_correct, ``completedNodes_correct, ``extension_correct,
      ``append_result_log_bound, ``takeFirst_member, ``messageCases_correct,
      ``rawOptionCases_correct, ``optionOr_correct, ``rawConfigurationsFrom_correct,
      ``compact_correct] do
    for axiomName in ← Lean.collectAxioms name do
      unless axiomName == ``propext || axiomName == ``Classical.choice || axiomName == ``Quot.sound do
        throwError "{name} depends on unapproved axiom {axiomName}"

end CCFRaft.SymbolicReceive.Tests

def main (args : List String) : IO Unit :=
  if let ["--smt", path] := args then CCFRaft.SymbolicReceive.Tests.writeSmtRegression path
  else if let ["--smt-zero", pathPrefix] := args then CCFRaft.SymbolicReceive.Tests.writeZeroSmtRegressions pathPrefix
  else if args = ["--smoke"] then CCFRaft.SymbolicReceive.Tests.smoke
  else if args = ["--construct"] then CCFRaft.SymbolicReceive.Tests.constructionRegressions
  else if args = ["--sharing"] then CCFRaft.SymbolicReceive.Tests.sharingRegression
  else if args = ["--fresh"] then CCFRaft.SymbolicReceive.Tests.freshRegressions
  else if args = ["--fixtures"] then CCFRaft.SymbolicReceive.Tests.fixtureRegressions
  else if args.isEmpty then CCFRaft.SymbolicReceive.Tests.run
  else throw (IO.userError
    "expected no arguments, --smoke, --construct, --sharing, --fresh, --fixtures, --smt PATH, or --smt-zero PREFIX")
