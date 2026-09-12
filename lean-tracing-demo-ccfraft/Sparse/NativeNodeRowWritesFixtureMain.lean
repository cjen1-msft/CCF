-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeNodeRowFixtureTerms
import Sparse.NativeFrameEncode
import Sparse.NativeArrayFixtureJson

set_option autoImplicit false
set_option warningAsError true

namespace CCFRaft.NativeNodeRowWriteFixtures

open Lean NativeSmt NativeEncode NativeArrayFixtures

private instance : Bootstrap (Fin 3) :=
  { configuration := {0, 1}, leader := 0, leader_mem := by simp }

def row (seed : Nat) : NodeState (Fin 3) Nat :=
  { role := if seed % 2 = 0 then .leader else .candidate
    currentTerm := 10 ^ 30 + seed
    log := ([
      { term := 5, content := .signature },
      { term := 0, content := .transaction (10 ^ 30) },
      { term := 3, content := .reconfiguration {0, 2} },
      { term := 1, content := .retiredCommitted {1} }] : List (Entry (Fin 3) Nat)).take (seed % 5)
    commitIndex := seed + 17
    sentIndex := fun peer => seed + peer.val + 11
    matchIndex := fun peer => 10 ^ 30 + seed + peer.val
    isNewFollower := seed % 2 = 0
    votedFor := if seed % 2 = 0 then none else some 2
    votesGranted := {0, 2}
    preVotesGranted := {1}
    membershipState := if seed % 2 = 0 then .retirementSigned else .retiredCommitted
    retirementIndex := some (seed + 1)
    retirementCommittableIndex := if seed % 2 = 0 then none else some (seed + 2)
    retiredCommittedIndex := some (10 ^ 30) }

def toggle {α : Type} [DecidableEq α] (item : α) (values : Finset α) : Finset α :=
  if item ∈ values then values.erase item else insert item values

def otherOption (value : Option Nat) : Option Nat :=
  if value.isSome then none else some 0

def hiddenEntry (node : Fin 3) : Expr (entryTy 3) :=
  .pair (.integer (-17 - node.val)) (.inr (.inl (.integer (-91 - node.val))))

def mutateRow (value : NodeState (Fin 3) Nat) (mutation : Nat) : NodeState (Fin 3) Nat :=
  match mutation with
  | 1 => { value with role := if value.role = .leader then .follower else .leader }
  | 2 => { value with currentTerm := value.currentTerm + 1 }
  | 3 => { value with log := value.log ++ [{ term := 0, content := .signature }] }
  | 4 => { value with commitIndex := value.commitIndex + 1 }
  | 5 => { value with sentIndex := updateIndex value.sentIndex 2 (value.sentIndex 2 + 1) }
  | 6 => { value with matchIndex := updateIndex value.matchIndex 0 (value.matchIndex 0 + 1) }
  | 7 => { value with isNewFollower := !value.isNewFollower }
  | 8 => { value with votedFor := if value.votedFor.isSome then none else some 0 }
  | 9 => { value with votesGranted := toggle 0 value.votesGranted }
  | 10 => { value with preVotesGranted := toggle 2 value.preVotesGranted }
  | 11 => { value with
      membershipState := if value.membershipState = .active then .retirementOrdered else .active }
  | 12 => { value with retirementIndex := otherOption value.retirementIndex }
  | 13 => { value with retirementCommittableIndex := otherOption value.retirementCommittableIndex }
  | 14 => { value with retiredCommittedIndex := otherOption value.retiredCommittedIndex }
  | 15 => { value with log := match value.log with
      | [] => [{ term := 1, content := .signature }]
      | entry :: rest => { entry with term := entry.term + 1 } :: rest }
  | _ => value

def mutate (state : State (Fin 3) Nat) (destination : Fin 3) (mutation : Nat) :
    State (Fin 3) Nat :=
  if mutation <= 15 then
    { state with nodes := updateNode state.nodes destination (mutateRow (state.nodes destination) mutation) }
  else
    match mutation with
    | 16 =>
      let other : Fin 3 := if destination = 0 then 1 else 0
      let changed := { state.nodes other with currentTerm := (state.nodes other).currentTerm + 1 }
      { state with nodes := updateNode state.nodes other changed }
    | 17 => { state with
        network := updateQueue state.network 0
          (state.network 0 ++ [.proposeVoteRequest { term := 2, source := 1, destination := 0 }]) }
    | 18 => { state with hasJoined := toggle 2 state.hasJoined }
    | 19 => { state with preVoteStatus := fun node =>
        if node = destination then
          if state.preVoteStatus node = .enabled then .capable else .enabled
        else state.preVoteStatus node }
    | 20 => { state with retirementCompleted := fun node =>
        if node = destination then toggle 0 (state.retirementCompleted node) else state.retirementCompleted node }
    | _ => { state with submittedTxIds := toggle 9 state.submittedTxIds }

def fixture (seed mode mutation : Nat) : Except String Json := do
  let source : Fin 3 := ⟨seed % 3, Nat.mod_lt _ (by decide)⟩
  let destination : Fin 3 := if source = 2 then 0 else 1
  let second : Fin 3 := if destination = 2 then 0 else 2
  let present := (List.finRange 3).filter fun node => (seed / 3).testBit node.val
  let state : State (Fin 3) Nat :=
    { nodes := NodeStore.ofFinset present.toFinset (fun node => row (seed + node.val))
      network := fun node => [
        .proposeVoteRequest { term := 7, source := node, destination := node },
        .requestVoteResponse { term := 2, source := 0, destination := node, voteGranted := true },
        .requestVoteResponse { term := 2, source := 0, destination := node, voteGranted := true }]
      hasJoined := {0, 2}, submittedTxIds := {9, 10 ^ 30}
      preVoteStatus := fun node => if node = 1 then .capable else .enabled
      retirementCompleted := fun node => {node, 1} }
  let replacement := if mode = 0 then row (seed + 9) else state.nodes source
  let once := { state with nodes := updateNode state.nodes destination replacement }
  let actual := if mode = 2 then
      { once with nodes := updateNode once.nodes second (once.nodes destination) }
    else once
  let decode := fun frame =>
    (frameObservations frame [9, 10 ^ 30]).toArray.mapM (decodeFrameInstruction 3 #["a", "b", "c"])
  let before <- decode state
  let after <- decode (mutate actual destination mutation)
  let program : EncodeM 3 Unit := do
    initialFrameDomains 3
    for node in List.finRange 3 do
      unless decide (state.allocated node) do
        -- Hidden rows deliberately disagree with the fresh state of absent nodes.
        for (item, column) in (nodeRowWriteDefinitions (width := 3) {} node (rowTerms (row 19))).drop 1 |>.zipIdx do
          if column + 1 != 6 then
            assertion (.equal (.free item.1 (column + 1)) item.2)
      for position in ([-7, 10 ^ 30] : List Int) do
        assertion (.equal (entryAt 3 {} node.val (.integer position)) (hiddenEntry node))
    for item in before do frameInstruction item
    let columns := (<- get).toColumns
    let values := if mode = 0 then rowTerms replacement else nodeRowSnapshot columns source
    writeNodeRow destination values
    if mode = 2 then
      let current := (<- get).toColumns
      writeNodeRow second (nodeRowSnapshot current destination)
    if mode != 0 then
      let current := (<- get).toColumns
      for target in (if mode = 2 then [destination, second] else [destination]) do
        for position in ([-7, 10 ^ 30] : List Int) do
          assertion (.equal (entryAt 3 current target.val (.integer position)) (hiddenEntry source))
    for item in after do frameInstruction item
  let (_, final) <- program.run (initialEncoding 3 {0, 1})
  unless final.next = 24 + (if mode = 2 then 32 else 16) do
    throw "row write allocated an unexpected number of symbols"
  return Json.mkObj [
    ("name", toJson s!"row-write-{seed}-{mode}-{mutation}"),
    ("script", toJson (renderScript final.assertions.toList)),
    ("mode", toJson mode), ("sourcePresent", toJson (decide (state.allocated source))),
    ("destinationPresent", toJson (decide (state.allocated destination))),
    ("self", toJson (source == destination)),
    ("expected", toJson (if mutation = 0 then "sat" else "unsat"))]

def invalidValues (column symbol : Nat) : NodeRowTerms 3 :=
  let values := rowTerms (row 3)
  match column with
  | 1 => { values with role := .free .int symbol }
  | 2 => { values with newFollower := .free .bool symbol }
  | 3 => { values with logLength := .free .int symbol }
  | 4 => { values with commit := .free .int symbol }
  | 5 => { values with currentTerm := .free .int symbol }
  | 6 => { values with logEntries := .free (.array .int (entryTy 3)) symbol }
  | 7 => { values with retirementIndex := .free optionalIntTy symbol }
  | 8 => { values with retirementCommittableIndex := .free optionalIntTy symbol }
  | 9 => { values with retiredCommittedIndex := .free optionalIntTy symbol }
  | 10 => { values with votedFor := .free optionalIntTy symbol }
  | 11 => { values with votesGranted := .free (.bits 3) symbol }
  | 12 => { values with preVotesGranted := .free (.bits 3) symbol }
  | 13 => { values with membershipState := .free .int symbol }
  | 14 => { values with sentIndex := .free (.array .int .int) symbol }
  | _ => { values with matchIndex := .free (.array .int .int) symbol }

def cases : Except String Json := do
  let parameters := (List.range 24).flatMap fun seed =>
    (List.range 3).flatMap fun mode => (List.range 22).map fun mutation => (seed, mode, mutation)
  let fixtures <- parameters.mapM fun (seed, mode, mutation) => fixture seed mode mutation
  let mut rejected := #[]
  for column in List.range' 1 15 do
    for symbol in [24, 25, 39, 1024] do
      match (writeNodeRow (width := 3) 1 (invalidValues column symbol)).run (initialEncoding 3 {0, 1}) with
      | .error error =>
        rejected := rejected.push (Json.mkObj [
          ("column", toJson column), ("symbol", toJson symbol), ("error", toJson error)])
      | .ok _ => throw "row write accepted a future symbol"
  return Json.mkObj [("fixtures", toJson fixtures), ("rejected", toJson rejected)]

end CCFRaft.NativeNodeRowWriteFixtures

def main : IO Unit :=
  match CCFRaft.NativeNodeRowWriteFixtures.cases with
  | .ok result => IO.println result.compress
  | .error error => throw (IO.userError error)
