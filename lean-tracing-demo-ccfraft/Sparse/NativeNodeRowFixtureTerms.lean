-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeNodeRowWrites

set_option autoImplicit false
set_option warningAsError true

namespace CCFRaft.NativeNodeRowWriteFixtures

open NativeSmt NativeEncode

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

def rowTerms (value : NodeState (Fin 3) Nat) : NodeRowTerms 3 :=
  let peers := fun (values : Fin 3 -> Nat) =>
    (List.finRange 3).foldl
      (fun result peer => Term.store result (.integer peer.val) (.integer (values peer)))
      (.defaultValue (.array .int .int))
  { role := .integer (roleCode value.role)
    newFollower := .boolean value.isNewFollower
    logLength := .integer value.log.length
    commit := .integer value.commitIndex
    currentTerm := .integer value.currentTerm
    logEntries := value.log.zipIdx.foldl
      (fun result (entry, index) => .store result (.integer index) (entryTerm entry))
      (.defaultValue (.array .int (entryTy 3)))
    retirementIndex := optionalTerm Nat.cast value.retirementIndex
    retirementCommittableIndex := optionalTerm Nat.cast value.retirementCommittableIndex
    retiredCommittedIndex := optionalTerm Nat.cast value.retiredCommittedIndex
    votedFor := optionalTerm (fun node => node.val) value.votedFor
    votesGranted := .bits (encodeBits value.votesGranted)
    preVotesGranted := .bits (encodeBits value.preVotesGranted)
    membershipState := .integer (membershipCode value.membershipState)
    sentIndex := peers value.sentIndex
    matchIndex := peers value.matchIndex }

end CCFRaft.NativeNodeRowWriteFixtures
