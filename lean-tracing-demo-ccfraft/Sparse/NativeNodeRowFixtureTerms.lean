-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeNodeRowWrites

set_option autoImplicit false
set_option warningAsError true

namespace CCFRaft.NativeNodeRowWriteFixtures

open NativeSmt NativeEncode

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
