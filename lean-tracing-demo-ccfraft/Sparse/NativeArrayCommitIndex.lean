-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayMajority
import Sparse.NativeMaximumSummary

set_option autoImplicit false

namespace CCFRaft.NativeArrayCommitIndex

open NativeArrayCheckQuorum NativeArrayMajority

variable {N T : Type} [DecidableEq N] [DecidableEq T] [Bootstrap N]

def Eligible (row : Local N T) (leader : N) (current position : Nat) : Prop :=
  row.commit < position + 1 /\
    (row.log.entries position).content = .signature /\
    (row.log.entries position).term = row.currentTerm /\
    MajorityAt row leader current (position + 1)

def CommitIndex (row : Local N T) (leader : N) (current best : Nat) : Prop :=
  Sparse.LogMatchSummary.StorageSummary row.log.length row.log.length best
    (Eligible row leader current)

theorem eligible_correct (row : Local N T) (state : State N T) (leader : N)
    (current position : Nat) (same : state.nodes leader = row.toModel)
    (selected : CurrentIndex row.log row.commit current) (live : position < row.log.length) :
    Eligible row leader current position <->
      (state.nodes leader).commitIndex < position + 1 /\
        isSignatureAt (state.nodes leader).log (position + 1) = true /\
        termAt (state.nodes leader).log (position + 1) = (state.nodes leader).currentTerm /\
        hasMajorityAt state leader (position + 1) := by
  have entry : entryAt? row.log.decode (position + 1) = some (row.log.entries position) := by
    simp [entryAt?, Log.decode, live]
  rw [Eligible, majority_at_correct row state leader current (position + 1) same selected, same]
  simp only [Local.toModel, isSignatureAt, termAt, entry, decide_eq_true_eq,
    Option.map_some, Option.getD_some]

theorem commit_index_correct (row : Local N T) (state : State N T) (leader : N)
    (current best : Nat) (same : state.nodes leader = row.toModel)
    (selected : CurrentIndex row.log row.commit current) :
    CommitIndex row leader current best <-> highestCommittableIndex state leader = best := by
  let candidate := fun index =>
    (state.nodes leader).commitIndex < index /\
      isSignatureAt (state.nodes leader).log index = true /\
      termAt (state.nodes leader).log index = (state.nodes leader).currentTerm /\
      hasMajorityAt state leader index
  have sameLength : (state.nodes leader).log.length = row.log.length := by
    rw [same]
    exact Log.decode_length row.log
  have fold := NativeMaximumSummary.bounded_maximum_iff_storage_summary
    candidate row.log.length row.log.length best
  have modelSummary :
      highestCommittableIndex state leader = best <->
        Sparse.LogMatchSummary.StorageSummary row.log.length row.log.length best
          (fun position => candidate (position + 1)) := by
    simpa only [highestCommittableIndex, sameLength, Nat.min_self, candidate] using fold
  exact (NativeMaximumSummary.storage_summary_congr
    (Eligible row leader current) (fun position => candidate (position + 1))
    row.log.length row.log.length best (fun position live =>
      eligible_correct row state leader current position same selected (by simpa using live))).trans
        modelSummary.symm

end CCFRaft.NativeArrayCommitIndex

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeArrayCommitIndex).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
