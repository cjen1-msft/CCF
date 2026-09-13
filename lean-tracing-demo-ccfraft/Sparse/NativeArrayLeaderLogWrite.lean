-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayLogWrite
import Sparse.NativeArrayRetirement

set_option autoImplicit false

namespace CCFRaft.NativeArrayLeaderLogWrite

open NativeArrayCheckQuorum

variable {N T : Type} [DecidableEq N] [DecidableEq T] [Bootstrap N]

def appendRow (row : Local N T) (content : EntryContent N T) : Local N T :=
  { row with
    log := NativeArrayLogWrite.append row.log
      (Log.ofList [{ term := row.currentTerm, content }]) }

theorem append_row_correct (row : Local N T) (content : EntryContent N T) :
    (appendRow row content).toModel =
      { row.toModel with
        log := row.toModel.log ++ [{ term := row.toModel.currentTerm, content }] } := by
  simp [appendRow, Local.toModel, NativeArrayLogWrite.append_correct]

def refreshRow (row : Local N T) (content : EntryContent N T)
    (retirement signature retired : Option Nat) : Local N T :=
  NativeArrayRetirement.refresh (appendRow row content) retirement signature retired

theorem refresh_row_correct (row : Local N T) (source : N) (content : EntryContent N T)
    (retirement signature retired : Option Nat)
    (retirementCorrect :
      retirementIndexInLog source (appendRow row content).log.decode = retirement)
    (signatureCorrect :
      retirement.bind (retirementCommittableIndexInLog
        (appendRow row content).log.decode) = signature)
    (retiredCorrect :
      retiredCommittedIndexInLog source (appendRow row content).log.decode = retired) :
    (refreshRow row content retirement signature retired).toModel =
      refreshRetirementState source
        { row.toModel with
          log := row.toModel.log ++ [{ term := row.toModel.currentTerm, content }] } := by
  rw [refreshRow, NativeArrayRetirement.refresh_correct _ source retirement signature retired
    retirementCorrect signatureCorrect retiredCorrect, append_row_correct]

end CCFRaft.NativeArrayLeaderLogWrite

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeArrayLeaderLogWrite).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
