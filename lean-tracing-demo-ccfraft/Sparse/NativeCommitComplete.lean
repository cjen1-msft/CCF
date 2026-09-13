-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeCommitPrefixAssignment
import Sparse.NativeCommitSound
import Sparse.NativeCommitSuffixAssignment

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem advance_commit_model_complete {width : PNat} [Bootstrap (Fin width)]
    (source : Fin width) (before after : Encoding width)
    (run : (advanceCommitIndex source).run before = .ok ((), after))
    (assignment : Assignment)
    (holds : Holds before.assertions.toList assignment)
    (valid : ReferencesValid before)
    (frame : NativeArrayVote.Frame (Fin width) Nat) (state : State (Fin width) Nat)
    (columnsRep : FrameColumnsRep assignment before.toColumns frame)
    (modelRep : frame.Rep state)
    (enabled : CCFRaft.Enabled state (.advanceCommitIndex source))
    (sameBootstrap : decodeBits before.bootstrap = INITIAL_CONFIGURATION) :
    exists extended : Assignment,
      assignment.AgreesBelow before.next extended /\
      Holds after.assertions.toList extended /\
      exists written : NativeArrayVote.Frame (Fin width) Nat,
        FrameColumnsRep extended after.toColumns written /\
        written.Rep (CCFRaft.next state (.advanceCommitIndex source)) := by
  obtain ⟨states, execution⟩ := advance_commit_success source before after run
  obtain ⟨prefixAssignment, prefixAgreement, prefixHolds, prefixRep, bestValue,
      _, _, _⟩ :=
    commit_prefix_assignment source before after states execution assignment holds
      valid frame state columnsRep modelRep enabled sameBootstrap
  obtain ⟨extended, suffixAgreement, afterHolds⟩ :=
    commit_suffix_assignment source before after states execution prefixAssignment
      prefixHolds valid frame prefixRep (highestCommittableIndex state source)
      bestValue sameBootstrap
  have prefixToExtended :
      prefixAssignment.AgreesBelow before.next extended :=
    suffixAgreement.restrict (by rw [execution.guardsAssertedNext]; omega)
  have originalAgreement : assignment.AgreesBelow before.next extended :=
    prefixAgreement.trans prefixToExtended
  have finalColumnsRep : FrameColumnsRep extended before.toColumns frame :=
    columnsRep.agrees_below before assignment extended frame valid originalAgreement
  obtain ⟨_, written, writtenRep, writtenModel⟩ :=
    advance_commit_model_sound source before after run extended afterHolds frame state
      finalColumnsRep modelRep sameBootstrap
  exact ⟨extended, originalAgreement, afterHolds, written, writtenRep, writtenModel⟩

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
