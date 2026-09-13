-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeCommitTermsEncoding
import Sparse.NativeRetirementTailExecution

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem retirement_tail_sound {width : PNat} [Bootstrap (Fin width)]
    (bootstrap : BitVec width) (source : Fin width)
    (row : NodeRowTerms width) (commit : Expr .int)
    (guards : Expr .int -> List (Expr .bool)) (before after : Encoding width)
    (run : (retirementTail bootstrap source row commit guards).run before =
      .ok ((), after))
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (columnsRep : FrameColumnsRep assignment before.toColumns frame)
    (nativeRow : NativeArrayCheckQuorum.Local (Fin width) Nat)
    (rowRep : row.Rep assignment nativeRow) (commitNat : Nat)
    (sameCommit : commit.eval assignment Locals.empty = (commitNat : Int))
    (sameBootstrap : decodeBits bootstrap = INITIAL_CONFIGURATION) :
    exists output : NativeArrayCheckQuorum.Local (Fin width) Nat,
      (retirementTailTerms before row commit).values.Rep assignment output /\
      output.toModel =
        refreshRetirementState source
          { nativeRow.toModel with commitIndex := commitNat } /\
      Holds (guards
        (retirementTailTerms before row commit).values.membershipState) assignment /\
      FrameColumnsRep assignment after.toColumns
        (retirementWriteFrame frame source
          (retirementCompletedNodes output.log.decode output.commit) output) := by
  obtain ⟨states, execution⟩ :=
    retirement_tail_success bootstrap source row commit guards before after run
  let terms := retirementTailTerms before row commit
  have writerHolds :=
    retirement_writes_prior_holds source terms.values terms.completed
      states.writerBefore after execution.runs.writeRun assignment holds
  have constraints :=
    retirement_tail_constraints bootstrap source row commit guards before after
      states execution assignment writerHolds
  obtain ⟨output, valuesRepRaw, outputModel⟩ :=
    commit_refresh_constraints_output_sound assignment bootstrap row source commit
      terms.first terms.retirement terms.signature terms.retired nativeRow commitNat
      rowRep sameBootstrap sameCommit constraints.refresh
  have valuesRep : terms.values.Rep assignment output := by
    simpa [terms, retirementTailTerms] using valuesRepRaw
  have sameLength :
      row.logLength.eval assignment Locals.empty = (output.log.length : Int) := by
    simpa [terms, retirementTailTerms, commitRowTerms] using valuesRep.logLength
  have sameOutputCommit :
      commit.eval assignment Locals.empty = (output.commit : Int) := by
    simpa [terms, retirementTailTerms, commitRowTerms] using valuesRep.commit
  have sameEntries : forall position, position < output.log.length ->
      modelEntry (row.logEntries.eval assignment Locals.empty (position : Int)) =
        output.log.entries position := by
    intro position live
    simpa [terms, retirementTailTerms, commitRowTerms] using
      valuesRep.logEntries position live
  have completedValue :
      terms.completed.eval assignment Locals.empty =
        encodeBits (retirementCompletedNodes output.log.decode output.commit) := by
    have correct :=
      retirement_completed_constraints_bits_correct bootstrap (.boolean true)
        row.logLength row.logEntries commit terms.current states.currentAsserted
        states.writerBefore (before.next + 5) execution.runs.completedRun assignment
        writerHolds output.log output.commit sameLength sameOutputCommit sameBootstrap
        sameEntries (by simp [Term.eval]) constraints.current
    simpa [terms, retirementTailTerms] using correct
  have completedDecoded :
      decodeBits (terms.completed.eval assignment Locals.empty) =
        retirementCompletedNodes output.log.decode output.commit := by
    rw [completedValue, decode_encode_bits]
  have writerRep :
      FrameColumnsRep assignment states.writerBefore.toColumns frame := by
    rw [execution.writerColumns]
    exact columnsRep
  have writtenRep :=
    retirement_writes_frame_sound source terms.values terms.completed
      states.writerBefore after execution.runs.writeRun assignment holds frame output
      writerRep valuesRep
  refine ⟨output, ?_, outputModel, ?_, ?_⟩
  · simpa [terms] using valuesRep
  · simpa [terms] using constraints.guards
  · simpa [completedDecoded] using writtenRep

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
