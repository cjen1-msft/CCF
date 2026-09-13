-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeRetirementWrites
import Sparse.NativeNodeRowWritesEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def retirementWriteColumns (rowColumns : Columns) (completedId : Nat) : Columns :=
  { rowColumns with retirementCompleted := completedId }

def retirementWriteFrame {width : PNat}
    (frame : NativeArrayVote.Frame (Fin width) Nat) (source : Fin width)
    (completedSet : Finset (Fin width))
    (output : NativeArrayCheckQuorum.Local (Fin width) Nat) :
    NativeArrayVote.Frame (Fin width) Nat :=
  { frame with
    nodes := Function.update frame.nodes source (some output)
    globals :=
      { frame.globals with
        retirementCompleted :=
          Function.update frame.globals.retirementCompleted source completedSet } }

structure RetirementWritesResult {width : PNat} (source : Fin width)
    (values : NodeRowTerms width) (completed : Expr (.bits width))
    (before written completedDefined after : Encoding width)
    (retiredNodes : Nat) : Prop where
  completedBounded :
    completed.symbols.all (fun symbol => symbol.2 < before.next) = true
  rowRun : (writeNodeRow source values).run before = .ok ((), written)
  completedRun :
    (define
      (.store (.free (.array .int (.bits width)) before.retirementCompleted)
        (.integer source.val) completed)).run written =
      .ok (retiredNodes, completedDefined)
  final :
    after = { completedDefined with retirementCompleted := retiredNodes }

theorem retirement_writes_success {width : PNat} (source : Fin width)
    (values : NodeRowTerms width) (completed : Expr (.bits width))
    (before after : Encoding width)
    (run : (writeRetirementRow source values completed).run before = .ok ((), after)) :
    exists written completedDefined retiredNodes,
      RetirementWritesResult source values completed before written completedDefined
        after retiredNodes := by
  simp only [writeRetirementRow, get_bind_run] at run
  split at run
  · rename_i completedBounded
    obtain ⟨_, written, rowRun, run⟩ := (bind_run _ _ _ _ _).mp run
    obtain ⟨retiredNodes, completedDefined, completedRun, run⟩ :=
      (bind_run _ _ _ _ _).mp run
    have final :
        after = { completedDefined with retirementCompleted := retiredNodes } :=
      (congrArg Prod.snd (Except.ok.inj run)).symm
    exact ⟨written, completedDefined, retiredNodes,
      { completedBounded, rowRun, completedRun, final }⟩
  · cases run

theorem retirement_writes_shape {width : PNat} (source : Fin width)
    (values : NodeRowTerms width) (completed : Expr (.bits width))
    (before written completedDefined after : Encoding width) (retiredNodes : Nat)
    (result : RetirementWritesResult source values completed before written
      completedDefined after retiredNodes) :
    after.next = before.next + 17 /\
      after.bootstrap = before.bootstrap /\
      after.toColumns = retirementWriteColumns written.toColumns written.next /\
      after.assertions = completedDefined.assertions := by
  have rowShape := write_node_row_success source values before written result.rowRun
  obtain ⟨retiredId, completedNext, completedBootstrap, completedColumns, _⟩ :=
    define_success
      (.store (.free (.array .int (.bits width)) before.retirementCompleted)
        (.integer source.val) completed)
      written completedDefined retiredNodes result.completedRun
  constructor
  · rw [result.final, completedNext, rowShape.next]
  constructor
  · rw [result.final]
    exact completedBootstrap.trans rowShape.bootstrap
  constructor
  · rw [result.final, completedColumns, retiredId]
    rfl
  · rw [result.final]

theorem retirement_writes_next {width : PNat} (source : Fin width)
    (values : NodeRowTerms width) (completed : Expr (.bits width))
    (before after : Encoding width)
    (run : (writeRetirementRow source values completed).run before = .ok ((), after)) :
    after.next = before.next + 17 := by
  obtain ⟨written, completedDefined, retiredNodes, result⟩ :=
    retirement_writes_success source values completed before after run
  exact (retirement_writes_shape source values completed before written
    completedDefined after retiredNodes result).1

theorem retirement_writes_bootstrap {width : PNat} (source : Fin width)
    (values : NodeRowTerms width) (completed : Expr (.bits width))
    (before after : Encoding width)
    (run : (writeRetirementRow source values completed).run before = .ok ((), after)) :
    after.bootstrap = before.bootstrap := by
  obtain ⟨written, completedDefined, retiredNodes, result⟩ :=
    retirement_writes_success source values completed before after run
  exact (retirement_writes_shape source values completed before written
    completedDefined after retiredNodes result).2.1

theorem retirement_writes_prior_holds {width : PNat} (source : Fin width)
    (values : NodeRowTerms width) (completed : Expr (.bits width))
    (before after : Encoding width)
    (run : (writeRetirementRow source values completed).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment) :
    Holds before.assertions.toList assignment := by
  obtain ⟨written, completedDefined, retiredNodes, result⟩ :=
    retirement_writes_success source values completed before after run
  have completedHolds : Holds completedDefined.assertions.toList assignment := by
    simpa [result.final] using holds
  have writtenHolds :=
    define_prior_holds _ written completedDefined retiredNodes result.completedRun
      assignment completedHolds
  exact write_node_row_prior_holds source values before written result.rowRun
    assignment writtenHolds

theorem retirement_writes_references {width : PNat} (source : Fin width)
    (values : NodeRowTerms width) (completed : Expr (.bits width))
    (before after : Encoding width)
    (run : (writeRetirementRow source values completed).run before = .ok ((), after))
    (valid : ReferencesValid before) : ReferencesValid after := by
  obtain ⟨written, completedDefined, retiredNodes, result⟩ :=
    retirement_writes_success source values completed before after run
  have writtenValid :=
    write_node_row_references source values before written result.rowRun valid
  have completedValid :=
    define_references _ written completedDefined retiredNodes
      result.completedRun writtenValid
  have completedShape :=
    define_success
      (.store (.free (.array .int (.bits width)) before.retirementCompleted)
        (.integer source.val) completed)
      written completedDefined retiredNodes result.completedRun
  rw [result.final]
  cases completedValid
  constructor <;> simp only [completedShape.2.1] <;> omega

theorem retirement_writes_frame_sound {width : PNat} (source : Fin width)
    (values : NodeRowTerms width) (completed : Expr (.bits width))
    (before after : Encoding width)
    (run : (writeRetirementRow source values completed).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (output : NativeArrayCheckQuorum.Local (Fin width) Nat)
    (rep : FrameColumnsRep assignment before.toColumns frame)
    (valuesRep : values.Rep assignment output) :
    FrameColumnsRep assignment after.toColumns
      (retirementWriteFrame frame source
        (decodeBits (completed.eval assignment Locals.empty)) output) := by
  obtain ⟨written, completedDefined, retiredNodes, result⟩ :=
    retirement_writes_success source values completed before after run
  have completedHolds : Holds completedDefined.assertions.toList assignment := by
    simpa [result.final] using holds
  have writtenHolds :=
    define_prior_holds _ written completedDefined retiredNodes result.completedRun
      assignment completedHolds
  have rowRep :=
    write_node_row_frame_sound source values output before written result.rowRun
      assignment writtenHolds frame rep valuesRep
  have completedBinding :=
    (define_holds
      (.store (.free (.array .int (.bits width)) before.retirementCompleted)
        (.integer source.val) completed)
      written completedDefined retiredNodes result.completedRun assignment completedHolds).2
  have completedShape :=
    define_success
      (.store (.free (.array .int (.bits width)) before.retirementCompleted)
        (.integer source.val) completed)
      written completedDefined retiredNodes result.completedRun
  have columns :=
    (retirement_writes_shape source values completed before written completedDefined
      after retiredNodes result).2.2.1
  constructor
  · rw [columns]
    cases rowRep.nodes
    constructor <;> assumption
  · rw [columns]
    exact rowRep.hasJoined
  · intro peer
    rw [columns]
    exact rowRep.preVoteStatus peer
  · intro peer
    have selected := stored_array_read_correct assignment before.retirementCompleted
      retiredNodes source.val peer.val completed completedBinding
    rw [columns]
    simp only [retirementWriteColumns, retirementWriteFrame]
    rw [<- completedShape.1]
    by_cases same : peer = source
    · subst peer
      simpa using selected
    · have different : peer.val ≠ source.val := fun equal => same (Fin.ext equal)
      rw [selected, if_neg different]
      simp only [Function.update, same]
      exact rep.retirementCompleted peer
  · intro txId
    rw [columns]
    exact rowRep.submittedTxIds txId
  · intro destination packetSource
    rw [columns]
    exact rowRep.queues destination packetSource

theorem retirement_writes_complete {width : PNat} (source : Fin width)
    (values : NodeRowTerms width) (completed : Expr (.bits width))
    (before after : Encoding width)
    (run : (writeRetirementRow source values completed).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds before.assertions.toList assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (output : NativeArrayCheckQuorum.Local (Fin width) Nat)
    (rep : FrameColumnsRep assignment before.toColumns frame)
    (valuesRep : values.Rep assignment output)
    (valid : ReferencesValid before) :
    after.next = before.next + 17 /\
      exists extended : Assignment,
        assignment.AgreesBelow before.next extended /\
        Holds after.assertions.toList extended /\
        FrameColumnsRep extended after.toColumns
          (retirementWriteFrame frame source
            (decodeBits (completed.eval assignment Locals.empty)) output) := by
  obtain ⟨written, completedDefined, retiredNodes, result⟩ :=
    retirement_writes_success source values completed before after run
  obtain ⟨rowAssignment, rowAgreement, rowHolds, _⟩ :=
    write_node_row_complete source values output before written result.rowRun
      assignment holds frame rep valuesRep valid
  obtain ⟨extended, completedAgreement, completedHolds⟩ :=
    define_extension
      (.store (.free (.array .int (.bits width)) before.retirementCompleted)
        (.integer source.val) completed)
      written completedDefined retiredNodes result.completedRun rowAssignment rowHolds
  have rowShape := write_node_row_success source values before written result.rowRun
  have agreement : assignment.AgreesBelow before.next extended :=
    rowAgreement.trans
      (completedAgreement.restrict (by rw [rowShape.next]; omega))
  have finalHolds : Holds after.assertions.toList extended := by
    simpa [result.final] using completedHolds
  have finalRep := rep.agrees_below before assignment extended frame valid agreement
  have finalValues :=
    valuesRep.agrees_below assignment extended values output before.next
      (write_node_row_values_bounded source values before written result.rowRun) agreement
  have completedBounded :
      forall symbol, symbol ∈ completed.symbols -> symbol.2 < before.next := by
    intro symbol member
    simpa using List.all_eq_true.mp result.completedBounded symbol member
  have completedSame :
      completed.eval extended Locals.empty = completed.eval assignment Locals.empty :=
    (completed.eval_agrees_below assignment extended Locals.empty before.next
      completedBounded agreement).symm
  have sound :=
    retirement_writes_frame_sound source values completed before after run extended
      finalHolds frame output finalRep finalValues
  exact
    ⟨(retirement_writes_shape source values completed before written completedDefined
      after retiredNodes result).1,
      extended, agreement, finalHolds, by simpa [completedSame] using sound⟩

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
