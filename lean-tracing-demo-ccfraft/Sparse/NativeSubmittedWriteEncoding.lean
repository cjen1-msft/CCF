-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeSubmittedWrite
import Sparse.NativeNatSetInsertEncoding
import Sparse.NativeFrameColumns
import Sparse.NativeDefinitionsEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def submittedWriteConstraint {width : PNat}
    (before : Encoding width) (value : Expr .int) : Expr .bool :=
  natSetInsertConstraints before.submittedTxIds before.submittedTxLimit
    before.next (before.next + 1) value

structure SubmittedWriteResult {width : PNat} (before after : Encoding width)
    (value : Expr .int) : Prop where
  valueBounded : value.symbols.all (fun symbol => symbol.2 < before.next) = true
  bootstrap : after.bootstrap = before.bootstrap
  columns : after.toColumns = submittedWriteColumns before.toColumns before.next
  next : after.next = before.next + 2
  clauses : after.assertions.toList =
    before.assertions.toList ++ [submittedWriteConstraint before value]

theorem insert_submitted_success {width : PNat} (value : Expr .int)
    (before after : Encoding width)
    (run : (insertSubmitted value).run before = .ok ((), after)) :
    SubmittedWriteResult before after value := by
  simp only [insertSubmitted, get_bind_run] at run
  split at run
  next valueBounded =>
    obtain ⟨cells, cellsFresh, cellsRun, run⟩ := (bind_run _ _ _ _ _).mp run
    obtain ⟨limit, limitFresh, limitRun, run⟩ := (bind_run _ _ _ _ _).mp run
    obtain ⟨unused, asserted, assertionRun, run⟩ := (bind_run _ _ _ _ _).mp run
    cases unused
    change Except.ok ((), { asserted with
      submittedTxIds := cells, submittedTxLimit := limit }) = .ok ((), after) at run
    have final := congrArg Prod.snd (Except.ok.inj run)
    dsimp only at final
    rw [<- final]
    obtain ⟨cellsId, cellsNext, cellsBootstrap, cellsColumns, cellsClauses⟩ :=
      fresh_success before cellsFresh cells cellsRun
    obtain ⟨limitId, limitNext, limitBootstrap, limitColumns, limitClauses⟩ :=
      fresh_success cellsFresh limitFresh limit limitRun
    obtain ⟨assertionFrame, assertionClauses⟩ :=
      assertion_success _ limitFresh asserted assertionRun
    have cellsEq : cells = before.next := cellsId
    have limitEq : limit = before.next + 1 := by
      rw [limitId, cellsNext]
    constructor
    · exact valueBounded
    · exact assertionFrame.bootstrap.trans
        (limitBootstrap.trans cellsBootstrap)
    · simp only [assertionFrame.columns, limitColumns, cellsColumns,
        submittedWriteColumns, cellsEq, limitEq]
    · rw [assertionFrame.next, limitNext, cellsNext]
    · rw [assertionClauses, Array.toList_push, limitClauses, cellsClauses,
        cellsEq, limitEq]
      rfl
  next valueUnbounded =>
    contradiction

theorem insert_submitted_holds {width : PNat} (value : Expr .int)
    (before after : Encoding width)
    (run : (insertSubmitted value).run before = .ok ((), after))
    (assignment : Assignment) :
    Holds after.assertions.toList assignment <->
      Holds before.assertions.toList assignment /\
        (submittedWriteConstraint before value).eval assignment Locals.empty =
          true := by
  rw [(insert_submitted_success value before after run).clauses]
  simp [Holds, or_imp, forall_and]

theorem insert_submitted_references {width : PNat} (value : Expr .int)
    (before after : Encoding width)
    (run : (insertSubmitted value).run before = .ok ((), after))
    (valid : ReferencesValid before) :
    ReferencesValid after := by
  have shape := insert_submitted_success value before after run
  cases valid
  constructor <;>
    simp only [shape.columns, submittedWriteColumns, shape.next] <;>
    omega

theorem insert_submitted_frame {width : PNat} (value : Expr .int)
    (valueNat : Nat) (before after : Encoding width)
    (run : (insertSubmitted value).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment before.toColumns frame)
    (sameValue : value.eval assignment Locals.empty = (valueNat : Int)) :
    FrameColumnsRep assignment after.toColumns
      { frame with globals :=
          { frame.globals with
            submittedTxIds := insert valueNat frame.globals.submittedTxIds } } := by
  have shape := insert_submitted_success value before after run
  have accepted := (insert_submitted_holds value before after run assignment).mp holds |>.2
  obtain ⟨newDomain, newRep⟩ :=
    (nat_set_insert_constraints_rep_correct assignment Locals.empty
      before.submittedTxIds before.submittedTxLimit before.next
      (before.next + 1) value valueNat frame.globals.submittedTxIds
      rep.submittedTxIds sameValue).mp (by
        simpa only [submittedWriteConstraint] using accepted)
  constructor
  · rw [shape.columns]
    exact { rep.nodes with }
  · simpa only [shape.columns, submittedWriteColumns] using rep.hasJoined
  · intro node
    simpa only [shape.columns, submittedWriteColumns] using rep.preVoteStatus node
  · intro node
    simpa only [shape.columns, submittedWriteColumns] using
      rep.retirementCompleted node
  · intro txId
    simpa only [shape.columns, submittedWriteColumns] using newRep txId
  · intro destination source
    simpa only [shape.columns, submittedWriteColumns, queueRow] using
      rep.queues destination source

theorem insert_submitted_complete {width : PNat} (value : Expr .int)
    (valueNat : Nat) (before after : Encoding width)
    (run : (insertSubmitted value).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds before.assertions.toList assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment before.toColumns frame)
    (valid : ReferencesValid before)
    (sameValue : value.eval assignment Locals.empty = (valueNat : Int)) :
    exists extended : Assignment,
      assignment.AgreesBelow before.next extended /\
      Holds after.assertions.toList extended /\
      FrameColumnsRep extended after.toColumns
        { frame with globals :=
            { frame.globals with
              submittedTxIds := insert valueNat frame.globals.submittedTxIds } } := by
  have shape := insert_submitted_success value before after run
  obtain ⟨extended, agreement, accepted, _, _⟩ :=
    nat_set_insert_rep_assignment assignment Locals.empty
      before.submittedTxIds before.submittedTxLimit before.next
      (before.next + 1) before.next value valueNat
      frame.globals.submittedTxIds rep.submittedTxIds valid.submittedTxIds
      valid.submittedTxLimit shape.valueBounded (le_refl _) (by omega) sameValue
  have extendedHolds : Holds before.assertions.toList extended :=
    before.holds_agrees_below assignment extended holds agreement
  have finalHolds : Holds after.assertions.toList extended :=
    (insert_submitted_holds value before after run extended).mpr
      ⟨extendedHolds, by simpa only [submittedWriteConstraint] using accepted⟩
  have boundedValue :
      forall symbol, symbol ∈ value.symbols -> symbol.2 < before.next := by
    intro symbol member
    simpa using List.all_eq_true.mp shape.valueBounded symbol member
  have extendedValue :
      value.eval extended Locals.empty = (valueNat : Int) :=
    (value.eval_agrees_below assignment extended Locals.empty before.next
      boundedValue agreement).symm.trans sameValue
  have extendedRep :=
    rep.agrees_below before assignment extended frame valid agreement
  exact ⟨extended, agreement, finalHolds,
    insert_submitted_frame value valueNat before after run extended finalHolds
      frame extendedRep extendedValue⟩

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
