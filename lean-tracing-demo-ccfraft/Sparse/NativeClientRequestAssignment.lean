-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeClientRequestExecution
import Sparse.NativeLeaderLogPrefix
import Sparse.NativeRetirementTailComplete
import Sparse.NativeRetirementTailSound
import Sparse.NativeSubmittedWriteEncoding
import Sparse.NativeClientRequestTermsEncoding
import Sparse.NativeArrayClientRequestModel

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

private theorem client_request_tail_guards {width : PNat}
    [Bootstrap (Fin width)]
    (source : Fin width) (transaction : Expr .int) (transactionNat : Nat)
    (before prepared : Encoding width)
    (rowTerms : NodeRowTerms width) (commit : Expr .int)
    (assignment prefixAssignment : Assignment)
    (prefixAgreement :
      assignment.AgreesBelow before.next prefixAssignment)
    (beforePrepared : before.next <= prepared.next)
    (valid : ReferencesValid before)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (state : State (Fin width) Nat)
    (columnsRep : FrameColumnsRep assignment before.toColumns frame)
    (modelRep : frame.Rep state)
    (enabled : CCFRaft.Enabled state (.clientRequest source transactionNat))
    (sameTransaction :
      transaction.eval assignment Locals.empty = (transactionNat : Int))
    (transactionBounded :
      transaction.symbols.all (fun symbol => symbol.2 < before.next) = true)
    (old : NativeArrayCheckQuorum.Local (Fin width) Nat)
    (sameOld : old = NativeArrayCheckQuorum.get frame.nodes source) :
    forall candidateAssignment,
      prefixAssignment.AgreesBelow prepared.next candidateAssignment ->
      forall output : NativeArrayCheckQuorum.Local (Fin width) Nat,
        (retirementTailTerms prepared rowTerms commit).values.Rep
            candidateAssignment output ->
        output.toModel =
            refreshRetirementState source
              { (NativeArrayLeaderLogWrite.appendRow old
                  (.transaction transactionNat)).toModel with
                commitIndex := old.commit } ->
        Holds (clientRequestGuards before.toColumns source transaction
          (retirementTailTerms prepared rowTerms commit).values.membershipState)
          candidateAssignment := by
  intro candidateAssignment candidateAgreement output outputRep outputModel
  have prefixToCandidate :
      prefixAssignment.AgreesBelow before.next candidateAssignment :=
    candidateAgreement.restrict beforePrepared
  have originalToCandidate :
      assignment.AgreesBelow before.next candidateAssignment :=
    prefixAgreement.trans prefixToCandidate
  have candidateFrameRep :
      FrameColumnsRep candidateAssignment before.toColumns frame :=
    columnsRep.agrees_below before assignment candidateAssignment frame valid
      originalToCandidate
  have boundedTransaction :
      forall symbol, symbol ∈ transaction.symbols ->
        symbol.2 < before.next := by
    intro symbol member
    simpa using List.all_eq_true.mp transactionBounded symbol member
  have candidateTransaction :
      transaction.eval candidateAssignment Locals.empty =
        (transactionNat : Int) :=
    (transaction.eval_agrees_below assignment candidateAssignment Locals.empty
      before.next boundedTransaction originalToCandidate).symm.trans
        sameTransaction
  subst old
  have outputModelAppended :
      output.toModel =
        refreshRetirementState source
          (NativeArrayLeaderLogWrite.appendRow
            (NativeArrayCheckQuorum.get frame.nodes source)
            (.transaction transactionNat)).toModel := by
    simpa [NativeArrayLeaderLogWrite.appendRow,
      NativeArrayCheckQuorum.Local.toModel] using outputModel
  have sameRow :
      state.nodes source =
        (NativeArrayCheckQuorum.get frame.nodes source).toModel :=
    (NativeArrayCheckQuorum.get_rep frame.nodes state modelRep.nodes source).symm
  have appendedModel :
      (NativeArrayLeaderLogWrite.appendRow
          (NativeArrayCheckQuorum.get frame.nodes source)
          (.transaction transactionNat)).toModel =
        { (state.nodes source) with
          log := (state.nodes source).log ++
            [{ term := (state.nodes source).currentTerm
               content := .transaction transactionNat }] } := by
    rw [NativeArrayLeaderLogWrite.append_row_correct, sameRow]
  have outputModelActual :
      output.toModel =
        refreshRetirementState source
          { (state.nodes source) with
            log := (state.nodes source).log ++
              [{ term := (state.nodes source).currentTerm
                 content := .transaction transactionNat }] } := by
    rw [outputModelAppended, appendedModel]
  have nativeEnabled :
      NativeArrayClientRequest.enabled frame source transactionNat output :=
    (NativeArrayClientRequest.enabled_correct frame state modelRep source
      transactionNat output outputModelActual).mpr enabled
  exact
    (client_request_guards_correct candidateAssignment before.toColumns frame
      candidateFrameRep source transaction
      (retirementTailTerms prepared rowTerms commit).values.membershipState
      transactionNat output candidateTransaction
      outputRep.membershipState).mpr nativeEnabled

private theorem client_request_retirement_assignment {width : PNat}
    [Bootstrap (Fin width)]
    (source : Fin width) (transaction : Expr .int) (transactionNat : Nat)
    (before prepared retired : Encoding width)
    (rowTerms : NodeRowTerms width) (commit : Expr .int)
    (tailRun :
      (retirementTail before.bootstrap source rowTerms commit
        (clientRequestGuards before.toColumns source transaction)).run prepared =
          .ok ((), retired))
    (assignment prefixAssignment : Assignment)
    (prefixAgreement :
      assignment.AgreesBelow before.next prefixAssignment)
    (prefixHolds : Holds prepared.assertions.toList prefixAssignment)
    (valid : ReferencesValid before)
    (preparedNext : prepared.next = before.next + 2)
    (preparedColumns : prepared.toColumns = before.toColumns)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (state : State (Fin width) Nat)
    (columnsRep : FrameColumnsRep assignment before.toColumns frame)
    (prefixFrameRep :
      FrameColumnsRep prefixAssignment before.toColumns frame)
    (modelRep : frame.Rep state)
    (enabled : CCFRaft.Enabled state (.clientRequest source transactionNat))
    (sameBootstrap : decodeBits before.bootstrap = INITIAL_CONFIGURATION)
    (sameTransaction :
      transaction.eval assignment Locals.empty = (transactionNat : Int))
    (transactionBounded :
      transaction.symbols.all (fun symbol => symbol.2 < before.next) = true)
    (old : NativeArrayCheckQuorum.Local (Fin width) Nat)
    (sameOld : old = NativeArrayCheckQuorum.get frame.nodes source)
    (rowRep : rowTerms.Rep prefixAssignment
      (NativeArrayLeaderLogWrite.appendRow old (.transaction transactionNat)))
    (rowBounded : rowTerms.Bounded prepared.next)
    (sameCommit : commit.eval prefixAssignment Locals.empty = (old.commit : Int))
    (commitBounded :
      commit.symbols.all (fun symbol => symbol.2 < prepared.next) = true) :
    exists retiredAssignment : Assignment,
      exists output : NativeArrayCheckQuorum.Local (Fin width) Nat,
        assignment.AgreesBelow before.next retiredAssignment /\
        Holds retired.assertions.toList retiredAssignment /\
        ReferencesValid retired /\
        FrameColumnsRep retiredAssignment retired.toColumns
          (retirementWriteFrame frame source
            (retirementCompletedNodes output.log.decode output.commit) output) /\
        transaction.eval retiredAssignment Locals.empty =
          (transactionNat : Int) := by
  have preparedValid : ReferencesValid prepared := by
    cases valid
    constructor <;> simp_all only <;> omega
  have preparedFrameRep :
      FrameColumnsRep prefixAssignment prepared.toColumns frame := by
    rw [preparedColumns]
    exact prefixFrameRep
  obtain ⟨retiredAssignment, tailAgreement, retiredHolds⟩ :=
    retirement_tail_complete before.bootstrap source rowTerms commit
      (clientRequestGuards before.toColumns source transaction)
      prepared retired tailRun prefixAssignment prefixHolds preparedValid frame
      preparedFrameRep
      (NativeArrayLeaderLogWrite.appendRow old (.transaction transactionNat))
      rowRep rowBounded old.commit sameCommit commitBounded sameBootstrap
      (client_request_tail_guards source transaction transactionNat before
        prepared rowTerms commit assignment prefixAssignment prefixAgreement
        (by omega) valid frame state columnsRep modelRep enabled sameTransaction
        transactionBounded old sameOld)
  have prefixToRetired :
      prefixAssignment.AgreesBelow before.next retiredAssignment :=
    tailAgreement.restrict (by omega)
  have originalToRetired :
      assignment.AgreesBelow before.next retiredAssignment :=
    prefixAgreement.trans prefixToRetired
  have retiredInputFrameRep :
      FrameColumnsRep retiredAssignment prepared.toColumns frame := by
    rw [preparedColumns]
    exact columnsRep.agrees_below before assignment retiredAssignment frame valid
      originalToRetired
  have retiredRowRep :
      rowTerms.Rep retiredAssignment
        (NativeArrayLeaderLogWrite.appendRow old (.transaction transactionNat)) :=
    rowRep.agrees_below prefixAssignment retiredAssignment rowTerms
      (NativeArrayLeaderLogWrite.appendRow old (.transaction transactionNat))
      prepared.next rowBounded tailAgreement
  have boundedCommit :
      forall symbol, symbol ∈ commit.symbols ->
        symbol.2 < prepared.next := by
    intro symbol member
    simpa using List.all_eq_true.mp commitBounded symbol member
  have retiredCommit :
      commit.eval retiredAssignment Locals.empty = (old.commit : Int) :=
    (commit.eval_agrees_below prefixAssignment retiredAssignment Locals.empty
      prepared.next boundedCommit tailAgreement).symm.trans sameCommit
  obtain ⟨output, _, _, _, retiredFrameRep⟩ :=
    retirement_tail_sound before.bootstrap source rowTerms commit
      (clientRequestGuards before.toColumns source transaction)
      prepared retired tailRun retiredAssignment retiredHolds frame
      retiredInputFrameRep
      (NativeArrayLeaderLogWrite.appendRow old (.transaction transactionNat))
      retiredRowRep old.commit retiredCommit sameBootstrap
  have retiredValid : ReferencesValid retired :=
    retirement_tail_references before.bootstrap source rowTerms commit
      (clientRequestGuards before.toColumns source transaction)
      prepared retired tailRun preparedValid
  have boundedTransaction :
      forall symbol, symbol ∈ transaction.symbols ->
        symbol.2 < before.next := by
    intro symbol member
    simpa using List.all_eq_true.mp transactionBounded symbol member
  have retiredTransaction :
      transaction.eval retiredAssignment Locals.empty =
        (transactionNat : Int) :=
    (transaction.eval_agrees_below assignment retiredAssignment Locals.empty
      before.next boundedTransaction originalToRetired).symm.trans sameTransaction
  exact ⟨retiredAssignment, output, originalToRetired, retiredHolds,
    retiredValid, retiredFrameRep, retiredTransaction⟩

private structure ClientRequestPreparedAssignmentResult {width : PNat}
    (source : Fin width) (transaction : Expr .int) (transactionNat : Nat)
    (before after : Encoding width) (assignment prefixAssignment : Assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (states : ClientRequestExecutionStates width)
    (prefixStates : LeaderLogPrefixStates width) : Prop where
  execution :
    ClientRequestExecutionResult source transaction before after states
  prefixResult :
    LeaderLogPrefixResult source (.inr (.inl transaction)) before
      states.prepared states.appended prefixStates
  agreement : assignment.AgreesBelow before.next prefixAssignment
  holds : Holds states.prepared.assertions.toList prefixAssignment
  frameRep : FrameColumnsRep prefixAssignment before.toColumns frame
  rowRep :
    (leaderLogPrefixTerms before source).appended.Rep prefixAssignment
      (NativeArrayLeaderLogWrite.appendRow
        (NativeArrayCheckQuorum.get frame.nodes source)
        (.transaction transactionNat))
  rowBounded :
    (leaderLogPrefixTerms before source).appended.Bounded states.prepared.next
  sameCommit :
    (leaderLogPrefixTerms before source).old.commit.eval
        prefixAssignment Locals.empty =
      (NativeArrayCheckQuorum.get frame.nodes source).commit
  commitBounded :
    (leaderLogPrefixTerms before source).old.commit.symbols.all
      (fun symbol => symbol.2 < states.prepared.next) = true

private theorem client_request_prepare_assignment {width : PNat}
    [Bootstrap (Fin width)]
    (source : Fin width) (transaction : Expr .int) (transactionNat : Nat)
    (before after : Encoding width)
    (run : (clientRequest source transaction).run before = .ok ((), after))
    (assignment : Assignment)
    (holds : Holds before.assertions.toList assignment)
    (valid : ReferencesValid before)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (columnsRep : FrameColumnsRep assignment before.toColumns frame)
    (sameTransaction :
      transaction.eval assignment Locals.empty = (transactionNat : Int))
    (transactionBounded :
      transaction.symbols.all (fun symbol => symbol.2 < before.next) = true) :
    exists states : ClientRequestExecutionStates width,
      exists prefixStates : LeaderLogPrefixStates width,
        exists prefixAssignment : Assignment,
          ClientRequestPreparedAssignmentResult source transaction
            transactionNat before after assignment prefixAssignment frame states
            prefixStates := by
  obtain ⟨states, execution⟩ :=
    client_request_execution source transaction before after run
  obtain ⟨prefixStates, prefixResult⟩ :=
    prepare_leader_log_success source (.inr (.inl transaction)) before
      states.prepared states.appended execution.prepareRun
  have contentBounded :
      ((.inr (.inl transaction) : Expr (contentTy width)).symbols.all
        (fun symbol => symbol.2 < before.next)) = true := by
    simpa [Term.symbols] using transactionBounded
  have sameContent :
      decodeContent
          ((.inr (.inl transaction) : Expr (contentTy width)).eval
            assignment Locals.empty) =
        (.transaction transactionNat : EntryContent (Fin width) Nat) := by
    simp [Term.eval, decodeContent, sameTransaction]
  obtain ⟨prefixAssignment, prefixAgreement, prefixHolds, prefixFrameRep,
      appendedRep, appendedBounded⟩ :=
    prepare_leader_log_assignment source (.inr (.inl transaction))
      (.transaction transactionNat) before states.prepared states.appended
      prefixStates prefixResult assignment holds valid frame columnsRep
      contentBounded sameContent
  let terms := leaderLogPrefixTerms before source
  let old := NativeArrayCheckQuorum.get frame.nodes source
  let appended :=
    NativeArrayLeaderLogWrite.appendRow old (.transaction transactionNat)
  have sameCommit :
      terms.old.commit.eval prefixAssignment Locals.empty = (old.commit : Int) := by
    simpa [terms, old, appended, leaderLogPrefixTerms,
      NativeArrayLeaderLogWrite.appendRow] using appendedRep.commit
  have commitBounded :
      terms.old.commit.symbols.all
        (fun symbol => symbol.2 < states.prepared.next) = true := by
    simpa [terms, leaderLogPrefixTerms, leaderLogRowTerms] using
      appendedBounded.commit
  exact ⟨states, prefixStates, prefixAssignment, execution, prefixResult,
    prefixAgreement, prefixHolds, prefixFrameRep, appendedRep, appendedBounded,
    sameCommit, commitBounded⟩

private structure ClientRequestRetiredAssignmentResult {width : PNat}
    [Bootstrap (Fin width)]
    (source : Fin width) (transaction : Expr .int) (transactionNat : Nat)
    (before after : Encoding width) (assignment retiredAssignment : Assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (states : ClientRequestExecutionStates width)
    (output : NativeArrayCheckQuorum.Local (Fin width) Nat) : Prop where
  execution :
    ClientRequestExecutionResult source transaction before after states
  agreement : assignment.AgreesBelow before.next retiredAssignment
  holds : Holds states.retired.assertions.toList retiredAssignment
  valid : ReferencesValid states.retired
  frameRep :
    FrameColumnsRep retiredAssignment states.retired.toColumns
      (retirementWriteFrame frame source
        (retirementCompletedNodes output.log.decode output.commit) output)
  sameTransaction :
    transaction.eval retiredAssignment Locals.empty = (transactionNat : Int)
  beforeRetired : before.next <= states.retired.next

private theorem client_request_retired_assignment {width : PNat}
    [Bootstrap (Fin width)]
    (source : Fin width) (transaction : Expr .int) (transactionNat : Nat)
    (before after : Encoding width)
    (assignment : Assignment)
    (valid : ReferencesValid before)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (state : State (Fin width) Nat)
    (columnsRep : FrameColumnsRep assignment before.toColumns frame)
    (modelRep : frame.Rep state)
    (enabled : CCFRaft.Enabled state (.clientRequest source transactionNat))
    (sameBootstrap : decodeBits before.bootstrap = INITIAL_CONFIGURATION)
    (sameTransaction :
      transaction.eval assignment Locals.empty = (transactionNat : Int))
    (transactionBounded :
      transaction.symbols.all (fun symbol => symbol.2 < before.next) = true)
    (states : ClientRequestExecutionStates width)
    (prefixStates : LeaderLogPrefixStates width)
    (prefixAssignment : Assignment)
    (prepared :
      ClientRequestPreparedAssignmentResult source transaction transactionNat
        before after assignment prefixAssignment frame states prefixStates) :
    exists retiredAssignment : Assignment,
      exists output : NativeArrayCheckQuorum.Local (Fin width) Nat,
        ClientRequestRetiredAssignmentResult source transaction transactionNat
          before after assignment retiredAssignment frame states output := by
  have execution := prepared.execution
  have prefixResult := prepared.prefixResult
  let terms := leaderLogPrefixTerms before source
  let old := NativeArrayCheckQuorum.get frame.nodes source
  have tailRun :
      (retirementTail before.bootstrap source terms.appended terms.old.commit
        (clientRequestGuards before.toColumns source transaction)).run
          states.prepared = .ok ((), states.retired) := by
    simpa only [prefixResult.outputTerms] using execution.tailRun
  obtain ⟨retiredAssignment, output, originalToRetired, retiredHolds,
      retiredValid, retiredFrameRep, retiredTransaction⟩ :=
    client_request_retirement_assignment source transaction transactionNat
      before states.prepared states.retired terms.appended terms.old.commit
      tailRun assignment prefixAssignment prepared.agreement
      prepared.holds
      valid prefixResult.afterNext prefixResult.afterColumns frame state
      columnsRep prepared.frameRep modelRep enabled sameBootstrap sameTransaction
      transactionBounded old rfl prepared.rowRep prepared.rowBounded
      prepared.sameCommit prepared.commitBounded
  have beforeRetired :
      before.next <= states.retired.next := by
    rw [retirement_tail_next before.bootstrap source terms.appended
      terms.old.commit
      (clientRequestGuards before.toColumns source transaction)
      states.prepared states.retired tailRun,
      prefixResult.afterNext]
    omega
  exact ⟨retiredAssignment, output, execution, originalToRetired, retiredHolds,
    retiredValid, retiredFrameRep, retiredTransaction, beforeRetired⟩

theorem client_request_assignment {width : PNat} [Bootstrap (Fin width)]
    (source : Fin width) (transaction : Expr .int) (transactionNat : Nat)
    (before after : Encoding width)
    (run : (clientRequest source transaction).run before = .ok ((), after))
    (assignment : Assignment)
    (holds : Holds before.assertions.toList assignment)
    (valid : ReferencesValid before)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (state : State (Fin width) Nat)
    (columnsRep : FrameColumnsRep assignment before.toColumns frame)
    (modelRep : frame.Rep state)
    (enabled : CCFRaft.Enabled state (.clientRequest source transactionNat))
    (sameBootstrap : decodeBits before.bootstrap = INITIAL_CONFIGURATION)
    (sameTransaction :
      transaction.eval assignment Locals.empty = (transactionNat : Int))
    (transactionBounded :
      transaction.symbols.all (fun symbol => symbol.2 < before.next) = true) :
    exists extended : Assignment,
      assignment.AgreesBelow before.next extended /\
        Holds after.assertions.toList extended := by
  obtain ⟨states, prefixStates, prefixAssignment, prepared⟩ :=
    client_request_prepare_assignment source transaction transactionNat before
      after run assignment holds valid frame columnsRep sameTransaction
      transactionBounded
  obtain ⟨retiredAssignment, output, retired⟩ :=
    client_request_retired_assignment source transaction transactionNat before
      after assignment valid frame state columnsRep modelRep enabled
      sameBootstrap sameTransaction transactionBounded states prefixStates
      prefixAssignment prepared
  obtain ⟨extended, submittedAgreement, finalHolds, _⟩ :=
    insert_submitted_complete transaction transactionNat states.retired after
      retired.execution.submittedRun retiredAssignment retired.holds
      (retirementWriteFrame frame source
        (retirementCompletedNodes output.log.decode output.commit) output)
      retired.frameRep retired.valid retired.sameTransaction
  exact ⟨extended,
    retired.agreement.trans
      (submittedAgreement.restrict retired.beforeRetired),
    finalHolds⟩

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
