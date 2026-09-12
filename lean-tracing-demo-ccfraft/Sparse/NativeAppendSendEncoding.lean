-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeAppendSend
import Sparse.NativeAppendGuardEncoding
import Sparse.NativeQueueStoreEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def appendSentNodes {width : PNat}
    (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat)
    (source destination : Fin width) (batchEnd : Nat) :
    NativeArrayCheckQuorum.Arrays (Fin width) Nat :=
  Function.update arrays source (some
    { NativeArrayCheckQuorum.get arrays source with
      sentIndex := CCFRaft.updateIndex
        (NativeArrayCheckQuorum.get arrays source).sentIndex destination batchEnd })

theorem get_append_sent {width : PNat}
    (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat)
    (source destination peer : Fin width) (batchEnd : Nat) :
    NativeArrayCheckQuorum.get (appendSentNodes arrays source destination batchEnd) peer =
      if peer = source then
        { NativeArrayCheckQuorum.get arrays source with
          sentIndex := CCFRaft.updateIndex
            (NativeArrayCheckQuorum.get arrays source).sentIndex destination batchEnd }
      else NativeArrayCheckQuorum.get arrays peer := by
  by_cases same : peer = source
  · subst peer
    simp [appendSentNodes, NativeArrayCheckQuorum.get]
  · simp [appendSentNodes, NativeArrayCheckQuorum.get, same]

def appendSentColumns (columns : Columns) (sentIndex : Nat) : Columns :=
  { columns with sentIndex }

theorem node_columns_append_sent {width : PNat}
    (assignment : Assignment) (before : Columns) (sentIndex : Nat)
    (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat)
    (source destination : Fin width) (batchEnd : Nat)
    (rep : NodeColumnsRep assignment before arrays)
    (present : (arrays source).isSome = true)
    (binding : assignment (.array .int (.array .int .int)) sentIndex =
      (appendSentIndex before source destination batchEnd).eval assignment Locals.empty) :
    NodeColumnsRep assignment (appendSentColumns before sentIndex)
      (appendSentNodes arrays source destination batchEnd) := by
  constructor
  · intro peer
    by_cases same : peer = source
    · subst peer
      simpa [appendSentNodes, present] using (rep.allocated source).trans present
    · simpa [appendSentNodes, same] using rep.allocated peer
  · intro peer
    have previous := rep.role peer
    rw [get_append_sent]
    by_cases same : peer = source <;> simp_all [appendSentColumns]
  · intro peer
    have previous := rep.newFollower peer
    rw [get_append_sent]
    by_cases same : peer = source <;> simp_all [appendSentColumns]
  · intro peer
    have previous := rep.currentTerm peer
    rw [get_append_sent]
    by_cases same : peer = source <;> simp_all [appendSentColumns]
  · intro peer
    have previous := rep.commit peer
    rw [get_append_sent]
    by_cases same : peer = source <;> simp_all
  · intro peer
    have previous := rep.length peer
    rw [get_append_sent]
    by_cases same : peer = source <;> simp_all
  · intro peer index within
    rw [get_append_sent] at within ⊢
    by_cases same : peer = source
    · subst peer
      simpa [appendSentColumns] using rep.entries source index (by simpa using within)
    · simpa [appendSentColumns, same] using rep.entries peer index (by simpa [same] using within)
  · intro peer
    have previous := rep.retirementIndex peer
    rw [get_append_sent]
    by_cases same : peer = source <;> simp_all [appendSentColumns]
  · intro peer
    have previous := rep.retirementCommittableIndex peer
    rw [get_append_sent]
    by_cases same : peer = source <;> simp_all [appendSentColumns]
  · intro peer
    have previous := rep.retiredCommittedIndex peer
    rw [get_append_sent]
    by_cases same : peer = source <;> simp_all [appendSentColumns]
  · intro peer
    have previous := rep.votedFor peer
    rw [get_append_sent]
    by_cases same : peer = source <;> simp_all [appendSentColumns]
  · intro peer
    have previous := rep.votesGranted peer
    rw [get_append_sent]
    by_cases same : peer = source <;> simp_all [appendSentColumns]
  · intro peer
    have previous := rep.preVotesGranted peer
    rw [get_append_sent]
    by_cases same : peer = source <;> simp_all [appendSentColumns]
  · intro peer
    have previous := rep.membershipState peer
    rw [get_append_sent]
    by_cases same : peer = source <;> simp_all [appendSentColumns]
  · intro peer target
    rw [get_append_sent]
    change (peerIndex sentIndex peer.val (.integer target.val)).eval assignment Locals.empty = _
    simp only [peerIndex, Term.eval]
    rw [binding]
    simp only [appendSentIndex, Term.eval, store_pair_eval]
    by_cases samePeer : peer = source
    · subst peer
      have allocatedSource :
          (allocated source.val : Expr .bool).eval assignment Locals.empty = true :=
        (rep.allocated source).trans present
      rw [allocatedSource]
      simp only [if_true]
      by_cases sameTarget : target = destination
      · subst target
        simp [CCFRaft.updateIndex]
      · have different : (target.val : Int) ≠ destination.val := by
          exact_mod_cast fun equal => sameTarget (Fin.ext equal)
        have previous := rep.sentIndex source target
        simp only [peerIndex, Term.eval, allocatedSource, if_true] at previous
        simpa [CCFRaft.updateIndex, sameTarget, different] using previous
    · have different : (peer.val : Int) ≠ source.val := by
        exact_mod_cast fun equal => samePeer (Fin.ext equal)
      have previous := rep.sentIndex peer target
      simp only [different, false_and, samePeer, if_false]
      simpa only [peerIndex, Term.eval] using previous
  · intro peer target
    have previous := rep.matchIndex peer target
    rw [get_append_sent]
    by_cases same : peer = source <;> simp_all [appendSentColumns]

structure AppendSendGuardPrefix {width : PNat} (before guarded : Encoding width)
    (source destination : Fin width) (batchEnd : Nat) : Prop where
  bootstrap : guarded.bootstrap = before.bootstrap
  columns : guarded.toColumns = before.toColumns
  next : guarded.next = before.next + 2
  clauses : guarded.assertions.toList = before.assertions.toList ++
    appendGuards before.toColumns before.bootstrap source destination batchEnd before.next

theorem append_send_guard_success {width : PNat} (columns : Columns) (bootstrap : BitVec width)
    (source destination : Fin width) (batchEnd : Nat) (before guarded : Encoding width)
    (run : (appendSendGuard columns bootstrap source destination batchEnd).run before =
      .ok ((), guarded)) :
    guarded.bootstrap = before.bootstrap /\
      guarded.toColumns = before.toColumns /\
      guarded.next = before.next + 2 /\
      guarded.assertions.toList = before.assertions.toList ++
        appendGuards columns bootstrap source destination batchEnd before.next := by
  simp only [appendSendGuard] at run
  obtain ⟨base, first, firstRun, run⟩ := (bind_run _ _ _ _ _).mp run
  obtain ⟨unused, second, secondRun, run⟩ := (bind_run _ _ _ _ _).mp run
  obtain ⟨baseEq, firstNext, firstBootstrap, firstColumns, firstClauses⟩ :=
    fresh_success before first base firstRun
  obtain ⟨_, secondNext, secondBootstrap, secondColumns, secondClauses⟩ :=
    fresh_success first second _ secondRun
  obtain ⟨guardFrame, guardClauses⟩ := assert_all_success _ second guarded run
  refine ⟨guardFrame.bootstrap.trans (secondBootstrap.trans firstBootstrap),
    guardFrame.columns.trans (secondColumns.trans firstColumns), ?_, ?_⟩
  · rw [guardFrame.next, secondNext, firstNext]
  · rw [guardClauses, secondClauses, firstClauses, baseEq]

theorem append_send_guard_steps {width : PNat} (source destination : Fin width) (batchEnd : Nat)
    (before after : Encoding width)
    (run : (sendAppend source destination batchEnd).run before = .ok ((), after)) :
    exists guarded : Encoding width,
      AppendSendGuardPrefix before guarded source destination batchEnd /\
      (appendSendBody before.toColumns source destination batchEnd).run guarded =
        .ok ((), after) := by
  simp only [sendAppend, get_bind_run] at run
  obtain ⟨unused, guarded, guardRun, bodyRun⟩ := (bind_run _ _ _ _ _).mp run
  cases unused
  obtain ⟨bootstrap, columns, next, clauses⟩ :=
    append_send_guard_success before.toColumns before.bootstrap source destination batchEnd
      before guarded guardRun
  exact ⟨guarded, ⟨bootstrap, columns, next, clauses⟩, bodyRun⟩

theorem append_send_body_steps {width : PNat} (columns : Columns)
    (source destination : Fin width) (batchEnd : Nat) (guarded after : Encoding width)
    (run : (appendSendBody columns source destination batchEnd).run guarded = .ok ((), after)) :
    exists defined : Encoding width,
      (define (appendSentIndex columns source destination batchEnd)).run guarded =
        .ok (guarded.next, defined) /\
      (pushQueue destination source (appendPacketTerm columns source destination)).run
        { defined with sentIndex := guarded.next } = .ok ((), after) := by
  simp only [appendSendBody] at run
  obtain ⟨sentIndex, defined, definition, pushed⟩ := (bind_run _ _ _ _ _).mp run
  have sentIndexEq := (define_success _ guarded defined sentIndex definition).1
  subst sentIndex
  exact ⟨defined, definition, pushed⟩

theorem append_send_steps {width : PNat} (source destination : Fin width) (batchEnd : Nat)
    (before after : Encoding width)
    (run : (sendAppend source destination batchEnd).run before = .ok ((), after)) :
    exists guarded defined : Encoding width,
      AppendSendGuardPrefix before guarded source destination batchEnd /\
      (define (appendSentIndex before.toColumns source destination batchEnd)).run guarded =
        .ok (before.next + 2, defined) /\
      (pushQueue destination source (appendPacketTerm before.toColumns source destination)).run
        { defined with sentIndex := before.next + 2 } = .ok ((), after) := by
  obtain ⟨guarded, shape, body⟩ :=
    append_send_guard_steps source destination batchEnd before after run
  obtain ⟨defined, definition, pushed⟩ :=
    append_send_body_steps before.toColumns source destination batchEnd guarded after body
  refine ⟨guarded, defined, shape, ?_, ?_⟩
  · simpa only [shape.next] using definition
  · simpa only [shape.next] using pushed

theorem AppendSendGuardPrefix.references {width : PNat} {before guarded : Encoding width}
    {source destination : Fin width} {batchEnd : Nat}
    (shape : AppendSendGuardPrefix before guarded source destination batchEnd)
    (valid : ReferencesValid before) : ReferencesValid guarded := by
  cases valid
  constructor <;> simp only [shape.columns, shape.next] <;> omega

theorem AppendSendGuardPrefix.holds {width : PNat} {before guarded : Encoding width}
    {source destination : Fin width} {batchEnd : Nat}
    (shape : AppendSendGuardPrefix before guarded source destination batchEnd)
    (assignment : Assignment) :
    Holds guarded.assertions.toList assignment <->
      Holds before.assertions.toList assignment /\
        Holds (appendGuards before.toColumns before.bootstrap source destination batchEnd before.next)
          assignment := by
  rw [shape.clauses]
  simp [Holds, or_imp, forall_and]

theorem ReferencesValid.update_sent_index {width : PNat} {state : Encoding width}
    (valid : ReferencesValid state) (sentIndex : Nat) (bound : sentIndex < state.next) :
    ReferencesValid { state with sentIndex } := by
  cases valid
  constructor <;> simp only <;> assumption

theorem send_append_references {width : PNat} (source destination : Fin width) (batchEnd : Nat)
    (before after : Encoding width)
    (run : (sendAppend source destination batchEnd).run before = .ok ((), after))
    (valid : ReferencesValid before) : ReferencesValid after := by
  obtain ⟨guarded, defined, shape, definition, pushed⟩ :=
    append_send_steps source destination batchEnd before after run
  have guardedValid := shape.references valid
  have definedValid : ReferencesValid defined := by
    have written := define_success _ guarded defined (before.next + 2) definition
    cases guardedValid
    constructor <;> simp only [written.2.2.2, written.2.1] <;> omega
  exact push_queue_references destination source _ { defined with sentIndex := before.next + 2 }
    after pushed (definedValid.update_sent_index _ (by
      have writtenNext := (define_success _ guarded defined _ definition).2.1
      rw [writtenNext, shape.next]
      omega))

theorem send_append_bootstrap {width : PNat} (source destination : Fin width) (batchEnd : Nat)
    (before after : Encoding width)
    (run : (sendAppend source destination batchEnd).run before = .ok ((), after)) :
    after.bootstrap = before.bootstrap := by
  obtain ⟨guarded, defined, shape, definition, pushed⟩ :=
    append_send_steps source destination batchEnd before after run
  exact (push_queue_success destination source _ _ after pushed).bootstrap.trans
    ((define_success _ guarded defined _ definition).2.2.1.trans shape.bootstrap)

theorem send_append_holds_before {width : PNat} (source destination : Fin width) (batchEnd : Nat)
    (before after : Encoding width)
    (run : (sendAppend source destination batchEnd).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment) :
    Holds before.assertions.toList assignment := by
  obtain ⟨guarded, defined, shape, definition, pushed⟩ :=
    append_send_steps source destination batchEnd before after run
  have sentHolds :=
    (push_queue_holds destination source _ { defined with sentIndex := before.next + 2 }
      after pushed assignment).mp holds |>.1
  have definedHolds : Holds defined.assertions.toList assignment := sentHolds
  have written := define_success _ guarded defined _ definition
  rw [written.2.2.2.2, Array.toList_push] at definedHolds
  have guardedHolds : Holds guarded.assertions.toList assignment := by
    intro formula member
    exact definedHolds formula (List.mem_append_left _ member)
  exact ((shape.holds assignment).mp guardedHolds).1

theorem append_sent_frame {width : PNat}
    (assignment : Assignment) (before : Columns) (sentIndex : Nat)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (source destination : Fin width) (batchEnd : Nat)
    (rep : FrameColumnsRep assignment before frame)
    (present : (frame.nodes source).isSome = true)
    (binding : assignment (.array .int (.array .int .int)) sentIndex =
      (appendSentIndex before source destination batchEnd).eval assignment Locals.empty) :
    FrameColumnsRep assignment (appendSentColumns before sentIndex)
      { frame with nodes := appendSentNodes frame.nodes source destination batchEnd } := by
  constructor
  · exact node_columns_append_sent assignment before sentIndex frame.nodes source destination
      batchEnd rep.nodes present binding
  · simpa [appendSentColumns] using rep.hasJoined
  · intro node
    simpa [appendSentColumns] using rep.preVoteStatus node
  · intro node
    simpa [appendSentColumns] using rep.retirementCompleted node
  · intro txId
    simpa [appendSentColumns] using rep.submittedTxIds txId
  · intro readDestination readSource
    simpa [appendSentColumns, queueRow] using rep.queues readDestination readSource

theorem send_append_frame_success {width : PNat} [Bootstrap (Fin width)]
    (source destination : Fin width) (batchEnd : Nat) (before after : Encoding width)
    (run : (sendAppend source destination batchEnd).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment before.toColumns frame)
    (sameBootstrap : decodeBits before.bootstrap = INITIAL_CONFIGURATION) :
    NativeArrayAppend.enabled frame source destination batchEnd /\
      FrameColumnsRep assignment after.toColumns
        (NativeArrayAppend.send frame source destination batchEnd) := by
  obtain ⟨guarded, defined, shape, definition, pushed⟩ :=
    append_send_steps source destination batchEnd before after run
  have sentHolds :=
    (push_queue_holds destination source _ { defined with sentIndex := before.next + 2 }
      after pushed assignment).mp holds |>.1
  have written := define_success _ guarded defined _ definition
  have definedHolds : Holds defined.assertions.toList assignment := sentHolds
  rw [written.2.2.2.2, Array.toList_push] at definedHolds
  have guardedHolds : Holds guarded.assertions.toList assignment := by
    intro formula member
    exact definedHolds formula (List.mem_append_left _ member)
  have enabled := append_guards_sound assignment before.toColumns frame rep before.bootstrap
    sameBootstrap source destination batchEnd before.next ((shape.holds assignment).mp guardedHolds).2
  have binding : assignment (.array .int (.array .int .int)) (before.next + 2) =
      (appendSentIndex before.toColumns source destination batchEnd).eval assignment Locals.empty := by
    have current := definedHolds
      (.equal (.free (.array .int (.array .int .int)) (before.next + 2))
        (appendSentIndex before.toColumns source destination batchEnd))
      (by simp)
    simpa only [Term.eval, decide_eq_true_eq] using current
  let sentFrame : NativeArrayVote.Frame (Fin width) Nat :=
    { frame with nodes := appendSentNodes frame.nodes source destination batchEnd }
  have sentRep : FrameColumnsRep assignment
      ({ defined with sentIndex := before.next + 2 } : Encoding width).toColumns sentFrame := by
    have columns : defined.toColumns = before.toColumns := written.2.2.2.1.trans shape.columns
    simpa only [sentFrame, columns] using
      append_sent_frame assignment before.toColumns (before.next + 2) frame source destination
        batchEnd rep enabled.1 binding
  have samePacket := append_packet_term_correct assignment before.toColumns frame.nodes rep.nodes
    source destination
  have pushedRep := push_queue_frame_success _ (.appendEntriesRequest
      (NativeArrayAppend.request (NativeArrayCheckQuorum.get frame.nodes source) source destination))
    { defined with sentIndex := before.next + 2 } after pushed assignment holds sentFrame sentRep
    samePacket
  refine ⟨enabled, ?_⟩
  simpa [NativeArrayAppend.send, sentFrame, appendSentNodes] using pushedRep

theorem send_append_model_success {width : PNat} [Bootstrap (Fin width)]
    (source destination : Fin width) (batchEnd : Nat) (before after : Encoding width)
    (run : (sendAppend source destination batchEnd).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat) (state : State (Fin width) Nat)
    (columns : FrameColumnsRep assignment before.toColumns frame)
    (model : frame.Rep state)
    (sameBootstrap : decodeBits before.bootstrap = INITIAL_CONFIGURATION) :
    Enabled state (.appendEntries source destination batchEnd) /\
      FrameColumnsRep assignment after.toColumns
        (NativeArrayAppend.send frame source destination batchEnd) /\
      (NativeArrayAppend.send frame source destination batchEnd).Rep
        (CCFRaft.next state (.appendEntries source destination batchEnd)) := by
  obtain ⟨enabled, encoded⟩ := send_append_frame_success source destination batchEnd before after
    run assignment holds frame columns sameBootstrap
  refine ⟨(NativeArrayAppend.enabled_correct frame state model source destination batchEnd).mp enabled,
    encoded, ?_⟩
  have frontier : batchEnd =
      min ((NativeArrayCheckQuorum.get frame.nodes source).sentIndex destination + 1)
        (NativeArrayCheckQuorum.get frame.nodes source).log.length := by
    rcases enabled with ⟨_, _, _, _, _, frontier, _⟩
    exact frontier
  exact NativeArrayAppend.send_rep frame state model source destination batchEnd frontier

theorem send_append_complete {width : PNat} [Bootstrap (Fin width)]
    (source destination : Fin width) (batchEnd : Nat) (before after : Encoding width)
    (run : (sendAppend source destination batchEnd).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds before.assertions.toList assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment before.toColumns frame) (valid : ReferencesValid before)
    (sameBootstrap : decodeBits before.bootstrap = INITIAL_CONFIGURATION)
    (enabled : NativeArrayAppend.enabled frame source destination batchEnd) :
    exists extended : Assignment, assignment.AgreesBelow before.next extended /\
      Holds after.assertions.toList extended /\
      FrameColumnsRep extended after.toColumns
        (NativeArrayAppend.send frame source destination batchEnd) := by
  obtain ⟨guarded, defined, shape, definition, pushed⟩ :=
    append_send_steps source destination batchEnd before after run
  obtain ⟨witnesses, guardAgreement, guards⟩ :=
    append_guards_complete before assignment frame rep valid sameBootstrap source destination
      batchEnd enabled
  have previous := before.holds_agrees_below assignment witnesses holds guardAgreement
  have guardedHolds := (shape.holds witnesses).mpr ⟨previous, guards⟩
  obtain ⟨written, writeAgreement, definedHolds⟩ :=
    define_extension _ guarded defined (before.next + 2) definition witnesses guardedHolds
  have beforeToWritten : assignment.AgreesBelow before.next written :=
    guardAgreement.trans (writeAgreement.restrict (by rw [shape.next]; omega))
  have writtenRep := rep.agrees_below before assignment written frame valid beforeToWritten
  have binding : written (.array .int (.array .int .int)) (before.next + 2) =
      (appendSentIndex before.toColumns source destination batchEnd).eval written Locals.empty := by
    have writtenShape := define_success _ guarded defined _ definition
    rw [writtenShape.2.2.2.2, Array.toList_push] at definedHolds
    have current := definedHolds
      (.equal (.free (.array .int (.array .int .int)) (before.next + 2))
        (appendSentIndex before.toColumns source destination batchEnd))
      (by simp)
    simpa only [Term.eval, decide_eq_true_eq] using current
  let sentFrame : NativeArrayVote.Frame (Fin width) Nat :=
    { frame with nodes := appendSentNodes frame.nodes source destination batchEnd }
  have sentRep : FrameColumnsRep written
      ({ defined with sentIndex := before.next + 2 } : Encoding width).toColumns sentFrame := by
    have columns : defined.toColumns = before.toColumns :=
      (define_success _ guarded defined _ definition).2.2.2.1.trans shape.columns
    simpa only [sentFrame, columns] using
      append_sent_frame written before.toColumns (before.next + 2) frame source destination
        batchEnd writtenRep enabled.1 binding
  have samePacket := append_packet_term_correct written before.toColumns frame.nodes
    writtenRep.nodes source destination
  obtain ⟨extended, pushAgreement, finalHolds, finalRep⟩ :=
    push_queue_complete _ (.appendEntriesRequest
      (NativeArrayAppend.request (NativeArrayCheckQuorum.get frame.nodes source) source destination))
      { defined with sentIndex := before.next + 2 } after pushed written definedHolds sentFrame sentRep
      (by
        have guardedValid := shape.references valid
        have definedValid : ReferencesValid defined := by
          have writtenShape := define_success _ guarded defined _ definition
          cases guardedValid
          constructor <;> simp only [writtenShape.2.2.2, writtenShape.2.1] <;> omega
        exact definedValid.update_sent_index _ (by
          have writtenNext := (define_success _ guarded defined _ definition).2.1
          rw [writtenNext, shape.next]
          omega))
      samePacket
  have agreement : assignment.AgreesBelow before.next extended :=
    beforeToWritten.trans (pushAgreement.restrict (by
      have writtenNext := (define_success _ guarded defined _ definition).2.1
      rw [writtenNext, shape.next]
      omega))
  refine ⟨extended, agreement, finalHolds, ?_⟩
  simpa [NativeArrayAppend.send, sentFrame, appendSentNodes] using finalRep

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
