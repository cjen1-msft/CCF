-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeVoteSend
import Sparse.NativeQueueStoreEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

structure VoteSendPrefix {width : PNat} (before guarded : Encoding width)
    (preVote : Bool) (source destination : Fin width) : Prop where
  bootstrap : guarded.bootstrap = before.bootstrap
  columns : guarded.toColumns = before.toColumns
  next : guarded.next = before.next + 3
  clauses : guarded.assertions.toList = before.assertions.toList ++
    voteGuards before.toColumns before.bootstrap preVote source destination before.next

theorem send_vote_prefix {width : PNat} (preVote : Bool) (source destination : Fin width)
    (before after : Encoding width)
    (run : (sendVote preVote source destination).run before = .ok ((), after)) :
    exists guarded : Encoding width, VoteSendPrefix before guarded preVote source destination /\
      (pushQueue destination source
        (votePacketTerm before.toColumns preVote source destination (.free .int (before.next + 2)))).run guarded = .ok ((), after) := by
  simp only [sendVote, get_bind_run] at run
  obtain ⟨base, first, firstRun, run⟩ := (bind_run _ _ _ _ _).mp run
  obtain ⟨unused, second, secondRun, run⟩ := (bind_run _ _ _ _ _).mp run
  obtain ⟨unused, third, thirdRun, run⟩ := (bind_run _ _ _ _ _).mp run
  obtain ⟨value, guarded, guardRun, run⟩ := (bind_run _ _ _ _ _).mp run
  cases value
  obtain ⟨baseEq, firstNext, firstBootstrap, firstColumns, firstClauses⟩ :=
    fresh_success before first base firstRun
  obtain ⟨_, secondNext, secondBootstrap, secondColumns, secondClauses⟩ :=
    fresh_success first second _ secondRun
  obtain ⟨_, thirdNext, thirdBootstrap, thirdColumns, thirdClauses⟩ :=
    fresh_success second third _ thirdRun
  obtain ⟨guardFrame, guardClauses⟩ := assert_all_success _ third guarded guardRun
  refine ⟨guarded, ?_, by simpa only [baseEq] using run⟩
  constructor
  · exact guardFrame.bootstrap.trans (thirdBootstrap.trans (secondBootstrap.trans firstBootstrap))
  · exact guardFrame.columns.trans (thirdColumns.trans (secondColumns.trans firstColumns))
  · rw [guardFrame.next, thirdNext, secondNext, firstNext]
  · rw [guardClauses, thirdClauses, secondClauses, firstClauses, baseEq]

theorem VoteSendPrefix.references {width : PNat} {before guarded : Encoding width}
    {preVote : Bool} {source destination : Fin width}
    (shape : VoteSendPrefix before guarded preVote source destination)
    (valid : ReferencesValid before) : ReferencesValid guarded := by
  cases valid
  constructor <;> simp only [shape.columns, shape.next] <;> omega

theorem VoteSendPrefix.holds {width : PNat} {before guarded : Encoding width}
    {preVote : Bool} {source destination : Fin width}
    (shape : VoteSendPrefix before guarded preVote source destination) (assignment : Assignment) :
    Holds guarded.assertions.toList assignment <->
      Holds before.assertions.toList assignment /\
        Holds (voteGuards before.toColumns before.bootstrap preVote source destination before.next) assignment := by
  rw [shape.clauses]
  simp [Holds, or_imp, forall_and]

theorem send_vote_references {width : PNat} (preVote : Bool) (source destination : Fin width)
    (before after : Encoding width)
    (run : (sendVote preVote source destination).run before = .ok ((), after))
    (valid : ReferencesValid before) : ReferencesValid after := by
  obtain ⟨guarded, shape, pushed⟩ := send_vote_prefix preVote source destination before after run
  exact push_queue_references destination source _ guarded after pushed (shape.references valid)

theorem send_vote_bootstrap {width : PNat} (preVote : Bool) (source destination : Fin width)
    (before after : Encoding width)
    (run : (sendVote preVote source destination).run before = .ok ((), after)) :
    after.bootstrap = before.bootstrap := by
  obtain ⟨guarded, shape, pushed⟩ := send_vote_prefix preVote source destination before after run
  exact (push_queue_success destination source _ guarded after pushed).bootstrap.trans shape.bootstrap

theorem send_vote_holds_before {width : PNat} (preVote : Bool) (source destination : Fin width)
    (before after : Encoding width)
    (run : (sendVote preVote source destination).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment) :
    Holds before.assertions.toList assignment := by
  obtain ⟨guarded, shape, pushed⟩ := send_vote_prefix preVote source destination before after run
  exact ((shape.holds assignment).mp
    ((push_queue_holds destination source _ guarded after pushed assignment).mp holds).1).1

theorem send_vote_frame_success {width : PNat} [Bootstrap (Fin width)]
    (preVote : Bool) (source destination : Fin width) (before after : Encoding width)
    (run : (sendVote preVote source destination).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment before.toColumns frame)
    (sameBootstrap : decodeBits before.bootstrap = INITIAL_CONFIGURATION) :
    NativeArrayVote.enabled frame.nodes preVote source destination /\
      exists signature : Nat, NativeArrayVote.SignatureIndex
        (NativeArrayCheckQuorum.get frame.nodes source).log signature /\
        FrameColumnsRep assignment after.toColumns (frame.vote preVote source destination signature) := by
  obtain ⟨guarded, shape, pushed⟩ := send_vote_prefix preVote source destination before after run
  have guardHolds := ((push_queue_holds destination source _ guarded after pushed assignment).mp holds).1
  obtain ⟨enabled, signature, sameSignature, latest⟩ :=
    vote_guards_sound assignment before.toColumns frame.nodes rep.nodes before.bootstrap sameBootstrap
      preVote source destination before.next ((shape.holds assignment).mp guardHolds).2
  let expected := NativeArrayVote.packet (NativeArrayCheckQuorum.get frame.nodes source)
    preVote source destination signature
  have packetSource : expected.source = source := by cases preVote <;> rfl
  have packetDestination : expected.destination = destination := by cases preVote <;> rfl
  have samePacket := vote_packet_term_eval assignment Locals.empty before.toColumns frame.nodes rep.nodes
    preVote source destination (.free .int (before.next + 2)) signature
      (by simpa only [Term.eval] using sameSignature)
  have guardedRep : FrameColumnsRep assignment guarded.toColumns frame := by
    simpa only [shape.columns] using rep
  refine ⟨enabled, signature, latest, ?_⟩
  exact push_queue_frame_success _ expected guarded after
    (by simpa only [packetSource, packetDestination] using pushed) assignment holds frame guardedRep samePacket

theorem send_vote_complete {width : PNat} [Bootstrap (Fin width)]
    (preVote : Bool) (source destination : Fin width) (before after : Encoding width)
    (run : (sendVote preVote source destination).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds before.assertions.toList assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment before.toColumns frame) (valid : ReferencesValid before)
    (sameBootstrap : decodeBits before.bootstrap = INITIAL_CONFIGURATION)
    (enabled : NativeArrayVote.enabled frame.nodes preVote source destination)
    (signature : Nat)
    (latest : NativeArrayVote.SignatureIndex (NativeArrayCheckQuorum.get frame.nodes source).log signature) :
    exists extended : Assignment, assignment.AgreesBelow before.next extended /\
      Holds after.assertions.toList extended /\
      FrameColumnsRep extended after.toColumns (frame.vote preVote source destination signature) := by
  obtain ⟨guarded, shape, pushed⟩ := send_vote_prefix preVote source destination before after run
  obtain ⟨witnesses, agreement, guards, sameSignature⟩ :=
    vote_guards_complete assignment before.toColumns frame.nodes rep.nodes before.bootstrap sameBootstrap
      preVote source destination before.next signature enabled latest
  have previous := before.holds_agrees_below assignment witnesses holds agreement
  have guardHolds := (shape.holds witnesses).mpr ⟨previous, guards⟩
  have witnessRep := rep.agrees_below before assignment witnesses frame valid agreement
  have guardedRep : FrameColumnsRep witnesses guarded.toColumns frame := by
    simpa only [shape.columns] using witnessRep
  let expected := NativeArrayVote.packet (NativeArrayCheckQuorum.get frame.nodes source)
    preVote source destination signature
  have packetSource : expected.source = source := by cases preVote <;> rfl
  have packetDestination : expected.destination = destination := by cases preVote <;> rfl
  have samePacket := vote_packet_term_eval witnesses Locals.empty before.toColumns frame.nodes witnessRep.nodes
    preVote source destination (.free .int (before.next + 2)) signature
      (by simpa only [Term.eval] using sameSignature)
  obtain ⟨extended, pushAgreement, finalHolds, finalRep⟩ :=
    push_queue_complete _ expected guarded after
      (by simpa only [packetSource, packetDestination] using pushed)
      witnesses guardHolds frame guardedRep (shape.references valid) samePacket
  refine ⟨extended, agreement.trans (pushAgreement.restrict ?_), finalHolds, finalRep⟩
  rw [shape.next]
  omega

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
