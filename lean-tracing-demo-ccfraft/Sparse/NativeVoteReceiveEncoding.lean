-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeVoteReceive
import Sparse.NativeVoteReceiveGuardEncoding
import Sparse.NativeVoteReceiveWritesEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def receiveVotePrefixClauses {width : PNat} (before : Encoding width)
    (source destination : Fin width) : List (Expr .bool) :=
  voteReceiveGuards before.toColumns source destination ++
    [signatureIndexTerm width destination.val (.free .int before.next)]

structure ReceiveVotePrefixResult {width : PNat} (before guarded : Encoding width)
    (source destination : Fin width) : Prop where
  bootstrap : guarded.bootstrap = before.bootstrap
  columns : guarded.toColumns = before.toColumns
  next : guarded.next = before.next + 1
  clauses : guarded.assertions.toList =
    before.assertions.toList ++ receiveVotePrefixClauses before source destination

theorem receive_vote_prefix_success {width : PNat}
    (source destination : Fin width) (before after : Encoding width) (signature : Nat)
    (run : (receiveVotePrefix before.toColumns source destination).run before =
      .ok (signature, after)) :
    signature = before.next /\ ReceiveVotePrefixResult before after source destination := by
  simp only [receiveVotePrefix] at run
  obtain ⟨unused, checked, guardRun, run⟩ := (bind_run _ _ _ _ _).mp run
  cases unused
  obtain ⟨signatureId, witnessed, freshRun, run⟩ := (bind_run _ _ _ _ _).mp run
  obtain ⟨unused, guarded, signatureRun, returned⟩ := (bind_run _ _ _ _ _).mp run
  cases unused
  have same : (signatureId, guarded) = (signature, after) := Except.ok.inj returned
  have sameId := congrArg Prod.fst same
  have sameAfter := congrArg Prod.snd same
  dsimp only at sameId sameAfter
  subst signature
  subst after
  obtain ⟨guardFrame, guardClauses⟩ := assert_all_success _ before checked guardRun
  obtain ⟨freshId, witnessNext, witnessBootstrap, witnessColumns, witnessClauses⟩ :=
    fresh_success checked witnessed signatureId freshRun
  obtain ⟨signatureFrame, signatureClauses⟩ :=
    assert_all_success _ witnessed guarded signatureRun
  have id : signatureId = before.next := freshId.trans guardFrame.next
  refine ⟨id, ?_⟩
  constructor
  · exact signatureFrame.bootstrap.trans (witnessBootstrap.trans guardFrame.bootstrap)
  · exact signatureFrame.columns.trans (witnessColumns.trans guardFrame.columns)
  · rw [signatureFrame.next, witnessNext, guardFrame.next]
  · rw [signatureClauses, witnessClauses, guardClauses, id]
    simp [receiveVotePrefixClauses, List.append_assoc]

theorem receive_vote_runs {width : PNat} (source destination : Fin width)
    (before after : Encoding width)
    (run : (receiveVote source destination).run before = .ok ((), after)) :
    exists signature : Nat, exists guarded : Encoding width,
      (receiveVotePrefix before.toColumns source destination).run before =
        .ok (signature, guarded) /\
      (receiveVoteTail before.toColumns source destination signature).run guarded =
        .ok ((), after) := by
  simp only [receiveVote, StateT.run, Bind.bind, StateT.bind, Except.bind] at run
  cases step : receiveVotePrefix before.toColumns source destination before with
  | error message =>
    rw [step] at run
    cases run
  | ok pair =>
    rcases pair with ⟨signature, guarded⟩
    rw [step] at run
    exact ⟨signature, guarded, step, run⟩

theorem ReceiveVotePrefixResult.references {width : PNat}
    {before guarded : Encoding width} {source destination : Fin width}
    (shape : ReceiveVotePrefixResult before guarded source destination)
    (valid : ReferencesValid before) : ReferencesValid guarded := by
  cases valid
  constructor <;> simp only [shape.columns, shape.next] <;> omega

theorem ReceiveVotePrefixResult.holds {width : PNat}
    {before guarded : Encoding width} {source destination : Fin width}
    (shape : ReceiveVotePrefixResult before guarded source destination)
    (assignment : Assignment) :
    Holds guarded.assertions.toList assignment <->
      Holds before.assertions.toList assignment /\
        Holds (voteReceiveGuards before.toColumns source destination) assignment /\
        (signatureIndexTerm width destination.val (.free .int before.next)).eval
          assignment Locals.empty = true := by
  rw [shape.clauses]
  simp [receiveVotePrefixClauses, Holds, or_imp, forall_and]

theorem receive_vote_references {width : PNat} (source destination : Fin width)
    (before after : Encoding width)
    (run : (receiveVote source destination).run before = .ok ((), after))
    (valid : ReferencesValid before) : ReferencesValid after := by
  obtain ⟨encodedSignature, guarded, prefixRun, writesRun⟩ :=
    receive_vote_runs source destination before after run
  obtain ⟨signatureId, shape⟩ :=
    receive_vote_prefix_success source destination before guarded encodedSignature prefixRun
  subst encodedSignature
  rw [receiveVoteTail] at writesRun
  exact vote_receive_writes_references source destination _ _ guarded after writesRun
    (shape.references valid)

theorem receive_vote_bootstrap {width : PNat} (source destination : Fin width)
    (before after : Encoding width)
    (run : (receiveVote source destination).run before = .ok ((), after)) :
    after.bootstrap = before.bootstrap := by
  obtain ⟨encodedSignature, guarded, prefixRun, writesRun⟩ :=
    receive_vote_runs source destination before after run
  obtain ⟨signatureId, shape⟩ :=
    receive_vote_prefix_success source destination before guarded encodedSignature prefixRun
  subst encodedSignature
  rw [receiveVoteTail] at writesRun
  obtain ⟨voted, popped, writesShape, popRun, pushRun⟩ :=
    vote_receive_writes_steps source destination _ _ guarded after writesRun
  exact (push_queue_success source destination _ popped after pushRun).bootstrap.trans
    ((pop_queue_success destination source voted popped popRun).bootstrap.trans
      (writesShape.bootstrap.trans shape.bootstrap))

theorem receive_vote_holds_before {width : PNat} (source destination : Fin width)
    (before after : Encoding width)
    (run : (receiveVote source destination).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment) :
    Holds before.assertions.toList assignment := by
  obtain ⟨encodedSignature, guarded, prefixRun, writesRun⟩ :=
    receive_vote_runs source destination before after run
  obtain ⟨signatureId, shape⟩ :=
    receive_vote_prefix_success source destination before guarded encodedSignature prefixRun
  subst encodedSignature
  rw [receiveVoteTail] at writesRun
  exact ((shape.holds assignment).mp
    (vote_receive_writes_holds_before source destination _ _ guarded after writesRun
      assignment holds)).1

theorem receive_vote_frame_success {width : PNat} (source destination : Fin width)
    (before after : Encoding width)
    (run : (receiveVote source destination).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment before.toColumns frame) :
    (frame.nodes destination).isSome = true /\
      exists request : RequestVoteRequest (Fin width), exists signature : Nat,
        (frame.queues destination source).peek = some (.requestVoteRequest request) /\
        request.source = source /\
        request.destination = destination /\
        request.term <= (NativeArrayCheckQuorum.get frame.nodes destination).currentTerm /\
        NativeArrayVote.SignatureIndex
          (NativeArrayCheckQuorum.get frame.nodes destination).log signature /\
        FrameColumnsRep assignment after.toColumns
          (NativeArrayVoteReceive.receive frame destination request signature) := by
  obtain ⟨encodedSignature, guarded, prefixRun, writesRun⟩ :=
    receive_vote_runs source destination before after run
  obtain ⟨signatureId, shape⟩ :=
    receive_vote_prefix_success source destination before guarded encodedSignature prefixRun
  subst encodedSignature
  rw [receiveVoteTail] at writesRun
  have guardedHolds :=
    vote_receive_writes_holds_before source destination _ _ guarded after writesRun assignment holds
  obtain ⟨_, guards, signatureConstraint⟩ := (shape.holds assignment).mp guardedHolds
  obtain ⟨present, request, selected, recipient, term⟩ :=
    (vote_receive_guards_correct assignment before.toColumns frame rep source destination).mp guards
  have sameColumns := shape.columns
  have guardedRep : FrameColumnsRep assignment guarded.toColumns frame := by
    simpa only [sameColumns] using rep
  obtain ⟨signature, sameSignature, latest⟩ :=
    (signature_index_term_witness assignment Locals.empty destination.val
      (NativeArrayCheckQuorum.get frame.nodes destination).log
      (NativeArrayCheckQuorum.get frame.nodes destination).commit
      (rep.nodes.configuration_log destination) (.free .int before.next)).mp signatureConstraint
  have nonempty : 0 < (frame.queues destination source).length := by
    by_contra empty
    have zero : (frame.queues destination source).length = 0 := by omega
    simp [NativeArrayQueue.Queue.peek, zero] at selected
  have samePacket := queue_head_packet_term_correct assignment before.toColumns frame rep
    source destination nonempty
  have head :
      (frame.queues destination source).cells (frame.queues destination source).head =
        .requestVoteRequest request := by
    simpa [NativeArrayQueue.Queue.peek, if_pos nonempty] using selected
  have sourceMatches := rep.queue_head_source source destination nonempty
  rw [head] at sourceMatches
  rw [head] at samePacket
  refine ⟨present, request, signature, selected, sourceMatches, recipient, term, latest, ?_⟩
  exact vote_receive_writes_frame_success source destination _ request _ signature guarded after
    writesRun assignment holds frame guardedRep present sourceMatches recipient samePacket sameSignature

theorem receive_vote_complete {width : PNat} (source destination : Fin width)
    (request : RequestVoteRequest (Fin width)) (signature : Nat)
    (before after : Encoding width)
    (run : (receiveVote source destination).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds before.assertions.toList assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment before.toColumns frame) (valid : ReferencesValid before)
    (present : (frame.nodes destination).isSome = true)
    (selected : (frame.queues destination source).peek = some (.requestVoteRequest request))
    (sameSource : request.source = source) (recipient : request.destination = destination)
    (term : request.term <= (NativeArrayCheckQuorum.get frame.nodes destination).currentTerm)
    (latest : NativeArrayVote.SignatureIndex
      (NativeArrayCheckQuorum.get frame.nodes destination).log signature) :
    exists extended : Assignment, assignment.AgreesBelow before.next extended /\
      Holds after.assertions.toList extended /\
      FrameColumnsRep extended after.toColumns
        (NativeArrayVoteReceive.receive frame destination request signature) := by
  obtain ⟨encodedSignature, guarded, prefixRun, writesRun⟩ :=
    receive_vote_runs source destination before after run
  obtain ⟨signatureId, shape⟩ :=
    receive_vote_prefix_success source destination before guarded encodedSignature prefixRun
  subst encodedSignature
  rw [receiveVoteTail] at writesRun
  let witnessAssignment := assignment.set .int before.next (signature : Int)
  have agreement : assignment.AgreesBelow before.next witnessAssignment :=
    assignment.agrees_below_set before.next .int before.next (signature : Int) (le_refl _)
  have witnessRep := rep.agrees_below before assignment witnessAssignment frame valid agreement
  have previousHolds := before.holds_agrees_below assignment witnessAssignment holds agreement
  have witnessGuards :=
    (vote_receive_guards_correct witnessAssignment before.toColumns frame witnessRep
      source destination).mpr ⟨present, request, selected, recipient, term⟩
  have sameSignature :
      (.free .int before.next : Expr .int).eval witnessAssignment Locals.empty = (signature : Int) := by
    simp [Term.eval, witnessAssignment, Assignment.set]
  have signatureConstraint :
      (signatureIndexTerm width destination.val (.free .int before.next)).eval
        witnessAssignment Locals.empty = true :=
    (signature_index_term_correct witnessAssignment Locals.empty destination.val
      (NativeArrayCheckQuorum.get frame.nodes destination).log
      (NativeArrayCheckQuorum.get frame.nodes destination).commit signature
      (witnessRep.nodes.configuration_log destination) (.free .int before.next)
      sameSignature).mpr latest
  have guardedHolds : Holds guarded.assertions.toList witnessAssignment :=
    (shape.holds witnessAssignment).mpr ⟨previousHolds, witnessGuards, signatureConstraint⟩
  have guardedValid : ReferencesValid guarded := shape.references valid
  have guardedRep : FrameColumnsRep witnessAssignment guarded.toColumns frame := by
    simpa only [shape.columns] using witnessRep
  have nonempty : 0 < (frame.queues destination source).length := by
    by_contra empty
    have zero : (frame.queues destination source).length = 0 := by omega
    simp [NativeArrayQueue.Queue.peek, zero] at selected
  have samePacket := queue_head_packet_term_correct witnessAssignment before.toColumns frame
    witnessRep source destination nonempty
  have head :
      (frame.queues destination source).cells (frame.queues destination source).head =
        .requestVoteRequest request := by
    simpa [NativeArrayQueue.Queue.peek, if_pos nonempty] using selected
  rw [head] at samePacket
  obtain ⟨extended, writeAgreement, finalHolds, finalRep⟩ :=
    vote_receive_writes_complete source destination _ request (.free .int before.next) signature
      guarded after writesRun witnessAssignment guardedHolds frame guardedRep guardedValid present
      sameSource recipient samePacket sameSignature
  refine ⟨extended, agreement.trans (writeAgreement.restrict ?_), finalHolds, finalRep⟩
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
