-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeTermGuard
import Sparse.NativeQueueHeadEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem term_update_guards_correct {width : PNat}
    (assignment : Assignment) (columns : Columns) (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment columns frame) (source destination : Fin width) :
    Holds (termUpdateGuards columns source destination) assignment <->
      (frame.nodes destination).isSome = true /\
        (NativeArrayVote.newerMessage? frame source destination).isSome = true := by
  by_cases nonempty : 0 < (frame.queues destination source).length
  · let packet := (frame.queues destination source).cells (frame.queues destination source).head
    have samePacket := queue_head_packet_term_correct assignment columns frame rep source destination nonempty
    have sameSource : packet.source = source := rep.queue_head_source source destination nonempty
    have allowed := packet_source_allowed_term_correct
      (queueHeadPacketTerm columns source destination) (allocated source.val)
      assignment Locals.empty frame.nodes packet samePacket
      (by simpa only [sameSource] using rep.nodes.allocated source)
    have lengthValue :
        (queueScalarTerm columns.queueLength (.integer destination.val) (.integer source.val) : Expr .int).eval
          assignment Locals.empty = ((frame.queues destination source).length : Int) := by
      rw [queue_scalar_correct]
      exact congrArg (fun value : Nat => (value : Int)) (rep.queue_length destination source)
    have guardMeaning :
        Holds (termUpdateGuards columns source destination) assignment <->
          (frame.nodes destination).isSome = true /\
            NativeArrayVote.sourceAllowed frame.nodes packet /\
              (NativeArrayCheckQuorum.get frame.nodes destination).currentTerm < packet.term := by
      simp [Holds, termUpdateGuards, lt, Term.eval, rep.nodes.allocated, rep.nodes.currentTerm,
        lengthValue, allowed, samePacket, packetValue, packetHeaderValue, Nat.ne_of_gt nonempty, packet]
    rw [guardMeaning]
    simp [NativeArrayVote.newerMessage?, NativeArrayQueue.Queue.peek, nonempty, packet]
  · have empty : (frame.queues destination source).length = 0 := by omega
    simp [Holds, termUpdateGuards, lt, Term.eval, queue_scalar_correct, rep.queue_length, empty,
      NativeArrayVote.newerMessage?, NativeArrayQueue.Queue.peek]

theorem term_update_guards_model_correct {width : PNat} [Bootstrap (Fin width)]
    (assignment : Assignment) (columns : Columns) (frame : NativeArrayVote.Frame (Fin width) Nat)
    (state : State (Fin width) Nat) (rep : FrameColumnsRep assignment columns frame)
    (model : frame.Rep state) (source destination : Fin width) :
    Holds (termUpdateGuards columns source destination) assignment <->
      Enabled state (.updateTerm source destination) := by
  rw [term_update_guards_correct assignment columns frame rep source destination]
  simp only [Enabled, NativeArrayCheckQuorum.allocated_rep frame.nodes state model.nodes,
    NativeArrayVote.newer_correct frame state model]

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
