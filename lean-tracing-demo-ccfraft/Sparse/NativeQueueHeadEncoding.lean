-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeQueueHead
import Sparse.NativeFrameColumns

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem FrameColumnsRep.queue_head {width : PNat} {assignment : Assignment} {columns : Columns}
    {frame : NativeArrayVote.Frame (Fin width) Nat} (rep : FrameColumnsRep assignment columns frame)
    (source destination : Fin width) (nonempty : 0 < (frame.queues destination source).length) :
    (queueRow assignment columns destination source).cells (queueRow assignment columns destination source).head =
      (frame.queues destination source).cells (frame.queues destination source).head := by
  have rowNonempty : 0 < (queueRow assignment columns destination source).length := by
    simpa only [queueRow, modelQueue, rep.queue_length] using nonempty
  have samePeek : (queueRow assignment columns destination source).peek = (frame.queues destination source).peek := by
    rw [NativeArrayQueue.Queue.peek_correct, NativeArrayQueue.Queue.peek_correct, rep.queues]
  simpa only [NativeArrayQueue.Queue.peek, if_pos rowNonempty, if_pos nonempty, Option.some.injEq] using samePeek

theorem queue_head_packet_term_correct {width : PNat}
    (assignment : Assignment) (columns : Columns) (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment columns frame) (source destination : Fin width)
    (nonempty : 0 < (frame.queues destination source).length) :
    (queueHeadPacketTerm columns source destination : Expr (packetTy width)).eval assignment Locals.empty =
      packetValue ((frame.queues destination source).cells (frame.queues destination source).head) := by
  rw [queue_head_packet_term_eval, rep.queue_head source destination nonempty]

theorem FrameColumnsRep.queue_head_source {width : PNat} {assignment : Assignment} {columns : Columns}
    {frame : NativeArrayVote.Frame (Fin width) Nat} (rep : FrameColumnsRep assignment columns frame)
    (source destination : Fin width) (nonempty : 0 < (frame.queues destination source).length) :
    ((frame.queues destination source).cells (frame.queues destination source).head).source = source := by
  rw [<- rep.queue_head source destination nonempty]
  exact model_queue_packet_source source _

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
