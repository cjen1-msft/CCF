-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeAppendReceive

set_option autoImplicit false

namespace CCFRaft.BranchPrototype

open NativeEncode NativeSmt

inductive ReceivePath where
  | rejectBeyondEnd
  | appendAtEnd
  deriving BEq

structure ReceivePlan where
  path : ReceivePath
  term : Nat
  previous : Nat
  oldLength : Nat
  entriesLength : Nat
  leaderCommit : Nat
  dependencies : List Nat

private def prepareReceive {width : PNat} (source destination : Fin width)
    (plan : ReceivePlan) : EncodeM width (NodeRowTerms width × Expr (appendPayloadTy width)) := do
  let state <- get
  let columns := state.toColumns
  let old := nodeRowSnapshot columns destination
  let packetId <- define (queueHeadPacketTerm columns source destination)
  let packet : Expr (packetTy width) := .free _ packetId
  let payloadId <- define (appendRequestPayloadTerm packet)
  let payload : Expr (appendPayloadTy width) := .free _ payloadId
  assertAll [
    allocated columns destination.val,
    .le (.integer 1) (queueScalarTerm columns.queueLength
      (.integer destination.val) (.integer source.val)),
    isAppendRequestTerm packet,
    .equal packet.fst.snd.snd (.integer destination.val),
    .equal packet.fst.fst (.integer plan.term),
    .equal old.currentTerm (.integer plan.term),
    .equal old.role (.integer (roleCode .follower)),
    .equal old.logLength (.integer plan.oldLength),
    .equal payload.fst (.integer plan.previous),
    .equal payload.snd.snd.fst (.integer plan.leaderCommit),
    .equal payload.snd.snd.snd.fst (.integer plan.entriesLength)]
  match plan.path with
  | .rejectBeyondEnd =>
    unless plan.oldLength < plan.previous do
      throw "prototype rejection requires previous beyond the local log"
  | .appendAtEnd =>
    unless plan.previous == plan.oldLength && plan.entriesLength == 1 do
      throw "prototype extension requires one entry at the local end"
    assertion (.le old.commit (.integer plan.previous))
    if plan.previous != 0 then
      assertion (.equal
        (.fst (normalizedEntryTerm (.select old.logEntries (.integer (plan.previous - 1)))))
        payload.snd.fst)
  return (old, payload)

def guardedReceive {width : PNat} (source destination : Fin width)
    (plan : ReceivePlan) : EncodeM width Unit := do
  let _ <- prepareReceive source destination plan
  receiveAppend source destination

def specialisedReceive {width : PNat} (source destination : Fin width)
    (plan : ReceivePlan) : EncodeM width Unit := do
  let (old, payload) <- prepareReceive source destination plan
  let (logLength, logEntries, committed, response) <-
    match plan.path with
    | .rejectBeyondEnd =>
      pure (.integer plan.oldLength, old.logEntries, old.commit,
        appendResponseTerm width destination source (.integer plan.term)
          (.boolean false) (.integer plan.oldLength))
    | .appendAtEnd => do
      let spliced <- fresh
      let logEntries : Expr (.array .int (entryTy width)) := .free _ spliced
      let logLength : Expr .int := .integer (plan.previous + 1)
      assertion (logSpliceTerm width (.integer plan.oldLength) old.logEntries
        (.integer 1) payload.snd.snd.snd.snd (.integer plan.previous) logEntries)
      let signature <- fresh
      assertion (boundedSignatureTerm width logLength logEntries
        (.integer (min plan.leaderCommit (plan.previous + 1))) (.free .int signature))
      let committed <- define (intMaxTerm old.commit (.free .int signature))
      pure (logLength, logEntries, .free .int committed,
        appendResponseTerm width destination source (.integer plan.term)
          (.boolean true) (.integer (plan.previous + 1)))
  let before <- get
  let first <- fresh
  let retirement <- fresh
  let signature <- fresh
  let retired <- fresh
  assertion (retirementRefreshConstraints width before.bootstrap logLength logEntries destination
    (.free .int first) (.free .int retirement) (.free .int signature) (.free .int retired))
  let current <- fresh
  assertion (currentConfigurationIndexTerm width logLength logEntries committed (.free .int current))
  let completed <- retirementCompletedConstraints before.bootstrap (.boolean true)
    logLength logEntries committed (.free .int current)
  let candidate := { old with logLength, logEntries, commit := committed }
  let values := appendReceiveFinalRowTerms candidate (.boolean false)
    (.free .int retirement) (.free .int signature) (.free .int retired)
  appendReceiveWrites source destination (.boolean false) values response
    (.free (.bits width) completed)

end CCFRaft.BranchPrototype
