-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativePacketPatternTerm
import Sparse.NativeQueueHead
import Sparse.NativeNodeRowWrites
import Sparse.NativeQueuePop
import Sparse.NativeLogSummaryTerms
import Sparse.NativeIntegerTerms

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def appendResponsePayloadTerm {context : List Ty} {width : PNat}
    (packet : Term context (packetTy width)) : Term context (.pair .bool .int) :=
  .cases (.snd packet) (.pair (.boolean false) (.integer 0))
    (.cases (.bound .here) (.bound .here) (.pair (.boolean false) (.integer 0)))

def appendResponseGuards {width : PNat} (columns : Columns)
    (source destination : Fin width) : List (Expr .bool) :=
  let packet := queueHeadPacketTerm columns source destination
  let row := nodeRowSnapshot columns destination
  let payload := appendResponsePayloadTerm packet
  [allocated columns destination.val,
    lt (.integer 0) (queueScalarTerm columns.queueLength (.integer destination.val) (.integer source.val)),
    packetPayloadPatternTerm (.appendEntriesResponse none none) (.snd packet),
    .equal (.snd (.snd (.fst packet))) (.integer destination.val),
    implies (allocated columns source.val)
      (.or (.not payload.fst)
        (.or (.le (.fst (.fst packet)) row.currentTerm)
          (.not (.equal row.role (.integer (roleCode .leader))))))]

def appendResponseRowTerms {width : PNat} (columns : Columns)
    (source destination : Fin width) (possible : Expr .int) : NodeRowTerms width :=
  let packet := queueHeadPacketTerm columns source destination
  let payload := appendResponsePayloadTerm packet
  let row := nodeRowSnapshot columns destination
  let peer : Expr .int := .integer source.val
  let acknowledges := all [allocated columns source.val, payload.fst,
    .equal (.fst (.fst packet)) row.currentTerm,
    .equal row.role (.integer (roleCode .leader))]
  let rejects := .and (allocated columns source.val) (.not payload.fst)
  let matched := .select row.matchIndex peer
  let sent := .select row.sentIndex peer
  { row with
    sentIndex := .ite rejects
      (.store row.sentIndex peer (intMaxTerm (logRangeMinTerm possible sent) matched))
      row.sentIndex
    matchIndex := .ite acknowledges
      (.store row.matchIndex peer (intMaxTerm matched payload.snd)) row.matchIndex }

def receiveAppendResponse {width : PNat}
    (source destination : Fin width) : EncodeM width Unit := do
  let before <- get
  let columns := before.toColumns
  assertAll (appendResponseGuards columns source destination)
  let row := nodeRowSnapshot columns destination
  let packet := queueHeadPacketTerm columns source destination
  let possible <- fresh
  assertion (nackMatchTerm width row.logLength row.logEntries
    (appendResponsePayloadTerm packet).snd (.fst (.fst packet)) (.free .int possible))
  writeNodeRow destination (appendResponseRowTerms columns source destination (.free .int possible))
  popQueue destination source

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
