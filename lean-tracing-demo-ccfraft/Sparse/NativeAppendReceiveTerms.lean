-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeLogRangeEncoding
import Sparse.NativeQueueHead

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def isAppendRequestTerm {context : List Ty} {width : PNat}
    (packet : Term context (packetTy width)) : Term context .bool :=
  .cases (.snd packet) (.boolean true) (.boolean false)

def appendRequestPayloadTerm {context : List Ty} {width : PNat}
    (packet : Term context (packetTy width)) : Term context (appendPayloadTy width) :=
  .cases (.snd packet) (.bound .here) (.defaultValue _)

structure AppendReceiveTerms where
  stepDown : Expr .bool
  rejects : Expr .bool
  acceptable : Expr .bool
  alreadyDone : Expr .bool
  extendsLog : Expr .bool
  conflict : Expr .bool
  handles : Expr .bool

def appendReceiveTerms {width : PNat} (columns : Columns) (destination : Fin width)
    (packet : Expr (packetTy width)) : AppendReceiveTerms :=
  let payload := appendRequestPayloadTerm packet
  let previous := payload.fst
  let previousTerm := payload.snd.fst
  let entries := payload.snd.snd.snd
  let oldLength : Expr .int := length columns destination.val
  let oldEntries : Expr (.array .int (entryTy width)) :=
    .select (.free (.array .int (.array .int (entryTy width))) columns.logEntries)
      (.integer destination.val)
  let currentTerm : Expr .int := read columns columns.currentTerm destination.val (.integer 0)
  let role : Expr .int := read columns columns.role destination.val (.integer 0)
  let sameTerm : Expr .bool := .equal packet.fst.fst currentTerm
  let follower : Expr .bool := .equal role (.integer (roleCode .follower))
  let logOk : Expr .bool := .or (.equal previous (.integer 0))
    (.and (.le previous oldLength)
      (.equal (.fst (normalizedEntryTerm (.select oldEntries (.sub previous (.integer 1))))) previousTerm))
  let stepDown := .and sameTerm
    (.or (.equal role (.integer (roleCode .candidate))) (.equal role (.integer (roleCode .preVoteCandidate))))
  let rejects := .or (lt packet.fst.fst currentTerm) (all [sameTerm, follower, .not logOk])
  let acceptable := all [sameTerm, follower, logOk, .le (commit columns destination.val) previous]
  let alreadyDone := appendAlreadyDoneTerm width oldLength oldEntries entries.fst entries.snd previous
  let extendsLog := appendNoConflictExtensionTerm width oldLength oldEntries entries.fst entries.snd previous
  let conflict := appendTermConflictTerm width oldLength oldEntries entries.fst entries.snd previous
  let handles := .or rejects (.and acceptable
    (.or alreadyDone (.or extendsLog
      (.and conflict (read columns columns.newFollower destination.val (.boolean true))))))
  { stepDown, rejects, acceptable, alreadyDone, extendsLog, conflict, handles }

def appendReceiveGuards {width : PNat} (columns : Columns) (source destination : Fin width) :
    List (Expr .bool) :=
  let packet := queueHeadPacketTerm columns source destination
  let terms := appendReceiveTerms columns destination packet
  [allocated columns destination.val,
    .le (.integer 1) (queueScalarTerm columns.queueLength (.integer destination.val) (.integer source.val)),
    isAppendRequestTerm packet,
    .equal packet.fst.snd.snd (.integer destination.val),
    .or terms.stepDown terms.handles]

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
