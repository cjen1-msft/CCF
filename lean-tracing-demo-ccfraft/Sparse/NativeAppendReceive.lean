-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeAppendReceiveCandidateTerms
import Sparse.NativeAppendReceiveFinalRowTerms
import Sparse.NativeAppendReceiveWrites
import Sparse.NativeAppendReceiveResponse
import Sparse.NativeLogSpliceEncoding
import Sparse.NativeLogSummaryTerms
import Sparse.NativeRetirementRefreshConstraints
import Sparse.NativeRetirementCompletedConstraints

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def receiveAppend {width : PNat} (source destination : Fin width) : EncodeM width Unit := do
  let before <- get
  let columns := before.toColumns
  assertAll (appendReceiveGuards columns source destination)
  let packetId <- define (queueHeadPacketTerm columns source destination)
  let packet : Expr (packetTy width) := .free _ packetId
  let branches := appendReceiveTerms columns destination packet
  let payload := appendRequestPayloadTerm packet
  let previous := payload.fst
  let previousTerm := payload.snd.fst
  let leaderCommit := payload.snd.snd.fst
  let entries := payload.snd.snd.snd
  let old := nodeRowSnapshot columns destination
  let spliced <- fresh
  let growsId <- define (.and branches.acceptable (.not branches.alreadyDone))
  let grows : Expr .bool := .free .bool growsId
  assertion (implies grows
    (logSpliceTerm width old.logLength old.logEntries entries.fst entries.snd previous
      (.free (.array .int (entryTy width)) spliced)))
  let lengthId <- define (.ite grows (logSpliceLength old.logLength entries.fst previous) old.logLength)
  let logLength : Expr .int := .free .int lengthId
  let entriesId <- define (.ite grows (.free (.array .int (entryTy width)) spliced) old.logEntries)
  let logEntries : Expr (.array .int (entryTy width)) := .free _ entriesId
  let commitSignature <- fresh
  assertion (implies branches.acceptable
    (boundedSignatureTerm width logLength logEntries
      (logRangeMinTerm leaderCommit (.add previous entries.fst)) (.free .int commitSignature)))
  let commitId <- define
    (.ite branches.acceptable (intMaxTerm old.commit (.free .int commitSignature)) old.commit)
  let commit : Expr .int := .free .int commitId
  let first <- fresh
  let retirement <- fresh
  let signature <- fresh
  let retired <- fresh
  let consumes : Expr .bool := .not branches.stepDown
  assertion (implies consumes
    (retirementRefreshConstraints width before.bootstrap logLength logEntries destination
      (.free .int first) (.free .int retirement) (.free .int signature) (.free .int retired)))
  let current <- fresh
  assertion (implies consumes
    (currentConfigurationIndexTerm width logLength logEntries commit (.free .int current)))
  let completed <- retirementCompletedConstraints before.bootstrap consumes
    logLength logEntries commit (.free .int current)
  let best <- fresh
  let hint := appendReceiveNackHint columns destination packet
  assertion (implies (.and branches.rejects hint)
    (nackMatchTerm width old.logLength old.logEntries previous previousTerm (.free .int best)))
  let candidate := appendReceiveCandidateRowTerms columns destination packet grows
    logLength logEntries commit
  let values := appendReceiveFinalRowTerms candidate branches.stepDown
    (.free .int retirement) (.free .int signature) (.free .int retired)
  appendReceiveWrites source destination branches.stepDown values
    (appendReceiveResponseTerm columns source destination packet (.free .int best))
    (.free (.bits width) completed)

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
