-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeParameterizedFrame

set_option autoImplicit false

namespace CCFRaft.StorePrototype

open Lean NativeEncode NativeSmt

-- Experimental representation only; no new correctness theorem is claimed.
def receiveStore {width : PNat} (source destination : Fin width) : EncodeM width Unit := do
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
  let direct := .and (.equal previous old.logLength) (.equal entries.fst (.integer 1))
  assertion (implies (.and grows (.not direct))
    (logSpliceTerm width old.logLength old.logEntries entries.fst entries.snd previous
      (.free (.array .int (entryTy width)) spliced)))
  let lengthId <- define (.ite grows (logSpliceLength old.logLength entries.fst previous) old.logLength)
  let logLength : Expr .int := .free .int lengthId
  let stored := .store old.logEntries previous (.select entries.snd (.integer 0))
  let entriesId <- define
    (.ite grows (.ite direct stored (.free (.array .int (entryTy width)) spliced)) old.logEntries)
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

def emit {width : PNat} {count : Nat} (base : Nat) :
    ParameterizedFrameInstruction width count -> EncodeM width Unit
  | .core (.receiveAppend source destination) => receiveStore source destination
  | item => parameterizedFrameInstruction base item

def encodeDetails (document : Json) : Except String Json := do
  let input <- decodeParameterizedFrameDocument document
  let (_, initial) <- (initialFrameDomains input.frame.width).run
    (initialEncoding input.frame.width input.frame.bootstrap)
  let (_, started) <- (declareNatParameters input.unknowns.size).run initial
  let groups := #[{ instruction := none, start := 0, stop := started.assertions.size : Group }]
  let (groups, final) <- (compileInstructionsWith (emit initial.next) 0 groups
    input.frame.instructions.toList).run started
  return compiledDetails document { assertions := final.assertions, groups }

end CCFRaft.StorePrototype

def main (arguments : List String) : IO UInt32 := do
  let text <- (← IO.getStdin).readToEnd
  let result := do
    let document <- Lean.Json.parse text
    if arguments == ["--batch"] then
      let outputs <- (← document.getArr?).mapM CCFRaft.StorePrototype.encodeDetails
      return Lean.toJson outputs
    else
      CCFRaft.StorePrototype.encodeDetails document
  match result with
  | .ok result => IO.println result.compress; return 0
  | .error error => (← IO.getStderr).putStrLn error; return 2
