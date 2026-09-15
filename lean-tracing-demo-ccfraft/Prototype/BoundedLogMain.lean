-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeParameterizedFrame

set_option autoImplicit false

namespace CCFRaft.BoundedLogPrototype

open Lean NativeEncode NativeSmt

def finiteSplice (width : PNat) (bound : Nat)
    (oldLength : Expr .int) (oldEntries : Expr (.array .int (entryTy width)))
    (payloadLength : Expr .int) (payloadEntries : Expr (.array .int (entryTy width)))
    (previous : Expr .int) (output : Expr (.array .int (entryTy width))) : Expr .bool :=
  let keep := logSpliceKeep oldLength previous
  let resultLength := logSpliceLength oldLength payloadLength previous
  all ((List.range bound).map fun index =>
    let position : Expr .int := .integer index
    implies (lt position resultLength)
      (.equal (.select output position)
        (.ite (lt position keep) (.select oldEntries position)
          (.select payloadEntries (.sub position keep)))))

def receiveBounded {width : PNat} (bound : Nat) (finite : Bool)
    (source destination : Fin width) : EncodeM width Unit := do
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
  let relation := if finite then
    finiteSplice width bound old.logLength old.logEntries entries.fst entries.snd previous
      (.free (.array .int (entryTy width)) spliced)
    else logSpliceTerm width old.logLength old.logEntries entries.fst entries.snd previous
      (.free (.array .int (entryTy width)) spliced)
  assertion (implies grows
    (.and (.le (logSpliceLength old.logLength entries.fst previous) (.integer bound)) relation))
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

def boundLengths {width : PNat} (bound : Nat) : EncodeM width Unit := do
  let state <- get
  assertAll ((List.range width.val).map fun node =>
    .le (length state.toColumns node) (.integer bound))

def emit {width : PNat} {count : Nat} (base bound : Nat) (finite : Bool)
    (item : ParameterizedFrameInstruction width count) : EncodeM width Unit := do
  match item with
  | .core (.receiveAppend source destination) => receiveBounded bound finite source destination
  | item => parameterizedFrameInstruction base item
  boundLengths bound

def encodeDetails (bound : Nat) (finite : Bool) (document : Json) : Except String Json := do
  let input <- decodeParameterizedFrameDocument document
  let (_, initial) <- (initialFrameDomains input.frame.width).run
    (initialEncoding input.frame.width input.frame.bootstrap)
  let (_, parameters) <- (declareNatParameters input.unknowns.size).run initial
  let (_, started) <- (boundLengths bound).run parameters
  let groups := #[{ instruction := none, start := 0, stop := started.assertions.size : Group }]
  let (groups, final) <- (compileInstructionsWith (emit initial.next bound finite) 0 groups
    input.frame.instructions.toList).run started
  return compiledDetails document { assertions := final.assertions, groups }

end CCFRaft.BoundedLogPrototype

def main (arguments : List String) : IO UInt32 := do
  let text <- (← IO.getStdin).readToEnd
  let result := do
    let document <- Lean.Json.parse text
    match arguments with
    | ["--batch", mode, limit] => do
      unless mode == "relational" || mode == "finite" do throw "invalid bounded mode"
      let some bound := limit.toNat? | throw "expected natural log bound"
      let outputs <- (← document.getArr?).mapM
        (CCFRaft.BoundedLogPrototype.encodeDetails bound (mode == "finite"))
      return Lean.toJson outputs
    | _ => throw "usage: --batch relational|finite BOUND"
  match result with
  | .ok output => IO.println output.compress; return 0
  | .error error => (← IO.getStderr).putStrLn error; return 2
