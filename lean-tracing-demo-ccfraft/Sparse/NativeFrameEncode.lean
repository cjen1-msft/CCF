-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeEncode
import Sparse.NativeFrameInitial
import Sparse.NativeArrayVote
import Sparse.NativeNatSet
import Sparse.NativeQueueColumns
import Sparse.NativePacketJson
import Sparse.NativeVoteSend
import Sparse.NativeTermUpdate
import Sparse.NativeCampaign
import Sparse.NativeAppendSend

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open Lean NativeSmt

abbrev FrameInstruction (width : PNat) := NativeArrayVote.Instruction (Fin width) Nat
abbrev FrameDecoded := TypedDocument FrameInstruction

def decodeFrameInstruction (width : PNat) (names : Array String) (value : Json) :
    Except String (FrameInstruction width) := do
  let kind <- (<- field value "kind").getStr?
  if kind = "requestVote" || kind = "requestPreVote" then
    fields value ["kind", "source", "destination"]
    return .vote (kind = "requestPreVote")
      (<- resolve width names (<- field value "source"))
      (<- resolve width names (<- field value "destination"))
  else if kind = "timeout" || kind = "becomePreVoteCandidate" then
    fields value ["kind", "node"]
    return .campaign (kind = "becomePreVoteCandidate") (<- resolve width names (<- field value "node"))
  else if kind = "updateTerm" then
    fields value ["kind", "source", "destination"]
    return .updateTerm (<- resolve width names (<- field value "source"))
      (<- resolve width names (<- field value "destination"))
  else if kind = "appendEntries" then
    fields value ["kind", "source", "destination", "batchEnd"]
    return .appendEntries (<- resolve width names (<- field value "source"))
      (<- resolve width names (<- field value "destination"))
      (<- natural (<- field value "batchEnd"))
  else if kind = "hasJoined" then
    fields value ["kind", "value"]
    return .hasJoined (<- decodeNodeSet width names (<- field value "value"))
  else if kind = "queueLength" then
    fields value ["kind", "source", "destination", "value"]
    return .queueLength (<- resolve width names (<- field value "source"))
      (<- resolve width names (<- field value "destination"))
      (<- natural (<- field value "value"))
  else if kind = "queuePoint" then
    fields value ["kind", "source", "destination", "index", "value"]
    return .queuePoint (<- resolve width names (<- field value "source"))
      (<- resolve width names (<- field value "destination"))
      (<- natural (<- field value "index")) (<- decodePacket width names (<- field value "value"))
  else if kind = "submittedTxId" then
    fields value ["kind", "txId", "value"]
    return .submittedTxId (<- natural (<- field value "txId"))
      (<- (<- field value "value").getBool?)
  else if kind = "retirementCompleted" then
    fields value ["kind", "node", "value"]
    return .retirementCompleted (<- resolve width names (<- field value "node"))
      (<- decodeNodeSet width names (<- field value "value"))
  else if kind = "preVoteStatus" then
    fields value ["kind", "node", "value"]
    let node <- resolve width names (<- field value "node")
    let expected <- (<- field value "value").getStr?
    let status <- match expected with
      | "capable" => pure PreVoteStatus.capable
      | "enabled" => pure .enabled
      | _ => throw s!"unknown pre-vote status {expected}"
    return .preVoteStatus node status
  else
    return .node (<- decodeInstruction width names value)

def decodeFrameDocument (document : Json) : Except String FrameDecoded :=
  decodeDocumentWith decodeFrameInstruction document

def frameObservationClauses {width : PNat} (columns : Columns) :
    FrameInstruction width -> Except String (List (Expr .bool))
  | .node item => observationClauses columns item
  | .hasJoined expected =>
    .ok [.equal (.free (.bits width) columns.hasJoined) (.bits (encodeBits expected))]
  | .preVoteStatus node expected =>
    .ok [.equal (.select (.free (.array .int .bool) columns.preVoteStatus) (.integer node.val))
      (.boolean (preVoteBit expected))]
  | .retirementCompleted node expected =>
    .ok [.equal (.select (.free (.array .int (.bits width)) columns.retirementCompleted) (.integer node.val))
      (.bits (encodeBits expected))]
  | .submittedTxId txId expected =>
    .ok [.equal (natSetMember columns.submittedTxIds columns.submittedTxLimit (.integer txId)) (.boolean expected)]
  | .queueLength source destination expected =>
    .ok [.equal (queueScalarTerm columns.queueLength (.integer destination.val) (.integer source.val))
      (.integer expected)]
  | .queuePoint source destination index expected =>
    .ok [queuePoint source
      (queueScalarTerm columns.queueHead (.integer destination.val) (.integer source.val))
      (queueScalarTerm columns.queueLength (.integer destination.val) (.integer source.val))
      (queueCellsTerm columns.queueCells (.integer destination.val) (.integer source.val)) index expected]
  | _ => .error "unsupported native Lean frame observation"

def frameInstruction {width : PNat} (item : FrameInstruction width) : EncodeM width Unit :=
  match item with
  | .node nodeInstruction => instruction nodeInstruction
  | .vote preVote source destination => sendVote preVote source destination
  | .updateTerm source destination => updateTerm source destination
  | .campaign preVote node => campaign preVote node
  | .appendEntries source destination batchEnd => sendAppend source destination batchEnd
  | _ => do
    let state <- get
    assertAll (<- frameObservationClauses state.toColumns item)

def compileFrameDecoded (input : FrameDecoded) : Except String Compiled := do
  let (_, start) <- (initialFrameDomains input.width).run (initialEncoding input.width input.bootstrap)
  let groups := #[{ instruction := none, start := 0, stop := start.assertions.size : Group }]
  let (groups, final) <-
    (compileInstructionsWith frameInstruction 0 groups input.instructions.toList).run start
  return { assertions := final.assertions, groups }

def compileFrame (document : Json) : Except String Compiled := do
  compileFrameDecoded (<- decodeFrameDocument document)

def encodeFrame (document : Json) : Except String String := do
  return renderScript (<- compileFrame document).assertions.toList

def encodeFrameDetails (document : Json) : Except String Json := do
  return compiledDetails document (<- compileFrame document)

end CCFRaft.NativeEncode
