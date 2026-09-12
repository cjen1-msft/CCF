-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeCampaignGuard
import Sparse.NativeDefinitions

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def campaignTerm (columns : Columns) (preVote : Bool) (node : Nat) : Expr .int :=
  .add (read columns columns.currentTerm node (.integer 0)) (.integer (if preVote then 0 else 1))

def campaignVotedFor (columns : Columns) (preVote : Bool) (node : Nat) : Expr optionalIntTy :=
  if preVote then read columns columns.votedFor node (.inl .unit) else .inr (.integer node)

def campaignVotesGranted {width : PNat} (columns : Columns) (preVote : Bool)
    (node : Fin width) : Expr (.bits width) :=
  if preVote then read columns columns.votesGranted node.val (.bits 0) else .bits (encodeBits {node})

def campaignPreVotesGranted {width : PNat} (preVote : Bool) (node : Fin width) : Expr (.bits width) :=
  .bits (if preVote then encodeBits {node} else 0)

def campaignWriteDefinitions {width : PNat} (before : Columns) (preVote : Bool)
    (node : Fin width) : List TypedDefinition :=
  [⟨.array .int .int, .store (.free (.array .int .int) before.role) (.integer node.val)
      (.integer (roleCode (if preVote then .preVoteCandidate else .candidate)))⟩,
    ⟨.array .int .int, .store (.free (.array .int .int) before.currentTerm) (.integer node.val)
      (campaignTerm before preVote node.val)⟩,
    ⟨.array .int optionalIntTy,
      .store (.free (.array .int optionalIntTy) before.votedFor) (.integer node.val)
        (campaignVotedFor before preVote node.val)⟩,
    ⟨.array .int (.bits width),
      .store (.free (.array .int (.bits width)) before.votesGranted) (.integer node.val)
        (campaignVotesGranted before preVote node)⟩,
    ⟨.array .int (.bits width),
      .store (.free (.array .int (.bits width)) before.preVotesGranted) (.integer node.val)
        (campaignPreVotesGranted preVote node)⟩]

def campaignWrites {width : PNat} (preVote : Bool) (node : Fin width) : EncodeM width Unit := do
  let before <- get
  match <- definitions (campaignWriteDefinitions before.toColumns preVote node) with
  | [roleId, termId, votedId, votesId, preVotesId] =>
    modify fun state => { state with
      role := roleId, currentTerm := termId, votedFor := votedId,
      votesGranted := votesId, preVotesGranted := preVotesId }
  | _ => throw "internal encoder error: campaign definition count changed"

def campaignGuard {width : PNat} (columns : Columns) (bootstrap : BitVec width)
    (preVote : Bool) (node : Fin width) : EncodeM width Unit := do
  let base <- fresh
  let _ <- fresh
  let _ <- fresh
  assertAll (campaignGuards columns bootstrap preVote node base)

def campaign {width : PNat} (preVote : Bool) (node : Fin width) : EncodeM width Unit :=
  fun before =>
    (campaignGuard before.toColumns before.bootstrap preVote node >>= fun _ =>
      campaignWrites preVote node).run before

end CCFRaft.NativeEncode
