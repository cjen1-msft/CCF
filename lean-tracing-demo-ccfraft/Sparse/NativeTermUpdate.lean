-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeTermGuard

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def updateTerm {width : PNat} (source destination : Fin width) : EncodeM width Unit := do
  let before <- get
  assertAll (termUpdateGuards before.toColumns source destination)
  let roleId <- define (stepDownRole before.role destination.val)
  let term : Expr .int := .fst (.fst (queueHeadPacketTerm before.toColumns source destination))
  let termId <- define (.store (.free (.array .int .int) before.currentTerm) (.integer destination.val) term)
  let followerId <- define (stepDownFollower before.newFollower destination.val)
  let votedId <- define (.store (.free (.array .int optionalIntTy) before.votedFor) (.integer destination.val) (.inl .unit))
  let preVotesId <- define (.store (.free (.array .int (.bits width)) before.preVotesGranted) (.integer destination.val) (.bits 0))
  modify fun state => { state with
    role := roleId, currentTerm := termId, newFollower := followerId,
    votedFor := votedId, preVotesGranted := preVotesId }

end CCFRaft.NativeEncode
