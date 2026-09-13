-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativePacketPatternTerm
import Sparse.NativeQueueHead
import Sparse.NativeNodeRowWrites
import Sparse.NativeQueuePop

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def voteResponseGrantedTerm {context : List Ty} {width : PNat}
    (packet : Term context (packetTy width)) : Term context .bool :=
  .cases (.snd packet) (.boolean false)
    (.cases (.bound .here) (.boolean false)
      (.cases (.bound .here) (.boolean false)
        (.cases (.bound .here) (.bound .here)
          (.cases (.bound .here) (.boolean false)
            (.cases (.bound .here) (.bound .here) (.boolean false))))))

def voteResponseGuards {width : PNat} (columns : Columns) (preVote : Bool)
    (source destination : Fin width) : List (Expr .bool) :=
  let packet := queueHeadPacketTerm columns source destination
  let row := nodeRowSnapshot columns destination
  let kind : NativePacketPattern.Payload (Fin width) Nat :=
    if preVote then .requestPreVoteResponse none else .requestVoteResponse none
  [allocated columns destination.val,
    lt (.integer 0) (queueScalarTerm columns.queueLength (.integer destination.val) (.integer source.val)),
    packetPayloadPatternTerm kind (.snd packet),
    .equal (.snd (.snd (.fst packet))) (.integer destination.val),
    implies (allocated columns source.val)
      (.or (.le (.fst (.fst packet)) row.currentTerm)
        (.not (.equal row.role (.integer (roleCode (if preVote then .preVoteCandidate else .candidate))))))]

def voteResponseRowTerms {width : PNat} (columns : Columns) (preVote : Bool)
    (source destination : Fin width) : NodeRowTerms width :=
  let packet := queueHeadPacketTerm columns source destination
  let row := nodeRowSnapshot columns destination
  let granted := all [allocated columns source.val,
    .equal (.fst (.fst packet)) row.currentTerm,
    .equal row.role (.integer (roleCode (if preVote then .preVoteCandidate else .candidate))),
    voteResponseGrantedTerm packet]
  let votes := if preVote then row.preVotesGranted else row.votesGranted
  let updated : Expr (.bits width) :=
    .ite granted (.bitsOr votes (.bits (encodeBits {source}))) votes
  if preVote then { row with preVotesGranted := updated }
  else { row with votesGranted := updated }

def receiveVoteResponse {width : PNat} (preVote : Bool)
    (source destination : Fin width) : EncodeM width Unit := do
  let before <- get
  assertAll (voteResponseGuards before.toColumns preVote source destination)
  writeNodeRow destination (voteResponseRowTerms before.toColumns preVote source destination)
  popQueue destination source

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
