-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativePacketPattern
import Sparse.NativePacketTerm

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def optionalPatternTerm {α : Type} {context : List Ty} {sort : Ty}
    (literal : α -> Term context sort) (expected : Option α)
    (actual : Term context sort) : Term context .bool :=
  match expected with
  | none => .boolean true
  | some value => .equal actual (literal value)

def packetHeaderPatternTerm {context : List Ty} {width : PNat}
    (expected : NativePacketPattern.Header (Fin width))
    (actual : Term context packetHeaderTy) : Term context .bool :=
  all [optionalPatternTerm (fun n => .integer n) expected.term (.fst actual),
    optionalPatternTerm (fun node => .integer node.val) expected.source (.fst (.snd actual)),
    optionalPatternTerm (fun node => .integer node.val) expected.destination (.snd (.snd actual))]

def packetPayloadPatternTerm {context : List Ty} {width : PNat}
    (expected : NativePacketPattern.Payload (Fin width) Nat)
    (actual : Term context (packetPayloadTy width)) : Term context .bool :=
  match expected with
  | .appendEntriesRequest previous previousTerm commit length entries =>
    .cases actual
      (all [
        optionalPatternTerm (fun n => .integer n) previous (.fst (.bound .here)),
        optionalPatternTerm (fun n => .integer n) previousTerm (.fst (.snd (.bound .here))),
        optionalPatternTerm (fun n => .integer n) commit (.fst (.snd (.snd (.bound .here)))),
        optionalPatternTerm (fun n => .integer n) length (.fst (.snd (.snd (.snd (.bound .here))))),
        optionalPatternTerm logTerm entries (.snd (.snd (.snd (.bound .here))))])
      (.boolean false)
  | .appendEntriesResponse success lastIndex =>
    .cases actual (.boolean false)
      (.cases (.bound .here)
        (.and (optionalPatternTerm Term.boolean success (.fst (.bound .here)))
          (optionalPatternTerm (fun n => .integer n) lastIndex (.snd (.bound .here))))
        (.boolean false))
  | .requestVoteRequest lastTerm lastIndex =>
    .cases actual (.boolean false)
      (.cases (.bound .here) (.boolean false)
        (.cases (.bound .here)
          (.and (optionalPatternTerm (fun n => .integer n) lastTerm (.fst (.bound .here)))
            (optionalPatternTerm (fun n => .integer n) lastIndex (.snd (.bound .here))))
          (.boolean false)))
  | .requestVoteResponse granted =>
    .cases actual (.boolean false)
      (.cases (.bound .here) (.boolean false)
        (.cases (.bound .here) (.boolean false)
          (.cases (.bound .here)
            (optionalPatternTerm Term.boolean granted (.bound .here))
            (.boolean false))))
  | .requestPreVote lastTerm lastIndex =>
    .cases actual (.boolean false)
      (.cases (.bound .here) (.boolean false)
        (.cases (.bound .here) (.boolean false)
          (.cases (.bound .here) (.boolean false)
            (.cases (.bound .here)
              (.and (optionalPatternTerm (fun n => .integer n) lastTerm (.fst (.bound .here)))
                (optionalPatternTerm (fun n => .integer n) lastIndex (.snd (.bound .here))))
              (.boolean false)))))
  | .requestPreVoteResponse granted =>
    .cases actual (.boolean false)
      (.cases (.bound .here) (.boolean false)
        (.cases (.bound .here) (.boolean false)
          (.cases (.bound .here) (.boolean false)
            (.cases (.bound .here) (.boolean false)
              (.cases (.bound .here)
                (optionalPatternTerm Term.boolean granted (.bound .here))
                (.boolean false))))))
  | .proposeVoteRequest =>
    .cases actual (.boolean false)
      (.cases (.bound .here) (.boolean false)
        (.cases (.bound .here) (.boolean false)
          (.cases (.bound .here) (.boolean false)
            (.cases (.bound .here) (.boolean false)
              (.cases (.bound .here) (.boolean false) (.boolean true))))))

def packetPatternTerm {context : List Ty} {width : PNat}
    (expected : NativePacketPattern.Pattern (Fin width) Nat)
    (actual : Term context (packetTy width)) : Term context .bool :=
  .and (packetHeaderPatternTerm expected.header (.fst actual))
    (packetPayloadPatternTerm expected.payload (.snd actual))

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
