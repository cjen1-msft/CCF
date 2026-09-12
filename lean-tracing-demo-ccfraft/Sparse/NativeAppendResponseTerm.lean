-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativePacketTerm

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def appendResponseTerm {context : List Ty} (width : PNat)
    (source destination : Fin width)
    (term : Term context .int) (success : Term context .bool)
    (lastLogIndex : Term context .int) : Term context (packetTy width) :=
  .pair
    (.pair term (.pair (.integer source.val) (.integer destination.val)))
    (.inr (.inl (.pair success lastLogIndex)))

theorem append_response_term_eval {context : List Ty} {width : PNat}
    (assignment : Assignment) (locals : Locals context)
    (source destination : Fin width)
    (term : Term context .int) (success : Term context .bool)
    (lastLogIndex : Term context .int)
    (responseTermNat lastNat : Nat) (successBool : Bool)
    (sameTerm : term.eval assignment locals = (responseTermNat : Int))
    (sameSuccess : success.eval assignment locals = successBool)
    (sameLast : lastLogIndex.eval assignment locals = (lastNat : Int)) :
    (appendResponseTerm width source destination term success lastLogIndex).eval
        assignment locals =
      packetValue (.appendEntriesResponse {
        term := responseTermNat
        success := successBool
        lastLogIndex := lastNat
        source
        destination
      }) := by
  simp [appendResponseTerm, Term.eval, sameTerm, sameSuccess, sameLast,
    packetValue, packetHeaderValue, packetPayloadValue, Message.term,
    Message.source, Message.destination]

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
