-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeClientRequestAssignment
import Sparse.NativeClientRequestSound
import Sparse.NativeClientRequestStructure

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem client_request_complete {width : PNat} [Bootstrap (Fin width)]
    (source : Fin width) (transaction : Expr .int) (transactionNat : Nat)
    (before after : Encoding width)
    (run : (clientRequest source transaction).run before = .ok ((), after))
    (assignment : Assignment)
    (holds : Holds before.assertions.toList assignment)
    (frame nextFrame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment before.toColumns frame)
    (valid : ReferencesValid before)
    (sameBootstrap : decodeBits before.bootstrap = INITIAL_CONFIGURATION)
    (sameTransaction :
      transaction.eval assignment Locals.empty = (transactionNat : Int))
    (request :
      NativeArrayClientRequest.Request frame source transactionNat nextFrame) :
    exists extended : Assignment,
      assignment.AgreesBelow before.next extended /\
        Holds after.assertions.toList extended /\
        FrameColumnsRep extended after.toColumns nextFrame := by
  let state := frame.realize
  have modelRep : frame.Rep state :=
    NativeArrayVote.realize_rep frame rep.valid
  obtain ⟨enabled, nextModel⟩ :=
    NativeArrayClientRequest.Request.model_correct frame nextFrame state modelRep
      source transactionNat request
  have transactionBounded :=
    client_request_transaction_bounded source transaction before after run
  obtain ⟨extended, agreement, afterHolds⟩ :=
    client_request_assignment source transaction transactionNat before after run
      assignment holds valid frame state rep modelRep enabled sameBootstrap
      sameTransaction transactionBounded
  have originalRep : FrameColumnsRep extended before.toColumns frame :=
    rep.agrees_below before assignment extended frame valid agreement
  have boundedTransaction :
      forall symbol, symbol ∈ transaction.symbols ->
        symbol.2 < before.next := by
    intro symbol member
    simpa using List.all_eq_true.mp transactionBounded symbol member
  have extendedTransaction :
      transaction.eval extended Locals.empty = (transactionNat : Int) :=
    (transaction.eval_agrees_below assignment extended Locals.empty before.next
      boundedTransaction agreement).symm.trans sameTransaction
  obtain ⟨written, writtenRequest, writtenRep⟩ :=
    client_request_frame_sound source transaction transactionNat before after run
      extended afterHolds frame originalRep sameBootstrap extendedTransaction
  have writtenModel :=
    (NativeArrayClientRequest.Request.model_correct frame written state modelRep
      source transactionNat writtenRequest).2
  exact ⟨extended, agreement, afterHolds,
    FrameColumnsRep.of_model_rep extended after.toColumns written nextFrame
      (CCFRaft.next state (.clientRequest source transactionNat))
      writtenRep writtenModel nextModel⟩

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
