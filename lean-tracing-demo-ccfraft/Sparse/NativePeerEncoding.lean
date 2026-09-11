-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeEncodeProofs

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem forall_identity_int (width : PNat) (predicate : Int -> Prop) :
    (forall index : Int, 0 <= index /\ index < width.val -> predicate index) <->
      forall peer : Fin width, predicate peer.val := by
  constructor
  · intro holds peer
    exact holds peer.val ⟨Int.natCast_nonneg _, Int.ofNat_lt.mpr peer.isLt⟩
  · intro holds index valid
    let peer : Fin width := ⟨index.toNat, by omega⟩
    simpa [peer, Int.toNat_of_nonneg valid.1] using holds peer

theorem peer_domain_correct (width : PNat) (column node : Nat) (assignment : Assignment) :
    (peerDomain width column node).eval assignment Locals.empty = true <->
      forall peer : Fin width,
        0 <= (peerIndex column node (.integer peer.val) : Expr .int).eval assignment Locals.empty := by
  simp only [peerDomain, Term.eval, decide_eq_true_eq]
  conv_lhs =>
    intro peer
    rw [implies_eval]
  simpa [peerIndex, allocated, lt, Term.eval, Locals.cons] using
    forall_identity_int width (fun peer =>
      0 <= if assignment (.array .int .bool) 0 node then
        assignment (.array .int (.array .int .int)) column node peer else 0)

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
