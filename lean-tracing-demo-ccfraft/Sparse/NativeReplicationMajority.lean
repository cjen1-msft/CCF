-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeMajorityTerms

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def replicationMajorityTerm {context : List Ty} {width : PNat}
    (configuration : Term context (.bits width))
    (matchIndex : Term context (.array .int .int))
    (source : Fin width) (candidate : Term context .int) : Term context .bool :=
  configurationMajorityTerm configuration fun peer =>
    .or (.boolean (decide (peer = source)))
      (.le candidate (.select matchIndex (.integer peer.val)))

theorem replication_majority_term_eval {context : List Ty} {width : PNat}
    (configuration : Term context (.bits width))
    (matchIndex : Term context (.array .int .int))
    (source : Fin width) (index : Term context .int)
    (assignment : Assignment) (locals : Locals context)
    (nodes : Finset (Fin width)) (candidate : Nat)
    (matchIndices : Fin width -> Nat)
    (sameConfiguration :
      configuration.eval assignment locals = encodeBits nodes)
    (sameIndex : index.eval assignment locals = (candidate : Int))
    (sameMatches : forall peer,
      matchIndex.eval assignment locals peer.val = (matchIndices peer : Int)) :
    (replicationMajorityTerm configuration matchIndex source index).eval
        assignment locals =
      decide
        ((nodes.filter fun peer =>
          peer = source \/ candidate <= matchIndices peer).card * 2 > nodes.card) := by
  apply configuration_majority_term_eval configuration
    (fun peer =>
      .or (.boolean (decide (peer = source)))
        (.le index (.select matchIndex (.integer peer.val))))
    assignment locals nodes
    (fun peer => peer = source \/ candidate <= matchIndices peer)
    sameConfiguration
  intro peer
  simp [Term.eval, sameIndex, sameMatches, decide_eq_true_eq]

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
