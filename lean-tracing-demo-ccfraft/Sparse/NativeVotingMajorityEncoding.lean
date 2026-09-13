-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayVotingMajority
import Sparse.NativeVotingMajority
import Sparse.NativeCommitIndexAssignment

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

private theorem configuration_filter_support {width : PNat}
    (configuration support : Finset (Fin width)) :
    configuration.filter (fun peer => peer ∈ support) =
      support ∩ configuration := by
  ext peer
  simp [and_comm]

theorem voting_majority_term_correct {context : List Ty} {width : PNat}
    [Bootstrap (Fin width)]
    (assignment : Assignment) (locals : Locals context)
    (bootstrap : BitVec width)
    (length current : Term context .int)
    (entries : Term context (.array .int (entryTy width)))
    (support : Term context (.bits width))
    (row : NativeArrayCheckQuorum.Local (Fin width) Nat)
    (currentNat : Nat) (supportSet : Finset (Fin width))
    (sameBootstrap : bootstrap = encodeBits INITIAL_CONFIGURATION)
    (sameLength : length.eval assignment locals = (row.log.length : Int))
    (sameCurrent : current.eval assignment locals = (currentNat : Int))
    (sameEntries : forall position, position < row.log.length ->
      modelEntry (entries.eval assignment locals (position : Int)) =
        row.log.entries position)
    (sameSupport : support.eval assignment locals = encodeBits supportSet) :
    (votingMajorityTerm width bootstrap length current entries support).eval
        assignment locals = true <->
      NativeArrayVotingMajority.Majority row currentNat supportSet := by
  rw [votingMajorityTerm, NativeArrayVotingMajority.Majority]
  apply all_active_term_correct assignment locals length current entries
    (configurationMajorityTerm (.bits bootstrap) fun peer => .bit support peer)
    (configurationMajorityTerm (members (.snd (selectedLogEntry entries)))
      fun peer => .bit (support.weaken .int) peer)
    row.log currentNat
    (fun _ nodes => (supportSet ∩ nodes).card * 2 > nodes.card)
    sameLength sameCurrent sameEntries
  · have encodedBootstrap :
        ((.bits bootstrap : Term context (.bits width)).eval assignment locals) =
          encodeBits INITIAL_CONFIGURATION := by
      simpa only [Term.eval] using sameBootstrap
    rw [configuration_majority_term_eval
      (.bits bootstrap) (fun peer => .bit support peer) assignment locals
      INITIAL_CONFIGURATION (fun peer => peer ∈ supportSet)
      encodedBootstrap]
    · simp only [decide_eq_true_eq]
      rw [configuration_filter_support]
    · intro peer
      rw [Term.eval, sameSupport, encode_bits_bit, decide_eq_true_eq]
  · intro position nodes live content
    have decoded :
        decodeContent
            ((.snd (selectedLogEntry entries) :
              Term (.int :: context) (contentTy width)).eval
              assignment (locals.cons (position : Int))) =
          .reconfiguration nodes := by
      simp only [Term.eval, selected_log_entry_eval]
      change
        (modelEntry (entries.eval assignment locals (position : Int))).content =
          .reconfiguration nodes
      rw [sameEntries position live]
      exact content
    have decodedMembers :=
      (configuration_decoding (.snd (selectedLogEntry entries)) assignment
        (locals.cons (position : Int)) nodes).mp decoded |>.2
    have encodedMembers :
        (members (.snd (selectedLogEntry entries))).eval assignment
            (locals.cons (position : Int)) = encodeBits nodes := by
      rw [<- decodedMembers, encode_decode_bits]
    have weakenedSupport :
        (support.weaken .int).eval assignment
            (locals.cons (position : Int)) = encodeBits supportSet := by
      simpa only [Term.weaken_eval] using sameSupport
    rw [configuration_majority_term_eval
      (members (.snd (selectedLogEntry entries)))
      (fun peer => .bit (support.weaken .int) peer)
      assignment (locals.cons (position : Int)) nodes
      (fun peer => peer ∈ supportSet) encodedMembers]
    · simp only [decide_eq_true_eq]
      rw [configuration_filter_support]
    · intro peer
      rw [Term.eval, weakenedSupport, encode_bits_bit, decide_eq_true_eq]

theorem voting_majority_term_bounded {context : List Ty} {width : PNat}
    (bootstrap : BitVec width)
    (length current : Term context .int)
    (entries : Term context (.array .int (entryTy width)))
    (support : Term context (.bits width)) (limit : Nat)
    (lengthBounded :
      length.symbols.all (fun symbol => symbol.2 < limit) = true)
    (currentBounded :
      current.symbols.all (fun symbol => symbol.2 < limit) = true)
    (entriesBounded :
      entries.symbols.all (fun symbol => symbol.2 < limit) = true)
    (supportBounded :
      support.symbols.all (fun symbol => symbol.2 < limit) = true) :
    (votingMajorityTerm width bootstrap length current entries support).symbols.all
      (fun symbol => symbol.2 < limit) = true := by
  have bootstrapMajorityBounded :
      (configurationMajorityTerm
        (.bits bootstrap : Term context (.bits width))
        (fun peer => .bit support peer)).symbols.all
          (fun symbol => symbol.2 < limit) = true := by
    apply configuration_majority_term_bounded
    · simp [Term.symbols]
    · intro peer
      simpa [Term.symbols] using supportBounded
  have physicalConfigurationBounded :
      (members (.snd (selectedLogEntry entries))).symbols.all
        (fun symbol => symbol.2 < limit) = true := by
    simpa [members, selectedLogEntry, Term.symbols, Term.weaken_symbols] using
      entriesBounded
  have physicalMajorityBounded :
      (configurationMajorityTerm
        (members (.snd (selectedLogEntry entries)))
        (fun peer => .bit (support.weaken .int) peer)).symbols.all
          (fun symbol => symbol.2 < limit) = true := by
    apply configuration_majority_term_bounded
    · exact physicalConfigurationBounded
    · intro peer
      simpa [Term.symbols, Term.weaken_symbols] using supportBounded
  exact all_active_term_bounded length current entries
    (configurationMajorityTerm (.bits bootstrap) fun peer => .bit support peer)
    (configurationMajorityTerm (members (.snd (selectedLogEntry entries)))
      fun peer => .bit (support.weaken .int) peer)
    limit lengthBounded currentBounded entriesBounded bootstrapMajorityBounded
    physicalMajorityBounded

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
