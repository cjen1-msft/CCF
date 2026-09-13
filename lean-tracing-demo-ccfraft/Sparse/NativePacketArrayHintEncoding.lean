-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativePacketArrayHint
import Sparse.NativeQueueDomain

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem log_prefix_cells_eval {context : List Ty} {width : PNat}
    (cells : Term context (.array .int (entryTy width))) (count : Nat)
    (assignment : Assignment) (locals : Locals context) (index : Int) :
    (logPrefixCells cells count).eval assignment locals index =
      if 0 <= index /\ index < (count : Int) then
        cells.eval assignment locals index
      else
        entryValue (defaultLogEntry width) := by
  classical
  induction count with
  | zero =>
    have outside : ¬ (0 <= index /\ index < (0 : Int)) := by omega
    simp only [logPrefixCells, Term.eval, Nat.cast_zero, if_neg outside]
    rfl
  | succ count previous =>
    simp only [logPrefixCells, Term.eval]
    by_cases same : index = (count : Int)
    · subst index
      simp
    · simp only [Function.update_apply, same, if_false, previous]
      have range : (0 <= index /\ index < ((count + 1 : Nat) : Int)) <->
          (0 <= index /\ index < (count : Int)) := by omega
      simp only [range]

theorem log_prefix_hint_correct {context : List Ty} {width : PNat}
    (count : Nat) (value : Term context (logTy width))
    (assignment : Assignment) (locals : Locals context)
    (valid : LogValueValid (value.eval assignment locals)) :
    (logPrefixHint count value).eval assignment locals = true := by
  apply (implies_eval _ _ assignment locals).mpr
  intro sameLength
  simp only [Term.eval, decide_eq_true_eq] at sameLength ⊢
  funext index
  rw [log_prefix_cells_eval]
  by_cases live : 0 <= index /\ index < (count : Int)
  · simp [live, Term.eval]
  · simp only [if_neg live]
    apply valid.tail
    by_cases negative : index < 0
    · exact Or.inl negative
    · right
      have nonnegative : 0 <= index := le_of_not_gt negative
      have beyond : (count : Int) <= index := by
        apply le_of_not_gt
        intro below
        exact live ⟨nonnegative, below⟩
      exact sameLength.symm ▸ beyond

theorem packet_array_hint_of_valid {context : List Ty} {width : PNat}
    (count : Nat) (value : Term context (packetTy width))
    (assignment : Assignment) (locals : Locals context)
    (valid : PacketValueValid (value.eval assignment locals)) :
    (packetArrayHint count value).eval assignment locals = true := by
  generalize observed : value.eval assignment locals = packet at valid ⊢
  rcases packet with ⟨header, payload⟩
  rcases payload with append | response | vote | granted | preVote | preGranted | proposal
  · simpa only [packetArrayHint, Term.eval, observed, Locals.cons] using
      log_prefix_hint_correct count
        (.snd (.snd (.snd (.bound .here)))) assignment (locals.cons append)
        valid.payload.2.2.2
  all_goals simp [packetArrayHint, Term.eval, observed]

theorem packet_array_hint_of_domain {context : List Ty} {width : PNat}
    (count : Nat) (value : Term context (packetTy width))
    (assignment : Assignment) (locals : Locals context)
    (domain : (packetDomain value).eval assignment locals = true) :
    (packetArrayHint count value).eval assignment locals = true := by
  exact packet_array_hint_of_valid count value assignment locals
    ((packet_domain_correct value assignment locals).mp domain)

theorem queue_packet_domain_and_array_hint_eval {context : List Ty} {width : PNat}
    (source : Term context .int) (packet : Term context (packetTy width))
    (count : Nat) (assignment : Assignment) (locals : Locals context) :
    (Term.and (queuePacketDomain source packet) (packetArrayHint count packet)).eval
        assignment locals =
      (queuePacketDomain source packet).eval assignment locals := by
  by_cases domain : (queuePacketDomain source packet).eval assignment locals = true
  · have valid := (queue_packet_domain_correct source packet assignment locals).mp domain
    have packetDomain :
        (NativeEncode.packetDomain packet).eval assignment locals = true :=
      (packet_domain_correct packet assignment locals).mpr valid.1
    have hint := packet_array_hint_of_domain count packet assignment locals packetDomain
    simp [Term.eval, domain, hint]
  · have domainFalse :
        (queuePacketDomain source packet).eval assignment locals = false :=
      Bool.eq_false_iff.mpr domain
    simp [Term.eval, domainFalse]

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
