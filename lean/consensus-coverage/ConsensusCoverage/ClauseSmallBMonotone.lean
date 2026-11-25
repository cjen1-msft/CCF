module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ClauseSmallB
import all ConsensusCoverage.HandReadersElectionBBoundRows
import all ConsensusCoverage.HandReadersElectionMono
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.ClauseSmallB

open Consensus Consensus.Model.Node Consensus.Proofs Safety Ledger
open ActionProfile SolvedWitnesses HandReadersElection

set_option maxRecDepth 8192

private theorem selected_split [Config.InitialConfiguration] {f t} (c : Ctx f t) (k : Rank.Kind)
    (h : Rank.Selected c k (Mono.pick .positive)) :
    Rank.Selected c k (Mono.pick .equal) ∨ Rank.Selected c k (Mono.pick .short) := by
  obtain ⟨v, n, term, r, a, l, i, st, post, input, pre, now, le, stamp, vote, sub, cut, _⟩ := h
  have signed := input.2.2.2.2.2.1
  have kept := Ledger.isSignatureAt_of_prefix sub (Ledger.isSignatureAt_take_of_le Nat.le.refl signed)
  obtain eq | lt := Nat.eq_or_lt_of_le (signatureIndex_le_maxCommittableIndex kept)
  · exact .inl ⟨v, n, term, r, a, l, i, st, post, input, pre, now, le, stamp, vote, sub, cut,
      beq_iff_eq.mpr eq⟩
  · exact .inr ⟨v, n, term, r, a, l, i, st, post, input, pre, now, le, stamp, vote, sub, cut,
      decide_eq_true lt⟩

private theorem selected_ignore [Config.InitialConfiguration] {f t} (c : Ctx f t)
    (k : Rank.Kind) (pick : NodeState → Nat → Bool) (h : Rank.Selected c k pick) :
    Rank.Selected c k (Mono.pick .positive) := by
  obtain ⟨v, n, term, r, a, l, i, st, post, input, pre, now, le, stamp, vote, sub, cut, _⟩ := h
  exact ⟨v, n, term, r, a, l, i, st, post, input, pre, now, le, stamp, vote, sub, cut, rfl⟩

private theorem mono_split [Config.InitialConfiguration] {f t} (c : Ctx f t) :
    sig c .termAt_mono_eq_zero_or_pos_inr ↔
      sig c .termAt_mono_eq_or_lt_of_le_inl ∨ sig c .termAt_mono_eq_or_lt_of_le_inr := by
  constructor
  · intro h
    obtain (ahead | tied) | campaign := Mono.necessary c .positive h
    · exact (selected_split c .ahead ahead).imp
        (fun eq => Mono.sufficient c .equal (.inl (.inl eq)))
        (fun lt => Mono.sufficient c .short (.inl (.inl lt)))
    · exact (selected_split c .tied tied).imp
        (fun eq => Mono.sufficient c .equal (.inl (.inr eq)))
        (fun lt => Mono.sufficient c .short (.inl (.inr lt)))
    · exact .inl (Mono.sufficient c .equal (.inr campaign))
  · rintro (eq | lt)
    all_goals
      first
      | have h := Mono.necessary c .equal eq
      | have h := Mono.necessary c .short lt
      apply Mono.sufficient c .positive
      rcases h with (ahead | tied) | campaign
      · exact .inl (.inl (selected_ignore c .ahead _ ahead))
      · exact .inl (.inr (selected_ignore c .tied _ tied))
      · first | exact .inr campaign | cases campaign.1.1

public theorem term_mono_split (s : Step) :
    label s (.step .termAt_mono_eq_zero_or_pos_inr) =
      (label s (.step .termAt_mono_eq_or_lt_of_le_inl) ||
        label s (.step .termAt_mono_eq_or_lt_of_le_inr)) := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  apply Bool.eq_iff_iff.mpr
  simp only [Bool.or_eq_true, label_true, holds, sig_iff]
  exact mono_split s.context

/-- Index zero always supplies the nonsignature arm of an entered scan. -/
public theorem frontier_scan_unsigned (s : Step) :
    label s (.step .maxCommittableIndexBounded_values_cons) =
      label s (.step .maxCommittableIndexBounded_signature_neg) :=
  (HandReadersElectionB.Bounds.nonempty.eq_label s).trans
    (HandReadersElectionB.Bounds.nonsignature.eq_label s).symm

public theorem frontier_signed_scan (s : Step)
    (yes : label s (.step .maxCommittableIndexBounded_signature_pos) = true) :
    label s (.step .maxCommittableIndexBounded_values_cons) = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  have test (tag : Classes.StepBranch) := (label_true s (.step tag)).trans (sig_iff s.context tag)
  apply (test _).mpr
  have hit := (test _).mp yes
  repeat' (change _ ∨ _ at hit; rcases hit with hit | hit)
  all_goals
    obtain ⟨log, root, _, tail, fold, _, _, _, _, bound, _⟩ := hit
    repeat' first
      | exact ⟨log, root, tail, fold, bound⟩
      | exact Or.inl ⟨log, root, tail, fold, bound⟩
      | apply Or.inr

end ConsensusCoverage.ClauseSmallB
