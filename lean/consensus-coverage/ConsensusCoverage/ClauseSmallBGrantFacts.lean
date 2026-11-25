module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ClauseSmallB
import ConsensusCoverage.ClauseSmallBMonotone
import all ConsensusCoverage.ClauseSmallB
import all ConsensusCoverage.ClauseMatchAck
import all ConsensusCoverage.ClauseQuestions
import all ConsensusCoverage.HandReadersElectionBFind
import all ConsensusCoverage.HandReadersElectionBKeys
import all ConsensusCoverage.HandReadersElectionGrant
import all ConsensusCoverage.HandReadersElectionMono
import all ConsensusCoverage.HandReadersElectionRank
import all ConsensusCoverage.ReadersRefuted
import all ConsensusCoverage.ReadersTotal
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.ClauseSmallB.GrantFacts

open Consensus Consensus.Proofs Safety SolvedWitnesses
open ClauseQuestions ClauseExactTables ActionProfile

set_option maxHeartbeats 0
set_option maxRecDepth 8192
set_option Elab.async false

public theorem columns : nonTrunk .grantFacts =
  [.ballot_step_mem_after_inl, .ballot_step_mem_after_inr, .grantFactsBefore_grant_inl,
    .grantFactsBefore_grant_inr, .grantFactsBefore_supported_inl, .grantFactsBefore_supported_inr,
    .replaceNode_keys_here_pos, .replaceNode_keys_here_neg, .rankAtGrant_persist_inl,
    .rankAtGrant_up_to_date_inl, .rankAtGrant_up_to_date_inr, .rankAtGrant_term_inl,
    .rankAtGrant_term_inr, .rankAtGrant_persist_inr, .maxCommittableIndexBounded_values_nil,
    .maxCommittableIndexBounded_values_cons, .maxCommittableIndexBounded_signature_pos,
    .maxCommittableIndexBounded_signature_neg, .termAt_mono_eq_zero_or_pos_inl,
    .termAt_mono_eq_zero_or_pos_inr, .termAt_mono_eq_or_lt_of_le_inl, .termAt_mono_eq_or_lt_of_le_inr,
    .find_of_mem_here_pos, .find_of_mem_here_neg] := by
  decide +kernel

private noncomputable abbrev bit (s : Step) (tag : Classes.StepBranch) := label s (.step tag)

private theorem recorded_split (s : Step) :
    bit s .grantFactsBefore_grant_inr =
      (bit s .grantFactsBefore_supported_inl || bit s .grantFactsBefore_supported_inr) := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  open HandReadersElection.Grant in
  have sem (k : Kind) : bit s (column k) = true ↔ Evidence s.context k :=
    ((label_true s (.step (column k))).trans (sig_iff s.context _)).trans
      ⟨necessary s.context k, sufficient s.context k⟩
  apply Bool.eq_iff_iff.mpr
  rw [Bool.or_eq_true]
  change bit s (HandReadersElection.Grant.column .recorded) = true ↔
    bit s (HandReadersElection.Grant.column .self) = true ∨
    bit s (HandReadersElection.Grant.column .seen) = true
  rw [sem, sem, sem]
  open HandReadersElection.Grant in
  constructor
  · rintro ⟨v, n, k, req, route, grant, self | seen⟩
    · exact .inl ⟨v, n, k, req, route, grant, self⟩
    · exact .inr ⟨v, n, k, req, route, grant, seen⟩
  · rintro (⟨v, n, k, req, route, grant, self⟩ | ⟨v, n, k, req, route, grant, seen⟩)
    · exact ⟨v, n, k, req, route, grant, .inl self⟩
    · exact ⟨v, n, k, req, route, grant, .inr seen⟩

private theorem find_eq_replace (s : Step) :
    bit s .find_of_mem_here_pos = bit s .replaceNode_keys_here_pos :=
  (HandReadersElectionB.Find.positive.eq_label s).trans
    (HandReadersElectionB.Keys.positive.eq_label s).symm

private theorem tied_of_cut (s : Step) (k : HandReadersElection.Rank.Kind)
    (which : k = .older ∨ k = .same)
    (h : bit s (HandReadersElection.Rank.column k) = true) :
    bit s .rankAtGrant_up_to_date_inr = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  open HandReadersElection.Rank in
  have test (kind : Kind) := (label_true s (.step (column kind))).trans (sig_iff s.context _)
  change label s (.step (HandReadersElection.Rank.column .tied)) = true
  apply (test .tied).mpr
  apply HandReadersElection.Rank.sufficient
  obtain ⟨v, n, term, req, k', log, i, st, post, source, pre, now, le, stamp, vote, pref, cut⟩ :=
    HandReadersElection.Rank.necessary s.context k ((test k).mp h)
  refine ⟨v, n, term, req, k', log, i, st, post, source, pre, now, le, stamp, vote, pref, ?_⟩
  rcases which with rfl | rfl <;>
    exact (Bool.and_eq_true_iff.mp cut).1

private theorem rank_recorded (s : Step) (k : HandReadersElection.Rank.Kind)
    (ranked : bit s (HandReadersElection.Rank.column k) = true) :
    bit s .grantFactsBefore_grant_inr = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  have rank := (label_true s (.step (HandReadersElection.Rank.column k))).trans (sig_iff s.context _)
  obtain ⟨v, n, term, req, _, _, _, _, _, source, _⟩ :=
    HandReadersElection.Rank.necessary s.context k (rank.mp ranked)
  have test := (label_true s (.step .grantFactsBefore_grant_inr)).trans (sig_iff s.context _)
  exact test.mpr (HandReadersElection.Grant.sufficient s.context .recorded
    ⟨v, n, term, req, source.1, source.2.1, source.2.2.1⟩)

private theorem rank_mono (s : Step) :
    (bit s .rankAtGrant_up_to_date_inl = true ∨ bit s .rankAtGrant_up_to_date_inr = true) →
      (bit s .termAt_mono_eq_or_lt_of_le_inl || bit s .termAt_mono_eq_or_lt_of_le_inr) = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  open HandReadersElection in
  have rank (k : Rank.Kind) :
      bit s (Rank.column k) = true → Rank.Selected s.context k (Mono.pick .positive) := by
    intro h
    have test := (label_true s (.step (Rank.column k))).trans (sig_iff s.context _)
    obtain ⟨v, n, term, req, k', log, i, st, post, source, pre, now, le, stamp, vote, pref, cut⟩ :=
      Rank.necessary s.context k (test.mp h)
    exact ⟨v, n, term, req, k', log, i, st, post, source, pre, now, le, stamp, vote, pref, cut, rfl⟩
  rw [← term_mono_split s]
  have test := (label_true s (.step .termAt_mono_eq_zero_or_pos_inr)).trans (sig_iff s.context _)
  intro h
  exact test.mpr (HandReadersElection.Mono.sufficient s.context .positive
    (.inl (h.imp (rank .ahead) (rank .tied))))

private def pack (v : List Bool) : List Bool :=
  let get := fun i => v[i]?.getD false
  let self := get 1
  let seen := get 2
  let lookup := get 3
  [false, false, get 0, self || seen, self, seen, lookup, lookup,
    get 4, get 5, get 6, get 7, get 8, get 9, get 10, get 11, get 12, get 11,
    false, get 13 || get 14, get 13, get 14, lookup, lookup]

private def selected : List Classes.StepBranch :=
  [.grantFactsBefore_grant_inl, .grantFactsBefore_supported_inl, .grantFactsBefore_supported_inr,
    .replaceNode_keys_here_pos, .rankAtGrant_persist_inl, .rankAtGrant_up_to_date_inl,
    .rankAtGrant_up_to_date_inr, .rankAtGrant_term_inl, .rankAtGrant_term_inr, .rankAtGrant_persist_inr,
    .maxCommittableIndexBounded_values_nil, .maxCommittableIndexBounded_values_cons,
    .maxCommittableIndexBounded_signature_pos,
    .termAt_mono_eq_or_lt_of_le_inl, .termAt_mono_eq_or_lt_of_le_inr]

private theorem shape (s : Step) : (nonTrunkLabel .grantFacts s).bits = pack (selected.map (bit s)) := by
  have no (k : Classes.StepBranch) (h : ReadersRefuted.read? k = some false) :=
    ReadersRefuted.read?_correct s h
  simp only [nonTrunkLabel, restrictedLabel, columns, selected, List.map_cons, List.map_nil, pack,
    List.getElem?_cons_zero, List.getElem?_cons_succ, Option.getD_some, recorded_split,
    ← HandReadersElection.Tables.replace_arms_eq s, ← HandReadersElection.Tables.find_arms_eq s,
    find_eq_replace s, term_mono_split, ← frontier_scan_unsigned s, no .ballot_step_mem_after_inl (by decide +kernel),
    no .ballot_step_mem_after_inr (by decide +kernel), no .termAt_mono_eq_zero_or_pos_inl (by decide +kernel)]

public def upperPatterns : List (List Bool) :=
  ((vectors 15).filter fun v =>
    let get := fun i => v[i]?.getD false
    (!(get 7 || get 8) || get 6) && (!(get 5 || get 6) || get 1 || get 2) &&
      (!(get 5 || get 6) || get 13 || get 14) && (!get 12 || get 11)).map pack

public theorem patterns_complete (s : Step) : (nonTrunkLabel .grantFacts s).bits ∈ upperPatterns := by
  rw [shape]
  apply List.mem_map_of_mem
  apply List.mem_filter.mpr
  refine ⟨vector_mem (selected.map (bit s)), ?_⟩
  have older := tied_of_cut s .older (.inl rfl)
  have same := tied_of_cut s .same (.inr rfl)
  change bit s .rankAtGrant_term_inl = true → _ at older
  change bit s .rankAtGrant_term_inr = true → _ at same
  have ahead := rank_recorded s .ahead
  have tied := rank_recorded s .tied
  change bit s .rankAtGrant_up_to_date_inl = true → _ at ahead
  change bit s .rankAtGrant_up_to_date_inr = true → _ at tied
  rw [recorded_split s] at ahead tied
  have mono := rank_mono s
  have signed := frontier_signed_scan s
  change ((!(bit s .rankAtGrant_term_inl || bit s .rankAtGrant_term_inr) ||
    bit s .rankAtGrant_up_to_date_inr) &&
    (!(bit s .rankAtGrant_up_to_date_inl || bit s .rankAtGrant_up_to_date_inr) ||
      bit s .grantFactsBefore_supported_inl || bit s .grantFactsBefore_supported_inr) &&
    (!(bit s .rankAtGrant_up_to_date_inl || bit s .rankAtGrant_up_to_date_inr) ||
      bit s .termAt_mono_eq_or_lt_of_le_inl || bit s .termAt_mono_eq_or_lt_of_le_inr) &&
    (!bit s .maxCommittableIndexBounded_signature_pos || bit s .maxCommittableIndexBounded_values_cons)) = true
  simp only [Bool.and_eq_true, Bool.or_eq_true, Bool.not_eq_true', ← Bool.not_eq_true] at *
  grind only

public def upperRows : List RestrictedProfile :=
  endpointRows.flatMap fun e =>
    (upperPatterns.filter fun bs => bs[22]?.getD false || decide (e.1 = e.2)).map (row e)

public theorem complete (s : Step) : nonTrunkLabel .grantFacts s ∈ upperRows := by
  change row (endpoints s) (nonTrunkLabel .grantFacts s).bits ∈ upperRows
  refine List.mem_flatMap.mpr ⟨_, endpoints_mem s, List.mem_map_of_mem (List.mem_filter.mpr
    ⟨patterns_complete s, ?_⟩)⟩
  rw [shape]
  change (bit s .replaceNode_keys_here_pos || decide ((endpoints s).1 = (endpoints s).2)) = true
  rw [← find_eq_replace s]
  cases h : bit s .find_of_mem_here_pos
  · simp [lookup_false_diagonal s h]
  · rfl

private def picks : List Pick :=
  [(row (z, p) (bits "000000110000000000000011"), 0, 0),
    (row (p, p) (bits "000000110000000000000011"), 0, 1),
    (row (z, b) (bits "000000110000000000000011"), 1, 0),
    (row (z, z) (bits "000000110000000000000011"), 2, 0),
    (row (z, b) (bits "000000110000001101000011"), 2, 2),
    (row (b, b) (bits "000000110000000000000011"), 2, 3),
    (row (b, b) (bits "000000000000000000000000"), 2, 4),
    (row (b, p) (bits "000000110000001111000011"), 2, 5),
    (row (z, z) (bits "001111111010101111011011"), 3, 6),
    (row (p, p) (bits "001111111010101111011011"), 4, 12),
    (row (z, z) (bits "000101110000000000000011"), 3, 5),
    (row (z, z) (bits "000110111110101111011011"), 3, 4),
    (row (p, p) (bits "000101111110101111011011"), 4, 11),
    (row (p, p) (bits "000110111110101111011011"), 168, 5)]

public def rows : List RestrictedProfile := picks.map Prod.fst

public def patterns : List (List Bool) := patternsOf rows

public def unresolvedRows : List RestrictedProfile := unresolved upperRows rows

public theorem covered_or_unresolved (s : Step) :
    nonTrunkLabel .grantFacts s ∈ rows ∨ nonTrunkLabel .grantFacts s ∈ unresolvedRows :=
  witnessed_or_unresolved (complete s)

public theorem counts : rows.Nodup ∧ rows.length = 14 ∧ patterns.Nodup ∧ patterns.length = 8 := by
  decide +kernel

private theorem picked : picks.all (checkPick .grantFacts) = true :=
  all_split 8 (by decide +kernel) (by decide +kernel)

public theorem lower (r : RestrictedProfile) (mem : r ∈ rows) :
    ∃ s, nonTrunkLabel .grantFacts s = r :=
  replay_picks (covered_of_check (by decide +kernel)) picked mem

public theorem patterns_lower (bs : List Bool) (mem : bs ∈ patterns) :
    ∃ s, (nonTrunkLabel .grantFacts s).bits = bs :=
  pattern_witness lower mem

end ConsensusCoverage.ClauseSmallB.GrantFacts
