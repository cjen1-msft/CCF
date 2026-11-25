module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ClauseSmallB
import ConsensusCoverage.ClauseSmallBMonotone
import all ConsensusCoverage.ClauseRankRead
import all ConsensusCoverage.ClauseSmallB
import all ConsensusCoverage.ClauseMatchAck
import all ConsensusCoverage.ClauseQuestions
import all ConsensusCoverage.HandReadersElectionBFind
import all ConsensusCoverage.HandReadersElectionBKeys
import all ConsensusCoverage.HandReadersElectionGrant
import all ConsensusCoverage.HandReadersElectionMono
import all ConsensusCoverage.HandReadersElectionRank
import all ConsensusCoverage.HandReadersElectionRankSites
import all ConsensusCoverage.ReadersRefuted
import all ConsensusCoverage.ReadersTotal
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
meta import ConsensusCoverage.ReachPath

namespace ConsensusCoverage.ClauseSmallB.GrantFacts

open Consensus Consensus.Model.Node Consensus.Proofs Safety Ledger SolvedWitnesses
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

private theorem tied_splits (s : Step) (h : bit s .rankAtGrant_up_to_date_inr = true) :
    bit s .rankAtGrant_term_inl = true ∨ bit s .rankAtGrant_term_inr = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  open HandReadersElection.Rank in
  have test (k : Kind) := (label_true s (.step (column k))).trans (sig_iff c _)
  obtain ⟨v, n, term, req, k, log, i, st, post, source, pre, now, le, stamp, vote, sub, cut⟩ :=
    HandReadersElection.Rank.necessary c .tied ((test .tied).mp h)
  have signed := source.2.2.2.2.2.1
  have atI := source.2.2.2.2.2.2
  have kept := isSignatureAt_of_prefix sub (isSignatureAt_take_of_le Nat.le.refl signed)
  have within := Nat.le_of_eq (List.length_take_of_le (signature_bound signed)).symm
  have mono := termAt_mono (c.inv.sorted v st pre)
    (signatureIndex_le_maxCommittableIndex kept) (maxCommittableIndexBounded _)
  rw [termAt_of_prefix sub within, termAt_take Nat.le.refl, atI] at mono
  change k ≤ maxCommittableTerm st.log at mono
  rcases Nat.lt_or_eq_of_le mono with older | same
  · exact .inl ((test .older).mpr (HandReadersElection.Rank.sufficient c .older
      ⟨v, n, term, req, k, log, i, st, post, source, pre, now, le, stamp, vote, sub,
        Bool.and_eq_true_iff.mpr ⟨cut, decide_eq_true older⟩⟩))
  · exact .inr ((test .same).mpr (HandReadersElection.Rank.sufficient c .same
      ⟨v, n, term, req, k, log, i, st, post, source, pre, now, le, stamp, vote, sub,
        Bool.and_eq_true_iff.mpr ⟨cut, beq_iff_eq.mpr same⟩⟩))

private theorem retained_eq (s : Step) :
    bit s .rankAtGrant_persist_inl =
      (bit s .rankAtGrant_up_to_date_inl || bit s .rankAtGrant_up_to_date_inr) := by
  have a := (HandReadersElection.Rank.exactReader .ahead).eq_label s
  have t := (HandReadersElection.Rank.exactReader .tied).eq_label s
  change bit s .rankAtGrant_up_to_date_inl =
    HandReadersElection.Rank.reader .ahead s.cfg s.before s.act s.after s.past at a
  change bit s .rankAtGrant_up_to_date_inr =
    HandReadersElection.Rank.reader .tied s.cfg s.before s.act s.after s.past at t
  exact (ClauseRankRead.retained_eq s).trans (by unfold ClauseRankRead.retained; rw [← a, ← t])

private theorem short_retained (s : Step) (yes : bit s .termAt_mono_eq_or_lt_of_le_inr = true) :
    bit s .rankAtGrant_persist_inl = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  let test (tag : Classes.StepBranch) := (label_true s (.step tag)).trans (sig_iff c tag)
  apply (test .rankAtGrant_persist_inl).mpr
  apply (ClauseRankRead.retained_iff c).mpr
  have short := HandReadersElection.Mono.necessary c .short ((test .termAt_mono_eq_or_lt_of_le_inr).mp yes)
  obtain (ahead | tied) | campaign := short
  · left
    obtain ⟨v,n,t,r,k,l,i,st,post,input,pre,now,le,stamp,vote,sub,cut,_⟩ := ahead
    exact ⟨v,n,t,r,k,l,i,st,post,input,pre,now,le,stamp,vote,sub,cut⟩
  · right
    obtain ⟨v,n,t,r,k,l,i,st,post,input,pre,now,le,stamp,vote,sub,cut,_⟩ := tied
    exact ⟨v,n,t,r,k,l,i,st,post,input,pre,now,le,stamp,vote,sub,cut⟩
  · cases campaign.1.1

private theorem lost_recorded (s : Step) (h : bit s .rankAtGrant_persist_inr = true) :
    bit s .grantFactsBefore_grant_inr = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  have loss := ((label_true s (.step .rankAtGrant_persist_inr)).trans (sig_iff c _)).mp h
  have test := (label_true s (.step .grantFactsBefore_grant_inr)).trans (sig_iff c _)
  apply test.mpr
  repeat' (change _ ∨ _ at loss; rcases loss with loss | loss)
  all_goals
    obtain ⟨v,n,term,r,k,l,i,site,_⟩ := loss
    have input : HandReadersElection.RankSites.Input c v n term r k l i :=
      HandReadersElection.RankSites.necessary c (by
        repeat' first | exact site | exact Or.inl site | apply Or.inr)
    exact HandReadersElection.Grant.sufficient c .recorded
      ⟨v, n, term, r, input.1, input.2.1, input.2.2.1⟩

private theorem rank_signed (s : Step) (kind : HandReadersElection.Rank.Kind)
    (yes : bit s (HandReadersElection.Rank.column kind) = true) :
    bit s .maxCommittableIndexBounded_signature_pos = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  let test (tag : Classes.StepBranch) := (label_true s (.step tag)).trans (sig_iff c tag)
  obtain ⟨v,n,term,r,k,l,i,st,post,input,pre,now,le,stamp,vote,sub,cut⟩ :=
    HandReadersElection.Rank.necessary c kind ((test _).mp yes)
  have routes := HandReadersElection.RankSites.sufficient c input
  obtain ⟨_,hit,_,seen,_,signed,atI⟩ := input
  have up := HandReadersElection.Rank.cut_up kind cut
  have pack := And.intro pre (And.intro now (And.intro le (And.intro stamp (And.intro vote up))))
  have bound := Nat.le_of_eq (List.length_take_of_le (signature_bound signed)).symm
  have stored := isSignatureAt_of_prefix sub (isSignatureAt_take_of_le Nat.le.refl signed)
  have leRank := signatureIndex_le_maxCommittableIndex stored
  have within := signature_bound stored
  have limit : ∀ j ∈ List.range (st.log.length + 1), j ≤ st.log.length :=
    fun _ h => Nat.le_of_lt_succ (List.mem_range.mp h)
  apply (test .maxCommittableIndexBounded_signature_pos).mpr
  rcases routes with root | root
  · have enter : (reach% step_maxCommittableIndexBounded_signature_pos[8]) s.frame s.after c st.log :=
      ⟨v,n,term,r,k,l,i,root,st,⟨post,pack⟩,post,pack,pre,pack.2,now,pack.2.2,le,pack.2.2.2,
        stamp,⟨vote,up⟩,vote,up,sub,seen,signed,atI,bound,stored,leRank,hit,rfl⟩
    iterate 8 right
    exact .inl ⟨st.log,enter,i,[],by simp,0,by simpa using within,Nat.zero_le _,stored,limit,within⟩
  · have enter : (reach% step_maxCommittableIndexBounded_signature_pos[0]) s.frame s.after c st.log :=
      .inr (.inr ⟨v,n,term,r,k,l,i,root,st,⟨post,pack⟩,post,pack,pre,pack.2,now,pack.2.2,le,pack.2.2.2,
        stamp,⟨vote,up⟩,vote,up,sub,seen,signed,atI,bound,stored,leRank,hit,rfl⟩)
    exact .inl ⟨st.log,enter,i,[],by simp,0,by simpa using within,Nat.zero_le _,stored,limit,within⟩

private def pack (v : List Bool) : List Bool :=
  let get := fun i => v[i]?.getD false
  let self := get 1
  let seen := get 2
  let lookup := get 3
  [false, false, get 0, self || seen, self, seen, lookup, lookup,
    get 4 || get 5 || get 6, get 4, get 5 || get 6, get 5, get 6, get 7, get 8, get 9, get 10, get 9,
    false, get 11 || get 12, get 11, get 12, lookup, lookup]

private def selected : List Classes.StepBranch :=
  [.grantFactsBefore_grant_inl, .grantFactsBefore_supported_inl, .grantFactsBefore_supported_inr,
    .replaceNode_keys_here_pos, .rankAtGrant_up_to_date_inl,
    .rankAtGrant_term_inl, .rankAtGrant_term_inr, .rankAtGrant_persist_inr,
    .maxCommittableIndexBounded_values_nil, .maxCommittableIndexBounded_values_cons,
    .maxCommittableIndexBounded_signature_pos,
    .termAt_mono_eq_or_lt_of_le_inl, .termAt_mono_eq_or_lt_of_le_inr]

private theorem shape (s : Step) : (nonTrunkLabel .grantFacts s).bits = pack (selected.map (bit s)) := by
  have no (k : Classes.StepBranch) (h : ReadersRefuted.read? k = some false) :=
    ReadersRefuted.read?_correct s h
  have tied : bit s .rankAtGrant_up_to_date_inr =
      (bit s .rankAtGrant_term_inl || bit s .rankAtGrant_term_inr) := by
    apply Bool.eq_iff_iff.mpr
    rw [Bool.or_eq_true]
    have earlier := tied_of_cut s .older (.inl rfl)
    have same := tied_of_cut s .same (.inr rfl)
    change bit s .rankAtGrant_term_inl = true → _ at earlier
    change bit s .rankAtGrant_term_inr = true → _ at same
    exact ⟨tied_splits s, fun h => h.elim earlier same⟩
  simp only [nonTrunkLabel, restrictedLabel, columns, selected, List.map_cons, List.map_nil, pack,
    List.getElem?_cons_zero, List.getElem?_cons_succ, Option.getD_some, recorded_split,
    retained_eq, tied, Bool.or_assoc,
    ← HandReadersElection.Tables.replace_arms_eq s, ← HandReadersElection.Tables.find_arms_eq s,
    find_eq_replace s, term_mono_split, ← frontier_scan_unsigned s, no .ballot_step_mem_after_inl (by decide +kernel),
    no .ballot_step_mem_after_inr (by decide +kernel), no .termAt_mono_eq_zero_or_pos_inl (by decide +kernel)]

public def upperPatterns : List (List Bool) :=
  ((vectors 13).filter fun v =>
    let get := fun i => v[i]?.getD false
    (!(get 4 || get 5 || get 6 || get 7) || get 1 || get 2) &&
      (!(get 4 || get 5 || get 6) || (get 10 && (get 11 || get 12))) &&
      (!get 10 || get 9) && (!get 12 || get 4 || get 5 || get 6)).map pack

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
  have older := tied_of_cut s .older (.inl rfl)
  have same := tied_of_cut s .same (.inr rfl)
  change bit s .rankAtGrant_up_to_date_inl = true → _ at ahead
  change bit s .rankAtGrant_up_to_date_inr = true → _ at tied
  change bit s .rankAtGrant_term_inl = true → _ at older
  change bit s .rankAtGrant_term_inr = true → _ at same
  have lost := lost_recorded s
  rw [recorded_split s] at ahead tied lost
  have mono := rank_mono s
  have signedAhead := rank_signed s .ahead
  have signedTied := rank_signed s .tied
  change bit s .rankAtGrant_up_to_date_inl = true → _ at signedAhead
  change bit s .rankAtGrant_up_to_date_inr = true → _ at signedTied
  have signed := frontier_signed_scan s
  have short := short_retained s
  have split := tied_splits s
  rw [retained_eq s, Bool.or_eq_true] at short
  change ((!(bit s .rankAtGrant_up_to_date_inl || bit s .rankAtGrant_term_inl ||
        bit s .rankAtGrant_term_inr || bit s .rankAtGrant_persist_inr) ||
      bit s .grantFactsBefore_supported_inl || bit s .grantFactsBefore_supported_inr) &&
    (!(bit s .rankAtGrant_up_to_date_inl || bit s .rankAtGrant_term_inl || bit s .rankAtGrant_term_inr) ||
      (bit s .maxCommittableIndexBounded_signature_pos &&
        (bit s .termAt_mono_eq_or_lt_of_le_inl || bit s .termAt_mono_eq_or_lt_of_le_inr))) &&
    (!bit s .maxCommittableIndexBounded_signature_pos || bit s .maxCommittableIndexBounded_values_cons) &&
    (!bit s .termAt_mono_eq_or_lt_of_le_inr || bit s .rankAtGrant_up_to_date_inl ||
      bit s .rankAtGrant_term_inl || bit s .rankAtGrant_term_inr)) = true
  simp only [Bool.and_eq_true, Bool.or_eq_true, Bool.not_eq_true', ← Bool.not_eq_true] at *
  repeat' apply And.intro
  all_goals grind only

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

public theorem upper_counts : upperPatterns.length = 1344 ∧ upperRows.length = 6048 := by
  decide +kernel

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
