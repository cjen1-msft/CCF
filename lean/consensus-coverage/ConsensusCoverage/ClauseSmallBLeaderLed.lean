module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ClauseSmallB
import ConsensusCoverage.ClauseSmallBMonotone
import all ConsensusCoverage.ClauseSmallB
import all ConsensusCoverage.ClauseMatchAck
import all ConsensusCoverage.ClauseQuestions
import all ConsensusCoverage.EventSupport
import all ConsensusCoverage.FrontierRows
import all ConsensusCoverage.HandReadersACampaign
import all ConsensusCoverage.HandReadersAPrimary
import all ConsensusCoverage.HandReadersAVoter
import all ConsensusCoverage.HandReadersAWin
import all ConsensusCoverage.PinnedLeader
import all ConsensusCoverage.ReadersRefuted
import all ConsensusCoverage.ReadersShapes
import all ConsensusCoverage.ReadersTotal
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.ClauseSmallB.LeaderLed

open Consensus Consensus.Proofs Safety SolvedWitnesses
open ClauseQuestions ClauseExactTables ActionProfile

set_option maxHeartbeats 0
set_option maxRecDepth 8192
set_option Elab.async false

public theorem columns : nonTrunk .leader_led =
  [.leader_led_now_after_inl, .leader_led_leader_inl, .leader_led_leader_inr,
    .wins_elect_committed_pos, .wins_elect_committed_neg, .campaign_three_campaign_inl,
    .campaign_three_campaign_inr, .campaign_votes_campaign_inl, .campaign_votes_campaign_inr,
    .campaign_votes_more_inl, .campaign_votes_more_inr, .facts_advance_inl_2,
    .facts_advance_inr_2, .facts_role_inl, .facts_role_inr,
    .maxCommittableIndexBounded_values_nil, .maxCommittableIndexBounded_values_cons,
    .maxCommittableIndexBounded_signature_pos, .maxCommittableIndexBounded_signature_neg,
    .termAt_mono_eq_zero_or_pos_inl, .termAt_mono_eq_zero_or_pos_inr,
    .termAt_mono_eq_or_lt_of_le_inl, .termAt_mono_eq_or_lt_of_le_inr,
    .vals_upToDate_lt_or_eq_of_le_inl, .vals_upToDate_lt_or_eq_of_le_inr] := by
  decide +kernel

private noncomputable abbrev bit (s : Step) (tag : Classes.StepBranch) := label s (.step tag)

section
variable [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t)

private theorem changed_split : sig c .leader_led_now_after_inl ↔
    sig c .leader_led_leader_inl ∨ sig c .leader_led_leader_inr := by
  constructor
  · rintro ⟨root, now, primary⟩
    obtain old | won := Summary.leader c.sum primary
    · exact .inl ⟨root, now, primary, now, old, old.1, old.2, now, primary⟩
    · exact .inr ⟨root, now, primary, now, won, now, primary⟩
  · rintro (⟨root, now, primary, _⟩ | ⟨root, now, primary, _⟩)
    all_goals exact ⟨root, now, primary⟩

private theorem wins_iff : sig c .leader_led_leader_inr ↔ Wins c.actor c.pre c.event c.post := by
  constructor
  · rintro ⟨_, _, _, _, won, _⟩
    exact won
  · intro won
    have ⟨primary, fresh⟩ := (ReadersShapes.wins_recorded c).mp won
    have change : ¬ Now f c.actor c.post := by
      intro old
      have same := c.now_pre old
      exact fresh ⟨same ▸ primary, congrArg Model.Node.NodeState.currentTerm same⟩
    exact ⟨⟨c.post_now, primary, fun old => change old.1, rfl⟩, c.post_now, primary,
      c.post_now, won, c.post_now, primary⟩

private theorem leader_disjoint (old : sig c .leader_led_leader_inl) :
    ¬ sig c .leader_led_leader_inr := by
  have base : c.pre.role = .primary ∧ c.post.currentTerm = c.pre.currentTerm := by
    obtain ⟨_, _, _, _, h, _⟩ := old
    exact h
  exact fun won => ((ReadersShapes.wins_recorded c).mp ((wins_iff c).mp won)).2 base

private theorem vote_implies_campaign (fresh : Bool)
    (vote : sig c (HandReadersA.CampaignRows.column true fresh)) :
    sig c (HandReadersA.CampaignRows.column false fresh) := by
  obtain ⟨guard, local_ | won⟩ := HandReadersA.CampaignRows.necessary c true fresh vote
  · exact HandReadersA.CampaignRows.sufficient c false fresh guard (.inl ⟨local_.1, local_.2.1, by simp⟩)
  · exact HandReadersA.CampaignRows.sufficient c false fresh guard (.inr won)

private theorem fresh_campaign_votes :
    sig c .campaign_three_campaign_inl ↔ sig c .campaign_votes_campaign_inl := by
  constructor
  · intro h
    obtain ⟨guard, local_ | won⟩ := HandReadersA.CampaignRows.necessary c false true h
    · obtain ⟨_, _, _, fresh | old⟩ := Summary.candidate c.sum local_.2.1
      · apply HandReadersA.CampaignRows.sufficient c true true guard
        refine .inl ⟨local_.1, local_.2.1, fun _ => ?_⟩
        rw [fresh.2.2.2]
        exact ⟨c.actor, CCF.Finset.mem_singleton.mpr rfl⟩
      · have lt := of_decide_eq_true guard
        have same := old.2.1
        omega
    · exact HandReadersA.CampaignRows.sufficient c true true guard (.inr won)
  · exact vote_implies_campaign c true

private theorem campaigns_disjoint (fresh : sig c .campaign_votes_campaign_inl) :
    ¬ sig c .campaign_three_campaign_inr := by
  intro old
  have yes := (HandReadersA.CampaignRows.necessary c true true fresh).1
  have no := (HandReadersA.CampaignRows.necessary c false false old).1
  exact Bool.noConfusion (no.symm.trans yes)

private theorem wins_campaign (won : sig c .leader_led_leader_inr) :
    sig c .campaign_votes_campaign_inl ∨ sig c .campaign_votes_campaign_inr := by
  have won := (wins_iff c).mp won
  cases h : decide (c.pre.currentTerm < c.post.currentTerm)
  · exact .inr (HandReadersA.CampaignRows.sufficient c true false h (.inr won))
  · exact .inl (HandReadersA.CampaignRows.sufficient c true true h (.inr won))

private theorem more_campaign (old : Bool) (more : sig c (HandReadersA.Voter.column old)) :
    sig c .campaign_votes_campaign_inr := by
  obtain ⟨same, evidence⟩ := HandReadersA.Voter.necessary c old more
  have guard : decide (c.pre.currentTerm < c.post.currentTerm) = false := by simp [same]
  apply HandReadersA.CampaignRows.sufficient c true false guard
  rcases evidence with local_ | won
  · obtain ⟨fresh, candidate, n, mem, _⟩ := local_
    exact .inl ⟨fresh, candidate, fun _ => ⟨n, mem⟩⟩
  · exact .inr won.1

private theorem win_commit (pos : Bool) : sig c (HandReadersA.Win.column pos) ↔
    sig c .leader_led_leader_inr ∧ decide (0 < c.pre.commitIndex) = pos := by
  rw [HandReadersA.Win.iff_test, HandReadersA.Win.test, decide_eq_true_eq,
    wins_iff c, ReadersShapes.wins_recorded c, and_assoc]

end

private def pack (v : List Bool) : List Bool :=
  let get := fun i => v[i]?.getD false
  let old := get 0
  let won := get 1
  let fresh := get 4
  [old || won, old, won, get 2, get 3, fresh, get 5, fresh, get 6, get 7, get 8, won,
    false, false, false, get 9, get 10, get 11, get 10, false,
    get 12 || get 13, get 12, get 13, false, get 14]

private def selected : List Classes.StepBranch :=
  [.leader_led_leader_inl, .leader_led_leader_inr, .wins_elect_committed_pos, .wins_elect_committed_neg,
    .campaign_votes_campaign_inl, .campaign_three_campaign_inr, .campaign_votes_campaign_inr,
    .campaign_votes_more_inl, .campaign_votes_more_inr, .maxCommittableIndexBounded_values_nil,
    .maxCommittableIndexBounded_values_cons, .maxCommittableIndexBounded_signature_pos,
    .termAt_mono_eq_or_lt_of_le_inl, .termAt_mono_eq_or_lt_of_le_inr, .vals_upToDate_lt_or_eq_of_le_inr]

private theorem shape (s : Step) : (nonTrunkLabel .leader_led s).bits = pack (selected.map (bit s)) := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  have test (tag : Classes.StepBranch) := (label_true s (.step tag)).trans (sig_iff s.context tag)
  have eq {a x : Classes.StepBranch} (h : sig s.context a ↔ sig s.context x) :
      bit s a = bit s x := Bool.eq_iff_iff.mpr ((test a).trans (h.trans (test x).symm))
  have split : bit s .leader_led_now_after_inl =
      (bit s .leader_led_leader_inl || bit s .leader_led_leader_inr) :=
    Bool.eq_iff_iff.mpr ((test _).trans ((changed_split _).trans
      ((or_congr (test _).symm (test _).symm).trans Bool.or_eq_true_iff.symm)))
  have no (k : Classes.StepBranch) (h : ReadersRefuted.read? k = some false) :=
    ReadersRefuted.read?_correct s h
  have won : sig s.context .facts_advance_inl_2 ↔ sig s.context .leader_led_leader_inr :=
    (HandReadersA.Primary.identity_iff s.context).trans (wins_iff s.context).symm
  simp only [nonTrunkLabel, restrictedLabel, columns, selected, List.map_cons, List.map_nil, pack,
    List.getElem?_cons_zero, List.getElem?_cons_succ, Option.getD_some, split,
    eq (fresh_campaign_votes s.context), eq won, term_mono_split, ← frontier_scan_unsigned s,
    no .facts_advance_inr_2 (by decide +kernel),
    no .facts_role_inl (by decide +kernel), no .facts_role_inr (by decide +kernel),
    no .termAt_mono_eq_zero_or_pos_inl (by decide +kernel),
    no .vals_upToDate_lt_or_eq_of_le_inl (by decide +kernel)]

private def valid (v : List Bool) : Bool :=
  let get := fun i => v[i]?.getD false
  !(get 0 && get 1) && !(get 4 && get 5) && (!get 6 || get 5) &&
    (!get 1 || get 4 || get 6) && (!(get 7 || get 8) || get 6) &&
    (!(get 2 && get 3)) && (get 1 == (get 2 || get 3)) && (!get 11 || get 10)

private theorem valid_all (s : Step) : valid (selected.map (bit s)) = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  have test (tag : Classes.StepBranch) := (label_true s (.step tag)).trans (sig_iff s.context tag)
  have one := leader_disjoint s.context
  have two := campaigns_disjoint s.context
  have votes := vote_implies_campaign s.context false
  change sig s.context .campaign_votes_campaign_inr → sig s.context .campaign_three_campaign_inr at votes
  have won := wins_campaign s.context
  have prev := more_campaign s.context true
  have new := more_campaign s.context false
  change sig s.context .campaign_votes_more_inl → _ at prev
  change sig s.context .campaign_votes_more_inr → _ at new
  have pos := win_commit s.context true
  have neg := win_commit s.context false
  have signed := frontier_signed_scan s
  change sig s.context .wins_elect_committed_pos ↔ _ at pos
  change sig s.context .wins_elect_committed_neg ↔ _ at neg
  have cuts (a b : Bool) : (a == b) = true ↔ (a = true ↔ b = true) := by
    cases a <;> cases b <;> decide
  simp only [test] at signed
  simp only [valid, selected, List.map_cons, List.map_nil, List.getElem?_cons_zero,
    List.getElem?_cons_succ, Option.getD_some, Bool.and_eq_true, Bool.or_eq_true,
    Bool.not_eq_true', ← Bool.not_eq_true, cuts, test]
  grind only

public def upperPatterns : List (List Bool) := ((vectors 15).filter valid).map pack

public theorem patterns_complete (s : Step) : (nonTrunkLabel .leader_led s).bits ∈ upperPatterns := by
  rw [shape]
  exact List.mem_map_of_mem (List.mem_filter.mpr ⟨vector_mem _, valid_all s⟩)

private theorem wins_diagonal (s : Step) (h : bit s .leader_led_leader_inr = true) :
    (endpoints s).1 = (endpoints s).2 := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  have win := (wins_iff s.context).mp
    (((label_true s (.step .leader_led_leader_inr)).trans (sig_iff s.context _)).mp h)
  have primary := ((ReadersShapes.wins_recorded s.context).mp win).1
  have new := PinnedLeader.wins_newPrimary s.context primary win
  rw [show s.frame.current = s.before from s.current_eq] at new
  have finite : ∀ r ∈ FrontierRows.table, r.wonPrimary = true →
      (r.zeroBefore, r.backedBefore) = (r.zeroAfter, r.backedAfter) := by decide +kernel
  exact finite _ (FrontierRows.complete s.run s.ran) new

public def upperRows : List RestrictedProfile :=
  endpointRows.flatMap fun e =>
    (upperPatterns.filter fun bs => !(bs[2]?.getD false) || decide (e.1 = e.2)).map (row e)

public theorem complete (s : Step) : nonTrunkLabel .leader_led s ∈ upperRows := by
  change row (endpoints s) (nonTrunkLabel .leader_led s).bits ∈ upperRows
  refine List.mem_flatMap.mpr ⟨_, endpoints_mem s, List.mem_map_of_mem (List.mem_filter.mpr
    ⟨patterns_complete s, ?_⟩)⟩
  rw [shape]
  change (!bit s .leader_led_leader_inr || decide ((endpoints s).1 = (endpoints s).2)) = true
  cases h : bit s .leader_led_leader_inr
  · rfl
  · simp [wins_diagonal s h]

private def picks : List Pick :=
  [(row (z, p) (bits "1100000000000000000000000"), 0, 0),
    (row (p, p) (bits "1100000000000000000000000"), 0, 1),
    (row (z, b) (bits "1100000000000000000000000"), 1, 0),
    (row (z, z) (bits "1100000000000000000000000"), 2, 0),
    (row (z, b) (bits "0000000000000001101000000"), 2, 2),
    (row (b, b) (bits "1100000000000000000000000"), 2, 3),
    (row (b, b) (bits "0000000000000000000000000"), 2, 4),
    (row (b, p) (bits "0000000000000001111000000"), 2, 5),
    (row (z, z) (bits "0000000000000000000000000"), 3, 1),
    (row (z, z) (bits "0000010100000001111011001"), 3, 4),
    (row (z, z) (bits "1010101011110001111011000"), 3, 6),
    (row (p, p) (bits "1011001011110001111011000"), 4, 12),
    (row (p, p) (bits "1011010100010001111011001"), 168, 5)]

public def rows : List RestrictedProfile := picks.map Prod.fst

public def patterns : List (List Bool) := patternsOf rows

public def unresolvedRows : List RestrictedProfile := unresolved upperRows rows

public theorem covered_or_unresolved (s : Step) :
    nonTrunkLabel .leader_led s ∈ rows ∨ nonTrunkLabel .leader_led s ∈ unresolvedRows :=
  witnessed_or_unresolved (complete s)

public theorem counts : rows.Nodup ∧ rows.length = 13 ∧ patterns.Nodup ∧ patterns.length = 8 := by
  decide +kernel

private theorem picked : picks.all (checkPick .leader_led) = true :=
  all_split 8 (by decide +kernel) (by decide +kernel)

public theorem lower (r : RestrictedProfile) (mem : r ∈ rows) :
    ∃ s, nonTrunkLabel .leader_led s = r :=
  replay_picks (covered_of_check (by decide +kernel)) picked mem

public theorem patterns_lower (bs : List Bool) (mem : bs ∈ patterns) :
    ∃ s, (nonTrunkLabel .leader_led s).bits = bs :=
  pattern_witness lower mem

end ConsensusCoverage.ClauseSmallB.LeaderLed
