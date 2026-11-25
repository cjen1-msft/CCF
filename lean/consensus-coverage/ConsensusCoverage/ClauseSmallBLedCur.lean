module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ClauseSmallB
import all ConsensusCoverage.ClauseMatchAck
import all ConsensusCoverage.ClauseQuestions
import all ConsensusCoverage.ClauseSmallB
import all ConsensusCoverage.CaseUnreachable
import all ConsensusCoverage.DeepElectionCases
import all ConsensusCoverage.FrontierRows
import all ConsensusCoverage.HandReadersAElection
import all ConsensusCoverage.HandReadersElectionBFind
import all ConsensusCoverage.HandReadersElectionBLed
import all ConsensusCoverage.HandReadersElectionTables
import all ConsensusCoverage.PinnedLeader
import all ConsensusCoverage.ReadersRefuted
import all ConsensusCoverage.ReadersTotal
import all ConsensusCoverage.ReadersCorpus
import all ConsensusCoverage.JointWitnesses
import all ConsensusCoverage.FrontierWitnesses
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
meta import ConsensusCoverage.ReachPath

namespace ConsensusCoverage.ClauseSmallB.LedCur

open Consensus Consensus.Proofs Safety SolvedWitnesses
open ClauseQuestions ClauseExactTables ActionProfile

set_option maxHeartbeats 0
set_option maxRecDepth 8192
set_option Elab.async false
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

public theorem columns : nonTrunk .led_cur =
    [.led_cur_now_after_inl, .led_cur_led_after_inl, .led_cur_led_cur_inl,
     .led_cur_led_cur_inr, .led_cur_lt_or_eq_of_le_inl, .led_cur_lt_or_eq_of_le_inr,
     .led_cur_led_after_inr, .led_cur_role_inl, .led_cur_role_inr, .led_cur_now_after_inr,
     .led_after_led_inl, .led_after_led_inr, .led_after_elected_after_inl,
     .led_after_elected_after_inr, .find_of_mem_here_pos, .find_of_mem_here_neg] :=
  by decide +kernel

section
variable [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t)

private abbrev Fresh := ¬ Now f c.actor c.post
private abbrev Older := ∃ k, Led f c.actor k ∧ k < c.pre.currentTerm
private abbrev Current := Led f c.actor c.pre.currentTerm
private abbrev Election := ElectStep f t c.actor c.post.currentTerm c.pre.log c.pre.commitIndex

private theorem site {k} (led : Led (f.advance t) c.actor k) (fresh : Fresh c) :
    (reach% step_led_cur_now_after_inl[0]) f t c c c.actor c.post k :=
  ⟨c.post_now, led, fun old => fresh old.1, rfl⟩

private theorem election_fresh (elect : Election c) : Fresh c := by
  intro old
  have same := c.now_pre old
  obtain ⟨_, _, _, lt | ⟨_, candidate⟩, _, role, _⟩ := c.electStep elect
  · rw [← same] at lt
    exact Nat.lt_irrefl _ lt
  · rw [same, candidate] at role
    rcases role with role | role <;> contradiction

private theorem elect_current {k l i} (elect : ElectStep f t c.actor k l i) : Election c := by
  obtain ⟨_, log, idx, _, term, _⟩ := c.electStep elect
  simpa only [Election, log, idx, term] using elect

private theorem earlier_iff : sig c .led_cur_led_cur_inl ↔ Fresh c ∧ Older c := by
  constructor
  · rintro ⟨k, enter, _, _, _, led, lt, _⟩
    exact ⟨fun old => enter.2.2.1 ⟨old, led⟩, k, led, lt⟩
  · rintro ⟨fresh, k, led, lt⟩
    have next := led.mono t
    exact ⟨k, site c next fresh, c.post_now, next, c.post_now, led, lt, c.post_now, next, c.term_le⟩

private theorem current_iff : sig c .led_cur_led_cur_inr ↔ Fresh c ∧ Current c := by
  constructor
  · rintro ⟨enter, _, _, _, led, _⟩
    exact ⟨fun old => enter.2.2.1 ⟨old, led⟩, led⟩
  · rintro ⟨fresh, led⟩
    have next := led.mono t
    have nc : c.pre.role ≠ .candidate := by
      obtain lt | ⟨_, nc⟩ := c.inv.led_cur _ _ _ c.pre_now led
      · exact (Nat.lt_irrefl _ lt).elim
      · exact nc
    exact ⟨site c next fresh, c.post_now, next, c.post_now, led, nc, nc, c.post_now, next, c.term_le⟩

private theorem rises_iff : sig c .led_cur_lt_or_eq_of_le_inl ↔
    sig c .led_cur_led_cur_inr ∧ c.pre.currentTerm < c.post.currentTerm := by
  constructor
  · rintro ⟨reach, now, led, now', old, nc, nc', lt, h⟩
    exact ⟨⟨reach, now, led, now', old, nc, nc', h⟩, lt⟩
  · rintro ⟨⟨reach, now, led, now', old, nc, nc', h⟩, lt⟩
    exact ⟨reach, now, led, now', old, nc, nc', lt, h⟩

private theorem same_iff : sig c .led_cur_lt_or_eq_of_le_inr ↔
    sig c .led_cur_led_cur_inr ∧ c.pre.currentTerm = c.post.currentTerm := by
  constructor
  · rintro ⟨reach, now, led, now', old, nc, nc', eq, h⟩
    exact ⟨⟨reach, now, led, now', old, nc, nc', h⟩, eq⟩
  · rintro ⟨⟨reach, now, led, now', old, nc, nc', h⟩, eq⟩
    exact ⟨reach, now, led, now', old, nc, nc', eq, h⟩

private theorem old_iff : sig c .led_cur_led_after_inl ↔
    sig c .led_cur_led_cur_inl ∨ sig c .led_cur_led_cur_inr := by
  rw [earlier_iff, current_iff]
  constructor
  · rintro ⟨k, enter, _, _, _, led, _⟩
    have fresh : Fresh c := fun old => enter.2.2.1 ⟨old, led⟩
    obtain lt | ⟨eq, _⟩ := c.inv.led_cur _ _ _ c.pre_now led
    · exact .inl ⟨fresh, k, led, lt⟩
    · rw [eq] at led
      exact .inr ⟨fresh, led⟩
  · rintro (⟨fresh, k, led, _⟩ | ⟨fresh, led⟩)
    all_goals
      have next := led.mono t
      exact ⟨_, site c next fresh, c.post_now, next, c.post_now, led, c.post_now, next⟩

private theorem new_iff : sig c .led_cur_led_after_inr ↔ Election c := by
  constructor
  · rintro ⟨_, _, _, _, _, ⟨_, _, elect⟩, _⟩
    exact elect_current c elect
  · intro elect
    have led : Led (f.advance t) c.actor c.post.currentTerm :=
      .inr ⟨_, _, .inr ⟨f.current, rfl, elect⟩⟩
    exact ⟨_, site c led (election_fresh c elect), c.post_now, led, c.post_now,
      ⟨_, _, elect⟩, _, ⟨_, elect⟩, _, elect, c.post_now, led⟩

private theorem now_iff : sig c .led_cur_now_after_inl ↔
    sig c .led_cur_led_after_inl ∨ sig c .led_cur_led_after_inr := by
  constructor
  · rintro ⟨k, enter, now, led⟩
    obtain old | fresh := c.led_after led
    · exact .inl ⟨k, enter, now, led, now, old, now, led⟩
    · obtain ⟨_, _, h⟩ := fresh
      exact .inr ((new_iff c).mpr (elect_current c h))
  · rintro (⟨k, enter, now, led, _⟩ | ⟨k, enter, now, led, _⟩)
    all_goals exact ⟨k, enter, now, led⟩

private theorem current_split : sig c .led_cur_led_cur_inr ↔
    sig c .led_cur_lt_or_eq_of_le_inl ∨ sig c .led_cur_lt_or_eq_of_le_inr := by
  rw [rises_iff, same_iff]
  have term := Nat.lt_or_eq_of_le c.term_le
  grind only

private theorem split_disjoint : sig c .led_cur_lt_or_eq_of_le_inl →
    ¬ sig c .led_cur_lt_or_eq_of_le_inr := by
  rw [rises_iff, same_iff]
  grind only

private theorem finds (h : sig c .led_cur_now_after_inl) : sig c .find_of_mem_here_pos := by
  apply HandReadersElectionB.Find.sufficient c
  left
  obtain old | new := (now_iff c).mp h
  · obtain earlier | current := (old_iff c).mp old
    · exact ((earlier_iff c).mp earlier).1
    · exact ((current_iff c).mp current).1
  · exact election_fresh c ((new_iff c).mp new)

private theorem elections_split : sig c .led_after_led_inr ↔
    sig c .led_after_elected_after_inl ∨ sig c .led_cur_led_after_inr := by
  have old := HandReadersElectionB.LedRows.vote_iff c true
  have either := HandReadersElectionB.LedRows.vote_iff c false
  change sig c .led_after_elected_after_inl ↔ _ at old
  change sig c .led_after_led_inr ↔ _ at either
  rw [either]
  constructor
  · rintro ⟨n, k, l, i, site, elect⟩
    obtain prior | new := c.elected_after elect
    · exact .inl (old.mpr ⟨n, k, l, i, site, prior⟩)
    · obtain ⟨rfl, _, _, _, _⟩ := c.electStep new
      exact .inr ((new_iff c).mpr (elect_current c new))
  · rintro (previous | new)
    · obtain ⟨n, k, l, i, site, elect⟩ := old.mp previous
      exact ⟨n, k, l, i, site, Or.inl elect⟩
    · exact either.mp (DeepElectionCases.electedLed c new)

private theorem new_requested : sig c .led_after_elected_after_inr ↔ sig c .led_cur_led_after_inr :=
  (HandReadersA.Election.iff_election c).trans (new_iff c).symm

private theorem old_origin (h : sig c .led_cur_led_after_inl) :
    sig c .led_after_led_inl ∨ sig c .led_after_elected_after_inl := by
  obtain ⟨k, root, now, led, _, prior, _, _⟩ := h
  have origin : (reach% step_led_after_led_inr[0]) f t c c.actor k :=
    .inl ⟨root, now, led, now, now, led, rfl⟩
  obtain ⟨node, term⟩ | ⟨l, i, elected⟩ := prior
  · rw [node, term] at origin led
    exact .inl (.inl ⟨origin, led⟩)
  · exact .inr ((HandReadersElectionB.LedRows.vote_iff c true).mpr
      ⟨c.actor, k, l, i, .inl origin, elected⟩)

private theorem multiple_terms_elected (earlier : sig c .led_cur_led_cur_inl)
    (current : sig c .led_cur_led_cur_inr) : sig c .led_after_elected_after_inl := by
  obtain ⟨_, k, lead, lt⟩ := (earlier_iff c).mp earlier
  obtain ⟨fresh, cur⟩ := (current_iff c).mp current
  obtain ⟨boot, _⟩ | ⟨l, i, elect⟩ := cur
  · have floor := c.inv.leader_floor lead
    change _ = 2 at boot
    omega
  · have led : Led (f.advance t) c.actor c.pre.currentTerm := .inr ⟨l, i, .inl elect⟩
    have now := c.post_now
    have origin : (reach% step_led_after_led_inr[0]) f t c c.actor c.pre.currentTerm :=
      .inl ⟨site c led fresh, now, led, now, now, led, rfl⟩
    exact (HandReadersElectionB.LedRows.vote_iff c true).mpr
      ⟨c.actor, c.pre.currentTerm, l, i, .inl origin, elect⟩

private theorem new_excludes_same (new : sig c .led_cur_led_after_inr) :
    ¬ sig c .led_cur_lt_or_eq_of_le_inr := by
  intro stable
  obtain ⟨valid, eq⟩ := (same_iff c).mp stable
  obtain ⟨_, _, _, lt | ⟨_, candidate⟩, _, _, _⟩ := c.electStep ((new_iff c).mp new)
  · exact (Nat.ne_of_lt lt) eq
  · obtain ⟨_, _, _, _, _, nc, _⟩ := valid
    exact nc candidate

private theorem election_role (elect : Election c) : c.post.role = .primary := by
  obtain primary | gone := (c.electStep elect).2.2.2.2.2.1
  · exact primary
  · exfalso
    rcases RetiredRoleOrigin.step c gone with ⟨role, term⟩ | ⟨_, pos, bound, atJ⟩ |
        ⟨_, _, arrived, same⟩
    · rcases (c.electStep elect).2.2.2.1 with fresh | ⟨_, candidate⟩
      · omega
      · simp [role] at candidate
    · exact CaseUnreachable.no_election_entry c elect pos bound atJ
    · obtain ⟨_, ok, _, _, payload⟩ := c.received_ok arrived
      simp only [MessageOK, payload] at ok
      obtain ⟨_, evidence⟩ := ok
      exact CaseUnreachable.no_repeat_election c elect (same ▸ evidence.led)

private theorem role_iff : sig c .led_cur_role_inl ↔ sig c .led_cur_led_after_inr := by
  rw [new_iff]
  constructor
  · rintro ⟨_, _, _, _, _, _, elect, _⟩
    exact elect
  · intro elect
    obtain ⟨_, _, _, term, _, role, pref, floor⟩ := c.electStep elect
    have led : Led (f.advance t) c.actor c.post.currentTerm :=
      .inr ⟨_, _, .inr ⟨f.current, rfl, elect⟩⟩
    have primary := election_role c elect
    refine ⟨site c led (election_fresh c elect), c.post_now, led, c.post_now,
      ⟨_, _, elect⟩, ⟨_, elect⟩, elect, ?_⟩
    repeat' first | assumption | exact c.post_now | apply And.intro

end

private noncomputable abbrev bit (s : Step) (tag : Classes.StepBranch) := label s (.step tag)

private def pack (earlier rises same elected bootstrap previous finds : Bool) : List Bool :=
  let current := rises || same
  let old := earlier || current
  [old || elected, old, earlier, current, rises, same, elected, elected, false, false,
    bootstrap, previous || elected, previous, elected, finds, finds]

private theorem shape (s : Step) :
    (nonTrunkLabel .led_cur s).bits =
      pack (bit s .led_cur_led_cur_inl) (bit s .led_cur_lt_or_eq_of_le_inl)
        (bit s .led_cur_lt_or_eq_of_le_inr) (bit s .led_cur_led_after_inr)
        (bit s .led_after_led_inl) (bit s .led_after_elected_after_inl)
        (bit s .find_of_mem_here_pos) := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  have test (tag : Classes.StepBranch) := (label_true s (.step tag)).trans (sig_iff s.context tag)
  have disj {a x y : Classes.StepBranch} (h : sig s.context a ↔ sig s.context x ∨ sig s.context y) :
      bit s a = (bit s x || bit s y) :=
    Bool.eq_iff_iff.mpr ((test a).trans (h.trans
      ((or_congr (test x).symm (test y).symm).trans Bool.or_eq_true_iff.symm)))
  have eq {a x : Classes.StepBranch} (h : sig s.context a ↔ sig s.context x) :
      bit s a = bit s x := Bool.eq_iff_iff.mpr ((test a).trans (h.trans (test x).symm))
  have no (b : Classes.StepBranch) (h : ReadersRefuted.read? b = some false) :=
    ReadersRefuted.read?_correct s h
  simp only [nonTrunkLabel, restrictedLabel, columns, List.map_cons, List.map_nil, pack,
    disj (now_iff s.context), disj (old_iff s.context), disj (current_split s.context),
    disj (elections_split s.context), eq (new_requested s.context), eq (role_iff s.context),
    ← HandReadersElection.Tables.find_arms_eq s,
    no .led_cur_role_inr (by decide +kernel), no .led_cur_now_after_inr (by decide +kernel)]

private theorem new_diagonal (s : Step) (yes : bit s .led_cur_led_after_inr = true) :
    (endpoints s).1 = (endpoints s).2 := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  have elect := (new_iff c).mp
    (((label_true s (.step .led_cur_led_after_inr)).trans (sig_iff c _)).mp yes)
  obtain ⟨pre, same⟩ | wins := Summary.leader c.sum (election_role c elect)
  · obtain ⟨_, _, _, fresh | ⟨_, cand⟩, _, _, _⟩ := c.electStep elect
    · omega
    · rw [pre] at cand
      contradiction
  · have new := PinnedLeader.wins_newPrimary c (election_role c elect) wins
    rw [show s.frame.current = s.before from s.current_eq] at new
    have finite : ∀ r ∈ FrontierRows.table, r.wonPrimary = true →
        (r.zeroBefore, r.backedBefore) = (r.zeroAfter, r.backedAfter) := by decide +kernel
    exact finite _ (FrontierRows.complete s.run s.ran) new

private def valid (earlier rises same elected bootstrap previous finds : Bool) : Bool :=
  !(rises && same) && !(elected && same) &&
    (!(earlier || rises || same) || (bootstrap || previous)) &&
    (!(earlier || rises || same || elected) || finds) &&
    (!(earlier && (rises || same)) || previous)

private theorem valid_all (s : Step) :
    valid (bit s .led_cur_led_cur_inl) (bit s .led_cur_lt_or_eq_of_le_inl)
      (bit s .led_cur_lt_or_eq_of_le_inr) (bit s .led_cur_led_after_inr)
      (bit s .led_after_led_inl) (bit s .led_after_elected_after_inl)
      (bit s .find_of_mem_here_pos) = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  have test (tag : Classes.StepBranch) := (label_true s (.step tag)).trans (sig_iff s.context tag)
  simp only [valid, Bool.and_eq_true, Bool.or_eq_true, Bool.not_eq_true', ← Bool.not_eq_true, test]
  have split := split_disjoint s.context
  have ban := new_excludes_same s.context
  have old := (old_iff s.context)
  have cur := (current_split s.context)
  have origin := old_origin s.context
  have now := (now_iff s.context)
  have find := finds s.context
  have multi := multiple_terms_elected s.context
  grind only

private def fiber (e : Endpoints) : List RestrictedProfile :=
  booleans.flatMap fun earlier =>
  booleans.flatMap fun rises =>
  booleans.flatMap fun same =>
  booleans.flatMap fun elected =>
  booleans.flatMap fun bootstrap =>
  booleans.flatMap fun previous =>
  booleans.flatMap fun finds =>
  if valid earlier rises same elected bootstrap previous finds &&
    ((!elected && finds) || decide (e.1 = e.2)) then
    [row e (pack earlier rises same elected bootstrap previous finds)]
  else []

public def upperRows : List RestrictedProfile := endpointRows.flatMap fiber

public def upperPatterns : List (List Bool) := patternsOf upperRows

public theorem upper_counts : upperPatterns.Nodup ∧ upperPatterns.length = 33 ∧
    upperRows.Nodup ∧ upperRows.length = 150 := by decide +kernel

public theorem complete (s : Step) : nonTrunkLabel .led_cur s ∈ upperRows := by
  change row (endpoints s) (nonTrunkLabel .led_cur s).bits ∈ upperRows
  rw [shape]
  apply List.mem_flatMap.mpr
  refine ⟨_, endpoints_mem s, ?_⟩
  have diag : ((!bit s .led_cur_led_after_inr && bit s .find_of_mem_here_pos) ||
      decide ((endpoints s).1 = (endpoints s).2)) = true := by
    cases elect : bit s .led_cur_led_after_inr <;> cases found : bit s .find_of_mem_here_pos
    · simp [lookup_false_diagonal s found]
    · rfl
    · simp [new_diagonal s elect]
    · simp [new_diagonal s elect]
  unfold fiber
  refine List.mem_flatMap.mpr ⟨_, bool_mem (bit s .led_cur_led_cur_inl), ?_⟩
  refine List.mem_flatMap.mpr ⟨_, bool_mem (bit s .led_cur_lt_or_eq_of_le_inl), ?_⟩
  refine List.mem_flatMap.mpr ⟨_, bool_mem (bit s .led_cur_lt_or_eq_of_le_inr), ?_⟩
  refine List.mem_flatMap.mpr ⟨_, bool_mem (bit s .led_cur_led_after_inr), ?_⟩
  refine List.mem_flatMap.mpr ⟨_, bool_mem (bit s .led_after_led_inl), ?_⟩
  refine List.mem_flatMap.mpr ⟨_, bool_mem (bit s .led_after_elected_after_inl), ?_⟩
  refine List.mem_flatMap.mpr ⟨_, bool_mem (bit s .find_of_mem_here_pos), ?_⟩
  rw [valid_all, diag]
  exact List.mem_cons_self

public theorem patterns_complete (s : Step) :
    (nonTrunkLabel .led_cur s).bits ∈ upperPatterns :=
  List.mem_eraseDups.mpr (List.mem_map_of_mem (complete s))

private def picks : List Pick :=
  [(row (z, p) (bits "1101010000100011"), 0, 0),
    (row (p, p) (bits "1101010000100011"), 0, 1),
    (row (z, b) (bits "1101010000100011"), 1, 0),
    (row (z, z) (bits "1101010000100011"), 2, 0),
    (row (z, b) (bits "0000000000000011"), 2, 2),
    (row (b, b) (bits "1101010000100011"), 2, 3),
    (row (b, b) (bits "0000000000100000"), 2, 4),
    (row (b, p) (bits "0000000000000011"), 2, 5),
    (row (z, z) (bits "0000000000000000"), 3, 3),
    (row (z, z) (bits "1101100000100011"), 3, 4),
    (row (z, z) (bits "0000000000000011"), 3, 5),
    (row (z, z) (bits "1110001100110111"), 3, 6),
    (row (p, p) (bits "0000000000000000"), 4, 6),
    (row (p, p) (bits "0000000000000011"), 4, 8),
    (row (p, p) (bits "1101100000100011"), 4, 11),
    (row (p, p) (bits "1000001100010111"), 4, 12),
    (row (b, b) (bits "0000000000000011"), 5, 5),
    (row (b, b) (bits "0000000000000000"), 5, 6),
    (row (b, b) (bits "1101100000100011"), 5, 11),
    (row (b, b) (bits "1000001100010111"), 5, 12),
    (row (b, b) (bits "1101010000011011"), 6, 10),
    (row (b, b) (bits "1110000000100011"), 6, 12),
    (row (b, p) (bits "1101010000011011"), 6, 15),
    (row (z, z) (bits "0000000000100000"), 18, 0),
    (row (p, p) (bits "0000000000100000"), 25, 8),
    (row (p, p) (bits "1000001100110111"), 168, 5),
    (row (b, b) (bits "1000001100110111"), 214, 9),
    (row (b, b) (bits "1101010000111011"), 214, 10)]

private def extraStep (i depth node : Nat) : Option Step := do
  let input ← ReadersCorpus.schedules[i]?
  let run := {input.run with schedule := input.run.schedule.take depth ++
    [.input node (.append [{content := .signature}])]}
  let ss ← JointWitnesses.recordedAt run input.valid input.choices
  return (← ss.getLast?).val

private def extraRows : List RestrictedProfile :=
  [row (z, z) (bits "1111010000111011"), row (p, p) (bits "1101010000011011"),
    row (p, p) (bits "1101010000111011")]

private def extraSteps : List Step :=
  [(3, 7, 0), (4, 13, 1), (168, 6, 1)].filterMap fun (i, depth, node) => extraStep i depth node

public def rows : List RestrictedProfile := picks.map Prod.fst ++ extraRows

public def patterns : List (List Bool) := patternsOf rows

public def unresolvedRows : List RestrictedProfile := unresolved upperRows rows

public theorem covered_or_unresolved (s : Step) :
    nonTrunkLabel .led_cur s ∈ rows ∨ nonTrunkLabel .led_cur s ∈ unresolvedRows :=
  witnessed_or_unresolved (complete s)

public theorem counts : rows.Nodup ∧ rows.length = 31 ∧ patterns.Nodup ∧ patterns.length = 12 := by
  decide +kernel

private theorem picked : picks.all (checkPick .led_cur) = true := by
  exact all_split 14 (by decide +kernel) (by decide +kernel)

public theorem lower (r : RestrictedProfile) (mem : r ∈ rows) :
    ∃ s, nonTrunkLabel .led_cur s = r := by
  have covered := covered_of_check (c := .led_cur) (by decide +kernel)
  rcases List.mem_append.mp mem with fromCorpus | extra
  · exact replay_picks covered picked fromCorpus
  · exact witnessed covered (steps := extraSteps) (by decide +kernel) extra

public theorem patterns_lower (bs : List Bool) (mem : bs ∈ patterns) :
    ∃ s, (nonTrunkLabel .led_cur s).bits = bs :=
  pattern_witness lower mem

end ConsensusCoverage.ClauseSmallB.LedCur
