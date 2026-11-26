module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ClauseMatchAck
public import ConsensusCoverage.ReadersCorpus
import all ConsensusCoverage.ActorLogRows
import all ConsensusCoverage.BackingStutter
import all ConsensusCoverage.ClauseExactTables
import all ConsensusCoverage.ClauseMatchAck
import all ConsensusCoverage.ClauseQuestions
import all ConsensusCoverage.EventSupport
import all ConsensusCoverage.HandReadersAPrimary
import all ConsensusCoverage.HandReadersOtherFacts
import all ConsensusCoverage.InertProfile
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.ReadersCorpus
import all ConsensusCoverage.ReadersGenerated
import all ConsensusCoverage.ReadersTotal
import all ConsensusCoverage.SignedQuiet
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.ClauseLogCluster

open ActionProfile ClauseQuestions ClauseExactTables
open Consensus Consensus.Proofs Consensus.Proofs.Safety

set_option maxRecDepth 8192
set_option maxHeartbeats 0

public def clauses : List Clause := [.sorted, .terms, .anchor, .rooted, .copyLogs]

public def nonTrunk (c : Clause) := ClauseMatchAck.nonTrunk c

public noncomputable def nonTrunkLabel (c : Clause) (s : Step) :=
  restrictedLabel (nonTrunk c) s

public theorem column_counts : clauses.map (fun c => (nonTrunk c).length) = [37,39,39,39,59] :=
  by decide +kernel

public theorem columns_in_copyLogs {c : Clause} (hc : c ∈ clauses) {b : Classes.StepBranch}
    (hb : b ∈ nonTrunk c) : b ∈ nonTrunk .copyLogs := by
  have all : clauses.all (fun c => (nonTrunk c).all (nonTrunk .copyLogs).contains) = true :=
    by decide +kernel
  exact List.contains_iff_mem.mp (List.all_eq_true.mp (List.all_eq_true.mp all c hc) b hb)

public theorem columns_readable {c : Clause} (hc : c ∈ clauses) {b : Classes.StepBranch}
    (hb : b ∈ nonTrunk c) : b ∈ ReadersTotal.covered := by
  have all : (nonTrunk .copyLogs).all ReadersTotal.covered.contains = true := by decide +kernel
  exact List.contains_iff_mem.mp (List.all_eq_true.mp all b (columns_in_copyLogs hc hb))

public def readLabel (c : Clause) (s : Step) : RestrictedProfile :=
  let read := ReadersTotal.read s.cfg s.before s.act s.after s.past
  ⟨(endpoints s).1, (nonTrunk c).map fun b => (read b).getD false, (endpoints s).2⟩

public theorem readLabel_eq {c : Clause} (hc : c ∈ clauses) (s : Step) :
    readLabel c s = nonTrunkLabel c s := by
  apply congrArg (fun bits => RestrictedProfile.mk (endpoints s).1 bits (endpoints s).2)
  apply List.map_congr_left
  intro b hb
  rw [ReadersTotal.read_total s (columns_readable hc hb), Option.getD_some]

private def unique [DecidableEq α] : List α → List α
  | [] => []
  | a :: as =>
    let tail := unique as
    if a ∈ tail then tail else a :: tail

private theorem mem_unique [DecidableEq α] {a : α} {xs : List α} :
    a ∈ unique xs ↔ a ∈ xs := by
  induction xs generalizing a with
  | nil => rfl
  | cons x xs ih =>
    simp only [unique]
    split
    · rename_i present
      have h : x ∈ xs := ih.mp present
      simp only [List.mem_cons, ih]
      exact ⟨Or.inr, fun h' => h'.elim (fun eq => eq ▸ h) id⟩
    · simp only [List.mem_cons, ih]

private theorem unique_nodup [DecidableEq α] (xs : List α) : (unique xs).Nodup := by
  induction xs with
  | nil => exact List.nodup_nil
  | cons a xs ih =>
    simp only [unique]
    split
    · exact ih
    · exact List.nodup_cons.mpr ⟨‹_›, ih⟩

public def sampledRows (c : Clause) (picks : List (Nat × Nat)) : List RestrictedProfile :=
  unique ((picks.filterMap fun (i,j) => ReadersCorpus.stepAt i j).map (readLabel c))

public theorem sampledRows_realized {c : Clause} (hc : c ∈ clauses) {picks : List (Nat × Nat)}
    {r : RestrictedProfile} (hr : r ∈ sampledRows c picks) :
    ∃ s : Step, nonTrunkLabel c s = r := by
  obtain ⟨s, _, eq⟩ := List.mem_map.mp (mem_unique.mp hr)
  exact ⟨s, (readLabel_eq hc s).symm.trans eq⟩

public def rowPatterns (rows : List RestrictedProfile) : List (List Bool) :=
  unique (rows.map RestrictedProfile.bits)

public theorem rowPatterns_realized {c : Clause} {rows : List RestrictedProfile}
    (realized : ∀ r ∈ rows, ∃ s : Step, nonTrunkLabel c s = r) {p : List Bool}
    (hp : p ∈ rowPatterns rows) : ∃ s : Step, (nonTrunkLabel c s).bits = p := by
  obtain ⟨r, hr, eq⟩ := List.mem_map.mp (mem_unique.mp hp)
  obtain ⟨s, hs⟩ := realized r hr
  exact ⟨s, (congrArg RestrictedProfile.bits hs).trans eq⟩

public theorem endpoints_complete (c : Clause) (s : Step) :
    ((nonTrunkLabel c s).pre, (nonTrunkLabel c s).post) ∈ endpointRows :=
  (endpoint_exact _).mpr ⟨s, rfl⟩

public def project (c : Clause) (r : RestrictedProfile) : RestrictedProfile :=
  ⟨r.pre, (nonTrunk c).map fun b => r.bits[(nonTrunk .copyLogs).idxOf b]?.getD false, r.post⟩

public theorem project_label {c : Clause} (hc : c ∈ clauses) (s : Step) :
    project c (nonTrunkLabel .copyLogs s) = nonTrunkLabel c s := by
  apply congrArg (fun bits => RestrictedProfile.mk (endpoints s).1 bits (endpoints s).2)
  apply List.map_congr_left
  intro b hb
  have atIndex := List.idxOf_lt_length_iff.mpr (columns_in_copyLogs hc hb)
  simp only [nonTrunkLabel, restrictedLabel, List.getElem?_map, List.getElem?_eq_getElem atIndex,
    List.getElem_idxOf atIndex, Option.map_some, Option.getD_some]

public theorem excluded (s : Step) (b : Classes.StepBranch)
    (h : ReadersRefuted.read? b = some false ∨ EventSupport.actionTag s.act ∉ EventSupport.allowed b) :
    label s (.step b) = false :=
  h.elim (ReadersRefuted.read?_correct s) (EventSupport.label_false s b)

public theorem same_actor_branch (s : Step) :
    label s (.step .sorted_now_after_inl) = label s (.step .rooted_now_after_inl) := by
  have sorted := ActorLogRows.at_step s (b := .sorted_now_after_inl) (by decide +kernel)
  have rooted := ActorLogRows.at_step s (b := .rooted_now_after_inl) (by decide +kernel)
  exact Option.some.inj (sorted.symm.trans rooted)

public theorem same_prefix_branch (s : Step) :
    label s (.step .sorted_post_log_inl) = label s (.step .rooted_post_log_inl) := by
  have sorted := ActorLogRows.at_step s (b := .sorted_post_log_inl) (by decide +kernel)
  have rooted := ActorLogRows.at_step s (b := .rooted_post_log_inl) (by decide +kernel)
  exact Option.some.inj (sorted.symm.trans rooted)

public theorem same_peer_branch (s : Step) :
    label s (.step .sorted_now_after_inr) = label s (.step .rooted_now_after_inr) := by
  obtain ⟨x, made, _⟩ := ReadersAtoms.ofXAction_matches s
  have sorted := ReadersTotal.compiled?_at s (b := .sorted_now_after_inr) (by decide +kernel)
  have rooted := ReadersTotal.compiled?_at s (b := .rooted_now_after_inr) (by decide +kernel)
  simp only [ReadersTotal.compiled?, Readers.read, made, Option.bind_some] at sorted rooted
  exact Option.some.inj (sorted.symm.trans rooted)

private theorem inactive_sorted_nodes (s : Step) (no : label s (.step .sorted_now_after_inl) = false) :
    s.after.nodes = s.before.nodes := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  obtain ⟨v, made, ok⟩ := GuardedDomain.ofAction_matches s
  have read := ActorLogRows.at_step s (b := .sorted_now_after_inl) (by decide +kernel)
  simp only [made, ActorLogRows.read?, Option.bind_some, no, Option.some.injEq, Bool.or_eq_false_iff] at read
  have same := s.context.now_pre ((GuardedDomain.View.old_post ok).mpr read.1)
  change s.context.tr.post = s.context.tr.pre at same
  rw [← s.current_eq, s.context.tr.nodesEq, same]
  exact InertProfile.replace_eq s.context.inv.distinct s.context.tr.found

public theorem inactive_sorted_diagonal (s : Step) (no : label s (.step .sorted_now_after_inl) = false) :
    (endpoints s).1 = (endpoints s).2 := by
  have eq := BackingStutter.endpoints s (inactive_sorted_nodes s no).symm
  rw [pre_answers, post_answers] at eq
  exact Prod.ext (congrFun eq .committed_logs_comparable_left_backed_inl)
    (congrFun eq .committed_logs_comparable_left_backed_inr)

public theorem advance_exclusive (s : Step) (same : label s (.step .facts_advance_inl) = true) :
    label s (.step .facts_advance_inr) = false := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  have spec (b) := (label_true s (.step b)).trans (SolvedWitnesses.sig_iff c b)
  have eq := ((HandReadersOther.Facts.exact_iff c false).mp ((spec _).mp same)).1.2
  apply Bool.eq_false_iff.mpr
  intro grow
  have lt := ((HandReadersOther.Facts.exact_iff c true).mp ((spec _).mp grow)).1.2
  change c.pre.commitIndex = c.post.commitIndex at eq
  change c.pre.commitIndex < c.post.commitIndex at lt
  omega

public theorem log_advance (s : Step)
    (hit : label s (.step .post_log_kind_append) = true ∨
      label s (.step .post_log_kind_ack) = true) :
    (label s (.step .facts_advance_inl) || label s (.step .facts_advance_inr)) = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  have spec (b) := (label_true s (.step b)).trans (SolvedWitnesses.sig_iff c b)
  have src : HandReadersOther.Facts.Source c := by
    rcases hit with ha | ha
    · exact .inr (.inr (.inl ((spec _).mp ha)))
    · exact .inr (.inr (.inr (.inl ((spec _).mp ha))))
  obtain ⟨m, site, a, eq⟩ := HandReadersOther.Facts.encode c src
  have primary := (HandReadersOther.Facts.decode c site).2.2.1
  apply Bool.or_eq_true_iff.mpr
  rcases a with same | grow
  · exact .inl ((spec _).mpr ((HandReadersOther.Facts.exact_iff c false).mpr
      ⟨⟨primary, eq.symm.trans (congrArg Model.Node.NodeState.commitIndex same.symm)⟩,src⟩))
  · exact .inr ((spec _).mpr ((HandReadersOther.Facts.exact_iff c true).mpr
      ⟨⟨primary, eq ▸ grow.2.2.2.2.2.2.1⟩,src⟩))

public theorem win_split (s : Step) :
    let win := label s (.step .facts_advance_inl_2)
    let pos := label s (.step .primaryState_log_prefix_commit_pos)
    let neg := label s (.step .primaryState_log_prefix_commit_neg)
    win = (pos || neg) ∧ (pos && neg) = false := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  have spec (b) := (label_true s (.step b)).trans (SolvedWitnesses.sig_iff c b)
  have w := (spec .facts_advance_inl_2).trans (HandReadersA.Primary.identity_iff c)
  have p := (spec .primaryState_log_prefix_commit_pos).trans (HandReadersA.Primary.phase c true)
  have n := (spec .primaryState_log_prefix_commit_neg).trans (HandReadersA.Primary.phase c false)
  dsimp only
  constructor
  · apply Bool.eq_iff_iff.mpr
    rw [Bool.or_eq_true, w, p, n]
    cases decide (0 < c.pre.commitIndex) <;> simp
  · apply Bool.eq_false_iff.mpr
    intro both
    obtain ⟨yes, no⟩ := Bool.and_eq_true_iff.mp both
    exact Bool.noConfusion ((p.mp yes).2.symm.trans (n.mp no).2)

public theorem win_diagonal (s : Step) (win : label s (.step .facts_advance_inl_2) = true) :
    (endpoints s).1 = (endpoints s).2 :=
  ClauseMatchAck.win_diagonal s win

private def bitAt (c : Clause) (bits : List Bool) (b : Classes.StepBranch) : Bool :=
  bits[(nonTrunk c).idxOf b]?.getD false

private theorem bitAt_label {c : Clause} {b : Classes.StepBranch} (hb : b ∈ nonTrunk c) (s : Step) :
    bitAt c (nonTrunkLabel c s).bits b = label s (.step b) := by
  have atIndex := List.idxOf_lt_length_iff.mpr hb
  simp only [bitAt, nonTrunkLabel, restrictedLabel, List.getElem?_map,
    List.getElem?_eq_getElem atIndex, List.getElem_idxOf atIndex, Option.map_some, Option.getD_some]

private def mirrorPairs : List (Classes.StepBranch × Classes.StepBranch) :=
  [(.sorted_now_after_inl, .rooted_now_after_inl), (.sorted_post_log_inl, .rooted_post_log_inl),
   (.sorted_now_after_inr, .rooted_now_after_inr)]

private theorem same_mirror (s : Step) {p : Classes.StepBranch × Classes.StepBranch}
    (mem : p ∈ mirrorPairs) : label s (.step p.1) = label s (.step p.2) := by
  simp only [mirrorPairs, List.mem_cons, List.not_mem_nil, or_false] at mem
  rcases mem with rfl | rfl | rfl
  · exact same_actor_branch s
  · exact same_prefix_branch s
  · exact same_peer_branch s

private theorem shared {c : Clause} (hc : c ∈ clauses) {b : Classes.StepBranch}
    (hb : b ∈ [.post_log_kind_append, .post_log_kind_ack, .facts_advance_inl, .facts_advance_inr, .facts_advance_inl_2,
      .primaryState_log_prefix_commit_pos, .primaryState_log_prefix_commit_neg]) :
    b ∈ nonTrunk c := by
  have all : clauses.all (fun c =>
      [.post_log_kind_append, .post_log_kind_ack, .facts_advance_inl, .facts_advance_inr, .facts_advance_inl_2,
       .primaryState_log_prefix_commit_pos, .primaryState_log_prefix_commit_neg].all
       (nonTrunk c).contains) = true := by decide +kernel
  exact List.contains_iff_mem.mp (List.all_eq_true.mp (List.all_eq_true.mp all c hc) b hb)

/-- Necessary conditions on the shared log labels. The action tag is retained
while checking support, then forgotten in the row bound. -/
public def admissibleBits (c : Clause) (bits : List Bool) : Prop :=
  let get := bitAt c bits
  (∃ tag ∈ EventSupport.inputs ++ EventSupport.messages, ∀ b ∈ nonTrunk c,
    ReadersRefuted.read? b = some false ∨ tag ∉ EventSupport.allowed b → get b = false) ∧
  (∀ p ∈ mirrorPairs, p.1 ∈ nonTrunk c → p.2 ∈ nonTrunk c → get p.1 = get p.2) ∧
  (get .facts_advance_inl = true → get .facts_advance_inr = false) ∧
  (get .post_log_kind_append = true ∨ get .post_log_kind_ack = true →
    (get .facts_advance_inl || get .facts_advance_inr) = true) ∧
  get .facts_advance_inl_2 =
    (get .primaryState_log_prefix_commit_pos || get .primaryState_log_prefix_commit_neg) ∧
  (get .primaryState_log_prefix_commit_pos && get .primaryState_log_prefix_commit_neg) = false

private instance (c : Clause) (bits : List Bool) : Decidable (admissibleBits c bits) := by
  unfold admissibleBits
  infer_instance

public theorem admissibleBits_complete {c : Clause} (hc : c ∈ clauses) (s : Step) :
    admissibleBits c (nonTrunkLabel c s).bits := by
  have eq (b) (hb : b ∈ nonTrunk c) := bitAt_label hb s
  have ea := eq .facts_advance_inl (shared hc (by decide))
  have eg := eq .facts_advance_inr (shared hc (by decide))
  have ei := eq .post_log_kind_append (shared hc (by decide))
  have ek := eq .post_log_kind_ack (shared hc (by decide))
  have ew := eq .facts_advance_inl_2 (shared hc (by decide))
  have ep := eq .primaryState_log_prefix_commit_pos (shared hc (by decide))
  have en := eq .primaryState_log_prefix_commit_neg (shared hc (by decide))
  dsimp only [admissibleBits]
  rw [ea, eg, ei, ek, ew, ep, en]
  exact ⟨⟨_, EventSupport.allTag _, fun b hb ban => (eq b hb).trans (excluded s b ban)⟩,
    fun p hp l r => (eq _ l).trans ((same_mirror s hp).trans (eq _ r).symm),
    advance_exclusive s, log_advance s, win_split s⟩

public def admissibleRow (c : Clause) (r : RestrictedProfile) : Prop :=
  (r.pre, r.post) ∈ endpointRows ∧ r.bits.length = (nonTrunk c).length ∧
  admissibleBits c r.bits ∧
  (bitAt c r.bits .facts_advance_inl_2 = true → r.pre = r.post) ∧
  (∀ b ∈ [.sorted_now_after_inl, .rooted_now_after_inl],
    b ∈ nonTrunk c → bitAt c r.bits b = false → r.pre = r.post)

private instance (c : Clause) (r : RestrictedProfile) : Decidable (admissibleRow c r) := by
  unfold admissibleRow
  infer_instance

public theorem admissibleRow_complete {c : Clause} (hc : c ∈ clauses) (s : Step) :
    admissibleRow c (nonTrunkLabel c s) := by
  refine ⟨endpoints_complete c s, List.length_map _, admissibleBits_complete hc s, ?_, ?_⟩
  · rw [bitAt_label (shared hc (by decide))]
    exact win_diagonal s
  · intro b hb mem no
    have off := (bitAt_label mem s).symm.trans no
    simp only [List.mem_cons, List.not_mem_nil, or_false] at hb
    rcases hb with rfl | rfl
    · exact inactive_sorted_diagonal s off
    · exact inactive_sorted_diagonal s ((same_actor_branch s).trans off)

public def quietRows (c : Clause) : List RestrictedProfile :=
  StateCoverage.activeTable.map fun e => ⟨e, List.replicate (nonTrunk c).length false, e⟩

public theorem quietRows_count (c : Clause) : (quietRows c).Nodup ∧ (quietRows c).length = 3 := by
  have distinct : StateCoverage.activeTable.Nodup := by decide +kernel
  refine ⟨distinct.map _ ?_, rfl⟩
  intro _ _ distinct eq
  exact distinct (congrArg RestrictedProfile.pre eq)

public theorem quietRows_realized (c : Clause) {r : RestrictedProfile} (hr : r ∈ quietRows c) :
    ∃ s : Step, nonTrunkLabel c s = r := by
  obtain ⟨e, active, rfl⟩ := List.mem_map.mp hr
  obtain ⟨s, eq⟩ := SignedQuiet.realized e active
  have pre : (endpoints s).1 = e := by
    have h := (congrArg (fun p : FullProfile.Profile => p.pre) eq)
    rw [pre_answers] at h
    exact ClauseQuestions.answers_eq.mp h
  have post : (endpoints s).2 = e := by
    have h := (congrArg (fun p : FullProfile.Profile => p.post) eq)
    rw [post_answers] at h
    exact ClauseQuestions.answers_eq.mp h
  have no (b : Classes.StepBranch) : label s (.step b) = false := by
    change (label s) (.step b) = _
    rw [eq]
    rfl
  exact ⟨s, by
    change RestrictedProfile.mk (endpoints s).1 ((nonTrunk c).map fun b => label s (.step b))
      (endpoints s).2 = _
    simp [pre, post, no, List.map_const']⟩

/-- The zero-vector fiber is exact for each clause containing the shared
sorted or rooted actor branch. -/
public theorem quietRows_complete {c : Clause}
    (hc : c = .sorted ∨ c = .rooted ∨ c = .copyLogs) (s : Step)
    (zero : (nonTrunkLabel c s).bits = List.replicate (nonTrunk c).length false) :
    nonTrunkLabel c s ∈ quietRows c := by
  have no (b : Classes.StepBranch) (mem : b ∈ nonTrunk c) : label s (.step b) = false := by
    rw [← bitAt_label mem s, zero]
    have k := List.idxOf_lt_length_iff.mpr mem
    simp [bitAt, k]
  have actor : label s (.step .sorted_now_after_inl) = false := by
    rcases hc with rfl | rfl | rfl
    · exact no _ (by decide +kernel)
    · exact (same_actor_branch s).trans (no _ (by decide +kernel))
    · exact no _ (by decide +kernel)
  have same := inactive_sorted_diagonal s actor
  apply List.mem_map.mpr
  refine ⟨(endpoints s).1, ?_, ?_⟩
  · have ep := (endpoint_exact _).mpr ⟨s,rfl⟩
    change ((endpoints s).1, (endpoints s).2) ∈ endpointRows at ep
    rw [← same] at ep
    exact (by decide +kernel : ∀ e ∈ endpointRows, e.1 = e.2 →
      e.1 ∈ StateCoverage.activeTable) ((endpoints s).1, (endpoints s).1) ep rfl
  · change RestrictedProfile.mk (endpoints s).1 _ (endpoints s).1 =
      RestrictedProfile.mk (endpoints s).1 (nonTrunkLabel c s).bits (endpoints s).2
    rw [zero, same]

public def live (b : Classes.StepBranch) : Bool := ReadersRefuted.read? b != some false

private def candidates : List Classes.StepBranch → List (List Bool)
  | [] => [[]]
  | b :: bs =>
    let tail := candidates bs
    let no := tail.map (false :: ·)
    if live b then no ++ tail.map (true :: ·) else no

private theorem candidates_complete (s : Step) (qs : List Classes.StepBranch) :
    (qs.map fun b => label s (.step b)) ∈ candidates qs := by
  induction qs with
  | nil => exact List.mem_cons_self
  | cons b bs ih =>
    simp only [candidates, List.map_cons]
    split
    · cases h : label s (.step b)
      · exact List.mem_append_left _ (List.mem_map.mpr ⟨_,ih,rfl⟩)
      · exact List.mem_append_right _ (List.mem_map.mpr ⟨_,ih,rfl⟩)
    · rename_i no
      have refuted : ReadersRefuted.read? b = some false := by simpa [live] using no
      rw [ReadersRefuted.read?_correct s refuted]
      exact List.mem_map.mpr ⟨_, ih, rfl⟩

private theorem candidates_length (qs : List Classes.StepBranch) :
    (candidates qs).length = 2 ^ (qs.filter live).length := by
  induction qs with
  | nil => rfl
  | cons b bs ih =>
    cases h : live b <;> simp [candidates, h, ih, Nat.pow_succ, Nat.mul_two]

public theorem live_counts :
    clauses.map (fun c => ((nonTrunk c).filter live).length) = [34,36,36,36,56] :=
  by decide +kernel

/-- An upper bound, not a realizability test. Use `admissibleBits` directly
to test a candidate without enumerating the full list. -/
public def upperPatterns (c : Clause) : List (List Bool) :=
  (candidates (nonTrunk c)).filter (fun bits => decide (admissibleBits c bits))

public theorem upperPatterns_complete {c : Clause} (hc : c ∈ clauses) (s : Step) :
    (nonTrunkLabel c s).bits ∈ upperPatterns c :=
  List.mem_filter.mpr ⟨candidates_complete s _, decide_eq_true (admissibleBits_complete hc s)⟩

private def rowCandidates (c : Clause) : List RestrictedProfile :=
  endpointRows.flatMap fun (pre, post) => (candidates (nonTrunk c)).map fun bits => ⟨pre, bits, post⟩

public def upperRows (c : Clause) : List RestrictedProfile :=
  (rowCandidates c).filter (fun r => decide (admissibleRow c r))

public theorem upperRows_complete {c : Clause} (hc : c ∈ clauses) (s : Step) :
    nonTrunkLabel c s ∈ upperRows c := by
  apply List.mem_filter.mpr
  refine ⟨List.mem_flatMap.mpr ⟨_, endpoints_complete c s, ?_⟩,
    decide_eq_true (admissibleRow_complete hc s)⟩
  exact List.mem_map.mpr ⟨_, candidates_complete s _, rfl⟩

public theorem upperPatterns_length_le (c : Clause) :
    (upperPatterns c).length ≤ 2 ^ ((nonTrunk c).filter live).length := by
  rw [← candidates_length]
  exact List.length_filter_le _ _

public theorem upperRows_length_le (c : Clause) :
    (upperRows c).length ≤ 6 * 2 ^ ((nonTrunk c).filter live).length := by
  have h : (upperRows c).length ≤ (rowCandidates c).length := List.length_filter_le _ _
  simp [rowCandidates, endpoint_rows, candidates_length] at h
  omega

private def picks : List (Nat × Nat) :=
  [(0,0), (0,1), (1,0), (2,0), (2,1), (2,2), (2,3), (2,4), (2,5), (2,6),
   (3,1), (3,2), (3,3), (3,5), (3,6), (4,6), (4,7), (4,8), (4,12),
   (5,5), (5,6), (5,7), (5,8), (5,12), (6,9), (6,10), (6,11), (6,12), (6,13), (6,14),
   (6,15), (18,0), (19,0), (20,2), (21,4)]

private def combinedWitnesses : List RestrictedProfile := sampledRows .copyLogs picks

public def witnessedRows (c : Clause) : List RestrictedProfile :=
  unique (combinedWitnesses.map (project c))

public def witnessedPatterns (c : Clause) : List (List Bool) := rowPatterns (witnessedRows c)

public theorem witnessed_nodup (c : Clause) :
    (witnessedPatterns c).Nodup ∧ (witnessedRows c).Nodup :=
  ⟨unique_nodup _, unique_nodup _⟩

public theorem witnessedRows_realized {c : Clause} (hc : c ∈ clauses)
    {r : RestrictedProfile} (hr : r ∈ witnessedRows c) :
    ∃ s : Step, nonTrunkLabel c s = r := by
  obtain ⟨wide, mem, pin⟩ := List.mem_map.mp (mem_unique.mp hr)
  obtain ⟨s, hs⟩ := sampledRows_realized (c := .copyLogs) (by decide) mem
  exact ⟨s, (project_label hc s).symm.trans ((congrArg (project c) hs).trans pin)⟩

public theorem witnessedPatterns_realized {c : Clause} (hc : c ∈ clauses)
    {p : List Bool} (hp : p ∈ witnessedPatterns c) : ∃ s : Step, (nonTrunkLabel c s).bits = p :=
  rowPatterns_realized (fun _ => witnessedRows_realized hc) hp

public def remainingRows (c : Clause) : List RestrictedProfile :=
  (upperRows c).filter (fun r => !(witnessedRows c).contains r)

public theorem upper_partition {c : Clause} (hc : c ∈ clauses) (s : Step) :
    nonTrunkLabel c s ∈ witnessedRows c ∨ nonTrunkLabel c s ∈ remainingRows c := by
  by_cases h : nonTrunkLabel c s ∈ witnessedRows c
  · exact .inl h
  · right
    apply List.mem_filter.mpr
    refine ⟨upperRows_complete hc s, ?_⟩
    rw [Bool.not_eq_true', ← Bool.not_eq_true, List.contains_iff_mem]
    exact h

end ConsensusCoverage.ClauseLogCluster
