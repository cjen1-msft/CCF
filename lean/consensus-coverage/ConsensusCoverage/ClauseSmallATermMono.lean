module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ClauseSmallA
import all ConsensusCoverage.BackingStutter
import all ConsensusCoverage.ClauseExactTables
import all ConsensusCoverage.ClauseMatchAck
import all ConsensusCoverage.ClauseQuestions
import all ConsensusCoverage.ClauseSmallA
import all ConsensusCoverage.HandReadersASeen
import all ConsensusCoverage.HandReadersElectionBKeys
import all ConsensusCoverage.HandReadersElectionBFind
import all ConsensusCoverage.InertProfile
import all ConsensusCoverage.ReadersCorpus
import all ConsensusCoverage.ReadersRefuted
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.ClauseSmallA.TermMono

open Consensus Consensus.Proofs Consensus.Proofs.Safety
open ActionProfile ClauseQuestions ClauseExactTables SolvedWitnesses
open HandReadersA HandReadersElectionB

set_option maxHeartbeats 0
set_option maxRecDepth 8192

public theorem columns : nonTrunk .term_mono =
    [.inv_step_term_mono_seen_inl, .inv_step_term_mono_now_inl, .inv_step_term_mono_seen_inr,
     .seen_after_seen_inl, .seen_after_seen_inr, .seen_after_now_after_inl, .seen_after_now_after_inr,
     .replaceNode_keys_here_pos, .replaceNode_keys_here_neg,
     .find_of_mem_here_pos, .find_of_mem_here_neg] := by decide +kernel

section
variable [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t)

private theorem seenOld : sig c .inv_step_term_mono_seen_inl ↔ ¬ Now f c.actor c.post := by
  constructor
  · rintro ⟨_, _, _, now, _, seen, fresh⟩ old
    apply fresh
    rcases c.now_after now with ⟨rfl, rfl⟩ | ⟨_, was⟩
    · exact ⟨old, seen⟩
    · exact ⟨was, seen⟩
  · intro fresh
    have was := c.inv.observed _ _ c.pre_now
    exact ⟨_, _, observe c.pre, c.post_now, .inl was, was, fun h => fresh h.1⟩

private theorem nowNew : sig c .inv_step_term_mono_now_inl ↔ ¬ Now f c.actor c.post := by
  constructor
  · rintro ⟨_, _, _, seen, _, _, _, _, fresh⟩ old
    exact fresh ⟨old, seen⟩
  · intro fresh
    have was := c.inv.observed _ _ c.pre_now
    exact ⟨observe c.pre, c.post_now, .inl was, was, c.post_now, .inl was, was,
      c.post_now, fun h => fresh h.1⟩

private theorem seenNew : sig c .inv_step_term_mono_seen_inr ↔ ¬ Now f c.actor c.post := by
  constructor
  · rintro ⟨_, now, _, _, _, _, fresh⟩ old
    have eq := c.now_post now
    subst eq
    exact fresh ⟨old, c.inv.observed _ _ old⟩
  · intro fresh
    exact ⟨c.post, c.post_now, c.post_seen, c.post_now, c.post_seen, c.post_seen, fun h => fresh h.1⟩
end

private def pack (changed keys : Bool) : List Bool :=
  [changed, changed, changed, changed, changed, changed, false, keys, keys, keys, keys]

private def row (e : Endpoints) (changed keys : Bool) : RestrictedProfile :=
  ⟨e.1, pack changed keys, e.2⟩

private noncomputable abbrev changed (s : Step) := label s (.step .seen_after_seen_inl)
private noncomputable abbrev keys (s : Step) := label s (.step .replaceNode_keys_here_pos)

private theorem shape (s : Step) : nonTrunkLabel .term_mono s = row (endpoints s) (changed s) (keys s) := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  have eq (b : Classes.StepBranch) (spec : sig s.context b ↔ ¬ Now s.frame s.context.actor s.context.post) :
      label s (.step b) = changed s := by
    apply Bool.eq_iff_iff.mpr
    change label s (.step b) = true ↔ label s (.step .seen_after_seen_inl) = true
    exact ((label_true s (.step b)).trans ((sig_iff _ _).trans spec)).trans
      ((label_true s (.step .seen_after_seen_inl)).trans
        ((sig_iff _ _).trans (SeenRows.iff_changed s.context .old))).symm
  have old := SeenRows.exactReader .old |>.eq_label s
  have seenPost := (SeenRows.exactReader .post |>.eq_label s).trans old.symm
  have seenActor := (SeenRows.exactReader .actor |>.eq_label s).trans old.symm
  have no : label s (.step .seen_after_now_after_inr) = false :=
    ReadersRefuted.read?_correct s (by decide +kernel)
  have replace := (Keys.negative.eq_label s).trans (Keys.positive.eq_label s).symm
  have findPos := (Find.positive.eq_label s).trans (Keys.positive.eq_label s).symm
  have findNeg := (Find.negative.eq_label s).trans (Keys.positive.eq_label s).symm
  have postEq : label s (.step .seen_after_seen_inr) = changed s := seenPost
  have actorEq : label s (.step .seen_after_now_after_inl) = changed s := seenActor
  have replaceEq : label s (.step .replaceNode_keys_here_neg) = keys s := replace
  have findPosEq : label s (.step .find_of_mem_here_pos) = keys s := findPos
  have findNegEq : label s (.step .find_of_mem_here_neg) = keys s := findNeg
  simp only [nonTrunkLabel, columns, restrictedLabel, row, pack, endpoints, List.map_cons, List.map_nil,
    eq _ (seenOld s.context), eq _ (nowNew s.context), eq _ (seenNew s.context), postEq,
    actorEq, no, replaceEq, findPosEq, findNegEq]

private theorem changed_spec (s : Step) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    changed s = true ↔ ¬ Now s.frame s.context.actor s.context.post := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  exact (label_true s _).trans ((sig_iff _ _).trans (SeenRows.iff_changed s.context .old))

private theorem changed_keys (s : Step) (h : changed s = true) : keys s = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  exact (label_true s _).mpr ((sig_iff _ _).mpr
    (Keys.sufficient s.context (.inl ((changed_spec s).mp h))))

private theorem unchanged_nodes (s : Step) (h : changed s = false) : s.before.nodes = s.after.nodes := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  have old : Now s.frame s.context.actor s.context.post := by
    exact Classical.not_not.mp fun fresh =>
      Bool.noConfusion (h.symm.trans ((changed_spec s).mpr fresh))
  have same := s.context.now_pre old
  change s.context.tr.post = s.context.tr.pre at same
  rw [← s.current_eq, s.context.tr.nodesEq, same]
  exact (InertProfile.replace_eq s.context.inv.distinct s.context.tr.found).symm

private theorem unchanged_diagonal (s : Step) (h : changed s = false) :
    (endpoints s).1 = (endpoints s).2 := by
  have eq := BackingStutter.endpoints s (unchanged_nodes s h)
  rw [pre_answers, post_answers] at eq
  exact Prod.ext (congrFun eq .committed_logs_comparable_left_backed_inl)
    (congrFun eq .committed_logs_comparable_left_backed_inr)

private theorem extra_backed (s : Step) (hc : changed s = false) (hk : keys s = true) :
    (endpoints s).1.2 = true := by
  have old : changed s = SeenRows.reader s.cfg s.before s.act s.after s.past :=
    (SeenRows.exactReader .old).eq_label s
  have h : Keys.reader s.cfg s.before s.act s.after s.past = true :=
    (Keys.positive.eq_label s).symm.trans hk
  cases hb : (endpoints s).1.2 with
  | true => rfl
  | false =>
    have quiet := BackingStutter.no_first_commit s (unchanged_nodes s hc) hb
    simp only [Keys.reader, ← old, hc, quiet, Bool.not_true, Bool.false_and, Bool.false_or] at h
    contradiction

public def witnessed : List RestrictedProfile :=
  endpointRows.flatMap fun e => row e true true :: if e.1 = e.2 then [row e false false] else []

public def remaining : List RestrictedProfile :=
  [row ((true,true),(true,true)) false true, row ((false,true),(false,true)) false true]

public def patterns : List (List Bool) := [pack true true, pack false false]
public def remainingPatterns : List (List Bool) := [pack false true]

public theorem counts :
    patterns.length = 2 ∧ (patterns ++ remainingPatterns).length = 3 ∧ (patterns ++ remainingPatterns).Nodup ∧
    witnessed.length = 9 ∧ (witnessed ++ remaining).length = 11 ∧ (witnessed ++ remaining).Nodup :=
  by decide +kernel

public theorem upper (s : Step) : nonTrunkLabel .term_mono s ∈ witnessed ++ remaining := by
  rw [shape]
  have mem := (endpoint_exact _).mpr ⟨s,rfl⟩
  cases hc : changed s with
  | true =>
    rw [changed_keys s hc]
    exact List.mem_append_left _ (List.mem_flatMap.mpr ⟨_,mem,List.mem_cons_self⟩)
  | false =>
    have diag := unchanged_diagonal s hc
    cases hk : keys s with
    | false =>
      exact List.mem_append_left _ (List.mem_flatMap.mpr ⟨_,mem,by simp [diag]⟩)
    | true =>
      exact List.mem_append_right _ ((by decide +kernel : ∀ e ∈ endpointRows,
        e.1 = e.2 → e.1.2 = true → row e false true ∈ remaining) _ mem diag (extra_backed s hc hk))

private def picks : List (Nat × Nat) := [(0,0),(0,1),(1,0),(2,0),(2,3),(2,4),(2,5),(3,3),(4,6)]
private noncomputable def steps := picks.filterMap fun (i,j) => ReadersCorpus.stepAt i j

private theorem checked : witnessed.all (steps.map (readRow (nonTrunk .term_mono))).contains = true :=
  by decide +kernel

public theorem lower (r : RestrictedProfile) (mem : r ∈ witnessed) :
    ∃ s : Step, nonTrunkLabel .term_mono s = r :=
  sampled _ (by rw [columns]; decide +kernel) _ _ checked mem

public theorem upper_patterns (s : Step) : (nonTrunkLabel .term_mono s).bits ∈ patterns ++ remainingPatterns := by
  exact (by decide +kernel : ∀ r ∈ witnessed ++ remaining, r.bits ∈ patterns ++ remainingPatterns) _ (upper s)

public theorem lower_patterns (p : List Bool) (mem : p ∈ patterns) :
    ∃ s : Step, (nonTrunkLabel .term_mono s).bits = p := by
  have hit := (by decide +kernel : ∀ q ∈ patterns, ∃ r ∈ witnessed, r.bits = q) p mem
  obtain ⟨r, hr, rfl⟩ := hit
  obtain ⟨s, eq⟩ := lower r hr
  exact ⟨s, congrArg RestrictedProfile.bits eq⟩

end ConsensusCoverage.ClauseSmallA.TermMono
