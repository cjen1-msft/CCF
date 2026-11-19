module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.BackingRead
public import ConsensusCoverage.GuardedDomain
import all ConsensusCoverage.ActionProfile
import all ConsensusCoverage.CommitKeys
import all ConsensusCoverage.GuardedDomain
import all ConsensusCoverage.InertProfile
import all ConsensusCoverage.SolvedWitnesses
import all ConsensusCoverage.StutterProfile
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.ActorLogRows

open ActionProfile GuardedDomain SolvedWitnesses
open Consensus Consensus.Model Consensus.Proofs Consensus.Proofs.Safety

set_option maxRecDepth 8192

private abbrev Sources [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t) :=
  reach_5 f t c c ∨ reach_6 f t c c ∨ reach_7 f t c c ∨ reach_8 f t c c

/-- Every indirect call through an election and a commit still requires new
evidence. With unchanged nodes only a new committed key can enter this path. -/
private theorem sources_iff (s : Step) (v : View) (ok : @View.Matches ⟨s.cfg⟩ _ _ v s.context) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    Sources s.context ↔ v.changed = true ∨ label s (.step .commitChains_step_committed_inr) = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  have vc : v.Matches c := ok
  have node : reach_5 s.frame s.after c c ↔ v.changed = true := by
    simp only [reach_5, and_true, GuardedDomain.any_fresh_now c, View.old_post vc, Bool.not_eq_false]
  have key : reach_6 s.frame s.after c c ↔ label s (.step .commitChains_step_committed_inr) = true := by
    rw [label_true]
    change _ ↔ PinnedClasses.sig c _
    rw [CommitKeys.fresh_iff c]
    simp only [reach_6, and_true, Committed]
  constructor
  · intro h
    by_cases changed : v.changed = true
    · exact .inl changed
    by_cases fresh : label s (.step .commitChains_step_committed_inr) = true
    · exact .inr fresh
    exfalso
    have same := c.now_pre ((View.old_post vc).mpr (Bool.eq_false_iff.mpr changed))
    have nodes : s.after.nodes = s.frame.current.nodes := by
      rw [c.tr.nodesEq, show c.tr.post = c.tr.pre from same]
      exact InertProfile.replace_eq c.inv.distinct c.tr.found
    have eq := StutterProfile.advance_logs_nodes (f := s.frame) nodes
    have elect := (congrArg LogFacts.Ghost.elected eq).trans (StutterProfile.frozenElection c.inv)
    have canon := (congrArg LogFacts.Ghost.canon eq).trans (StutterProfile.frozenCanon s.folded)
    have old {k p} (post : Committed (s.frame.advance s.after) k p) : Committed s.frame k p := by
      apply Classical.byContradiction
      exact fun absent => fresh (key.mp ⟨k, p, post, absent, rfl⟩)
    have no2 {k p n e l j} : ¬reach_2 s.frame s.after c c k p n e l j := by
      rintro ⟨post, elected, lt, new, _⟩
      exact new ⟨old post, by simpa only [Elected, elect] using elected, lt⟩
    have no3 : ¬reach_3 s.frame s.after c c := fun ⟨_, _, _, _, _, _, root, _⟩ => no2 root
    have no4 {n st k b i} : ¬reach_4 s.frame s.after c c n st k b i :=
      fun ⟨_, _, _, _, _, root, _⟩ => no2 root
    rcases h with newNode | new | ⟨_, _, post, notOld, _⟩ | indirect
    · exact changed (node.mp newNode)
    · exact fresh (key.mp new)
    · exact notOld (by simpa only [canon] using post)
    · change reach_8 s.frame s.after c c at indirect
      simp only [reach_8, no3, no4, false_and, false_or, exists_false] at indirect
  · exact fun h => h.elim (fun h => .inl (node.mpr h)) (fun h => .inr (.inl (key.mpr h)))

@[expose] public def covered : List Classes.StepBranch :=
  [.rooted_now_after_inl, .sorted_now_after_inl, .rooted_post_log_inl, .sorted_post_log_inl]

@[expose] public def read? (v : View) (fresh : Bool) : Classes.StepBranch → Option Bool
  | .rooted_now_after_inl | .sorted_now_after_inl => some (v.changed || fresh)
  | .rooted_post_log_inl | .sorted_post_log_inl => some ((v.changed || fresh) && decide (v.post.log <+: v.pre.log))
  | _ => none

private theorem four (s : Step) (v : View) (ok : @View.Matches ⟨s.cfg⟩ _ _ v s.context)
    (b : Classes.StepBranch) (mem : b ∈ covered) :
    read? v (label s (.step .commitChains_step_committed_inr)) b = some (label s (.step b)) := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  have main := sources_iff s v ok
  have vc : v.Matches c := ok
  have now := c.post_now
  have root := c.inv.rooted c.actor c.pre c.pre_now
  have terms : (∀ (entry : Node.Entry), entry ∈ c.pre.log → entry.term ≤ c.pre.currentTerm) = True :=
    propext (iff_true_intro (c.inv.terms c.actor c.pre c.pre_now))
  simp only [covered, List.mem_cons, List.not_mem_nil, or_false] at mem
  rcases mem with rfl | rfl | rfl | rfl
  all_goals
    apply congrArg some
    apply Bool.eq_iff_iff.mpr
    rw [label_true]
    change _ ↔ PinnedClasses.sig c _
    rw [SolvedWitnesses.sig_iff]
  all_goals first | (
    change (_ || _) = true ↔ step_sorted_now_after_inl _ _ c
    simpa only [Bool.or_eq_true, step_sorted_now_after_inl, now, and_true] using main.symm) | skip
  all_goals
    first | change (_ && _) = true ↔ step_rooted_post_log_inl _ _ c
          | change (_ && _) = true ↔ step_sorted_post_log_inl _ _ c
    simp only [Bool.and_eq_true, Bool.or_eq_true, decide_eq_true_eq, ← main, Sources,
      step_rooted_post_log_inl, step_sorted_post_log_inl, now, root, terms, true_and, and_true,
      ← or_and_right, ← View.post_eq vc, ← View.pre_eq vc]
    rfl

public theorem at_step (s : Step) {b : Classes.StepBranch} (mem : b ∈ covered) :
    let backing := BackingRead.read (s.cfg.min?.getD 0) s.after (s.before :: s.past)
    (ofAction s.cfg s.before s.after s.past s.act).bind (read? · (backing.1 || backing.2) b) =
      some (label s (.step b)) := by
  obtain ⟨v, made, ok⟩ := ofAction_matches s
  simp only [made, Option.bind_some, BackingRead.any_eq, CommitKeys.fresh_answer, four s v ok b mem]

end ConsensusCoverage.ActorLogRows
