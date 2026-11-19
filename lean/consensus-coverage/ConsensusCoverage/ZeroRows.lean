module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.StutterProfile
import all ConsensusCoverage.ActionProfile
import all ConsensusCoverage.FrontierRows
import all ConsensusCoverage.LeaderRefinement
import all ConsensusCoverage.PairQuestions
import all ConsensusCoverage.ProofContexts
import all ConsensusCoverage.SolvedWitnesses
import all ConsensusCoverage.StateBasis
import all ConsensusCoverage.StateCoverage
import all ConsensusCoverage.StutterProfile
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.ZeroRows

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety
open ActionProfile FullProfile

private theorem new_commit [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t) :
    PinnedClasses.sig c .commitChains_step_committed_inr ↔
      ∃ k p, Committed (f.advance t) k p ∧ ¬ Committed f k p := by
  rw [SolvedWitnesses.sig_iff]
  change SolvedWitnesses.step_commitChains_step_committed_inr f t c ↔ _
  constructor
  · exact fun ⟨k, p, fresh, _⟩ => ⟨k, p, fresh⟩
  · rintro ⟨k, p, post, fresh⟩
    rcases keep : post with prior | ⟨n, st, base, i, step, eq, backing⟩
    · exact (fresh prior).elim
    · have h := And.intro step (And.intro eq backing)
      exact ⟨k, p, ⟨post, fresh⟩, ⟨n, st, base, i, h⟩, n, ⟨st, base, i, h⟩,
        st, ⟨base, i, h⟩, base, ⟨i, h⟩, i, h, step, ⟨eq, backing⟩, eq, backing, post⟩

private theorem zero_iff [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t)
    {nodes : List NodeID} {act : Model.Action}
    (ran : (transitionSystem Config.INITIAL_CONFIGURATION nodes).step f.current act = some t)
    (quiet : ¬ PinnedClasses.sig c .terms_now_after_inl) :
    StateBasis.Zero f ↔ StateBasis.Zero (f.advance t) := by
  constructor
  · rintro ⟨n, st, old, zero⟩
    by_cases who : n = c.actor
    · subst n
      by_cases still : c.post.commitIndex = 0
      · exact ⟨c.actor, c.post, c.post_now, still⟩
      · have bound := (c.inv_step.frontier _ _ c.post_now).1
        have nonempty : c.post.log ≠ [] := by
          intro empty
          simp [empty] at bound
          exact still bound
        obtain ⟨entry, mem⟩ := List.exists_mem_of_ne_nil _ nonempty
        apply False.elim (quiet (LeaderRefinement.terms_of_change c ?_ mem))
        intro existed
        have same := (c.now_pre existed).trans (c.now_pre old).symm
        exact still (same ▸ zero)
    · refine ⟨n, st, ?_, zero⟩
      change (n, st) ∈ t.nodes
      rw [c.tr.nodesEq]
      exact List.mem_map.mpr ⟨_, old, by simp [who]⟩
  · exact fun h => (PairQuestions.zero_mem _).mp
      (PairQuestions.zero_old c ran ((PairQuestions.zero_mem _).mpr h))

/-- Two step answers suffice to rule out an endpoint change. Changing the last
zero index requires a changed actor with a nonempty log; first backing requires
a new commit key. Neither argument assumes that the snapshots stutter. -/
public theorem endpoints (s : Step)
    (terms : label s (.step .terms_now_after_inl) = false)
    (commit : label s (.step .commitChains_step_committed_inr) = false) :
    (label s).pre = (label s).post := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  have ran := s.ran
  rw [← s.current_eq] at ran
  have zero := zero_iff c ran (fun yes => Bool.noConfusion (terms.symm.trans ((label_true ..).mpr yes)))
  have old {k p} (h : Committed (s.frame.advance s.after) k p) : Committed s.frame k p := by
    apply Classical.byContradiction
    intro notOld
    exact Bool.noConfusion (commit.symm.trans ((label_true ..).mpr ((new_commit c).mpr ⟨k, p, h, notOld⟩)))
  have backed : StateBasis.Backing s.frame ↔ StateBasis.Backing (s.frame.advance s.after) := by
    rw [StateCoverage.backed_iff _ c.inv, StateCoverage.backed_iff _ c.inv_step]
    exact ⟨fun ⟨_, k, p, h⟩ => ⟨List.ne_nil_of_mem c.post_now, k, p, Or.inl h⟩,
      fun ⟨_, k, p, h⟩ => ⟨List.ne_nil_of_mem c.pre_now, k, p, old h⟩⟩
  have ctx := (StateBasis.ctx_equiv_iff ‹_› ‹_› s.frame (s.frame.advance s.after)).mpr ⟨zero, backed⟩
  funext b
  exact Bool.eq_iff_iff.mpr ((label_true s (.pre b)).trans ((ctx b).trans (label_true s (.post b)).symm))

public def table : List Profile := ProofContexts.table.map StutterProfile.diagonal

public theorem count : table.Nodup ∧ table.length = 3 := by
  have inj : Function.Injective StutterProfile.diagonal := fun _ _ h => funext fun b => congrFun h (.pre b)
  exact ⟨ProofContexts.count.1.map _ (fun _ _ h eq => h (inj eq)), by simpa [table] using ProofContexts.count.2⟩

public theorem mem_of_zero (s : Step) (quiet : (label s).step = fun _ => false) : label s ∈ table := by
  have same := endpoints s (congrFun quiet _) (congrFun quiet _)
  have before := pre_answers s
  have key := (StateCoverage.exact (StateCoverage.read s.cfg s.before s.past)).2.mpr
    ⟨s.cfg, s.nodes, s.before, s.past, s.run, rfl, fun _ => FrontierRows.no_step_without_nodes s.ran⟩
  refine List.mem_map.mpr ⟨(label s).pre, ?_, ?_⟩
  · exact List.mem_map.mpr ⟨_, key, before.symm⟩
  · funext q
    cases q with
    | pre => rfl
    | step b => exact (congrFun quiet b).symm
    | post b => exact congrFun same b

end ConsensusCoverage.ZeroRows
