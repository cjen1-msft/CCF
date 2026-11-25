module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.DeepActorCases

open Consensus Consensus.Proofs Consensus.Model Consensus.Model.Node Safety
open ActionProfile ReadersAtoms GuardedDomain SolvedWitnesses

set_option maxRecDepth 8192

inductive ActorCase where
  | keyHere | keyOther | bootstrap | previousElection

def ActorCase.column : ActorCase → Classes.StepBranch
  | .keyHere => .replaceNode_keys_here_pos
  | .keyOther => .replaceNode_keys_here_neg
  | .bootstrap => .led_after_led_inl
  | .previousElection => .led_after_elected_after_inl

private def test (x : XView) : ActorCase → Bool
  | .keyHere | .keyOther => true
  | .bootstrap => x.base.actor == x.base.bootstrap
  | .previousElection =>
    electedExact x.base.actor x.base.pre.currentTerm x.base.pre.log x.base.pre.commitIndex
      (x.base.before :: x.base.past)

def check (s : Step) (k : ActorCase) : Bool :=
  (ofXAction s.cfg s.before s.after s.past s.act).any fun x => x.base.changed && test x k

theorem correct (s : Step) (k : ActorCase) (yes : check s k = true) :
    label s (.step k.column) = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  obtain ⟨x, made, ok⟩ := ofXAction_matches s
  simp only [check, made, Option.any_some, Bool.and_eq_true] at yes
  obtain ⟨changed, testOk⟩ := yes
  have fresh : ¬Now s.frame c.actor c.post := fun h =>
    Bool.noConfusion (changed.symm.trans ((View.old_post ok.1).mp h))
  have now := c.post_now
  have seen := c.post_seen
  have keys : (reach% SolvedWitnesses.step_replaceNode_keys_here_pos[12])
      s.frame s.after c c.actor :=
    ⟨⟨c.post, ⟨now, seen, now, seen, seen, fun p => fresh p.1, rfl⟩, now, rfl⟩, rfl⟩
  have ledRoot {term} (led : Led (s.frame.advance s.after) c.actor term) :
      (reach% SolvedWitnesses.step_led_after_led_inr[0]) s.frame s.after c c.actor term :=
    .inl ⟨⟨now, led, fun p => fresh p.1, rfl⟩, now, led, now, now, led, rfl⟩
  refine (label_true s _).mpr ((SolvedWitnesses.sig_iff c _).mpr ?_)
  cases k with
  | keyHere =>
    change step_replaceNode_keys_here_pos _ _ _
    iterate 12 right
    exact ⟨c.actor, keys, (c.actor, c.post), rfl⟩
  | keyOther =>
    change step_replaceNode_keys_here_neg _ _ _
    iterate 12 right
    exact ⟨c.actor, keys, (c.actor + 1, c.post), Nat.succ_ne_self _⟩
  | bootstrap =>
    have actor : c.actor = Config.INITIAL_PRIMARY :=
      (View.actor_eq ok.1).trans ((beq_iff_eq.mp testOk).trans (X.bootstrap ok))
    have led : Led (s.frame.advance s.after) c.actor BOOTSTRAP_TERM := .inl ⟨rfl, actor⟩
    exact Or.inl (actor ▸ And.intro (ledRoot led) led)
  | previousElection =>
    have e := (X.elected_before ok _ _ _ _).mpr testOk
    rw [← View.actor_eq ok.1, ← View.pre_eq ok.1] at e
    have advanced : Elected (s.frame.advance s.after) c.actor c.pre.currentTerm c.pre.log
        c.pre.commitIndex := Or.inl e
    have led : Led (s.frame.advance s.after) c.actor c.pre.currentTerm :=
      .inr ⟨_, _, advanced⟩
    exact Or.inl ⟨_, _, ledRoot led, ⟨_, _, advanced⟩, _, ⟨_, advanced⟩, _,
      advanced, e, led⟩

end ConsensusCoverage.DeepActorCases
