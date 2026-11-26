module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.DeepInputCases

open Consensus Consensus.Proofs Consensus.Model Consensus.Model.Node Safety
open ActionProfile ReadersAtoms GuardedDomain SolvedWitnesses

set_option maxRecDepth 8192

inductive InputCase where
  | emptyBackup | signedBackup | electionTimeout

def InputCase.column : InputCase → Classes.StepBranch
  | .emptyBackup => .initAsBackup_summary_eq_zero_or_pos_inl
  | .signedBackup => .initAsBackup_summary_eq_zero_or_pos_inr
  | .electionTimeout => .summary_kind_election

private def test (x : XView) : InputCase → Bool
  | .emptyBackup => decide (x.base.pre.isFresh ∧ x.event = .internal (.initAsBackup []))
  | .signedBackup => decide (x.base.pre.isFresh ∧
      x.event = .internal (.initAsBackup x.base.post.log) ∧
      isSignatureAt x.base.post.log x.base.post.log.length = true ∧ 0 < x.base.post.log.length)
  | .electionTimeout => decide (x.event = .internal (.timeout .election))

def check (s : Step) (k : InputCase) : Bool :=
  (ofXAction s.cfg s.before s.after s.past s.act).any fun x => x.base.changed && test x k

-- All three summaries have the same incoming caller: a changed post-state
-- enters the commit-backing obligation before it scrutinizes the event.
private theorem summary [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)
    (fresh : ¬Now f c.actor c.post) :
    (reach% SolvedWitnesses.step_initAsBackup_summary_eq_zero_or_pos_inl[15,0,0])
      f t c t c.tr := by
  have now := c.post_now
  exact ⟨.inl ⟨⟨now, fresh, rfl⟩, now, now, now,
    fun h => ⟨⟨_, h⟩, fun _ _ => h⟩, rfl⟩, rfl, .rfl⟩

local macro "backup_case " c:ident root:ident fresh:ident event:ident entries:term:arg : tactic => `(tactic| {
  iterate 15 right
  left
  refine ⟨_, $entries, ⟨_, ⟨_, Ctx.tr $c, $root, rfl, rfl⟩, _, $event, $event, rfl⟩, ?_⟩
  obtain ⟨role, term, log, index⟩ := $fresh
  repeat' first | assumption | apply And.intro })

theorem correct (s : Step) (k : InputCase) (yes : check s k = true) :
    label s (.step k.column) = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  obtain ⟨x, made, ok⟩ := ofXAction_matches s
  simp only [check, made, Option.any_some, Bool.and_eq_true] at yes
  obtain ⟨changed, testOk⟩ := yes
  have freshPost : ¬Now s.frame c.actor c.post := fun was =>
    Bool.noConfusion (changed.symm.trans ((View.old_post ok.1).mp was))
  have root := summary c freshPost
  refine (label_true s _).mpr ((SolvedWitnesses.sig_iff c _).mpr ?_)
  cases k with
  | electionTimeout =>
    have ev : c.event = .internal (.timeout .election) :=
      (X.event_eq ok).trans (of_decide_eq_true testOk)
    change step_summary_kind_election _ _ _
    iterate 15 right
    exact .inl ⟨_, ⟨_, c.tr, root, rfl⟩, _, ev, ev, rfl⟩
  | emptyBackup =>
    obtain ⟨fr, ev⟩ := of_decide_eq_true (p := x.base.pre.isFresh ∧
      x.event = .internal (.initAsBackup [])) testOk
    have fresh : c.pre.isFresh := (View.pre_eq ok.1).symm ▸ fr
    have event := (X.event_eq ok).trans ev
    have signed : ([] : List Entry) = [] ∨ isSignatureAt [] 0 = true := .inl rfl
    have zero : ([] : List Entry).length = 0 := rfl
    change step_initAsBackup_summary_eq_zero_or_pos_inl _ _ _
    backup_case c root fresh event ([] : List Entry)
  | signedBackup =>
    obtain ⟨fr, ev, sig_, pos⟩ := of_decide_eq_true (p := x.base.pre.isFresh ∧
      x.event = .internal (.initAsBackup x.base.post.log) ∧
      isSignatureAt x.base.post.log x.base.post.log.length = true ∧ 0 < x.base.post.log.length) testOk
    have fresh : c.pre.isFresh := (View.pre_eq ok.1).symm ▸ fr
    have event := (X.event_eq ok).trans ev
    have signed : x.base.post.log = [] ∨ _ := Or.inr sig_
    change step_initAsBackup_summary_eq_zero_or_pos_inr _ _ _
    backup_case c root fresh event (x.base.post.log)

end ConsensusCoverage.DeepInputCases
