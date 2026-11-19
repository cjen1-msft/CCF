module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ActionFrontier
public import ConsensusCoverage.EventSupport
import all ConsensusCoverage.ActionFrontier
import all ConsensusCoverage.FrontierRows
import all ConsensusCoverage.Projection

namespace ConsensusCoverage.ReplayAnswers

open ActionProfile FullProfile Consensus

/-- Values shared by all questions at a validated action boundary. -/
public structure Evidence where
  key : FrontierRows.Row × Bool
  tag : EventSupport.Tag

public def read (cfg : Configuration) (s : Model.State) (a : Model.Action)
    (t : Model.State) (past : List Model.State) : Evidence :=
  ⟨(FrontierRows.historyLabel cfg s t past, LeaderEffect.changedPrimary s t), EventSupport.actionTag a⟩

private def leader (k : FrontierRows.Row × Bool) : Classes.StepBranch → Option Bool
  | .leader_led_leader_inr => some k.1.wonPrimary
  | .leader_led_now_after_inl => some k.2
  | .leader_led_leader_inl => some (k.2 && !k.1.wonPrimary)
  | _ => none

/-- `none` is an unknown coordinate, not a negative answer. -/
public def answer (e : Evidence) : Question → Option Bool
  | .pre b => some (ProofContexts.answers (e.key.1.zeroBefore, e.key.1.backedBefore) b)
  | .post b => some (ProofContexts.answers (e.key.1.zeroAfter, e.key.1.backedAfter) b)
  | .step b => (leader e.key b).orElse fun _ =>
      if e.tag ∈ EventSupport.allowed b then none else some false

private theorem leader_sound (s : Step) (b : Classes.StepBranch) {v : Bool}
    (h : leader (ActionFrontier.project (label s)) b = some v) : label s (.step b) = v := by
  generalize key : ActionFrontier.project (label s) = k at h
  have won := congrArg (fun (p : FrontierRows.Row × Bool) => p.1.wonPrimary) key
  have changed := congrArg Prod.snd key
  have incumbent := ActionFrontier.incumbent_eq s
  rw [key] at incumbent
  cases b <;> first | exact won.trans (Option.some.inj h) | exact changed.trans (Option.some.inj h)
                    | exact incumbent.trans (Option.some.inj h) | contradiction

public theorem sound (s : Step) (q : Question) {v : Bool}
    (known : answer (read s.cfg s.before s.act s.after s.past) q = some v) : label s q = v := by
  cases q with
  | pre b => exact (congrFun (pre_answers s) b).trans (Option.some.inj known)
  | post b => exact (congrFun (post_answers s) b).trans (Option.some.inj known)
  | step b =>
    simp only [answer, read, ← ActionFrontier.project_eq] at known
    cases h : leader (ActionFrontier.project (label s)) b with
    | some res => exact (leader_sound s b h).trans (by simpa [h] using known)
    | none =>
      simp only [h, Option.orElse_none] at known
      split at known
      · contradiction
      · rename_i excluded
        exact (EventSupport.label_false s b excluded).trans (Option.some.inj known)

end ConsensusCoverage.ReplayAnswers
