module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.JointWitnesses
public import ConsensusCoverage.ReadersPolar
import all ConsensusCoverage.FrontierWitnesses
import all ConsensusCoverage.JointWitnesses
import all ConsensusCoverage.ActionContext
import all ConsensusCoverage.ActionProfile
import all ConsensusCoverage.SolvedWitnesses
import all ConsensusCoverage.GuardedDomain
import all ConsensusCoverage.ReadersAtoms
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.CensusQueueStep

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety
open ActionProfile FrontierRows ReadersAtoms GuardedDomain

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxRecDepth 8192

/-- Resolve sparse queue choices in the original ordered network, not in an abstract frame. -/
def selected (r : Run) (valid : r.valid) (choices : List (Nat × Nat)) (offset : Nat) : Option Step := do
  let steps ← JointWitnesses.recordedAt {r with schedule := r.schedule.take (offset + 1)} valid choices
  return (← steps[offset]?).val

private theorem viewSome (s : Step) : (ofXAction s.cfg s.before s.after s.past s.act).isSome := by
  obtain ⟨_, made, _⟩ := ofXAction_matches s
  simp [made]

public def view (s : Step) : XView :=
  (ofXAction s.cfg s.before s.after s.past s.act).get (viewSome s)

public theorem view_matches (s : Step) : @XView.Matches ⟨s.cfg⟩ _ _ (view s) s.context := by
  obtain ⟨x, made, ok⟩ := ofXAction_matches s
  simpa [view, made] using ok

/-- Rebuild the context with computable data fields. The original transition
supplies all proof fields, but is never evaluated to recover an actor or event. -/
noncomputable def context (s : Step) : @Ctx ⟨s.cfg⟩ s.frame s.after := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let x := view s
  let ok := view_matches s
  let c := s.context
  have act : c.tr.actor = x.base.actor := X.tr_actor_eq ok
  have pre : c.tr.pre = x.base.pre := X.tr_pre_eq ok
  have post : c.tr.post = x.base.post := X.tr_post_eq ok
  have event : c.tr.event = x.event := X.tr_event_eq ok
  have outputs : c.tr.outputs = x.outputs := X.outputs_eq ok
  have pending : c.tr.pending = pendingOf x := X.pending_eq ok
  refine ⟨⟨x.base.actor, x.base.pre, x.base.post, x.event, x.outputs, pendingOf x, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩, c.inv⟩
  · rw [← act, ← pre]; exact c.tr.found
  · exact X.run_eq ok
  · rw [← act, ← post]; exact c.tr.nodesEq
  · rw [← pending, ← outputs]; exact c.tr.networkEq
  · rw [← pending]; exact c.tr.pendingSub
  · rw [← act, ← event, ← pending]; exact c.tr.source
  · rw [← event]; exact c.tr.available

public theorem context_eq (s : Step) : context s = s.context := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  apply ActionContext.injective
  change ActionContext.encode (view s).base.actor (view s).event =
    ActionContext.encode s.context.tr.actor s.context.tr.event
  rw [X.tr_actor_eq (view_matches s), X.tr_event_eq (view_matches s)]

public theorem reflected (s : Step) : @XView.Matches ⟨s.cfg⟩ _ _ (view s) (context s) :=
  (context_eq s).symm ▸ view_matches s

theorem ofFormula (s : Step) (b : Classes.StepBranch)
    (h : @SolvedWitnesses.sig ⟨s.cfg⟩ _ _ (context s) b) : label s (.step b) = true := by
  apply (label_true s _).mpr
  apply (@SolvedWitnesses.sig_iff ⟨s.cfg⟩ _ _ s.context b).mpr
  rwa [context_eq] at h

def pools (s : Step) : ReadersPolar.Pools := ReadersPolar.prepare s.cfg (view s)

end ConsensusCoverage.CensusQueueStep
