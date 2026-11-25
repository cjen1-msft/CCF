module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ActionProfile
import all ConsensusCoverage.GuardedDomain
import all ConsensusCoverage.ReadersAtoms

namespace ConsensusCoverage.HandReadersA

open CCF.MultiNodeTransitionSystem Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety ActionProfile

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

public abbrev Reader := FullProfile.Configuration → State → Action → State → List State → Bool

public structure Exact (b : Classes.StepBranch) where
  eval : Reader
  eq_label (s : Step) : label s (.step b) = eval s.cfg s.before s.act s.after s.past

/-- A local query needs just two node lookups; it does not replay the history,
compare function-valued node records, or compute committed keys. -/
def actorRead (p : NodeID → NodeState → Event → NodeState → Bool) : Reader :=
  fun _ before act after _ =>
    let n := GuardedDomain.actionActor act
    ((nodeState before n).bind fun pre =>
      (nodeState after n).map fun post => p n pre (ReadersAtoms.eventOf act) post).getD false

theorem actorRead_at (s : Step) (p : NodeID → NodeState → Event → NodeState → Bool) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    actorRead p s.cfg s.before s.act s.after s.past =
      p s.context.actor s.context.pre s.context.event s.context.post := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  have action := (s.context_eq c).mpr rfl
  have pre : nodeState s.before c.actor = some c.pre := by rw [← s.current_eq]; exact c.tr.found
  have post := Direct.nodeState_of_mem c.keys_after c.post_now
  have ev : ReadersAtoms.eventOf (ActionContext.action c) = c.event := by
    change ReadersAtoms.eventOf (ActionContext.encode c.tr.actor c.tr.event) = c.tr.event
    cases c.tr.event <;> rfl
  simp only [actorRead, ← action, GuardedDomain.actionActor_eq, pre, post, ev,
    Option.bind_some, Option.map_some, Option.getD_some]
  rfl

end ConsensusCoverage.HandReadersA
