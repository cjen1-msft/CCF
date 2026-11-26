module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.FullProfile
import all ConsensusCoverage.FullProfile
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.ActionContext

open CCF CCF.MultiNodeTransitionSystem
open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

private def encode (actor : NodeID) : Event → Model.Action
  | .internal input => .local actor input
  | .receive src msg => .deliver ⟨src, actor, msg⟩

public def action [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t) : Model.Action :=
  encode c.tr.actor c.tr.event

private theorem restored {cfg ns s t} {a : Model.Action}
    (ran : (transitionSystem cfg ns).step s a = some t) :
    ∃ tr : LocalTransition s t, encode tr.actor tr.event = a := by
  letI : Config.InitialConfiguration := ⟨cfg⟩
  cases a with
  | «local» actor input =>
    have available (es : List Entry) (eq : Event.internal input = .internal (.initAsBackup es)) :
        committedPrefixOf s es = true := by
      cases eq
      by_cases yes : committedPrefixOf s es = true
      · exact yes
      · simp [transitionSystem, networkStep, yes] at ran
    obtain ⟨pre, post, outputs, found, result, rfl⟩ := Concrete.step_local ran
    exact ⟨⟨actor, pre, post, .internal input, outputs, s.network, found, result, rfl, rfl,
      fun _ h => h, .inl ⟨input, rfl, rfl⟩, available⟩, rfl⟩
  | deliver e =>
    obtain ⟨queued, pre, post, outputs, found, result, rfl⟩ := Concrete.step_deliver ran
    exact ⟨⟨e.target, pre, post, .receive e.source e.payload, outputs, removeOne e s.network,
      found, result, rfl, rfl, fun _ mem => mem_removeOne mem,
      .inr ⟨e, queued, rfl, rfl, rfl⟩, by intro _ eq; cases eq⟩, rfl⟩

private theorem pending_eq {s t : Model.State} (tr : LocalTransition s t) :
    tr.pending = match tr.event with
    | .internal _ => s.network
    | .receive src msg => removeOne ⟨src, tr.actor, msg⟩ s.network := by
  rcases tr.source with ⟨_, h, eq⟩ | ⟨⟨_, _, _⟩, _, rfl, h, eq⟩ <;> simpa [h] using eq

private theorem encode_inj {x y : NodeID} {e d : Event} (eq : encode x e = encode y d) :
    x = y ∧ e = d := by cases e <;> cases d <;> simp_all [encode]

/-- The node lookup, local computation and pending queue are deterministic once
the actual action is fixed. Two actions producing the same snapshots need not be equal. -/
public theorem injective [Config.InitialConfiguration] {f : Frame} {t : Model.State} :
    Function.Injective (action (f := f) (t := t)) := by
  rintro ⟨l, il⟩ ⟨r, ir⟩ eq
  have ⟨ha, he⟩ := encode_inj eq
  have pendL := pending_eq l
  have pendR := pending_eq r
  cases l; cases r
  cases ha; cases he
  congr 1
  congr 1
  all_goals grind

/-- A successful recorded action on an initialized proof frame determines
exactly one proof context. No arbitrary choice of a second action is needed. -/
public theorem exists_unique {cfg ns f t a} (folded : FullProfile.Folded cfg ns f)
    (ran : (transitionSystem cfg ns).step (FullProfile.current f) a = some t) :
    letI : Config.InitialConfiguration := ⟨cfg⟩
    ∃ c : Ctx f t, action c = a ∧ ∀ c', action c' = a → c' = c := by
  letI : Config.InitialConfiguration := ⟨cfg⟩
  obtain ⟨tr, ha⟩ := restored ran
  let c : Ctx f t := ⟨tr, folded.invariant⟩
  exact ⟨c, ha, fun _ h => injective (h.trans ha.symm)⟩

end ConsensusCoverage.ActionContext
