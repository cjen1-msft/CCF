module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.CensusOutgoing
import all ConsensusCoverage.CensusExactLocal
import all ConsensusCoverage.CensusGhost
import all ConsensusCoverage.ReadersGenerated
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.GuardedDomain
import all ConsensusCoverage.LeaderEffect

namespace ConsensusCoverage.CensusProbe

open Consensus Consensus.Model Consensus.Model.Node ReadersAtoms

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxRecDepth 16384
set_option maxHeartbeats 0

/-- Exactly the set represented by the native arc mask: source IDs before
the step together with target IDs after the step, without multiplicity. -/
public def SameProbes (s t : Model.State) (before after : List Model.Envelope) : Prop :=
  ∀ n, n ∈ before.map (·.source) ++ after.map (·.target) ↔ n ∈ s.network.map (·.source) ++ t.network.map (·.target)

private theorem all_eq {xs ys : List α} (mem : ∀ a, a ∈ xs ↔ a ∈ ys) (p : α → Bool) :
    xs.all p = ys.all p := by
  apply Bool.eq_iff_iff.mpr
  simp only [List.all_eq_true]
  exact ⟨fun h a m => h a ((mem a).mpr m), fun h a m => h a ((mem a).mp m)⟩

private theorem pack_eq (s t : Model.State) (before after : List Model.Envelope) (mask : SameProbes s t before after)
    (past : List Model.State) (boot n : NodeID) (pre post : NodeState) :
    GuardedDomain.pack boot {s with network := before} {t with network := after} [] n pre post =
      {GuardedDomain.pack boot s t past n pre post with
        before := {s with network := before}, after := {t with network := after}, past := []} := by
  unfold GuardedDomain.pack LeaderEffect.sameNode LeaderEffect.probes
  rw [all_eq mask]

private abbrev swapped (x : XView) (before after : List Model.Envelope) : XView :=
  {x with base.before.network := before, base.after.network := after}

private theorem result_eq {b : Classes.StepBranch} (localMem : b ∈ CensusExactLocal.columns) (cfg : FullProfile.Configuration)
    (s t : Model.State) (before after : List Model.Envelope) (mask : SameProbes s t before after)
    (past : List Model.State) (boot n : NodeID) (pre post : NodeState) (e : Event)
    (input : CensusGhost.Input) (p q : List (Nat × List Entry)) (fallback : Unit → Option Bool)
    (stable : let x := packX (GuardedDomain.pack boot s t past n pre post) e
              @ReadersCompiler.readView ⟨cfg⟩ (swapped x before after) b = @ReadersCompiler.readView ⟨cfg⟩ x b) :
    (let v := GuardedDomain.pack boot {s with network := before} {t with network := after} [] n pre post
     @CensusGhost.Exec.readView input ⟨cfg⟩ ⟨v, e, outputsOf n pre e, p, q⟩ b) =
      (@ReadersCompiler.readView ⟨cfg⟩ (packX (GuardedDomain.pack boot s t past n pre post) e) b).orElse fallback := by
  let x := packX (GuardedDomain.pack boot s t past n pre post) e
  have eq := CensusExactLocal.correct localMem input cfg (swapped x before after) [] p q fallback
  change @ReadersCompiler.readView ⟨cfg⟩ (swapped x before after) b = @ReadersCompiler.readView ⟨cfg⟩ x b at stable
  rw [stable] at eq
  rw [pack_eq s t before after mask past]
  exact eq

private theorem lookup (s : Model.State) (q : List Model.Envelope) (n : NodeID) :
    CCF.MultiNodeTransitionSystem.nodeState {s with network := q} n = CCF.MultiNodeTransitionSystem.nodeState s n := rfl

private theorem answers_of_stable {b : Classes.StepBranch} (mem : b ∈ CensusExactLocal.columns) (cfg : FullProfile.Configuration)
    (s t : Model.State) (act : Model.Action) (past : List Model.State)
    (before after : List Model.Envelope) (mask : SameProbes s t before after)
    (g h : ExplorerGhost.Ghost) (fallback : XView → Unit → Option Bool)
    (stable : ∀ x, ofXAction cfg s t past act = some x →
      @ReadersCompiler.readView ⟨cfg⟩ (swapped x before after) b = @ReadersCompiler.readView ⟨cfg⟩ x b) :
    ((CensusGhost.answers cfg g h {s with network := before} {t with network := after} act).bind (· b)) =
      ((ofXAction cfg s t past act).bind fun x => (@ReadersCompiler.readView ⟨cfg⟩ x b).orElse (fallback x)) := by
  cases a : CCF.MultiNodeTransitionSystem.nodeState s (GuardedDomain.actionActor act) <;>
    cases z : CCF.MultiNodeTransitionSystem.nodeState t (GuardedDomain.actionActor act) <;>
    simp only [CensusGhost.answers, ofXAction, GuardedDomain.ofAction, lookup, a, z,
      Option.bind_eq_bind, Option.bind_none, Option.bind_some, pure]
  · apply result_eq mem cfg s t before after mask past
    apply stable
    simp only [ofXAction, GuardedDomain.ofAction, a, z, Option.bind_eq_bind, Option.bind_some, pure]

/-- These local coordinates permit arbitrary queues with the same endpoint
mask, including when the replacement envelopes were never emitted. -/
public theorem answers_eq {b : Classes.StepBranch} (queueMem : b ∈ CensusExactLocal.queueColumns) (cfg : FullProfile.Configuration)
    (s t : Model.State) (act : Model.Action) (past : List Model.State)
    (before after : List Model.Envelope) (mask : SameProbes s t before after)
    (g h : ExplorerGhost.Ghost) (fallback : XView → Unit → Option Bool) :
    ((CensusGhost.answers cfg g h {s with network := before} {t with network := after} act).bind (· b)) =
      ((ofXAction cfg s t past act).bind fun x => (@ReadersCompiler.readView ⟨cfg⟩ x b).orElse (fallback x)) := by
  have subset : CensusExactLocal.queueColumns.all CensusExactLocal.columns.contains = true := by decide +kernel
  have mem := List.contains_iff_mem.mp ((List.all_eq_true.mp subset) b queueMem)
  exact answers_of_stable mem cfg s t act past before after mask g h fallback
    fun x _ => CensusExactLocal.queue_correct queueMem cfg x before after

/-- For all the local coordinates one-copy membership on emitted envelopes
(`CensusOutgoing.agree_of_one_copy`) and the native endpoint mask suffice. -/
public theorem answers_eq_outgoing {b : Classes.StepBranch} (mem : b ∈ CensusExactLocal.columns) (cfg : FullProfile.Configuration)
    (s t : Model.State) (act : Model.Action) (past : List Model.State)
    (before after : List Model.Envelope) (mask : SameProbes s t before after)
    (g h : ExplorerGhost.Ghost) (fallback : XView → Unit → Option Bool)
    (agree : ∀ x, ofXAction cfg s t past act = some x → CensusOutgoing.Agree x before after) :
    ((CensusGhost.answers cfg g h {s with network := before} {t with network := after} act).bind (· b)) =
      ((ofXAction cfg s t past act).bind fun x => (@ReadersCompiler.readView ⟨cfg⟩ x b).orElse (fallback x)) :=
  answers_of_stable mem cfg s t act past before after mask g h fallback
    fun x made => CensusOutgoing.correct mem cfg x before after (agree x made)

end ConsensusCoverage.CensusProbe
