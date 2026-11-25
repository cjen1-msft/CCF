module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.CensusProbe
public import ConsensusCoverage.Readers
import all ConsensusCoverage.CensusExactLocal
import all ConsensusCoverage.CensusGhost
import all ConsensusCoverage.Readers
import all ConsensusCoverage.ReadersGenerated
import all ConsensusCoverage.ReadersPolarGenerated
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.GuardedDomain

namespace ConsensusCoverage.CensusLocal

open Consensus Consensus.Model Consensus.Model.Node ReadersAtoms

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxRecDepth 16384
set_option maxHeartbeats 0

/-- On every total generated coordinate the fallback pool is irrelevant,
even for a physical view that did not arise on an initialized step. This
does not justify changing the view's ordered history to a finite ghost. -/
public theorem covered_eq_exact (cfg : FullProfile.Configuration) (x : XView)
    (pools : Thunk (Option ReadersPolar.Pools)) {b : Classes.StepBranch} (mem : b ∈ Readers.covered) :
    Readers.read? ⟨cfg, some x, pools⟩ b = @ReadersCompiler.readView ⟨cfg⟩ x b := by
  unfold Readers.read?
  simp only [Option.bind_some]
  exact CensusExactLocal.ignore_fallback cfg x _ mem

/-- Changing the entire ghost, ordered past, and both lists of commit
certificates cannot affect this generated answer. The two full network
snapshots, the action view, and its outputs are held fixed. -/
public def Factored (b : Classes.StepBranch) : Prop :=
  ∀ (input : CensusGhost.Input) (cfg : FullProfile.Configuration) (x : XView)
    (past : List Model.State) (pre post : List (Nat × List Entry)) (pools : Thunk (Option ReadersPolar.Pools)),
    let view : XView := {x with base := {x.base with past}, committedBefore := pre, committedAfter := post}
    @CensusGhost.Exec.readView input ⟨cfg⟩ view b = Readers.read? ⟨cfg, some x, pools⟩ b

public def columns : List Classes.StepBranch := CensusExactLocal.columns

public theorem correct {b : Classes.StepBranch} (mem : b ∈ columns) : Factored b := by
  intro input cfg x past pre post pools
  unfold Readers.read?
  simp only [Option.bind_some]
  exact CensusExactLocal.correct mem input cfg x past pre post _

/-- On a concrete action, the small compiler can use empty history and
arbitrary commit and ghost payloads for a local coordinate. Even the
two node-lookup failure paths agree. The snapshots remain unchanged. -/
public theorem action_read {b : Classes.StepBranch} (mem : b ∈ columns)
    (cfg : FullProfile.Configuration) (s t : Model.State) (act : Model.Action) (past : List Model.State)
    (g : CensusGhost.Input) (pre post : List (Nat × List Entry)) :
    ((GuardedDomain.ofAction cfg s t [] act).bind fun v =>
      let e := eventOf act
      let x : XView := ⟨v, e, outputsOf v.actor v.pre e, pre, post⟩
      @CensusGhost.Exec.readView g ⟨cfg⟩ x b) = Readers.read? (Readers.read cfg s act t past) b := by
  cases a : CCF.MultiNodeTransitionSystem.nodeState s (GuardedDomain.actionActor act) <;>
    cases z : CCF.MultiNodeTransitionSystem.nodeState t (GuardedDomain.actionActor act) <;>
    simp only [Readers.read?, Readers.read, ofXAction, GuardedDomain.ofAction, a, z,
      Option.bind_eq_bind, Option.bind_none, Option.bind_some, pure]
  exact CensusExactLocal.correct mem g cfg (packX (GuardedDomain.pack _ s t past _ _ _) (eventOf act)) [] pre post _

/-- This subset can reuse a different queued representative of the same
local edge and endpoint mask, even if neither ghost came from this run. -/
public theorem action_read_mask {b : Classes.StepBranch} (mem : b ∈ CensusExactLocal.queueColumns)
    (cfg : FullProfile.Configuration) (s t : Model.State) (act : Model.Action) (past : List Model.State)
    (before after : List Model.Envelope) (mask : CensusProbe.SameProbes s t before after) (g h : ExplorerGhost.Ghost) :
    ((CensusGhost.answers cfg g h {s with network := before} {t with network := after} act).bind (· b)) =
      Readers.read? (Readers.read cfg s act t past) b :=
  CensusProbe.answers_eq mem cfg s t act past before after mask g h fun x _ =>
    (Readers.read cfg s act t past).pools.get.bind fun pools => @ReadersPolarCompiler.readView ⟨cfg⟩ x pools b

/-- The sent-envelope membership premise follows from the one-copy
decompositions in `CensusOutgoing.agree_of_one_copy`. -/
public theorem action_read_outgoing {b : Classes.StepBranch} (mem : b ∈ columns)
    (cfg : FullProfile.Configuration) (s t : Model.State) (act : Model.Action) (past : List Model.State)
    (before after : List Model.Envelope) (mask : CensusProbe.SameProbes s t before after) (g h : ExplorerGhost.Ghost)
    (agree : ∀ x, ofXAction cfg s t past act = some x → CensusOutgoing.Agree x before after) :
    ((CensusGhost.answers cfg g h {s with network := before} {t with network := after} act).bind (· b)) =
      Readers.read? (Readers.read cfg s act t past) b :=
  CensusProbe.answers_eq_outgoing mem cfg s t act past before after mask g h
    (fun x _ => (Readers.read cfg s act t past).pools.get.bind fun pools => @ReadersPolarCompiler.readView ⟨cfg⟩ x pools b) agree

end ConsensusCoverage.CensusLocal
