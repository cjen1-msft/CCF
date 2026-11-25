module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.CensusGhost
import all ConsensusCoverage.CensusGhost
import all ConsensusCoverage.Readers
import all ConsensusCoverage.ReadersGenerated
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.GuardedDomain
meta import Lean

namespace ConsensusCoverage.CensusLocal

open Consensus Consensus.Model Consensus.Model.Node ReadersAtoms

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxRecDepth 16384
set_option maxHeartbeats 0

/-- Changing the entire ghost, ordered past, and both lists of commit
certificates cannot affect this generated answer. The two full network
snapshots, the action view, and its outputs are held fixed. -/
public def Factored (b : Classes.StepBranch) : Prop :=
  ∀ (input : CensusGhost.Input) (cfg : FullProfile.Configuration) (x : XView)
    (past : List Model.State) (pre post : List (Nat × List Entry)),
    let view : XView := {x with base := {x.base with past}, committedBefore := pre, committedAfter := post}
    CensusGhost.Exec.read? input ⟨cfg, some view⟩ b = Readers.read? ⟨cfg, some x⟩ b

meta section

open Lean Meta Elab Term

private partial def localBody (root : Name) : MetaM Bool := do
  let scope := `ConsensusCoverage.ReadersCompiler.R
  let mut seen : NameSet := {}
  let mut todo := [root]
  while let n :: rest := todo do
    todo := rest
    if seen.contains n then continue
    seen := seen.insert n
    let d ← getConstInfoDefn n
    let calls := d.value.getUsedConstants
    if calls.any (#[``GuardedDomain.View.past, ``XView.committedBefore, ``XView.committedAfter].contains ·) then
      return false
    todo := (calls.filter (·.getPrefix == scope)).toList ++ todo
  return true

end

open Lean Meta Elab Term in
local elab "local_certificates" : term => do
  let scope := `ConsensusCoverage.ReadersCompiler.R
  let names := (← getEnv).constants.toList.filterMap fun (n, d) => do
    guard (n.getPrefix == scope && n.getString!.startsWith "step_")
    let .defnInfo _ := d | none
    return n
  let mut expr ← `(([] : List { b : Classes.StepBranch // Factored b }))
  for n in names.mergeSort (fun a b => a.getString! ≥ b.getString!) do
    unless ← localBody n do continue
    let arm := mkIdent <| ``Classes.StepBranch ++ Name.mkSimple ((n.getString!.drop 5).toString)
    expr ← `((⟨$arm, by unfold Factored; intros; rfl⟩) :: $expr)
  elabTerm expr none

private def certificates : List { b : Classes.StepBranch // Factored b } := local_certificates

public def columns : List Classes.StepBranch := certificates.map Subtype.val

public theorem correct {b : Classes.StepBranch} (mem : b ∈ columns) : Factored b := by
  obtain ⟨⟨_, proof⟩, _, rfl⟩ := List.mem_map.mp mem
  exact proof

/-- On a concrete action, the small compiler can use empty history and
arbitrary commit and ghost payloads for a local coordinate. Even the
two node-lookup failure paths agree. The snapshots remain unchanged. -/
public theorem action_read {b : Classes.StepBranch} (mem : b ∈ columns)
    (cfg : FullProfile.Configuration) (s t : Model.State) (act : Model.Action) (past : List Model.State)
    (g : CensusGhost.Input) (pre post : List (Nat × List Entry)) :
    ((GuardedDomain.ofAction cfg s t [] act).bind fun v =>
      let e := eventOf act
      let x : XView := ⟨v, e, outputsOf v.actor v.pre e, pre, post⟩
      CensusGhost.Exec.read? g ⟨cfg, some x⟩ b) = Readers.read? (Readers.read cfg s act t past) b := by
  cases a : CCF.MultiNodeTransitionSystem.nodeState s (GuardedDomain.actionActor act) <;>
    cases z : CCF.MultiNodeTransitionSystem.nodeState t (GuardedDomain.actionActor act) <;>
    simp only [Readers.read, ofXAction, GuardedDomain.ofAction, a, z,
      Option.bind_eq_bind, Option.bind_none, Option.bind_some, pure]
  · rfl
  · rfl
  · rfl
  · exact correct mem g cfg (packX (GuardedDomain.pack _ s t past _ _ _) (eventOf act)) [] pre post

end ConsensusCoverage.CensusLocal
