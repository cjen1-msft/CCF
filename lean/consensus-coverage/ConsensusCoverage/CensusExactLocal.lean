module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.CensusGhost
import all ConsensusCoverage.CensusGhost
import all ConsensusCoverage.ReadersGenerated
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.GuardedDomain
meta import Lean

namespace ConsensusCoverage.CensusExactLocal

open Consensus Consensus.Model Consensus.Model.Node ReadersAtoms

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxRecDepth 16384
set_option maxHeartbeats 0

/-- Replacing the one-sided fallback on a total coordinate cannot change
the answer. No hypothesis about the fallback or the history is needed. -/
public theorem ignore_fallback (cfg : FullProfile.Configuration) (x : XView)
    (fallback : Unit → Option Bool) {b : Classes.StepBranch} (mem : b ∈ ReadersCompiler.generatedColumns) :
    (@ReadersCompiler.readView ⟨cfg⟩ x b).orElse fallback = @ReadersCompiler.readView ⟨cfg⟩ x b := by
  have known : (@ReadersCompiler.readView ⟨cfg⟩ x b).isSome :=
    (@ReadersCompiler.readView_supported ⟨cfg⟩ x b).trans (decide_eq_true mem)
  obtain ⟨_, eq⟩ := Option.isSome_iff_exists.mp known
  simp only [eq, Option.orElse_some]

/-- Local coordinates also ignore the entire finite ghost, ordered past,
and both commit lists. The network snapshots and action remain real. -/
public def Factored (b : Classes.StepBranch) : Prop :=
  ∀ (input : CensusGhost.Input) (cfg : FullProfile.Configuration) (x : XView)
    (past : List Model.State) (pre post : List (Nat × List Entry)) (fallback : Unit → Option Bool),
    let view : XView := {x with base := {x.base with past}, committedBefore := pre, committedAfter := post}
    @CensusGhost.Exec.readView input ⟨cfg⟩ view b = (@ReadersCompiler.readView ⟨cfg⟩ x b).orElse fallback

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

end ConsensusCoverage.CensusExactLocal
