module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.CensusExactLocal
public import ConsensusCoverage.CensusQueue
import all ConsensusCoverage.CensusExactLocal
import all ConsensusCoverage.ReadersGenerated
import all ConsensusCoverage.ReadersAtoms
import all Consensus.Proofs.SafetyInvariant
meta import Lean

namespace ConsensusCoverage.CensusOutgoing

open Consensus Consensus.Model Consensus.Model.Node ReadersAtoms ReadersCompiler.R

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxRecDepth 16384
set_option maxHeartbeats 0

private abbrev swap (x : XView) (before after : List Model.Envelope) : XView :=
  {x with base.before.network := before, base.after.network := after}

/-- Membership on the sent envelopes is the only extra queue information
needed by the history-independent generated coordinates, at a fixed changed bit. -/
public structure Agree (x : XView) (before after : List Model.Envelope) : Prop where
  pre : ∀ z : {z // z ∈ x.outputs.outgoing}, decide (z.val ∈ before) = decide (z.val ∈ x.base.before.network)
  post : ∀ z : {z // z ∈ x.outputs.outgoing}, decide (z.val ∈ after) = decide (z.val ∈ x.base.after.network)

/-- On two one-copy queues for the same removed and emitted envelopes, the
pending part may differ. The decomposition is by membership, not order. -/
public theorem agree_of_one_copy (x : XView) (before after removed pending other : List Model.Envelope)
    (pre : ∀ e, e ∈ x.base.before.network ↔ e ∈ removed ∨ e ∈ pending)
    (post : ∀ e, e ∈ x.base.after.network ↔ e ∈ pending ∨ e ∈ x.outputs.outgoing)
    (one : (pending ++ x.outputs.outgoing).Nodup)
    (otherPre : ∀ e, e ∈ before ↔ e ∈ removed ∨ e ∈ other)
    (otherPost : ∀ e, e ∈ after ↔ e ∈ other ∨ e ∈ x.outputs.outgoing)
    (otherOne : (other ++ x.outputs.outgoing).Nodup) : Agree x before after := by
  constructor <;> intro z
  all_goals
    have a := CensusQueue.outgoing_membership pre post one z.property
    have b := CensusQueue.outgoing_membership otherPre otherPost otherOne z.property
    apply Bool.eq_iff_iff.mpr
    simp only [decide_eq_true_eq]
  · exact b.1.trans a.1.symm
  · exact ⟨fun _ => a.2, fun _ => b.2⟩

private theorem pending_before (x : XView) (e : Model.Envelope) (mem : e ∈ pendingOf x) :
    e ∈ x.base.before.network := by
  cases h : x.event <;> simp only [pendingOf, h] at mem
  · exact mem
  · exact Proofs.Safety.mem_removeOne mem

private theorem retained_arm [Proofs.Config.InitialConfiguration] (x : XView) :
    step_mem_network_mem_append_inl x = false := by
  have mem (z : {e // e ∈ pendingOf x}) := pending_before x z.val z.property
  simp [step_mem_network_mem_append_inl, reach_1013, reach_1014, reach_25, reach_43, mem]

private theorem eq238 [Proofs.Config.InitialConfiguration] (x : XView) (s t : List Model.Envelope) (h : Agree x s t) :
    reach_238 (swap x s t) = reach_238 x := by
  simp only [reach_238, reach_26, reach_25, XView.sent, swap, h.pre, h.post]

private theorem eq64 [Proofs.Config.InitialConfiguration] (x : XView) (s t : List Model.Envelope) (h : Agree x s t) :
    reach_64 (swap x s t) = reach_64 x := by
  simp only [reach_64, reach_43, swap, h.pre, h.post]

private def Stable (b : Classes.StepBranch) : Prop :=
  ∀ (cfg : FullProfile.Configuration) (x : XView) (s t : List Model.Envelope), Agree x s t →
    @ReadersCompiler.readView ⟨cfg⟩ (swap x s t) b = @ReadersCompiler.readView ⟨cfg⟩ x b

private def remaining := CensusExactLocal.columns.filter (!CensusExactLocal.queueColumns.contains ·)

open Lean Meta Elab Term in
local elab "outgoing_certificates" : term => do
  let mut list := Lean.mkConst ``remaining
  let mut out ← `(([] : List { b : Classes.StepBranch // Stable b }))
  repeat
    let value ← whnf list
    if value.isAppOf ``List.nil then break
    unless value.isAppOfArity ``List.cons 3 do throwError "expected a concrete list of local branch names"
    let b := (← whnf value.getAppArgs[1]!).getAppFn.constName!
    let arm := mkIdent b
    let root := mkIdent (`ConsensusCoverage.ReadersCompiler.R ++ Name.mkSimple ("step_" ++ b.getString!))
    out ← `((⟨$arm, by
      intro cfg x s t h
      change some (@$root ⟨cfg⟩ (swap x s t)) = some (@$root ⟨cfg⟩ x)
      congr 1
      first
      | exact (retained_arm _).trans (retained_arm _).symm
      | unfold $root:ident
        first
        | rw [@eq238 ⟨cfg⟩ x s t h] <;> rfl
        | rw [@eq64 ⟨cfg⟩ x s t h] <;> rfl
        | simp only [reach_26, reach_25, reach_43, reach_1013, reach_1014, XView.sent, swap, h.pre, h.post] <;> rfl
      ⟩) :: $out)
    list := value.appArg!
  elabTerm out none

set_option linter.unusedSimpArgs false in
private def certificates : List { b : Classes.StepBranch // Stable b } := outgoing_certificates

/-- All history-independent exact answers tolerate an arbitrary residual
queue when the emitted envelopes have the same pre/post membership. -/
public theorem correct {b : Classes.StepBranch} (mem : b ∈ CensusExactLocal.columns)
    (cfg : FullProfile.Configuration) (x : XView) (s t : List Model.Envelope) (h : Agree x s t) :
    @ReadersCompiler.readView ⟨cfg⟩ (swap x s t) b = @ReadersCompiler.readView ⟨cfg⟩ x b := by
  by_cases free : b ∈ CensusExactLocal.queueColumns
  · exact CensusExactLocal.queue_correct free cfg x s t
  · have covered : remaining.all (certificates.map Subtype.val).contains = true := by decide +kernel
    have m : b ∈ remaining := List.mem_filter.mpr ⟨mem, by simpa using free⟩
    obtain ⟨⟨_, proof⟩, _, rfl⟩ := List.mem_map.mp (List.contains_iff_mem.mp ((List.all_eq_true.mp covered) b m))
    exact proof cfg x s t h

end ConsensusCoverage.CensusOutgoing
