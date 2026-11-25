module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ClauseGlobalBound
public import ConsensusCoverage.ClauseSampleBound
public meta import ConsensusCoverage.Classes
public meta import ConsensusCoverage.ReadersTotal
public meta import Lean
import all ConsensusCoverage.ClauseRankRead
import all ConsensusCoverage.BoundedWitnesses
import all ConsensusCoverage.CensusWidth
import all ConsensusCoverage.ClauseGlobalBound
import all ConsensusCoverage.ClauseQuestions
import all ConsensusCoverage.ClauseSampleBound
import all ConsensusCoverage.ExploredWitnesses
import all ConsensusCoverage.JointWitnesses
import all ConsensusCoverage.ReadersCorpus
import all ConsensusCoverage.ReadersTotal

namespace ConsensusCoverage.ClauseWideTree

open ClauseQuestions ClauseSampleBound ActionProfile

set_option maxRecDepth 8192
set_option maxHeartbeats 0

public abbrev Key := Nat × Nat

open Lean Meta in
local elab "coveredSlots%" : term => do
  let cs := (← getConstInfoInduct ``Classes.StepBranch).ctors.toArray
  mkArrayLit (mkConst ``Classes.StepBranch) (ReadersTotal.covered.map fun (b : Classes.StepBranch) =>
    mkConst cs[b.ctorIdx]!)

/-- Without this checked literal index, each witness recomputes the entire
deduplicated reader list to find its first branch. -/
private def slots : Array Classes.StepBranch := coveredSlots%

private theorem slots_eq : slots.toList = ReadersTotal.covered := by decide +kernel

private def classify (splits : List Nat) (trees : Forest) (k : Nat) (answer : Nat → Option Bool) :
    Option Key :=
  if k ∈ splits then ((trees k).run answer).map (k,·) else some (k,0)

private def project (splits : List Nat) (trees : Forest) (p : RestrictedProfile) :=
  let k := ExploredWitnesses.project (ClauseGlobalBound.restored p)
  classify splits trees k (p.bits[·]?)

private def answer (s : Step) (b : Classes.StepBranch) :=
  if b = .rankAtGrant_persist_inl then some (ClauseRankRead.retained s)
  else ReadersTotal.read s.cfg s.before s.act s.after s.past b

private theorem answer_correct (s : Step) {b : Classes.StepBranch} {v} (h : answer s b = some v) :
    label s (.step b) = v := by
  unfold answer at h
  split at h
  · subst b
    exact (ClauseRankRead.retained_eq s).trans (Option.some.inj h)
  · exact ReadersTotal.read_correct s h

public def read (splits : List Nat) (trees : Forest) (s : Step) : Option Key := do
  let k := ExploredWitnesses.encode (← JointWitnesses.read s)
  classify splits trees k fun i => slots[i]?.bind (answer s)

private theorem restored (s : Step) :
    ExploredWitnesses.project (ClauseGlobalBound.restored (restrictedLabel ReadersTotal.covered s)) =
    ExploredWitnesses.project (label s) :=
  congrArg (fun x : (Nat × Bool) × Bool => x.1.1) (ClauseGlobalBound.restore_key s)

private theorem correct (splits : List Nat) (trees : Forest) (s : Step) {k}
    (hit : read splits trees s = some k) : project splits trees (restrictedLabel ReadersTotal.covered s) = some k := by
  unfold read at hit
  rw [JointWitnesses.read_eq] at hit
  simp only [Option.bind_eq_bind, Option.bind_some] at hit
  unfold project
  rw [restored]
  change classify splits trees (ExploredWitnesses.project (label s)) _ = some k at hit
  unfold classify at hit ⊢
  split at hit
  · rw [ite_eq_left ‹_›]
    obtain ⟨code,path,rfl⟩ := Option.map_eq_some_iff.mp hit
    apply Option.map_eq_some_iff.mpr
    refine ⟨code, Tree.sound _ ?_ path,rfl⟩
    intro i v h
    obtain ⟨b,slot,eq⟩ := Option.bind_eq_some_iff.mp h
    change (ReadersTotal.covered.map (fun b => label s (.step b)))[i]? = some v
    rw [List.getElem?_map,← slots_eq,Array.getElem?_toList,slot,Option.map_some,answer_correct s eq]
  · rwa [ite_eq_right ‹_›]

public def Hit (splits : List Nat) (trees : Forest) (k : Key) : Prop :=
  ∃ s : Step, project splits trees (restrictedLabel ReadersTotal.covered s) = some k

public theorem hit (splits : List Nat) (trees : Forest) (i j : Nat) (k : Key)
    (eq : (ReadersCorpus.stepAt i j).bind (read splits trees) = some k) : Hit splits trees k := by
  obtain ⟨s,_,ok⟩ := Option.bind_eq_some_iff.mp eq
  exact ⟨s,correct _ _ _ ok⟩

public def checkedKeys (splits : List Nat) {trees : Forest}
    (samples : List {k : Key // Hit splits trees k}) :=
  ((BoundedWitnesses.keys.filter (· ∉ splits)).map (·,0)) ++ samples.map Subtype.val

/-- Keep one certified row for every unsplit old key. Only split or new keys
need model replays and evaluation of wider coordinates. -/
public theorem checked_bound (splits : List Nat) (trees : Forest)
    (samples : List {k : Key // Hit splits trees k}) (n : Nat)
    (cert : (checkedKeys splits samples).length = n ∧ (checkedKeys splits samples).Nodup)
    (rows : List RestrictedProfile) (all : ∀ s, restrictedLabel ReadersTotal.covered s ∈ rows) :
    n ≤ rows.length := by
  have sub : checkedKeys splits samples ⊆ rows.filterMap (project splits trees) := by
    intro k hm
    rcases List.mem_append.mp hm with old | checked
    · obtain ⟨nr,mem,rfl⟩ := List.mem_map.mp old
      obtain ⟨base,outside⟩ := List.mem_filter.mp mem
      obtain ⟨s,found⟩ := BoundedWitnesses.occurs base
      exact List.mem_filterMap.mpr ⟨_,all s,by
        simp only [project,restored,found,classify,of_decide_eq_true outside,↓reduceIte]⟩
    · obtain ⟨⟨_,s,h⟩,_,rfl⟩ := List.mem_map.mp checked
      exact List.mem_filterMap.mpr ⟨_,all s,h⟩
  exact cert.1 ▸ Nat.le_trans (cert.2.length_le_of_subset sub) (List.length_filterMap_le _ _)

end ConsensusCoverage.ClauseWideTree
