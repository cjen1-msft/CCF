module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ReadersGenerated
import all ConsensusCoverage.ReadersCompiler
import all ConsensusCoverage.ReadersGenerated
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.ActionProfile
import all ConsensusCoverage.SolvedWitnesses

namespace ConsensusCoverage.Readers

open Consensus Consensus.Proofs ActionProfile ReadersAtoms

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

/-- Inputs shared by every generated reader at a recorded action boundary. -/
public structure Evidence where
  cfg : FullProfile.Configuration
  view : Option XView

/-- `past` excludes `before` and is ordered newest first. -/
public def read (cfg : FullProfile.Configuration) (before : Model.State) (act : Model.Action)
    (after : Model.State) (past : List Model.State) : Evidence :=
  ⟨cfg, ofXAction cfg before after past act⟩

set_option maxHeartbeats 0 in
/-- A missing reader is unknown, not a negative step answer. -/
public def read? (e : Evidence) (b : Classes.StepBranch) : Option Bool :=
  e.view.bind fun x => @ReadersCompiler.readView ⟨e.cfg⟩ x b

/-- Every listed coordinate can be read on every initialized recorded step. -/
public def covered : List Classes.StepBranch := ReadersCompiler.generatedColumns

public theorem read?_correct (s : Step) (b : Classes.StepBranch) {v : Bool}
    (h : read? (read s.cfg s.before s.act s.after s.past) b = some v) :
    label s (.step b) = v := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  obtain ⟨x, made, ok⟩ := ofXAction_matches s
  change (ofXAction _ _ _ _ _).bind (fun x => @ReadersCompiler.readView ⟨s.cfg⟩ x b) = some v at h
  rw [made] at h
  have iff : v = true ↔ SolvedWitnesses.sig s.context b :=
    ReadersCompiler.picked_some h
      (@ReadersCompiler.readView_correct ⟨s.cfg⟩ s.frame s.after s.context b x ok)
  exact Bool.eq_iff_iff.mpr ((label_true s (.step b)).trans
    ((SolvedWitnesses.sig_iff s.context b).trans iff.symm))

public theorem read?_at (s : Step) {b : Classes.StepBranch} (mem : b ∈ covered) :
    read? (read s.cfg s.before s.act s.after s.past) b = some (label s (.step b)) := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  obtain ⟨x, made, _⟩ := ofXAction_matches s
  have yes : (@ReadersCompiler.readView ⟨s.cfg⟩ x b).isSome :=
    (@ReadersCompiler.readView_supported ⟨s.cfg⟩ x b).trans (decide_eq_true mem)
  obtain ⟨v, eq⟩ := Option.isSome_iff_exists.mp yes
  have h : read? (read s.cfg s.before s.act s.after s.past) b = some v := by
    change (ofXAction _ _ _ _ _).bind (fun x => @ReadersCompiler.readView ⟨s.cfg⟩ x b) = some v
    rw [made]
    exact eq
  rw [h, read?_correct s b h]

set_option maxRecDepth 8192 in
public theorem covered_nodup : covered.Nodup := by decide

end ConsensusCoverage.Readers
