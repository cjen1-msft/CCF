module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ReadersGenerated
public import ConsensusCoverage.ReadersPolarGenerated
import all ConsensusCoverage.ReadersCompiler
import all ConsensusCoverage.ReadersGenerated
import all ConsensusCoverage.ReadersPolarCompiler
import all ConsensusCoverage.ReadersPolarGenerated
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
  pools : Thunk (Option ReadersPolar.Pools)

/-- `past` excludes `before` and is ordered newest first. -/
public def read (cfg : FullProfile.Configuration) (before : Model.State) (act : Model.Action)
    (after : Model.State) (past : List Model.State) : Evidence :=
  let view := ofXAction cfg before after past act
  ⟨cfg, view, Thunk.mk fun _ => view.map (ReadersPolar.prepare cfg)⟩

set_option maxHeartbeats 0 in
/-- Try the exact reader first. Neither a failed witness search nor a missing
test is a negative step answer. -/
public def read? (e : Evidence) (b : Classes.StepBranch) : Option Bool :=
  e.view.bind fun x => (@ReadersCompiler.readView ⟨e.cfg⟩ x b).orElse fun _ =>
    e.pools.get.bind fun pools => @ReadersPolarCompiler.readView ⟨e.cfg⟩ x pools b

/-- Every listed coordinate can be read on every initialized recorded step. -/
public def covered : List Classes.StepBranch := ReadersCompiler.generatedColumns

public theorem read?_correct (s : Step) (b : Classes.StepBranch) {v : Bool}
    (h : read? (read s.cfg s.before s.act s.after s.past) b = some v) :
    label s (.step b) = v := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  obtain ⟨x, made, ok⟩ := ofXAction_matches s
  simp only [read?, read, made, Option.bind_some] at h
  let pools := ReadersPolar.prepare s.cfg x
  change (@ReadersCompiler.readView ⟨s.cfg⟩ x b).orElse
    (fun _ => @ReadersPolarCompiler.readView ⟨s.cfg⟩ x pools b) = some v at h
  have iff : v = true ↔ SolvedWitnesses.sig s.context b := by
    cases found : @ReadersCompiler.readView ⟨s.cfg⟩ x b with
    | none =>
      exact ReadersPolarCompiler.picked_some (by simpa only [found, Option.orElse_none] using h)
        (@ReadersPolarCompiler.readView_correct ⟨s.cfg⟩ s.frame s.after s.context b x ok pools)
    | some ans =>
      exact ReadersCompiler.picked_some (by simpa only [found, Option.orElse_some] using h)
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
    simp only [read?, read, made, Option.bind_some]
    change (@ReadersCompiler.readView ⟨s.cfg⟩ x b).orElse
      (fun _ => @ReadersPolarCompiler.readView ⟨s.cfg⟩ x (ReadersPolar.prepare s.cfg x) b) = some v
    exact congrArg (fun r => r.orElse fun _ =>
      @ReadersPolarCompiler.readView ⟨s.cfg⟩ x (ReadersPolar.prepare s.cfg x) b) eq
  rw [h, read?_correct s b h]

set_option maxRecDepth 8192 in
public theorem covered_nodup : covered.Nodup := by decide

end ConsensusCoverage.Readers
