module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ReadersAtoms
public import ConsensusCoverage.ReadersCompiler
public import ConsensusCoverage.ReadersMatchGuard
public import ConsensusCoverage.ReadersShapes
public import Consensus.Proofs.LogFacts
public import Consensus.Proofs.VoteFacts
import all ConsensusCoverage.ActionProfile
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.ReadersCompiler
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
meta import ConsensusCoverage.ReadersCompiler
meta import Lean

namespace ConsensusCoverage.ReadersExtra

open Consensus Consensus.Proofs ActionProfile ReadersAtoms
open Lean Elab Command

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxHeartbeats 0
set_option maxRecDepth 16384
set_option Elab.async false

run_cmd liftTermElabM do
  let columns := ({} : NameSet)
  let columns := columns.insert ``Classes.StepBranch.match_ack_matchIndex_inl
  let columns := columns.insert ``Classes.StepBranch.match_ack_now_after_inl
  let columns := columns.insert ``Classes.StepBranch.acceptLog_eq_conflict_some
  let columns := columns.insert ``Classes.StepBranch.acceptLog_eq_eq_zero_or_pos_inl
  let columns := columns.insert ``Classes.StepBranch.acceptLog_eq_eq_zero_or_pos_inr
  let columns := columns.insert ``Classes.StepBranch.acceptLog_eq_conflict_none
  let columns := columns.insert ``Classes.StepBranch.acceptLog_eq_long_pos
  let columns := columns.insert ``Classes.StepBranch.acceptLog_eq_long_neg
  let columns := columns.insert ``Classes.StepBranch.acceptLog_eq_eq_or_lt_of_le_inl
  let columns := columns.insert ``Classes.StepBranch.acceptLog_eq_eq_or_lt_of_le_inr
  ReadersCompiler.driverWith none {
    namespaceName := `ConsensusCoverage.ReadersExtra.Compiled,
    columns := some columns, extraRules := true }

/-- Additional exact readers over the raw view, outside the factored census. -/
public def covered : List Classes.StepBranch := Compiled.generatedColumns

public def read? (cfg : FullProfile.Configuration) (view : Option XView)
    (b : Classes.StepBranch) : Option Bool :=
  view.bind fun x => @Compiled.readView ⟨cfg⟩ x b

public theorem read?_correct (s : Step) {b : Classes.StepBranch} {v : Bool}
    (h : read? s.cfg (ofXAction s.cfg s.before s.after s.past s.act) b = some v) :
    label s (.step b) = v := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  obtain ⟨x, made, ok⟩ := ofXAction_matches s
  simp only [read?, made, Option.bind_some] at h
  have iff := ReadersCompiler.picked_some h
    (@Compiled.readView_correct ⟨s.cfg⟩ s.frame s.after s.context b x ok)
  exact Bool.eq_iff_iff.mpr ((label_true s (.step b)).trans
    ((SolvedWitnesses.sig_iff s.context b).trans iff.symm))

public theorem read?_at (s : Step) {b : Classes.StepBranch} (mem : b ∈ covered) :
    read? s.cfg (ofXAction s.cfg s.before s.after s.past s.act) b = some (label s (.step b)) := by
  obtain ⟨x, made, _⟩ := ofXAction_matches s
  have yes : (@Compiled.readView ⟨s.cfg⟩ x b).isSome :=
    (@Compiled.readView_supported ⟨s.cfg⟩ x b).trans (decide_eq_true mem)
  obtain ⟨v, eq⟩ := Option.isSome_iff_exists.mp yes
  have read : read? s.cfg (ofXAction s.cfg s.before s.after s.past s.act) b = some v := by
    simpa only [read?, made, Option.bind_some] using eq
  exact read.trans (congrArg some (read?_correct s read).symm)

public theorem covered_count : covered.length = 10 := by decide +kernel

end ConsensusCoverage.ReadersExtra
