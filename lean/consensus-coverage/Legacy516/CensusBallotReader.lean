module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.CensusBallots
public import ConsensusCoverage.ReadersGenerated
import all ConsensusCoverage.CensusBallots
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.ReadersGenerated
import all ConsensusCoverage.SolvedWitnesses
import all ConsensusCoverage.ActionProfile

namespace ConsensusCoverage.CensusBallotReader

open Consensus Consensus.Proofs ActionProfile ReadersAtoms

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxRecDepth 8192

public theorem covered {b : Classes.StepBranch} {v : Bool} (h : CensusBallots.answer b = some v) :
    b ∈ ReadersCompiler.generatedColumns := by
  unfold CensusBallots.answer at h
  split at h
  · rcases ‹_ ∨ _› with rfl | rfl <;> decide +kernel
  · cases h

/-- On every initialized recorded action, the constant shortcut and the
real ordered generated reader agree, including on the exact Option value. -/
public theorem ordered (s : Step) {b : Classes.StepBranch} {v : Bool} (h : CensusBallots.answer b = some v) :
    ((ofXAction s.cfg s.before s.after s.past s.act).bind fun x => @ReadersCompiler.readView ⟨s.cfg⟩ x b) = some v := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  obtain ⟨x, made, ok⟩ := ofXAction_matches s
  rw [made, Option.bind_some]
  have known : (ReadersCompiler.readView x b).isSome :=
    (ReadersCompiler.readView_supported x b).trans (decide_eq_true (covered h))
  obtain ⟨value, read⟩ := Option.isSome_iff_exists.mp known
  rw [read]
  have iff := ReadersCompiler.picked_some read (ReadersCompiler.readView_correct s.frame s.after s.context b x ok)
  have eq : label s (.step b) = value :=
    Bool.eq_iff_iff.mpr ((label_true s (.step b)).trans ((SolvedWitnesses.sig_iff s.context b).trans iff.symm))
  rw [← eq, CensusBallots.answer_correct s h]

end ConsensusCoverage.CensusBallotReader
