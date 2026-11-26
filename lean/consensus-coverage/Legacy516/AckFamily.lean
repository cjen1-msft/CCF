module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.FamilyPrune
meta import ConsensusCoverage.FamilyPrune
import all ConsensusCoverage.ActionContext
import all ConsensusCoverage.EventSupport
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.AckFamily

open ActionProfile FullProfile Consensus Consensus.Proofs Consensus.Proofs.Safety

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxHeartbeats 0
set_option maxRecDepth 8192

public section

run_cmd Lean.Elab.Command.liftTermElabM do
  let stale := [``EvidenceSupport.Family.pending, ``EvidenceSupport.Family.seen, ``EvidenceSupport.Family.grant,
    ``EvidenceSupport.Family.elected, ``EvidenceSupport.Family.canon, ``EvidenceSupport.Family.committed]
  FamilyPrune.generate `ConsensusCoverage.AckFamily ``EventSupport.Tag.appendEntriesResponse stale

@[expose] def test (cfg : Configuration) (before : Model.State) (act : Model.Action)
    (after : Model.State) (past : List Model.State) : Bool :=
  EventSupport.actionTag act == .appendEntriesResponse &&
    let e := EvidenceSupport.read cfg before act after past
    e.now && stale.all fun k => !e.fresh k

/-- Every column outside the generated table is false on the recorded
append response that adds only its actor's node record. -/
theorem excluded_of_test (s : Step) (pass : test s.cfg s.before s.act s.after s.past = true)
    (b : Classes.StepBranch) (out : possible b = false) :
    label s (.step b) = false := by
  simp only [test, Bool.and_eq_true, beq_iff_eq, List.all_eq_true, Bool.not_eq_true'] at pass
  exact excluded s pass.1 pass.2.2 trivial b out

end
end ConsensusCoverage.AckFamily
