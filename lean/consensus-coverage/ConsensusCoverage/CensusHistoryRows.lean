module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.CensusPriorRows
public import ConsensusCoverage.CensusObservationRows
public import ConsensusCoverage.CensusProbe
import all ConsensusCoverage.CensusPriorRows
import all ConsensusCoverage.CensusObservationRows
import all ConsensusCoverage.CensusExactLocal
import all ConsensusCoverage.CensusGhost
import all ConsensusCoverage.ReadersGenerated
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.GuardedDomain

namespace ConsensusCoverage.CensusHistoryRows

open Consensus Consensus.Model ReadersAtoms

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxRecDepth 16384

public def columns : List Classes.StepBranch :=
  CensusExactLocal.columns ++ CensusObservationRows.columns ++ CensusPriorRows.columns

public theorem count : columns.Nodup ∧ columns.length = 72 ∧
    columns.all ReadersCompiler.generatedColumns.contains = true := by decide +kernel

/-- For these generated total coordinates the actual finite action lookup
has the same answer as the actual ordered lookup. Both may fail. No
post-commit, election, or canonical-log agreement is required. This
theorem fixes both physical snapshots; it is not a queue quotient. -/
public theorem action_read {b : Classes.StepBranch} (mem : b ∈ columns) (cfg : FullProfile.Configuration)
    (s t : Model.State) (act : Model.Action) (past : List Model.State) (g h : ExplorerGhost.Ghost)
    (pre : CensusObserved.Tracks g (s :: past)) (post : CensusObserved.Tracks h (t :: s :: past))
    (commits : CensusCommitHistory.CommitHistory (cfg.min?.getD 0) g (s :: past)) :
    ((CensusGhost.answers cfg g h s t act).bind (· b)) =
      ((ofXAction cfg s t past act).bind fun x => @ReadersCompiler.readView ⟨cfg⟩ x b) := by
  simp only [columns, List.mem_append] at mem
  rcases mem with (localMem | obsMem) | priorMem
  · cases a : CCF.MultiNodeTransitionSystem.nodeState s (GuardedDomain.actionActor act) <;>
      cases z : CCF.MultiNodeTransitionSystem.nodeState t (GuardedDomain.actionActor act) <;>
      simp only [CensusGhost.answers, ofXAction, GuardedDomain.ofAction, a, z,
        Option.bind_eq_bind, Option.bind_none, Option.bind_some, pure]
    rename_i before after
    let x := packX (GuardedDomain.pack (cfg.min?.getD 0) s t past (GuardedDomain.actionActor act) before after) (eventOf act)
    have agree := CensusExactLocal.correct localMem
      ⟨CensusGhost.slice g, CensusGhost.slice h, ExplorerGhost.elections h s t⟩ cfg x [] g.committed h.committed (fun _ => none)
    have drop (v : Option Bool) : v.orElse (fun _ => none) = v := by cases v <;> rfl
    rw [drop] at agree
    exact agree
  · exact CensusObservationRows.action_read obsMem cfg s t act past g h pre post
  · exact CensusPriorRows.action_read priorMem cfg s t act past g h commits

end ConsensusCoverage.CensusHistoryRows
