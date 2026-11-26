module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.CensusGrantHistory
import all ConsensusCoverage.CensusGrantHistory
import all ConsensusCoverage.StateCoverage
import all ConsensusCoverage.ActionProfile
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.CensusTimed

open Consensus Consensus.Model Consensus.Model.Node ExplorerGhost CensusObserved CensusGrants

private theorem lookup_iff (ps : List (NodeID × NodeState)) (v : NodeID) (st : NodeState)
    (unique : (ps.map Prod.fst).Nodup) : (v, st) ∈ ps ↔ ps.lookup v = some st := by
  induction ps with
  | nil => simp
  | cons p ps ih =>
    rcases p with ⟨w, z⟩
    simp only [List.map_cons, List.nodup_cons] at unique
    by_cases eq : v = w
    · subst w
      have absent : (v, st) ∉ ps := fun mem => unique.1 (List.mem_map.mpr ⟨_, mem, rfl⟩)
      simp [absent, eq_comm]
    · simp [List.lookup_cons, beq_eq_false_iff_ne.mpr eq, eq, ih unique.2]

public theorem lookup_run {cfg ns s h} (run : StateCoverage.Run cfg ns s h) (v : NodeID) (st : NodeState) :
    (v, st) ∈ s.nodes ↔ s.nodes.lookup v = some st := by
  letI : Consensus.Proofs.Config.InitialConfiguration := ⟨cfg⟩
  apply lookup_iff
  simpa only [StateCoverage.frame_current] using (@StateCoverage.run_inv ‹_› _ _ _ run).distinct

/-- History facts tracked by the actual start/advance functions. The
native interning step is not part of this invariant. -/
public structure Tracks (g : Ghost) (h : List Model.State) : Prop where
  observations : CensusObserved.Tracks g h
  grants : GrantHistory g h
  elections : ElectionHistory g h

public theorem tracks_start (b : NodeID) (s : Model.State) : Tracks (start b s) [s] :=
  ⟨CensusObserved.tracks_start b s, grants_start b s, elections_start b s⟩

public theorem tracks_step (s : ActionProfile.Step) {g : Ghost} {edge : Edge}
    (old : Tracks g (s.before :: s.past))
    (run : ExplorerGhost.read s.cfg g s.before s.after s.act = some edge) :
    Tracks edge.ghost (s.after :: s.before :: s.past) := by
  have be := lookup_run s.run
  have af := lookup_run (StateCoverage.Run.step s.run s.ran)
  have grants := grants_read run old.observations old.grants be af
  exact ⟨CensusObserved.tracks_read _ _ _ _ _ _ _ old.observations run,
    grants, elections_read run old.elections be grants⟩

end ConsensusCoverage.CensusTimed
