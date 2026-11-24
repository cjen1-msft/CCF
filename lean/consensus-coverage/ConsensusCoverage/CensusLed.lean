module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.CensusTimed
import all ConsensusCoverage.CensusObserved
import all ConsensusCoverage.ExplorerGhost
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.GuardedDomain
import all ConsensusCoverage.CommitMonitor

namespace ConsensusCoverage.CensusLed

open Consensus Consensus.Model Consensus.Model.Node ExplorerGhost CensusObserved

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

public theorem led_eq {g : Ghost} {h : List Model.State} (history : ElectionHistory g h)
    (b n k : Nat) : g.led b n k = GuardedDomain.ledAt b h n k := by
  apply Bool.eq_iff_iff.mpr
  simp only [Ghost.led, GuardedDomain.ledAt, Bool.or_eq_true]
  apply or_congr_right
  have exactElections (m term : Nat) (l : List Entry) (i : Nat) :=
    (history m term l i).trans (ReadersAtoms.electedExact_iff m term l i h)
  simp only [List.any_eq_true, Prod.exists, Bool.and_eq_true, beq_iff_eq, exactElections,
    CommitMonitor.elected_iff]
  grind

/-- The term domains need only preserve membership: bootstrap and the
terms of the recorded timed elections are enough. -/
public theorem term_mem {g : Ghost} {h : List Model.State} (history : ElectionHistory g h)
    (b n k : Nat) : k ∈ g.terms b n ↔ k ∈ GuardedDomain.ledTerms b h n := by
  have stored : k ∈ g.terms b n ↔ g.led b n k = true := by
    unfold Ghost.terms Ghost.led
    split <;> simp only [List.mem_cons, List.mem_filterMap, List.any_eq_true, Prod.exists,
      Bool.or_eq_true, Bool.and_eq_true, beq_iff_eq]
    all_goals grind
  rw [stored, led_eq history, GuardedDomain.ledTerms, List.mem_filter]
  constructor
  · intro led
    refine ⟨?_, led⟩
    rcases Bool.or_eq_true_iff.mp led with boot | elect
    · simp [GuardedDomain.ledAt] at *
      grind
    · obtain ⟨l, i, elect⟩ := (CommitMonitor.elected_iff _ _ _).mp elect
      have term := ReadersAtoms.electedExact_term ((ReadersAtoms.electedExact_iff _ _ _ _ _).mpr elect)
      simpa [ReadersAtoms.histNodes, List.map_flatMap] using List.mem_cons_of_mem BOOTSTRAP_TERM term
  · exact And.right

end ConsensusCoverage.CensusLed
