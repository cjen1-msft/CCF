module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ExplorerGhost
public import ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.ExplorerGhost
import all ConsensusCoverage.ReadersAtoms

namespace ConsensusCoverage.CensusObserved

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs ExplorerGhost ReadersAtoms

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

public def observe (p : NodeID × NodeState) : NodeID × Nat × List Entry :=
  (p.1, p.2.currentTerm, p.2.log)

private theorem mem_union [BEq α] [LawfulBEq α] (x : α) (left right : List α) :
    x ∈ union left right ↔ x ∈ left ∨ x ∈ right := by
  induction right generalizing left with
  | nil => simp [union]
  | cons a l ih =>
    change x ∈ union (if left.contains a then left else a :: left) l ↔ _
    rw [ih]
    by_cases mem : a ∈ left <;> simp [mem] <;> grind

private theorem log_seen (g : Ghost) (b : NodeID) (s : Model.State) :
    (logDelta g b s).1.seen = union g.seen (s.nodes.map observe) := rfl

private theorem log_votes (g : Ghost) (b : NodeID) (s : Model.State) :
    (logDelta g b s).1.votes = VoteFacts.advance g.votes s := rfl

/-- Exact historical inputs for the observation and vote-stamp reader atoms.
Observation membership, not its storage order or multiplicity, matters. -/
public def Tracks (g : Ghost) (hist : List Model.State) : Prop :=
  (∀ o, o ∈ g.seen ↔ o ∈ (histNodes hist).map observe) ∧ g.votes = voteStamps hist

public theorem tracks_start (b : NodeID) (s : Model.State) : Tracks (start b s) [s] := by
  constructor
  · intro o
    change o ∈ (logDelta {} b s).1.seen ↔ _
    rw [log_seen, mem_union]
    simp [histNodes]
  · rfl

public theorem tracks_read (cfg : FullProfile.Configuration) (g : Ghost)
    (s t : Model.State) (act : Model.Action) (edge : Edge) (hist : List Model.State)
    (ok : Tracks g hist) (hr : ExplorerGhost.read cfg g s t act = some edge) :
    Tracks edge.ghost (t :: hist) := by
  unfold ExplorerGhost.read at hr
  simp only [Option.bind_eq_bind, Option.bind_eq_some_iff] at hr
  obtain ⟨_, _, _, _, _, _, _, _, eq⟩ := hr
  cases eq
  constructor
  · intro o
    rw [log_seen, mem_union]
    change (o ∈ g.seen ∨ o ∈ t.nodes.map observe) ↔ _
    rw [ok.1]
    simp [histNodes, or_comm]
  · dsimp
    rw [log_votes]
    change VoteFacts.advance g.votes t = VoteFacts.advance (voteStamps hist) t
    rw [ok.2]

end ConsensusCoverage.CensusObserved
