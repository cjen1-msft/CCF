module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ExplorerGhost
public import ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.ExplorerGhost
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.GuardedDomain
import all ConsensusCoverage.CommitMonitor
import all Consensus.Proofs.SafetyInvariant

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

public theorem observation_mem {g : Ghost} {hist : List Model.State} (ok : Tracks g hist)
    (n : NodeID) (o : Safety.Observation) :
    o ∈ ExplorerGhost.observations g n ↔ o ∈ GuardedDomain.observations hist n := by
  cases o with | mk k l =>
    have stored : Safety.Observation.mk k l ∈ ExplorerGhost.observations g n ↔ (n, k, l) ∈ g.seen := by
      rw [ExplorerGhost.observations, List.mem_filterMap]
      constructor
      · rintro ⟨⟨id, term, log⟩, mem, eq⟩
        split at eq <;> simp_all
      · exact fun mem => ⟨(n, k, l), mem, by simp⟩
    rw [stored, ok.1]
    simp only [List.mem_map, histNodes, List.mem_flatMap, GuardedDomain.observations,
      List.mem_filter, Prod.exists, beq_iff_eq, observe, Prod.mk.injEq, Safety.observe,
      Safety.Observation.mk.injEq]
    grind

public theorem prefix_mem {g : Ghost} {hist : List Model.State} (ok : Tracks g hist)
    (p : List Entry) :
    p ∈ ([] :: g.seen.flatMap (fun (_, _, l) => prefixes l)).eraseDups ↔ p ∈ historicalPrefixes hist := by
  rw [List.mem_eraseDups, historicalPrefixes, List.mem_cons, List.mem_cons]
  apply or_congr_right
  simp only [List.mem_flatMap]
  constructor
  · rintro ⟨o, mem, pre⟩
    obtain ⟨node, hn, rfl⟩ := List.mem_map.mp ((ok.1 o).mp mem)
    exact ⟨node, hn, pre⟩
  · rintro ⟨node, hn, pre⟩
    exact ⟨observe node, (ok.1 _).mpr (List.mem_map.mpr ⟨node, hn, rfl⟩), pre⟩

/-- Exact single-step election tuples, conditional on grant answers and
unambiguous pre-state lookup. No raw history is needed to enumerate tuples. -/
public theorem election_mem {g : Ghost} {s t : Model.State} {h : List Model.State}
    (lookup : ∀ n x, (n, x) ∈ s.nodes ↔ s.nodes.lookup n = some x)
    (grants : ∀ v n k r, g.granted v n k r = grantedIn (t :: s :: h) v n k r)
    (n k : Nat) (l : List Entry) (i : Nat) :
    (n, k, l, i) ∈ elections g s t ↔ electionExact t s h n k l i = true := by
  constructor
  · intro mem
    obtain ⟨⟨id, y⟩, new, yes⟩ := List.mem_filterMap.mp mem
    cases hx : s.nodes.lookup id with
    | none => simp [hx] at yes
    | some x =>
      simp [hx, guard, Option.bind_eq_some_iff, grants] at yes
      obtain ⟨⟨floor, role⟩, ⟨⟨bound, campaign⟩, sub⟩, votes, rfl, rfl, rfl, rfl⟩ := yes
      simp only [electionExact, List.any_eq_true, Prod.exists, Bool.and_eq_true, decide_eq_true_eq]
      exact ⟨id, x, (lookup _ _).mpr hx, id, y, new,
        ⟨rfl, rfl, rfl, rfl, bound, campaign, rfl, role, sub, floor⟩, by simpa using votes⟩
  · intro yes
    simp only [electionExact, List.any_eq_true, Prod.exists, Bool.and_eq_true, decide_eq_true_eq] at yes
    obtain ⟨_, x, old, id, y, new, ⟨rfl, rfl, rfl, rfl, bound, campaign, term, role, sub, floor⟩, quorum⟩ := yes
    subst k
    refine List.mem_filterMap.mpr ⟨(_, y), new, ?_⟩
    have votes : CommitMonitor.quorum (Config.activeConfigurationsOf x)
        (fun v => g.granted v id y.currentTerm (LogFacts.requestAt y.currentTerm x.log x.commitIndex)) = true := by
      simpa [grants] using quorum
    simp [(lookup _ _).mp old, floor, role, campaign, sub, bound, votes, guard]

public def ElectionHistory (g : Ghost) (h : List Model.State) : Prop :=
  ∀ n k l i, (n, k, l, i) ∈ g.elected ↔ electedExact n k l i h = true

public theorem elections_start (b : NodeID) (s : Model.State) : ElectionHistory (start b s) [s] := by
  intro n k l i
  change (n, k, l, i) ∈ ([] : List (NodeID × Nat × List Entry × Nat)) ↔ false = true
  simp

public theorem elections_read {cfg : FullProfile.Configuration} {g : Ghost} {s t : Model.State}
    {act : Model.Action} {edge : Edge} {h : List Model.State}
    (run : ExplorerGhost.read cfg g s t act = some edge)
    (old : ElectionHistory g (s :: h))
    (lookup : ∀ n x, (n, x) ∈ s.nodes ↔ s.nodes.lookup n = some x)
    (grants : ∀ v n k r, edge.ghost.granted v n k r = grantedIn (t :: s :: h) v n k r) :
    ElectionHistory edge.ghost (t :: s :: h) := by
  intro n k l i
  have accumulated : edge.ghost.elected = union g.elected (elections edge.ghost s t) := by
    unfold ExplorerGhost.read at run
    simp only [Option.bind_eq_bind, Option.bind_eq_some_iff] at run
    obtain ⟨_, _, _, _, _, _, _, _, eq⟩ := run
    cases eq
    rfl
  rw [accumulated, mem_union, old, election_mem lookup grants]
  simp only [electedExact, Bool.or_eq_true, or_comm]

end ConsensusCoverage.CensusObserved
