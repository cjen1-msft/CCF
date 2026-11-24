module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.CensusObserved
import all ConsensusCoverage.CensusObserved
import all ConsensusCoverage.CensusGrantFold
import all ConsensusCoverage.CensusGrants
import all ConsensusCoverage.ExplorerGhost
import all ConsensusCoverage.GrantFrontier
import all ConsensusCoverage.GrantMonitor
import all ConsensusCoverage.Historical
import all ConsensusCoverage.ReadersAtoms

namespace ConsensusCoverage.CensusGrants

open Consensus Consensus.Model Consensus.Model.Node ExplorerGhost

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

private def eligible (g : Ghost) (v c k : Nat) :=
  v == c || g.seen.any fun (n, term, _) => n == c && term == k

private def MayGrant (g : Ghost) (s : Model.State) (v c k : Nat) (x y : NodeState) : Prop :=
  s.nodes.lookup v = some x ∧ y.votedFor = some c ∧ y.currentTerm = k ∧
    x.currentTerm ≤ k ∧ eligible g v c k = true

private theorem selected {g : Ghost} {s : Model.State} {v c k : Nat} {y : NodeState}
    (yes : select (v, c, k) (candidate g s (v, y)) ≠ none) : ∃ x, MayGrant g s v c k x y := by
  cases vote : y.votedFor with
  | none => simp [candidate, vote, select] at yes
  | some w =>
    cases pre : s.nodes.lookup v with
    | none => simp [candidate, vote, pre, select] at yes
    | some x =>
      by_cases e : (x.currentTerm ≤ y.currentTerm && eligible g v w y.currentTerm) = true
      <;> unfold eligible at e
      <;> cases old : g.granted v w y.currentTerm (GrantFrontier.minimum x y.currentTerm)
      <;> simp [candidate, vote, pre, select, e, old, guard,
        show (failure : Option Unit) = none from rfl] at yes
      have facts : x.currentTerm ≤ y.currentTerm ∧ eligible g v w y.currentTerm = true := by
        simpa [eligible] using e
      exact ⟨x, pre, by grind, by grind, by grind, by grind⟩

private theorem update_iff (g : Ghost) (s t : Model.State) (v c k : Nat) (r : RequestVoteRequest)
    (lookup : ∀ z, (v, z) ∈ t.nodes ↔ t.nodes.lookup v = some z) :
    ({g with grants := (extendGrants g s t).1}).granted v c k r = true ↔
      g.granted v c k r = true ∨ ∃ x y, t.nodes.lookup v = some y ∧
        MayGrant g s v c k x y ∧ voteLogUpToDate x r := by
  cases post : t.nodes.lookup v with
  | none => simp [absent g s t v c k r post lookup]
  | some y =>
    by_cases can : ∃ x, MayGrant g s v c k x y
    · obtain ⟨x, pre, vote, term, le, elig⟩ := can
      subst k
      rw [by_voter g s t v c _ r y post lookup, eligible_update g s t v c x y pre vote le elig]
      simp [MayGrant, pre, vote, elig]
      grind
    · have no : select (v, c, k) (candidate g s (v, y)) = none :=
        Classical.byContradiction fun h => can (selected h)
      have same : ({g with grants := (extendGrants g s t).1}).granted v c k r = g.granted v c k r := by
        unfold Ghost.granted
        rw [extend_lookup _ _ _ _ _ _ lookup]
        simp [post, no]
      rw [same]
      grind

/-- The stream and the ordered-history reader agree on every request, not
just the campaign request chosen by an election reader. -/
public def GrantHistory (g : Ghost) (h : List Model.State) : Prop :=
  ∀ v c k r, g.granted v c k r = ReadersAtoms.grantedIn h v c k r

public theorem grants_start (bootstrap : NodeID) (s : Model.State) : GrantHistory (start bootstrap s) [s] := by
  intro v c k r
  rfl

private theorem eligible_iff {g : Ghost} {h : List Model.State} (seen : CensusObserved.Tracks g h)
    (q : GrantMonitor.Query) :
    eligible g q.voter q.candidate q.term = true ↔ q.voter = q.candidate ∨ GrantMonitor.HasSeen q h := by
  simp only [eligible, Bool.or_eq_true, beq_iff_eq]
  apply or_congr_right
  simp only [List.any_eq_true, Prod.exists, Bool.and_eq_true, beq_iff_eq,
    seen.1, List.mem_map, ReadersAtoms.histNodes, List.mem_flatMap, CensusObserved.observe,
    GrantMonitor.HasSeen, Historical.Seen, Prod.mk.injEq]
  grind

/-- Every actual successful advance preserves all vote grants, assuming
node-table lookup agrees with membership at both ends of the edge. -/
public theorem grants_read {cfg : FullProfile.Configuration} {g : Ghost}
    {s t : Model.State} {act : Model.Action} {edge : Edge} {h : List Model.State}
    (run : ExplorerGhost.read cfg g s t act = some edge)
    (seen : CensusObserved.Tracks g (s :: h)) (old : GrantHistory g (s :: h))
    (before : ∀ v x, (v, x) ∈ s.nodes ↔ s.nodes.lookup v = some x)
    (after : ∀ v y, (v, y) ∈ t.nodes ↔ t.nodes.lookup v = some y) :
    GrantHistory edge.ghost (t :: s :: h) := by
  intro v c k r
  have updated : edge.ghost.grants = (extendGrants g s t).1 := by
    unfold ExplorerGhost.read at run
    simp only [Option.bind_eq_bind, Option.bind_eq_some_iff] at run
    obtain ⟨_, _, _, _, _, _, _, _, eq⟩ := run
    cases eq
    rfl
  have same : edge.ghost.granted v c k r =
      ({g with grants := (extendGrants g s t).1}).granted v c k r := by
    simp [Ghost.granted, updated]
  apply Bool.eq_iff_iff.mpr
  rw [same, update_iff _ _ _ _ _ _ _ (after v), old, ReadersAtoms.grantedIn_iff,
    ReadersAtoms.grantedIn_iff, GrantMonitor.granted_cons ⟨v, c, k, r⟩]
  apply or_congr_right
  simp only [MayGrant, ← before, ← after, Historical.GrantStep]
  have elig := eligible_iff seen (GrantMonitor.Query.mk v c k r)
  grind

end ConsensusCoverage.CensusGrants
