module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.Proofs.SafetyInvariant
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.GrantMonitor

open Consensus Consensus.Model.Node Consensus.Proofs.Safety

public structure Query where
  voter : NodeID
  candidate : NodeID
  term : Nat
  request : RequestVoteRequest

public structure Memory where
  seenCandidate : Bool
  granted : Bool
deriving DecidableEq, Repr

private def here (q : Query) (s : Model.State) : Bool :=
  s.nodes.any fun (n, st) => n == q.candidate && st.currentTerm == q.term

private def grantStep (q : Query) (s t : Model.State) : Bool :=
  (s.nodes.any fun (n, st) =>
    n == q.voter && decide (st.currentTerm ≤ q.term ∧ voteLogUpToDate st q.request)) &&
  (t.nodes.any fun (n, st) =>
    n == q.voter && st.currentTerm == q.term && st.votedFor == some q.candidate)

public def start (q : Query) (s : Model.State) : Memory := ⟨here q s, false⟩

/-- Candidate evidence must predate the grant; seeing the candidate for the first time
in the after-state is insufficient, except when the voter is the candidate itself. -/
public def advance (q : Query) (old : Memory) (s t : Model.State) : Memory :=
  ⟨old.seenCandidate || here q t,
   old.granted || (grantStep q s t && (q.voter == q.candidate || old.seenCandidate))⟩

public def HasSeen (q : Query) (h : List Model.State) : Prop :=
  ∃ st, Seen h q.candidate st ∧ st.currentTerm = q.term

public def HasGrant (q : Query) (h : List Model.State) : Prop :=
  Granted h q.voter q.candidate q.term q.request

private theorem seen_cons (q : Query) (t : Model.State) (h : History) :
    HasSeen q (t :: h) ↔ HasSeen q h ∨ here q t = true := by
  simp only [HasSeen, Seen, here, List.any_eq_true, Prod.exists, Bool.and_eq_true, beq_iff_eq,
    List.mem_cons]
  grind

private theorem grantStep_iff (q : Query) (s t : Model.State) :
    grantStep q s t = true ↔ GrantStep t s q.voter q.candidate q.term q.request := by
  simp only [grantStep, GrantStep, Bool.and_eq_true, List.any_eq_true, Prod.exists, beq_iff_eq,
    decide_eq_true_eq]
  grind

private theorem granted_cons (q : Query) (t s : Model.State) (h : History) :
    Granted (t :: s :: h) q.voter q.candidate q.term q.request ↔
      Granted (s :: h) q.voter q.candidate q.term q.request ∨
      (GrantStep t s q.voter q.candidate q.term q.request ∧
        (q.voter = q.candidate ∨ HasSeen q (s :: h))) := by
  constructor
  · rintro ⟨a, b, rest, suffix, step, seen⟩
    rcases List.suffix_cons_iff.mp suffix with eq | old
    · cases eq; exact .inr ⟨step, seen⟩
    · exact .inl ⟨a, b, rest, old, step, seen⟩
  · rintro (⟨a, b, rest, old, step, seen⟩ | ⟨step, seen⟩)
    · exact ⟨a, b, rest, List.suffix_cons_iff.mpr (.inr old), step, seen⟩
    · exact ⟨t, s, h, List.suffix_refl _, step, seen⟩

/-- Batch specification of the online monitor; the proof's histories are newest first. -/
public def scan (q : Query) (s : Model.State) : List Model.State → Memory
  | [] => start q s
  | prev :: h => advance q (scan q prev h) prev s

public theorem correct (q : Query) (s : Model.State) (h : List Model.State) :
    ((scan q s h).seenCandidate = true ↔ HasSeen q (s :: h)) ∧
    ((scan q s h).granted = true ↔ HasGrant q (s :: h)) := by
  unfold HasGrant
  induction h generalizing s with
  | nil =>
    constructor
    · rw [seen_cons]
      simp [scan, start, HasSeen, Seen]
    · change false = true ↔ _
      constructor
      · intro no; contradiction
      · rintro ⟨a, b, rest, suffix, _, _⟩
        have len := suffix.length_le
        simp at len
  | cons prev h ih =>
    obtain ⟨seen, granted⟩ := ih prev
    rw [seen_cons, granted_cons]
    simp [scan, advance, seen, granted, grantStep_iff]

/-- The fourth bit combination, a grant without candidate evidence, is impossible.
In the self-vote case the granting after-state itself supplies that evidence. -/
public theorem granted_implies_seen (q : Query) (s : Model.State) (h : List Model.State)
    (yes : (scan q s h).granted = true) : (scan q s h).seenCandidate = true := by
  obtain ⟨seen, grant⟩ := correct q s h
  apply seen.2
  obtain ⟨a, b, rest, suffix, step, self | ⟨st, old, term⟩⟩ := grant.1 yes
  · obtain ⟨_, post, _, mem, _, term, _⟩ := step
    rw [self] at mem
    exact ⟨post, ⟨a, suffix.subset List.mem_cons_self, mem⟩, term⟩
  · obtain ⟨prior, member, mem⟩ := old
    exact ⟨st, ⟨prior, suffix.subset (.tail a member), mem⟩, term⟩

end ConsensusCoverage.GrantMonitor
