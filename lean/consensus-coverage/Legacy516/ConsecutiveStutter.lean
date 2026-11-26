module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ActionProfile
public import ConsensusCoverage.SignedQuiet
import all ConsensusCoverage.BackingStutter
import all ConsensusCoverage.CommitKeys
import all ConsensusCoverage.Historical
import all ConsensusCoverage.StateCoverage
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.ConsecutiveStutter

open ActionProfile
open Consensus Consensus.Proofs Consensus.Proofs.Safety

private theorem fold_grant_eq (cfg : FullProfile.Configuration)
    {prev before after : Model.State} {past : List Model.State}
    (first : prev.nodes = before.nodes) (second : before.nodes = after.nodes) :
    (CommitKeys.historicalFold cfg (after :: before :: prev :: past)).grant =
      (CommitKeys.historicalFold cfg (before :: prev :: past)).grant := by
  letI : Config.InitialConfiguration := ⟨cfg⟩
  let old := Historical.logFacts (prev :: past)
  let mid := LogFacts.advance Config.INITIAL_PRIMARY old (some prev) before
  let latest := LogFacts.advance Config.INITIAL_PRIMARY mid (some before) after
  -- The pre-frame of the first edge already observes everything in `prev`.
  have seen : mid.seen = old.seen := by
    funext n k l
    apply propext
    change (old.seen n k l ∨
      ∃ st, (n, st) ∈ before.nodes ∧ st.currentTerm = k ∧ st.log = l) ↔ old.seen n k l
    rw [← first]
    exact ⟨fun h => h.elim id Or.inr, Or.inl⟩
  change latest.grant = mid.grant
  funext v c k r
  apply propext
  refine ⟨?_, Or.inl⟩
  rintro (prior | ⟨p, eq, grant, eligible⟩)
  · exact prior
  · cases Option.some.inj eq
    have priorGrant : LogFacts.GrantAt prev before v c k r := by
      simpa only [LogFacts.GrantAt, first, second] using grant
    rw [seen] at eligible
    exact .inr ⟨prev, rfl, priorGrant, eligible⟩

/-- In an initialized run, the second of two successive node-preserving
actions adds no grant. Only the immediately preceding action must also
preserve nodes; neither action is restricted on messages or commit keys. -/
public theorem noNewGrant (s : Step) {prev : Model.State} {past : List Model.State}
    (history : s.past = prev :: past) (first : prev.nodes = s.before.nodes)
    (second : s.before.nodes = s.after.nodes) :
    GrantFrontier.noNewGrant s.after (s.before :: s.past) = true := by
  rw [history, GrantFrontier.noNewGrant_iff s.cfg, fold_grant_eq s.cfg first second]
  exact fun _ _ _ _ grant => grant

/-- The actual grant relation is unchanged, for every request. -/
public theorem grants_eq (s : Step) {prev : Model.State} {past : List Model.State}
    (history : s.past = prev :: past) (first : prev.nodes = s.before.nodes)
    (second : s.before.nodes = s.after.nodes) :
    GrantFrontier.grantsAfter s = GrantFrontier.grantsBefore s :=
  (GrantFrontier.step_grant_eq s).mp (noNewGrant s history first second)

/-- For these steps the evidence gate need only test committed-key freshness. -/
public theorem evidence_eq (s : Step) {prev : Model.State} {past : List Model.State}
    (history : s.past = prev :: past) (first : prev.nodes = s.before.nodes)
    (second : s.before.nodes = s.after.nodes) :
    SignedQuiet.evidence s.cfg s.before s.after s.past =
      CommitKeys.noNew (s.cfg.min?.getD 0) s.after (s.before :: s.past) := by
  simp only [SignedQuiet.evidence, noNewGrant s history first second, Bool.true_and]

/-- A node-preserving action cannot add a key if its predecessor added none.
The predecessor need not preserve nodes: its post-frame already tested the
same certificates against the same committed backing. -/
public theorem noNewCommit (s : Step) {prev : Model.State} {past : List Model.State}
    (history : s.past = prev :: past) (nodes : s.before.nodes = s.after.nodes)
    (quiet : CommitKeys.noNew (s.cfg.min?.getD 0) s.before (prev :: past) = true) :
    CommitKeys.noNew (s.cfg.min?.getD 0) s.after (s.before :: s.past) = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let f := StateCoverage.frame prev past
  have frame_eq : s.frame = f.advance s.before := by
    change StateCoverage.frame s.before s.past = _
    rw [history]
    rfl
  have earlier : ∀ k p, Committed s.frame k p → Committed f k p := by
    rw [frame_eq]
    change ∀ k p, (StateCoverage.frame s.before (prev :: past)).logs.committed k p →
      (StateCoverage.frame prev past).logs.committed k p
    rw [StateCoverage.frame_logs, StateCoverage.frame_logs]
    exact (CommitKeys.noNew_iff s.cfg _ _).mp quiet
  have same := nodes.symm.trans (congrArg (fun t : Model.State => t.nodes) s.current_eq).symm
  apply (CommitKeys.step_noNew s).mpr
  intro k p post
  change Committed (s.frame.advance s.after) k p at post
  change Committed s.frame k p
  rcases post with old | ⟨n, st, b, i, cert, rfl, backing⟩
  · exact old
  · have cert := (BackingStutter.commitStep_iff_of_nodes s.folded.invariant same).mp cert
    have backing : Backed f st.log b k :=
      backing.imp_right fun ⟨e, part, was, le, sub⟩ => ⟨e, part, earlier e part was, le, sub⟩
    rw [frame_eq] at cert ⊢
    exact .inr ⟨n, st, b, i, cert, rfl, backing⟩

end ConsensusCoverage.ConsecutiveStutter
