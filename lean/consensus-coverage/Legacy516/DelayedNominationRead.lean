module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.BackingStutter
public import ConsensusCoverage.GrantFrontier
public import ConsensusCoverage.ReducedQuestions
import all ConsensusCoverage.ActionContext
import all ConsensusCoverage.CommitMonitor
import all ConsensusCoverage.Historical
import all ConsensusCoverage.NominationRows
import all ConsensusCoverage.ReducedQuestions
import all ConsensusCoverage.StateCoverage
import all ConsensusCoverage.StutterProfile
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.DelayedNomination

open ActionProfile
open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

/-- Every election on an edge has a leader record in its newer snapshot.
Use exactly those node/term pairs, and then continue through the older edges. -/
private def scanElections : List Model.State → Bool
  | t :: s :: h =>
      (t.nodes.any fun (n, st) => CommitMonitor.election t s h n st.currentTerm) ||
        scanElections (s :: h)
  | _ => false

@[expose] public def hasElection (h : List Model.State) : Bool := scanElections h

private theorem hasElection_iff (h : List Model.State) :
    scanElections h = true ↔ ∃ n k l i, Historical.Elected h n k l i := by
  induction h with
  | nil => simp [scanElections, Historical.Elected]
  | cons t h ih =>
    cases h with
    | nil =>
      simp only [scanElections, Bool.false_eq_true, false_iff, Historical.Elected]
      rintro ⟨_, _, _, _, _, _, _, suf, _⟩
      have := suf.length_le
      simp at this
    | cons s rest =>
      rw [scanElections, Bool.or_eq_true, ih]
      have edge : (t.nodes.any fun (n, st) => CommitMonitor.election t s rest n st.currentTerm) = true ↔
          ∃ n k l i, Historical.ElectStep t s rest n k l i := by
        simp only [List.any_eq_true, Prod.exists, CommitMonitor.election_iff]
        constructor
        · rintro ⟨n, st, _, l, i, elect⟩
          exact ⟨n, st.currentTerm, l, i, elect⟩
        · rintro ⟨n, k, l, i, elect⟩
          obtain ⟨_, st, _, mem, _, _, _, _, term, _⟩ := id elect
          exact ⟨n, st, mem, l, i, term.symm ▸ elect⟩
      rw [edge]
      unfold Historical.Elected
      simp only [Historical.edge_cons, List.cons.injEq]
      grind

/-- The scan is exact for the proof ghost, including all older snapshots. -/
private theorem noElection_iff (s : Step) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    hasElection (s.after :: s.before :: s.past) = false ↔
      ∀ n k l i, ¬ (s.frame.advance s.after).logs.elected n k l i := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  change _ ↔ ∀ n k l i, ¬ (StateCoverage.frame s.after (s.before :: s.past)).logs.elected n k l i
  simp only [hasElection, StateCoverage.frame_logs, (Historical.logFacts_correct _).elected,
    ← Bool.not_eq_true, hasElection_iff]
  grind

/-- Family membership on raw replay data; no proof context is consulted. -/
@[expose] public def test (cfg : FullProfile.Configuration) (before : Model.State)
    (act : Model.Action) (after : Model.State) (past : List Model.State) : Bool :=
  decide (EventSupport.actionTag act = .nominateSuccessor) &&
    !CommitKeys.noNew (cfg.min?.getD 0) after (before :: past) &&
    GrantFrontier.noNewGrant after (before :: past) &&
    !hasElection (after :: before :: past)

private theorem test_iff (s : Step) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    test s.cfg s.before s.act s.after s.past = true ↔
      EventSupport.actionTag s.act = .nominateSuccessor ∧
      label s (.step .commitChains_step_committed_inr) = true ∧
      GrantFrontier.grantsAfter s = GrantFrontier.grantsBefore s ∧
      (∀ n k l i, ¬ (s.frame.advance s.after).logs.elected n k l i) := by
  unfold test
  rw [CommitKeys.fresh_answer]
  simp only [Bool.and_eq_true, decide_eq_true_eq, GrantFrontier.step_grant_eq,
    Bool.not_eq_true', noElection_iff, and_assoc]

/-- Whether the local input sends a proposal, regardless of earlier queue membership. -/
@[expose] public def sends (before : Model.State) (act : Model.Action) : Bool :=
  match act with
  | .local n .nominateSuccessor =>
    (before.nodes.lookup n).any fun st => (findSuccessor st n).isSome
  | _ => false

/-- Whether there is another node besides the recorded actor. -/
@[expose] public def other (before : Model.State) (act : Model.Action) : Bool :=
  match act with
  | .local n .nominateSuccessor => before.nodes.any fun p => p.1 != n
  | _ => false

private theorem before_nodes (s : Step) (tag : EventSupport.actionTag s.act = .nominateSuccessor) :
    s.after.nodes = s.before.nodes :=
  (NominationRows.run_nomination s tag).2.2.1.trans
    (congrArg (fun st : Model.State => st.nodes) s.current_eq)

public theorem backed (s : Step) (h : test s.cfg s.before s.act s.after s.past = true) :
    (StateCoverage.read s.cfg s.before s.past).2 = true := by
  obtain ⟨tag, commit, _⟩ := (test_iff s).mp h
  cases a : (StateCoverage.read s.cfg s.before s.past).2 with
  | true => rfl
  | false =>
    have old := BackingStutter.no_first_commit s (before_nodes s tag).symm a
    simp [← CommitKeys.fresh_answer, old] at commit

public theorem endpoints (s : Step) (h : test s.cfg s.before s.act s.after s.past = true) :
    (label s).pre = (label s).post :=
  BackingStutter.endpoints s (before_nodes s ((test_iff s).mp h).1).symm

end ConsensusCoverage.DelayedNomination
