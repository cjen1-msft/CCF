module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.CommitKeys
public import ConsensusCoverage.GrantMonitor
import all ConsensusCoverage.ActionProfile
import all ConsensusCoverage.CommitKeys
import all ConsensusCoverage.GrantMonitor
import all ConsensusCoverage.Historical
import all ConsensusCoverage.SolvedWitnesses
import all ConsensusCoverage.StateCoverage
import all Consensus.Proofs.SafetyInvariant

/-! An exact check for new vote-grant facts. Each eligible pair of voter records
contributes a cone of requests whose minimum is the pre-state log threshold.
The history scan determines whether that minimum was already granted. -/

namespace ConsensusCoverage.GrantFrontier

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety

set_option autoImplicit false
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

/-- Use the voter log's threshold, not `LogFacts.requestAt`, which describes
a candidate's campaign. The request's own term is ignored by ghost grants. -/
private def minimum (x : NodeState) (k : Nat) : RequestVoteRequest :=
  ⟨k, maxCommittableTerm x.log, maxCommittableIndex x.log⟩

private def pairCovered (before : Model.State) (past : List Model.State)
    (pre post : NodeID × NodeState) : Bool :=
  let (v, x) := pre
  let (w, y) := post
  match y.votedFor with
  | none => true
  | some c =>
    let k := y.currentTerm
    if v = w ∧ x.currentTerm ≤ k then
      let old := GrantMonitor.scan ⟨v, c, k, minimum x k⟩ before past
      !(v == c || old.seenCandidate) || old.granted
    else true

/-- Test the finitely many eligible pre/post record pairs. An empty prior
history has no incoming edge, so it cannot produce a grant. -/
@[expose] public def noNewGrant (after : Model.State) (history : List Model.State) : Bool :=
  match history with
  | [] => true
  | before :: past =>
    before.nodes.all fun pre => after.nodes.all fun post => pairCovered before past pre post

/-- The old unvoted check remains sufficient when the node table is unchanged. -/
public theorem noNewGrant_of_unvoted (after : Model.State) (history : List Model.State)
    (unvoted : after.nodes.all (fun (_, st) => st.votedFor.isNone) = true) :
    noNewGrant after history = true := by
  cases history with
  | nil => rfl
  | cons before past =>
    simp only [noNewGrant, List.all_eq_true, Prod.forall]
    intro v x _ w y mem
    have none := Option.isNone_iff_eq_none.mp (List.all_eq_true.mp unvoted (w, y) mem)
    simp [pairCovered, none]

private theorem pairCovered_iff (before : Model.State) (past : List Model.State)
    (v w : NodeID) (x y : NodeState) :
    pairCovered before past (v, x) (w, y) = true ↔
      ∀ c, y.votedFor = some c → v = w → x.currentTerm ≤ y.currentTerm →
        (v = c ∨ GrantMonitor.HasSeen ⟨v, c, y.currentTerm, minimum x y.currentTerm⟩
          (before :: past)) →
        Historical.Granted (before :: past) v c y.currentTerm (minimum x y.currentTerm) := by
  cases vote : y.votedFor with
  | none => simp [pairCovered, vote]
  | some c =>
    have ok := GrantMonitor.correct ⟨v, c, y.currentTerm, minimum x y.currentTerm⟩ before past
    by_cases edge : v = w ∧ x.currentTerm ≤ y.currentTerm
    · simp only [pairCovered, vote, ite_eq_left edge, Bool.or_eq_true, Bool.not_eq_true',
        Bool.eq_false_iff, ok.2, GrantMonitor.HasGrant, Option.some.injEq]
      grind [ok.1]
    · simp [pairCovered, vote, edge]
      grind

private theorem minimum_upToDate (x : NodeState) (k : Nat) :
    voteLogUpToDate x (minimum x k) := .inr ⟨rfl, Nat.le_refl _⟩

private theorem upToDate_of_minimum {x z : NodeState} {k : Nat} {r : RequestVoteRequest}
    (old : voteLogUpToDate z (minimum x k)) (now : voteLogUpToDate x r) :
    voteLogUpToDate z r := by
  simp only [voteLogUpToDate, minimum] at *
  grind

private theorem grant_of_minimum {h : List Model.State} {v c : NodeID}
    {k : Nat} {x : NodeState} {r : RequestVoteRequest}
    (old : Historical.Granted h v c k (minimum x k)) (now : voteLogUpToDate x r) :
    Historical.Granted h v c k r := by
  obtain ⟨a, b, rest, suffix, ⟨z, y, pre, post, le, term, vote, up⟩, seen⟩ := old
  exact ⟨a, b, rest, suffix, ⟨z, y, pre, post, le, term, vote, upToDate_of_minimum up now⟩, seen⟩

private theorem historical_cons_iff (before after : Model.State) (past : List Model.State) :
    noNewGrant after (before :: past) = true ↔
      ∀ v c k r, Historical.Granted (after :: before :: past) v c k r →
        Historical.Granted (before :: past) v c k r := by
  simp only [noNewGrant, List.all_eq_true, Prod.forall, pairCovered_iff]
  constructor
  · intro covered v c k r post
    rcases (GrantMonitor.granted_cons ⟨v, c, k, r⟩ after before past).mp post with
      old | ⟨⟨x, y, pre, post, le, term, vote, up⟩, seen⟩
    · exact old
    · change y.currentTerm = k at term
      subst k
      exact grant_of_minimum (covered v x pre v y post c vote rfl le seen) up
  · intro noNew v x pre w y post c vote eq le seen
    subst w
    apply noNew v c y.currentTerm (minimum x y.currentTerm)
    exact (GrantMonitor.granted_cons ⟨v, c, y.currentTerm, minimum x y.currentTerm⟩
      after before past).mpr (.inr ⟨⟨x, y, pre, post, le, rfl, vote, minimum_upToDate x _⟩, seen⟩)

/-- Exact on every finite snapshot history, including histories that are not
reachable. No bound on node IDs, terms, or request fields is needed. -/
public theorem noNewGrant_iff (cfg : CCF.Finset NodeID) (after : Model.State)
    (history : List Model.State) :
    noNewGrant after history = true ↔
      ∀ v c k r, (CommitKeys.historicalFold cfg (after :: history)).grant v c k r →
        (CommitKeys.historicalFold cfg history).grant v c k r := by
  letI : Config.InitialConfiguration := ⟨cfg⟩
  change _ ↔ ∀ v c k r, (Historical.logFacts (after :: history)).grant v c k r →
    (Historical.logFacts history).grant v c k r
  simp only [(Historical.logFacts_correct (after :: history)).grant,
    (Historical.logFacts_correct history).grant]
  cases history with
  | nil =>
    simp only [noNewGrant, true_iff]
    rintro v c k r ⟨a, b, rest, suffix, _, _⟩
    have len := suffix.length_le
    simp at len
  | cons before past => exact historical_cons_iff before after past

/-- The grant relation in the proof frame immediately before the recorded edge. -/
public def grantsBefore (s : ActionProfile.Step) :
    NodeID → NodeID → Nat → RequestVoteRequest → Prop :=
  s.frame.logs.grant

/-- The grant relation after advancing the proof frame across the recorded edge. -/
public def grantsAfter (s : ActionProfile.Step) :
    NodeID → NodeID → Nat → RequestVoteRequest → Prop :=
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  (s.frame.advance s.after).logs.grant

/-- Exact inclusion for the actual pre/post safety frames of a recorded step. -/
public theorem step_noNew (s : ActionProfile.Step) :
    noNewGrant s.after (s.before :: s.past) = true ↔
      ∀ v c k r, grantsAfter s v c k r → grantsBefore s v c k r := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  change _ ↔ ∀ v c k r,
    (StateCoverage.frame s.after (s.before :: s.past)).logs.grant v c k r →
      (StateCoverage.frame s.before s.past).logs.grant v c k r
  rw [StateCoverage.frame_logs, StateCoverage.frame_logs]
  exact noNewGrant_iff s.cfg s.after (s.before :: s.past)

/-- Direct replacement for the unvoted hypothesis when assembling `StableLogs`:
grant facts are cumulative, so ruling out new grants gives equality. -/
public theorem step_grant_eq (s : ActionProfile.Step) :
    noNewGrant s.after (s.before :: s.past) = true ↔
      grantsAfter s = grantsBefore s := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  rw [step_noNew]
  constructor
  · intro same
    exact funext fun v => funext fun c => funext fun k => funext fun r =>
      propext ⟨same v c k r, Or.inl⟩
  · intro eq
    rw [eq]
    exact fun _ _ _ _ h => h

/-- Failure gives an actual new fact in the unbounded request relation. -/
public theorem step_fresh_iff (s : ActionProfile.Step) :
    (!noNewGrant s.after (s.before :: s.past)) = true ↔
      ∃ v c k r, grantsAfter s v c k r ∧ ¬ grantsBefore s v c k r := by
  rw [Bool.not_eq_true', Bool.eq_false_iff]
  change (¬ noNewGrant s.after (s.before :: s.past) = true) ↔ _
  rw [step_noNew s]
  constructor
  · intro fails
    apply Classical.byContradiction
    intro noFresh
    apply fails
    intro v c k r post
    apply Classical.byContradiction
    intro noOld
    exact noFresh ⟨v, c, k, r, post, noOld⟩
  · rintro ⟨v, c, k, r, post, noOld⟩ old
    exact noOld (old v c k r post)

/-- Every genuinely new grant hits the direct invariant-clause path of the
pinned `grantFactsBefore` branch. That bit also has other call sites. -/
public theorem fresh_implies_grant_arm (s : ActionProfile.Step)
    (fresh : noNewGrant s.after (s.before :: s.past) = false) :
    ActionProfile.label s (.step .grantFactsBefore_grant_inr) = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  obtain ⟨v, c, k, r, post, notOld⟩ := (step_fresh_iff s).mp (by simp [fresh])
  change (s.frame.advance s.after).logs.grant v c k r at post
  change ¬s.frame.logs.grant v c k r at notOld
  apply (ActionProfile.label_true s _).mpr
  change PinnedClasses.sig s.context .grantFactsBefore_grant_inr
  rw [SolvedWitnesses.sig_iff]
  change SolvedWitnesses.step_grantFactsBefore_grant_inr s.frame s.after s.context
  rcases post with old | ⟨p, eq, grant, seen⟩
  · exact (notOld old).elim
  · have post : (s.frame.advance s.after).logs.grant v c k r :=
      .inr ⟨p, eq, grant, seen⟩
    exact .inl ⟨v, c, k, r, ⟨⟨post, notOld⟩, post⟩, ⟨p, eq, grant, seen⟩,
      p, ⟨eq, grant, seen⟩, eq, ⟨grant, seen⟩, grant, seen, post,
      fun stamp old k' l i obs lt sig atI => by
        rcases obs with prior | ⟨x, mem, term, _⟩
        · exact old k' l i prior lt sig atI
        · have le := s.context.ballots.bounds _ stamp x mem
          change k ≤ x.currentTerm at le
          omega⟩

end ConsensusCoverage.GrantFrontier
