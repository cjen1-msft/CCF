module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.Proofs.SafetyInvariant
import all Consensus.Proofs.SafetyInvariant
import Consensus.Proofs.LogFacts
import all ConsensusCoverage.StateCoverage

/-! Batch specifications for the log ghost on newest-first snapshot histories.
These characterizations do not require the snapshots to form a valid run. -/

namespace ConsensusCoverage.Historical

open CCF Consensus Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Config
open Consensus.Model (BOOTSTRAP_TERM)
variable [Config.InitialConfiguration]

private abbrev History := List Model.State

/-- `node` has `state` in the newest state of `history`. -/
private def Now : History -> NodeID -> NodeState -> Prop
  | [], _, _ => False
  | current :: _, node, state => (node, state) ∈ current.nodes

/-- `node` had `state` at some point of `history`. -/
private def Seen (history : History) (node : NodeID) (state : NodeState) : Prop :=
  exists current, current ∈ history /\ (node, state) ∈ current.nodes

/-- The vote request of a candidate with this term, log and commit index. -/
private def vals (term : Nat) (log : List Entry) (commit : Nat) : RequestVoteRequest where
  term
  lastCommittableTerm := termAt log (max commit (maxCommittableIndex log))
  lastCommittableIndex := max commit (maxCommittableIndex log)

/-- `voter` votes for `candidate` in `term`, and `request` outranks the voter's
log before the step. -/
private def GrantStep (after before : Model.State) (voter candidate : NodeID) (term : Nat)
    (request : RequestVoteRequest) : Prop :=
  LogFacts.GrantAt before after voter candidate term request

/-- A grant requires a candidate observation in its term at or before the granting step. -/
private def Granted (history : History) (voter candidate : NodeID) (term : Nat)
    (request : RequestVoteRequest)
    : Prop :=
  exists after before rest,
    after :: before :: rest <:+ history
    /\ GrantStep after before voter candidate term request
    /\ exists state, Seen (after :: before :: rest) candidate state /\ state.currentTerm = term

/-- `node` becomes the leader of `term`, campaigning with `log` and `commit`. -/
private def ElectStep (after before : Model.State) (rest : History)
    (node : NodeID) (term : Nat) (log : List Entry) (commit : Nat)
    : Prop :=
  exists candidate leader,
    (node, candidate) ∈ before.nodes
    /\ (node, leader) ∈ after.nodes
    /\ candidate.log = log
    /\ candidate.commitIndex = commit
    /\ commit <= log.length
    /\ (candidate.currentTerm < term
        \/ (candidate.currentTerm = term /\ candidate.role = .candidate))
    /\ leader.currentTerm = term
    /\ (leader.role = .primary \/ leader.role = .none)
    /\ log.take (maxCommittableIndex log) <+: leader.log
    /\ 3 <= term
    /\ exists voters,
        hasQuorum (activeConfigurations log commit) voters
        /\ forall voter,
            voter ∈ voters
            -> Granted (after :: before :: rest) voter node term (vals term log commit)

private def Elected (history : History) (node : NodeID) (term : Nat)
    (log : List Entry) (commit : Nat)
    : Prop :=
  exists after before rest,
    after :: before :: rest <:+ history
    /\ ElectStep after before rest node term log commit

/-- `node` led `term`: the bootstrap leader, or elected. -/
private def Led (history : History) (node : NodeID) (term : Nat) : Prop :=
  (term = BOOTSTRAP_TERM /\ node = INITIAL_PRIMARY)
  \/ exists log commit, Elected history node term log commit

/-- `node` now has `state` as the leader of `term`, possibly stepped down. -/
private def CanonNow (history : History) (node : NodeID) (state : NodeState) (term : Nat)
    : Prop :=
  Now history node state
  /\ state.currentTerm = term
  /\ Not (state.role = .candidate)
  /\ Led history node term

/-- `log` was the log of the leader of `term` at some point. -/
private def Canon (history : History) (term : Nat) (log : List Entry) : Prop :=
  exists earlier,
    earlier <:+ history
    /\ exists node state, CanonNow earlier node state term /\ state.log = log

private def logFacts : History → LogFacts.Ghost
  | [] => LogFacts.empty
  | s :: h => LogFacts.advance INITIAL_PRIMARY (logFacts h) h.head? s

private structure Represents (g : LogFacts.Ghost) (h : History) : Prop where
  seen : ∀ n k l, g.seen n k l ↔ ∃ st, Seen h n st ∧ st.currentTerm = k ∧ st.log = l
  grant : ∀ v c k r, g.grant v c k r ↔ Granted h v c k r
  elected : ∀ n k l i, g.elected n k l i ↔ Elected h n k l i
  canon : ∀ k l, g.canon k l ↔ Canon h k l

omit [Config.InitialConfiguration] in
private theorem edge_cons (P : Model.State → Model.State → History → Prop) (s : Model.State)
    (h : History) :
    (∃ a b r, a :: b :: r <:+ s :: h ∧ P a b r) ↔
      (∃ a b r, a :: b :: r <:+ h ∧ P a b r) ∨ ∃ b r, h = b :: r ∧ P s b r := by
  constructor
  · rintro ⟨a, b, r, suffix, p⟩
    rcases List.suffix_cons_iff.1 suffix with eq | old
    · cases eq; exact .inr ⟨_, _, rfl, p⟩
    · exact .inl ⟨a, b, r, old, p⟩
  · rintro (⟨a, b, r, old, p⟩ | ⟨b, r, rfl, p⟩)
    · exact ⟨a, b, r, List.suffix_cons_iff.2 (.inr old), p⟩
    · exact ⟨s, b, r, List.suffix_refl _, p⟩

private theorem logFacts_correct (h : History) : Represents (logFacts h) h := by
  induction h with
  | nil =>
    constructor <;> simp [logFacts, LogFacts.empty, Seen, Granted, Elected, Canon, CanonNow, Now]
  | cons s h ih =>
    let g := logFacts h
    let t := LogFacts.advance INITIAL_PRIMARY g h.head? s
    change Represents t (s :: h)
    have seen (n k l) : t.seen n k l ↔ ∃ st, Seen (s :: h) n st ∧ st.currentTerm = k ∧ st.log = l := by
      change g.seen n k l ∨ _ ↔ _
      rw [ih.seen]; simp only [Seen, List.mem_cons]; grind
    have grant (v c k r) : t.grant v c k r ↔ Granted (s :: h) v c k r := by
      change g.grant v c k r ∨ _ ↔ _
      rw [ih.grant]
      unfold Granted
      rw [edge_cons]
      apply or_congr_right
      change (∃ p, h.head? = some p ∧ GrantStep s p v c k r ∧
        ∃ l, t.seen c k l) ↔ _
      simp only [seen]
      cases h <;> simp [List.cons.injEq] <;> grind
    have elected (n k l i) : t.elected n k l i ↔ Elected (s :: h) n k l i := by
      change g.elected n k l i ∨ (∃ p, h.head? = some p ∧ LogFacts.ElectionAt p s t.grant n k l i) ↔ _
      rw [ih.elected]
      unfold Elected
      rw [edge_cons]
      apply or_congr_right
      simp only [LogFacts.ElectionAt, grant, ElectStep]
      cases h <;> simp [List.cons.injEq, LogFacts.requestAt, vals]
      exact ⟨fun p => ⟨_, _, ⟨rfl, rfl⟩, p⟩, fun ⟨_, _, ⟨rfl, rfl⟩, p⟩ => p⟩
    have now (n st k) : t.canonNow INITIAL_PRIMARY s n st k ↔ CanonNow (s :: h) n st k := by
      simp only [LogFacts.Ghost.canonNow, LogFacts.Ghost.led, CanonNow, Led, Now, elected]
    have canon (k l) : t.canon k l ↔ Canon (s :: h) k l := by
      change g.canon k l ∨ (∃ n st, t.canonNow INITIAL_PRIMARY s n st k ∧ st.log = l) ↔ _
      rw [ih.canon]; simp only [Canon, now, List.suffix_cons_iff]
      grind
    exact ⟨seen, grant, elected, canon⟩

private theorem frame_logs (s : Model.State) (h : History) :
    (StateCoverage.frame s h).logs = logFacts (s :: h) := by
  induction h generalizing s with
  | nil => rfl
  | cons t h ih =>
    change LogFacts.advance INITIAL_PRIMARY (StateCoverage.frame t h).logs
      (some (StateCoverage.frame t h).current) s = _
    rw [ih t, StateCoverage.frame_current]
    rfl

private theorem frame_correct (s : Model.State) (h : History) :
    Represents (StateCoverage.frame s h).logs (s :: h) := by
  rw [frame_logs]
  exact logFacts_correct (s :: h)

private theorem led_iff (s : Model.State) (h : History) (n : NodeID) (k : Nat) :
    (StateCoverage.frame s h).logs.led INITIAL_PRIMARY n k ↔ Led (s :: h) n k := by
  simp only [LogFacts.Ghost.led, Led, (frame_correct s h).elected]

end ConsensusCoverage.Historical
