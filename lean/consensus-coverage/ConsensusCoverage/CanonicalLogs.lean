module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.CommitKeys
public import ConsensusCoverage.ActionProfile
import all ConsensusCoverage.ActionProfile
import all ConsensusCoverage.CommitKeys
import all ConsensusCoverage.GrantMonitor
import all ConsensusCoverage.Historical
import all ConsensusCoverage.StateCoverage
import all Consensus.Proofs.SafetyInvariant

/-! Canonical log readers. Edge freshness is decided by `GrantFrontier.freshCanon`. -/

namespace ConsensusCoverage.CanonicalLogs

open CCF Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety

set_option autoImplicit false
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

/-- All canonical term/log pairs in the newest-first history. A pair may be
listed more than once if it is observed at different snapshots. -/
@[expose] public def keys (cfg : Finset NodeID) (history : List Model.State) : List CommitKeys.Key :=
  CommitKeys.canonical cfg history

private theorem mem_keys (cfg : Finset NodeID) (s : Model.State) (h : List Model.State)
    (term : Nat) (log : List Entry) :
    (term, log) ∈ keys cfg (s :: h) ↔ Canon (@StateCoverage.frame ⟨cfg⟩ s h) term log := by
  letI : Config.InitialConfiguration := ⟨cfg⟩
  exact (CommitKeys.mem_canonical (s :: h) term log).trans
    ((Historical.frame_correct s h).canon term log).symm

@[expose] public def logsFor (cfg : Finset NodeID) (history : List Model.State)
    (term : Nat) : List (List Entry) :=
  ((keys cfg history).filter fun p => p.1 == term).map Prod.snd

private theorem mem_logsFor (cfg : Finset NodeID) (s : Model.State) (h : List Model.State)
    (term : Nat) (log : List Entry) :
    log ∈ logsFor cfg (s :: h) term ↔ Canon (@StateCoverage.frame ⟨cfg⟩ s h) term log := by
  simp only [logsFor, List.mem_map, List.mem_filter, Prod.exists, beq_iff_eq, mem_keys]
  grind

@[expose] public def canon (cfg : Finset NodeID) (history : List Model.State)
    (term : Nat) (log : List Entry) : Bool :=
  (keys cfg history).contains (term, log)

private theorem canon_iff (cfg : Finset NodeID) (s : Model.State) (h : List Model.State)
    (term : Nat) (log : List Entry) :
    canon cfg (s :: h) term log = true ↔ Canon (@StateCoverage.frame ⟨cfg⟩ s h) term log := by
  rw [canon, List.contains_iff_mem, mem_keys]

/-- Test the canonical-log conditions for a record already taken from the current
snapshot. A node that has stepped down can still be the leader of its term. -/
@[expose] public def leaderRecord (cfg : Finset NodeID) (history : List Model.State)
    (n : NodeID) (st : NodeState) (term : Nat) : Bool :=
  st.currentTerm == term && decide (st.role ≠ .candidate) && GrantMonitor.led cfg history n term

private theorem leaderRecord_iff (cfg : Finset NodeID) (s : Model.State) (h : List Model.State)
    (n : NodeID) (st : NodeState) (term : Nat) (member : (n, st) ∈ s.nodes) :
    letI : Config.InitialConfiguration := ⟨cfg⟩
    leaderRecord cfg (s :: h) n st term = true ↔ CanonNow (StateCoverage.frame s h) n st term := by
  letI : Config.InitialConfiguration := ⟨cfg⟩
  change _ ↔ (n, st) ∈ (StateCoverage.frame s h).current.nodes ∧
    st.currentTerm = term ∧ st.role ≠ .candidate ∧
      (StateCoverage.frame s h).logs.led Config.INITIAL_PRIMARY n term
  rw [StateCoverage.frame_current]
  have led := @GrantMonitor.led_iff ⟨cfg⟩ s h n term
  change GrantMonitor.led cfg (s :: h) n term = true ↔ _ at led
  simp only [leaderRecord, Bool.and_eq_true, beq_iff_eq, decide_eq_true_eq, member, true_and, led]
  exact and_assoc

/-- Test whether the current snapshot contains a canonical record for this
node, term, and log, without needing equality on full `NodeState` records. -/
@[expose] public def canonNow (cfg : Finset NodeID) (s : Model.State) (h : List Model.State)
    (n : NodeID) (term : Nat) (log : List Entry) : Bool :=
  s.nodes.any fun (id, st) =>
    id == n && decide (st.log = log) && leaderRecord cfg (s :: h) n st term

private theorem canonNow_iff (cfg : Finset NodeID) (s : Model.State) (h : List Model.State)
    (n : NodeID) (term : Nat) (log : List Entry) :
    letI : Config.InitialConfiguration := ⟨cfg⟩
    canonNow cfg s h n term log = true ↔
      ∃ st, CanonNow (StateCoverage.frame s h) n st term ∧ st.log = log := by
  letI : Config.InitialConfiguration := ⟨cfg⟩
  simp only [canonNow, List.any_eq_true, Prod.exists, Bool.and_eq_true, beq_iff_eq, decide_eq_true_eq]
  constructor
  · rintro ⟨id, st, mem, ⟨same, eq⟩, now⟩
    subst id
    exact ⟨st, (leaderRecord_iff cfg s h n st term mem).mp now, eq⟩
  · rintro ⟨st, now, eq⟩
    have mem := now.1
    rw [StateCoverage.frame_current] at mem
    exact ⟨n, st, mem, ⟨rfl, eq⟩, (leaderRecord_iff cfg s h n st term mem).mpr now⟩

private theorem step_canonBefore_iff (s : ActionProfile.Step) (term : Nat) (log : List Entry) :
    canon s.cfg (s.before :: s.past) term log = true ↔ Canon s.frame term log :=
  canon_iff s.cfg s.before s.past term log

private theorem step_canonAfter_iff (s : ActionProfile.Step) (term : Nat) (log : List Entry) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    canon s.cfg (s.after :: s.before :: s.past) term log = true ↔
      Canon (s.frame.advance s.after) term log :=
  canon_iff s.cfg s.after (s.before :: s.past) term log

private theorem step_canonNow_iff (s : ActionProfile.Step) (n : NodeID) (term : Nat) (log : List Entry) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    canonNow s.cfg s.after (s.before :: s.past) n term log = true ↔
      ∃ st, CanonNow (s.frame.advance s.after) n st term ∧ st.log = log :=
  canonNow_iff s.cfg s.after (s.before :: s.past) n term log

/-- An enumerated successor key carries the merged copy, owner, and winning-prefix facts. -/
private theorem step_key_facts (s : ActionProfile.Step) {term : Nat} {log : List Entry}
    (mem : (term, log) ∈ keys s.cfg (s.after :: s.before :: s.past)) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    CanonLog (s.frame.advance s.after).logs term log := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  exact s.context.inv_step.canonLogs term log ((mem_keys s.cfg s.after (s.before :: s.past) term log).mp mem)

/-- Every current primary's log is included in the successor enumeration. -/
private theorem step_primary_mem (s : ActionProfile.Step) {n : NodeID} {st : NodeState}
    (member : (n, st) ∈ s.after.nodes) (primary : st.role = .primary) :
    (st.currentTerm, st.log) ∈ keys s.cfg (s.after :: s.before :: s.past) := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  have led := s.context.inv_step.leader_led n st member primary
  have now : CanonNow (s.frame.advance s.after) n st st.currentTerm :=
    ⟨member, rfl, by simp [primary], led⟩
  exact (mem_keys s.cfg s.after (s.before :: s.past) _ _).mpr (.inr ⟨n, st, now, rfl⟩)

end ConsensusCoverage.CanonicalLogs
