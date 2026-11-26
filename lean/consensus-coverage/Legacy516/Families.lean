module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.DelayedNomination
public import ConsensusCoverage.EvidenceSupport
public import ConsensusCoverage.EventSupport
public import ConsensusCoverage.NominationWitnesses
public import ConsensusCoverage.SignedQuiet
import all ConsensusCoverage.DelayedNomination
import all ConsensusCoverage.DelayedNominationRead
import all ConsensusCoverage.EvidenceSupport
import all ConsensusCoverage.GuardedDomain
import all ConsensusCoverage.InertProfile
import all ConsensusCoverage.NominationWitnesses
import all ConsensusCoverage.ProofContexts
import all ConsensusCoverage.SignedQuiet
import all ConsensusCoverage.StateCoverage
import all ConsensusCoverage.StutterProfile
import all ConsensusCoverage.ZeroRows
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.Families

open ActionProfile FullProfile
open Consensus Consensus.Proofs Consensus.Proofs.Safety

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

/-- Open families group the remaining actions by kind and exact freshness bits.
The ledger does not determine their labels or whether they share labels with
closed rows. -/
public inductive Family
  | quiet | freshNomination | delayedNomination
  | open (tag : EventSupport.Tag) (evidence : EvidenceSupport.Evidence)
  deriving DecidableEq, Repr

@[expose] public def Family.closed : Family → Bool
  | .open .. => false
  | _ => true

/-- First quiet, then fresh nomination, then delayed nomination; the tests
are disjoint on a recorded step. -/
@[expose] public def classify (cfg : Configuration) (before : Model.State) (act : Model.Action)
    (after : Model.State) (past : List Model.State) : Family :=
  if SignedQuiet.gate cfg before act after past then .quiet
  else if NominationRows.test cfg before act after past then .freshNomination
  else if DelayedNomination.test cfg before act after past then .delayedNomination
  else .open (EventSupport.actionTag act) (EvidenceSupport.read cfg before act after past)

private def tagCode : EventSupport.Tag → String
  | .append => "append"
  | .sendEntries => "sendEntries"
  | .timeout => "timeout"
  | .nominateSuccessor => "nominateSuccessor"
  | .initAsBackup => "initAsBackup"
  | .appendEntriesRequest => "appendEntriesRequest"
  | .appendEntriesResponse => "appendEntriesResponse"
  | .requestVoteRequest => "requestVoteRequest"
  | .requestVoteResponse => "requestVoteResponse"
  | .requestPreVoteRequest => "requestPreVoteRequest"
  | .requestPreVoteResponse => "requestPreVoteResponse"
  | .proposeRequestVoteRequest => "proposeRequestVoteRequest"

public def evidenceOrder : String := "pending now seen grant elected canon committed"

/-- Stable family names shared by the replay reader and explorer.
The seven bits use `evidenceOrder`; `1` means a new fact. -/
public def code : Family → String
  | .quiet => "quiet"
  | .freshNomination => "fresh-nomination"
  | .delayedNomination => "delayed-nomination"
  | .open tag e =>
    let bits := [e.pending, e.now, e.seen, e.grant, e.elected, e.canon, e.committed]
    s!"open:{tagCode tag}:{String.ofList (bits.map fun b => if b then '1' else '0')}"

public theorem tests_disjoint (s : Step) :
    let quiet := SignedQuiet.gate s.cfg s.before s.act s.after s.past = true
    let fresh := NominationRows.test s.cfg s.before s.act s.after s.past = true
    let delayed := DelayedNomination.test s.cfg s.before s.act s.after s.past = true
    ¬ (quiet ∧ fresh) ∧ ¬ (quiet ∧ delayed) ∧ ¬ (fresh ∧ delayed) := by
  let commit := Classes.StepBranch.commitChains_step_committed_inr
  have newKey (h : DelayedNomination.test s.cfg s.before s.act s.after s.past = true) :
      (label s).step commit = true := ((DelayedNomination.test_iff s).mp h).2.1
  refine ⟨?_, ?_, ?_⟩
  · rintro ⟨q, n⟩
    have old := congrFun ((SignedQuiet.gate_iff s).mp q) .messages_mem_network_inr
    have new := congrFun ((NominationRows.test_iff s).mp n) .messages_mem_network_inr
    exact Bool.noConfusion (old.symm.trans new)
  · rintro ⟨q, d⟩
    exact Bool.noConfusion ((congrFun ((SignedQuiet.gate_iff s).mp q) commit).symm.trans (newKey d))
  · rintro ⟨n, d⟩
    exact Bool.noConfusion ((congrFun ((NominationRows.test_iff s).mp n) commit).symm.trans (newKey d))

public theorem classify_quiet_iff (s : Step) :
    classify s.cfg s.before s.act s.after s.past = .quiet ↔
      SignedQuiet.gate s.cfg s.before s.act s.after s.past = true := by
  unfold classify
  split <;> rename_i h
  · simp [h]
  · split
    · simp [h]
    · split <;> simp [h]

public theorem classify_fresh_iff (s : Step) :
    classify s.cfg s.before s.act s.after s.past = .freshNomination ↔
      NominationRows.test s.cfg s.before s.act s.after s.past = true := by
  have disjoint := (tests_disjoint s).1
  unfold classify
  split
  · rename_i h
    simp [show ¬ NominationRows.test s.cfg s.before s.act s.after s.past = true from
      fun n => disjoint ⟨h, n⟩]
  · split <;> rename_i h
    · simp [h]
    · split <;> simp [h]

public theorem classify_delayed_iff (s : Step) :
    classify s.cfg s.before s.act s.after s.past = .delayedNomination ↔
      DelayedNomination.test s.cfg s.before s.act s.after s.past = true := by
  obtain ⟨_, qd, nd⟩ := tests_disjoint s
  unfold classify
  split
  · rename_i h
    simp [show ¬ DelayedNomination.test s.cfg s.before s.act s.after s.past = true from
      fun d => qd ⟨h, d⟩]
  · split
    · rename_i h
      simp [show ¬ DelayedNomination.test s.cfg s.before s.act s.after s.past = true from
        fun d => nd ⟨h, d⟩]
    · split <;> simp_all

/-- Only closed families have a certified list; the empty list for an open
family does not assert that it has no labels. -/
public def Family.rows : Family → List Profile
  | .quiet => ZeroRows.table
  | .freshNomination => NominationRows.table
  | .delayedNomination => DelayedNomination.rows
  | .open .. => []

public theorem rows_exact (f : Family) (closed : f.closed = true) :
    f.rows.Nodup ∧ ∀ p : Profile, p ∈ f.rows ↔
      ∃ s : Step, classify s.cfg s.before s.act s.after s.past = f ∧ label s = p := by
  cases f with
  | quiet =>
    refine ⟨ZeroRows.count.1, fun p => ?_⟩
    rw [Family.rows, SignedQuiet.exact]
    simp only [classify_quiet_iff, SignedQuiet.gate_iff, ActionProfile.Realized]
    exact ⟨fun ⟨⟨s, eq⟩, shape⟩ => ⟨s, eq.symm ▸ shape, eq⟩,
      fun ⟨s, shape, eq⟩ => ⟨⟨s, eq⟩, eq ▸ shape⟩⟩
  | freshNomination =>
    refine ⟨NominationRows.exact.1, fun p => ?_⟩
    rw [Family.rows, NominationRows.exact.2.2]
    simp only [classify_fresh_iff, NominationRows.test_iff, ActionProfile.Realized]
    exact ⟨fun ⟨⟨s, eq⟩, shape⟩ => ⟨s, eq.symm ▸ shape, eq⟩,
      fun ⟨s, shape, eq⟩ => ⟨⟨s, eq⟩, eq ▸ shape⟩⟩
  | delayedNomination =>
    exact ⟨DelayedNomination.exact.1, fun p => by
      rw [Family.rows, DelayedNomination.exact.2.2]
      simp only [classify_delayed_iff]⟩
  | «open» tag evidence => cases closed

public def closedRows : List Profile :=
  Family.quiet.rows ++ Family.freshNomination.rows ++ Family.delayedNomination.rows

private def rowKey (p : Profile) : Bool × Bool × Bool × Bool :=
  (p (.pre .committed_logs_comparable_left_backed_inl),
    p (.pre .committed_logs_comparable_left_backed_inr),
    p (.step .messages_mem_network_inr), p (.step .commitChains_step_committed_inr))

/-- The ten distinct full labels, with exhaustion and initialized witnesses
restricted to steps classified as closed. -/
public theorem exact :
    closedRows.Nodup ∧ closedRows.length = 10 ∧ ∀ p : Profile, p ∈ closedRows ↔
      ∃ s : Step, (classify s.cfg s.before s.act s.after s.past).closed = true ∧ label s = p := by
  have keys : (closedRows.map rowKey).Nodup := by decide +kernel
  refine ⟨(List.pairwise_map.mp keys).imp (fun ne eq => ne (congrArg rowKey eq)), rfl, fun p => ?_⟩
  simp only [closedRows, List.mem_append]
  constructor
  · rintro ((mem | mem) | mem)
    all_goals
      obtain ⟨s, family, eq⟩ := ((rows_exact _ rfl).2 p).mp mem
      exact ⟨s, by simp only [family, Family.closed], eq⟩
  · rintro ⟨s, closed, eq⟩
    cases h : classify s.cfg s.before s.act s.after s.past with
    | quiet => exact .inl (.inl (((rows_exact .quiet rfl).2 p).mpr ⟨s, h, eq⟩))
    | freshNomination => exact .inl (.inr (((rows_exact .freshNomination rfl).2 p).mpr ⟨s, h, eq⟩))
    | delayedNomination => exact .inr (((rows_exact .delayedNomination rfl).2 p).mpr ⟨s, h, eq⟩)
    | «open» tag evidence => simp [h, Family.closed] at closed

/-- On initialized recorded actions the all-false gate is exactly the
all-zero evidence case. -/
public theorem quiet_iff (s : Step) :
    classify s.cfg s.before s.act s.after s.past = .quiet ↔
      ∀ k : EvidenceSupport.Family, (EvidenceSupport.read s.cfg s.before s.act s.after s.past).fresh k = false := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  rw [classify_quiet_iff]
  obtain ⟨v, made, ok⟩ := GuardedDomain.ofAction_matches s
  simp only [SignedQuiet.gate, SignedQuiet.test, made, Option.any_some, Bool.not_eq_true', Bool.and_eq_true]
  constructor
  · rintro ⟨⟨unchanged, queue⟩, evidence⟩ k
    have same := s.context.now_pre ((GuardedDomain.View.old_post ok).mpr unchanged)
    change s.context.tr.post = s.context.tr.pre at same
    have nodes : s.after.nodes = s.before.nodes := by
      rw [← s.current_eq, s.context.tr.nodesEq, same]
      exact InertProfile.replace_eq s.context.inv.distinct s.context.tr.found
    have logs := SignedQuiet.stable s nodes evidence
    change (s.frame.advance s.after).logs = s.frame.logs at logs
    apply (EvidenceSupport.fresh_iff s k).mpr
    cases k with
    | pending =>
      intro e he
      change e ∈ (FullProfile.current s.frame).network
      rw [s.current_eq]
      exact List.contains_iff_mem.mp (List.all_eq_true.mp queue e he)
    | now =>
      intro n st post
      change (n, st) ∈ (FullProfile.current s.frame).nodes
      rw [s.current_eq, ← nodes]
      exact post
    | seen => simpa only [EvidenceSupport.Stable, Seen, logs] using fun _ _ h => h
    | grant => simpa only [EvidenceSupport.Stable, Granted, logs] using fun _ _ _ _ h => h
    | elected => simpa only [EvidenceSupport.Stable, Elected, logs] using fun _ _ _ _ h => h
    | canon => simpa only [EvidenceSupport.Stable, Canon, logs] using fun _ _ h => h
    | committed => simpa only [EvidenceSupport.Stable, Committed, logs] using fun _ _ h => h
  · intro no
    have now := (EvidenceSupport.fresh_iff s .now).mp (no .now)
    have pending := (EvidenceSupport.fresh_iff s .pending).mp (no .pending)
    refine ⟨⟨(GuardedDomain.View.old_post ok).mp (now _ _ s.context.post_now), ?_⟩, ?_⟩
    · apply List.all_eq_true.mpr
      intro e he
      apply List.contains_iff_mem.mpr
      have old : e ∈ (FullProfile.current s.frame).network := pending e he
      rwa [s.current_eq] at old
    · simpa only [EvidenceSupport.read, EvidenceSupport.readFrom, EvidenceSupport.Evidence.fresh,
        SignedQuiet.evidence, Bool.not_eq_false', Bool.and_eq_true] using And.intro (no .grant) (no .committed)

end ConsensusCoverage.Families
