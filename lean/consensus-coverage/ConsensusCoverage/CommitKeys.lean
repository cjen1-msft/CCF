module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ActionProfile
public import Consensus.Proofs.LogFacts
import all ConsensusCoverage.ActionProfile
import all ConsensusCoverage.CommitMonitor
import all ConsensusCoverage.Historical
import all ConsensusCoverage.StateCoverage
import all Consensus.Proofs.SafetyInvariant

/-!
# Exact committed prefixes

Scan a newest-first history for `(term, signed prefix)` certificates. At each
snapshot the quorum can use observations through that snapshot, but a positive
base must be backed by a key from the strict past.
-/

namespace ConsensusCoverage.CommitKeys

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

private abbrev Key := Nat × List Entry

private def leader (bootstrap : NodeID) (history : List Model.State)
    (n : NodeID) (st : NodeState) : Bool :=
  decide (st.role ≠ .candidate) &&
    (decide (st.currentTerm = BOOTSTRAP_TERM ∧ n = bootstrap) ||
      CommitMonitor.elected n st.currentTerm history)

private theorem leader_iff [Config.InitialConfiguration] (history : List Model.State)
    (n : NodeID) (st : NodeState) :
    leader Config.INITIAL_PRIMARY history n st = true ↔
      st.role ≠ .candidate ∧ Historical.Led history n st.currentTerm := by
  simp only [leader, Bool.and_eq_true, Bool.or_eq_true, decide_eq_true_eq,
    CommitMonitor.elected_iff, Historical.Led]

private def backed (old : List Key) (st : NodeState) (base : Nat) : Bool :=
  decide (base = 0) || old.any fun (k, part) =>
    decide (k ≤ st.currentTerm ∧ st.log.take base <+: part)

private theorem backed_iff [Config.InitialConfiguration] {history : List Model.State}
    {old : List Key} (old_exact : ∀ k l, (k, l) ∈ old ↔ Historical.Committed history k l)
    (st : NodeState) (base : Nat) :
    backed old st base = true ↔ base = 0 ∨
      ∃ k part, Historical.Committed history k part ∧ k ≤ st.currentTerm ∧ st.log.take base <+: part := by
  simp only [backed, Bool.or_eq_true, decide_eq_true_eq, List.any_eq_true, Prod.exists, old_exact]

private def acknowledges (history : List Model.State) (k : Nat) (part : List Entry)
    (v : NodeID) : Bool :=
  history.any fun snap => snap.nodes.any fun (id, x) =>
    decide (id = v ∧ x.currentTerm = k ∧ part <+: x.log)

private theorem acknowledges_iff (history : List Model.State) (k : Nat) (part : List Entry)
    (v : NodeID) :
    acknowledges history k part v = true ↔
      ∃ x, Historical.Seen history v x ∧ x.currentTerm = k ∧ part <+: x.log := by
  simp only [acknowledges, List.any_eq_true, Prod.exists, decide_eq_true_eq, Historical.Seen]
  constructor
  · rintro ⟨snap, seen, _, x, mem, rfl, term, sub⟩
    exact ⟨x, ⟨snap, seen, mem⟩, term, sub⟩
  · rintro ⟨x, ⟨snap, seen, mem⟩, term, sub⟩
    exact ⟨snap, seen, v, x, mem, rfl, term, sub⟩

private def certified (s : Model.State) (history : List Model.State)
    (old : List Key) (st : NodeState) (i : Nat) : Bool :=
  isSignatureAt st.log i && (decide (termAt st.log i = st.currentTerm) &&
    (List.range (i + 1)).any fun base =>
      backed old st base &&
        CommitMonitor.quorum ((activeConfigurations st.log base).filter (·.index ≤ i))
          (acknowledges (s :: history) st.currentTerm (st.log.take i)))

private def here (bootstrap : NodeID) (s : Model.State) (history : List Model.State)
    (old : List Key) : List Key :=
  (s.nodes.filter fun (n, st) => leader bootstrap (s :: history) n st).flatMap fun (_, st) =>
    ((List.range (st.log.length + 1)).filter (certified s history old st)).map
      fun i => (st.currentTerm, st.log.take i)

private theorem mem_here [Config.InitialConfiguration] (s : Model.State) (history : List Model.State)
    (old : List Key) (old_exact : ∀ k l, (k, l) ∈ old ↔ Historical.Committed history k l)
    (k : Nat) (l : List Entry) :
    (k, l) ∈ here Config.INITIAL_PRIMARY s history old ↔
      ∃ n st base i, Historical.CommitStep (s :: history) n st k base i ∧ l = st.log.take i ∧
        (base = 0 ∨ ∃ e p, Historical.Committed history e p ∧ e ≤ k ∧ st.log.take base <+: p) := by
  simp only [here, List.mem_flatMap, List.mem_filter, List.mem_map, Prod.exists, List.mem_range,
    Nat.lt_succ_iff, Prod.mk.injEq, leader_iff, certified, Bool.and_eq_true, List.any_eq_true,
    decide_eq_true_eq, backed_iff old_exact, CommitMonitor.quorum_iff, acknowledges_iff,
    Historical.CommitStep, Historical.CanonNow, Historical.Now]
  constructor
  · rintro ⟨n, st, ⟨now, role, led⟩, i, ⟨len, sig, term, base, le, back, votes⟩, rfl, rfl⟩
    exact ⟨n, st, base, i, ⟨⟨now, rfl, role, led⟩, le, len, sig, term, votes⟩, rfl, back⟩
  · rintro ⟨n, st, base, i, ⟨⟨now, rfl, role, led⟩, le, len, sig, term, votes⟩, rfl, back⟩
    exact ⟨n, st, ⟨now, role, led⟩, i, ⟨len, sig, term, base, le, back, votes⟩, rfl, rfl⟩

/-- Every key in the historical commit ghost, with duplicates removed.
The history is newest first; its oldest snapshot can itself contain a
certificate if it is signed. -/
@[expose] public def keys (bootstrap : NodeID) (history : List Model.State) : List (Nat × List Entry) :=
  match history with
  | [] => []
  | s :: h =>
    let old := keys bootstrap h
    (here bootstrap s h old ++ old).eraseDups

private theorem mem_historical [Config.InitialConfiguration] (history : List Model.State) :
    ∀ k l, (k, l) ∈ keys Config.INITIAL_PRIMARY history ↔ Historical.Committed history k l := by
  induction history with
  | nil =>
    intro k l
    simp only [keys, List.not_mem_nil, false_iff]
    intro h
    cases h
  | cons s h ih =>
    intro k l
    rw [keys, List.mem_eraseDups, List.mem_append, mem_here s h _ ih, ih, Historical.commit_cons, or_comm]

/-- Proof-only view of the same fold used to construct the safety frame. -/
public def historicalFold (cfg : CCF.Finset NodeID) (history : List Model.State) : LogFacts.Ghost :=
  @Historical.logFacts ⟨cfg⟩ history

/-- Exact on every finite historical fold, without a reachability hypothesis. -/
public theorem mem_iff (cfg : CCF.Finset NodeID) (history : List Model.State)
    (k : Nat) (l : List Entry) :
    (k, l) ∈ keys (cfg.min?.getD 0) history ↔ (historicalFold cfg history).committed k l := by
  letI : Config.InitialConfiguration := ⟨cfg⟩
  exact (mem_historical history k l).trans ((Historical.logFacts_correct history).committed k l).symm

/-- Proof-only wrapper for `s.frame.logs.committed`, whose frame is private. -/
public def committedBefore (s : ActionProfile.Step) (k : Nat) (l : List Entry) : Prop :=
  s.frame.logs.committed k l

/-- The keys of the given replay are exactly the actual pre-step commit evidence. -/
public theorem step_mem (s : ActionProfile.Step) (k : Nat) (l : List Entry) :
    (k, l) ∈ keys (s.cfg.min?.getD 0) (s.before :: s.past) ↔ committedBefore s k l := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  change _ ↔ (@StateCoverage.frame ⟨s.cfg⟩ s.before s.past).logs.committed k l
  rw [StateCoverage.frame_logs]
  exact mem_iff s.cfg (s.before :: s.past) k l

/-- A Boolean inclusion test. Unlike absence of signatures it also accepts
steps with signatures that only reproduce existing commit evidence. -/
@[expose] public def noNew (bootstrap : NodeID) (after : Model.State)
    (history : List Model.State) : Bool :=
  let old := keys bootstrap history
  (here bootstrap after history old).all old.contains

public theorem noNew_iff (cfg : CCF.Finset NodeID) (after : Model.State) (history : List Model.State) :
    noNew (cfg.min?.getD 0) after history = true ↔
      ∀ k l, (historicalFold cfg (after :: history)).committed k l →
        (historicalFold cfg history).committed k l := by
  simp only [noNew, List.all_eq_true, List.contains_iff_mem, Prod.forall, ← mem_iff,
    keys, List.mem_eraseDups, List.mem_append]
  grind

/-- Proof-only wrapper for the actual successor frame's commit evidence. -/
public def committedAfter (s : ActionProfile.Step) (k : Nat) (l : List Entry) : Prop :=
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  (s.frame.advance s.after).logs.committed k l

/-- No key is added to the ghost by the exact recorded step. -/
public theorem step_noNew (s : ActionProfile.Step) :
    noNew (s.cfg.min?.getD 0) s.after (s.before :: s.past) = true ↔
      ∀ k l, committedAfter s k l → committedBefore s k l := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  change _ ↔ ∀ k l,
    (@StateCoverage.frame ⟨s.cfg⟩ s.after (s.before :: s.past)).logs.committed k l →
      (@StateCoverage.frame ⟨s.cfg⟩ s.before s.past).logs.committed k l
  rw [StateCoverage.frame_logs, StateCoverage.frame_logs]
  exact noNew_iff s.cfg _ _

private def signature : Entry := ⟨BOOTSTRAP_TERM, .signature⟩

private def jointCfg : CCF.Finset NodeID := {0, 1}

private def shortLog : List Entry :=
  [⟨BOOTSTRAP_TERM, .transaction 0 {configuration := some jointCfg}⟩,
   ⟨BOOTSTRAP_TERM, .transaction 1 {configuration := some {0}}⟩, signature]

private def backingSnapshot (log : List Entry) : Model.State :=
  {nodes := [(0, {initialNodeState jointCfg 0 with log}),
             (1, {initialNodeState jointCfg 1 with log := shortLog})]}

-- Only voter 0 acknowledges the longer log. Its certificate can omit the
-- first configuration only once the shorter signed key is in the strict past.
private theorem backing_regression :
    let before := backingSnapshot shortLog
    let after := backingSnapshot (shortLog ++ [signature])
    let short := (BOOTSTRAP_TERM, shortLog)
    let long := (BOOTSTRAP_TERM, shortLog ++ [signature])
    short ∈ keys 0 [after] ∧ long ∉ keys 0 [after] ∧
      long ∈ keys 0 [after, before] ∧ noNew 0 after [before] = false ∧
      noNew 0 after [after, before] = true := by
  decide +kernel

private def soloSign : ActionProfile.Step := by
  let before := StateCoverage.initial [0, 1]
  let a : Model.Action := .local 0 (.append [{content := .signature}])
  let system := transitionSystem {0} [0, 1]
  have ran : (system.step before a).isSome := by decide +kernel
  exact ⟨{0}, [0, 1], before, [], a, (system.step before a).get ran,
    .initial (StateCoverage.init _ (by decide)), (Option.some_get _).symm⟩

private theorem initialized_signature_regression :
    keys 0 [soloSign.before] = [] ∧
      (keys 0 [soloSign.after, soloSign.before]).map (fun (k, l) => (k, l.length)) = [(2, 2)] ∧
      noNew 0 soloSign.after [soloSign.before] = false := by
  decide +kernel

end ConsensusCoverage.CommitKeys
