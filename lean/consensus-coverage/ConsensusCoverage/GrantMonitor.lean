module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.Historical
import all ConsensusCoverage.Historical
import all ConsensusCoverage.StateCoverage
import CCF.Proofs.Finset

/-! Executable readers for observations, grants, and elections on newest-first histories. -/

namespace ConsensusCoverage.GrantMonitor

open CCF Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

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
    n == q.voter && decide (st.currentTerm ≤ q.term) &&
    @decide (LogFacts.Outranks q.request st.log) (by unfold LogFacts.Outranks; infer_instance)) &&
  (t.nodes.any fun (n, st) =>
    n == q.voter && st.currentTerm == q.term && st.votedFor == some q.candidate)

@[expose] public def start (q : Query) (s : Model.State) : Memory := ⟨here q s, false⟩

/-- A grant requires candidate evidence from this snapshot or an earlier one. -/
@[expose] public def advance (q : Query) (old : Memory) (s t : Model.State) : Memory :=
  let seen := old.seenCandidate || here q t
  ⟨seen, old.granted || (grantStep q s t && seen)⟩

public def HasSeen (q : Query) (h : List Model.State) : Prop :=
  ∃ st, Historical.Seen h q.candidate st ∧ st.currentTerm = q.term

public def HasGrant (q : Query) (h : List Model.State) : Prop :=
  Historical.Granted h q.voter q.candidate q.term q.request

private theorem seen_cons (q : Query) (t : Model.State) (h : Historical.History) :
    HasSeen q (t :: h) ↔ HasSeen q h ∨ here q t = true := by
  simp only [HasSeen, Historical.Seen, here, List.any_eq_true, Prod.exists, Bool.and_eq_true, beq_iff_eq,
    List.mem_cons]
  grind

private theorem grantStep_iff (q : Query) (s t : Model.State) :
    grantStep q s t = true ↔ Historical.GrantStep t s q.voter q.candidate q.term q.request := by
  simp only [grantStep, Historical.GrantStep, LogFacts.GrantAt, Bool.and_eq_true,
    List.any_eq_true, Prod.exists, beq_iff_eq, decide_eq_true_eq]
  grind

private theorem granted_cons (q : Query) (t s : Model.State) (h : Historical.History) :
    Historical.Granted (t :: s :: h) q.voter q.candidate q.term q.request ↔
      Historical.Granted (s :: h) q.voter q.candidate q.term q.request ∨
      (Historical.GrantStep t s q.voter q.candidate q.term q.request ∧ HasSeen q (t :: s :: h)) := by
  constructor
  · rintro ⟨a, b, rest, suffix, step, seen⟩
    rcases List.suffix_cons_iff.mp suffix with eq | old
    · cases eq; exact .inr ⟨step, seen⟩
    · exact .inl ⟨a, b, rest, old, step, seen⟩
  · rintro (⟨a, b, rest, old, step, seen⟩ | ⟨step, seen⟩)
    · exact ⟨a, b, rest, List.suffix_cons_iff.mpr (.inr old), step, seen⟩
    · exact ⟨t, s, h, List.suffix_refl _, step, seen⟩

/-- Batch specification of the online monitor; the proof's histories are newest first. -/
@[expose] public def scan (q : Query) (s : Model.State) : List Model.State → Memory
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
      simp [scan, start, HasSeen, Historical.Seen]
    · change false = true ↔ _
      constructor
      · intro no; contradiction
      · rintro ⟨a, b, rest, suffix, _, _⟩
        have len := suffix.length_le
        simp at len
  | cons prev h ih =>
    obtain ⟨seen, granted⟩ := ih prev
    rw [seen_cons, granted_cons]
    simp [scan, advance, seen, granted, grantStep_iff, seen_cons q s (prev :: h)]

/-- Every recorded grant has candidate evidence in its granting after-state or earlier. -/
public theorem granted_implies_seen (q : Query) (s : Model.State) (h : List Model.State)
    (yes : (scan q s h).granted = true) : (scan q s h).seenCandidate = true := by
  obtain ⟨seen, grant⟩ := correct q s h
  apply seen.2
  obtain ⟨a, b, rest, suffix, _, st, ⟨prior, member, mem⟩, term⟩ := grant.1 yes
  exact ⟨st, ⟨prior, suffix.subset member, mem⟩, term⟩

/-- Scan observed logs of a node in a term. The test can check an exact log or a prefix. -/
@[expose] public def seenWhere (history : List Model.State) (n : NodeID) (k : Nat)
    (test : List Entry → Bool) : Bool :=
  history.any fun s => s.nodes.any fun (id, st) =>
    id == n && st.currentTerm == k && test st.log

private theorem seenWhere_iff (history : List Model.State) (n : NodeID) (k : Nat)
    (test : List Entry → Bool) :
    seenWhere history n k test = true ↔
      ∃ st, Historical.Seen history n st ∧ st.currentTerm = k ∧ test st.log = true := by
  simp only [seenWhere, Historical.Seen, List.any_eq_true, Prod.exists, Bool.and_eq_true, beq_iff_eq]
  grind

@[expose] public def seen (history : List Model.State) (n : NodeID) (k : Nat) (log : List Entry) : Bool :=
  seenWhere history n k fun l => decide (l = log)

private theorem seen_iff [Config.InitialConfiguration] (s : Model.State) (h : List Model.State)
    (n : NodeID) (k : Nat) (log : List Entry) :
    seen (s :: h) n k log = true ↔ (StateCoverage.frame s h).logs.seen n k log := by
  simp only [seen, seenWhere_iff, decide_eq_true_eq, (Historical.frame_correct s h).seen]

@[expose] public def grant (history : List Model.State) (q : Query) : Bool :=
  match history with
  | [] => false
  | s :: h => (scan q s h).granted

private theorem grant_historical (history : List Model.State) (q : Query) :
    grant history q = true ↔ HasGrant q history := by
  cases history with
  | nil => simp [grant, HasGrant, Historical.Granted]
  | cons s h => exact (correct q s h).2

private theorem grant_iff [Config.InitialConfiguration] (s : Model.State) (h : List Model.State)
    (q : Query) :
    grant (s :: h) q = true ↔ (StateCoverage.frame s h).logs.grant q.voter q.candidate q.term q.request :=
  (grant_historical _ _).trans ((Historical.frame_correct s h).grant ..).symm

/-- It suffices to count eligible members of the configurations: other voters
cannot contribute to any of the required majorities. -/
@[expose] public def quorum (cs : List Configuration) (test : NodeID → Bool) : Bool :=
  let voters := Finset.ofList ((cs.flatMap (·.nodes.val)).filter test)
  decide (hasQuorum cs voters)

public theorem quorum_iff (cs : List Configuration) (test : NodeID → Bool) :
    quorum cs test = true ↔ ∃ voters, hasQuorum cs voters ∧ ∀ v ∈ voters, test v = true := by
  let support := Finset.ofList ((cs.flatMap (·.nodes.val)).filter test)
  change decide (hasQuorum cs support) = true ↔ _
  rw [decide_eq_true_eq]
  constructor
  · intro h
    exact ⟨support, h, fun _ mem => (List.mem_filter.mp (Finset.mem_ofList.mp mem)).2⟩
  · rintro ⟨voters, ⟨nonempty, majority⟩, passes⟩
    refine ⟨nonempty, List.all_eq_true.mpr fun c mem => decide_eq_true ?_⟩
    have sub : voters ∩ c.nodes ⊆ support ∩ c.nodes := by
      intro v member
      obtain ⟨yes, inC⟩ := Finset.mem_inter.mp member
      exact Finset.mem_inter.mpr ⟨Finset.mem_ofList.mpr (List.mem_filter.mpr
        ⟨List.mem_flatMap.mpr ⟨c, mem, inC⟩, passes v yes⟩), inC⟩
    have le := Finset.card_le_card sub
    have gt := of_decide_eq_true (List.all_eq_true.mp majority c mem)
    unfold hasConfigurationMajority at gt ⊢
    omega

private def election (t s : Model.State) (rest : List Model.State) (n : NodeID) (k : Nat)
    (test : List Entry → Nat → Bool) : Bool :=
  s.nodes.any fun (old, x) => t.nodes.any fun (newId, y) =>
    test x.log x.commitIndex &&
    decide (old = n ∧ newId = n ∧ x.commitIndex ≤ x.log.length ∧
      (x.currentTerm < k ∨ (x.currentTerm = k ∧ x.role = .candidate)) ∧ y.currentTerm = k ∧
      (y.role = .primary ∨ y.role = .none) ∧ x.log.take (maxCommittableIndex x.log) <+: y.log ∧ 3 ≤ k) &&
    quorum (activeConfigurations x.log x.commitIndex) fun v =>
      grant (t :: s :: rest) ⟨v, n, k, LogFacts.requestAt k x.log x.commitIndex⟩

private theorem election_iff (t s : Model.State) (rest : List Model.State) (n : NodeID) (k : Nat)
    (test : List Entry → Nat → Bool) :
    election t s rest n k test = true ↔
      ∃ log i, test log i = true ∧ Historical.ElectStep t s rest n k log i := by
  simp only [election, List.any_eq_true, Prod.exists, Bool.and_eq_true, decide_eq_true_eq,
    quorum_iff, grant_historical, HasGrant, Historical.ElectStep, Historical.vals, LogFacts.requestAt]
  constructor
  · rintro ⟨_, x, old, _, y, new, ⟨accept, rfl, rfl, facts⟩, votes⟩
    exact ⟨_, _, accept, x, y, old, new, rfl, rfl, facts.1, facts.2.1, facts.2.2.1,
      facts.2.2.2.1, facts.2.2.2.2.1, facts.2.2.2.2.2, votes⟩
  · rintro ⟨_, _, accept, x, y, old, new, rfl, rfl, le, term, eq, role, sub, floor, votes⟩
    exact ⟨n, x, old, n, y, new, ⟨accept, rfl, rfl, le, term, eq, role, sub, floor⟩, votes⟩

private def electedWhere (n : NodeID) (k : Nat) (test : List Entry → Nat → Bool) :
    List Model.State → Bool
  | t :: s :: h => election t s h n k test || electedWhere n k test (s :: h)
  | _ => false

private theorem electedWhere_iff (n : NodeID) (k : Nat) (test : List Entry → Nat → Bool)
    (history : List Model.State) :
    electedWhere n k test history = true ↔
      ∃ l i, test l i = true ∧ Historical.Elected history n k l i := by
  induction history with
  | nil => simp [electedWhere, Historical.Elected]
  | cons t h ih =>
    cases h with
    | nil =>
      simp only [electedWhere, Bool.false_eq_true, false_iff, Historical.Elected]
      rintro ⟨_, _, _, _, _, _, suf, _⟩
      have := suf.length_le
      simp at this
    | cons s rest =>
      rw [electedWhere, Bool.or_eq_true, election_iff, ih]
      unfold Historical.Elected
      simp only [Historical.edge_cons, List.cons.injEq]
      grind

@[expose] public def elected (history : List Model.State) (n : NodeID) (k : Nat)
    (log : List Entry) (commit : Nat) : Bool :=
  electedWhere n k (fun l i => decide (l = log ∧ i = commit)) history

private theorem elected_iff [Config.InitialConfiguration] (s : Model.State) (h : List Model.State)
    (n : NodeID) (k : Nat) (log : List Entry) (commit : Nat) :
    elected (s :: h) n k log commit = true ↔ (StateCoverage.frame s h).logs.elected n k log commit := by
  simp only [elected, electedWhere_iff, decide_eq_true_eq, (Historical.frame_correct s h).elected]
  grind

@[expose] public def led (cfg : Finset NodeID) (history : List Model.State)
    (n : NodeID) (k : Nat) : Bool :=
  decide (k = BOOTSTRAP_TERM ∧ n = cfg.min?.getD 0) || electedWhere n k (fun _ _ => true) history

private theorem led_historical [Config.InitialConfiguration] (history : List Model.State)
    (n : NodeID) (k : Nat) :
    led Config.INITIAL_CONFIGURATION history n k = true ↔ Historical.Led history n k := by
  simp only [led, Historical.Led, Config.INITIAL_PRIMARY, Bool.or_eq_true, decide_eq_true_eq,
    electedWhere_iff, true_and]

private theorem led_iff [Config.InitialConfiguration] (s : Model.State) (h : List Model.State)
    (n : NodeID) (k : Nat) :
    led Config.INITIAL_CONFIGURATION (s :: h) n k = true ↔
      (StateCoverage.frame s h).logs.led Config.INITIAL_PRIMARY n k :=
  (led_historical _ _ _).trans (Historical.led_iff s h n k).symm

end ConsensusCoverage.GrantMonitor
