module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.GrantMonitor
import all ConsensusCoverage.GrantMonitor
import all ConsensusCoverage.Historical
import all Consensus.Proofs.SafetyInvariant
import CCF.Proofs.Finset

/-! Decide whether the proof has any committed prefix. A chain cannot produce the first
certificate: its earlier link would already count. At a fresh certificate it therefore
suffices to check base zero. No bound on terms, log lengths or node IDs is used. -/

namespace ConsensusCoverage.CommitMonitor

open CCF Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs

private def quorum (cs : List Configuration) (test : NodeID → Bool) : Bool :=
  let voters := Finset.ofList ((cs.flatMap (·.nodes.val)).filter test)
  decide (hasQuorum cs voters)

private theorem quorum_iff (cs : List Configuration) (test : NodeID → Bool) :
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

private def election (t s : Model.State) (rest : List Model.State) (n k : Nat) : Bool :=
  s.nodes.any fun (old, x) => t.nodes.any fun (newId, y) =>
    decide (old = n ∧ newId = n ∧ x.commitIndex ≤ x.log.length ∧
      (x.currentTerm < k ∨ (x.currentTerm = k ∧ x.role = .candidate)) ∧ y.currentTerm = k ∧
      (y.role = .primary ∨ y.role = .none) ∧ x.log.take (maxCommittableIndex x.log) <+: y.log ∧ 3 ≤ k) &&
      quorum (activeConfigurations x.log x.commitIndex) fun v =>
        (GrantMonitor.scan ⟨v, n, k, LogFacts.requestAt k x.log x.commitIndex⟩ t (s :: rest)).granted

private theorem election_iff (t s : Model.State) (rest : List Model.State) (n k : Nat) :
    election t s rest n k = true ↔ ∃ log i, Historical.ElectStep t s rest n k log i := by
  have grants (v : Nat) (r : RequestVoteRequest) :
      (GrantMonitor.scan ⟨v, n, k, r⟩ t (s :: rest)).granted = true ↔
        Historical.Granted (t :: s :: rest) v n k r :=
    (GrantMonitor.correct ⟨v, n, k, r⟩ t (s :: rest)).2
  simp only [election, List.any_eq_true, Prod.exists, Bool.and_eq_true, decide_eq_true_eq,
    quorum_iff, grants, Historical.ElectStep]
  constructor
  · rintro ⟨_, x, old, _, y, new, ⟨rfl, rfl, facts⟩, votes⟩
    exact ⟨_, _, x, y, old, new, rfl, rfl, facts.1, facts.2.1, facts.2.2.1,
      facts.2.2.2.1, facts.2.2.2.2.1, facts.2.2.2.2.2, votes⟩
  · rintro ⟨_, _, x, y, old, new, rfl, rfl, le, term, eq, role, sub, floor, votes⟩
    exact ⟨n, x, old, n, y, new, ⟨rfl, rfl, le, term, eq, role, sub, floor⟩, votes⟩

private def elected (n k : Nat) : List Model.State → Bool
  | t :: s :: h => election t s h n k || elected n k (s :: h)
  | _ => false

private theorem elected_iff (n k : Nat) (h : List Model.State) :
    elected n k h = true ↔ ∃ l i, Historical.Elected h n k l i := by
  induction h with
  | nil => simp [elected, Historical.Elected]
  | cons t h ih =>
    cases h with
    | nil =>
      simp only [elected, Bool.false_eq_true, false_iff, Historical.Elected]
      rintro ⟨_, _, _, _, _, suf, _⟩
      have := suf.length_le; simp at this
    | cons s rest =>
      rw [elected, Bool.or_eq_true, election_iff, ih]
      unfold Historical.Elected
      simp only [Historical.edge_cons, List.cons.injEq]
      grind

private def fresh (bootstrap : NodeID) (s : Model.State) (h : List Model.State) : Bool :=
  let hist := s :: h
  s.nodes.any fun (n, st) =>
    let k := st.currentTerm
    decide (st.role ≠ .candidate) &&
    (decide (k = BOOTSTRAP_TERM ∧ n = bootstrap) || elected n k hist) &&
    (List.range (st.log.length + 1)).any fun i =>
      isSignatureAt st.log i && decide (termAt st.log i = k) &&
      quorum ((activeConfigurations st.log 0).filter (·.index ≤ i)) fun v =>
        hist.any fun snap => snap.nodes.any fun (id, x) =>
          decide (id = v ∧ x.currentTerm = k ∧ st.log.take i <+: x.log)

private theorem fresh_iff [Config.InitialConfiguration] (s : Model.State) (h : List Model.State) :
    fresh Config.INITIAL_PRIMARY s h = true ↔
      ∃ n st k i, Historical.CommitStep (s :: h) n st k 0 i := by
  simp only [fresh, List.any_eq_true, Prod.exists, Bool.and_eq_true, Bool.or_eq_true,
    decide_eq_true_eq, elected_iff, List.mem_range, Nat.lt_succ_iff, quorum_iff,
    Historical.CommitStep, Historical.CanonNow, Historical.Led, Historical.Now,
    Historical.Seen, Nat.zero_le, true_and]
  constructor
  · rintro ⟨n, st, now, ⟨role, led⟩, i, bound, ⟨sig, eq⟩, voters, votes, seen⟩
    refine ⟨n, st, st.currentTerm, i, ⟨now, rfl, role, led⟩, bound, sig, eq, voters, votes, ?_⟩
    intro v member
    obtain ⟨a, past, _, x, found, rfl, term, sub⟩ := seen v member
    exact ⟨x, ⟨a, past, found⟩, term, sub⟩
  · rintro ⟨n, st, _, i, ⟨now, rfl, role, led⟩, bound, sig, eq, voters, votes, seen⟩
    refine ⟨n, st, now, ⟨role, led⟩, i, bound, ⟨sig, eq⟩, voters, votes, ?_⟩
    intro v member
    obtain ⟨x, ⟨a, past, found⟩, term, sub⟩ := seen v member
    exact ⟨a, past, v, x, found, rfl, term, sub⟩

/-- Input is a sequence of protocol snapshots, newest first. The bootstrap node is the
smallest initial voter; action labels and ghost state are not inputs. -/
public def anyCommit (bootstrap : NodeID) : List Model.State → Bool
  | [] => false
  | s :: h => anyCommit bootstrap h || fresh bootstrap s h

theorem anyCommit_iff [Config.InitialConfiguration] (h : List Model.State) :
    anyCommit Config.INITIAL_PRIMARY h = true ↔ ∃ k p, (Historical.logFacts h).committed k p := by
  suffices anyCommit Config.INITIAL_PRIMARY h = true ↔ ∃ k p, Historical.Committed h k p by
    simpa only [(Historical.logFacts_correct h).committed] using this
  induction h with
  | nil =>
    simp only [anyCommit, Bool.false_eq_true, false_iff]
    rintro ⟨_, _, c⟩; cases c
  | cons s h ih =>
    rw [anyCommit, Bool.or_eq_true, ih, fresh_iff]
    simp only [Historical.commit_cons]
    constructor
    · rintro (⟨k, p, c⟩ | ⟨n, st, k, i, fresh⟩)
      · exact ⟨k, p, .inl c⟩
      · exact ⟨k, _, .inr ⟨n, st, 0, i, fresh, rfl, .inl rfl⟩⟩
    · rintro ⟨k, p, old | ⟨n, st, b, i, commit, _, rfl | ⟨e, part, back, _⟩⟩⟩
      · exact .inl ⟨k, p, old⟩
      · exact .inr ⟨n, st, k, i, commit⟩
      · exact .inl ⟨e, part, back⟩

end ConsensusCoverage.CommitMonitor
