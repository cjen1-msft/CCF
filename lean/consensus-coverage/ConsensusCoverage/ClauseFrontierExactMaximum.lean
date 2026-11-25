module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ClauseFrontierExactFactors
import all ConsensusCoverage.ClauseFrontierExactFactors
import all ConsensusCoverage.HandReadersElectionBBounds
import all ConsensusCoverage.HandReadersElectionBFrontier
import all ConsensusCoverage.HandReadersOtherFrontier
import all ConsensusCoverage.AssistAcceptedA
import all ConsensusCoverage.FollowerFoldCasesB
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.ClauseFrontierExact.Maximum

open Consensus Model Model.Node Proofs Safety ActionProfile SolvedWitnesses
open HandReadersElectionB

set_option maxHeartbeats 0
set_option maxRecDepth 16384

local macro "place " h:term : tactic => `(tactic|
  repeat' first | exact $h | exact Or.inl $h | apply Or.inr)

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)

private theorem signature_cons (h : sig c .maxCommittableIndexBounded_signature_pos) :
    sig c .maxCommittableIndexBounded_values_cons := by
  change step_maxCommittableIndexBounded_signature_pos f t c at h
  change step_maxCommittableIndexBounded_values_cons f t c
  unfold step_maxCommittableIndexBounded_signature_pos at h
  unfold step_maxCommittableIndexBounded_values_cons
  rcases h with h | h | h | h | h | h | h | h | h | h | h | h | h | h | h | h
  all_goals
    obtain ⟨log,site,_⟩ := h
    have tail := (Bounds.cons log).mpr trivial
    place ⟨log,site,tail⟩

private theorem accepted_calls {q : AppendEntriesRequest} (h : Frontier.Good c q) :
    sig c .maxCommittableIndexBounded_values_nil ∧
      sig c .maxCommittableIndexBounded_values_cons ∧
      (0 < maxCommittableIndex
        ((Frontier.resultLog (Frontier.adjusted c.pre q) q).take
          (min q.primaryCommit (q.prevLogIndex + q.entries.length))) →
        sig c .maxCommittableIndexBounded_signature_pos) := by
  have ⟨fresh,event,pass⟩ := h
  let log := (Frontier.resultLog (Frontier.adjusted c.pre q) q).take
    (min q.primaryCommit (q.prevLogIndex + q.entries.length))
  have nil := (Frontier.erased_iff c).mpr ⟨q,fresh,event,pass⟩
  have site : (reach% step_maxCommittableIndexBounded_values_cons[15]) f t c log :=
    (Frontier.last_iff c _).mpr ⟨q,fresh,event,pass,rfl⟩
  refine ⟨?_,?_,?_⟩
  · change step_maxCommittableIndexBounded_values_nil f t c
    unfold step_maxCommittableIndexBounded_values_nil
    place nil
  · change step_maxCommittableIndexBounded_values_cons f t c
    unfold step_maxCommittableIndexBounded_values_cons
    have tail := (Bounds.cons log).mpr trivial
    place ⟨log,site,tail⟩
  · intro pos
    change step_maxCommittableIndexBounded_signature_pos f t c
    unfold step_maxCommittableIndexBounded_signature_pos
    have tail := (Bounds.signed log).mpr pos
    place ⟨log,site,tail⟩

end

theorem signature_needs_scan (s : Step)
    (h : label s (.step .maxCommittableIndexBounded_signature_pos) = true) :
    label s (.step .maxCommittableIndexBounded_values_cons) = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  have spec (q : Classes.StepBranch) := (label_true s (.step q)).trans (sig_iff s.context q)
  exact (spec _).mpr (signature_cons s.context ((spec _).mp h))

theorem append_accept_scans (s : Step) (k : HandReadersA.Handler.Branch)
    (accepted : k = .clear ∨ k = .conflict)
    (h : label s (.step (HandReadersA.Handler.column k)) = true) :
    label s (.step .maxCommittableIndexBounded_values_nil) = true ∧
    label s (.step .maxCommittableIndexBounded_values_cons) = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  have spec (q : Classes.StepBranch) := (label_true s (.step q)).trans (sig_iff c q)
  have sig := (spec _).mp h
  obtain ⟨n,q,ev⟩ := HandReadersA.Handler.requires_request c k sig
  obtain ⟨fresh,test⟩ := (HandReadersA.Handler.at_request c ev k).mp sig
  have pass : Frontier.Pass c.pre q := by
    rcases accepted with rfl | rfl <;>
      simp only [HandReadersA.Handler.test, Bool.and_eq_true, decide_eq_true_eq] at test <;>
      exact test.1
  obtain ⟨nil,cons,_⟩ := accepted_calls c ⟨fresh,⟨n,ev⟩,pass⟩
  exact ⟨(spec _).mpr nil,(spec _).mpr cons⟩

theorem advance_needs_signature (s : Step)
    (h : label s (.step .advance_le_total_inl) = true) :
    label s (.step .maxCommittableIndexBounded_signature_pos) = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  have spec (q : Classes.StepBranch) := (label_true s (.step q)).trans (sig_iff c q)
  have hit : sig c (AssistAcceptedA.column (HandReadersOther.Frontier.kind true)) := (spec _).mp h
  obtain ⟨fresh,test⟩ := (HandReadersOther.Frontier.iff_test c true).mp hit
  cases ev : c.event with
  | internal i => simp [ev,HandReadersOther.Frontier.test] at test
  | receive n m =>
    cases m <;> simp only [ev,HandReadersOther.Frontier.test, Bool.and_eq_true, decide_eq_true_eq,
      Bool.false_eq_true] at test <;> try contradiction
    rename_i q
    obtain ⟨pass,guard⟩ := test
    let w := HandReadersOther.Frontier.working c.pre q
    have gas : 0 < max w.commitIndex (AssistAcceptedA.bound w q) ∧
        w.commitIndex ≤ AssistAcceptedA.bound w q := of_decide_eq_true guard
    obtain ⟨positive,le⟩ := gas
    have route := accepted_calls c ⟨fresh,⟨n,ev⟩,pass⟩
    apply (spec _).mpr
    apply route.2.2
    rw [Nat.max_eq_right le] at positive
    exact positive

end ConsensusCoverage.ClauseFrontierExact.Maximum
