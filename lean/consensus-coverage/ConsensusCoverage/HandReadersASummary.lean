module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersABase
import all ConsensusCoverage.HandReadersBGate
import all ConsensusCoverage.HandReadersBFactor
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
public meta import ConsensusCoverage.HandReadersBFactor

namespace ConsensusCoverage.HandReadersA.SummaryRows

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety ActionProfile SolvedWitnesses
open HandReadersBGate
open Lean Elab Command

set_option maxRecDepth 16384
set_option maxHeartbeats 1000000
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

inductive Branch where | empty | signed | bump | higherAck | otherAck

def column : Branch → Classes.StepBranch
  | .empty => .initAsBackup_summary_eq_zero_or_pos_inl
  | .signed => .initAsBackup_summary_eq_zero_or_pos_inr
  | .bump => .appendEntriesRequest_summary_observe_bumping_inl
  | .higherAck => .appendEntriesResponse_summary_observe_response_inl
  | .otherAck => .appendEntriesResponse_summary_observe_response_inr

def test (k : Branch) (self : NodeID) (pre : NodeState) (event : Event) (_ : NodeState) : Bool :=
  match k,event with
  | .empty,.internal (.initAsBackup entries) => decide (pre.isFresh ∧ entries = [])
  | .signed,.internal (.initAsBackup entries) =>
    decide (pre.isFresh ∧ 0 < entries.length ∧ isSignatureAt entries entries.length = true)
  | .bump,.receive _ (.appendEntriesRequest q) => decide (pre.currentTerm < q.term)
  | .higherAck,.receive n (.appendEntriesResponse q) =>
    decide (n ∈ eligiblePeers pre self ∧ pre.role = .primary ∧ pre.currentTerm < q.term)
  | .otherAck,.receive n (.appendEntriesResponse q) =>
    decide (n ∈ eligiblePeers pre self ∧ (pre.role = .primary → q.term ≤ pre.currentTerm))
  | _,_ => false

def gated (p : NodeID → NodeState → Event → NodeState → Bool) : Reader :=
  fun cfg before act after past => actorRead p cfg before act after past && active cfg before act after past

def reader (k : Branch) : Reader := gated (test k)

private def guard (self : NodeID) (st : NodeState) (event : Event) : Branch → Prop
  | .empty => ∃ xs, event = .internal (.initAsBackup xs) ∧ st.isFresh ∧ xs = []
  | .signed => ∃ xs, event = .internal (.initAsBackup xs) ∧ st.isFresh ∧
      0 < xs.length ∧ isSignatureAt xs xs.length = true
  | .bump => ∃ n q, event = .receive n (.appendEntriesRequest q) ∧ st.currentTerm < q.term
  | .higherAck => ∃ n q, event = .receive n (.appendEntriesResponse q) ∧ n ∈ eligiblePeers st self ∧
      st.role = .primary ∧ st.currentTerm < q.term
  | .otherAck => ∃ n q, event = .receive n (.appendEntriesResponse q) ∧ n ∈ eligiblePeers st self ∧
      (st.role = .primary → q.term ≤ st.currentTerm)

private theorem guard_iff (self st event post k) :
    guard self st event k ↔ test k self st event post = true := by
  cases event with
  | internal i => cases i <;> cases k <;> simp [guard,test]
  | receive n m => cases m <;> cases k <;> simp [guard,test] <;> grind

run_cmd liftTermElabM do
  for n in #[``step_initAsBackup_summary_eq_zero_or_pos_inl, ``step_initAsBackup_summary_eq_zero_or_pos_inr,
      ``step_appendEntriesRequest_summary_observe_bumping_inl, ``step_appendEntriesResponse_summary_observe_response_inl,
      ``step_appendEntriesResponse_summary_observe_response_inr] do
    HandReadersBFactor.compile n

section
variable [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t)

private theorem install (signed : Bool) :
    (if signed then HandReadersBFactor.Tail.step_initAsBackup_summary_eq_zero_or_pos_inr f t c
      else HandReadersBFactor.Tail.step_initAsBackup_summary_eq_zero_or_pos_inl f t c) ↔
      guard c.actor c.pre c.event (if signed then .signed else .empty) := by
  cases signed
  all_goals
    constructor
    · rintro ⟨_,xs,⟨_,⟨rfl,rfl⟩,_,ev,_,rfl⟩,⟨fresh,valid⟩,_,_,_,_,_,_,_,_,_,len⟩
      first
      | exact ⟨xs,ev,fresh,List.length_eq_zero_iff.mp len⟩
      | exact ⟨xs,ev,fresh,len,valid.resolve_left (List.ne_nil_of_length_pos len)⟩
    · rintro ⟨xs,ev,fresh,branch⟩
      have valid : xs = [] ∨ isSignatureAt xs xs.length = true := by first | exact .inl branch | exact .inr branch.2
      obtain ⟨role,term,log,index⟩ := fresh
      refine ⟨_,xs,⟨c.event,⟨rfl,rfl⟩,_,ev,ev,rfl⟩,?_⟩
      first | rw [branch] at * | have pos := branch.1
      repeat' first | assumption | rfl | apply And.intro

private theorem request : HandReadersBFactor.Tail.step_appendEntriesRequest_summary_observe_bumping_inl f t c ↔
    guard c.actor c.pre c.event .bump := by
  constructor
  · rintro ⟨_,q,⟨_,⟨rfl,rfl⟩,n,_,ev,_,rfl⟩,higher,_⟩
    exact ⟨n,q,ev,higher⟩
  · rintro ⟨n,q,ev,higher⟩
    obtain bump | stable := observe_bumping c.pre (message := .appendEntriesRequest q) trivial
    · exact ⟨_,q,⟨c.event,⟨rfl,rfl⟩,n,_,ev,ev,rfl⟩,bump⟩
    · exact (Nat.not_le_of_lt higher stable.1).elim

private theorem ack (higher : Bool) :
    (if higher then HandReadersBFactor.Tail.step_appendEntriesResponse_summary_observe_response_inl f t c
      else HandReadersBFactor.Tail.step_appendEntriesResponse_summary_observe_response_inr f t c) ↔
      guard c.actor c.pre c.event (if higher then .higherAck else .otherAck) := by
  cases higher
  all_goals
    constructor
    · rintro ⟨_,_,n,q,⟨_,⟨rfl,rfl,rfl⟩,_,ev,_,rfl⟩,notElse,facts⟩
      have peer : n ∈ eligiblePeers c.pre c.actor := Classical.byContradiction fun no => notElse ⟨trivial,no⟩
      first | exact ⟨n,q,ev,peer,facts.1⟩ | exact ⟨n,q,ev,peer,facts.1,facts.2.1⟩
    · rintro ⟨n,q,ev,peer,cut⟩
      refine ⟨_,_,n,q,⟨c.event,⟨rfl,rfl,rfl⟩,_,ev,ev,rfl⟩,fun no => no.2 peer,?_⟩
      rcases observe_response c.pre q with bump | stable
      all_goals first | assumption | exact (Nat.not_le_of_lt bump.2.1 (cut bump.1)).elim
                      | exact (Nat.not_le_of_lt cut.2 (stable.1 cut.1)).elim
end

def exactReader (k : Branch) : Exact (column k) where
  eval := reader k
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    let c := s.context
    have no := quiet s
    apply Bool.eq_iff_iff.mpr
    rw [label_true, show holds s (.step (column k)) ↔ sig c (column k) from sig_iff _ _,
      reader,gated,Bool.and_eq_true,actorRead_at,live,and_comm,← guard_iff]
    cases k
    all_goals first
      | exact (HandReadersBFactor.Exact.step_initAsBackup_summary_eq_zero_or_pos_inl _ _ c no).trans
          (and_congr_right fun _ => install c false)
      | exact (HandReadersBFactor.Exact.step_initAsBackup_summary_eq_zero_or_pos_inr _ _ c no).trans
          (and_congr_right fun _ => install c true)
      | exact (HandReadersBFactor.Exact.step_appendEntriesRequest_summary_observe_bumping_inl _ _ c no).trans
          (and_congr_right fun _ => request c)
      | exact (HandReadersBFactor.Exact.step_appendEntriesResponse_summary_observe_response_inl _ _ c no).trans
          (and_congr_right fun _ => ack c true)
      | exact (HandReadersBFactor.Exact.step_appendEntriesResponse_summary_observe_response_inr _ _ c no).trans
          (and_congr_right fun _ => ack c false)

end ConsensusCoverage.HandReadersA.SummaryRows
