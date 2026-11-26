module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersASummary
import all ConsensusCoverage.HandReadersTrunkBFactor
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
public meta import ConsensusCoverage.HandReadersTrunkBFactor

namespace ConsensusCoverage.HandReadersTrunkB.Elect

open Consensus Model Model.Node Proofs Safety ActionProfile HandReadersA HandReadersBGate SolvedWitnesses
open Lean Elab Command

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxHeartbeats 3000000
set_option maxRecDepth 16384

def column (win : Bool) : Classes.StepBranch :=
  if win then .elect_result_elected_inr else .elect_result_elected_inl

private abbrev candidate (st : NodeState) (n : NodeID) :=
  { st with votesGranted := insert n st.votesGranted }

private def guard (win : Bool) (self : NodeID) (st : NodeState) (ev : Event) : Prop :=
  ∃ n q, ev = .receive n (.requestVoteResponse q) ∧ n ∈ eligiblePeers st self ∧
    (st.role = .candidate ∧ q.term = st.currentTerm ∧ q.voteGranted = true) ∧
    (win = true → hasQuorum st.activeConfigurations (insert n st.votesGranted))

def test (win : Bool) (self : NodeID) (st : NodeState) (ev : Event) (_ : NodeState) : Bool :=
  match ev with
  | .receive n (.requestVoteResponse q) =>
    decide (n ∈ eligiblePeers st self ∧
      (st.role = .candidate ∧ q.term = st.currentTerm ∧ q.voteGranted = true) ∧
      (win = true → hasQuorum st.activeConfigurations (insert n st.votesGranted)))
  | _ => false

private theorem guard_iff (win self st ev post) :
    guard win self st ev ↔ test win self st ev post = true := by
  cases ev with
  | internal _ => simp [guard,test]
  | receive n m => cases m <;> simp [guard,test] <;> grind

run_cmd liftTermElabM do
  for n in #[``step_elect_result_elected_inl,``step_elect_result_elected_inr] do
    HandReadersTrunkBFactor.compile n

section
variable [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t)

private abbrev tail (win : Bool) := if win then
  HandReadersTrunkBFactor.Tail.step_elect_result_elected_inr f t c
  else HandReadersTrunkBFactor.Tail.step_elect_result_elected_inl f t c

private theorem tail_iff (win : Bool) : tail c win ↔ guard win c.actor c.pre c.event := by
  constructor
  · cases win
    · rintro ⟨_,_,⟨_,n,q,⟨_,⟨rfl,rfl,rfl⟩,_,ev,_,rfl⟩,pass,_,_,_,g,_,_,rfl⟩,_⟩
      exact ⟨n,q,ev,Classical.byContradiction (fun no => pass ⟨trivial,no⟩),g,by simp⟩
    · rintro ⟨_,_,_,_,⟨_,n,q,⟨_,⟨rfl,rfl,rfl⟩,_,ev,_,rfl⟩,pass,_,_,_,g,_,_,rfl⟩,won,_⟩
      exact ⟨n,q,ev,Classical.byContradiction (fun no => pass ⟨trivial,no⟩),g,fun _ => won.2.1⟩
  · rintro ⟨n,q,ev,peer,g,quorum⟩
    let mid := candidate c.pre n
    let leader := primaryState mid
    have pass : ¬(True ∧ ¬n ∈ eligiblePeers c.pre c.actor) := fun h => h.2 peer
    obtain higher | obs := observe_bumping c.pre (message := .requestVoteResponse q) trivial
    · exact (Nat.not_lt_of_ge (Nat.le_of_eq g.2.1) higher.1).elim
    have camp : Campaign c.actor c.pre (.receive n (.requestVoteResponse q)) mid := by
      refine ⟨g.1,rfl,rfl,.inr ⟨g.1,rfl,.inl rfl,?_⟩⟩
      intro voter mem
      rcases CCF.Finset.mem_insert.mp mem with rfl | old
      · exact .inr ⟨q,rfl,g.2⟩
      · exact .inl old
    cases win
    · exact ⟨_,mid,⟨_,n,q,⟨c.event,⟨rfl,rfl,rfl⟩,_,ev,ev,rfl⟩,pass,obs,obs.1,obs.2,g,
        .inl ⟨rfl,rfl⟩,camp,rfl⟩,.inl trivial⟩
    · have adv : Advance c.actor leader leader := .inl rfl
      have empty : ∀ e ∈ ([] : List Model.Envelope), LeaderStart c.actor mid.currentTerm leader e := by simp
      have won := And.intro g.1 (And.intro (quorum rfl) (And.intro adv empty))
      exact ⟨_,mid,leader,[],⟨_,n,q,⟨c.event,⟨rfl,rfl,rfl⟩,_,ev,ev,rfl⟩,pass,obs,obs.1,obs.2,g,
        .inr won,camp,rfl⟩,won,won.1,won.2,won.2.1,won.2.2,adv,empty,.inr won⟩
end

def exactReader (win : Bool) : Exact (column win) where
  eval := SummaryRows.gated (test win)
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    let c := s.context
    apply Bool.eq_iff_iff.mpr
    rw [label_true,show holds s (.step (column win)) ↔ sig c (column win) from sig_iff _ _,
      SummaryRows.gated,Bool.and_eq_true,actorRead_at,live,and_comm,←guard_iff,←tail_iff]
    cases win
    · exact HandReadersTrunkBFactor.Exact.step_elect_result_elected_inl _ _ _ (quiet s)
    · exact HandReadersTrunkBFactor.Exact.step_elect_result_elected_inr _ _ _ (quiet s)

end ConsensusCoverage.HandReadersTrunkB.Elect
