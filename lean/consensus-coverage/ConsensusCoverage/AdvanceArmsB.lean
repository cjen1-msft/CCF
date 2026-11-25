module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.NominationRetirementB
import all ConsensusCoverage.BatchArmsB
import all ConsensusCoverage.SelfQuorumCasesB
import all ConsensusCoverage.ReceiveCasesB
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.DeepSchedulesB
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.AdvanceArmsB

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety
open ActionProfile ReadersAtoms SolvedWitnesses DeepSchedulesB

set_option maxRecDepth 8192
set_option maxHeartbeats 600000

private def appended (s : NodeState) : NodeState :=
  {s with log := s.log ++ [({term := s.currentTerm, content := .signature} : Entry)]}

section
variable [Config.InitialConfiguration] {f : Frame} {t : Model.State} {c : Ctx f t}

private structure Origins (c : Ctx f t) (actor : NodeID) (m n : NodeState) : Prop where
  term : (reach% step_term_advance_inl[6]) f t c actor m n
  vote : (reach% step_votedFor_advance_inl[6]) f t c actor m n
  role : (reach% step_role_advance_inl[6]) f t c actor m n
  ack : (reach% step_matchIndex_advance_inl[6]) f t c actor m n
  log : (reach% step_log_advance_inl[6]) f t c actor m n
  commit : (reach% step_commit_le_advance_inl[6]) f t c actor m n

private theorem origins (s : BatchArmsB.Seed c) (m n : NodeState) (middle : m = appended s.before)
    (vote : s.before.votedFor = some s.self) (adv : Advance s.self m n)
    (primary : n.role = .primary) (term : n.currentTerm = s.before.currentTerm)
    (log : n.log = m.log) (le : s.before.commitIndex ≤ n.commitIndex) :
    Origins c s.self m n := by
  let entries : List Entry := [⟨s.before.currentTerm, .signature⟩]
  have terms : ∀ e ∈ entries, e.term = s.before.currentTerm := by simp [entries]
  let e := SelfQuorumCasesB.heartbeat s.self m
  let q : AppendEntriesRequest := ⟨m.currentTerm, 0, termAt m.log 0, [], 0⟩
  have mt : m.currentTerm = s.before.currentTerm := middle ▸ rfl
  have mc : m.commitIndex = s.before.commitIndex := middle ▸ rfl
  have ae : AEFrom s.self s.before.currentTerm s.before.commitIndex m.log e :=
    mt ▸ mc ▸ SelfQuorumCasesB.beat s.self m
  have batch : BatchState s.self s.before m [e] :=
    ⟨⟨entries, s.before.sentIndex, middle, terms⟩, SelfQuorumCasesB.singleton ae⟩
  have ok : AEOk s.self e.target n q := by
    refine ⟨Nat.succ_ne_self _, mt.trans term.symm, Nat.zero_le _, ?_, List.nil_prefix, Nat.zero_le _⟩
    rw [log]
  have ae' : AEFrom s.self n.currentTerm n.commitIndex n.log e :=
    ⟨rfl, ok.1, q, rfl, ok.2⟩
  have empty : ∀ e' ∈ ([] : List Model.Envelope), e'.source = s.self ∧
      e'.payload = .proposeRequestVoteRequest m.currentTerm := by simp
  constructor
  all_goals first
    | (iterate 3 right
       left
       refine ⟨s.before, s.contents, s.entered, s.guards, s.guards.1, s.guards.2, s.guards,
        m, [e], batch, [], ⟨adv, empty⟩, adv, empty, batch.1, batch.2, entries,
        ⟨s.before.sentIndex, middle, terms⟩, s.before.sentIndex, ⟨middle, terms⟩, middle, terms,
        e, .head _, .head _, q, ⟨rfl, ok⟩, rfl, ok, BatchArmsB.start s, ?_⟩)
    | (right
       left
       refine ⟨s.before, s.contents, s.entered, s.guards, s.guards.1, s.guards.2, s.guards,
        m, [e], batch, [], ⟨adv, empty⟩, adv, empty, batch.1, batch.2, entries,
        ⟨s.before.sentIndex, middle, terms⟩, s.before.sentIndex, ⟨middle, terms⟩, middle, terms, ?_⟩)
  · exact ⟨BatchArmsB.start s, log, Or.inl primary, le, rfl⟩
  · exact ⟨term, s.self, vote, BatchArmsB.start s, term, log, Or.inl primary, le, rfl⟩
  · exact ⟨term, log, le, ae', rfl⟩
  · exact ⟨primary, s.guards.1, term, BatchArmsB.start s, term, log, Or.inl primary, le, rfl⟩
  · exact ⟨term, Or.inl primary, le, rfl⟩
  · exact ⟨e, .head _, .head _, BatchArmsB.start s, term, log, Or.inl primary, rfl⟩

end

public def questions : List Classes.StepBranch := [.term_advance_inl, .term_advance_inr,
  .votedFor_advance_inl, .votedFor_advance_inr, .role_advance_inl, .role_advance_inr,
  .matchIndex_advance_inl, .matchIndex_advance_inr, .log_advance_inl, .log_advance_inr,
  .commit_le_advance_inl, .commit_le_advance_inr]

private theorem casesOf [Config.InitialConfiguration] {f : Frame} {t : Model.State} {c : Ctx f t}
    (s : BatchArmsB.Seed c) (m : NodeState) (middle : m = appended s.before)
    (vote : s.before.votedFor = some s.self) (ahead : m.commitIndex < highestCommittableIndex m s.self)
    {b : Classes.StepBranch} (mem : b ∈ questions) : sig c b := by
  let n := {m with commitIndex := highestCommittableIndex m s.self}
  have stable : Advance s.self m m := Or.inl rfl
  have grow : Advance s.self m n := Or.inr ⟨rfl, rfl, rfl, rfl, rfl, rfl, ahead, rfl, Or.inl rfl⟩
  have strict := Or.resolve_left grow fun eq => (Nat.ne_of_lt ahead) (congrArg NodeState.commitIndex eq).symm
  have primary : m.role = .primary := middle ▸ s.guards.1
  have term : m.currentTerm = s.before.currentTerm := middle ▸ rfl
  have commit : s.before.commitIndex = m.commitIndex := middle ▸ rfl
  have u := origins s m m middle vote stable primary term rfl (Nat.le_of_eq commit)
  have v := origins s m n middle vote grow primary term rfl (commit ▸ Nat.le_of_lt ahead)
  simp only [questions, List.mem_cons, List.not_mem_nil, or_false] at mem
  rcases mem with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl
  all_goals iterate 6 right
  all_goals left
  · exact ⟨_, _, u.term, stable⟩
  · exact ⟨_, _, _, v.term, strict, grow⟩
  · exact ⟨_, _, u.vote, stable⟩
  · exact ⟨_, _, _, v.vote, strict, grow⟩
  · exact ⟨_, _, u.role, stable⟩
  · exact ⟨_, _, _, v.role, strict, grow⟩
  · exact ⟨_, _, u.ack, stable⟩
  · exact ⟨_, _, _, v.ack, strict, grow⟩
  · exact ⟨_, _, u.log, stable⟩
  · exact ⟨_, _, _, v.log, strict, grow⟩
  · exact ⟨_, _, u.commit, stable⟩
  · exact ⟨_, _, _, v.commit, strict, grow⟩

private theorem fromView [Config.InitialConfiguration] {f : Frame} {t : Model.State} {c : Ctx f t}
    (x : XView) (ok : x.Matches c) (changed : x.base.changed = true)
    (ev : x.event = .internal (.append (BatchArmsB.items x.event)))
    (guards : x.base.pre.role = .primary ∧ ¬ x.base.pre.isRetiredCommitted x.base.actor ∧
      BatchArmsB.items x.event ≠ [])
    (vote : x.base.pre.votedFor = some x.base.actor)
    (ahead : (appended x.base.pre).commitIndex < highestCommittableIndex (appended x.base.pre) x.base.actor)
    {b : Classes.StepBranch} (mem : b ∈ questions) : sig c b :=
  casesOf (BatchArmsB.seedOf ok changed ev guards) (appended x.base.pre) rfl vote ahead mem

public theorem occurs {b : Classes.StepBranch} (mem : b ∈ questions) :
    ∃ s : Step, label s (.step b) = true := by
  let a := ReceiveCasesB.asSample electedAppend 6 (by decide +kernel) (by decide +kernel)
  letI : Config.InitialConfiguration := ⟨a.s.cfg⟩
  have witness := fromView (c := a.s.context) a.x a.ok (by decide +kernel)
    (by decide +kernel) (by decide +kernel) (by decide +kernel) (by decide +kernel) mem
  exact ⟨a.s, (label_true a.s _).mpr ((sig_iff a.s.context _).mpr witness)⟩

end ConsensusCoverage.AdvanceArmsB
