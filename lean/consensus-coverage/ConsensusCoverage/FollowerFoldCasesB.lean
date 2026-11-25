module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ReceiveCasesB
import all ConsensusCoverage.ReceiveCasesB
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
meta import Lean

namespace ConsensusCoverage.FollowerFoldCasesB

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety
open ActionProfile ReadersAtoms SolvedWitnesses DeepSchedulesB

set_option maxRecDepth 8192
set_option maxHeartbeats 600000

section
variable [Config.InitialConfiguration] {f : Frame} {t : Model.State} {c : Ctx f t}

private abbrev observed (s : NodeState) (q : AppendEntriesRequest) :=
  observeTerm s (.appendEntriesRequest q)

private abbrev prepared (s : NodeState) (q : AppendEntriesRequest) :=
  let z := observed s q
  if q.term = z.currentTerm ∧ (z.role = .candidate ∨ z.role = .preVoteCandidate) then
    becomeAwareOfNewTerm z q.term else z

private abbrev limit (q : AppendEntriesRequest) := min q.primaryCommit (q.prevLogIndex + q.entries.length)

private abbrev Loop (c : Ctx f t) (self frontier : Nat) :=
  (reach% step_fromLeader_loop_entries_cons[0]) f t c self frontier

-- Use the direct commit-frontier caller: all of its finite obligations refer
-- to the concrete request, not to a quantified safety-summary continuation.
private theorem received {x : XView} (ok : x.Matches c) (fresh : x.base.changed = true)
    (n : NodeID) (q : AppendEntriesRequest) (ev : x.event = .receive n (.appendEntriesRequest q))
    (initial : Direct.CommitFrontier x.base.pre) (seen : Direct.CommitFrontier (observed x.base.pre q))
    (ready : Direct.CommitFrontier (prepared x.base.pre q))
    (current : ¬ q.term < (prepared x.base.pre q).currentTerm)
    (matchLog : appendEntryMatchesLog (prepared x.base.pre q) q)
    (safe : (prepared x.base.pre q).commitIndex ≤ q.prevLogIndex)
    (clear : firstTermConflictIndex {prepared x.base.pre q with primaryKnown := true} q = none) :
    Loop c x.base.actor (limit q) := by
  let m := Message.appendEntriesRequest q
  have start : (reach% step_fromLeader_loop_entries_cons[0,0,0,0,0,0]) f t c
      x.base.actor x.base.pre x.event x.base.post x.outputs :=
    ⟨c.post_now, c.post_now, c.post_now,
      fun old => Bool.noConfusion (fresh.symm.trans ((GuardedDomain.View.old_post ok.1).mp old)),
      (X.tr_actor_eq ok).symm, (X.tr_pre_eq ok).symm, (X.tr_event_eq ok).symm,
      (X.tr_post_eq ok).symm, (X.outputs_eq ok).symm⟩
  have recv : (reach% step_fromLeader_loop_entries_cons[0,0,0,0,0]) f t c
      x.base.actor x.base.pre n m :=
    ⟨x.event, x.base.post, x.outputs, start, ev, X.run_for ok ev.symm, initial, X.run_eq ok⟩
  have obs : (reach% step_fromLeader_loop_entries_cons[0,0,0,0]) f t c
      x.base.actor (observed x.base.pre q) q := by
    exact ⟨x.base.pre, n, m, recv, fun h => Bool.noConfusion h.1, rfl,
      fun h => Bool.noConfusion h.1, initial, seen, rfl⟩
  refine ⟨q, ?_, rfl⟩
  left
  refine ⟨_, obs, fun h => h.elim current (· matchLog), ?_, clear, clear, seen, ready, safe⟩
  rintro (below | bad)
  · exact Nat.not_lt_of_ge safe below
  · exact (by simp [clear] at bad)

omit [Config.InitialConfiguration] in
private theorem copyLoop :
    let a := ReceiveCasesB.asSample copyCommit 4 (by decide +kernel) (by decide +kernel)
    @Loop ⟨a.s.cfg⟩ _ _ a.s.context 1 2 := by
  let a := ReceiveCasesB.asSample copyCommit 4 (by decide +kernel) (by decide +kernel)
  letI : Config.InitialConfiguration := ⟨a.s.cfg⟩
  let q := ReceiveCasesB.appendRequest (ReceiveCasesB.msg a.x.event)
  have call := received (x := a.x) (c := a.s.context) a.ok (by decide +kernel) 0 q
    (by decide +kernel) (by unfold Direct.CommitFrontier; decide +kernel)
    (by unfold Direct.CommitFrontier; decide +kernel) (by unfold Direct.CommitFrontier; decide +kernel)
    (by decide +kernel) (by decide +kernel) (by decide +kernel) (by decide +kernel)
  rw [show a.x.base.actor = 1 by decide +kernel, show limit q = 2 by decide +kernel] at call
  exact call

private def sg : Entry := ⟨2, .signature⟩
private def tx : Entry := ⟨2, .transaction 0 {}⟩
private def state (log : List Entry) : NodeState :=
  ⟨.none, 2, log, 0, fun _ => 0, fun _ => 0, false, none, false, ∅, ∅, none⟩

-- A one-element induction step followed by an empty tail. After choosing
-- the head and starting state, the repeated witnesses are uniquely fixed
-- by the record and fold equalities.
local macro "fold_facts " index:term:arg : tactic => `(tactic|
  repeat' first
    | rfl
    | exact Or.inl rfl
    | exact Or.inr rfl
    | exact Nat.le_refl _
    | exact Nat.le_max_left _ _
    | exact Nat.zero_le _
    | (apply And.intro)
    | (refine Exists.intro (none : Option Nat) ?_)
    | (refine Exists.intro Role.none ?_)
    | (refine Exists.intro false ?_)
    | (refine Exists.intro ($index : Nat) ?_)
    | decide +kernel)

local macro "prefix_pair " base:term:arg index:term:arg seed:ident : tactic => `(tactic|
  (refine ⟨$base ++ [sg], ($base ++ [sg]) ++ [], 2, ?_, List.prefix_append _ [], rfl, rfl⟩
   refine ⟨1, $seed, sg, [], Ledger.fromLeader_loop 1 2 [], state $base, rfl, ?_⟩
   fold_facts $index))

private theorem positivePair (seed : Loop c 1 2) :
    (reach% step_maxCommittableIndex_le_of_prefix_zero_neg[0]) f t c [sg, sg] [sg, sg] := by
  prefix_pair [sg] 2 seed

private theorem zeroPair (seed : Loop c 1 2) :
    (reach% step_maxCommittableIndex_le_of_prefix_zero_pos[0]) f t c [tx, tx] [tx, tx] := by
  prefix_pair [tx, tx] 0 seed

public def questions : List Classes.StepBranch :=
  [.maxCommittableIndex_le_of_prefix_zero_neg, .maxCommittableIndex_le_of_prefix_zero_pos,
   .maxCommittableIndexPositiveIsSignature_values_nil, .maxCommittableIndexPositiveIsSignature_values_cons,
   .maxCommittableIndexPositiveIsSignature_headValid_pos, .maxCommittableIndexPositiveIsSignature_headValid_neg,
   .maxCommittableIndexPositiveIsSignature_bestValid_inl, .maxCommittableIndexPositiveIsSignature_bestValid_inr,
   .maxCommittableIndexPositiveIsSignature_bestLeHead_pos, .maxCommittableIndexPositiveIsSignature_bestLeHead_neg]

private theorem casesOf {b : Classes.StepBranch} (mem : b ∈ questions) (seed : Loop c 1 2) : sig c b := by
  let log := [sg, sg]
  have pair := positivePair seed
  have pos : 0 < maxCommittableIndex log := by decide +kernel
  have nz := Nat.ne_of_gt pos
  have pre : log <+: log := List.prefix_refl _
  have call : (reach% step_maxCommittableIndexPositiveIsSignature_values_cons[0]) f t c log :=
    Or.inr ⟨_, pair, nz, pre, pos⟩
  simp only [questions, List.mem_cons, List.not_mem_nil, or_false] at mem
  rcases mem with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl
  all_goals left
  · exact ⟨_, _, pair, nz, pre⟩
  · exact ⟨_, _, zeroPair seed, rfl, List.prefix_refl _⟩
  · exact Or.inr ⟨_, _, pair, nz, pre, pos⟩
  · exact ⟨_, call, [], fun _ h => h, pos⟩
  · exact ⟨_, call, 1, [], fun _ h => h, 0, .inl rfl, rfl, pos⟩
  · exact ⟨_, call, 0, [], fun _ h => h, 0, .inl rfl, by decide +kernel, pos⟩
  · exact ⟨_, call, 1, [], fun _ h => h, .inl trivial, rfl, pos⟩
  · exact ⟨_, call, 1, [], fun _ h => h, 1, .inr rfl, rfl, rfl, pos⟩
  · exact ⟨_, call, 1, [], fun _ h => h, 1, .inr rfl, rfl, rfl, Nat.le_refl _, pos⟩
  · exact ⟨_, call, 1, [], fun _ h => h, 2, .inr rfl, rfl, rfl, by decide +kernel, pos⟩

omit [Config.InitialConfiguration] in
public theorem occurs {b : Classes.StepBranch} (mem : b ∈ questions) :
    ∃ s : Step, label s (.step b) = true := by
  let a := ReceiveCasesB.asSample copyCommit 4 (by decide +kernel) (by decide +kernel)
  letI : Config.InitialConfiguration := ⟨a.s.cfg⟩
  exact ⟨a.s, (label_true a.s _).mpr ((sig_iff a.s.context _).mpr (casesOf mem copyLoop))⟩

end

end ConsensusCoverage.FollowerFoldCasesB
