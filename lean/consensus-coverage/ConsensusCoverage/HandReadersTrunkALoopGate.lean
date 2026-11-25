module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersTrunkAFactor
import all ConsensusCoverage.HandReadersTrunkARequest
import all ConsensusCoverage.HandReadersAObserve
import all ConsensusCoverage.HandReadersBFactor
import all ConsensusCoverage.AssistConflictA
import all ConsensusCoverage.AssistReplyBranchesA
import all ConsensusCoverage.AssistReplyA
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
public meta import ConsensusCoverage.HandReadersTrunkAFactor

namespace ConsensusCoverage.HandReadersTrunkA.Loop

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety SolvedWitnesses
open HandReadersA ActionProfile AssistReplyA AssistReplyBranchesA AssistConflictA

set_option maxRecDepth 16384
set_option maxHeartbeats 1800000

open Lean Meta Elab Command in
run_cmd liftTermElabM do
  let n := ``step_fromLeader_loop_entries_cons
  let cs := ReachPath.children n.getPrefix (←getConstInfo n).value!
  lambdaTelescope (←getConstInfo cs[0]!).value! fun xs _ => do
    let context := xs.extract 0 4
    let (self,limit) := (xs[4]!,xs[5]!)
    let arms ← cs.mapM fun r => mkLambdaFVars #[limit] (mkAppN (mkConst r) xs) >>= fun l =>
      mkAppM ``Exists #[l] >>= fun v => mkLambdaFVars #[self] v >>= fun s => mkAppM ``Exists #[s]
    for (name,ps) in [(`ConsensusCoverage.HandReadersTrunkA.Loop.SummaryLive,arms.toList.tail!),
        (`ConsensusCoverage.HandReadersTrunkA.Loop.Live,arms.toList)] do
      addDecl (.defnDecl {
        name,levelParams := [],type := ←mkForallFVars context (mkSort .zero)
        value := ←mkLambdaFVars context (Factor.disj ps),hints := .abbrev,safety := .safe })
  Factor.compile `ConsensusCoverage.HandReadersTrunkA.Loop.SummaryLive

private def accepted (_ : NodeID) (pre : NodeState) (q : AppendEntriesRequest) :=
  let z := observed pre q
  decide (q.term = z.currentTerm ∧ appendEntryMatchesLog z q ∧ z.commitIndex ≤ q.prevLogIndex ∧ ¬Bad z q)

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)

private abbrev Good := ∃ src q, c.event = .receive src (.appendEntriesRequest q) ∧ accepted c.actor c.pre q

private theorem observedCall {self z q}
    (h : (reach% step_fromLeader_loop_entries_cons[0,0,0,0]) f t c self z q) :
    ¬Now f c.actor c.post ∧ ∃ src, c.event = .receive src (.appendEntriesRequest q) ∧ z = observed c.pre q := by
  obtain ⟨_,src,_,rcv,_,rfl,_,_,_,rfl⟩ := h
  obtain ⟨fresh,rfl,rfl,ev⟩ := (Observe.receive_iff c).mp rcv
  exact ⟨fresh,src,ev,rfl⟩

omit [Config.InitialConfiguration] in
private theorem acceptsOf {z : NodeState} {q : AppendEntriesRequest} (lo : q.term ≤ z.currentTerm)
    (accept : ¬(q.term < (prepared z q).currentTerm ∨ ¬appendEntryMatchesLog (prepared z q) q))
    (proceed : ¬Bad z q) : q.term = z.currentTerm ∧ appendEntryMatchesLog z q ∧
      z.commitIndex ≤ q.prevLogIndex ∧ ¬Bad z q := by
  have p := fields z q
  refine ⟨Nat.le_antisymm lo (p.term ▸ Nat.le_of_not_lt (not_or.mp accept).1),?_,?_,proceed⟩
  · simpa only [appendEntryMatchesLog,p.log] using Classical.not_not.mp (not_or.mp accept).2
  · rw [← p.commit]
    exact Nat.le_of_not_lt (fun lt => proceed (.inl lt))

private theorem direct {self lim} (h : (reach% step_fromLeader_loop_entries_cons[0]) f t c self lim) :
    HandReadersBGate.Source c ∧ Good c := by
  obtain ⟨q,call,_⟩ := h
  change (reach% step_fromLeader_loop_entries_cons[0,0,0]) f t c self q at call
  rcases call with ⟨z,o,a,p,_⟩ | ⟨z,o,a,p,_⟩
  all_goals
    obtain ⟨fresh,src,ev,rfl⟩ := observedCall c o
    have lo : q.term ≤ (observed c.pre q).currentTerm := by
      obtain raised | stable := observe_bumping c.pre (message := .appendEntriesRequest q) trivial
      · rw [show observed c.pre q = _ from raised.2]; exact Nat.le_refl _
      · rw [show observed c.pre q = _ from stable.2]; exact stable.1
    exact ⟨.node fresh,src,q,ev,decide_eq_true (acceptsOf lo a p)⟩
end

private theorem summaryTail [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t) :
    HandReadersBFactor.Tail.SummaryLive f t c ↔ Good c := by
  constructor
  · rintro (⟨self,_,q,⟨src,z,call,a,p,_⟩,_⟩ | ⟨self,_,q,⟨src,z,call,a,p,_⟩,_⟩ |
      ⟨self,_,q,⟨src,z,call,a,p,_⟩,_⟩ | ⟨self,_,q,⟨src,z,call,a,p,_⟩,_⟩)
    all_goals
      have co : Request.Call f t c self src z q := by first | exact .inl call | exact .inr call
      obtain ⟨rfl,ev,rfl⟩ := (Request.call_iff c _ _ _ _).mp co
      have lo : q.term ≤ (observed c.pre q).currentTerm := by
        obtain raised | stable := observe_bumping c.pre (message := .appendEntriesRequest q) trivial
        · rw [show observed c.pre q = _ from raised.2]; exact Nat.le_refl _
        · rw [show observed c.pre q = _ from stable.2]; exact stable.1
      exact ⟨src,q,ev,decide_eq_true (acceptsOf lo a p)⟩
  · rintro ⟨src,q,ev,yes⟩
    let z := observed c.pre q
    let w := prepared z q
    let v := base z q
    have call := (Request.call_iff c c.actor src z q).mpr ⟨rfl,ev,rfl⟩
    obtain ⟨same,matched,safe,proceed⟩ := of_decide_eq_true yes
    have p := fields z q
    have accept : ¬(q.term < w.currentTerm ∨ ¬appendEntryMatchesLog w q) := by
      rintro (lt | mismatch)
      · exact (Nat.not_lt_of_ge (Nat.le_of_eq (p.term.trans same.symm))) lt
      · exact mismatch (by simpa only [appendEntryMatchesLog,w,p.log] using matched)
    have eq : firstTermConflictIndex v q = conflictIndex z.log q := by
      rw [firstTermConflictIndex_eq]; change conflictIndex w.log q = _; rw [p.log]
    have lo := Nat.le_of_eq same
    cases found : firstTermConflictIndex v q with
    | none =>
      rcases call with call | call
      · left
        exact ⟨c.actor,_,q,⟨src,z,call,accept,proceed,found,found,_,_,rfl,lo,p.term,p.log,p.commit,
          p.vote,p.match_,p.role,p.cand,p.stays,common c.actor src z q,same,p.stays same,matched,safe,eq⟩,rfl⟩
      · right; left
        exact ⟨c.actor,_,q,⟨src,z,call,accept,proceed,found,found,_,_,rfl,lo,p.term,p.log,p.commit,
          p.vote,p.match_,p.role,p.cand,p.stays,common c.actor src z q,same,p.stays same,matched,safe,eq⟩,rfl⟩
    | some i =>
      rcases call with call | call
      · right; right; left
        exact ⟨c.actor,_,q,⟨src,z,call,accept,proceed,i,found,found,_,_,rfl,lo,p.term,p.log,p.commit,
          p.vote,p.match_,p.role,p.cand,p.stays,common c.actor src z q,same,p.stays same,matched,safe,eq⟩,rfl⟩
      · right; right; right
        exact ⟨c.actor,_,q,⟨src,z,call,accept,proceed,i,found,found,_,_,rfl,lo,p.term,p.log,p.commit,
          p.vote,p.match_,p.role,p.cand,p.stays,common c.actor src z q,same,p.stays same,matched,safe,eq⟩,rfl⟩

theorem live_iff (s : Step) : letI : Config.InitialConfiguration := ⟨s.cfg⟩
    Live s.frame s.after s.context ↔ HandReadersBGate.Source s.context ∧ Good s.context := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  change (∃ self lim, (reach% step_fromLeader_loop_entries_cons[0]) _ _ s.context self lim) ∨
    SummaryLive _ _ s.context ↔ _
  rw [Factor.Split.SummaryLive_iff,HandReadersBFactor.Exact.SummaryLive _ _ _ (HandReadersBGate.quiet s),summaryTail]
  exact or_iff_right_of_imp fun ⟨_,_,h⟩ => direct _ h

end ConsensusCoverage.HandReadersTrunkA.Loop
