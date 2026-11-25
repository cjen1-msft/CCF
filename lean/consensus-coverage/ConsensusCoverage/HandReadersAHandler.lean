module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersABase
import all ConsensusCoverage.HandReadersAObserve
import all ConsensusCoverage.DeepHandlerCases
import all ConsensusCoverage.GuardedDomain
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersA.Handler

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety SolvedWitnesses ActionProfile

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxRecDepth 8192

open DeepHandlerCases (current conflict)

inductive Branch where | down | stay | clear | conflict

def column : Branch → Classes.StepBranch
  | .down => .handleAppendEntriesRequest_stepDown_pos
  | .stay => .handleAppendEntriesRequest_stepDown_neg
  | .clear => .handleAppendEntriesRequest_conflict_none
  | .conflict => .handleAppendEntriesRequest_conflict_some

def test (k : Branch) (observed : NodeState) (r : AppendEntriesRequest) : Bool :=
  let st := current observed r
  let down := r.term = observed.currentTerm ∧ (observed.role = .candidate ∨ observed.role = .preVoteCandidate)
  let reject := r.term < st.currentTerm ∨ ¬appendEntryMatchesLog st r
  let noPrefix := r.term < st.currentTerm ∨ termAt st.log r.prevLogIndex = 0
  match k with
  | .down => decide (down ∨ reject ∧ noPrefix)
  | .stay => decide (¬down ∨ reject ∧ ¬noPrefix)
  | .clear | .conflict =>
    let overlap := conflict observed r
    let rollback := r.prevLogIndex < st.commitIndex ∨ (overlap.isSome ∧ !st.isNewFollower)
    decide (¬reject ∧ ¬rollback) && (overlap.isSome == (match k with | .conflict => true | _ => false))

def reader (k : Branch) : Reader := fun cfg before act after past =>
  match ReadersAtoms.eventOf act with
  | .receive _ (.appendEntriesRequest r) =>
    (GuardedDomain.ofAction cfg before after past act).any fun v =>
      v.changed && test k (observeTerm v.pre (.appendEntriesRequest r)) r
  | _ => false

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)

private abbrev Call (st : NodeState) (r : AppendEntriesRequest) :=
  (reach% step_handleAppendEntriesRequest_conflict_none[0]) f t c st r

private theorem call_iff {st r} : Call c st r ↔ ¬ Now f c.actor c.post ∧
    (∃ n, c.event = .receive n (.appendEntriesRequest r)) ∧ st = observeTerm c.pre (.appendEntriesRequest r) := by
  constructor
  · rintro ⟨a,pre,n,m,src,_,rfl,_,_,_,rfl⟩
    obtain ⟨fresh,rfl,rfl,ev⟩ := (Observe.receive_iff c).mp src
    exact ⟨fresh,⟨n,ev⟩,rfl⟩
  · rintro ⟨fresh,⟨n,ev⟩,rfl⟩
    have fr := c.inv.frontier _ _ c.pre_now
    exact ⟨_,_,n,_,(Observe.receive_iff c).mpr ⟨fresh,rfl,rfl,ev⟩,fun h => Bool.noConfusion h.1,
      rfl,fun h => Bool.noConfusion h.1,fr,fr.of_log (Concrete.observeTerm_log _ _) (Concrete.observeTerm_commitIndex _ _),rfl⟩

private theorem pick {n r} (ev : c.event = .receive n (.appendEntriesRequest r))
    (P : NodeState → AppendEntriesRequest → Prop) :
    (∃ st q, Call c st q ∧ P st q) ↔
      ¬ Now f c.actor c.post ∧ P (observeTerm c.pre (.appendEntriesRequest r)) r := by
  constructor
  · rintro ⟨st,q,call,h⟩
    obtain ⟨fresh,⟨_,e⟩,rfl⟩ := (call_iff c).mp call
    cases ev.symm.trans e
    exact ⟨fresh,h⟩
  · rintro ⟨fresh,h⟩
    exact ⟨_,_,(call_iff c).mpr ⟨fresh,⟨_,ev⟩,rfl⟩,h⟩

private theorem at_request {n r} (ev : c.event = .receive n (.appendEntriesRequest r)) (k : Branch) :
    sig c (column k) ↔ ¬Now f c.actor c.post ∧ test k (observeTerm c.pre (.appendEntriesRequest r)) r = true := by
  let observed := observeTerm c.pre (.appendEntriesRequest r)
  let cur := current observed r
  let ci := conflict observed r
  have fr : Direct.CommitFrontier observed := (c.inv.frontier _ _ c.pre_now).of_log
    (Concrete.observeTerm_log _ _) (Concrete.observeTerm_commitIndex _ _)
  have fc : Direct.CommitFrontier cur := by
    unfold cur current; split <;> first | exact fr | exact fr.of_log rfl rfl
  have bound (i : Nat) (h : ci = some i) : r.prevLogIndex + 1 ≤ i :=
    Ledger.firstTermConflictIndex_ge h
  cases k
  all_goals first
    | change step_handleAppendEntriesRequest_stepDown_pos f t c ↔ _; unfold step_handleAppendEntriesRequest_stepDown_pos
    | change step_handleAppendEntriesRequest_stepDown_neg f t c ↔ _; unfold step_handleAppendEntriesRequest_stepDown_neg
    | change step_handleAppendEntriesRequest_conflict_none f t c ↔ _; unfold step_handleAppendEntriesRequest_conflict_none
    | change step_handleAppendEntriesRequest_conflict_some f t c ↔ _; unfold step_handleAppendEntriesRequest_conflict_some
  all_goals
    simp only [pick c ev, test, Bool.and_eq_true, beq_iff_eq, decide_eq_true_eq]
    change Direct.CommitFrontier (observeTerm c.pre (.appendEntriesRequest r)) at fr
    dsimp only [ci,cur,observed,conflict,current] at bound fc ⊢
    cases eq : conflict observed r with
    | none => dsimp only [ci,observed,conflict,current] at eq; simp only [eq, Option.isSome_none] at *; grind (splits := 12)
    | some i =>
      have le := bound i eq
      dsimp only [ci,observed,conflict,current] at eq
      simp only [eq, Option.isSome_some] at *
      grind (splits := 12)

private theorem requires_request (k : Branch) (h : sig c (column k)) :
    ∃ n r, c.event = .receive n (.appendEntriesRequest r) := by
  have wanted {st r} (p : Call c st r) : ∃ n r, c.event = .receive n (.appendEntriesRequest r) :=
    let ⟨n,ev⟩ := ((call_iff c).mp p).2.1
    ⟨n,r,ev⟩
  cases k
  case down | stay => rcases h with h | h | h | h | h | h <;> obtain ⟨_,_,p,_⟩ := h <;> exact wanted p
  case clear | conflict => obtain ⟨_,_,p,_⟩ := h; exact wanted p
end

def exactReader (k : Branch) : Exact (column k) where
  eval := reader k
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    obtain ⟨v,made,ok⟩ := GuardedDomain.ofAction_matches s
    have ev : ReadersAtoms.eventOf s.act = s.context.event := by
      rw [← (s.context_eq s.context).mpr rfl]
      change ReadersAtoms.eventOf (ActionContext.encode _ s.context.tr.event) = s.context.tr.event
      cases s.context.tr.event <;> rfl
    apply Bool.eq_iff_iff.mpr
    rw [label_true, show holds s (.step (column k)) ↔ sig s.context (column k) from sig_iff _ _,reader,ev]
    by_cases req : ∃ n r, s.context.event = .receive n (.appendEntriesRequest r)
    · obtain ⟨n,r,e⟩ := req
      rw [at_request s.context e, e, made]
      simp only [Option.any_some, Bool.and_eq_true,
        GuardedDomain.View.old_post ok, Bool.not_eq_false, GuardedDomain.View.pre_eq ok]
    · have no := mt (requires_request s.context k) req
      simp only [no, false_iff, Bool.not_eq_true]
      split
      · exact (req ⟨_,_,by assumption⟩).elim
      · rfl

end ConsensusCoverage.HandReadersA.Handler
