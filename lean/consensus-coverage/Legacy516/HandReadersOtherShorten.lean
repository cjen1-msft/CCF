module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersABase
import all ConsensusCoverage.Readers
import all ConsensusCoverage.CommitKeys
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersOther.Shorten

open Consensus Model Model.Node Proofs Safety ActionProfile HandReadersA SolvedWitnesses
set_option maxRecDepth 8192
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

def test (zero : Bool) (keys : List (Nat × List Entry)) (j k : Nat) : Bool :=
  if zero then j == 0 else j != 0 || keys.any fun p => decide (p.1 ≤ k)

private def selected (zero : Bool) (keys : List (Nat × List Entry)) (_ : NodeID)
    (pre : NodeState) (ev : Event) (post : NodeState) :=
  match ev with
  | .receive _ (.appendEntriesRequest q) =>
    let i := maxCommittableIndexUpTo post.log (min q.primaryCommit (q.prevLogIndex + q.entries.length))
    decide (pre.commitIndex ≤ i) && test zero keys q.primaryCommit q.term
  | _ => false

def reader (zero : Bool) : Reader := fun cfg before act after past =>
  let e := Readers.read cfg before act after past
  let keys := fun h => CommitKeys.keys (cfg.min?.getD 0) h
  ((Readers.read? e .commit_backed_kind_accept).getD false &&
    actorRead (selected zero (keys (before :: past))) cfg before act after past) ||
  ((Readers.read? e .new_message_h_appendEntriesRequest).getD false &&
    actorRead (fun _ _ _ post => test zero (keys (after :: before :: past)) post.commitIndex post.currentTerm)
      cfg before act after past)

private def column (zero : Bool) : Classes.StepBranch := if zero then .shorten_backed_inl else .shorten_backed_inr

abbrev Guard (zero : Bool) (f : Frame) (j k : Nat) :=
  if zero then j = 0 else j ≠ 0 ∨ ∃ e p, Committed f e p ∧ e ≤ k

abbrev Strong (f : Frame) (l : List Entry) (j k : Nat) :=
  ∃ e p, Committed f e p ∧ e ≤ k ∧ l.take j <+: p

theorem guard_iff {f l j k} (b : Backed f l j k) :
    Guard false f j k ↔ Strong f l j k := by
  constructor
  · rintro (ne | ⟨e,p,mem,le⟩)
    · exact b.resolve_left ne
    · by_cases z : j = 0
      · exact ⟨e,p,mem,le,by simp [z]⟩
      · exact b.resolve_left z
  · rintro ⟨e,p,mem,le,_⟩; exact .inr ⟨e,p,mem,le⟩

theorem test_iff {keys : List (Nat × List Entry)} {f : Frame}
    (exactKeys : ∀ k l, (k,l) ∈ keys ↔ Committed f k l) (zero : Bool) (j k : Nat) :
    test zero keys j k = true ↔ Guard zero f j k := by
  cases zero <;> simp [test,Guard,List.any_eq_true,Prod.exists,exactKeys]

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)

abbrev Recv (n : NodeID) (r : AppendEntriesRequest) :=
  (reach% step_shorten_backed_inl[0,0]) f t c c n r ∨ (reach% step_shorten_backed_inl[1,0]) f t c c n r
abbrev Limit (r : AppendEntriesRequest) := maxCommittableIndexUpTo c.post.log
  (min r.primaryCommit (r.prevLogIndex + r.entries.length))

theorem recv_iff {n r} : Recv c n r ↔ step_commit_backed_kind_accept f t c ∧
    c.event = .receive n (.appendEntriesRequest r) := by
  constructor
  · rintro (⟨rt,a,b,ev,acc,eq,now,h,_⟩ | ⟨rt,a,b,ev,acc,eq,now,h,_⟩)
    all_goals exact ⟨by first | exact .inl ⟨rt,a,b,n,r,ev,acc,eq,now,h⟩
                              | exact .inr ⟨rt,a,b,n,r,ev,acc,eq,now,h⟩,ev⟩
  · rintro ⟨(⟨rt,a,b,src,q,ev,acc,eq,now,h⟩ | ⟨rt,a,b,src,q,ev,acc,eq,now,h⟩),ev'⟩
    all_goals
      cases ev.symm.trans ev'
      first | exact .inl ⟨rt,a,b,ev,acc,eq,now,h,rfl⟩ | exact .inr ⟨rt,a,b,ev,acc,eq,now,h,rfl⟩

abbrev Incoming (g : Frame) (l : List Entry) (i j k : Nat) :=
  (reach% step_shorten_backed_inl[0]) f t c g l i j k ∨
  (reach% step_shorten_backed_inl[1]) f t c g l i j k

theorem incoming_of {n r} (src : Recv c n r) (choose : c.pre.commitIndex ≤ Limit c r) :
    ∃ l, Incoming c f l (Limit c r) r.primaryCommit r.term ∧ Backed f l r.primaryCommit r.term ∧
      Limit c r ≤ r.primaryCommit := by
  have ev := ((recv_iff c).mp src).2
  have acc : Accepted c.pre r c.post := by rcases src with h | h <;> exact h.2.2.2.choose_spec.choose
  obtain ⟨l,sh⟩ := c.accept_shape ev acc
  have le := Safety.maxCommittableIndexUpTo_le c.post.log (min r.primaryCommit (r.prevLogIndex + r.entries.length))
  refine ⟨l,?_,sh.1.backed,Nat.le_trans le (Nat.min_le_left _ _)⟩
  rcases src with h | h
  case' inl => left
  case' inr => right
  all_goals exact ⟨n,r,h,sh,sh.1,sh.2,sh.2.1,sh.2.2,sh.2.2.1,sh.2.2.2,sh.2.2.2.1,sh.2.2.2.2,
    acc.1,acc.2,acc.2.1,acc.2.2,acc.2.2.1,acc.2.2.2,acc.2.2.2.1,acc.2.2.2.2,acc.2.2.2.2.1,
    acc.2.2.2.2.2,acc.2.2.2.2.2.1,acc.2.2.2.2.2.2,Nat.max_eq_right choose,ev,acc,le,rfl,rfl,rfl,rfl⟩

local macro "along " h:term : tactic => `(tactic| {
  have tail := $h
  repeat' first | exact tail | exact tail.1 | obtain ⟨_,tail⟩ := tail })

theorem incoming_only {g l i j k} (h : Incoming c g l i j k) :
    ∃ n r, Recv c n r ∧ c.pre.commitIndex ≤ Limit c r ∧ g = f ∧ j = r.primaryCommit ∧ k = r.term := by
  rcases h with ⟨n,r,src,rest⟩ | ⟨n,r,src,rest⟩
  all_goals
    have eq : max c.pre.commitIndex (Limit c r) = Limit c r := by along rest
    exact ⟨n,r,by first | exact .inl src | exact .inr src,eq ▸ Nat.le_max_left ..,by along rest,
      by along rest,by along rest⟩

abbrev Outgoing (g : Frame) (l : List Entry) (i j k : Nat) :=
  (reach% step_shorten_backed_inl[2]) f t c g l i j k

private theorem sent_of (h : step_new_message_h_appendEntriesRequest f t c) :
    ∃ i, Outgoing c (f.advance t) c.post.log i c.post.commitIndex c.post.currentTerm ∧
      Backed (f.advance t) c.post.log c.post.commitIndex c.post.currentTerm ∧ i ≤ c.post.commitIndex := by
  obtain ⟨e,src,own,body,r,pin,_,sent⟩ := h
  have b := body
  rw [pin] at b
  obtain ⟨ae,non,origin⟩ := b
  have led := c.post_led origin
  exact ⟨r.primaryCommit,⟨e,src,own,body,r,pin,pin,ae,⟨non,origin⟩,non,origin,ae.1,ae.2,
    ae.2.1,ae.2.2,ae.2.2.1,ae.2.2.2,ae.2.2.2.1,ae.2.2.2.2,ae.2.2.2.2.1,ae.2.2.2.2.2,
    sent,led,rfl,rfl,rfl,rfl,rfl⟩,(c.commit_backed _ _ c.post_now).2 non led,ae.2.2.2.2.2⟩

private theorem sent_only {g l i j k} (h : Outgoing c g l i j k) :
    step_new_message_h_appendEntriesRequest f t c ∧ g = f.advance t ∧ j = c.post.commitIndex ∧ k = c.post.currentTerm := by
  obtain ⟨e,src,own,body,r,pin,pin',rest⟩ := h
  exact ⟨⟨e,src,own,body,r,pin,pin',by along rest⟩,by along rest,by along rest,by along rest⟩

private abbrev Site (g : Frame) (l : List Entry) (i j k : Nat) := Incoming c g l i j k ∨ Outgoing c g l i j k
private abbrev Ticket (zero : Bool) := ∃ g l i j k, Site c g l i j k ∧ Backed g l j k ∧ i ≤ j ∧ Guard zero g j k

private theorem ticket_iff (zero : Bool) : sig c (column zero) ↔ Ticket c zero := by
  constructor
  · cases zero
    · rintro (h | h | h)
      all_goals
        obtain ⟨g,l,i,j,k,site,strong,rest⟩ := h
        have b : Backed g l j k := by along rest
        exact ⟨g,l,i,j,k,by first | exact .inl (.inl site) | exact .inl (.inr site) | exact .inr site,
          b,by along rest,(guard_iff b).mpr strong⟩
    · rintro (h | h | h)
      all_goals
        obtain ⟨g,l,i,k,site,b,le⟩ := h
        exact ⟨g,l,i,0,k,by first | exact .inl (.inl site) | exact .inl (.inr site) | exact .inr site,b,le,rfl⟩
  · rintro ⟨g,l,i,j,k,site,b,le,cut⟩
    cases zero
    · obtain ⟨e,p,m,bound,sub⟩ := (guard_iff b).mp cut
      have pack := And.intro m (And.intro bound sub)
      rcases site with (h | h) | h
      all_goals
        repeat' first | refine ⟨g,l,i,j,k,h,?_⟩ | (left; refine ⟨g,l,i,j,k,h,?_⟩) | right
        exact ⟨⟨e,p,pack⟩,e,⟨p,pack⟩,p,pack,m,pack.2,bound,sub,b,le⟩
    · change j = 0 at cut; subst j
      rcases site with (h | h) | h
      all_goals repeat' first | exact ⟨g,l,i,k,h,b,le⟩ | exact Or.inl ⟨g,l,i,k,h,b,le⟩ | right

private theorem sites_iff (zero : Bool) : Ticket c zero ↔
    (step_commit_backed_kind_accept f t c ∧ ∃ n r, c.event = .receive n (.appendEntriesRequest r) ∧
      c.pre.commitIndex ≤ Limit c r ∧ Guard zero f r.primaryCommit r.term) ∨
    (step_new_message_h_appendEntriesRequest f t c ∧ Guard zero (f.advance t) c.post.commitIndex c.post.currentTerm) := by
  constructor
  · rintro ⟨_,_,_,_,_,h | h,_,_,g⟩
    · obtain ⟨n,r,src,le,rfl,rfl,rfl⟩ := incoming_only c h
      exact .inl ⟨((recv_iff c).mp src).1,n,r,((recv_iff c).mp src).2,le,g⟩
    · obtain ⟨msg,rfl,rfl,rfl⟩ := sent_only c h; exact .inr ⟨msg,g⟩
  · rintro (⟨a,n,r,ev,le,g⟩ | ⟨msg,g⟩)
    · obtain ⟨l,src,b,k⟩ := incoming_of c ((recv_iff c).mpr ⟨a,ev⟩) le
      exact ⟨_,l,_,_,_,.inl src,b,k,g⟩
    · obtain ⟨i,src,b,k⟩ := sent_of c msg; exact ⟨_,_,i,_,_,.inr src,b,k,g⟩
end

def exactReader (zero : Bool) : Exact (column zero) where
  eval := reader zero
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    let c := s.context
    have pre (k l) : (k,l) ∈ CommitKeys.keys (s.cfg.min?.getD 0) (s.before :: s.past) ↔ Committed s.frame k l :=
      CommitKeys.step_mem s k l
    have post (k l) : (k,l) ∈ CommitKeys.keys (s.cfg.min?.getD 0) (s.after :: s.before :: s.past) ↔
        Committed (s.frame.advance s.after) k l := by
      change _ ↔ (StateCoverage.frame s.after (s.before :: s.past)).logs.committed k l
      rw [StateCoverage.frame_logs]; exact CommitKeys.mem_iff ..
    apply Bool.eq_iff_iff.mpr
    rw [label_true,holds,sig_iff,ticket_iff,sites_iff,reader]
    simp only [Bool.or_eq_true,Bool.and_eq_true,actorRead_at,Readers.read?_at s
      (b := .commit_backed_kind_accept) (by decide +kernel),Readers.read?_at s
      (b := .new_message_h_appendEntriesRequest) (by decide +kernel),Option.getD_some,label_true,holds,sig_iff,test_iff post]
    apply or_congr _ Iff.rfl
    apply and_congr_right; intro _
    cases s.context.event with
    | internal => simp [selected]
    | receive n m => cases m <;> simp [selected,Limit,test_iff pre] <;> grind

end ConsensusCoverage.HandReadersOther.Shorten
