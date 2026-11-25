module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersOtherShorten
import all ConsensusCoverage.HandReadersOtherTransferSites
import all ConsensusCoverage.HandReadersOtherWeaken
import all ConsensusCoverage.HandReadersABase
import all ConsensusCoverage.Readers
import all ConsensusCoverage.CommitKeys
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersOther.Transfer

open Consensus Model Model.Node Proofs Safety Ledger ActionProfile HandReadersA SolvedWitnesses

set_option maxRecDepth 8192
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

def reader (zero : Bool) : Reader := fun cfg before act after past =>
  let keys := CommitKeys.keys (cfg.min?.getD 0) (before :: past)
  let atActor := fun p => actorRead p cfg before act after past
  let e := Readers.read cfg before act after past
  let test := Shorten.test zero keys
  let unbounded := fun (i : Nat) => if zero then i == 0 else i != 0 || !keys.isEmpty
  (atActor (fun _ pre _ post => test pre.commitIndex post.currentTerm) &&
    (Weaken.gate false cfg before act after past || Weaken.gate true cfg before act after past)) ||
  (atActor (fun _ pre _ _ => unbounded pre.commitIndex) &&
    ((Readers.read? e .commit_backed_kind_same).getD false || (Readers.read? e .accept_backed_max_eq_or_inl).getD false)) ||
  (atActor (fun _ _ _ post => test post.commitIndex post.currentTerm) &&
    (Readers.read? e .accept_backed_max_eq_or_inr).getD false)

private def column (zero : Bool) : Classes.StepBranch := if zero then .transfer_backed_inl else .transfer_backed_inr

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)

private abbrev Ticket (zero : Bool) := ∃ l l' i k, Site c l l' i k ∧ Backed f l i k ∧
  l'.take i = l.take i ∧ Shorten.Guard zero f i k

private theorem ticket_iff (zero : Bool) : sig c (column zero) ↔ Ticket c zero := by
  constructor
  · cases zero <;> rintro (h | h | h | h)
    all_goals first
      | obtain ⟨l,l',i,k,co,strong,_,_,_,_,_,_,_,_,b,eq⟩ := h
        exact ⟨l,l',i,k,by repeat' first | exact co | exact Or.inl co | apply Or.inr,
          b,eq,(Shorten.guard_iff b).mpr strong⟩
      | obtain ⟨l,l',k,co,b,eq⟩ := h
        exact ⟨l,l',0,k,by repeat' first | exact co | exact Or.inl co | apply Or.inr,b,eq,rfl⟩
  · rintro ⟨l,l',i,k,site,b,eq,g⟩
    cases zero
    case true =>
      change i = 0 at g; subst i
      rcases site with h | h | h | h
      all_goals repeat' first | exact ⟨l,l',k,h,b,eq⟩ | exact Or.inl ⟨l,l',k,h,b,eq⟩ | apply Or.inr
    case false =>
      obtain ⟨e,p,m,bnd,sub⟩ := (Shorten.guard_iff b).mp g
      have pack := And.intro m (And.intro bnd sub)
      rcases site with h | h | h | h
      all_goals
        repeat' first | (left; refine ⟨l,l',i,k,h,?_⟩) | refine ⟨l,l',i,k,h,?_⟩ | apply Or.inr
        exact ⟨⟨e,p,pack⟩,e,⟨p,pack⟩,p,pack,m,pack.2,bnd,sub,b,eq⟩

private abbrev AnyKey (zero : Bool) := if zero then c.pre.commitIndex = 0 else
  c.pre.commitIndex ≠ 0 ∨ ∃ e p, Committed f e p

private theorem iff_guard (zero : Bool) : Ticket c zero ↔
    ((Shorten.Guard zero f c.pre.commitIndex c.post.currentTerm ∧ (Weaken.Gate c false ∨ Weaken.Gate c true)) ∨
    (AnyKey c zero ∧ AnyGate c)) ∨
    (Shorten.Guard zero f c.post.commitIndex c.post.currentTerm ∧ step_accept_backed_max_eq_or_inr f t c) := by
  constructor
  · rintro ⟨_,_,i,k,site,_,_,g⟩
    rcases origin c site with ⟨⟨q,gate⟩,rfl,rfl⟩ | ⟨gate,rfl⟩ | ⟨gate,rfl,rfl⟩
    · exact .inl (.inl ⟨g,by cases q <;> first | exact .inl gate | exact .inr gate⟩)
    · refine .inl (.inr ⟨?_,gate⟩)
      cases zero
      · rcases g with ne | ⟨e,p,m,_⟩; exact .inl ne; exact .inr ⟨e,p,m⟩
      · exact g
    · exact .inr ⟨g,gate⟩
  · rintro ((⟨g,h | h⟩ | ⟨g,h⟩) | ⟨g,h⟩)
    · obtain ⟨site,b,agree⟩ := weakened c (q := false) h; exact ⟨_,_,_,_,site,b,agree,g⟩
    · obtain ⟨site,b,agree⟩ := weakened c (q := true) h; exact ⟨_,_,_,_,site,b,agree,g⟩
    · have witness : ∃ k, Backed f c.pre.log c.pre.commitIndex k ∧ Shorten.Guard zero f c.pre.commitIndex k := by
        obtain ⟨k,b⟩ := (c.inv.commit_backed _ _ c.pre_now).1
        cases zero
        · rcases g with ne | ⟨e,p,key⟩
          · exact ⟨k,b,.inl ne⟩
          · exact ⟨max k e,b.weaken (Nat.le_max_left ..),.inr ⟨e,p,key,Nat.le_max_right ..⟩⟩
        · exact ⟨k,b,g⟩
      obtain ⟨k,b,cut⟩ := witness
      obtain ⟨site,agree⟩ := unbounded c h b
      exact ⟨_,_,_,k,site,b,agree,cut⟩
    · obtain ⟨l,site,b,agree⟩ := later_ready c h
      exact ⟨l,_,_,_,site,b,agree.symm,g⟩
end

def exactReader (zero : Bool) : Exact (column zero) where
  eval := reader zero
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    let keys := CommitKeys.keys (s.cfg.min?.getD 0) (s.before :: s.past)
    have pre (k l) : (k,l) ∈ keys ↔ Committed s.frame k l := CommitKeys.step_mem s k l
    have existsKey : keys ≠ [] ↔ ∃ e p, Committed s.frame e p := by
      constructor
      · intro h; obtain ⟨⟨e,p⟩,mem⟩ := List.exists_mem_of_ne_nil _ h
        exact ⟨e,p,(pre e p).mp mem⟩
      · rintro ⟨e,p,mem⟩; exact List.ne_nil_of_mem ((pre e p).mpr mem)
    apply Bool.eq_iff_iff.mpr
    rw [label_true,holds,sig_iff,ticket_iff,iff_guard,reader]
    simp only [Bool.or_eq_true,Bool.and_eq_true,actorRead_at,Weaken.gate_iff,Readers.read?_at s
      (b := .commit_backed_kind_same) (by decide +kernel),Readers.read?_at s
      (b := .accept_backed_max_eq_or_inl) (by decide +kernel),Readers.read?_at s
      (b := .accept_backed_max_eq_or_inr) (by decide +kernel),Option.getD_some,label_true,holds,sig_iff]
    cases zero <;> simp [Shorten.test_iff pre,AnyKey,AnyGate,keys,←existsKey] <;> rfl

end ConsensusCoverage.HandReadersOther.Transfer
