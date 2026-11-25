module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersABase
import all ConsensusCoverage.DeepEffectCases
import all ConsensusCoverage.LeaderEffect
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersA.Append

open CCF Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety SolvedWitnesses ActionProfile

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

def reader : Reader := fun _ _ act _ _ => match act with
  | .local _ (.append _) => true
  | _ => false

inductive Branch where | none | some | cons

def column : Branch → Classes.StepBranch
  | .none => .appendEntry_configuration_none
  | .some => .appendEntry_configuration_some
  | .cons => .foldlM__items_cons

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)

private abbrev Local (i : Input) := (reach% step_appendEntry_configuration_none[0,0]) f t c i
private abbrev Content (v : EntryContent) := (reach% step_appendEntry_configuration_none[0]) f t c v
private abbrev Appends := ∃ es, c.event = .internal (.append es)

private theorem local_event {i} (h : Local c i) : c.event = .internal i := by
  obtain ⟨_,_,e,_,_,⟨_,_,_,_,_,_,pin,_,_⟩,ev,_⟩ := h
  exact pin.symm.trans ev

private theorem origin {es} (ev : c.event = .internal (.append es)) : Local c (.append es) := by
  have ran : (step (Capabilities.record c.actor) c.actor c.pre (.internal (.append es))).run {} =
      some (c.post,c.tr.outputs) := ev ▸ c.tr.ran
  obtain ⟨_,_,grow⟩ := LeaderEffect.appendBatch_grows c.actor c.pre es _ _ _ ran
  have fresh : ¬Now f c.actor c.post := fun h =>
    (Nat.lt_irrefl _) ((c.now_pre h) ▸ grow)
  exact ⟨_,_,c.event,_,_,⟨c.post_now,c.post_now,c.post_now,fresh,rfl,rfl,rfl,rfl,rfl⟩,
    ev,ran,c.inv.frontier _ _ c.pre_now,c.tr.ran⟩

private theorem content_iff (v : EntryContent) : Content c v ↔ Appends c := by
  constructor
  · rintro ⟨i,h,es,rfl,_⟩; exact ⟨es,local_event c h⟩
  · rintro ⟨es,ev⟩
    exact ⟨_,origin c ev,es,rfl,rfl,⟨v,[]⟩,rfl⟩

private theorem cons_iff : step_foldlM__items_cons f t c ↔ Appends c := by
  constructor
  · rintro ⟨_,_,(⟨_,_,_,⟨_,e,_,_,⟨_,_,_,_,_,_,p,_,_⟩,ev,_⟩,es,rfl,_⟩ |
        ⟨_,_,_,⟨_,e,_,_,⟨_,_,_,_,_,_,p,_,_⟩,ev,_⟩,es,rfl,_⟩),_⟩ <;> exact ⟨es,p.symm.trans ev⟩
  · rintro ⟨es,ev⟩
    exact DeepEffectCases.flushCons c ⟨_,origin c ev,es,rfl⟩

private theorem iff_append (k : Branch) : sig c (column k) ↔ Appends c := by
  cases k
  case cons => exact cons_iff c
  all_goals
    constructor
    · rintro (⟨_,p,_⟩ | ⟨_,p,_⟩ | ⟨_,p,_⟩ | ⟨_,p,_⟩) <;> exact (content_iff c _).mp p
    · intro h
      first
      | exact Or.inr (Or.inl ⟨.signature,(content_iff c _).mpr h,rfl,by decide,rfl⟩)
      | exact Or.inr (Or.inr (Or.inr ⟨.transaction 0 {configuration := some ∅},
          (content_iff c _).mpr h,by decide,by decide,∅,rfl⟩))
end

def exactReader (k : Branch) : Exact (column k) where
  eval := reader
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    apply Bool.eq_iff_iff.mpr
    rw [label_true, show holds s (.step (column k)) ↔ sig s.context (column k) from sig_iff _ _, iff_append]
    rw [← (s.context_eq s.context).mpr rfl]
    change (∃ es, s.context.tr.event = .internal (.append es)) ↔
      reader _ _ (ActionContext.encode s.context.tr.actor s.context.tr.event) _ _ = true
    cases s.context.tr.event with
    | receive => simp [ActionContext.encode,reader]
    | internal i => cases i <;> simp [ActionContext.encode,reader]

end ConsensusCoverage.HandReadersA.Append
