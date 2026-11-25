module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersABase
import all ConsensusCoverage.HandReadersOtherFactsSites
import all ConsensusCoverage.Readers
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersOther.Facts

open Consensus Model Model.Node Proofs Safety ActionProfile HandReadersA SolvedWitnesses

set_option maxRecDepth 8192
set_option maxHeartbeats 1400000
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

private def gates : List Classes.StepBranch :=
  [.commit_backed_kind_append,.commit_backed_kind_ack,.post_log_kind_append,.post_log_kind_ack,
    .keep_log_kind_append,.keep_log_kind_ack,.persist_pre_kind_append,.persist_pre_kind_ack]

def reader (grow : Bool) : Reader := fun cfg before act after past =>
  actorRead (fun _ pre _ post => (pre.role == .primary) &&
    (if grow then decide (pre.commitIndex < post.commitIndex) else pre.commitIndex == post.commitIndex))
    cfg before act after past &&
  (let e := Readers.read cfg before act after past
   gates.any fun b => (Readers.read? e b).getD false)

local macro "place " h:term : tactic => `(tactic| {
  repeat' first | exact $h | exact Or.inl $h | apply Or.inr
  done })

private def column (growth : Bool) : Classes.StepBranch := if growth then .facts_advance_inr else .facts_advance_inl

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)

private theorem exact_iff (growth : Bool) : sig c (column growth) ↔
    (c.pre.role = .primary ∧ (if growth then c.pre.commitIndex < c.post.commitIndex
      else c.pre.commitIndex = c.post.commitIndex)) ∧ Source c := by
  constructor
  · intro h
    cases growth <;> repeat' (change _ ∨ _ at h; rcases h with h | h)
    all_goals first
      | obtain ⟨self,m,co,_⟩ := h
        have site : Sites f t c self m m := by place co
        obtain ⟨i,z,l,live⟩ := decode c site
        exact ⟨⟨l,i.symm.trans (congrArg NodeState.commitIndex z)⟩,live⟩
      | obtain ⟨self,m,z,co,fields,_⟩ := h
        have site : Sites f t c self m z := by place co
        obtain ⟨i,rfl,l,live⟩ := decode c site
        exact ⟨⟨l,i ▸ fields.2.2.2.2.2.2.1⟩,live⟩
  · rintro ⟨⟨_,cut⟩,src⟩
    obtain ⟨m,site,a,i⟩ := encode c src
    cases growth
    · have eq := a.resolve_right fun h => (Nat.ne_of_lt (i ▸ h.2.2.2.2.2.2.1)) cut
      subst m
      rcases site with h | h | h | h | h | h | h | h | h | h | h | h | h | h | h | h
      all_goals place ⟨c.actor,c.post,h,a⟩
    · have gt : m.commitIndex < c.post.commitIndex := i ▸ cut
      have h := a.resolve_left fun eq => (Nat.ne_of_gt gt) (congrArg NodeState.commitIndex eq)
      rcases site with r | r | r | r | r | r | r | r | r | r | r | r | r | r | r | r
      all_goals
        repeat' first | (apply Or.inl; refine ⟨_,_,_,r,h,?_⟩) | refine ⟨_,_,_,r,h,?_⟩ | apply Or.inr
        obtain ⟨_,_,_,_,_,_,_,_,_⟩ := h
        repeat' first | assumption | apply And.intro
end

def exactReader (growth : Bool) : Exact (column growth) where
  eval := reader growth
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    apply Bool.eq_iff_iff.mpr
    rw [label_true,holds,sig_iff,exact_iff,reader,Bool.and_eq_true,actorRead_at]
    apply and_congr
    · cases growth <;> simp
    · simp only [gates,List.any_cons,List.any_nil,Bool.or_false,Bool.or_eq_true,
        Readers.read?_at s (b := .commit_backed_kind_append) (by decide +kernel),
        Readers.read?_at s (b := .commit_backed_kind_ack) (by decide +kernel),
        Readers.read?_at s (b := .post_log_kind_append) (by decide +kernel),
        Readers.read?_at s (b := .post_log_kind_ack) (by decide +kernel),
        Readers.read?_at s (b := .keep_log_kind_append) (by decide +kernel),
        Readers.read?_at s (b := .keep_log_kind_ack) (by decide +kernel),
        Readers.read?_at s (b := .persist_pre_kind_append) (by decide +kernel),
        Readers.read?_at s (b := .persist_pre_kind_ack) (by decide +kernel),Option.getD_some,label_true,holds,sig_iff]
      rfl

end ConsensusCoverage.HandReadersOther.Facts
