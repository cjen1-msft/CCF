module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersABase
import all ConsensusCoverage.CanonicalLogs
import all ConsensusCoverage.Readers
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersOther.Prefix

open Consensus Model Model.Node Proofs Safety ActionProfile SolvedWitnesses HandReadersA

set_option maxRecDepth 8192
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

private def available (cfg : FullProfile.Configuration) (h : List State) (k : Nat) :=
  (CanonicalLogs.keys (cfg.min?.getD 0) h).any fun (t,l) => decide (t ≤ k ∧ l ≠ [])

def reader : Reader := fun cfg before act after past =>
  let e := Readers.read cfg before act after past
  (actorRead (fun _ pre _ _ => !pre.log.isEmpty) cfg before act after past &&
    (Readers.read? e .rooted_post_log_inl).getD false) ||
  (actorRead (fun _ _ _ post => available cfg (before :: past) post.currentTerm) cfg before act after past &&
    (Readers.read? e .rooted_post_log_inr_inr).getD false)

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)

private abbrev Root := (reach% step_rooted_post_log_inl[0]) f t c c ∨
  (reach% step_rooted_post_log_inl[1]) f t c c ∨ (reach% step_rooted_post_log_inl[2]) f t c c ∨
  (reach% step_rooted_post_log_inl[3]) f t c c

private abbrev Key := ∃ k l, Canon f k l ∧ k ≤ c.post.currentTerm ∧ l ≠ []

private theorem head_key {l : List Entry} (copy : CopyLog f.logs c.post.currentTerm l) (ne : l ≠ []) :
    Key c := by
  cases l with
  | nil => contradiction
  | cons x xs =>
    obtain ⟨log,can,len,_⟩ := copy.anchor 1 (by decide) (by simp)
    exact ⟨_,log,can,copy.terms x (.head _),by rintro rfl; contradiction⟩

local macro "place " h:term : tactic => `(tactic| {
  repeat' first | exact $h | exact Or.inl $h | apply Or.inr
  done })

private theorem copy_site {l : List Entry} {n} (root : Root c) (copy : CopyLog f.logs c.post.currentTerm l)
    (len : n ≤ l.length) (eq : c.post.log = l.take n) (nonempty : l ≠ []) :
    step_prefix_small_inr f t c := by
  obtain ⟨a,tail,rfl⟩ := List.exists_cons_of_ne_nil nonempty
  have pack := And.intro copy (And.intro len eq)
  have ex : ∃ log i, CopyLog f.logs c.post.currentTerm log ∧ i ≤ log.length ∧ c.post.log = log.take i :=
    ⟨a::tail,n,pack⟩
  have pre := c.inv.rooted _ _ c.pre_now
  rcases root with r | r | r | r
  all_goals
    place ⟨(a::tail).take n,a::tail,Or.inr ⟨n,⟨r,c.post_now,c.post_now,c.post_now,Or.inr ex,ex,
      ⟨n,pack⟩,pack,copy,pack.2,len,eq,pre⟩,copy.rooted,rfl⟩,a,tail,List.prefix_refl _,copy.rooted,List.take_prefix ..⟩

private theorem iff_prefix : step_prefix_small_inr f t c ↔
    (c.pre.log ≠ [] ∧ step_rooted_post_log_inl f t c) ∨
    (Key c ∧ step_rooted_post_log_inr_inr f t c) := by
  constructor
  · rintro (h | h | h | h)
    all_goals
      obtain ⟨sm,lg,call,a,rest,sub,_,_⟩ := h
      have nonempty : lg ≠ [] := by intro nil; rw [nil] at sub; simpa using sub.length_le
      rcases call with ⟨r,x,y,z,pre,rooted,rfl,rfl⟩ | ⟨n,co,_,rfl⟩
      · exact .inl ⟨nonempty,by place ⟨r,x,y,z,pre,rooted⟩⟩
      · obtain ⟨r,x,y,z,alt,ex,nn,pack,copy,tail,len,eq,pre⟩ := co
        exact .inr ⟨head_key c copy nonempty,by place ⟨r,x,y,z,alt,ex,lg,nn,n,pack,copy,tail,len,eq,pre⟩⟩
  · rintro (⟨ne,h⟩ | ⟨key,h⟩)
    · obtain ⟨a,tail,eq⟩ := List.exists_cons_of_ne_nil ne
      have sub : a::tail <+: c.pre.log := eq ▸ List.prefix_refl _
      rcases h with h | h | h | h
      all_goals
        obtain ⟨r,x,y,z,pre,rooted⟩ := h
        place ⟨c.post.log,c.pre.log,Or.inl ⟨r,x,y,z,pre,rooted,rfl,rfl⟩,a,tail,sub,rooted,pre⟩
    · rcases h with h | h | h | h
      all_goals
        obtain ⟨r,_,_,_,_,_,l,_,n,_,copy,_,len,eq,_⟩ := h
        have root : Root c := by place r
        by_cases ne : l = []
        · have empty : c.post.log = [] := by simp [eq,ne]
          obtain ⟨k,log,canon,le,nonempty⟩ := key
          have old := c.inv.copyLog canon
          have weak : CopyLog f.logs c.post.currentTerm log :=
            ⟨old.rooted,fun v m => Nat.le_trans (old.terms v m) le,old.sorted,old.anchor⟩
          exact copy_site c (n := 0) root weak (Nat.zero_le _) empty nonempty
        · exact copy_site c root copy len eq ne
end

def exactReader : Exact .prefix_small_inr where
  eval := reader
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    let c := s.context
    have keys (k l) : (k,l) ∈ CanonicalLogs.keys (s.cfg.min?.getD 0) (s.before :: s.past) ↔
        Canon s.frame k l := by
      change _ ↔ (StateCoverage.frame s.before s.past).logs.canon k l
      rw [StateCoverage.frame_logs,(Historical.logFacts_correct _).canon]
      exact CanonicalLogs.mem_keys _ k l
    apply Bool.eq_iff_iff.mpr
    rw [label_true,holds,sig_iff,show sig c .prefix_small_inr ↔ _ from iff_prefix c]
    simp only [reader,Bool.or_eq_true,Bool.and_eq_true,actorRead_at,Bool.not_eq_true',
      List.isEmpty_eq_false_iff,available,List.any_eq_true,Prod.exists,decide_eq_true_eq,keys,
      Readers.read?_at s (b := .rooted_post_log_inl) (by decide +kernel),
      Readers.read?_at s (b := .rooted_post_log_inr_inr) (by decide +kernel),Option.getD_some,label_true,holds,sig_iff]
    rfl

end ConsensusCoverage.HandReadersOther.Prefix
