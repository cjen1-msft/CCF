module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ClauseLogCluster
import all ConsensusCoverage.ClauseLogCluster
import all ConsensusCoverage.HandReadersAPrimary
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.ClauseLogCluster.Routes

open ActionProfile ClauseQuestions
open Consensus Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety
open SolvedWitnesses

set_option maxRecDepth 16384
set_option maxHeartbeats 0
set_option pp.maxSteps 150

local macro "put " value:term : tactic => `(tactic| {
  first | (left; exact $value) | (right; left; exact $value) |
    (right; right; left; exact $value) | (right; right; right; exact $value) })

local macro "put7 " value:term : tactic => `(tactic| {
  first | (left; exact $value) | (right; left; exact $value) |
    (right; right; left; exact $value) | (right; right; right; left; exact $value) |
    (right; right; right; right; left; exact $value) |
    (right; right; right; right; right; left; exact $value) |
    (right; right; right; right; right; right; exact $value) })

section
variable [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t)

private theorem sorted_prefix (h : step_sorted_post_log_inl f t c) : step_sorted_now_after_inl f t c := by
  rcases h with ⟨g,_⟩ | ⟨g,_⟩ | ⟨g,_⟩ | ⟨g,_⟩
  · exact .inl ⟨g,c.post_now⟩
  · exact .inr (.inl ⟨g,c.post_now⟩)
  · exact .inr (.inr (.inl ⟨g,c.post_now⟩))
  · exact .inr (.inr (.inr ⟨g,c.post_now⟩))

private theorem sorted_append (h : step_sorted_post_log_inr_inl f t c) : step_sorted_now_after_inl f t c := by
  rcases h with ⟨g,_⟩ | ⟨g,_⟩ | ⟨g,_⟩ | ⟨g,_⟩
  · exact .inl ⟨g,c.post_now⟩
  · exact .inr (.inl ⟨g,c.post_now⟩)
  · exact .inr (.inr (.inl ⟨g,c.post_now⟩))
  · exact .inr (.inr (.inr ⟨g,c.post_now⟩))

private theorem sorted_copy (h : step_sorted_post_log_inr_inr f t c) : step_sorted_now_after_inl f t c := by
  rcases h with ⟨g,_⟩ | ⟨g,_⟩ | ⟨g,_⟩ | ⟨g,_⟩
  · exact .inl ⟨g,c.post_now⟩
  · exact .inr (.inl ⟨g,c.post_now⟩)
  · exact .inr (.inr (.inl ⟨g,c.post_now⟩))
  · exact .inr (.inr (.inr ⟨g,c.post_now⟩))

private theorem sorted_peer (h : step_sorted_now_after_inr f t c) : step_sorted_now_after_inl f t c := by
  rcases h with ⟨g,_⟩ | ⟨g,_⟩ | ⟨g,_⟩
  · exact .inr (.inl ⟨g,c.post_now⟩)
  · exact .inr (.inr (.inl ⟨g,c.post_now⟩))
  · exact .inr (.inr (.inr ⟨g,c.post_now⟩))

private abbrev Appends :=
  ∃ es, c.post.log = c.pre.log ++ es ∧ (∀ e ∈ es, e.term = c.pre.currentTerm) ∧
    c.pre.role = .primary ∧ c.post.currentTerm = c.pre.currentTerm ∧ c.post.role ≠ .candidate

private abbrev Copies :=
  ∃ l n, CopyLog f.logs c.post.currentTerm l ∧ n ≤ l.length ∧ c.post.log = l.take n

private theorem sorted_appends_of (h : step_sorted_post_log_inr_inl f t c) : Appends c := by
  rcases h with h | h | h | h
  all_goals exact h.2.2.2.2.2.1

private theorem sorted_copies_of (h : step_sorted_post_log_inr_inr f t c) : Copies c := by
  rcases h with h | h | h | h
  all_goals exact h.2.2.2.2.2.1

private theorem prefix_of (h : step_sorted_post_log_inl f t c) : c.post.log <+: c.pre.log := by
  rcases h with h | h | h | h
  all_goals exact h.2.2.2.2.1

private theorem sorted_of_prefix (h : step_sorted_now_after_inl f t c)
    (pref : c.post.log <+: c.pre.log) : step_sorted_post_log_inl f t c := by
  have now := c.post_now
  have inv := c.inv.terms c.actor c.pre c.pre_now
  rcases h with ⟨g,_⟩ | ⟨g,_⟩ | ⟨g,_⟩ | ⟨g,_⟩
  all_goals put ⟨g,now,now,now,pref,inv⟩

private theorem sorted_of_append (h : step_sorted_now_after_inl f t c) (app : Appends c) :
    step_sorted_post_log_inr_inl f t c := by
  have now := c.post_now
  have inv := c.inv.terms c.actor c.pre c.pre_now
  have original := app
  obtain ⟨entries,log,terms,role,term,nc⟩ := app
  rcases h with ⟨g,_⟩ | ⟨g,_⟩ | ⟨g,_⟩ | ⟨g,_⟩
  all_goals put ⟨g,now,now,now,Or.inl original,original,entries,⟨log,terms,role,term,nc⟩,
    log,⟨terms,role,term,nc⟩,terms,⟨role,term,nc⟩,role,⟨term,nc⟩,term,nc,inv⟩

private theorem sorted_of_copy (h : step_sorted_now_after_inl f t c) (copy : Copies c) :
    step_sorted_post_log_inr_inr f t c := by
  have now := c.post_now
  have inv := c.inv.terms c.actor c.pre c.pre_now
  have original := copy
  obtain ⟨l,n,cp,bound,log⟩ := copy
  have item : ∃ m, CopyLog f.logs c.post.currentTerm l ∧ m ≤ l.length ∧ c.post.log = l.take m :=
    ⟨n,cp,bound,log⟩
  rcases h with ⟨g,_⟩ | ⟨g,_⟩ | ⟨g,_⟩ | ⟨g,_⟩
  all_goals put ⟨g,now,now,now,Or.inr original,original,l,item,n,⟨cp,bound,log⟩,cp,⟨bound,log⟩,bound,log,inv⟩

private theorem sorted_routes (h : step_sorted_now_after_inl f t c) :
    step_sorted_post_log_inl f t c ∨ step_sorted_post_log_inr_inl f t c ∨ step_sorted_post_log_inr_inr f t c := by
  rcases c.post_log with pref | add | copy
  · exact .inl (sorted_of_prefix c h pref)
  · exact .inr (.inl (sorted_of_append c h add))
  · exact .inr (.inr (sorted_of_copy c h copy))

private theorem sorted_prefix_copy (h : step_sorted_post_log_inl f t c) : step_sorted_post_log_inr_inr f t c := by
  have pref := prefix_of c h
  have pre := currentCopyLog c.inv.rooted c.inv.terms c.inv.sorted c.inv.anchor c.actor c.pre c.pre_now
  have cp : CopyLog f.logs c.post.currentTerm c.pre.log :=
    ⟨pre.rooted, fun e mem => Nat.le_trans (pre.terms e mem) c.term_le, pre.sorted, pre.anchor⟩
  exact sorted_of_copy c (sorted_prefix c h)
    ⟨_,_,cp,pref.length_le,List.prefix_iff_eq_take.mp pref⟩

private theorem sorted_append_copy (add : step_sorted_post_log_inr_inl f t c)
    (copy : step_sorted_post_log_inr_inr f t c) : step_sorted_post_log_inl f t c := by
  obtain ⟨entries,log,terms,leader,_,_⟩ := sorted_appends_of c add
  obtain ⟨l,n,cp,bound,eq⟩ := sorted_copies_of c copy
  apply sorted_of_prefix c (sorted_append c add)
  by_cases es : entries = []
  · rw [log, es, List.append_nil]
    exact List.prefix_refl _
  have growth : c.pre.log.length < c.post.log.length := by
    rw [log, List.length_append]
    exact Nat.lt_add_of_pos_right (List.length_pos_iff.mpr es)
  let k := c.post.log.length
  have kpos : k > 0 := Nat.zero_lt_of_lt growth
  have len : k = n := by change c.post.log.length = n; rw [eq, List.length_take_of_le bound]
  have termAtEnd : termAt c.post.log k = c.pre.currentTerm := by
    have fits : k ≤ (c.pre.log ++ entries).length := by
      change c.post.log.length ≤ _
      rw [log]
      exact Nat.le_refl _
    rw [log]
    obtain ⟨e,mem,atEnd⟩ := termAt_append_right growth fits
    exact atEnd.trans (terms e mem)
  obtain ⟨a,canon,within,atK⟩ := cp.anchor k kpos (len ▸ bound)
  have t : termAt l k = c.pre.currentTerm := by
    rw [← termAt_take (n := n) (Nat.le_of_eq len), ← eq]
    exact termAtEnd
  rw [t] at canon
  have old : a <+: c.pre.log :=
    (c.inv.canon_mono _ _ c.pre_now (by rw [leader]; decide) (c.inv.leader_led _ _ c.pre_now leader)).1 _ canon
  exact (Nat.not_le_of_lt growth (Nat.le_trans within old.length_le)).elim

private theorem primary_role (h : step_post_log_role_inl f t c) : c.post.role = .primary := by
  rcases h with h | h | h | h | h | h | h
  all_goals
    obtain ⟨_,_,_,leader,_,_,rest⟩ := h
    exact rest.2.2.2.2.2.trans leader

private theorem none_role (h : step_post_log_role_inr f t c) : c.post.role = .none := by
  rcases h with h | h | h | h | h | h | h
  all_goals
    obtain ⟨_,_,_,_,_,_,rest⟩ := h
    exact rest.2.2.2.2.2

private theorem keep_role_kind (h : step_post_log_role_inl f t c) : step_post_log_kind_append f t c := by
  rcases h with h | h | h | h | h | h | h
  all_goals
    obtain ⟨g,es,sent,leader,terms,advance,rest⟩ := h
    put7 ⟨g,es,sent,leader,terms,advance,rest.1⟩

private theorem none_role_kind (h : step_post_log_role_inr f t c) : step_post_log_kind_append f t c := by
  rcases h with h | h | h | h | h | h | h
  all_goals
    obtain ⟨g,es,sent,leader,terms,advance,rest⟩ := h
    put7 ⟨g,es,sent,leader,terms,advance,rest.1⟩

private theorem append_roles (h : step_post_log_kind_append f t c) :
    step_post_log_role_inl f t c ∨ step_post_log_role_inr f t c := by
  rcases h with h | h | h | h | h | h | h
  all_goals
    obtain ⟨g,es,sent,leader,terms,advance,pin⟩ := h
    have facts := Advance.facts advance
    rcases facts.2.2 with role | role
    · left
      put7 ⟨g,es,sent,leader,terms,advance,pin,facts.1,facts.2,facts.2.1,facts.2.2,role⟩
    · right
      put7 ⟨g,es,sent,leader,terms,advance,pin,facts.1,facts.2,facts.2.1,facts.2.2,role⟩

private theorem equal_kind (h : step_post_log_kind_same f t c) : c.post.log = c.pre.log := by
  rcases h with h | h | h | h | h | h | h
  all_goals
    obtain ⟨_,log,_,_⟩ := h
    exact log

private theorem equal_accept (h : step_post_log_accept_shape_inl f t c) : c.post.log = c.pre.log := by
  rcases h with h | h | h | h | h | h | h
  all_goals
    obtain ⟨_,_,_,_,_,_,_,_,_,_,_,_,_,_,rest⟩ := h
    exact rest.2.2

private theorem changed_accept (h : step_post_log_accept_shape_inr f t c) : c.post.log ≠ c.pre.log := by
  rcases h with h | h | h | h | h | h | h
  all_goals
    obtain ⟨_,_,r,_,_,_,l,_,_,_,_,_,_,_,rest⟩ := h
    intro eq
    apply rest.2.2.2
    let n := r.prevLogIndex + r.entries.length
    calc
      c.pre.log.take n = c.post.log.take n := congrArg (List.take n) eq.symm
      _ = (l.take n).take n := congrArg (List.take n) rest.2.2.1
      _ = l.take n := by rw [List.take_take, Nat.min_self]

private theorem accept_keep_kind (h : step_post_log_accept_shape_inl f t c) :
    step_post_log_kind_accept f t c := by
  rcases h with h | h | h | h | h | h | h
  all_goals
    obtain ⟨g,n,r,e,a,pin,_⟩ := h
    put7 ⟨g,n,r,e,a,pin⟩

private theorem accept_change_kind (h : step_post_log_accept_shape_inr f t c) :
    step_post_log_kind_accept f t c := by
  rcases h with h | h | h | h | h | h | h
  all_goals
    obtain ⟨g,n,r,e,a,pin,_⟩ := h
    put7 ⟨g,n,r,e,a,pin⟩

private theorem accept_routes (h : step_post_log_kind_accept f t c) :
    step_post_log_accept_shape_inl f t c ∨ step_post_log_accept_shape_inr f t c := by
  rcases h with h | h | h | h | h | h | h
  all_goals
    obtain ⟨g,n,r,e,a,pin⟩ := h
    obtain ⟨l,ev,bound,take,shape,prev⟩ := c.accept_shape e a
    rcases shape with same | diff
    · left
      put7 ⟨g,n,r,e,a,pin,l,
        ⟨ev,bound,take,Or.inl same,prev⟩,ev,⟨bound,take,Or.inl same,prev⟩,
        bound,⟨take,Or.inl same,prev⟩,take,⟨Or.inl same,prev⟩,Or.inl same,prev,same⟩
    · right
      put7 ⟨g,n,r,e,a,pin,l,
        ⟨ev,bound,take,Or.inr diff,prev⟩,ev,⟨bound,take,Or.inr diff,prev⟩,
        bound,⟨take,Or.inr diff,prev⟩,take,⟨Or.inr diff,prev⟩,Or.inr diff,prev,diff⟩

private theorem elect_kind (h : step_post_log_kind_elect f t c) : step_facts_advance_inl_2 f t c := by
  apply (HandReadersA.Primary.identity_iff c).mpr
  rcases h with h | h | h | h | h | h | h
  all_goals
    obtain ⟨_,win,_⟩ := h
    exact win

private theorem rooted_append_eq : step_sorted_post_log_inr_inl f t c ↔ step_rooted_post_log_inr_inl f t c := by
  have terms : (∀ (entry : Entry), entry ∈ c.pre.log → entry.term ≤ c.pre.currentTerm) = True :=
    propext (iff_true_intro (c.inv.terms _ _ c.pre_now))
  simp only [step_sorted_post_log_inr_inl, step_rooted_post_log_inr_inl, terms, c.inv.rooted _ _ c.pre_now, and_true]
  rfl

private theorem rooted_copy_eq : step_sorted_post_log_inr_inr f t c ↔ step_rooted_post_log_inr_inr f t c := by
  have terms : (∀ (entry : Entry), entry ∈ c.pre.log → entry.term ≤ c.pre.currentTerm) = True :=
    propext (iff_true_intro (c.inv.terms _ _ c.pre_now))
  simp only [step_sorted_post_log_inr_inr, step_rooted_post_log_inr_inr, terms, c.inv.rooted _ _ c.pre_now, and_true]
  rfl
end

private theorem implies (s : Step) (a b : Classes.StepBranch)
    (rule : letI : Config.InitialConfiguration := ⟨s.cfg⟩
      sig s.context a → sig s.context b) :
    label s (.step a) = true → label s (.step b) = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  have spec (k) := (label_true s (.step k)).trans (sig_iff s.context k)
  exact fun h => (spec b).mpr (rule ((spec a).mp h))

private theorem excludes (s : Step) (a b : Classes.StepBranch)
    (rule : letI : Config.InitialConfiguration := ⟨s.cfg⟩
      sig s.context a → sig s.context b → False) :
    label s (.step a) = true → label s (.step b) = false := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  have spec (k) := (label_true s (.step k)).trans (sig_iff s.context k)
  exact fun h => Bool.eq_false_iff.mpr fun g => rule ((spec a).mp h) ((spec b).mp g)

public def implications : List (Classes.StepBranch × Classes.StepBranch) :=
  [(.sorted_post_log_inl, .sorted_now_after_inl),
   (.sorted_post_log_inr_inl, .sorted_now_after_inl),
   (.sorted_post_log_inr_inr, .sorted_now_after_inl),
   (.sorted_now_after_inr, .sorted_now_after_inl),
   (.rooted_post_log_inl, .rooted_now_after_inl),
   (.rooted_now_after_inr, .rooted_now_after_inl),
   (.post_log_kind_elect, .facts_advance_inl_2)]

public theorem implications_sound (s : Step) {p : Classes.StepBranch × Classes.StepBranch}
    (mem : p ∈ implications) : label s (.step p.1) = true → label s (.step p.2) = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  simp only [implications, List.mem_cons, List.not_mem_nil, or_false] at mem
  rcases mem with rfl | rfl | rfl | rfl | rfl | rfl | rfl
  · exact implies s _ _ (sorted_prefix s.context)
  · exact implies s _ _ (sorted_append s.context)
  · exact implies s _ _ (sorted_copy s.context)
  · exact implies s _ _ (sorted_peer s.context)
  · rw [← same_prefix_branch s, ← same_actor_branch s]
    exact implies s _ _ (sorted_prefix s.context)
  · rw [← same_peer_branch s, ← same_actor_branch s]
    exact implies s _ _ (sorted_peer s.context)
  · exact implies s _ _ (elect_kind s.context)

public def exclusions : List (Classes.StepBranch × Classes.StepBranch) :=
  [(.post_log_role_inl, .post_log_role_inr),
   (.post_log_kind_same, .post_log_accept_shape_inr),
   (.post_log_accept_shape_inl, .post_log_accept_shape_inr)]

public theorem exclusions_sound (s : Step) {p : Classes.StepBranch × Classes.StepBranch}
    (mem : p ∈ exclusions) : label s (.step p.1) = true → label s (.step p.2) = false := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  simp only [exclusions, List.mem_cons, List.not_mem_nil, or_false] at mem
  rcases mem with rfl | rfl | rfl
  · exact excludes s _ _ (fun h g => Role.noConfusion
      ((primary_role s.context h).symm.trans (none_role s.context g)))
  · exact excludes s _ _ (fun h g => changed_accept s.context g (equal_kind s.context h))
  · exact excludes s _ _ (fun h g => changed_accept s.context g (equal_accept s.context h))

public theorem sorted_actor_eq (s : Step) :
    label s (.step .sorted_now_after_inl) =
      (label s (.step .sorted_post_log_inl) ||
       label s (.step .sorted_post_log_inr_inl) ||
       label s (.step .sorted_post_log_inr_inr)) := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  have spec (k) := (label_true s (.step k)).trans (sig_iff s.context k)
  apply Bool.eq_iff_iff.mpr
  simp only [Bool.or_eq_true_iff, spec, or_assoc]
  exact ⟨sorted_routes s.context, fun h =>
    h.elim (sorted_prefix s.context) (fun g => g.elim (sorted_append s.context) (sorted_copy s.context))⟩

public theorem sorted_prefix_is_copy (s : Step) :
    label s (.step .sorted_post_log_inl) = true → label s (.step .sorted_post_log_inr_inr) = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  exact implies s _ _ (sorted_prefix_copy s.context)

public theorem sorted_copy_and_append (s : Step) :
    label s (.step .sorted_post_log_inr_inl) = true →
    label s (.step .sorted_post_log_inr_inr) = true →
    label s (.step .sorted_post_log_inl) = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  have spec (k) := (label_true s (.step k)).trans (sig_iff s.context k)
  exact fun add cp => (spec _).mpr (sorted_append_copy s.context ((spec _).mp add) ((spec _).mp cp))

public theorem accept_eq (s : Step) :
    label s (.step .post_log_kind_accept) =
      (label s (.step .post_log_accept_shape_inl) || label s (.step .post_log_accept_shape_inr)) := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  have spec (k) := (label_true s (.step k)).trans (sig_iff s.context k)
  apply Bool.eq_iff_iff.mpr
  simp only [Bool.or_eq_true_iff, spec]
  exact ⟨accept_routes s.context, fun h => h.elim (accept_keep_kind s.context) (accept_change_kind s.context)⟩

public theorem append_eq (s : Step) :
    label s (.step .post_log_kind_append) =
      (label s (.step .post_log_role_inl) || label s (.step .post_log_role_inr)) := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  have spec (k) := (label_true s (.step k)).trans (sig_iff s.context k)
  apply Bool.eq_iff_iff.mpr
  simp only [Bool.or_eq_true_iff, spec]
  exact ⟨append_roles s.context, fun h => h.elim (keep_role_kind s.context) (none_role_kind s.context)⟩

private def check (c : Clause) (bits : List Bool) (rules : List (Classes.StepBranch × Classes.StepBranch))
    (expected : Bool) : Prop :=
  ∀ p ∈ rules, p.1 ∈ nonTrunk c → p.2 ∈ nonTrunk c →
    bitAt c bits p.1 = true → bitAt c bits p.2 = expected

private instance (c : Clause) (bits : List Bool) (rules : List (Classes.StepBranch × Classes.StepBranch))
    (expected : Bool) : Decidable (check c bits rules expected) := by
  unfold check
  infer_instance

public def sortedColumns : List Classes.StepBranch :=
  [.sorted_now_after_inl, .sorted_post_log_inl, .sorted_post_log_inr_inl, .sorted_post_log_inr_inr,
    .sorted_now_after_inr]

public def rootedColumns : List Classes.StepBranch :=
  [.rooted_now_after_inl, .rooted_post_log_inl, .rooted_post_log_inr_inl, .rooted_post_log_inr_inr,
    .rooted_now_after_inr]

public noncomputable def sortedActorBits (s : Step) : List Bool :=
  sortedColumns.map fun b => label s (.step b)

public def sortedActorPatterns : List (List Bool) :=
  [[false,false,false,false,false], [true,false,false,true,false], [true,false,false,true,true],
   [true,false,true,false,false], [true,false,true,false,true], [true,true,false,true,false],
   [true,true,false,true,true], [true,true,true,true,false], [true,true,true,true,true]]

public theorem sortedActorPatterns_count : sortedActorPatterns.Nodup ∧ sortedActorPatterns.length = 9 :=
  by decide +kernel

public theorem sortedActorBits_complete (s : Step) : sortedActorBits s ∈ sortedActorPatterns := by
  have actor := sorted_actor_eq s
  have pref := sorted_prefix_is_copy s
  have noGrowth := sorted_copy_and_append s
  have peer := implications_sound s (p := (.sorted_now_after_inr, .sorted_now_after_inl)) (by decide)
  have exhaustive : ∀ a b c d e : Bool, a = (b || c || d) →
      (b = true → d = true) → (c = true → d = true → b = true) →
      (e = true → a = true) → [a,b,c,d,e] ∈ sortedActorPatterns := by decide +kernel
  exact exhaustive _ _ _ _ _ actor pref noGrowth peer

public theorem rootedActorBits_eq (s : Step) :
    (rootedColumns.map fun b => label s (.step b)) = sortedActorBits s := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  have spec (k) := (label_true s (.step k)).trans (sig_iff s.context k)
  have app : label s (.step .sorted_post_log_inr_inl) = label s (.step .rooted_post_log_inr_inl) :=
    Bool.eq_iff_iff.mpr ((spec .sorted_post_log_inr_inl).trans
      ((rooted_append_eq s.context).trans (spec .rooted_post_log_inr_inl).symm))
  have cp : label s (.step .sorted_post_log_inr_inr) = label s (.step .rooted_post_log_inr_inr) :=
    Bool.eq_iff_iff.mpr ((spec .sorted_post_log_inr_inr).trans
      ((rooted_copy_eq s.context).trans (spec .rooted_post_log_inr_inr).symm))
  simp only [rootedColumns, sortedActorBits, sortedColumns, List.map_cons, List.map_nil, same_actor_branch s,
    same_prefix_branch s, same_peer_branch s, app, cp]

private def checkActor (qs : List Classes.StepBranch) (c : Clause) (bits : List Bool) : Bool :=
  if qs.all (nonTrunk c).contains then
    sortedActorPatterns.contains (qs.map (bitAt c bits))
  else true

private theorem checkActor_complete (qs : List Classes.StepBranch) (c : Clause) (s : Step)
    (eq : (qs.map fun b => label s (.step b)) = sortedActorBits s) :
    checkActor qs c (nonTrunkLabel c s).bits = true := by
  unfold checkActor
  split
  · rename_i all
    have mem {b : Classes.StepBranch} (hb : b ∈ qs) : b ∈ nonTrunk c :=
      List.contains_iff_mem.mp (List.all_eq_true.mp all b hb)
    have reads := List.map_congr_left fun b hb => bitAt_label (mem hb) s
    rw [reads, eq]
    exact List.contains_iff_mem.mpr (sortedActorBits_complete s)
  · rfl

private def checkMirror (c : Clause) (bits : List Bool) : Bool :=
  if (sortedColumns ++ rootedColumns).all (nonTrunk c).contains then
    sortedColumns.map (bitAt c bits) == rootedColumns.map (bitAt c bits)
  else true

private theorem checkMirror_complete (c : Clause) (s : Step) :
    checkMirror c (nonTrunkLabel c s).bits = true := by
  unfold checkMirror
  split
  · rename_i all
    have mem {b : Classes.StepBranch} (hb : b ∈ sortedColumns ++ rootedColumns) : b ∈ nonTrunk c :=
      List.contains_iff_mem.mp (List.all_eq_true.mp all b hb)
    have sorted := List.map_congr_left fun b hb => bitAt_label (mem (List.mem_append_left _ hb)) s
    have rooted := List.map_congr_left fun b hb => bitAt_label (mem (List.mem_append_right _ hb)) s
    rw [sorted, rooted, rootedActorBits_eq]
    exact beq_self_eq_true _
  · rfl

private def checkSplit (c : Clause) (bits : List Bool) (a b d : Classes.StepBranch) : Bool :=
  if [a,b,d].all (nonTrunk c).contains then
    bitAt c bits a == (bitAt c bits b || bitAt c bits d)
  else true

private theorem checkSplit_complete (c : Clause) (s : Step) (a b d : Classes.StepBranch)
    (eq : label s (.step a) = (label s (.step b) || label s (.step d))) :
    checkSplit c (nonTrunkLabel c s).bits a b d = true := by
  unfold checkSplit
  split
  · rename_i all
    have mem {x : Classes.StepBranch} (hx : x ∈ [a,b,d]) : x ∈ nonTrunk c :=
      List.contains_iff_mem.mp (List.all_eq_true.mp all x hx)
    rw [bitAt_label (mem List.mem_cons_self) s,
      bitAt_label (mem (List.mem_cons_of_mem _ List.mem_cons_self)) s,
      bitAt_label (mem (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ List.mem_cons_self))) s, eq]
    exact beq_self_eq_true _
  · rfl

public def allowed (c : Clause) (bits : List Bool) : Bool :=
  checkActor sortedColumns c bits && checkActor rootedColumns c bits && checkMirror c bits &&
    (checkSplit c bits .post_log_kind_append .post_log_role_inl .post_log_role_inr &&
     checkSplit c bits .post_log_kind_accept .post_log_accept_shape_inl .post_log_accept_shape_inr) &&
    decide (check c bits implications true ∧ check c bits exclusions false)

public theorem allowed_complete {c : Clause} (s : Step) : allowed c (nonTrunkLabel c s).bits = true := by
  apply Bool.and_eq_true_iff.mpr
  constructor
  · simp only [Bool.and_eq_true_iff]
    exact ⟨⟨⟨checkActor_complete sortedColumns c s rfl,
       checkActor_complete rootedColumns c s (rootedActorBits_eq s)⟩, checkMirror_complete c s⟩,
      checkSplit_complete c s _ _ _ (append_eq s), checkSplit_complete c s _ _ _ (accept_eq s)⟩
  · apply decide_eq_true
    refine ⟨?_,?_⟩ <;> intro p mem l r h <;> rw [bitAt_label l s] at h <;> rw [bitAt_label r s]
    · exact implications_sound s mem h
    · exact exclusions_sound s mem h

public def upper (c : Clause) : List RestrictedProfile :=
  (upperRows c).filter (fun r => allowed c r.bits)

public theorem upper_complete {c : Clause} (hc : c ∈ clauses) (s : Step) :
    nonTrunkLabel c s ∈ upper c :=
  List.mem_filter.mpr ⟨upperRows_complete hc s, allowed_complete s⟩

end ConsensusCoverage.ClauseLogCluster.Routes
