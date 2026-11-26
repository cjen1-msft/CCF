module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.CensusBallots
import all ConsensusCoverage.EvidenceSupport
import all ConsensusCoverage.HandReadersASeen
import all ConsensusCoverage.HandReadersElectionTables
import all ConsensusCoverage.InertProfile
import all ConsensusCoverage.Readers
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all ConsensusCoverage.StutterProfile
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersElectionB.Keys

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety
open ActionProfile SolvedWitnesses HandReadersA
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxRecDepth 8192

def reader : Reader := fun cfg s a t hist =>
  SeenRows.reader cfg s a t hist ||
    (!CommitKeys.noNew (cfg.min?.getD 0) t (s :: hist) &&
      (let e := Readers.read cfg s a t hist
       (Readers.read? e .canon_mono_now_after_inl).getD false ||
         (Readers.read? e .canon_mono_now_after_inr).getD false))

local macro "injectRoot " h:term : tactic => `(tactic|
  repeat' first | exact $h | exact Or.inl $h | apply Or.inr)

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)

abbrev Source :=
  (reach% step_canon_mono_now_after_inl[0]) f t c c ∨
  (reach% step_canon_mono_now_after_inl[1]) f t c c ∨
  (reach% step_canon_mono_now_after_inl[2]) f t c c ∨
  (reach% step_canon_mono_now_after_inl[3]) f t c c

abbrev Eligible := ∃ n st, Now (f.advance t) n st ∧ st.role ≠ .candidate ∧ Led (f.advance t) n st.currentTerm
abbrev Gate := ¬ Now f c.actor c.post ∨ Source c ∧ Eligible (f := f) (t := t)

include c in
private theorem current {n st} (now : Now (f.advance t) n st) (nc : st.role ≠ .candidate)
    (led : Led (f.advance t) n st.currentTerm) :
    ∀ n' st', CanonNow (f.advance t) n' st' st.currentTerm → st'.log <+: st.log :=
  fun n' st' cn => (c.canon_mono _ _ now nc led).1 _ (.inr ⟨n',st',cn,rfl⟩)

theorem canon_iff :
    (sig c .canon_mono_now_after_inl ∨ sig c .canon_mono_now_after_inr) ↔
      Source c ∧ Eligible (f := f) (t := t) := by
  constructor
  · rintro (h | h)
    all_goals rcases h with h | h | h | h
    all_goals first
      | obtain ⟨site,now,nc,led,_⟩ := h
        exact ⟨by injectRoot site,_,_,now,nc,led⟩
      | obtain ⟨site,n,st,now,nc,led,_⟩ := h
        exact ⟨by injectRoot site,n,st,now,nc,led⟩
  · rintro ⟨site,n,st,now,nc,led⟩
    have top := current c now nc led
    rcases c.now_after now with ⟨rfl,rfl⟩ | ⟨other,old⟩
    · left
      rcases site with site | site | site | site
      all_goals injectRoot (And.intro site ⟨now,nc,led,top⟩)
    · right
      rcases site with site | site | site | site
      all_goals
        repeat' first | exact ⟨site,n,st,now,nc,led,⟨other,old⟩,other,old,top⟩
                      | exact Or.inl ⟨site,n,st,now,nc,led,⟨other,old⟩,other,old,top⟩ | apply Or.inr

theorem message_change {st} (h : (reach% step_replaceNode_keys_here_pos[7,0,1]) f t c c st) :
    ¬ Now f c.actor c.post := by
  obtain ⟨_,_,_,_,_,_,_,_,_,lt,_⟩ := h
  intro old
  have eq := c.now_pre old
  have bad : c.pre.currentTerm < c.post.currentTerm := lt
  rw [eq] at bad
  exact Nat.lt_irrefl _ bad

theorem observation_change {st} (h : (reach% step_replaceNode_keys_here_pos[12,0,0]) f t c c st) :
    ¬ Now f c.actor c.post := by
  obtain ⟨now,_,_,_,_,delta,_⟩ := h
  intro old
  exact delta ⟨c.now_post now ▸ old,c.inv.observed _ _ old⟩

private theorem fromOld (h : Led f c.actor c.post.currentTerm) :
    c.pre.log <+: c.post.log ∧ CanonMono f ∧ c.pre.currentTerm = c.post.currentTerm ∧
    c.pre.role ≠ .candidate := by
  obtain ⟨eq,nc⟩ := c.old_led_actor h
  exact ⟨c.keep_log eq.symm nc (eq ▸ h),c.inv.canon_mono,eq,nc⟩

theorem sufficient (h : Gate c) : sig c .replaceNode_keys_here_pos := by
  rcases h with change | ⟨site,n,st,now,nc,led⟩
  · have entry : (reach% step_replaceNode_keys_here_pos[12]) f t c c.actor :=
      ⟨⟨c.post,⟨c.post_now,c.post_seen,c.post_now,c.post_seen,c.post_seen,fun old => change old.1,rfl⟩,
        c.post_now,rfl⟩,rfl⟩
    iterate 12 right
    exact ⟨_,entry,(c.actor,c.post),rfl⟩
  · have cn : CanonNow (f.advance t) n st st.currentTerm := ⟨now,rfl,nc,led⟩
    have canon : Canon (f.advance t) st.currentTerm st.log := .inr ⟨_,_,cn,rfl⟩
    have top := current c now nc led
    rcases site with site | site | site | site
    all_goals
      first
      | have _ : (reach% step_canon_mono_now_after_inl[0]) f t c c := site
        iterate 3 right
        left
      | have _ : (reach% step_canon_mono_now_after_inl[1]) f t c c := site
        iterate 4 right
        left
      | have _ : (reach% step_canon_mono_now_after_inl[2]) f t c c := site
        left
      | iterate 5 right
        left
    all_goals
      refine ⟨c.actor,⟨.inr ?_,rfl⟩,(c.actor,c.post),rfl⟩
      rcases c.now_after now with ⟨rfl,rfl⟩ | ⟨other,old⟩
      · exact .inl ⟨site,now,nc,led,now,led,nc,top,now,led,_,canon,⟨_,_,cn,rfl⟩,⟨_,cn,rfl⟩,
          _,⟨cn,rfl⟩,cn,rfl,canon,now,rfl,nc,led,now,led,fromOld c,rfl⟩
      · exact .inr ⟨site,n,st,now,nc,led,⟨other,old⟩,other,old,_,canon,⟨_,_,cn,rfl⟩,⟨_,cn,rfl⟩,
          _,⟨cn,rfl⟩,cn,rfl,canon,now,rfl,nc,led,now,led,c.led_other other led,rfl⟩
end

theorem necessary (s : Step) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    sig s.context .replaceNode_keys_here_pos → Gate s.context := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  have bad : ¬ sig c .ballot_step_mem_after_inl := fun yes =>
    Bool.noConfusion (((label_true s (.step .ballot_step_mem_after_inl)).mpr ((sig_iff c _).mpr yes)).symm.trans
      (CensusBallots.label_false s (.inl rfl)))
  intro h
  repeat' (change _ ∨ _ at h; rcases h with h | h)
  all_goals
    obtain ⟨_,⟨parent,_⟩,_⟩ := h
    repeat' (change _ ∨ _ at parent; rcases parent with parent | parent)
  all_goals
    first
    | obtain ⟨root,_⟩ := parent
      exfalso
      apply bad
      repeat' first | exact ⟨⟨root,rfl⟩,c.post_now⟩ | exact Or.inl ⟨⟨root,rfl⟩,c.post_now⟩ | apply Or.inr
      done
    | obtain ⟨site,now,nc,led,_⟩ := parent
      exact .inr ⟨by injectRoot site,_,_,now,nc,led⟩
    | obtain ⟨site,n,st,now,nc,led,_⟩ := parent
      exact .inr ⟨by injectRoot site,n,st,now,nc,led⟩
    | obtain ⟨_,root,_⟩ := parent
      first | exact .inl (message_change c root) | exact .inl (observation_change c root)

theorem reader_iff (s : Step) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    reader s.cfg s.before s.act s.after s.past = true ↔ Gate s.context := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  obtain ⟨v,made,ok⟩ := GuardedDomain.ofAction_matches s
  have canon (b) (mem : b ∈ Readers.covered) :
      (Readers.read? (Readers.read s.cfg s.before s.act s.after s.past) b).getD false = true ↔ sig c b := by
    rw [Readers.read?_at s mem,Option.getD_some,label_true,holds,sig_iff]
  rw [reader,Bool.or_eq_true,Bool.and_eq_true,Bool.or_eq_true,
    canon _ (by decide +kernel),canon _ (by decide +kernel),canon_iff,
    SeenRows.reader,made,Option.any_some,← Bool.not_eq_false,← GuardedDomain.View.old_post ok]
  constructor
  · exact fun h => h.imp_right And.right
  · rintro (changed | enabled)
    · exact .inl changed
    · by_cases changed : ¬ Now s.frame c.actor c.post
      · exact .inl changed
      · have old := Classical.not_not.mp changed
        have same := c.now_pre old
        have nodes : s.after.nodes = s.frame.current.nodes := by
          change c.tr.post = c.tr.pre at same
          rw [c.tr.nodesEq,same]
          exact InertProfile.replace_eq c.inv.distinct c.tr.found
        have eq := StutterProfile.advance_logs_nodes nodes
        have el := (congrArg LogFacts.Ghost.elected eq).trans (StutterProfile.frozenElection s.folded.invariant)
        have ca := (congrArg LogFacts.Ghost.canon eq).trans (StutterProfile.frozenCanon s.folded)
        refine .inr ⟨?_,enabled⟩
        rw [Bool.not_eq_true',← Bool.not_eq_true,CommitKeys.step_noNew]
        intro stale
        have refute (b) (mem : [EvidenceSupport.Family.now,.elected,.canon,.committed] ∈ EvidenceSupport.supports b) :
            ¬ sig c b := by
          intro positive
          apply EvidenceSupport.sig_false c b mem _ ((sig_iff c b).mpr positive)
          intro k hk
          simp only [List.mem_cons,List.not_mem_nil,or_false] at hk
          rcases hk with rfl | rfl | rfl | rfl
          · intro n st m
            change (n,st) ∈ s.after.nodes at m
            rwa [nodes] at m
          · intro n k l i m
            simpa only [Elected,el] using m
          · intro k l m
            simpa only [Canon,ca] using m
          · exact stale
        exact ((canon_iff c).mpr enabled).elim (refute _ (by decide +kernel)) (refute _ (by decide +kernel))

def positive : Exact .replaceNode_keys_here_pos where
  eval := reader
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    apply Bool.eq_iff_iff.mpr
    rw [label_true,holds,sig_iff,reader_iff]
    exact ⟨necessary s,sufficient s.context⟩

def negative : Exact .replaceNode_keys_here_neg where
  eval := reader
  eq_label s := (HandReadersElection.Tables.replace_arms_eq s).symm.trans (positive.eq_label s)

end ConsensusCoverage.HandReadersElectionB.Keys
