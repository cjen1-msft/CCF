module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersTrunkDTableBound
import all ConsensusCoverage.HandReadersTrunkDTableSites
import all ConsensusCoverage.HandReadersABase
import all ConsensusCoverage.DeepListCases
import all ConsensusCoverage.GuardedDomain
import all ConsensusCoverage.DelayedNominationArms
import all ConsensusCoverage.CommitKeys
import all ConsensusCoverage.Readers
import all ConsensusCoverage.EvidenceSupport
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all ConsensusCoverage.HandReadersBFactor
import all Consensus.Proofs.SafetyInvariant
public meta import ConsensusCoverage.HandReadersTrunkDTableBound
public meta import ConsensusCoverage.HandReadersBFactor

namespace ConsensusCoverage.HandReadersTrunkD.Table

open Consensus Model Model.Node Proofs Safety ActionProfile SolvedWitnesses HandReadersA EvidenceSupport
set_option maxRecDepth 16384
set_option maxHeartbeats 1400000
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

private def column (actor : Bool) : Classes.StepBranch :=
  if actor then .mem_replaceNode_here_pos else .mem_replaceNode_here_neg

def reader (actor : Bool) : Reader := fun cfg before act after past =>
  let all := (GuardedDomain.ofAction cfg before after past act).any (·.changed) ||
    !CommitKeys.noNew (cfg.min?.getD 0) after (before :: past)
  let e := Readers.read cfg before act after past
  let yes := fun b => (Readers.read? e b).getD false
  if actor then all || yes .commit_backed_now_after_inl || yes .rv_stable_now_after_inl || yes .ballot_step_mem_after_inl
  else (all && before.nodes.any (fun (n,_) => n != GuardedDomain.actionActor act)) ||
    yes .rv_stable_now_after_inr || yes .ballot_step_mem_after_inr

section
variable [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t)

private abbrev AllPairs := ¬Now f c.actor c.post ∨ ¬Stable f t .committed
private abbrev Peer := ∃ n st, Now f n st ∧ n ≠ c.actor
private abbrev Member (n : NodeID) (st : NodeState) := Sites f t c c.actor n c.post st
private abbrev Ticket (pos : Bool) :=
  ∃ n st, Member c n st ∧ Now (f.advance t) n st ∧ (if pos then n = c.actor else n ≠ c.actor)

local macro "place " v:term : tactic => `(tactic| {
  repeat' first | exact $v | exact Or.inl $v | apply Or.inr
  done })

open Lean Meta Elab Tactic in
local elab "at_site " h:ident " yield " v:term : tactic => withMainContext do
  let r := (←inferType (←getFVarFromUserName h.getId)).getAppFn.constName!
  let body ←whnf (←(←getMainGoal).getType)
  let arms := HandReadersBFactor.disjuncts body
  let some i := arms.findIdx? (fun a => a.getUsedConstants.contains r) | throwError "missing matching membership site"
  let pf ←Term.elabTermEnsuringType v arms[i]!
  Term.synthesizeSyntheticMVarsNoPostponing
  (←getMainGoal).assign (←HandReadersBFactor.into body (←instantiateMVars pf) i arms.length)

private theorem present {n st} (ne : n ≠ c.actor) (old : Now f n st) : Now (f.advance t) n st := by
  change (n,st) ∈ t.nodes
  rw [c.tr.nodesEq]; exact List.mem_map.mpr ⟨(n,st),old,by simp [ne]⟩

private theorem ticket_iff (pos : Bool) : sig c (column pos) ↔ Ticket c pos := by
  constructor
  · intro h
    cases pos
    case false =>
      repeat' (change _ ∨ _ at h; rcases h with h | h)
      all_goals
        obtain ⟨u,n,v,st,h,_,_,key,x,_,old,eq,ne,mem⟩ := h
        have site : Sites f t c u n v st := by at_site h yield h
        obtain ⟨rfl,rfl⟩ := pinned f t c u n v st site
        have p : (key,x) = (n,st) := by simpa [ne] using eq
        cases p
        exact ⟨_,_,site,by change (n,st) ∈ t.nodes; rwa [c.tr.nodesEq],ne⟩
    case true =>
      repeat' (change _ ∨ _ at h; rcases h with h | h)
      all_goals
        obtain ⟨u,n,v,st,h,_,_,x,_,_,eq,mem⟩ := h
        have site : Sites f t c u n v st := by at_site h yield h
        obtain ⟨rfl,rfl⟩ := pinned f t c u n v st site
        have p : (c.actor,c.post) = (n,st) := by simpa using eq
        cases p; exact ⟨_,_,site,c.post_now,rfl⟩
  · rintro ⟨n,st,site,now,k⟩
    have mem : (n,st) ∈ Concrete.replaceNode f.current.nodes c.actor c.post := c.tr.nodesEq ▸ now
    cases pos
    case true =>
      change n = c.actor at k; subst n; obtain rfl := c.now_post now
      repeat' (change _ ∨ _ at site; rcases site with site | site)
      all_goals at_site site yield ⟨_,_,_,_,site,(c.actor,c.pre),⟨c.pre_now,by simp⟩,c.pre,⟨c.pre_now,by simp⟩,c.pre_now,by simp,mem⟩
    case false =>
      change n ≠ c.actor at k
      have old := ((c.now_after now).resolve_left fun h => k h.1).2
      have eq : (if (n == c.actor) = true then (c.actor,c.post) else (n,st)) = (n,st) := by simp [k]
      repeat' (change _ ∨ _ at site; rcases site with site | site)
      all_goals at_site site yield ⟨_,_,_,_,site,(n,st),⟨old,eq⟩,n,st,⟨old,eq⟩,old,eq,k,mem⟩

private theorem any_member (a : AllPairs c) {n st} (now : Now (f.advance t) n st) : Member c n st := by
  rcases a with fresh | keys
  · iterate 4 right
    left; exact ⟨t,c.tr,⟨⟨⟨_,_,c.post_now,fresh,rfl⟩,now,rfl⟩,now,rfl,HEq.rfl⟩,now,rfl,rfl⟩
  · have newKey : DelayedNomination.Fresh f t := by
      change ¬∀ k p, Committed (f.advance t) k p → Committed f k p at keys
      apply Classical.byContradiction; intro no
      exact keys fun k l yes => Classical.byContradiction fun ne => no ⟨k,l,yes,ne⟩
    place (DelayedNomination.r1233 (c := c) newKey now)

private abbrev LocalGate (pos : Bool) :=
  if pos then (AllPairs c ∨ step_commit_backed_now_after_inl f t c ∨ step_rv_stable_now_after_inl f t c ∨
    step_ballot_step_mem_after_inl f t c) else
    ((AllPairs c ∧ Peer c) ∨ step_rv_stable_now_after_inr f t c ∨ step_ballot_step_mem_after_inr f t c)

local elab "excluded_site% " co:ident " under " s:term:arg : term => do
  let h ←Lean.Elab.Term.elabTerm co none
  let p ←Lean.Meta.inferType h
  let stable ←Lean.Elab.Term.elabTerm s none
  return Lean.mkAppN (Lean.mkConst (excluded p.getAppFn.constName!)) (p.getAppArgs ++ #[stable,h])

private theorem stable_only (stable : Still f t) (pos : Bool) {n st} (co : Member c n st)
    (now : Now (f.advance t) n st) (k : if pos then n = c.actor else n ≠ c.actor) : LocalGate c pos := by
  rcases residual f t c _ _ _ _ stable co with ⟨u,tr,h,_,_,_⟩ | ⟨u,tr,h,_,_,_⟩
  · obtain ⟨⟨ae,_,_⟩,_,rfl,he⟩ := h
    cases eq_of_heq he
    obtain ⟨rfl,rfl⟩ : n = c.actor ∧ st = c.post := by
      have a := ae; repeat' first | exact a | obtain ⟨_,a⟩ := a
    cases pos
    · exact (k rfl).elim
    · exact .inr (.inl (.inr ⟨ae,now⟩))
  · rcases h with ⟨(⟨_,_,_,p,_⟩ | ⟨_,_,_,p,_⟩ | ⟨term,r,site,_,candidate,stamp,seen,prior,_⟩),_,rfl,he⟩ |
      ⟨ballot,_,rfl,he⟩
    · exact (excluded_site% p under stable).elim
    · exact (excluded_site% p under stable).elim
    · cases eq_of_heq he
      cases pos
      · have old := ((c.now_after now).resolve_left (fun h => k h.1)).2
        exact .inr (.inl ⟨n,term,r,site,st,now,candidate,stamp,⟨k,old⟩,k,old,seen,prior⟩)
      · change n = c.actor at k; subst n; obtain rfl := c.now_post now
        exact .inr (.inr (.inl ⟨term,r,site,now,candidate,stamp,seen,prior⟩))
    · cases eq_of_heq he
      cases pos
      · right; right; place ⟨ballot,n,st,now,k,((c.now_after now).resolve_left fun h => k h.1).2⟩
      · right; right; right; place ⟨ballot,c.post_now⟩

private theorem ballot_site {tr : LocalTransition f.current t} {n st} (now : Now (f.advance t) n st)
    (same : tr = c.tr)
    (h : (reach% step_ballot_step_mem_after_inl[0]) f t c tr ∨
      (reach% step_ballot_step_mem_after_inl[1]) f t c tr ∨ (reach% step_ballot_step_mem_after_inl[2]) f t c tr ∨
      (reach% step_ballot_step_mem_after_inl[3]) f t c tr ∨ (reach% step_ballot_step_mem_after_inl[4]) f t c tr ∨
      (reach% step_ballot_step_mem_after_inl[5]) f t c tr ∨ (reach% step_ballot_step_mem_after_inl[6]) f t c tr ∨
      (reach% step_ballot_step_mem_after_inl[7]) f t c tr ∨ (reach% step_ballot_step_mem_after_inl[8]) f t c tr ∨
      (reach% step_ballot_step_mem_after_inl[9]) f t c tr ∨ (reach% step_ballot_step_mem_after_inl[10]) f t c tr ∨
      (reach% step_ballot_step_mem_after_inl[11]) f t c tr) : Member c n st := by
  subst tr
  repeat' (change _ ∨ _ at h; rcases h with h | h)
  all_goals first
    | place ⟨t,c.tr,Or.inr ⟨h,now,rfl,HEq.rfl⟩,now,rfl,rfl⟩
    | place ⟨t,c.tr,Or.inr (Or.inl ⟨h,now,rfl,HEq.rfl⟩),now,rfl,rfl⟩
    | place ⟨t,c.tr,Or.inr (Or.inr ⟨h,now,rfl,HEq.rfl⟩),now,rfl,rfl⟩
    | place ⟨t,c.tr,⟨h,now,rfl,HEq.rfl⟩,now,rfl,rfl⟩

private theorem sufficient (pos : Bool) (g : LocalGate c pos) : Ticket c pos := by
  cases pos
  case true =>
    refine ⟨c.actor,c.post,?_,c.post_now,rfl⟩
    rcases g with fresh | (⟨old,_⟩ | ⟨packet,_⟩) | ⟨term,r,src,now,role,stamp,seen,prior⟩ | b
    · exact any_member c fresh c.post_now
    · exact any_member c (.inl old.2.1) c.post_now
    · place ⟨t,c.tr,⟨⟨packet,c.post_now,rfl⟩,c.post_now,rfl,HEq.rfl⟩,c.post_now,rfl,rfl⟩
    · place ⟨t,c.tr,Or.inl ⟨Or.inr (.inr ⟨term,r,src,now,role,stamp,seen,prior,rfl⟩),now,rfl,HEq.rfl⟩,now,rfl,rfl⟩
    · apply ballot_site c c.post_now rfl
      repeat' (change _ ∨ _ at b; rcases b with b | b)
      all_goals place b.1
  case false =>
    rcases g with ⟨a,n,st,old,ne⟩ | ⟨n,term,r,src,st,now,role,stamp,_,ne,_,seen,prior⟩ | b
    · have now := present c ne old
      exact ⟨n,st,any_member c a now,now,ne⟩
    · refine ⟨n,st,?_,now,ne⟩
      place ⟨t,c.tr,Or.inl ⟨Or.inr (.inr ⟨term,r,src,now,role,stamp,seen,prior,rfl⟩),now,rfl,HEq.rfl⟩,now,rfl,rfl⟩
    · repeat' (change _ ∨ _ at b; rcases b with b | b)
      all_goals
        obtain ⟨h,n,st,now,ne,_⟩ := b
        exact ⟨n,st,ballot_site c now rfl (by place h),now,ne⟩
end

def exactReader (pos : Bool) : Exact (column pos) where
  eval := reader pos
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    let c := s.context
    have iffG : Ticket c pos ↔ LocalGate c pos := by
      refine ⟨?_,sufficient c pos⟩
      rintro ⟨n,st,co,now,k⟩
      by_cases all : AllPairs c
      · cases pos
        · exact .inl ⟨all,n,st,((c.now_after now).resolve_left fun h => k h.1).2,k⟩
        · exact .inl all
      · exact stable_only c (still s (Classical.byContradiction fun h => all (.inl h))
          (Classical.byContradiction fun h => all (.inr h))) pos co now k
    obtain ⟨v,made,ok⟩ := GuardedDomain.ofAction_matches s
    have actor : GuardedDomain.actionActor s.act = c.actor := by
      rw [←(s.context_eq c).mpr rfl]; exact GuardedDomain.actionActor_eq ..
    have all : AllPairs c ↔ v.changed = true ∨ CommitKeys.noNew (s.cfg.min?.getD 0) s.after (s.before :: s.past) = false := by
      rw [AllPairs,GuardedDomain.View.old_post ok,Bool.not_eq_false,←Bool.not_eq_true,CommitKeys.step_noNew]
      rfl
    have peer : Peer c ↔ s.before.nodes.any (fun (n,_) => n != c.actor) = true := by
      simp only [Peer,List.any_eq_true,Prod.exists,bne_iff_ne]
      change (∃ n st, (n,st) ∈ s.frame.current.nodes ∧ _) ↔ _
      rw [show s.frame.current = s.before from s.current_eq]
    apply Bool.eq_iff_iff.mpr
    rw [label_true,holds,sig_iff,ticket_iff,iffG,reader,made,Option.any_some]
    cases pos <;> simp only [LocalGate,ite_true,ite_false,Bool.false_eq_true,Bool.or_eq_true,Bool.and_eq_true,
      Bool.not_eq_true',←all,actor,←peer,Readers.read?_at s (b := .commit_backed_now_after_inl) (by decide +kernel),
      Readers.read?_at s (b := .rv_stable_now_after_inr) (by decide +kernel),
      Readers.read?_at s (b := .rv_stable_now_after_inl) (by decide +kernel),
      Readers.read?_at s (b := .ballot_step_mem_after_inr) (by decide +kernel),
      Readers.read?_at s (b := .ballot_step_mem_after_inl) (by decide +kernel),Option.getD_some,label_true,holds,sig_iff]
    all_goals change _ ↔ _; simp only [or_assoc]; rfl

end ConsensusCoverage.HandReadersTrunkD.Table
