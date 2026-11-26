module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersAElection
import all ConsensusCoverage.DeepBoundCases
import all ConsensusCoverage.ReadersShapes
import all ConsensusCoverage.ReadersRequestCuts
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.GuardedDomain
import all ConsensusCoverage.ReachPath
public meta import ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
public meta import Lean

namespace ConsensusCoverage.HandReadersElection.Grant

open CCF Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety
open ActionProfile SolvedWitnesses HandReadersA ReadersAtoms ReadersShapes GuardedDomain
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxRecDepth 8192

inductive Kind where | recorded | self | seen

def column : Kind → Classes.StepBranch
  | .recorded => .grantFactsBefore_grant_inr
  | .self => .grantFactsBefore_supported_inl
  | .seen => .grantFactsBefore_supported_inr

def checkSide (k : Kind) (v n : NodeID) (seen : Bool) : Bool :=
  match k with
  | .recorded => v == n || seen
  | .self => v == n
  | .seen => seen

def view (kind : Kind) (x : XView) : Bool :=
  let before := x.base.before :: x.base.past
  let candidates := replayRequests (requestHistory x)
  let elect := electionExact x.base.after x.base.before x.base.past x.base.actor
    x.base.post.currentTerm x.base.pre.log x.base.pre.commitIndex
  let req := LogFacts.requestAt x.base.post.currentTerm x.base.pre.log x.base.pre.commitIndex
  x.base.before.nodes.any fun (v,pre) => x.base.after.nodes.any fun (w,post) =>
    decide (v = w ∧ pre.currentTerm ≤ post.currentTerm) && post.votedFor.any fun n =>
      checkSide kind v n ((observations before n).any (·.currentTerm == post.currentTerm)) &&
        ((elect && decide (n = x.base.actor ∧ post.currentTerm = x.base.post.currentTerm ∧ voteLogUpToDate pre req)) ||
        candidates.any fun r => decide (voteLogUpToDate pre r) && !grantedIn before v n post.currentTerm r)

def reader (kind : Kind) : Reader := fun cfg before act after past =>
  (ofXAction cfg before after past act).any (view kind)

section
variable [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t)

abbrev Election := ElectStep f t c.actor c.post.currentTerm c.pre.log c.pre.commitIndex
abbrev Request := LogFacts.requestAt c.post.currentTerm c.pre.log c.pre.commitIndex
abbrev Route (v n : NodeID) (k : Nat) (r : RequestVoteRequest) :=
  ¬ f.logs.grant v n k r ∨
    Election c ∧ n = c.actor ∧ k = c.post.currentTerm ∧ r = Request c

private abbrev SeenCandidate (n : NodeID) (k : Nat) := ∃ l, f.logs.seen n k l
private def Side (kind : Kind) (v n : NodeID) (k : Nat) : Prop :=
  match kind with
  | .recorded => v = n ∨ SeenCandidate (f := f) n k
  | .self => v = n
  | .seen => SeenCandidate (f := f) n k

abbrev Evidence (kind : Kind) := ∃ v n k r, Route c v n k r ∧ LogFacts.GrantAt f.current t v n k r ∧
  Side (f := f) kind v n k

open Lean Elab Term Meta in
local elab "grantSites% " f:term:arg t:term:arg c:term:arg v:term:arg n:term:arg k:term:arg r:term:arg : term => do
  let root := ``step_grantFactsBefore_grant_inr
  let sites := ReachPath.children root.getPrefix (← getConstInfo root).value!
  let mut arms := #[]
  for site in sites do
    let name := mkIdent site
    arms := arms.push (← elabTerm (← `($name $f $t $c $v $n $k $r)) (some (.sort .zero)))
  return arms.pop.foldr (mkApp2 (mkConst ``Or)) arms.back!

abbrev Sites (v n : NodeID) (k : Nat) (r : RequestVoteRequest) :=
  grantSites% f t c v n k r

local macro "along " h:term : tactic => `(tactic| {
  have spine := $h
  repeat' first | exact spine | exact spine.1
                | change _ ∧ _ at spine; obtain ⟨_,spine⟩ := spine
                | change Exists _ at spine; obtain ⟨_,spine⟩ := spine })

private theorem route_of_site {v n k r} (h : Sites c v n k r) : Route c v n k r := by
  rcases h with h | h | h | h | h | h | h | h | h | h | h
  · exact .inl h.1.2
  all_goals
    apply Or.inr
    repeat' (change _ ∨ _ at h; rcases h with h | h)
  all_goals
    obtain ⟨term,a,b,tail⟩ := h
    let log : List Entry := by first | exact a | exact b
    let idx : Nat := by first | exact b | exact a
    have elect : ElectStep f t n term log idx := by along tail
    have eq : k = term := by along tail
    have req : r = LogFacts.requestAt term log idx := by along tail
    obtain ⟨hn,hl,hi,_,ht,_⟩ := c.electStep elect
    exact ⟨by simpa only [Election,← hn,hl,hi,ht] using elect,hn,eq.trans ht.symm,
      by simpa only [Request,hl,hi,ht] using req⟩

theorem elected_site {v} (elect : Election c)
    (granted : (f.advance t).logs.grant v c.actor c.post.currentTerm (Request c)) :
    (reach% step_grantFactsBefore_grant_inr[1]) f t c v c.actor c.post.currentTerm (Request c) := by
  have parent := DeepBoundCases.entered c elect
  obtain ⟨st,w,pre,post,log,idx,le,terms,term,role,sub,floor,xs,q,grants⟩ := elect
  let ys := insert v xs
  have quorum : hasQuorum (activeConfigurations c.pre.log c.pre.commitIndex) ys :=
    quorum_mono (fun _ m => Finset.mem_insert.mpr (.inr m)) q
  have support : ∀ u ∈ ys, (f.advance t).logs.grant u c.actor c.post.currentTerm (Request c) := by
    intro u h
    obtain rfl | old := Finset.mem_insert.mp h
    · exact granted
    · exact grants u old
  have vote : v ∈ ys := Finset.mem_insert.mpr (.inl rfl)
  left
  refine ⟨_,_,_,parent,st,⟨w,pre,post,log,idx,le,terms,term,role,sub,floor,ys,quorum,support⟩,
    w,?_,pre,?_,post,?_,log,?_,idx,?_,le,?_,terms,?_,term,?_,role,?_,sub,?_,floor,
    ⟨ys,quorum,support⟩,ys,⟨quorum,support⟩,quorum,support,vote,?_,rfl,rfl⟩
  all_goals repeat' first | assumption | exact ⟨ys,quorum,support⟩ | apply And.intro
  exact ⟨st,w,pre,post,log,idx,le,terms,term,role,sub,floor,ys,quorum,support⟩

private theorem necessary (kind : Kind) (h : sig c (column kind)) : Evidence c kind := by
  cases kind
  all_goals repeat' (change _ ∨ _ at h; rcases h with h | h)
  all_goals
    first
    | obtain ⟨v,k,r,site,part,p,_,eq,hit,_⟩ := h
      refine ⟨v,v,k,r,?_,?_,rfl⟩
    | obtain ⟨v,n,k,r,site,part,p,_,eq,hit,tail⟩ := h
      refine ⟨v,n,k,r,?_,?_,?_⟩
    all_goals
      first
      | apply route_of_site c
        repeat' first | exact site | exact Or.inl site | apply Or.inr
      | obtain rfl := Option.some.inj eq; exact hit.1
      | exact hit.2
      | obtain rfl := Option.some.inj eq; along tail

private theorem sufficient (kind : Kind) (h : Evidence c kind) : sig c (column kind) := by
  obtain ⟨v,n,k,r,route,hit,yes⟩ := h
  have sup : v = n ∨ ∃ l, f.logs.seen n k l := by cases kind <;> first | exact yes | exact .inl yes | exact .inr yes
  have g : (f.advance t).logs.grant v n k r := .inr ⟨_,rfl,hit,sup⟩
  have ⟨⟨stamp,rank⟩,_⟩ := c.grantFactsBefore _ _ _ _ g
  have oldRank : VoterRank f.logs f.logs.canon v k k r := fun k l i seen => rank k l i (.inl seen)
  have extend : (⟨v,k,some n⟩ ∈ (f.advance t).votes) → VoterRank f.logs f.logs.canon v k k r →
      VoterRank (f.advance t).logs f.logs.canon v k k r := fun _ _ => rank
  have which : (reach% step_grantFactsBefore_grant_inr[0]) f t c v n k r ∨
      (reach% step_grantFactsBefore_grant_inr[1]) f t c v n k r := by
    obtain fresh | ⟨elect,rfl,rfl,rfl⟩ := route
    · exact .inl ⟨⟨g,fresh⟩,g⟩
    · exact .inr (elected_site c elect g)
  cases kind <;> rcases which with site | site
  all_goals
    first
    | left; first | refine ⟨v,n,k,r,site,?_⟩ | change v = n at yes; subst n; refine ⟨v,k,r,site,?_⟩
    | right; left; first | refine ⟨v,n,k,r,site,?_⟩ | change v = n at yes; subst n; refine ⟨v,k,r,site,?_⟩
    first
    | refine ⟨⟨_,rfl,hit,sup⟩,_,⟨rfl,hit,sup⟩,rfl,⟨hit,sup⟩,hit,sup,?_⟩
    | have yesSelf := Or.inl (b := SeenCandidate (f := f) v k) True.intro
      refine ⟨⟨_,rfl,hit,yesSelf⟩,_,⟨rfl,hit,yesSelf⟩,rfl,⟨hit,yesSelf⟩,hit,yesSelf,?_⟩
    first
    | exact ⟨g,extend⟩
    | refine ⟨rfl,.rfl,hit,?_⟩
      obtain ⟨st,post,m,m',le,eq,vote,up⟩ := hit
      refine ⟨st,⟨post,m,m',le,eq,vote,up⟩,post,⟨m,m',le,eq,vote,up⟩,m,⟨m',le,eq,vote,up⟩,
        m',⟨le,eq,vote,up⟩,le,⟨eq,vote,up⟩,eq,⟨vote,up⟩,vote,up,?_⟩
      first | exact ⟨extend,vote,stamp,g,extend,oldRank,stamp⟩
            | obtain ⟨l,seen⟩ := yes
              exact ⟨⟨l,seen⟩,l,seen,g,extend,oldRank,stamp⟩

private theorem side_iff {x : XView} (ok : x.Matches c) (kind : Kind) (v n k : Nat) :
    checkSide kind v n ((observations (x.base.before :: x.base.past) n).any
      (·.currentTerm == k)) = true ↔ Side (f := f) kind v n k := by
  have seen : (observations (x.base.before :: x.base.past) n).any (·.currentTerm == k) = true ↔
      SeenCandidate (f := f) n k := by
    simp only [List.any_eq_true,beq_iff_eq,SeenCandidate,X.seen_before ok]
    constructor
    · rintro ⟨⟨_,l⟩,mem,rfl⟩
      exact ⟨l,mem⟩
    · rintro ⟨l,mem⟩
      exact ⟨⟨_,l⟩,mem,rfl⟩
  cases kind <;> simp only [checkSide,Side,Bool.or_eq_true,beq_iff_eq,seen]

private theorem fresh_iff {x : XView} (ok : x.Matches c) {v n k : Nat} {pre : NodeState}
    (mem : (v,pre) ∈ f.current.nodes) :
    (replayRequests (requestHistory x)).any (fun r => decide (voteLogUpToDate pre r) &&
      !grantedIn (x.base.before :: x.base.past) v n k r) = true ↔
      ∃ r, voteLogUpToDate pre r ∧ ¬f.logs.grant v n k r := by
  rw [replayRequests_bound (history := requestHistory x) (P := fun r =>
    voteLogUpToDate pre r ∧ ¬f.logs.grant v n k r) (fun r =>
      and_congr (request_vote_before ok ⟨v,mem⟩ r).symm
        (not_congr (request_grant_before ok v n k r).symm))]
  simp only [List.any_eq_true,Bool.and_eq_true,decide_eq_true_eq,Bool.not_eq_true',Bool.eq_false_iff,
    X.grant_before ok]

private theorem view_iff {x : XView} (ok : x.Matches c) (kind : Kind) :
    view kind x = true ↔ Evidence c kind := by
  have elect : Election c ↔ electionExact x.base.after x.base.before x.base.past x.base.actor
      x.base.post.currentTerm x.base.pre.log x.base.pre.commitIndex = true := by
    simp only [Election,X.elect_now ok,View.actor_eq ok.1,View.pre_eq ok.1,View.post_eq ok.1,true_and]
  have req : Request c = LogFacts.requestAt x.base.post.currentTerm x.base.pre.log x.base.pre.commitIndex := by
    simp only [Request,View.post_eq ok.1,View.pre_eq ok.1]
  have before := congrArg (·.nodes) (X.before_eq ok)
  have after := congrArg (·.nodes) (X.after_eq ok)
  simp only [view,List.any_eq_true (p := fun _ : NodeID × NodeState => _),Prod.exists,
    Bool.and_eq_true,decide_eq_true_eq,Option.any_eq_true,Bool.or_eq_true,side_iff c ok,
    ← elect,← req]
  simp only [← before,← after,← View.actor_eq ok.1,← View.post_eq ok.1]
  constructor
  · rintro ⟨v,st,m,_,post,m',⟨rfl,le⟩,n,voted,side,chosen⟩
    rcases chosen with ⟨win,eq,term,up⟩ | fresh
    · exact ⟨v,n,_,_,.inr ⟨win,eq,term,rfl⟩,⟨st,post,m,m',le,rfl,voted,up⟩,side⟩
    · obtain ⟨r,up,old⟩ := (fresh_iff c ok m).mp fresh
      exact ⟨v,n,_,r,.inl old,⟨st,post,m,m',le,rfl,voted,up⟩,side⟩
  · rintro ⟨v,n,k,r,route,⟨st,post,m,m',le,rfl,voted,up⟩,side⟩
    refine ⟨v,st,m,v,post,m',⟨rfl,le⟩,n,voted,side,?_⟩
    rcases route with fresh | ⟨win,eq,term,rfl⟩
    · exact .inr ((fresh_iff c ok m).mpr ⟨r,up,fresh⟩)
    · exact .inl ⟨win,eq,term,up⟩
end

def exactReader (kind : Kind) : Exact (column kind) where
  eval := reader kind
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    obtain ⟨x,made,ok⟩ := ofXAction_matches s
    apply Bool.eq_iff_iff.mpr
    rw [reader,made,Option.any_some,view_iff s.context ok,label_true,holds,sig_iff]
    exact ⟨necessary s.context kind,sufficient s.context kind⟩

end ConsensusCoverage.HandReadersElection.Grant
