module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersElectionGrant
import all ConsensusCoverage.ReachPath
public meta import ConsensusCoverage.ReachPath
public meta import Lean
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersElection.RankSites

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety SolvedWitnesses
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxRecDepth 8192

open Lean Elab Term Meta in
local elab "rankSites% " a:term:arg* : term => do
  let root := ``step_rankAtGrant_persist_inl
  let sites := ReachPath.children root.getPrefix (← getConstInfo root).value!
  let mut arms := #[]
  for site in sites do
    let name := mkIdent site
    arms := arms.push (← elabTerm (← `($name $a*)) (some (.sort .zero)))
  return arms.pop.foldr (mkApp2 (mkConst ``Or)) arms.back!

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)

abbrev Sites (v n term : Nat) (r : RequestVoteRequest) (k : Nat) (l : List Entry) (i : Nat) :=
  rankSites% f t c v n term r k l i

abbrev Input (v n term : Nat) (r : RequestVoteRequest) (k : Nat) (l : List Entry) (i : Nat) :=
  Grant.Route c v n term r ∧ LogFacts.GrantAt f.current t v n term r ∧
    (v = n ∨ ∃ l, f.logs.seen n term l) ∧ f.logs.seen v k l ∧ k < term ∧
    isSignatureAt l i = true ∧ termAt l i = k

local macro "along " h:term : tactic => `(tactic| {
  have spine := $h
  repeat' first | exact spine | exact spine.1
                | change _ ∧ _ at spine; obtain ⟨_,spine⟩ := spine
                | change Exists _ at spine; obtain ⟨_,spine⟩ := spine })

include c in
private theorem impossible {v n k r a l i}
    (hit : LogFacts.GrantAt f.current t v n k r) (seen : f.logs.seen v a l) (le : k ≤ a)
    (signed : isSignatureAt l i = true) (eq : termAt l i = a) (lt : r.lastCommittableTerm < a) :
    False := by
  obtain (hi | ⟨same,_⟩) | ⟨e,_,lo,hi,_⟩ := c.rankAtGrant hit seen signed eq
  all_goals omega

set_option maxHeartbeats 4000000 in
theorem necessary {v n term r k l i} (site : Sites c v n term r k l i) :
    Input c v n term r k l i := by
  rcases site with site | site | site | site | site | site | site | site | site | site | site | site
  all_goals repeat' (change _ ∨ _ at site; rcases site with site | site)
  all_goals
    first
    | change ∃ _ : Nat, _ at site
      obtain ⟨term',caller,_,p,_,eq,⟨hit,sup⟩,_,_,_,_,_,st,_,post,_,_,_,_,_,_,_,_,_,_,_,
        a,_,lt,signed,stamp,seen,_,_,rfl,rfl⟩ := site
      obtain rfl := Option.some.inj eq
      refine ⟨Grant.route_of_site c ?_,hit,sup,seen,lt,signed,stamp⟩
      repeat' first | exact caller | exact Or.inl caller | apply Or.inr
    | obtain ⟨log,idx,_,xs,_,pack,ws⟩ := site
      have hit : LogFacts.GrantAt f.current t v n term (vals term log idx) := by along ws
      obtain ⟨_,_,a,p,j,seen,le,signed,eq,lt⟩ := pack
      exact (impossible c hit seen le signed eq lt).elim

theorem sufficient {v n term r k l i} (input : Input c v n term r k l i) :
    (reach% step_rankAtGrant_persist_inl[0]) f t c v n term r k l i ∨
      (reach% step_rankAtGrant_persist_inl[1]) f t c v n term r k l i := by
  obtain ⟨route,hit,sup,seen,lt,signed,atI⟩ := input
  have g : (f.advance t).logs.grant v n term r := .inr ⟨_,rfl,hit,sup⟩
  have stamp := (c.grantFactsBefore _ _ _ _ g).1.1
  have which : (reach% step_grantFactsBefore_grant_inr[0]) f t c v n term r ∨
      (reach% step_grantFactsBefore_grant_inr[1]) f t c v n term r := by
    obtain fresh | ⟨elect,rfl,rfl,rfl⟩ := route
    · exact .inl ⟨⟨g,fresh⟩,g⟩
    · exact .inr (Grant.elected_site c elect g)
  obtain ⟨st,w,pre,post,le,termEq,vote,up⟩ := hit
  have edge := And.intro pre (And.intro post (And.intro le (And.intro termEq (And.intro vote up))))
  have actual : LogFacts.GrantAt f.current t v n term r := ⟨st,w,edge⟩
  rcases which with root | root
  · left
    exact ⟨term,root,⟨_,rfl,actual,sup⟩,_,⟨rfl,actual,sup⟩,rfl,⟨actual,sup⟩,actual,sup,
      rfl,.rfl,actual,st,⟨w,edge⟩,w,edge,pre,edge.2,post,edge.2.2,le,edge.2.2.2,
      termEq,⟨vote,up⟩,vote,up,k,.inl seen,lt,signed,atI,seen,g,stamp,rfl,rfl⟩
  · right; left
    exact ⟨term,root,⟨_,rfl,actual,sup⟩,_,⟨rfl,actual,sup⟩,rfl,⟨actual,sup⟩,actual,sup,
      rfl,.rfl,actual,st,⟨w,edge⟩,w,edge,pre,edge.2,post,edge.2.2,le,edge.2.2.2,
      termEq,⟨vote,up⟩,vote,up,k,.inl seen,lt,signed,atI,seen,g,stamp,rfl,rfl⟩
end

end ConsensusCoverage.HandReadersElection.RankSites
