module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersTrunkCCommit
import all ConsensusCoverage.HandReadersTrunkCAppend
import all ConsensusCoverage.HandReadersTrunkCExtension
import all ConsensusCoverage.HandReadersTrunkABatch
import all ConsensusCoverage.HandReadersBFactor
import all ConsensusCoverage.PromotionImpossibleB
import all ConsensusCoverage.AdvanceArmsB
import all ConsensusCoverage.SelfQuorumCasesB
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
public meta import ConsensusCoverage.HandReadersBFactor

namespace ConsensusCoverage.HandReadersTrunkC.RoleSites

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety SolvedWitnesses
open Lean Meta Elab Command HandReadersA ActionProfile

set_option maxRecDepth 16384
set_option maxHeartbeats 2000000

private theorem birth [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t)
    {n st xs} (h : ∃ ev, (n = c.tr.actor ∧ st = c.tr.pre ∧ ev = c.tr.event) ∧
      ∃ input, ev = .internal input ∧ ev = .internal input ∧ input = .append xs) :
    n = c.actor ∧ st = c.pre ∧ c.event = .internal (.append xs) := by
  obtain ⟨_,⟨rfl,rfl,rfl⟩,_,ev,_,rfl⟩ := h
  exact ⟨rfl,rfl,ev⟩

private theorem batch [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t)
    {n st xs m app msgs} (atCall : n = c.actor ∧ st = c.pre ∧ c.event = .internal (.append xs))
    (primary : st.role = .primary) (bat : BatchState n st app msgs) (eq : m = app)
    (grew : m.commitIndex < highestCommittableIndex m n) : Batch.Good c := by
  obtain ⟨rfl,rfl,ev⟩ := atCall
  obtain ⟨⟨suffix,si,h,_⟩,_⟩ := bat
  exact ⟨⟨_,ev⟩,Extension.normalize c primary suffix si app h (eq ▸ grew)⟩

private theorem ack {n} {st : NodeState} {source response post} (a : Advance n
    {st with matchIndex := CCF.Function.update st.matchIndex source (max (st.matchIndex source) response)} post)
    (leader : ¬(st.role != Role.primary) = true) (candidate : post.role = .candidate) : False := by
  have primary : st.role = .primary := by simpa using leader
  rcases a.role with same | gone
  · exact Role.noConfusion (candidate.symm.trans (same.trans primary))
  · exact Role.noConfusion (candidate.symm.trans gone)

private theorem campaign [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t)
    {n actor before cand ev m} (atCall : before = c.pre) (camp : Campaign n before ev cand)
    (eq : m = primaryState cand) (grew : m.commitIndex < highestCommittableIndex m actor) : False :=
  PromotionImpossibleB.cannotGrow actor eq (PromotionImpossibleB.campOld c atCall camp) grew

meta section

private abbrev Field := Expr × Expr
private def find (fs : Array Field) (p : Expr → Bool) : MetaM Expr := do
  let some (_,h) := fs.find? fun (q,_) => p q | throwError "missing local projection"
  return h

private def gateName (r : Name) := (`ConsensusCoverage.HandReadersTrunkC.RoleSites.Pin).str r.getString!

private def pin (r : Name) : MetaM Unit := do
  let n := gateName r
  unless (←getEnv).contains n do
    lambdaTelescope (←getConstInfo r).value! fun xs body => do
      withLocalDeclD `h (mkAppN (mkConst r) xs) fun h => do
        let c := xs[3]!
        let pf ← if xs.size == 7 then do
          let part ←HandReadersBFactor.splitAt (←HandReadersBFactor.roots) (xs.extract 0 4) body
          let both ←mkAppM ``Iff.mp #[part.proof,h]
          mkAppM ``birth #[c,←mkAppM ``And.right #[both]]
        else PromotionImpossibleB.beforeOrigin c xs[5]! body h
        let v ←mkLambdaFVars (xs.push h) pf
        addDecl (.thmDecl {name := n,levelParams := [],type := ←inferType v,value := v})

private def compile (r : Name) : MetaM Name := do
  let name := (`ConsensusCoverage.HandReadersTrunkC.RoleSites.Strict).str r.getString!
  let info ←getConstInfo r
  for ch in ReachPath.children r.getPrefix info.value! do
    if (←forallTelescope (←getConstInfo ch).type fun xs _ => pure xs.size) != 8 then pin ch
  lambdaTelescope info.value! fun xs body => do
    let c := xs[3]!
    let m := xs[5]!
    let tgt ←mkAppM ``Batch.Good #[c]
    let grow ←mkAppM ``LT.lt #[←mkAppM ``NodeState.commitIndex #[m],←mkAppM ``highestCommittableIndex #[m,xs[4]!]]
    withLocalDeclD `origin (mkAppN (mkConst r) xs) fun origin => withLocalDeclD `grew grow fun grew => do
      let pf ← PromotionImpossibleB.withFields body origin #[] fun fs => do
        let (call,h,_) ←PromotionImpossibleB.firstReach fs
        let ch := call.getAppFn.constName!
        let fields := call.getAppArgs
        if fields.size == 8 then
          let a ←find fs (·.isAppOf ``Advance)
          let leader ←find fs fun q => q.isAppOf ``Not && q.appArg!.isAppOf ``Eq && (q.appArg!.getArg! 1).isAppOf ``bne
          let cand ←find fs fun q => q.isAppOf ``Eq && q.appArg!.isConstOf ``Role.candidate
          return mkApp2 (mkConst ``False.elim [.zero]) tgt (←mkAppM ``ack #[a,leader,cand])
        let atCall := mkAppN (mkConst (gateName ch)) (fields.push h)
        let (_,eq) ←PromotionImpossibleB.nodeEq m fs
        if fields.size == 7 then
          let b ←find fs (·.isAppOf ``BatchState)
          let leader ←find fs fun q => q.isAppOf ``Eq && q.appArg!.isConstOf ``Role.primary
          mkAppM ``batch #[c,atCall,leader,b,eq,grew]
        else
          let camp ←find fs (·.isAppOf ``Campaign)
          return mkApp2 (mkConst ``False.elim [.zero]) tgt (←mkAppM ``campaign #[c,atCall,camp,eq,grew])
      let v ←mkLambdaFVars (xs ++ #[origin,grew]) pf
      addDecl (.thmDecl {name,levelParams := [],type := ←inferType v,value := v})
  return name

end

run_cmd liftTermElabM do
  let top := ``step_role_advance_inr
  for r in ReachPath.children top.getPrefix (←getConstInfo top).value! do
    discard <| compile r

open Elab.Term in
local elab "role_site% " src:ident : term => do
  let v ←elabTerm src none
  let ty ←inferType v
  let decl := (`ConsensusCoverage.HandReadersTrunkC.RoleSites.Strict).str ty.getAppFn.constName!.getString!
  return mkAppN (mkConst decl) (ty.getAppArgs.push v)

private theorem strictNecessary [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t)
    (h : step_role_advance_inr f t c) : Batch.Good c := by
  iterate 24 (rcases h with h | h; case inl =>
    obtain ⟨_,_,_,site,strict,_⟩ := h
    exact (role_site% site) (strict.2.2.2.2.2.2.2.1 ▸ strict.2.2.2.2.2.2.1))
  obtain ⟨_,_,_,site,strict,_⟩ := h
  exact (role_site% site) (strict.2.2.2.2.2.2.2.1 ▸ strict.2.2.2.2.2.2.1)

private theorem strictSupply [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t)
    (g : Batch.Good c) : step_role_advance_inr f t c := by
  obtain ⟨⟨xs,ev⟩,ahead⟩ := g
  let s := HandReadersTrunkA.Batch.seed c ev
  let m := AdvanceArmsB.appended c.pre
  let post := {m with commitIndex := highestCommittableIndex m c.actor}
  let e := SelfQuorumCasesB.heartbeat c.actor m
  let q : AppendEntriesRequest := ⟨m.currentTerm,0,termAt m.log 0,[],0⟩
  let es : List Entry := [⟨c.pre.currentTerm,.signature⟩]
  have terms : ∀ x ∈ es, x.term = c.pre.currentTerm := by simp [es]
  have ae : AEFrom c.actor c.pre.currentTerm c.pre.commitIndex m.log e := SelfQuorumCasesB.beat _ _
  have batch : BatchState c.actor c.pre m [e] := ⟨⟨es,c.pre.sentIndex,rfl,terms⟩,SelfQuorumCasesB.singleton ae⟩
  have ok : AEOk c.actor e.target post q := ⟨Nat.succ_ne_self _,rfl,Nat.zero_le _,rfl,List.nil_prefix,Nat.zero_le _⟩
  have fromPost : AEFrom c.actor post.currentTerm post.commitIndex post.log e := ⟨rfl,ok.1,q,rfl,ok.2⟩
  have a : Advance c.actor m post := .inr ⟨rfl,rfl,rfl,rfl,rfl,rfl,ahead,rfl,.inl rfl⟩
  have empty : ∀ a ∈ ([] : List Model.Envelope), a.source = c.actor ∧ a.payload = .proposeRequestVoteRequest m.currentTerm := by simp
  iterate 6 right
  left
  refine ⟨c.actor,m,post,?_,⟨rfl,rfl,rfl,rfl,rfl,rfl,ahead,rfl,.inl rfl⟩,a⟩
  iterate 3 right
  left
  exact ⟨c.pre,xs,s.entered,s.guards,s.guards.1,s.guards.2,s.guards,m,[e],batch,[],⟨a,empty⟩,a,empty,
    batch.1,batch.2,es,⟨_,rfl,terms⟩,c.pre.sentIndex,⟨rfl,terms⟩,rfl,terms,e,.head _,.head _,
    q,⟨rfl,ok⟩,rfl,ok,BatchArmsB.start s,rfl,rfl,Nat.le_of_lt ahead,fromPost,rfl⟩

def strict := Batch.exactOfGood .role_advance_inr fun s =>
  ⟨@strictNecessary ⟨s.cfg⟩ _ _ s.context, @strictSupply ⟨s.cfg⟩ _ _ s.context⟩

end ConsensusCoverage.HandReadersTrunkC.RoleSites
