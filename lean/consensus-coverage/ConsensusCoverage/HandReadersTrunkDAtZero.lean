module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersTrunkCRoleStrict
import all ConsensusCoverage.HandReadersTrunkABatch
import all ConsensusCoverage.HandReadersAAppend
import all ConsensusCoverage.HandReadersBFactor
import all ConsensusCoverage.DeepPrefixCases
import all ConsensusCoverage.PromotionImpossibleB
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
public meta import ConsensusCoverage.HandReadersBFactor
public meta import ConsensusCoverage.PromotionImpossibleB

namespace ConsensusCoverage.HandReadersTrunkD.Prefix

open Consensus Model Model.Node Proofs Safety Ledger SolvedWitnesses ActionProfile HandReadersA
open Lean Meta Elab Command
set_option maxRecDepth 16384
set_option maxHeartbeats 3000000

private abbrev App [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t) :=
  ∃ xs, c.event = .internal (.append xs)

private theorem appBirth [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t)
    {n st xs} (h : ∃ ev, (n = c.tr.actor ∧ st = c.tr.pre ∧ ev = c.tr.event) ∧
      ∃ i, ev = .internal i ∧ ev = .internal i ∧ i = .append xs) : App c := by
  obtain ⟨_,_,ev⟩ := HandReadersTrunkC.RoleSites.birth c h
  exact ⟨xs,ev⟩

private theorem posEq {a b : Nat} (e : a = b) (p : 0 < b) : 0 < a := e ▸ p
private theorem factsPos [Config.InitialConfiguration] {g l k b i} (facts : CommitFacts g l k b i) :
    0 < i := signature_pos facts.signature

meta section
private def certName (n : Name) := (`ConsensusCoverage.HandReadersTrunkD.Prefix.Zero).str n.getString!
private abbrev Flds := PromotionImpossibleB.Fields

private def positive (fs : Flds) (i : Expr) : MetaM (Option Expr) := do
  let zero := mkNatLit 0
  let mut vals := #[]
  for (p,h) in fs do
    if p.isAppOf ``LT.lt || p.isAppOf ``GT.gt then vals := vals.push h
    if p.isAppOfArity ``Eq 3 && (p.getArg! 1).isAppOf ``isSignatureAt && p.appArg!.isConstOf ``Bool.true then
      vals := vals.push (←mkAppM ``signature_pos #[h])
    if p.isAppOf ``CommitFacts then vals := vals.push (←mkAppM ``factsPos #[h])
  for h in vals do
    let p ←inferType h
    if ←isDefEq p (←mkAppM ``LT.lt #[zero,i]) then return some h
    for (q,eq) in fs do
      if q.isAppOfArity ``Eq 3 && (q.getArg! 1) == i then
        if let some hp ←observing? (mkAppM ``posEq #[eq,h]) then return some hp
  return none

private partial def compile (n : Name) (index : Option Nat) : MetaM Unit := do
  let out := certName n
  if (←getEnv).contains out then return
  let ci ←getConstInfo n
  lambdaTelescope ci.value! fun xs p=>do
    let c := xs[3]!
    let target ← mkAppM ``App #[c]
    let ik := index.map (fun j=>xs[j]!)
    let pred := mkAppN (mkConst n) xs
    let target ← if let some i := ik then mkAppM ``Or #[target,←mkAppM ``LT.lt #[mkNatLit 0,i]] else pure target
    withLocalDeclD `site pred fun site=>do
      let v ← if xs.size == 7 && (←inferType xs.back!).isAppOf ``List &&
          ((←inferType xs.back!).appArg!.isConstOf ``AppendEntryInput) then do
        let entry ← HandReadersBFactor.splitAt (←HandReadersBFactor.roots) (xs.extract 0 4) p
        mkAppM ``appBirth #[c,←mkAppM ``And.right #[←mkAppM ``Iff.mp #[entry.proof,site]]]
      else PromotionImpossibleB.withFields p site #[] fun fs=>do
        if let some i := ik then
          if let some h ←positive fs i then
            return ←mkAppOptM ``Or.inr #[target.getArg! 0,none,h]
        let (co,h,_) ←PromotionImpossibleB.firstReach fs
        let r := co.getAppFn.constName!
        let args := co.getAppArgs
        let ix? := ik.bind fun i=> (args.toList.zipIdx.find? (fun (a,j)=>j ≥ 4 && a==i)).map Prod.snd
        -- Only sender/appended-packet chains can reach this fallback. Other
        -- branches must have provided a positive index, never a guessed event.
        if args.size < 6 then throwError "{n.getString!} lacks index evidence at {r.getString!}"
        compile r ix?
        let hv := mkAppN (mkConst (certName r)) (args.push h)
        if ik.isSome && ix?.isNone then return ←mkAppOptM ``Or.inl #[none,target.appArg!,hv]
        return hv
      let pf ←mkLambdaFVars (xs.push site) (←mkExpectedTypeHint v target)
      addDecl (.thmDecl {name:=out,levelParams:=[],type:=←mkForallFVars (xs.push site) target,value:=pf})
end

run_cmd liftTermElabM do
  let q:=``step_termAt_take_zero_pos
  for r in ReachPath.children q.getPrefix (←getConstInfo q).value! do compile r (some 4)

open Elab.Term in
local elab "zero_origin% " h:ident : term => do
  let h ←elabTerm h none
  let p ←inferType h
  return mkAppN (mkConst (certName p.getAppFn.constName!)) (p.getAppArgs.push h)

private theorem iff_append [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t) :
    step_termAt_take_zero_pos f t c ↔ App c := by
  constructor
  · intro h
    repeat' (change _ ∨ _ at h; rcases h with h | h)
    all_goals obtain ⟨_,site,_⟩ := h; exact (zero_origin% site).resolve_right (Nat.lt_irrefl 0)
  · rintro ⟨xs,ev⟩
    let s := HandReadersTrunkA.Batch.seed c ev
    have h := DeepPrefixCases.sender s.self s.before s.contents s.entered s.guards 0 (Nat.zero_le _)
    iterate 10 right
    exact .inl ⟨_,h,Nat.zero_le _⟩

def zero : Exact .termAt_take_zero_pos where
  eval := Append.reader
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    apply Eq.trans _ ((Append.exactReader .cons).eq_label s)
    apply Bool.eq_iff_iff.mpr
    rw [label_true,holds,sig_iff,label_true,holds,sig_iff,Append.iff_append]
    exact iff_append s.context

end ConsensusCoverage.HandReadersTrunkD.Prefix
