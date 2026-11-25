module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersBFactor
import all ConsensusCoverage.HandReadersTrunkCCommit
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
public meta import ConsensusCoverage.HandReadersBFactor

namespace ConsensusCoverage.HandReadersTrunkC.LogSites

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety SolvedWitnesses
open Lean Meta Elab Term Command

set_option maxRecDepth 16384
set_option maxHeartbeats 1500000

private theorem cons {a b c d : Prop} (h : a ↔ c) (rest : b ↔ d) : (a ∨ b) ↔ (c ∨ d) := or_congr h rest
private theorem finish {p q a b : Prop} (h : p ↔ a ∨ b) (k : q ↔ a ∨ b) : p ↔ q := h.trans k.symm

-- Express each log projection site as its commit projection or its sender
-- projection. The batch receipts differ only by two consequences of Advance.
local macro "batch_pair" : term => `(by
  constructor
  all_goals
    rintro ⟨st,xs,entry,g,pr,gn,g',app,sent,b,later,pair,a,empty,b0,b1,es,bs,si,ss,appEq,terms,env,mem,mem',rest⟩
    refine ⟨st,xs,entry,g,pr,gn,g',app,sent,b,later,pair,a,empty,b0,b1,es,bs,si,ss,appEq,terms,env,mem,mem',?_⟩
    have ci : app.commitIndex = st.commitIndex := appEq ▸ rfl
    have le' := a.commit_le
    rw [ci] at le'
    first
    | (obtain ⟨start,term,role,le,eq⟩ := rest; exact ⟨start,term,a.log,role,eq⟩)
    | (obtain ⟨start,term,log,role,eq⟩ := rest; exact ⟨start,term,role,le',eq⟩)
    | (obtain ⟨req,pkg,msg,ok,start,term,role,le,eq⟩ := rest; exact ⟨req,pkg,msg,ok,start,term,a.log,role,eq⟩)
    | (obtain ⟨req,pkg,msg,ok,start,term,log,role,eq⟩ := rest; exact ⟨req,pkg,msg,ok,start,term,role,le',eq⟩))

private theorem dist {a b c : Prop} : a ∨ (b ∨ c) ↔ (a ∨ b) ∨ c := or_assoc.symm

meta section

private def join (as bs : List Expr) : MetaM Expr := do
  let a :: b :: tl := as | return mkApp (mkConst ``Iff.rfl) (mkApp2 (mkConst ``Or) as.head! bs.head!)
  let disj (l : List Expr) := l.dropLast.foldr (fun x y => mkApp2 (mkConst ``Or) x y) l.getLast!
  let rhs := disj bs
  let rec go (xs : List Expr) : MetaM Expr := do
    match xs with
    | x :: y :: ys =>
      let pf ←go (y :: ys)
      let h ←mkAppM ``or_congr #[mkApp (mkConst ``Iff.rfl) x,pf]
      return ←mkAppM ``Iff.trans #[h,mkApp3 (mkConst ``dist) x (disj (y :: ys)) rhs]
    | [x] => return mkApp (mkConst ``Iff.rfl) (mkApp2 (mkConst ``Or) x rhs)
    | [] => throwError "empty batch partition"
  go (a :: b :: tl)

def siteName (n : Name) := (`ConsensusCoverage.HandReadersTrunkC.LogSites.Iff).str n.getString!

run_cmd liftTermElabM do
  let children (n : Name) : MetaM (Array Name) := do return ReachPath.children n.getPrefix (←getConstInfo n).value!
  let logs ← children ``step_log_advance_inr
  let commits ← children ``step_commit_le_advance_inr
  let sends ← children ``step_sentIndex_advance_inr
  for i in [:logs.size] do
    let n := logs[i]!
    lambdaTelescope (←getConstInfo n).value! fun xs p => do
      let l := HandReadersBFactor.disjuncts p
      let c := mkAppN (mkConst commits[i]!) xs
      let s := mkAppN (mkConst sends[i]!) xs
      let cs := HandReadersBFactor.disjuncts (←unfoldDefinition? c).get!
      let ss := HandReadersBFactor.disjuncts (←unfoldDefinition? s).get!
      let mut pf := mkApp (mkConst ``Iff.rfl) s
      for (a,b) in ((l.take cs.length).zip cs).reverse do
        let ty ←mkAppM ``Iff #[a,b]
        let pr ←elabTermEnsuringType (←`(batch_pair)) ty
        synthesizeSyntheticMVarsNoPostponing
        pf ←mkAppM ``cons #[←instantiateMVars pr,pf]
      let rhs := mkApp2 (mkConst ``Or) c s
      let final ←mkAppM ``Iff.trans #[pf,←join cs ss]
      addDecl (.thmDecl {
        name := siteName n,levelParams := [],type := ←mkForallFVars xs (←mkAppM ``Iff #[mkAppN (mkConst n) xs,rhs])
        value := ←mkLambdaFVars xs final })

end

end ConsensusCoverage.HandReadersTrunkC.LogSites
