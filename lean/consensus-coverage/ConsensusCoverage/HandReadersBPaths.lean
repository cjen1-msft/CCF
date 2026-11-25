module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersBGate
import all ConsensusCoverage.EvidenceSupport
import all ConsensusCoverage.ProofWalk
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
public meta import Lean

namespace ConsensusCoverage.HandReadersBPaths

open Consensus Consensus.Model Consensus.Proofs Safety SolvedWitnesses HandReadersBGate
open Lean Meta Elab Term Command

set_option maxRecDepth 8192

variable [Config.InitialConfiguration] {f : Frame} {t : Model.State} {c : Ctx f t}

private theorem fields {u} {tr : LocalTransition f.current u} (eq : u = t) (he : HEq tr c.tr) :
    tr.event = c.event := by
  subst u
  cases eq_of_heq he
  rfl

meta section
private def reaches (p : Expr) :=
  p.getAppFn.constName?.any fun n => n.getPrefix == `ConsensusCoverage.SolvedWitnesses && n.getString!.startsWith "reach_"

private def quietName (n : Name) := (`ConsensusCoverage.HandReadersBPaths.No).str n.getString!
private def pinName (n : Name) := (`ConsensusCoverage.HandReadersBPaths.Pin).str n.getString!
private def lowerName (n : Name) := (`ConsensusCoverage.HandReadersBPaths.Lower).str n.getString!

private partial def certify (n barred : Name) : MetaM Unit := do
  let out := quietName n
  if (← getEnv).contains out then return
  let ci ← getConstInfo n
  for ch in ReachPath.children n.getPrefix ci.value! do
    unless ch == barred do certify ch barred
  lambdaTelescope ci.value! fun xs body => do
    let fp := xs.extract 0 3
    let pred := mkAppN (mkConst n) xs
    withLocalDeclD `quiet (mkAppN (mkConst ``Quiet) fp) fun quiet => do
      let hs := #[``Quiet.pending,``Quiet.now,``Quiet.seen,``Quiet.seen,``Quiet.elected,``Quiet.canon,
        ``Quiet.committed].map (fun n => mkAppN (mkConst n) (fp.push quiet))
      let ck : EvidenceSupport.Check := ⟨xs,mkAppN (mkConst ``Frame.advance) fp,hs,119⟩
      withLocalDeclD `h pred fun h => do
        let some pr ← ProofWalk.refute (fun (p,hp) => do
          if reaches p then
            let name := p.getAppFn.constName!
            if name == barred then return some (mkAppN (mkConst ``grantClosed) (p.getAppArgs.push hp))
            else return some (mkAppN (mkConst (quietName name)) (p.getAppArgs ++ #[quiet,hp]))
          if p.isAppOf ``ElectStep && p.getArg! 1 == xs[1]! && p.getArg! 2 == xs[2]! then
            let notElect ← mkAppM ``Iff.mp #[mkAppN (mkConst ``EvidenceSupport.stable_elect_iff) (xs.extract 0 4), hs[4]!]
            return some (mkAppN notElect ((p.getAppArgs.extract 3 p.getAppNumArgs).push hp))
          return none) (fun facts => do
            for (p,neg) in facts do
              if p.isAppOf ``Not then
                if let some pos ← EvidenceSupport.rebuild ck facts p.appArg! then return some (mkApp neg pos)
            return none) [(body,h)] | throwError "unrefuted inactive dispatch dependency {n}"
        let vars := xs ++ #[quiet,h]
        addDecl (.thmDecl {
          name := out, levelParams := [], type := ← mkForallFVars vars (mkConst ``False)
          value := ← mkLambdaFVars vars pr })

-- The last two atoms of each transition call pin both the state and its
-- dependent transition. Extract only those atoms; never unfold its callers.
private partial def pinProof (p h target : Expr) : MetaM Expr := do
  if p.isAppOf ``Or then
    let arms ← #[p.getArg! 0,p.appArg!].mapM fun q => withLocalDeclD `arm q fun a =>
      do mkLambdaFVars #[a] (← pinProof q a target)
    return ProofWalk.casesOr p h target arms[0]! arms[1]!
  let mut facts := #[]
  let mut spine := p
  let mut pr := h
  while spine.isAppOf ``And do
    let (a,b) := ProofWalk.conjuncts spine pr
    facts := facts.push a
    spine := b.1
    pr := b.2
  facts := facts.push (spine,pr)
  for (_,a) in facts do
    for (_,b) in facts do
      if let some proof ← observing? (mkAppM ``fields #[a,b]) then
        if ← isDefEq (← inferType proof) target then return proof
  throwError "transition call has no pair of frame/actor pins"

private def pin (n : Name) : MetaM Unit := do
  let ci ← getConstInfo n
  lambdaTelescope ci.value! fun xs body => do
    let hty := mkAppN (mkConst n) xs
    let tr := xs.back!
    let tgt ← mkEq (←mkAppM ``LocalTransition.event #[tr]) (←mkAppM ``Ctx.event #[xs[3]!])
    withLocalDeclD `call hty fun h => do
      let pr ← pinProof body h tgt
      let vars := xs.push h
      addDecl (.thmDecl {
        name := pinName n, levelParams := [], type := ← mkForallFVars vars tgt
        value := ← mkLambdaFVars vars pr })

private def generate (top barred : Name) : MetaM Unit := do
  for n in ReachPath.children top.getPrefix (←getConstInfo top).value! do
    let cs := ReachPath.children n.getPrefix (←getConstInfo n).value!
    unless cs.size == 1 do throwError "expected one pinned transition of {n}"
    let tr := cs[0]!
    certify tr barred
    pin tr
    let ci ← getConstInfo n
    lambdaTelescope ci.value! fun xs body => do
      let hty := mkAppN (mkConst n) xs
      let e := xs.back!
      let tgt ← mkEq e (←mkAppM ``Ctx.event #[xs[3]!])
      let q := mkAppN (mkConst ``Quiet) (xs.extract 0 3)
      let conj ← mkAppM ``And #[tgt,mkNot q]
      withLocalDeclD `call hty fun h => do
        let descend := fun u tr' call eq => do
          let args := xs.extract 0 4 ++ #[u,tr']
          let pin := mkAppN (mkConst (pinName tr)) (args.push call)
          let pos ← mkAppM ``Eq.trans #[eq,pin]
          let no ← withLocalDeclD `quiet q fun stable =>
            mkLambdaFVars #[stable] (mkAppN (mkConst (quietName tr)) (args ++ #[stable,call]))
          mkAppM ``And.intro #[pos,no]
        let pr ← withLocalDeclD `u (body.getArg! 0) fun u => do
          let ty := body.appArg!.beta #[u]
          withLocalDeclD `first ty fun first => do
            let inner ← withLocalDeclD `tr (ty.getArg! 0) fun tr' => do
              let ty' := ty.appArg!.beta #[tr']
              withLocalDeclD `second ty' fun second => do
                let (a,b) := ProofWalk.conjuncts ty' second
                mkLambdaFVars #[tr',second] (← descend u tr' a.2 b.2)
            mkLambdaFVars #[u,first] (ProofWalk.casesExists ty first conj inner)
        let vars := xs.push h
        addDecl (.thmDecl {
          name := lowerName n, levelParams := [], type := ← mkForallFVars vars conj
          value := ← mkLambdaFVars vars (ProofWalk.casesExists body h conj pr) })

end

run_cmd liftTermElabM do
  generate ``step_summary_event_receive (← ReachPath.resolve (← `(reachPath| step_summary_event_receive[10,0,0,0])))

end ConsensusCoverage.HandReadersBPaths
