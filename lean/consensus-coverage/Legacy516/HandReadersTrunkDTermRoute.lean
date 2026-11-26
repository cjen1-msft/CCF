module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersTrunkDTermSites
import all ConsensusCoverage.HandReadersTrunkAFactor
import all ConsensusCoverage.HandReadersBFactor
import all ConsensusCoverage.SolvedWitnesses
public meta import ConsensusCoverage.HandReadersTrunkDTermSites
public meta import ConsensusCoverage.HandReadersTrunkAFactor

namespace ConsensusCoverage.HandReadersTrunkD.Term

open Lean Meta Elab Command SolvedWitnesses

set_option maxRecDepth 16384
set_option maxHeartbeats 6000000

private meta partial def shrink (p : Expr) : MetaM (Expr × Expr) := do
  if p.isAppOfArity ``Or 2 then
    let (a,h) ←shrink (p.getArg! 0)
    let (b,k) ←shrink p.appArg!
    return (mkApp2 (mkConst ``Or) a b,←mkAppM ``or_congr #[h,k])
  if p.isAppOfArity ``Exists 2 then
    return ←withLocalDeclD `w (p.getArg! 0) fun x => do
      let (b,h) ←shrink (p.appArg!.beta #[x])
      return (mkApp2 p.getAppFn (p.getArg! 0) (←mkLambdaFVars #[x] b),
        ←mkAppM ``exists_congr #[←mkLambdaFVars #[x] h])
  unless p.isAppOfArity ``And 2 do throwError "expected a pinned Advance site"
  let call := p.getArg! 0
  let r := call.getAppFn.constName!
  let a := (←getConstInfo (shortName r)).value!.beta call.getAppArgs
  return (mkApp2 (mkConst ``And) a p.appArg!,←mkAppM ``and_congr #[
    mkAppN (mkConst (shortIff r)) call.getAppArgs,mkApp (mkConst ``Iff.rfl) p.appArg!])

run_cmd liftTermElabM do
  for (q,n) in [( ``step_term_advance_inl,`Identity),( ``step_term_advance_inr,`Strict)] do
    lambdaTelescope (←getConstInfo q).value! fun xs body => do
      let (b,h) ←shrink body
      let name := `ConsensusCoverage.HandReadersTrunkD.Term ++ n
      addDecl (.defnDecl {
        name,levelParams := [],type := ←mkForallFVars xs (mkSort .zero)
        value := ←mkLambdaFVars xs b,hints := .abbrev,safety := .safe})
      addDecl (.thmDecl {
        name := name.appendAfter "_iff",levelParams := []
        type := ←mkForallFVars xs (←mkAppM ``Iff #[mkAppN (mkConst q) xs,mkAppN (mkConst name) xs])
        value := ←mkLambdaFVars xs h})
      HandReadersTrunkA.Factor.compile name

end ConsensusCoverage.HandReadersTrunkD.Term
