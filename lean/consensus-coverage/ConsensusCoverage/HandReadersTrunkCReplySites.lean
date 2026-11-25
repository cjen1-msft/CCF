module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersTrunkARoleRoute
import all ConsensusCoverage.HandReadersBFactor
import all ConsensusCoverage.SolvedWitnesses
public meta import ConsensusCoverage.HandReadersTrunkARoleRoute

namespace ConsensusCoverage.HandReadersTrunkC.Reply

open Lean Meta Elab Command SolvedWitnesses

set_option maxRecDepth 16384
set_option maxHeartbeats 2400000

private theorem keep {a b c : Prop} (h : b → c) : a ∨ b → a ∨ c := Or.imp_right h
private theorem skipLeft {a b c : Prop} (h : b → c) : b → a ∨ c := fun hb => .inr (h hb)

meta section

def sitesName (n : Name) := (`ConsensusCoverage.HandReadersTrunkC.Reply.Sites).str n.getString!

-- Each phase has several projections of the same local proof. For the
-- sufficient direction retain one projection per phase at every dispatch.
private def compileSites (n : Name) : MetaM Unit := do
  lambdaTelescope (←getConstInfo n).value! fun xs body => do
    let arms := HandReadersBFactor.disjuncts body
    let origins := ReachPath.children n.getPrefix arms.head!
    let width := 1 + ((arms.drop 1).takeWhile (fun arm => ReachPath.children n.getPrefix arm != origins)).length
    let mut sub := mkConst ``False
    let mut full := mkConst ``False
    let mut proof := mkConst ``False.elim [0]
    let mut used := false
    for (a,i) in arms.zipIdx.reverse do
      let take := [0,7,14,23,37].contains (i / width)
      if used then
        proof := if take then mkApp4 (mkConst ``keep) a sub full proof
          else mkApp4 (mkConst ``skipLeft) a sub full proof
      else if take then
        if i+1 == arms.length then
          proof := mkApp (mkConst ``id [.zero]) a
        else
          proof := mkApp2 (mkConst ``Or.inl) a full
      if take then
        sub := if used then mkApp2 (mkConst ``Or) a sub else a
        used := true
      full := if i+1 == arms.length then a else mkApp2 (mkConst ``Or) a full
    let sn := sitesName n
    addDecl (.defnDecl {
      name := sn,levelParams := [],type := ←mkForallFVars xs (mkSort .zero)
      value := ←mkLambdaFVars xs sub,hints := .abbrev,safety := .safe })
    addDecl (.thmDecl {
      name := sn.appendAfter "_supply",levelParams := []
      type := ←mkForallFVars xs (←mkArrow (mkAppN (mkConst sn) xs) (mkAppN (mkConst n) xs))
      value := ←mkLambdaFVars xs proof })
    HandReadersTrunkA.Request.compileRole sn

end

run_cmd liftTermElabM do
  for n in #[``step_aeReply_stepDown_pos,``step_aeReply_stepDown_neg] do
    compileSites n

end ConsensusCoverage.HandReadersTrunkC.Reply
