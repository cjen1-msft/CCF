module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public meta import Lean

namespace ConsensusCoverage.PathPremises
public meta section

open Lean Meta Elab Tactic

private partial def extract (h type target : Expr) : MetaM (Option Expr) := do
  if ← withReducible (isDefEq type target) then return some h
  if type.isAppOfArity ``And 2 then
    if let some p ← extract (.proj ``And 1 h) (type.getArg! 1) target then return some p
    return ← extract (.proj ``And 0 h) (type.getArg! 0) target
  if type.isAppOfArity ``Or 2 then
    let branch (t : Expr) := withLocalDeclD `arm t fun x => do
      let some p ← extract x t target | return none
      return some (← mkLambdaFVars #[x] p)
    let some l ← branch (type.getArg! 0) | return none
    let some r ← branch (type.getArg! 1) | return none
    return some (← mkAppM ``Or.elim #[h, l, r])
  if type.isAppOfArity ``Exists 2 && type.appArg!.isLambda then
    let pred := type.appArg!
    return ← withLocalDeclD pred.bindingName! pred.bindingDomain! fun x => do
      let t := pred.beta #[x]
      withLocalDeclD `path t fun y => do
        let some p ← extract y t target | return none
        let body ← mkLambdaFVars #[x, y] p
        return some (← mkAppM ``Exists.elim #[h, body])
  return none

/-- Project a common premise from a normalized path. Open only the supplied
predicate, not its recursive callees or the protocol's semantic definitions. -/
elab "path_premise " hyp:ident : tactic => withMainContext do
  let h ← getFVarId hyp
  let type ← h.getType
  let type := (← unfoldDefinition? type).getD type
  let goal ← getMainGoal
  let target ← goal.getType
  let some p ← extract (.fvar h) type target | throwError "no common premise"
  goal.assign p
  replaceMainGoal []

end
end ConsensusCoverage.PathPremises
