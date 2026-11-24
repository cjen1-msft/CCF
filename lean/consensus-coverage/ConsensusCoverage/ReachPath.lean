module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public meta import Lean

namespace ConsensusCoverage.ReachPath

public meta section

open Lean Elab Term Tactic
open Lean.Parser.Tactic (location)

/-- The distinct direct reach dependencies, in expression traversal order. -/
def children (namespaceName : Name) (body : Expr) : Array Name :=
  body.getUsedConstants.filter fun
    | .str pre name => pre == namespaceName && name.startsWith "reach_"
    | _ => false

declare_syntax_cat reachPath
syntax ident "[" num,* "]" : reachPath

/-- Follow local dependency positions from a named predicate, not global reach numbers. -/
def resolve (path : TSyntax `reachPath) : TermElabM Name := do
  let `(reachPath| $root:ident [$indices:num,*]) := path
    | throwUnsupportedSyntax
  let mut name ← realizeGlobalConstNoOverloadWithInfo root
  let ns := name.getPrefix
  for index in indices.getElems do
    let info ← getConstInfo name
    let some body := info.value? | throwErrorAt root "no body for {name}"
    let some child := (children ns body)[index.getNat]?
      | throwErrorAt index "no reach dependency {index.getNat} in {name}"
    name := child
  return name

elab "reach% " path:reachPath : term => do
  let name ← resolve path
  elabTerm (mkIdentFrom path name) none

elab "reachName% " path:reachPath : term => do
  return toExpr (← resolve path)

elab "reach_unfold " path:reachPath loc:(location)? : tactic => withMainContext do
  let decl := mkIdentFrom path (← resolve path)
  evalTactic (← `(tactic| unfold $decl $[$loc:location]?))

end

end ConsensusCoverage.ReachPath
