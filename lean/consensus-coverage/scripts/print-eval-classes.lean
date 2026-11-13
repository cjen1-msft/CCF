module

meta import Lean
import all ConsensusCoverage.Classes
import all Consensus.Proofs.SafetyInvariant

/-!
# Print the classes selected for evaluation (`eval-selection.txt`) with their `reach` chains

For each selected class: its definition, the `reach_k` definitions it uses (transitively), and
the number of existential binders in the class and in the chain.

    WS=$(python3 lean/relevance/scripts/workspace.py consensus-coverage)
    lake -d $WS/consensus-coverage env lean $PWD/lean/consensus-coverage/scripts/print-eval-classes.lean
-/

open Lean Meta

meta def countEx (e : Expr) : Nat := Id.run do
  let mut k := 0
  let mut stack := #[e]
  while !stack.isEmpty do
    let e := stack.back!
    stack := stack.pop
    if e.isAppOfArity ``Exists 2 then k := k + 1
    match e with
    | .app f a => stack := stack.push f |>.push a
    | .lam _ t b _ | .forallE _ t b _ => stack := stack.push t |>.push b
    | .letE _ t v b _ => stack := stack.push t |>.push v |>.push b
    | .mdata _ b => stack := stack.push b
    | _ => pure ()
  return k

meta def reachRefs (e : Expr) : Array Name :=
  (e.getUsedConstants.filter fun n =>
    (`ConsensusCoverage.Classes).isPrefixOf n
      && (n.componentsRev.head!.toString.startsWith "reach_"))

#eval show MetaM Unit from do
  let file := "/workspaces/ccf-coverage-eval/lean/consensus-coverage/scripts/eval-selection.txt"
  let names := (← IO.FS.lines file).filter fun l => !l.startsWith "#" && l != ""
  for s in names do
    let n := `ConsensusCoverage.Classes ++ s.toName
    let ci ← getConstInfo n
    let mut seen : NameSet := {}
    let mut todo := reachRefs ci.value!
    let mut chainEx := 0
    let mut chain := #[]
    while !todo.isEmpty do
      let r := todo.back!
      todo := todo.pop
      if seen.contains r then continue
      seen := seen.insert r
      let v := (← getConstInfo r).value!
      chainEx := chainEx + countEx v
      chain := chain.push r
      todo := todo ++ reachRefs v
    IO.println s!"===== {s}: {countEx ci.value!} existentials, reach chain {chain.size} defs with {chainEx}"
    IO.println (← ppExpr ci.value!).pretty
    (← IO.getStdout).flush
    for r in chain do
      let v := (← getConstInfo r).value!
      IO.println s!"  -- {r}: {countEx v} existentials, size {v.approxDepth}"
