module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.ReadersGenerated
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.GuardedDomain
meta import Lean

/-! Print the transitive historical atom inputs and their time boundary for
each generated reader. These are syntactic dependencies (upper bounds),
not assertions that a branch can distinguish two values of each input. -/

open Lean Meta Elab Command
open ConsensusCoverage

set_option maxHeartbeats 0

private meta def boundary (h : Expr) : String := Id.run do
  unless h.isAppOfArity ``List.cons 3 do return "unrecognized"
  if (h.getArg! 1).isAppOf ``GuardedDomain.View.before then return "pre"
  if (h.getArg! 1).isAppOf ``GuardedDomain.View.after then return "post"
  return "unrecognized"

private meta def historyAtom (e : Expr) : Option String := do
  let n ← e.getAppFn.constName?
  let args := e.getAppArgs
  if n == ``List.map && args.size == 4 && args[3]!.isAppOfArity ``ReadersAtoms.histNodes 1 then
    let fn := args[2]!
    let field := if fn.isAppOfArity ``Prod.fst 2 then "id" else Id.run do
      let .lam _ _ body _ := fn | return "unrecognized"
      let some field := body.getAppFn.constName? | return "unrecognized"
      return if field == ``Prod.fst then "id" else field.getString!
    return s!"{boundary args[3]!.appArg!}.domain.{field}"
  if n == ``ReadersAtoms.electionExact && args.size == 7 then return "edge.election"
  for (name, arity, i, atom) in [
      (``ReadersAtoms.electedExact, 5, 4, "elections"), (``GuardedDomain.canonAt, 4, 3, "canonical"),
      (``ReadersAtoms.grantedIn, 5, 0, "grants"), (``GuardedDomain.observations, 2, 0, "observations"),
      (``GuardedDomain.ledTerms, 3, 1, "leaderTerms"), (``ReadersAtoms.voteStamps, 1, 0, "votes"),
      (``ReadersAtoms.historicalPrefixes, 1, 0, "prefixes")] do
    if n == name && args.size == arity then return s!"{boundary args[i]!}.{atom}"
  if n == ``ReadersAtoms.XView.committedBefore && args.size == 1 then return "pre.commits"
  if n == ``ReadersAtoms.XView.committedAfter && args.size == 1 then return "post.commits"
  none

run_cmd liftTermElabM do
  let scope := `ConsensusCoverage.ReadersCompiler.R
  let env ← getEnv
  let mut inputs : NameMap (Array Name × List String) := {}
  for (n, d) in env.constants.toList do
    if n.getPrefix != scope then continue
    let .defnInfo d := d | continue
    let found ← IO.mkRef ([] : List String)
    let _ ← Core.transform d.value (pre := fun e => do
      if let some a := historyAtom e then found.modify (a :: ·)
      return .continue)
    inputs := inputs.insert n (d.value.getUsedConstants.filter (·.getPrefix == scope), (← found.get).eraseDups)
  let questions := inputs.toList.map Prod.fst |>.filter (·.getString!.startsWith "step_")
  IO.println "question\thistorical_inputs"
  for n in questions.mergeSort (fun a b => a.getString! ≤ b.getString!) do
    let mut todo := [n]
    let mut seen : NameSet := {}
    let mut atoms : List String := []
    while !todo.isEmpty do
      let node := todo.head!
      todo := todo.tail!
      if seen.contains node then continue
      seen := seen.insert node
      let some (deps, localAtoms) := inputs.find? node | continue
      todo := deps.toList ++ todo
      atoms := localAtoms ++ atoms
    IO.println s!"{n.getString!}\t{String.intercalate "," (atoms.eraseDups.mergeSort (· ≤ ·))}"
