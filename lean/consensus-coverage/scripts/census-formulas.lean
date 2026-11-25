module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.SolvedWitnesses
meta import Lean

/-! Export normalized predicates without expanding shared reach calls.
`CENSUS_FORMULAS` optionally selects space-separated short names and
`CENSUS_FORMULAS_OUT` writes the TSV directly. Use with
`census-candidates.py --formulas` for proof handoff. -/

open Lean Meta Elab Command
open ConsensusCoverage.SolvedWitnesses

set_option pp.maxSteps 1000000
set_option pp.deepTerms true
set_option pp.proofs true
set_option maxRecDepth 8192

run_cmd liftTermElabM do
  let scope := `ConsensusCoverage.SolvedWitnesses
  let selection := ((← IO.getEnv "CENSUS_FORMULAS").getD "").splitOn " "
  let selective := selection != [""]
  let names := (← getEnv).constants.toList.filterMap fun (n, d) => do
    guard (n.getPrefix == scope)
    let .defnInfo _ := d | none
    guard (n.getString!.startsWith "step_" || n.getString!.startsWith "reach_")
    guard (!selective || selection.contains n.getString!)
    return n
  if selective && names.length != selection.eraseDups.length then throwError "unknown normalized predicate"
  let out ← match ← IO.getEnv "CENSUS_FORMULAS_OUT" with
    | some path => pure (IO.FS.Stream.ofHandle (← IO.FS.Handle.mk path .write))
    | none => IO.getStdout
  out.putStrLn "name\tnormalized_body"
  for n in names.mergeSort (fun a b => a.getString! ≤ b.getString!) do
    let body := (← getConstInfoDefn n).value
    let text := (← ppExpr body).pretty 1000000
    if text.contains "⋯" then throwError "truncated predicate: {n}"
    out.putStrLn s!"{n.getString!}\t{(text.replace "\n" " ").replace "\t" " "}"
    out.flush
