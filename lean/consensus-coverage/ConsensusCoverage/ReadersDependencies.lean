module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.ReadersGenerated
import all ConsensusCoverage.ReadersCompiler
meta import Lean

/-! Report conservative input-use flags for the generated reader bodies.
The history flags identify the data needed by the current implementation,
not an equivalence with a smaller explorer ghost. -/

namespace ConsensusCoverage.ReadersDependencies

meta section

open Lean Elab Command Meta

private def surface (name : Name) : Name :=
  (privateToUserName? name).getD name

private def inputs (name : Name) : Array String :=
  match surface name with
  | `ConsensusCoverage.GuardedDomain.View.pre
  | `ConsensusCoverage.GuardedDomain.View.post
  | `CCF.MultiNodeTransitionSystem.State.nodes => #["node_table"]
  | `ConsensusCoverage.GuardedDomain.View.changed => #["changed_bit"]
  | `ConsensusCoverage.GuardedDomain.View.actor => #["action", "envelope"]
  | `ConsensusCoverage.ReadersAtoms.XView.event => #["action", "envelope"]
  | `ConsensusCoverage.ReadersAtoms.XView.outputs => #["node_table", "action", "envelope"]
  | `ConsensusCoverage.GuardedDomain.View.bootstrap
  | `Consensus.Proofs.Config.INITIAL_PRIMARY
  | `Consensus.Proofs.Config.GENESIS => #["configuration"]
  | `ConsensusCoverage.ReadersAtoms.XView.committedBefore
  | `ConsensusCoverage.ReadersAtoms.XView.committedAfter => #["commits"]
  | `ConsensusCoverage.GuardedDomain.View.past => #["history_input"]
  | `ConsensusCoverage.ReadersAtoms.histNodes
  | `ConsensusCoverage.ReadersAtoms.historicalPrefixes => #["historical_nodes"]
  | `ConsensusCoverage.GuardedDomain.canonAt
  | `ConsensusCoverage.CanonicalLogs.keys => #["canonical"]
  | `ConsensusCoverage.GuardedDomain.observations => #["observations"]
  | `ConsensusCoverage.GuardedDomain.ledTerms => #["leaders"]
  | `ConsensusCoverage.ReadersAtoms.electedExact
  | `ConsensusCoverage.ReadersAtoms.electionExact => #["elections"]
  | `ConsensusCoverage.ReadersAtoms.grantedIn => #["grants"]
  | `ConsensusCoverage.ReadersAtoms.voteStamps => #["votes"]
  | `CCF.MultiNodeTransitionSystem.State.rec
  | `CCF.MultiNodeTransitionSystem.State.recOn
  | `CCF.MultiNodeTransitionSystem.State.casesOn => #["node_table", "queue"]
  | `CCF.MultiNodeTransitionSystem.State.network
  | `ConsensusCoverage.LeaderEffect.probes => #["queue"]
  | _ => #[]

private def project (env : Environment) (name : Name) (i : Nat) : Option Name :=
  (getStructureFields env name)[i]?.map fun field => name ++ field

private partial def collect (env : Environment) (e : Expr)
    (names : Std.HashSet Name := {}) (seen : Std.HashSet Expr := {}) :
    Std.HashSet Name × Std.HashSet Expr := Id.run do
  if seen.contains e then return (names, seen)
  let seen := seen.insert e
  match e with
  | .const n _ => return (names.insert n, seen)
  | .proj n i arg =>
    let names := if let some field := project env n i then names.insert field else names
    return collect env arg names seen
  | .app f a =>
    let (names, seen) := collect env f names seen
    return collect env a names seen
  | .lam _ _ body _ | .mdata _ body => return collect env body names seen
  | .letE _ _ value body _ =>
    let (names, seen) := collect env value names seen
    return collect env body names seen
  | _ => return (names, seen)

private def inProject (n : Name) : Bool :=
  let n := surface n
  [`ConsensusCoverage, `Consensus, `CCF].any (·.isPrefixOf n)

private def summarize (env : Environment) (root : Name)
    (memo : Std.HashMap Name (Array Name)) :
    Std.HashSet String × Std.HashMap Name (Array Name) := Id.run do
  let mut flags : Std.HashSet String := {}
  let mut visited : Std.HashSet Name := {}
  let mut memo := memo
  let mut pending := #[root]
  repeat
    let some n := pending.back? | break
    pending := pending.pop
    if visited.contains n then continue
    visited := visited.insert n
    for tag in inputs n do flags := flags.insert tag
    if !inProject n then continue
    if let some calls := memo[n]? then
      pending := pending ++ calls
    else if let some (.defnInfo d) := env.find? n then
      let (names, _) := collect env d.value
      let calls := names.toArray
      memo := memo.insert n calls
      pending := pending ++ calls
  return (flags, memo)

run_cmd liftTermElabM do
  let some file ← IO.getEnv "CCF_READERS_DEPENDENCIES" | return
  let env ← getEnv
  let cols := #["configuration", "node_table", "history_input", "historical_nodes", "commits",
    "canonical", "observations", "leaders", "elections", "grants", "votes", "action", "envelope",
    "changed_bit", "queue"]
  let constructors := (← getConstInfoInduct ``Classes.StepBranch).ctors
  let functions := `ConsensusCoverage.ReadersCompiler.R
  let dispatch ← getConstInfo `ConsensusCoverage.ReadersCompiler.readView
  let used := dispatch.value!.getUsedConstants
  let out ← IO.FS.Handle.mk file .write
  out.putStrLn (String.intercalate "\t" ("reader" :: "covered" :: cols.toList))
  let mut memo := {}
  for ctor in constructors do
    let name := functions ++ ("step_" ++ ctor.getString!).toName
    let covered := used.contains name
    let (flags, next) := summarize env name memo
    memo := next
    out.putStrLn (String.intercalate "\t"
      (ctor.toString :: (if covered then "1" else "0") ::
        cols.toList.map (fun field => if !covered then "-" else if flags.contains field then "1" else "0")))
  out.flush

end
end ConsensusCoverage.ReadersDependencies
