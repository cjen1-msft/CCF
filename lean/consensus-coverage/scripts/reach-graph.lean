module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

meta import Lean
import all ConsensusCoverage.PinnedClasses
import all ConsensusCoverage.SolvedWitnesses

meta section

open Lean

/-- Edges and fingerprints to locate old proof references in a regenerated reach DAG.
Fingerprints are only migration hints; Lean checks the resulting proofs. -/
private def reachChildren (ns : Name) (e : Expr) : Array Name :=
  e.getUsedConstants.filter fun n => n.getPrefix == ns && n.getString!.startsWith "reach_"

private def fingerprint (e : Expr) (map : Std.HashMap Name Nat) : UInt64 :=
  (e.replace fun
    | .const name levels => (map[name]?).map fun key => .const (.num `reach key) levels
    | _ => none).hash

private abbrev Digests := StateRefT (Std.HashMap Name UInt64) CoreM

private partial def transitive (n : Name) : Digests UInt64 := do
  if let some h := (← get)[n]? then return h
  let ci ← getConstInfo n
  let e := ci.value!
  let mut keys := {}
  for child in reachChildren n.getPrefix e do
    keys := keys.insert child (← transitive child).toNat
  let h := mixHash ci.type.hash (fingerprint e keys)
  modify fun cache => cache.insert n h
  return h

set_option maxHeartbeats 0 in
set_option maxRecDepth 8192 in
#eval show CoreM Unit from do
  let some path ← IO.getEnv "REACH_OUT" | return
  let out ← IO.FS.Handle.mk path .write
  let nodes := (← getEnv).constants.toList.filterMap fun (n, ci) => do
    guard (n.getPrefix == `ConsensusCoverage.PinnedClasses ||
      n.getPrefix == `ConsensusCoverage.SolvedWitnesses)
    let stem := n.getString!
    guard (stem.startsWith "reach_" || stem.startsWith "step_" || stem.startsWith "state_")
    let .defnInfo _ := ci | none
    return n
  let digests ← (nodes.mapM transitive).run' {}
  for (name, digest) in nodes.zip digests do
    let ci ← getConstInfo name
    let body := ci.value!
    let children := reachChildren name.getPrefix body
    let positions := children.foldl (fun (m : Std.HashMap Name Nat) n => m.insert n m.size) {}
    out.putStrLn <| "\t".intercalate [
      toString name, toString ci.type.hash, toString (fingerprint body positions), toString digest,
      ",".intercalate (children.toList.map Name.getString!)]
