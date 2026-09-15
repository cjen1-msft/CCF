-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicReceive
import Shared.SymbolicNormalizeCacheTests

set_option autoImplicit false

namespace Symbolic.NormalizeProfile

open NormalizeCacheTests

private def headShape : Nat → {s : Ty} → Expr s → String
  | 0, _, _ => "..."
  | n + 1, _, .fst value => s!"fst({headShape n value})"
  | n + 1, _, .snd value => s!"snd({headShape n value})"
  | n + 1, _, .leftD value _ => s!"leftD({headShape n value})"
  | n + 1, _, .rightD value _ => s!"rightD({headShape n value})"
  | n + 1, _, .isLeft value => s!"isLeft({headShape n value})"
  | n + 1, _, .ite condition _ _ => s!"ite({headShape n condition})"
  | _, _, .named group slot _ => s!"named({group},{slot})"
  | _, _, .pair _ _ => "pair"
  | _, _, .eq _ _ => "eq"
  | _, _, .lt _ _ => "lt"
  | _, _, .and _ _ => "and"
  | _, _, .not _ => "not"
  | _, _, .get? _ _ => "get?"
  | _, _, .contains _ _ => "contains"
  | _, _, .length _ => "length"
  | _, _, _ => "other"

private def report (state : Expr.NormalizationState) : IO Unit := do
  IO.println s!"stats={repr state.stats}"
  let buckets := state.entries.toList.mergeSort (fun a b => a.2.length ≥ b.2.length)
  IO.println s!"buckets={buckets.length} entries={buckets.foldl (fun n b => n + b.2.length) 0}"
  for (key, bucket) in buckets.take 8 do
    let shapes := (bucket.take 3).map fun ⟨_, expression, _⟩ => headShape 8 expression
    IO.println s!"bucket={key} size={bucket.length} examples={shapes}"

private def run {s : Ty} (label : String) (expressions : List (Expr s)) : IO Unit := do
  IO.eprintln s!"normalizing {label}"
  let start ← IO.monoMsNow
  let cell ← IO.mkRef ((expressions.mapM Expr.normalizeMemoM).run { stats := some {} })
  let (_, state) ← cell.get
  IO.println s!"{label} ms={(← IO.monoMsNow) - start}"
  report state

def selectors (depth : Nat) : IO Unit :=
  run s!"selectors depth={depth}" (fields depth (.named 0 0 (record depth)))

def receive (guard : Bool) : IO Unit := do
  let bounds : CCFRaft.BoundedState.Bounds := ⟨16, 4, 8, 1, 1⟩
  let entry := Expr.named 0 0 (CCFRaft.SymbolicModel.freshEntry bounds 0)
  if guard then
    let node : CCFRaft.Node := ⟨14, by decide⟩
    let transition := CCFRaft.SymbolicReceive.step bounds entry node node
    run "fresh receive guard" [transition.enabled]
  else
    run "fresh entry bounds" [CCFRaft.SymbolicModel.stateWithin bounds entry]

end Symbolic.NormalizeProfile

def main (args : List String) : IO Unit :=
  match args with
  | ["--selectors", depth] =>
      match depth.toNat? with
      | some depth => Symbolic.NormalizeProfile.selectors depth
      | none => throw (IO.userError "depth must be a natural number")
  | ["--entry"] => Symbolic.NormalizeProfile.receive false
  | ["--guard"] => Symbolic.NormalizeProfile.receive true
  | _ => throw (IO.userError "usage: --selectors DEPTH | --entry | --guard")
