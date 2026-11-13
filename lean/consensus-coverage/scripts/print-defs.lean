module

meta import Lean
import all ConsensusCoverage.Classes
import all Consensus.Proofs.SafetyInvariant

/-! Print the named generated definitions (names from env `DEFS`, space-separated). -/

open Lean Meta

#eval show MetaM Unit from do
  let some defs ← IO.getEnv "DEFS" | return
  for s in defs.splitOn " " do
    let n := `ConsensusCoverage.Classes ++ s.toName
    IO.println s!"== {s}"
    IO.println (← ppExpr (← getConstInfo n).value!).pretty
