module

meta import Lean
import all ConsensusCoverage.Classes
import all Consensus.Proofs.SafetyInvariant

/-!
Print the named generated definitions (names from env `DEFS`, space-separated).
Set `DEFS_FORMAT=raw` to print expression strings without elaborator pretty-printing.
Set `DEFS_OUT` to write directly to a file instead of buffering a Lean message.
-/

open Lean Meta

#eval show MetaM Unit from do
  let some defs ← IO.getEnv "DEFS" | return
  let raw := (← IO.getEnv "DEFS_FORMAT") == some "raw"
  let out ← match ← IO.getEnv "DEFS_OUT" with
    | some path => pure (IO.FS.Stream.ofHandle (← IO.FS.Handle.mk path .write))
    | none => IO.getStdout
  for s in defs.splitOn " " do
    let n := `ConsensusCoverage.Classes ++ s.toName
    let value := (← getConstInfo n).value!
    out.putStrLn s!"== {s}"
    if raw then
      out.putStrLn (toString value)
    else
      out.putStrLn (← ppExpr value).pretty
  out.flush
