module

meta import Relevance.Generate
import all Consensus.Proofs.SafetyInvariant

/-!
# Shared walk of the consensus safety proof, measurement only

The call of `generate.lean` with `(shared := true)`: every theorem is walked once and its call
sites are recorded (no per-path inlining). Writes the branch table to the file named by
`RELEVANCE_TABLE`, if set. Same inputs as `generate.lean`: `Ctx f after` supplies one protocol
transition and the pre-state invariant. Its endpoints are `f` and `f.advance after`.
State classes are extracted from `Inv f`.

Run from the repository root (the workspace is out of tree):

    WS=$(python3 lean/relevance/scripts/workspace.py consensus-coverage)
    lake -d $WS/consensus-coverage env lean $PWD/lean/consensus-coverage/scripts/shared.lean
-/

set_option maxHeartbeats 0

open Consensus Consensus.Proofs Consensus.Proofs.Safety

relevance_generate ConsensusCoverage.Shared
  (scope := Consensus.Proofs) (package := [Consensus])
  (roots := [Consensus.Proofs.CommittedLogs.committed_logs_prefix,
    Consensus.Proofs.Election.election_safety])
  (step := fun [Config.InitialConfiguration]
    (f : Frame) (after : Model.State) => Ctx f after)
  (pre := fun [Config.InitialConfiguration]
    (f : Frame) (_ : Model.State) => f)
  (post := fun [Config.InitialConfiguration]
    (f : Frame) (after : Model.State) => f.advance after)
  (state := fun [Config.InitialConfiguration] (f : Frame) => Inv f)
  (shared := true)

open Lean in
#eval show MetaM Unit from do
  let some path ← IO.getEnv "RELEVANCE_TABLE" | return
  let .lit (.strVal s) := (← getConstInfo `ConsensusCoverage.Shared.table).value! | return
  IO.FS.writeFile path s
