module

meta import Relevance.Generate
import all Consensus.Proofs.SafetyInvariant

/-!
# Shared walk of the consensus safety proof, measurement only

The call of `generate.lean` with `(shared := true)`: every theorem is walked once and its call
sites are recorded (no per-path inlining). Writes the branch table to the file named by
`RELEVANCE_TABLE`, if set. Same inputs as `generate.lean`: the step is one `Ctx` (a step of an
execution with the invariant holding before it) from history `before :: rest` to
`after :: before :: rest`; the state is a history satisfying `Inv`; `inv_of_exec` turns an
execution into the invariant at its head, so theorems taking an execution are
state-level.

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
    (after before : Model.State) (rest : History) => Ctx after before rest)
  (pre := fun [Config.InitialConfiguration]
    (_ before : Model.State) (rest : History) => before :: rest)
  (post := fun [Config.InitialConfiguration]
    (after before : Model.State) (rest : History) => after :: before :: rest)
  (state := fun [Config.InitialConfiguration] (history : History) => Inv history)
  (derive := [Consensus.Proofs.Safety.inv_of_exec])
  (shared := true)

open Lean in
#eval show MetaM Unit from do
  let some path ← IO.getEnv "RELEVANCE_TABLE" | return
  let .lit (.strVal s) := (← getConstInfo `ConsensusCoverage.Shared.table).value! | return
  IO.FS.writeFile path s
