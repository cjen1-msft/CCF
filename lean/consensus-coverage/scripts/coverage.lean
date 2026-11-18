module

meta import Relevance.Generate
import all Consensus.Proofs.SafetyInvariant
import all Consensus.Proofs.Direct

/-!
# Coverage classes of the marked consensus safety proof (shared lemma cases)

One `relevance_generate` call with `(shared := true)` over the public safety theorems (log
safety, election safety) and the two node-local ones. `Ctx f after` supplies one protocol
transition and the pre-state invariant. Its endpoints are `f` and `f.advance after`.
State classes are extracted from `Inv f`. Set `RELEVANCE_TABLE` to write the branch table.

Run from the repository root (the workspace is out of tree):

    WS=$(python3 lean/relevance/scripts/workspace.py consensus-coverage)
    lake -d $WS/consensus-coverage env lean $PWD/lean/consensus-coverage/scripts/coverage.lean
-/

set_option maxHeartbeats 0

open Consensus Consensus.Proofs Consensus.Proofs.Safety

@[expose] public section

relevance_generate ConsensusCoverage.Classes
  (scope := Consensus.Proofs) (package := [Consensus])
  (roots := [Consensus.Proofs.CommittedLogs.committed_logs_prefix,
    Consensus.Proofs.Election.election_safety,
    Consensus.Proofs.Direct.single_node_committed_log_monotonic,
    Consensus.Proofs.Direct.committed_frontier_is_signature])
  (step := fun [Config.InitialConfiguration]
    (f : Frame) (after : Model.State) => Ctx f after)
  (pre := fun [Config.InitialConfiguration]
    (f : Frame) (_ : Model.State) => f)
  (post := fun [Config.InitialConfiguration]
    (f : Frame) (after : Model.State) => f.advance after)
  (state := fun [Config.InitialConfiguration] (f : Frame) => Inv f)
  (shared := true)

end

open Lean in
#eval show MetaM Unit from do
  let some path ← IO.getEnv "RELEVANCE_TABLE" | return
  let .lit (.strVal s) := (← getConstInfo `ConsensusCoverage.Classes.table).value! | return
  IO.FS.writeFile path s
