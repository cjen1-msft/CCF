module

meta import Relevance.Generate
import all Consensus.Proofs.SafetyInvariant
import all Consensus.Proofs.Direct

/-!
# Coverage classes of the marked consensus safety proof (shared lemma cases)

One `relevance_generate` call with `(shared := true)` over the public safety theorems (log
safety, election safety) and the two node-local ones. The step is one `Ctx` (a step of an
execution with the invariant holding before it) from history `before :: rest` to
`after :: before :: rest`; the state is a history satisfying `Inv`; `good_of_exec` turns an
execution into the invariant at every point of it, so theorems taking an execution are
state-level. Writes the branch table to the file named by `RELEVANCE_TABLE`, if set.

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
  (step := fun [Config.InitialConfiguration] (nodes : List Model.Node.NodeID)
    (after before : Model.State) (rest : History) => Ctx nodes after before rest)
  (pre := fun [Config.InitialConfiguration] (_ : List Model.Node.NodeID)
    (_ before : Model.State) (rest : History) => before :: rest)
  (post := fun [Config.InitialConfiguration] (_ : List Model.Node.NodeID)
    (after before : Model.State) (rest : History) => after :: before :: rest)
  (state := fun [Config.InitialConfiguration] (history : History) => Inv history)
  (derive := [Consensus.Proofs.Safety.good_of_exec])
  (shared := true)

end

open Lean in
#eval show MetaM Unit from do
  let some path ← IO.getEnv "RELEVANCE_TABLE" | return
  let .lit (.strVal s) := (← getConstInfo `ConsensusCoverage.Classes.table).value! | return
  IO.FS.writeFile path s
