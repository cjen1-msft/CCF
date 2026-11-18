module

meta import Relevance.Generate
public import Consensus.Proofs.SafetyInvariant
public import Consensus.Proofs.Direct
import all Consensus.Proofs.SafetyInvariant
import all Consensus.Proofs.Direct

/-!
# The generated coverage classes, as a module

The same `relevance_generate` call as `scripts/coverage.lean` (shared lemma cases), compiled
once so that the evaluator can import the class definitions instead of regenerating them.
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
