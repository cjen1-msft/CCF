module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ExplorerGhost
import all ConsensusCoverage.ExplorerGhost
import all ConsensusCoverage.GrantFrontier

namespace ConsensusCoverage.CensusGrants

open Consensus Consensus.Model Consensus.Model.Node ExplorerGhost

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

/-- Processing one eligible voter preserves exactly the union of its old
grant cone and the requests up to date with the voter's pre-state. In
particular recording only the lesser threshold does not lose requests. -/
public theorem eligible_update (g : Ghost) (before after : Model.State) (v c : NodeID)
    (x y : NodeState) (pre : before.nodes.lookup v = some x) (vote : y.votedFor = some c)
    (term : x.currentTerm ≤ y.currentTerm)
    (eligible : (v == c || g.seen.any fun (n, k, _) => n == c && k == y.currentTerm) = true)
    (r : RequestVoteRequest) :
    let next := {g with grants := (extendGrants g before {after with nodes := [(v, y)]}).1}
    next.granted v c y.currentTerm r = (g.granted v c y.currentTerm r || decide (voteLogUpToDate x r)) := by
  cases old : g.grants.lookup (v, c, y.currentTerm) with
  | none =>
    simp [extendGrants, pre, vote, term, eligible, Ghost.granted, GrantFrontier.minimum,
      thresholdLE, voteLogUpToDate, old]
    grind
  | some cutoff =>
    rcases cutoff with ⟨k, i⟩
    simp [extendGrants, pre, vote, term, eligible, Ghost.granted, GrantFrontier.minimum,
      thresholdLE, voteLogUpToDate, old]
    split <;> simp <;> grind

end ConsensusCoverage.CensusGrants
