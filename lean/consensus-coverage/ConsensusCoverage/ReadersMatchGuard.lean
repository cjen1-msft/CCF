module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.GuardedDomain
import all ConsensusCoverage.Historical
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.ReadersMatchGuard

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety
open ConsensusCoverage.ReadersAtoms

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

public def afterPeers (x : XView) : List NodeID :=
  ((histNodes (x.base.after :: x.base.before :: x.base.past)).map Prod.fst).eraseDups

theorem positiveAfter [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    {x : XView} {c : Ctx f t} (ok : x.Matches c) {peer : NodeID}
    (primary : x.base.post.role = .primary) (other : ¬ peer = x.base.actor)
    (positive : 0 < x.base.post.matchIndex peer) :
    peer ∈ afterPeers x := by
  have now := (X.now_after ok ..).mpr (X.post_mem ok)
  obtain ⟨acker, _, seen, _⟩ := c.inv_step.match_ack _ _ peer now primary other positive
  change (f.advance t).logs.seen peer acker.currentTerm acker.log at seen
  rw [X.logs_after ok, (Historical.logFacts_correct _).seen] at seen
  obtain ⟨_, ⟨s, hs, mem⟩, _⟩ := seen
  exact List.mem_eraseDups.mpr (List.mem_map_of_mem (mem_histNodes hs mem))

end ConsensusCoverage.ReadersMatchGuard
