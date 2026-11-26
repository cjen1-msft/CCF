module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.CensusQueueStep
public meta import ConsensusCoverage.CensusQueueElection
public meta import ConsensusCoverage.CensusQueueHints
public meta import ConsensusCoverage.CensusQueueSearch

namespace ConsensusCoverage.CensusQueueCertificate

/-- For a fixed step, try constructive premise rules and then search the
normalized formula. Nothing about a failed search is a negative theorem. -/
macro "queue_certify " s:term : tactic =>
  `(tactic| first | queue_win $s | queue_hint $s | queue_prove)

end ConsensusCoverage.CensusQueueCertificate
