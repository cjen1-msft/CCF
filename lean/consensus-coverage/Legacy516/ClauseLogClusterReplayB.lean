module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ClauseLogClusterReplay
import all ConsensusCoverage.ClauseLogClusterReplay
import all ConsensusCoverage.HandReadersElectionBPrefixAccept
import all ConsensusCoverage.HandReadersElectionBPrefixCopies
import all ConsensusCoverage.HandReadersElectionBPrefixDirect
import all ConsensusCoverage.HandReadersElectionBPrefixLogs

namespace ConsensusCoverage.ClauseLogCluster.Replay

set_option maxRecDepth 16384
set_option maxHeartbeats 0
set_option pp.maxSteps 150

public def batchB : List Sample := [
  sample! 2 4 3 "00000000000000000000000000000000000001000000000000000000000" 3,
  sample! 2 5 3 "11000101101011000101101000000011000110010100000110001111000" 1,
  sample! 2 6 1 "10111011010110111011010110110000000101000000000000000000000" 1,
  sample! 3 1 2 "11110101111011110101111001000000000110000000000110000000000" 2,
  sample! 3 2 2 "11000101101011000101101001000000000110000000000110000000000" 2,
  sample! 3 3 2 "00000000000000000000000000000000000000000000000000000000000" 2,
  sample! 3 5 2 "00000001101000000001101001000000000000000000000110000000000" 2]

end ConsensusCoverage.ClauseLogCluster.Replay
