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

public def batchC : List Sample := [
  sample! 3 6 2 "11000101101111000101101111000000010110000001000110100000000" 2,
  sample! 4 6 1 "00000000000000000000000000000000000000000000000000000000000" 1,
  sample! 4 7 1 "11110101111011110101111001000000000110000000000110000000000" 1,
  sample! 4 8 1 "11000101101011000101101001000000000110000000000110000000000" 1,
  sample! 4 12 1 "11000111101111000111101111000000010110000001000111000000000" 1,
  sample! 5 5 3 "11000101101011000101101000000011000110010100000110001111000" 3,
  sample! 5 6 3 "00000000000000000000000000000000000000000000000000000000000" 3]

end ConsensusCoverage.ClauseLogCluster.Replay
