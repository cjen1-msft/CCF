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

public def batchD : List Sample := [
  sample! 5 7 3 "11110101111011110101111001000000000110000000000110000000000" 3,
  sample! 5 8 3 "11000101101011000101101001000000000110000000000110000000000" 3,
  sample! 5 12 3 "11000111101111000111101111000000010110000001000111000000000" 3,
  sample! 6 9 3 "11000111101111000111101111000000010110000001000110100000000" 3,
  sample! 6 10 3 "10111011010110111011010110110000000101000000000000000000000" 3,
  sample! 6 11 3 "11110101111011110101111001110000000111000000000110000000000" 3,
  sample! 6 12 3 "11000101101011000101101001000011000110010100000110001111111" 3]

end ConsensusCoverage.ClauseLogCluster.Replay
