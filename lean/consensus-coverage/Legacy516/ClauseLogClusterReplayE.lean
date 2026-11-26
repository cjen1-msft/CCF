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

public def batchE : List Sample := [
  sample! 6 13 3 "11110101111011110101111001000100000111000000000110000000000" 3,
  sample! 6 14 3 "10000101001110000101001100000010100110000110000110001111111" 3,
  sample! 6 15 3 "11110101111011110101111000000100000110100000000110000000000" 1,
  sample! 18 0 2 "00000000000000000000000000000000000001000000000000000000000" 2,
  sample! 19 0 2 "00000001101000000001101001000000000000000000000100000000000" 2,
  sample! 20 2 3 "00000001111100000001111101110000000001000000000110000000000" 3,
  sample! 21 4 2 "10000101001010000101001000000010100000001010000110001011110" 2]

end ConsensusCoverage.ClauseLogCluster.Replay
