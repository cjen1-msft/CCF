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

public def batchA : List Sample := [
  sample! 0 0 2 "10111001010010111001010010110000000100100000000000000000000" 1,
  sample! 0 1 1 "10111001010010111001010010110000000100100000000000000000000" 1,
  sample! 1 0 2 "10111001010110111001010110110000000100100000000000000000000" 3,
  sample! 2 0 2 "10111001010110111001010110110000000101000000000000000000000" 2,
  sample! 2 1 2 "11110101111011110101111001110000000111000000000110000000000" 2,
  sample! 2 2 2 "10000101001110000101001100000010100000001010000110001011110" 3,
  sample! 2 3 3 "11110101111011110101111000000100000110100000000110000000000" 3]

end ConsensusCoverage.ClauseLogCluster.Replay
