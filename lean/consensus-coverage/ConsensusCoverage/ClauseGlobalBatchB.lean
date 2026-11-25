module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ClauseGlobalSamples
import all ConsensusCoverage.ClauseGlobalSamples
import all ConsensusCoverage.ClauseWideTree
import all ConsensusCoverage.ReadersTotal

namespace ConsensusCoverage.ClauseGlobalBatchB

open ClauseGlobalSamples

set_option maxRecDepth 16384
set_option maxHeartbeats 0
set_option Elab.async false

private def s17 : List Sample := [global_sample! 1236950825721 0 3 1,
  global_sample! 1236950825721 1 113 18,
  global_sample! 1236950825721 2 172 7,
  global_sample! 1256814804992 0 124 10]

private def s18 : List Sample := [global_sample! 1256814804992 1 41 4,
  global_sample! 1256814804992 2 62 10,
  global_sample! 1256814804992 3 192 4,
  global_sample! 1256814804992 4 193 4]

private def s19 : List Sample := [global_sample! 1256814804992 5 26 10,
  global_sample! 1256814944257 0 21 1,
  global_sample! 1256814944257 1 32 1,
  global_sample! 1256815009792 0 26 1]

private def s20 : List Sample := [global_sample! 1256815009792 1 194 5,
  global_sample! 1256815009864 0 175 1,
  global_sample! 1256815009864 1 196 13,
  global_sample! 1264936263801 0 36 5]

private def s21 : List Sample := [global_sample! 1264936263801 1 125 10,
  global_sample! 1264936270585 0 3 2,
  global_sample! 1264936270585 1 113 19,
  global_sample! 1265004322817 0 35 7]

private def s22 : List Sample := [global_sample! 1265004322817 1 3 5,
  global_sample! 1265140736121 0 102 13,
  global_sample! 1265140736121 1 90 7,
  global_sample! 1265140736121 2 23 15]

private def s23 : List Sample := [global_sample! 1265140736121 3 125 9,
  global_sample! 1265140743033 0 113 21,
  global_sample! 1265140743033 1 3 4,
  global_sample! 1265140743033 2 28 8]

private def s24 : List Sample := [global_sample! 1271310547704 0 23 9,
  global_sample! 1271310547704 1 114 18,
  global_sample! 1271310563969 0 26 2,
  global_sample! 1271310563969 1 137 2]

private def s25 : List Sample := [global_sample! 1271310564089 0 101 2,
  global_sample! 1271310564089 1 113 17,
  global_sample! 1271310564089 2 21 2,
  global_sample! 1271310565113 0 102 11]

private def s26 : List Sample := [global_sample! 1271310565113 1 102 8,
  global_sample! 1300309965512 0 48 2,
  global_sample! 1300309965512 1 129 3,
  global_sample! 1300309965560 0 36 3]

private def s27 : List Sample := [global_sample! 1300309965560 1 90 9,
  global_sample! 1300309965560 2 115 18,
  global_sample! 1300309966584 0 26 18,
  global_sample! 1300309966584 1 107 12]

private def s28 : List Sample := [global_sample! 1300309981825 0 26 0,
  global_sample! 1300309981825 1 194 4,
  global_sample! 1300309981945 0 2 1,
  global_sample! 1300309981945 1 26 4]

private def s29 : List Sample := [global_sample! 1300309981945 2 114 19,
  global_sample! 1325534748748 0 20 1,
  global_sample! 1325534748748 1 162 3,
  global_sample! 1575187889273 0 3 6]

private def s30 : List Sample := [global_sample! 1575187889273 1 28 11,
  global_sample! 1717987123272 0 46 1,
  global_sample! 1717987123272 1 177 12,
  global_sample! 1737851347064 0 80 8]

private def s31 : List Sample := [global_sample! 1737851347064 1 70 4,
  global_sample! 1737851379833 0 81 9,
  global_sample! 1737851379833 1 96 4,
  global_sample! 1737851379833 2 69 5]

private def s32 : List Sample := [global_sample! 1752346901241 0 110 11,
  global_sample! 1752346901241 1 179 14,
  global_sample! 1855426109561 0 30 12,
  global_sample! 1855426109561 1 178 11]

private def s33 : List Sample := [global_sample! 1855426109561 2 182 21,
  global_sample! 1855426109561 3 93 15,
  global_sample! 1855426109561 4 179 6,
  global_sample! 1855426116345 0 117 2]

public def samples := [s17, s18, s19, s20, s21, s22, s23, s24, s25, s26, s27, s28, s29, s30, s31, s32, s33].flatten

end ConsensusCoverage.ClauseGlobalBatchB
