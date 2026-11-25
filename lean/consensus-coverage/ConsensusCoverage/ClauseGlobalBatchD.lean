module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ClauseGlobalSamples
import all ConsensusCoverage.ClauseGlobalSamples
import all ConsensusCoverage.ClauseWideTree
import all ConsensusCoverage.ReadersTotal

namespace ConsensusCoverage.ClauseGlobalBatchD

open ClauseGlobalSamples

set_option maxRecDepth 16384
set_option maxHeartbeats 0
set_option Elab.async false

private def s51 : List Sample := [global_sample! 1883616033913 0 109 10,
  global_sample! 1883616033913 1 42 19,
  global_sample! 1889785838328 0 49 2,
  global_sample! 1889785838328 1 6 10]

private def s52 : List Sample := [global_sample! 1889785838328 2 83 3,
  global_sample! 1889785838328 3 117 14,
  global_sample! 1889785854713 0 83 2,
  global_sample! 1889785854713 1 177 11]

private def s53 : List Sample := [global_sample! 1889785854713 2 175 4,
  global_sample! 1889785854713 3 175 3,
  global_sample! 1889785854713 4 109 8,
  global_sample! 1889785854713 5 179 13]

private def s54 : List Sample := [global_sample! 1889785854713 6 121 5,
  global_sample! 1889785854713 7 173 5,
  global_sample! 1889785854713 8 140 3,
  global_sample! 1889785854713 9 139 4]

private def s55 : List Sample := [global_sample! 1889785855737 0 116 16,
  global_sample! 1889785855737 1 73 14,
  global_sample! 1889786100474 0 50 2,
  global_sample! 1889786100474 1 86 3]

private def s56 : List Sample := [global_sample! 1889786116859 0 52 2,
  global_sample! 1889786116859 1 87 7,
  global_sample! 1889786116859 2 87 6,
  global_sample! 1918785256184 0 111 2]

private def s57 : List Sample := [global_sample! 1918785256184 1 112 7,
  global_sample! 1918785256184 2 176 9,
  global_sample! 1918785256184 3 22 5,
  global_sample! 1918785256184 4 110 9]

private def s58 : List Sample := [global_sample! 1918785257208 0 27 16,
  global_sample! 1918785257208 1 116 17,
  global_sample! 1918785272569 0 45 2,
  global_sample! 1918785272569 1 6 11]

private def s59 : List Sample := [global_sample! 1918785272569 2 121 3,
  global_sample! 1918785272569 3 117 15,
  global_sample! 1918785518330 0 51 2,
  global_sample! 1918785518330 1 70 3]

private def s60 : List Sample := [global_sample! 1918785518330 2 91 12,
  global_sample! 1918785518330 3 141 7,
  global_sample! 2164663762041 0 24 10,
  global_sample! 2164663762041 1 40 14]

private def s61 : List Sample := [global_sample! 2164663778425 0 144 11,
  global_sample! 2164663778425 1 88 16,
  global_sample! 2193663193209 0 5 12,
  global_sample! 2193663193209 1 121 9]

private def s62 : List Sample := [global_sample! 2193663193209 2 178 13,
  global_sample! 2193663193209 3 133 10,
  global_sample! 2193663193209 4 141 6,
  global_sample! 2193663193209 5 166 5]

private def s63 : List Sample := [global_sample! 2193663193209 6 130 6,
  global_sample! 2193663193209 7 138 6,
  global_sample! 2193663193209 8 145 17,
  global_sample! 2193663196281 0 136 9]

private def s64 : List Sample := [global_sample! 2193663196281 1 98 8,
  global_sample! 2193663196281 2 138 7,
  global_sample! 2193663196281 3 73 8,
  global_sample! 2193663196281 4 128 7]

private def s65 : List Sample := [global_sample! 2193663196281 5 93 11]

public def samples := [s51, s52, s53, s54, s55, s56, s57, s58, s59, s60, s61, s62, s63, s64, s65].flatten

end ConsensusCoverage.ClauseGlobalBatchD
