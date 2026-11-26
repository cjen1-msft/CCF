module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ClauseGlobalSamples
import all ConsensusCoverage.ClauseGlobalSamples
import all ConsensusCoverage.ClauseWideTree
import all ConsensusCoverage.ReadersTotal

namespace ConsensusCoverage.ClauseGlobalBatchC

open ClauseGlobalSamples

set_option maxRecDepth 16384
set_option maxHeartbeats 0
set_option Elab.async false

private def s34 : List Sample := [global_sample! 1855426116345 1 170 6,
  global_sample! 1855426265091 0 58 2,
  global_sample! 1855426265091 1 21 7,
  global_sample! 1875290095616 0 73 7]

private def s35 : List Sample := [global_sample! 1875290095616 1 86 8,
  global_sample! 1875290095616 2 33 11,
  global_sample! 1875290095616 3 79 9,
  global_sample! 1875290234881 0 140 2]

private def s36 : List Sample := [global_sample! 1875290234881 1 30 6,
  global_sample! 1875290300416 0 60 6,
  global_sample! 1875290300416 1 143 5,
  global_sample! 1875290300488 0 174 2]

private def s37 : List Sample := [global_sample! 1875290300488 1 121 4,
  global_sample! 1875290300536 0 33 10,
  global_sample! 1875290300536 1 79 10,
  global_sample! 1875290300536 2 175 6]

private def s38 : List Sample := [global_sample! 1875290307704 0 180 16,
  global_sample! 1875290307704 1 91 17,
  global_sample! 1875290333305 0 38 13,
  global_sample! 1875290333305 1 85 15]

private def s39 : List Sample := [global_sample! 1875290333305 2 179 11,
  global_sample! 1875290333305 3 180 17,
  global_sample! 1875290333305 4 127 4,
  global_sample! 1875290333305 5 87 10]

private def s40 : List Sample := [global_sample! 1875290340217 0 130 7,
  global_sample! 1875290340217 1 176 10,
  global_sample! 1875290340473 0 109 7,
  global_sample! 1875290340473 1 117 9]

private def s41 : List Sample := [global_sample! 1875290340473 2 177 8,
  global_sample! 1875290562638 0 111 3,
  global_sample! 1875290562638 1 178 14,
  global_sample! 1875290562686 0 179 12]

private def s42 : List Sample := [global_sample! 1875290562686 1 160 3,
  global_sample! 1875290562686 2 180 18,
  global_sample! 1875290569854 0 112 8,
  global_sample! 1875290569854 1 117 12]

private def s43 : List Sample := [global_sample! 1875290569854 2 176 11,
  global_sample! 1883377482617 0 131 5,
  global_sample! 1883377482617 1 30 16,
  global_sample! 1883411554425 0 30 3]

private def s44 : List Sample := [global_sample! 1883411554425 1 131 4,
  global_sample! 1883411561209 0 42 3,
  global_sample! 1883411561209 1 116 10,
  global_sample! 1883411561593 0 95 19]

private def s45 : List Sample := [global_sample! 1883411561593 1 42 7,
  global_sample! 1883479711745 0 94 16,
  global_sample! 1883479711745 1 144 10,
  global_sample! 1883479711865 0 42 9]

private def s46 : List Sample := [global_sample! 1883479711865 1 128 6,
  global_sample! 1883479718777 0 165 4,
  global_sample! 1883479718777 1 117 7,
  global_sample! 1883479718777 2 145 16]

private def s47 : List Sample := [global_sample! 1883479718777 3 73 6,
  global_sample! 1883479718777 4 95 18,
  global_sample! 1883479719033 0 116 13,
  global_sample! 1883479719033 1 30 17]

private def s48 : List Sample := [global_sample! 1883616026745 0 121 7,
  global_sample! 1883616026745 1 131 3,
  global_sample! 1883616026745 2 178 9,
  global_sample! 1883616026745 3 89 8]

private def s49 : List Sample := [global_sample! 1883616026745 4 85 19,
  global_sample! 1883616026745 5 5 10,
  global_sample! 1883616026745 6 209 5,
  global_sample! 1883616026745 7 180 19]

private def s50 : List Sample := [global_sample! 1883616033657 0 98 6,
  global_sample! 1883616033657 1 128 5,
  global_sample! 1883616033657 2 37 11,
  global_sample! 1883616033657 3 93 7]

public def samples := [s34, s35, s36, s37, s38, s39, s40, s41, s42, s43, s44, s45, s46, s47, s48, s49, s50].flatten

end ConsensusCoverage.ClauseGlobalBatchC
