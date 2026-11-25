module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ClauseGlobalSamples
import all ConsensusCoverage.ClauseGlobalSamples
import all ConsensusCoverage.ClauseWideTree
import all ConsensusCoverage.ReadersTotal

namespace ConsensusCoverage.ClauseGlobalBatchA

open ClauseGlobalSamples

set_option maxRecDepth 16384
set_option maxHeartbeats 0
set_option Elab.async false

private def s0 : List Sample := [global_sample! 618475528313 0 134 8,
  global_sample! 618475528313 1 69 9,
  global_sample! 618475535097 0 186 5,
  global_sample! 618475535097 1 187 10]

private def s1 : List Sample := [global_sample! 637819640568 0 175 10,
  global_sample! 638339514368 0 75 13,
  global_sample! 638339514368 1 25 7,
  global_sample! 638339514368 2 34 7]

private def s2 : List Sample := [global_sample! 638339752057 0 92 12,
  global_sample! 638339752057 1 84 12,
  global_sample! 638339752057 2 181 16,
  global_sample! 638339752057 3 59 4]

private def s3 : List Sample := [global_sample! 638339759225 0 96 10,
  global_sample! 638339759225 1 80 18,
  global_sample! 646460973177 0 70 6,
  global_sample! 646460973177 1 119 7]

private def s4 : List Sample := [global_sample! 646460979961 0 188 7,
  global_sample! 646460979961 1 189 13,
  global_sample! 646460980345 0 119 10,
  global_sample! 646460980345 1 22 13]

private def s5 : List Sample := [global_sample! 646529130617 0 135 7,
  global_sample! 646529130617 1 22 15,
  global_sample! 646529130617 2 87 16,
  global_sample! 646529137529 0 96 8]

private def s6 : List Sample := [global_sample! 646529137529 1 4 11,
  global_sample! 646529137529 2 74 12,
  global_sample! 646529137529 3 80 12,
  global_sample! 646529137529 4 181 19]

private def s7 : List Sample := [global_sample! 646529137529 5 34 16,
  global_sample! 646529137529 6 81 11,
  global_sample! 646665445497 0 119 6,
  global_sample! 646665445497 1 84 14]

private def s8 : List Sample := [global_sample! 646665445497 2 179 16,
  global_sample! 646665445497 3 80 11,
  global_sample! 646665445497 4 191 8,
  global_sample! 646665445497 5 74 9]

private def s9 : List Sample := [global_sample! 646665452409 0 87 15,
  global_sample! 646665452409 1 135 6,
  global_sample! 646665452409 2 22 12,
  global_sample! 652835257080 0 46 2]

private def s10 : List Sample := [global_sample! 652835257080 1 80 16,
  global_sample! 652835257080 2 2 6,
  global_sample! 652835257080 3 96 12,
  global_sample! 652835273465 0 84 9]

private def s11 : List Sample := [global_sample! 652835273465 1 175 9,
  global_sample! 652835273465 2 70 5,
  global_sample! 652835273465 3 96 11,
  global_sample! 652835273465 4 25 9]

private def s12 : List Sample := [global_sample! 652835273465 5 92 13,
  global_sample! 652835535611 0 175 8,
  global_sample! 681834674936 0 59 2,
  global_sample! 681834674936 1 134 9]

private def s13 : List Sample := [global_sample! 681834674936 2 97 12,
  global_sample! 681834691321 0 69 6,
  global_sample! 681834691321 1 96 13,
  global_sample! 681834937082 0 69 8]

private def s14 : List Sample := [global_sample! 681834937082 1 132 7,
  global_sample! 927713197177 0 135 8,
  global_sample! 927713197177 1 74 14,
  global_sample! 956712611961 0 96 9]

private def s15 : List Sample := [global_sample! 956712611961 1 168 5,
  global_sample! 956712611961 2 80 14,
  global_sample! 956712611961 3 179 18,
  global_sample! 956712611961 4 181 20]

private def s16 : List Sample := [global_sample! 956712615033 0 87 19,
  global_sample! 956712615033 1 81 17,
  global_sample! 1236950818937 0 62 15,
  global_sample! 1236950818937 1 137 9]

public def samples := [s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15, s16].flatten

end ConsensusCoverage.ClauseGlobalBatchA
