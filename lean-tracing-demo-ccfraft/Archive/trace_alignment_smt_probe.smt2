; Copyright (c) Microsoft Corporation. All rights reserved.
; Licensed under the Apache 2.0 License.
;
; A deliberately small trace-alignment feasibility probe.
; It is not the CCFRaft encoding. It checks that the chosen solver workflow can:
; 1. materialize an unknown entry state and unknown action parameters; and
; 2. return the labelled event/action constraints behind an inconsistent trace.

(set-logic QF_ALIA)
(set-option :incremental true)
(set-option :produce-models true)
(set-option :produce-unsat-assumptions true)

; Unknown state at the start of a production trace window.
(declare-const term0 Int)
(declare-const last0 Int)
(declare-const commit0 Int)
(declare-const match0 Int)
(declare-const leader0 Bool)
(declare-const pendingResponse0 Bool)
(declare-const responseSource0 Int)
(declare-const responseDestination0 Int)
(declare-const responseTerm0 Int)
(declare-const responseIndex0 Int)
(declare-const submitted0 (Array Int Bool))

; Unknown action data.
; action0 = 0 denotes ClientRequest in this probe.
(declare-const action0 Int)
(declare-const command0 Int)
(declare-const responseIndex1 Int)
(declare-const highestCommittable2 Int)
(declare-const submitted1 (Array Int Bool))

; Materialized states after the three reduced actions.
(declare-const last1 Int)
(declare-const commit1 Int)
(declare-const match1 Int)
(declare-const pendingResponse1 Bool)

(declare-const last2 Int)
(declare-const commit2 Int)
(declare-const match2 Int)
(declare-const pendingResponse2 Bool)

(declare-const last3 Int)
(declare-const commit3 Int)
(declare-const match3 Int)
(declare-const pendingResponse3 Bool)

; Labels returned by get-unsat-assumptions.
(declare-const event401 Bool)
(declare-const mapClientRequest401 Bool)
(declare-const event405 Bool)
(declare-const mapReceiveResponse405 Bool)
(declare-const event406 Bool)
(declare-const mapAdvanceCommit406 Bool)
(declare-const conflictingEvent407 Bool)
(declare-const entryStateBounds Bool)
(declare-const actionParameterBounds Bool)
(declare-const messageBounds Bool)

; Domain and local well-formedness constraints.
(assert
  (=> entryStateBounds
    (and
      (>= term0 0)
      (>= commit0 0)
      (>= match0 0)
      (<= commit0 last0)
      (<= match0 last0))))
(assert
  (=> actionParameterBounds
    (and (>= command0 0) (< command0 64))))
(assert
  (=> messageBounds
    (and
      (>= responseSource0 0)
      (< responseSource0 15)
      (>= responseDestination0 0)
      (< responseDestination0 15)
      (>= responseTerm0 0)
      (>= responseIndex0 0))))

; Event 401 observes the unknown entry state and a replicated sequence number.
(assert
  (=> event401
    (and
      (= term0 7)
      (= last0 119)
      (= commit0 116)
      leader0
      (= last1 120))))

; Its deterministic reduction chooses ClientRequest but leaves the command ID unknown.
(assert
  (=> mapClientRequest401
    (and
      (= action0 0)
      leader0
      (not (select submitted0 command0))
      (= last1 (+ last0 1))
      (= commit1 commit0)
      (= match1 match0)
      (= pendingResponse1 pendingResponse0)
      (= submitted1 (store submitted0 command0 true)))))

; Event 405 identifies the response that was already in flight at the cut.
(assert
  (=> event405
    (and
      (= responseSource0 1)
      (= responseDestination0 0)
      (= responseTerm0 7)
      (= responseIndex0 120)
      (= responseIndex1 120))))

; Receiving that response requires the unknown initial queue to contain it.
(assert
  (=> mapReceiveResponse405
    (and
      pendingResponse1
      (= responseIndex1 responseIndex0)
      (= last2 last1)
      (= commit2 commit1)
      (= match2 responseIndex1)
      (not pendingResponse2))))

; Event 406 observes a leader commit to index 120.
(assert
  (=> event406
    (and
      (= commit2 116)
      (= highestCommittable2 120))))

(assert
  (=> mapAdvanceCommit406
    (and
      leader0
      (> highestCommittable2 commit2)
      (<= highestCommittable2 last2)
      (= last3 last2)
      (= commit3 highestCommittable2)
      (= match3 match2)
      (= pendingResponse3 pendingResponse2))))

; First query: derive one concrete entry state and concrete action parameters.
(check-sat-assuming
  (event401
   mapClientRequest401
   event405
   mapReceiveResponse405
   event406
   mapAdvanceCommit406
   entryStateBounds
   actionParameterBounds
   messageBounds))
(get-value
  (term0
   last0
   commit0
   match0
   pendingResponse0
   action0
   command0
   (select submitted0 command0)
   (select submitted1 command0)
   responseSource0
   responseDestination0
   responseTerm0
   responseIndex0
   responseIndex1
   highestCommittable2
   last3
   commit3))

; Second query: add a contradictory observation after the same mapped commit.
(assert (=> conflictingEvent407 (= commit3 121)))
(check-sat-assuming
  (event401
   mapClientRequest401
   event405
   mapReceiveResponse405
   event406
   mapAdvanceCommit406
   conflictingEvent407
   entryStateBounds
   actionParameterBounds
   messageBounds))
(get-unsat-assumptions)
