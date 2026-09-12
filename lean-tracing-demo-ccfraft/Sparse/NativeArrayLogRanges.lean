-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayCheckQuorum

set_option autoImplicit false

namespace CCFRaft.NativeArrayLogRanges

open NativeArrayCheckQuorum

variable {N T A : Type}

def EqualRange (project : Entry N T -> A) (left right : Log N T)
    (leftStart rightStart count : Nat) : Prop :=
  forall index, index < count -> project (left.entries (leftStart + index)) =
    project (right.entries (rightStart + index))

theorem equal_range_correct (project : Entry N T -> A) (left right : Log N T)
    (leftStart rightStart count : Nat)
    (leftBound : leftStart + count <= left.length)
    (rightBound : rightStart + count <= right.length) :
    EqualRange project left right leftStart rightStart count <->
      ((left.decode.drop leftStart).take count).map project =
        ((right.decode.drop rightStart).take count).map project := by
  have leftLength : min count (left.length - leftStart) = count := Nat.min_eq_left (by omega)
  have rightLength : min count (right.length - rightStart) = count := Nat.min_eq_left (by omega)
  constructor
  · intro same
    apply List.ext_getElem
    · simp [Log.decode, leftLength, rightLength]
    · intro index within otherWithin
      have live : index < count := by
        simp only [List.length_map, List.length_take] at within
        exact lt_of_lt_of_le within (Nat.min_le_left _ _)
      simpa [Log.decode] using same index live
  · intro same index within
    have equal := congrArg (fun values : List A => values[index]?) same
    have leftLive : leftStart + index < left.length := by omega
    have rightLive : rightStart + index < right.length := by omega
    simpa [Log.decode, within, leftLive, rightLive] using equal

def AlreadyDone (log payload : Log N T) (previous : Nat) : Prop :=
  payload.length = 0 \/
    (previous + payload.length <= log.length /\ EqualRange Entry.term log payload previous 0 payload.length)

theorem already_done_correct [DecidableEq N] [DecidableEq T]
    (row : Local N T) (request : AppendEntriesRequest N T) (payload : Log N T)
    (samePayload : request.entries = payload.decode) :
    AlreadyDone row.log payload request.prevLogIndex <-> CCFRaft.alreadyDone row.toModel request := by
  by_cases empty : payload.length = 0
  · have nil : payload.decode = [] :=
      List.eq_nil_iff_length_eq_zero.mpr (by rw [Log.decode, List.length_ofFn]; exact empty)
    simp [AlreadyDone, CCFRaft.alreadyDone, samePayload, empty, nil]
  · have notNil : payload.decode ≠ [] := by
      intro nil
      apply empty
      have length := congrArg List.length nil
      simpa [Log.decode] using length
    by_cases fits : request.prevLogIndex + payload.length <= row.log.length
    · have range := equal_range_correct Entry.term row.log payload request.prevLogIndex 0 payload.length fits (by omega)
      have payloadTake : payload.decode.take payload.length = payload.decode := by
        have length : payload.decode.length = payload.length := by simp [Log.decode]
        rw [← length, List.take_length]
      simp only [List.drop_zero, payloadTake] at range
      simpa [AlreadyDone, CCFRaft.alreadyDone, samePayload, Local.toModel, empty, fits,
        notNil, Log.decode] using range
    · simp [AlreadyDone, CCFRaft.alreadyDone, samePayload, Local.toModel, empty, fits,
        Log.decode]

def HasTermConflict (log payload : Log N T) (previous : Nat) : Prop :=
  payload.length ≠ 0 /\
    Not (EqualRange Entry.term log payload previous 0 (min payload.length (log.length - previous)))

theorem term_conflict_correct [DecidableEq N] [DecidableEq T]
    (row : Local N T) (request : AppendEntriesRequest N T) (payload : Log N T)
    (samePayload : request.entries = payload.decode) :
    HasTermConflict row.log payload request.prevLogIndex <-> CCFRaft.hasTermConflict row.toModel request := by
  by_cases previousWithin : request.prevLogIndex <= row.log.length
  · have range := equal_range_correct Entry.term row.log payload request.prevLogIndex 0
      (min payload.length (row.log.length - request.prevLogIndex))
      (by have := Nat.min_le_right payload.length (row.log.length - request.prevLogIndex); omega)
      (by simp)
    have nil : (payload.decode = []) <-> payload.length = 0 := by
      rw [← List.length_eq_zero_iff]
      simp [Log.decode]
    simpa [HasTermConflict, CCFRaft.hasTermConflict, overlapLength, Local.toModel,
      samePayload, nil, Log.decode] using and_congr (not_congr nil.symm) (not_congr range)
  · have zero : row.log.length - request.prevLogIndex = 0 := by omega
    simp [HasTermConflict, CCFRaft.hasTermConflict, overlapLength, Local.toModel,
      samePayload, Log.decode, zero, EqualRange]

def NoConflictExtension (log payload : Log N T) (previous : Nat) : Prop :=
  payload.length ≠ 0 /\ previous <= log.length /\ log.length < previous + payload.length /\
    EqualRange id log payload previous 0 (log.length - previous)

theorem no_conflict_extension_correct [DecidableEq N] [DecidableEq T]
    (row : Local N T) (request : AppendEntriesRequest N T) (payload : Log N T)
    (samePayload : request.entries = payload.decode) :
    NoConflictExtension row.log payload request.prevLogIndex <-> CCFRaft.noConflictExtension row.toModel request := by
  by_cases previousWithin : request.prevLogIndex <= row.log.length
  · by_cases grows : row.log.length < request.prevLogIndex + payload.length
    · have range := equal_range_correct id row.log payload request.prevLogIndex 0
        (row.log.length - request.prevLogIndex) (by omega) (by omega)
      have nil : (payload.decode = []) <-> payload.length = 0 := by
        rw [← List.length_eq_zero_iff]
        simp [Log.decode]
      simpa [NoConflictExtension, CCFRaft.noConflictExtension, Local.toModel,
        samePayload, nil, Log.decode, previousWithin, grows] using
          and_congr (not_congr nil.symm) range
    · simp [NoConflictExtension, CCFRaft.noConflictExtension, Local.toModel,
        samePayload, Log.decode, grows]
  · simp [NoConflictExtension, CCFRaft.noConflictExtension, Local.toModel,
      samePayload, Log.decode, previousWithin]

end CCFRaft.NativeArrayLogRanges

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeArrayLogRanges).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
