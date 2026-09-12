-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeDefinitions
import Sparse.NativeAssignmentEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

structure DefinitionsResult {width : PNat} (items : List TypedDefinition)
    (before after : Encoding width) (ids : List Nat) : Prop where
  ids : ids = definitionIds items before.next
  next : after.next = before.next + items.length
  bootstrap : after.bootstrap = before.bootstrap
  columns : after.toColumns = before.toColumns
  clauses : after.assertions.toList =
    before.assertions.toList ++ definitionClauses items before.next

theorem definitions_success {width : PNat} (items : List TypedDefinition)
    (before after : Encoding width) (ids : List Nat)
    (run : (definitions items).run before = .ok (ids, after)) :
    DefinitionsResult items before after ids := by
  induction items generalizing before after ids with
  | nil =>
    simp only [definitions, StateT.run, pure] at run
    obtain ⟨rfl, rfl⟩ := Except.ok.inj run
    constructor <;> simp [definitionIds, definitionClauses]
  | cons item rest ih =>
    rcases item with ⟨sort, value⟩
    simp only [definitions] at run
    obtain ⟨id, middle, defined, run⟩ := (bind_run _ _ _ _ _).mp run
    obtain ⟨restIds, final, continued, returned⟩ := (bind_run _ _ _ _ _).mp run
    have same : (id :: restIds, final) = (ids, after) := Except.ok.inj returned
    have sameIds := congrArg Prod.fst same
    have sameAfter := congrArg Prod.snd same
    dsimp only at sameIds sameAfter
    subst ids
    subst after
    obtain ⟨idEq, middleNext, middleBootstrap, middleColumns, middleClauses⟩ :=
      define_success value before middle id defined
    obtain result := ih middle final restIds continued
    constructor
    · simp only [definitionIds, idEq, result.ids, middleNext]
    · simp only [List.length_cons, result.next, middleNext]
      omega
    · exact result.bootstrap.trans middleBootstrap
    · exact result.columns.trans middleColumns
    · rw [result.clauses, middleClauses, Array.toList_push]
      simp [definitionClauses, idEq, middleNext, List.append_assoc]

theorem define_prior_holds {width : PNat} {sort : Ty} (value : Expr sort)
    (before after : Encoding width) (id : Nat)
    (run : (define value).run before = .ok (id, after))
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment) :
    Holds before.assertions.toList assignment := by
  rw [(define_success value before after id run).2.2.2.2] at holds
  exact fun formula member => holds formula (by simp [member])

theorem define_references {width : PNat} {sort : Ty} (value : Expr sort)
    (before after : Encoding width) (id : Nat)
    (run : (define value).run before = .ok (id, after))
    (valid : ReferencesValid before) : ReferencesValid after := by
  obtain ⟨_, next, _, columns, _⟩ := define_success value before after id run
  cases valid
  constructor <;> simp only [columns, next] <;> omega

theorem definitions_extension {width : PNat} (items : List TypedDefinition)
    (before after : Encoding width) (ids : List Nat)
    (run : (definitions items).run before = .ok (ids, after))
    (assignment : Assignment) (holds : Holds before.assertions.toList assignment) :
    exists extended : Assignment, assignment.AgreesBelow before.next extended /\
      Holds after.assertions.toList extended := by
  induction items generalizing before after ids assignment with
  | nil =>
    simp only [definitions, StateT.run, pure] at run
    obtain ⟨rfl, rfl⟩ := Except.ok.inj run
    exact ⟨assignment, by intro sort id within; rfl, holds⟩
  | cons item rest ih =>
    rcases item with ⟨sort, value⟩
    simp only [definitions] at run
    obtain ⟨id, middle, defined, run⟩ := (bind_run _ _ _ _ _).mp run
    obtain ⟨restIds, final, continued, returned⟩ := (bind_run _ _ _ _ _).mp run
    have same : (id :: restIds, final) = (ids, after) := Except.ok.inj returned
    have sameAfter := congrArg Prod.snd same
    dsimp only at sameAfter
    subst after
    obtain ⟨first, firstAgreement, firstHolds⟩ :=
      define_extension value before middle id defined assignment holds
    obtain ⟨extended, restAgreement, finalHolds⟩ :=
      ih middle final restIds continued first firstHolds
    have middleNext := (define_success value before middle id defined).2.1
    exact ⟨extended,
      firstAgreement.trans (restAgreement.restrict (by rw [middleNext]; omega)),
      finalHolds⟩

end CCFRaft.NativeEncode
