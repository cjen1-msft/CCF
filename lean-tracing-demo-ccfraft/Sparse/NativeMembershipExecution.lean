-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeMembershipChange
import Sparse.NativeMembershipWritesEncoding
import Sparse.NativeRetirementCompletedConstraintsEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

structure MembershipExecutionTerms (width : PNat) where
  configuration : Finset (Fin width)
  old : NodeRowTerms width
  current : Expr .int
  previous : Expr (.bits width)
  added : Expr (.bits width)
  entries : Expr (.array .int (entryTy width))
  length : Expr .int
  (first retirement signature retired committedCurrent : Expr .int)
  completed : Expr (.bits width)
  values : NodeRowTerms width

def membershipExecutionTerms {width : PNat} (before : Encoding width)
    (source : Fin width) (configuration : Finset (Fin width)) :
    MembershipExecutionTerms width :=
  let old := nodeRowSnapshot before.toColumns source
  let current : Expr .int := .free .int before.next
  let previous : Expr (.bits width) := .free _ (before.next + 1)
  let added : Expr (.bits width) := .free _ (before.next + 2)
  let entries : Expr (.array .int (entryTy width)) := .free _ (before.next + 3)
  let length : Expr .int := .free .int (before.next + 4)
  let first : Expr .int := .free .int (before.next + 5)
  let retirement : Expr .int := .free .int (before.next + 6)
  let signature : Expr .int := .free .int (before.next + 7)
  let retired : Expr .int := .free .int (before.next + 8)
  let committedCurrent : Expr .int := .free .int (before.next + 9)
  let completed : Expr (.bits width) := .free _ (before.next + 10)
  { configuration, old, current, previous, added, entries, length, first, retirement, signature, retired,
    committedCurrent, completed
    values := membershipRowTerms before.toColumns source length entries added retirement
      signature retired }

private def membershipChangeSuffix {width : PNat} (before : Encoding width)
    (source : Fin width) (configuration : Finset (Fin width))
    (previousId addedId entriesId lengthId : Nat) : EncodeM width Unit := do
  let old := nodeRowSnapshot before.toColumns source
  let added : Expr (.bits width) := .free _ addedId
  let entries : Expr (.array .int (entryTy width)) := .free _ entriesId
  let length : Expr .int := .free .int lengthId
  let first <- fresh
  let retirement <- fresh
  let signature <- fresh
  let retired <- fresh
  assertion (retirementRefreshConstraints width before.bootstrap length entries source
    (.free .int first) (.free .int retirement) (.free .int signature) (.free .int retired))
  let values := membershipRowTerms before.toColumns source length entries added
    (.free .int retirement) (.free .int signature) (.free .int retired)
  assertAll (membershipGuards before.toColumns source configuration
    (.free (.bits width) previousId)
    values.membershipState)
  let committedCurrent <- fresh
  assertion (currentConfigurationIndexTerm width length entries old.commit
    (.free .int committedCurrent))
  let completed <- retirementCompletedConstraints before.bootstrap (.boolean true) length
    entries old.commit (.free .int committedCurrent)
  membershipWrites source added values (.free (.bits width) completed)

structure MembershipSuffixStates (width : PNat) where
  firstFresh : Encoding width
  retirementFresh : Encoding width
  signatureFresh : Encoding width
  retiredFresh : Encoding width
  refreshAsserted : Encoding width
  guardsAsserted : Encoding width
  committedCurrentFresh : Encoding width
  committedCurrentAsserted : Encoding width
  writerBefore : Encoding width

structure MembershipSuffixRuns {width : PNat} (source : Fin width)
    (configuration : Finset (Fin width)) (before lengthDefined after : Encoding width)
    (states : MembershipSuffixStates width) : Prop where
  firstRun : fresh.run lengthDefined = .ok (before.next + 5, states.firstFresh)
  retirementRun : fresh.run states.firstFresh =
    .ok (before.next + 6, states.retirementFresh)
  signatureRun : fresh.run states.retirementFresh =
    .ok (before.next + 7, states.signatureFresh)
  retiredRun : fresh.run states.signatureFresh = .ok (before.next + 8, states.retiredFresh)
  refreshRun :
    let terms := membershipExecutionTerms before source configuration
    (assertion (retirementRefreshConstraints width before.bootstrap terms.length terms.entries
      source terms.first terms.retirement terms.signature terms.retired)).run
        states.retiredFresh = .ok ((), states.refreshAsserted)
  guardsRun :
    let terms := membershipExecutionTerms before source configuration
    (assertAll (membershipGuards before.toColumns source configuration terms.previous
      terms.values.membershipState)).run states.refreshAsserted =
        .ok ((), states.guardsAsserted)
  committedCurrentRun : fresh.run states.guardsAsserted =
    .ok (before.next + 9, states.committedCurrentFresh)
  committedCurrentAssertionRun :
    let terms := membershipExecutionTerms before source configuration
    (assertion (currentConfigurationIndexTerm width terms.length terms.entries terms.old.commit
      terms.committedCurrent)).run states.committedCurrentFresh =
        .ok ((), states.committedCurrentAsserted)
  completedRun :
    let terms := membershipExecutionTerms before source configuration
    (retirementCompletedConstraints before.bootstrap (.boolean true) terms.length terms.entries
      terms.old.commit terms.committedCurrent).run states.committedCurrentAsserted =
        .ok (before.next + 10, states.writerBefore)
  writeRun :
    let terms := membershipExecutionTerms before source configuration
    (membershipWrites source terms.added terms.values terms.completed).run states.writerBefore =
      .ok ((), after)

private theorem membership_change_suffix_runs {width : PNat} (source : Fin width)
    (configuration : Finset (Fin width)) (before lengthDefined after : Encoding width)
    (lengthNext : lengthDefined.next = before.next + 5)
    (run : (membershipChangeSuffix before source configuration (before.next + 1)
      (before.next + 2)
      (before.next + 3) (before.next + 4)).run lengthDefined =
      .ok ((), after)) :
    exists states, MembershipSuffixRuns source configuration before lengthDefined after states := by
  simp only [membershipChangeSuffix] at run
  obtain ⟨firstId, firstFresh, firstRun, run⟩ := (bind_run _ _ _ _ _).mp run
  obtain ⟨retirementId, retirementFresh, retirementRun, run⟩ :=
    (bind_run _ _ _ _ _).mp run
  obtain ⟨signatureId, signatureFresh, signatureRun, run⟩ := (bind_run _ _ _ _ _).mp run
  obtain ⟨retiredId, retiredFresh, retiredRun, run⟩ := (bind_run _ _ _ _ _).mp run
  obtain ⟨refreshValue, refreshAsserted, refreshRun, run⟩ :=
    (bind_run _ _ _ _ _).mp run
  cases refreshValue
  obtain ⟨guardValue, guardsAsserted, guardsRun, run⟩ := (bind_run _ _ _ _ _).mp run
  cases guardValue
  obtain ⟨committedCurrentId, committedCurrentFresh, committedCurrentRun, run⟩ :=
    (bind_run _ _ _ _ _).mp run
  obtain ⟨committedValue, committedCurrentAsserted, committedCurrentAssertionRun, run⟩ :=
    (bind_run _ _ _ _ _).mp run
  cases committedValue
  obtain ⟨completedId, writerBefore, completedRun, writeRun⟩ :=
    (bind_run _ _ _ _ _).mp run
  obtain ⟨firstEq, firstNext, _, _, _⟩ :=
    fresh_success lengthDefined firstFresh firstId firstRun
  obtain ⟨retirementEq, retirementNext, _, _, _⟩ :=
    fresh_success firstFresh retirementFresh retirementId retirementRun
  obtain ⟨signatureEq, signatureNext, _, _, _⟩ :=
    fresh_success retirementFresh signatureFresh signatureId signatureRun
  obtain ⟨retiredEq, retiredNext, _, _, _⟩ :=
    fresh_success signatureFresh retiredFresh retiredId retiredRun
  obtain ⟨refreshFrame, _⟩ := assertion_success _ retiredFresh refreshAsserted refreshRun
  obtain ⟨guardsFrame, _⟩ := assert_all_success _ refreshAsserted guardsAsserted guardsRun
  obtain ⟨committedEq, committedNext, _, _, _⟩ :=
    fresh_success guardsAsserted committedCurrentFresh committedCurrentId committedCurrentRun
  obtain ⟨committedFrame, _⟩ := assertion_success _ committedCurrentFresh
    committedCurrentAsserted committedCurrentAssertionRun
  have completedShape := retirement_completed_constraints_success _ _ _ _ _ _
    committedCurrentAsserted writerBefore completedId completedRun
  have ids : firstId = before.next + 5 /\ retirementId = before.next + 6 /\
      signatureId = before.next + 7 /\ retiredId = before.next + 8 /\
      committedCurrentId = before.next + 9 /\ completedId = before.next + 10 := by
    have refreshNext := refreshFrame.next
    have guardsNext := guardsFrame.next
    have committedAssertedNext := committedFrame.next
    have completedEq := completedShape.completedId
    constructor
    · omega
    constructor
    · omega
    constructor
    · omega
    constructor
    · omega
    constructor <;> omega
  rcases ids with ⟨rfl, rfl, rfl, rfl, rfl, rfl⟩
  let states : MembershipSuffixStates width :=
    { firstFresh, retirementFresh, signatureFresh, retiredFresh, refreshAsserted,
      guardsAsserted, committedCurrentFresh, committedCurrentAsserted, writerBefore }
  refine ⟨states, ?_⟩
  constructor
  · exact firstRun
  · exact retirementRun
  · exact signatureRun
  · exact retiredRun
  · simpa [membershipExecutionTerms] using refreshRun
  · simpa [membershipExecutionTerms] using guardsRun
  · exact committedCurrentRun
  · simpa [membershipExecutionTerms] using committedCurrentAssertionRun
  · simpa [membershipExecutionTerms] using completedRun
  · simpa [membershipExecutionTerms] using writeRun

structure MembershipPrefixStates (width : PNat) where
  currentFresh : Encoding width
  currentAsserted : Encoding width
  previousDefined : Encoding width
  addedDefined : Encoding width
  entriesDefined : Encoding width
  lengthDefined : Encoding width

structure MembershipPrefixRuns {width : PNat} (source : Fin width)
    (configuration : Finset (Fin width)) (before after : Encoding width)
    (initial : MembershipPrefixStates width) (suffix : MembershipSuffixStates width) : Prop where
  currentRun : fresh.run before = .ok (before.next, initial.currentFresh)
  currentAssertionRun :
    let terms := membershipExecutionTerms before source configuration
    (assertion (currentConfigurationIndexTerm width terms.old.logLength terms.old.logEntries
      terms.old.logLength terms.current)).run initial.currentFresh =
        .ok ((), initial.currentAsserted)
  previousRun :
    let terms := membershipExecutionTerms before source configuration
    (define (currentConfigurationMembersTerm width before.bootstrap terms.old.logEntries
      terms.current)).run initial.currentAsserted = .ok (before.next + 1, initial.previousDefined)
  addedRun :
    let terms := membershipExecutionTerms before source configuration
    (define (membershipAddedTerm configuration terms.previous)).run initial.previousDefined =
      .ok (before.next + 2, initial.addedDefined)
  entriesRun :
    (define (membershipLogEntriesTerm before.toColumns source configuration)).run
      initial.addedDefined = .ok (before.next + 3, initial.entriesDefined)
  lengthRun :
    let terms := membershipExecutionTerms before source configuration
    (define (.add terms.old.logLength (.integer 1))).run initial.entriesDefined =
      .ok (before.next + 4, initial.lengthDefined)
  suffixRuns :
    MembershipSuffixRuns source configuration before initial.lengthDefined after suffix

structure MembershipChangeExecutionResult {width : PNat} (source : Fin width)
    (configuration : Finset (Fin width)) (before after : Encoding width)
    (initial : MembershipPrefixStates width) (suffix : MembershipSuffixStates width) : Prop where
  runs : MembershipPrefixRuns source configuration before after initial suffix
  writerNext : suffix.writerBefore.next = before.next + 11 + 3 * width
  writerBootstrap : suffix.writerBefore.bootstrap = before.bootstrap
  writerColumns : suffix.writerBefore.toColumns = before.toColumns
  finalNext : after.next = before.next + 29 + 20 * width

private def membershipChangeDefinitions {width : PNat} (before : Encoding width)
    (source : Fin width) (configuration : Finset (Fin width)) (current : Nat) :
    EncodeM width Unit := do
  let old := nodeRowSnapshot before.toColumns source
  let previous <- define (currentConfigurationMembersTerm width before.bootstrap old.logEntries
    (.free .int current))
  let addedId <- define (membershipAddedTerm configuration (.free (.bits width) previous))
  let entriesId <- define (membershipLogEntriesTerm before.toColumns source configuration)
  let lengthId <- define (.add old.logLength (.integer 1))
  membershipChangeSuffix before source configuration previous addedId entriesId lengthId

structure MembershipHeadStates (width : PNat) where
  currentFresh : Encoding width
  currentAsserted : Encoding width

structure MembershipHeadRuns {width : PNat} (source : Fin width)
    (configuration : Finset (Fin width)) (before after : Encoding width)
    (states : MembershipHeadStates width) : Prop where
  currentRun : fresh.run before = .ok (before.next, states.currentFresh)
  currentAssertionRun :
    let terms := membershipExecutionTerms before source configuration
    (assertion (currentConfigurationIndexTerm width terms.old.logLength terms.old.logEntries
      terms.old.logLength terms.current)).run states.currentFresh =
        .ok ((), states.currentAsserted)
  definitionRun :
    (membershipChangeDefinitions before source configuration before.next).run
      states.currentAsserted = .ok ((), after)

private theorem membership_change_head_runs {width : PNat} (source : Fin width)
    (configuration : Finset (Fin width)) (before after : Encoding width)
    (run : (membershipChange source configuration).run before = .ok ((), after)) :
    exists states, MembershipHeadRuns source configuration before after states := by
  rw [membershipChange, get_bind_run] at run
  obtain ⟨currentId, currentFresh, currentRun, run⟩ := (bind_run _ _ _ _ _).mp run
  obtain ⟨currentValue, currentAsserted, currentAssertionRun, run⟩ :=
    (bind_run _ _ _ _ _).mp run
  cases currentValue
  have currentEq := (fresh_success before currentFresh currentId currentRun).1
  subst currentId
  let states : MembershipHeadStates width := { currentFresh, currentAsserted }
  refine ⟨states, ?_⟩
  constructor
  · exact currentRun
  · simpa [membershipExecutionTerms] using currentAssertionRun
  · simpa [membershipChangeDefinitions, membershipChangeSuffix, membershipExecutionTerms] using run

structure MembershipDefinitionStates (width : PNat) where
  previousDefined : Encoding width
  addedDefined : Encoding width
  entriesDefined : Encoding width
  lengthDefined : Encoding width

structure MembershipDefinitionRuns {width : PNat} (source : Fin width)
    (configuration : Finset (Fin width)) (before currentAsserted after : Encoding width)
    (definitions : MembershipDefinitionStates width)
    (suffix : MembershipSuffixStates width) : Prop where
  previousRun :
    let terms := membershipExecutionTerms before source configuration
    (define (currentConfigurationMembersTerm width before.bootstrap terms.old.logEntries
      terms.current)).run currentAsserted = .ok (before.next + 1, definitions.previousDefined)
  addedRun :
    let terms := membershipExecutionTerms before source configuration
    (define (membershipAddedTerm configuration terms.previous)).run definitions.previousDefined =
      .ok (before.next + 2, definitions.addedDefined)
  entriesRun :
    (define (membershipLogEntriesTerm before.toColumns source configuration)).run
      definitions.addedDefined = .ok (before.next + 3, definitions.entriesDefined)
  lengthRun :
    let terms := membershipExecutionTerms before source configuration
    (define (.add terms.old.logLength (.integer 1))).run definitions.entriesDefined =
      .ok (before.next + 4, definitions.lengthDefined)
  suffixRuns :
    MembershipSuffixRuns source configuration before definitions.lengthDefined after suffix

private theorem membership_change_definition_runs {width : PNat} (source : Fin width)
    (configuration : Finset (Fin width)) (before currentAsserted after : Encoding width)
    (currentNext : currentAsserted.next = before.next + 1)
    (run : (membershipChangeDefinitions before source configuration before.next).run
      currentAsserted = .ok ((), after)) :
    exists definitions suffix,
      MembershipDefinitionRuns source configuration before currentAsserted after
        definitions suffix := by
  simp only [membershipChangeDefinitions] at run
  obtain ⟨previousId, previousDefined, previousRun, run⟩ := (bind_run _ _ _ _ _).mp run
  obtain ⟨addedId, addedDefined, addedRun, run⟩ := (bind_run _ _ _ _ _).mp run
  obtain ⟨entriesId, entriesDefined, entriesRun, run⟩ := (bind_run _ _ _ _ _).mp run
  obtain ⟨lengthId, lengthDefined, lengthRun, run⟩ := (bind_run _ _ _ _ _).mp run
  obtain ⟨previousEq, previousNext, _, _, _⟩ :=
    define_success _ currentAsserted previousDefined previousId previousRun
  obtain ⟨addedEq, addedNext, _, _, _⟩ :=
    define_success _ previousDefined addedDefined addedId addedRun
  obtain ⟨entriesEq, entriesNext, _, _, _⟩ :=
    define_success _ addedDefined entriesDefined entriesId entriesRun
  obtain ⟨lengthEq, lengthNext, _, _, _⟩ :=
    define_success _ entriesDefined lengthDefined lengthId lengthRun
  have ids : previousId = before.next + 1 /\ addedId = before.next + 2 /\
      entriesId = before.next + 3 /\ lengthId = before.next + 4 := by
    constructor
    · omega
    constructor
    · omega
    constructor <;> omega
  rcases ids with ⟨rfl, rfl, rfl, rfl⟩
  have suffixRun :
      (membershipChangeSuffix before source configuration (before.next + 1) (before.next + 2)
        (before.next + 3) (before.next + 4)).run lengthDefined = .ok ((), after) := by
    exact run
  obtain ⟨suffix, suffixRuns⟩ :=
    membership_change_suffix_runs source configuration before lengthDefined after
      (by omega) suffixRun
  let definitions : MembershipDefinitionStates width :=
    { previousDefined, addedDefined, entriesDefined, lengthDefined }
  refine ⟨definitions, suffix, ?_⟩
  constructor
  · simpa [membershipExecutionTerms] using previousRun
  · simpa [membershipExecutionTerms] using addedRun
  · exact entriesRun
  · simpa [membershipExecutionTerms] using lengthRun
  · exact suffixRuns

private theorem membership_change_prefix_runs {width : PNat} (source : Fin width)
    (configuration : Finset (Fin width)) (before after : Encoding width)
    (run : (membershipChange source configuration).run before = .ok ((), after)) :
    exists initial suffix,
      MembershipPrefixRuns source configuration before after initial suffix := by
  obtain ⟨head, headRuns⟩ :=
    membership_change_head_runs source configuration before after run
  obtain ⟨_, currentNext, _, _, _⟩ :=
    fresh_success before head.currentFresh before.next headRuns.currentRun
  obtain ⟨currentFrame, _⟩ :=
    assertion_success _ head.currentFresh head.currentAsserted headRuns.currentAssertionRun
  have currentAssertedNext := currentFrame.next
  obtain ⟨definitions, suffix, definitionRuns⟩ :=
    membership_change_definition_runs source configuration before head.currentAsserted after
      (by omega) headRuns.definitionRun
  let initial : MembershipPrefixStates width :=
    { currentFresh := head.currentFresh
      currentAsserted := head.currentAsserted
      previousDefined := definitions.previousDefined
      addedDefined := definitions.addedDefined
      entriesDefined := definitions.entriesDefined
      lengthDefined := definitions.lengthDefined }
  refine ⟨initial, suffix, ?_⟩
  refine
    { currentRun := headRuns.currentRun
      currentAssertionRun := headRuns.currentAssertionRun
      previousRun := definitionRuns.previousRun
      addedRun := definitionRuns.addedRun
      entriesRun := definitionRuns.entriesRun
      lengthRun := definitionRuns.lengthRun
      suffixRuns := definitionRuns.suffixRuns }

theorem membership_change_success {width : PNat} (source : Fin width)
    (configuration : Finset (Fin width)) (before after : Encoding width)
    (run : (membershipChange source configuration).run before = .ok ((), after)) :
    exists initial suffix,
      MembershipChangeExecutionResult source configuration before after initial suffix := by
  obtain ⟨initial, suffix, runs⟩ :=
    membership_change_prefix_runs source configuration before after run
  let suffixRuns := runs.suffixRuns
  have completedShape := retirement_completed_constraints_success before.bootstrap
    (.boolean true) (membershipExecutionTerms before source configuration).length
    (membershipExecutionTerms before source configuration).entries
    (membershipExecutionTerms before source configuration).old.commit
    (membershipExecutionTerms before source configuration).committedCurrent
    suffix.committedCurrentAsserted suffix.writerBefore (before.next + 10)
    suffixRuns.completedRun
  have currentShape := fresh_success before initial.currentFresh before.next runs.currentRun
  have currentAssertionShape :=
    assertion_success _ initial.currentFresh initial.currentAsserted runs.currentAssertionRun
  have previousShape :=
    define_success _ initial.currentAsserted initial.previousDefined (before.next + 1)
      runs.previousRun
  have addedShape := define_success _ initial.previousDefined initial.addedDefined (before.next + 2)
    runs.addedRun
  have entriesShape := define_success _ initial.addedDefined initial.entriesDefined
    (before.next + 3)
    runs.entriesRun
  have lengthShape := define_success _ initial.entriesDefined initial.lengthDefined
    (before.next + 4)
    runs.lengthRun
  have firstShape := fresh_success initial.lengthDefined suffix.firstFresh (before.next + 5)
    suffixRuns.firstRun
  have retirementShape :=
    fresh_success suffix.firstFresh suffix.retirementFresh (before.next + 6)
      suffixRuns.retirementRun
  have signatureShape :=
    fresh_success suffix.retirementFresh suffix.signatureFresh (before.next + 7)
      suffixRuns.signatureRun
  have retiredShape :=
    fresh_success suffix.signatureFresh suffix.retiredFresh (before.next + 8)
      suffixRuns.retiredRun
  have refreshShape :=
    assertion_success _ suffix.retiredFresh suffix.refreshAsserted suffixRuns.refreshRun
  have guardsShape :=
    assert_all_success _ suffix.refreshAsserted suffix.guardsAsserted suffixRuns.guardsRun
  have committedShape := fresh_success suffix.guardsAsserted suffix.committedCurrentFresh
    (before.next + 9) suffixRuns.committedCurrentRun
  have committedAssertionShape := assertion_success _ suffix.committedCurrentFresh
    suffix.committedCurrentAsserted suffixRuns.committedCurrentAssertionRun
  have writerNext : suffix.writerBefore.next = before.next + 11 + 3 * width := by
    rw [completedShape.next, committedAssertionShape.1.next,
      committedShape.2.1, guardsShape.1.next, refreshShape.1.next, retiredShape.2.1,
      signatureShape.2.1, retirementShape.2.1, firstShape.2.1, lengthShape.2.1,
      entriesShape.2.1, addedShape.2.1, previousShape.2.1, currentAssertionShape.1.next,
      currentShape.2.1]
  have writerBootstrap : suffix.writerBefore.bootstrap = before.bootstrap := by
    rw [completedShape.sameBootstrap,
      committedAssertionShape.1.bootstrap, committedShape.2.2.1, guardsShape.1.bootstrap,
      refreshShape.1.bootstrap, retiredShape.2.2.1, signatureShape.2.2.1,
      retirementShape.2.2.1, firstShape.2.2.1, lengthShape.2.2.1,
      entriesShape.2.2.1, addedShape.2.2.1, previousShape.2.2.1,
      currentAssertionShape.1.bootstrap, currentShape.2.2.1]
  have writerColumns : suffix.writerBefore.toColumns = before.toColumns := by
    rw [completedShape.sameColumns, committedAssertionShape.1.columns,
      committedShape.2.2.2.1, guardsShape.1.columns, refreshShape.1.columns,
      retiredShape.2.2.2.1, signatureShape.2.2.2.1, retirementShape.2.2.2.1,
      firstShape.2.2.2.1, lengthShape.2.2.2.1, entriesShape.2.2.2.1,
      addedShape.2.2.2.1, previousShape.2.2.2.1, currentAssertionShape.1.columns,
      currentShape.2.2.2.1]
  obtain ⟨allocated, written, joinedDefined, completedDefined, joined, retiredNodes,
    writeResult⟩ := membership_writes_success source
      (membershipExecutionTerms before source configuration).added
      (membershipExecutionTerms before source configuration).values
      (membershipExecutionTerms before source configuration).completed suffix.writerBefore after
      suffixRuns.writeRun
  have writeShape := membership_writes_shape source
    (membershipExecutionTerms before source configuration).added
    (membershipExecutionTerms before source configuration).values
    (membershipExecutionTerms before source configuration).completed suffix.writerBefore allocated
    written joinedDefined completedDefined after joined retiredNodes writeResult
  refine ⟨initial, suffix, ?_⟩
  exact
    { runs
      writerNext
      writerBootstrap
      writerColumns
      finalNext := by omega }

theorem membership_change_prior_holds {width : PNat} (source : Fin width)
    (configuration : Finset (Fin width)) (before after : Encoding width)
    (run : (membershipChange source configuration).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment) :
    Holds before.assertions.toList assignment := by
  obtain ⟨initial, suffix, result⟩ :=
    membership_change_success source configuration before after run
  let suffixRuns := result.runs.suffixRuns
  let terms := membershipExecutionTerms before source configuration
  have writerHolds := membership_writes_prior_holds source terms.added terms.values
    terms.completed suffix.writerBefore after suffixRuns.writeRun assignment holds
  have committedHolds := retirement_completed_constraints_holds_before before.bootstrap
    (.boolean true) terms.length terms.entries terms.old.commit terms.committedCurrent
    suffix.committedCurrentAsserted suffix.writerBefore (before.next + 10)
    suffixRuns.completedRun assignment writerHolds
  have committedFreshHolds := (assertion_holds _ suffix.committedCurrentFresh
    suffix.committedCurrentAsserted suffixRuns.committedCurrentAssertionRun assignment
    committedHolds).1
  have guardsHolds := fresh_prior_holds suffix.guardsAsserted suffix.committedCurrentFresh
    (before.next + 9) suffixRuns.committedCurrentRun assignment committedFreshHolds
  have refreshHolds :=
    ((assert_all_holds _ suffix.refreshAsserted suffix.guardsAsserted suffixRuns.guardsRun
      assignment).mp guardsHolds).1
  have retiredHolds := (assertion_holds _ suffix.retiredFresh suffix.refreshAsserted
    suffixRuns.refreshRun assignment refreshHolds).1
  have signatureHolds := fresh_prior_holds suffix.signatureFresh suffix.retiredFresh
    (before.next + 8) suffixRuns.retiredRun assignment retiredHolds
  have retirementHolds := fresh_prior_holds suffix.retirementFresh suffix.signatureFresh
    (before.next + 7) suffixRuns.signatureRun assignment signatureHolds
  have firstHolds := fresh_prior_holds suffix.firstFresh suffix.retirementFresh
    (before.next + 6) suffixRuns.retirementRun assignment retirementHolds
  have lengthHolds := fresh_prior_holds initial.lengthDefined suffix.firstFresh
    (before.next + 5) suffixRuns.firstRun assignment firstHolds
  have entriesHolds := define_prior_holds _ initial.entriesDefined initial.lengthDefined
    (before.next + 4) result.runs.lengthRun assignment lengthHolds
  have addedHolds := define_prior_holds _ initial.addedDefined initial.entriesDefined
    (before.next + 3) result.runs.entriesRun assignment entriesHolds
  have previousHolds := define_prior_holds _ initial.previousDefined initial.addedDefined
    (before.next + 2) result.runs.addedRun assignment addedHolds
  have currentAssertedHolds := define_prior_holds _ initial.currentAsserted
    initial.previousDefined (before.next + 1) result.runs.previousRun assignment previousHolds
  have currentFreshHolds := (assertion_holds _ initial.currentFresh initial.currentAsserted
    result.runs.currentAssertionRun assignment currentAssertedHolds).1
  exact fresh_prior_holds before initial.currentFresh before.next result.runs.currentRun assignment
    currentFreshHolds

theorem membership_change_references {width : PNat} (source : Fin width)
    (configuration : Finset (Fin width)) (before after : Encoding width)
    (run : (membershipChange source configuration).run before = .ok ((), after))
    (valid : ReferencesValid before) : ReferencesValid after := by
  obtain ⟨initial, suffix, result⟩ :=
    membership_change_success source configuration before after run
  have writerValid : ReferencesValid suffix.writerBefore := by
    cases valid
    constructor <;> simp_all only [result.writerColumns, result.writerNext] <;> omega
  exact membership_writes_references source
    (membershipExecutionTerms before source configuration).added
    (membershipExecutionTerms before source configuration).values
    (membershipExecutionTerms before source configuration).completed suffix.writerBefore after
    result.runs.suffixRuns.writeRun writerValid

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
