-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeMembershipWrites
import Sparse.NativeAllocationEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def membershipWriteColumns (rowColumns : Columns) (base : Nat) : Columns :=
  { rowColumns with
    hasJoined := base
    retirementCompleted := base + 1 }

def membershipWriteFrame {width : PNat}
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (source : Fin width) (addedSet completedSet : Finset (Fin width))
    (output : NativeArrayCheckQuorum.Local (Fin width) Nat) :
    NativeArrayVote.Frame (Fin width) Nat :=
  { frame with
    nodes := Function.update
      (NativeArrayAllocation.allocate frame.nodes addedSet) source (some output)
    globals :=
      { frame.globals with
        hasJoined := frame.globals.hasJoined ∪ addedSet
        retirementCompleted :=
          Function.update frame.globals.retirementCompleted source completedSet } }

structure MembershipWritesResult {width : PNat} (source : Fin width)
    (added : Expr (.bits width)) (values : NodeRowTerms width)
    (completed : Expr (.bits width))
    (before allocated written joinedDefined completedDefined after : Encoding width)
    (joined retiredNodes : Nat) : Prop where
  addedBounded : added.symbols.all (fun symbol => symbol.2 < before.next) = true
  completedBounded : completed.symbols.all (fun symbol => symbol.2 < before.next) = true
  rowDefinitionsBounded :
    (nodeRowWriteDefinitions before.toColumns source values).all
      (fun item => item.2.symbols.all (fun symbol => symbol.2 < before.next)) = true
  allocationRun : (allocateNodes added).run before = .ok ((), allocated)
  rowRun : (writeNodeRow source values).run allocated = .ok ((), written)
  joinedRun :
    (define (.bitsOr (.free (.bits width) before.hasJoined) added)).run written =
      .ok (joined, joinedDefined)
  completedRun :
    (define
      (.store (.free (.array .int (.bits width)) before.retirementCompleted)
        (.integer source.val) completed)).run joinedDefined =
      .ok (retiredNodes, completedDefined)
  final :
    after =
      { completedDefined with
        hasJoined := joined
        retirementCompleted := retiredNodes }

theorem membership_writes_success {width : PNat} (source : Fin width)
    (added : Expr (.bits width)) (values : NodeRowTerms width)
    (completed : Expr (.bits width)) (before after : Encoding width)
    (run : (membershipWrites source added values completed).run before = .ok ((), after)) :
    exists allocated written joinedDefined completedDefined joined retiredNodes,
      MembershipWritesResult source added values completed before allocated written
        joinedDefined completedDefined after joined retiredNodes := by
  simp only [membershipWrites, get_bind_run] at run
  split at run
  · rename_i inputsBounded
    simp only [Bool.and_eq_true] at inputsBounded
    obtain ⟨_, allocated, allocationRun, run⟩ := (bind_run _ _ _ _ _).mp run
    obtain ⟨_, written, rowRun, run⟩ := (bind_run _ _ _ _ _).mp run
    obtain ⟨joined, joinedDefined, joinedRun, run⟩ := (bind_run _ _ _ _ _).mp run
    obtain ⟨retiredNodes, completedDefined, completedRun, run⟩ :=
      (bind_run _ _ _ _ _).mp run
    have final :
        after =
          { completedDefined with
            hasJoined := joined
            retirementCompleted := retiredNodes } :=
      (congrArg Prod.snd (Except.ok.inj run)).symm
    exact
      ⟨allocated, written, joinedDefined, completedDefined, joined, retiredNodes,
      {
        addedBounded := inputsBounded.1.1
        completedBounded := inputsBounded.1.2
        rowDefinitionsBounded := inputsBounded.2
        allocationRun
        rowRun
        joinedRun
        completedRun
        final }⟩
  · cases run

theorem allocate_nodes_next {width : PNat} (added : Expr (.bits width))
    (before after : Encoding width)
    (run : (allocateNodes added).run before = .ok ((), after)) :
    after.next = before.next + 17 * width /\
      after.bootstrap = before.bootstrap := by
  have shape := allocate_nodes_success added before after run
  exact ⟨shape.next, shape.sameBootstrap⟩

theorem membership_writes_shape {width : PNat} (source : Fin width)
    (added : Expr (.bits width)) (values : NodeRowTerms width)
    (completed : Expr (.bits width))
    (before allocated written joinedDefined completedDefined after : Encoding width)
    (joined retiredNodes : Nat)
    (result : MembershipWritesResult source added values completed before allocated written
      joinedDefined completedDefined after joined retiredNodes) :
    after.next = before.next + 17 * width + 18 /\
      after.bootstrap = before.bootstrap /\
      after.toColumns =
        membershipWriteColumns written.toColumns written.next /\
      after.assertions = completedDefined.assertions := by
  have allocationShape :=
    allocate_nodes_next added before allocated result.allocationRun
  have rowShape :=
    write_node_row_success source values allocated written result.rowRun
  obtain ⟨joinedId, joinedNext, joinedBootstrap, joinedColumns, joinedClauses⟩ :=
    define_success (.bitsOr (.free (.bits width) before.hasJoined) added)
      written joinedDefined joined result.joinedRun
  obtain ⟨retiredId, completedNext, completedBootstrap, completedColumns,
    completedClauses⟩ :=
    define_success
      (.store (.free (.array .int (.bits width)) before.retirementCompleted)
        (.integer source.val) completed)
      joinedDefined completedDefined retiredNodes result.completedRun
  constructor
  · rw [result.final, completedNext, joinedNext, rowShape.next, allocationShape.1]
  constructor
  · rw [result.final]
    exact completedBootstrap.trans (joinedBootstrap.trans
      (rowShape.bootstrap.trans allocationShape.2))
  constructor
  · rw [result.final, completedColumns, joinedColumns, retiredId, joinedId, joinedNext]
    rfl
  · rw [result.final]

theorem membership_writes_next_after_allocation {width : PNat} (source : Fin width)
    (added : Expr (.bits width)) (values : NodeRowTerms width)
    (completed : Expr (.bits width))
    (before allocated written joinedDefined completedDefined after : Encoding width)
    (joined retiredNodes : Nat)
    (result : MembershipWritesResult source added values completed before allocated written
      joinedDefined completedDefined after joined retiredNodes) :
    after.next = allocated.next + 18 := by
  have rowShape :=
    write_node_row_success source values allocated written result.rowRun
  have joinedShape :=
    define_success (.bitsOr (.free (.bits width) before.hasJoined) added)
      written joinedDefined joined result.joinedRun
  have completedShape :=
    define_success
      (.store (.free (.array .int (.bits width)) before.retirementCompleted)
        (.integer source.val) completed)
      joinedDefined completedDefined retiredNodes result.completedRun
  rw [result.final, completedShape.2.1, joinedShape.2.1, rowShape.next]

theorem membership_writes_values_bounded {width : PNat} (source : Fin width)
    (added : Expr (.bits width)) (values : NodeRowTerms width)
    (completed : Expr (.bits width))
    (before allocated written joinedDefined completedDefined after : Encoding width)
    (joined retiredNodes : Nat)
    (result : MembershipWritesResult source added values completed before allocated written
      joinedDefined completedDefined after joined retiredNodes) :
    values.Bounded before.next :=
  node_row_definition_values_bounded before.toColumns source values before.next
    result.rowDefinitionsBounded

private theorem encoded_union {width : PNat} (left right : Finset (Fin width)) :
    encodeBits left ||| encodeBits right = encodeBits (left ∪ right) := by
  apply BitVec.eq_of_getLsbD_eq
  intro index within
  let node : Fin width := ⟨index, within⟩
  rw [BitVec.getLsbD_or]
  change
    ((encodeBits left).getLsbD node.val || (encodeBits right).getLsbD node.val) =
      (encodeBits (left ∪ right)).getLsbD node.val
  rw [encode_bits_bit, encode_bits_bit, encode_bits_bit]
  by_cases inLeft : node ∈ left <;> by_cases inRight : node ∈ right <;>
    simp [inLeft, inRight]

theorem membership_writes_prior_holds_after_allocation {width : PNat}
    (source : Fin width) (added : Expr (.bits width))
    (values : NodeRowTerms width) (completed : Expr (.bits width))
    (before allocated written joinedDefined completedDefined after : Encoding width)
    (joined retiredNodes : Nat)
    (result : MembershipWritesResult source added values completed before allocated written
      joinedDefined completedDefined after joined retiredNodes)
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment) :
    Holds allocated.assertions.toList assignment := by
  have completedHolds : Holds completedDefined.assertions.toList assignment := by
    simpa [result.final] using holds
  have joinedHolds :=
    define_prior_holds _ _ _ _ result.completedRun assignment completedHolds
  have writtenHolds :=
    define_prior_holds _ _ _ _ result.joinedRun assignment joinedHolds
  exact write_node_row_prior_holds source values allocated written
    result.rowRun assignment writtenHolds

theorem membership_writes_references_after_allocation {width : PNat}
    (source : Fin width) (added : Expr (.bits width))
    (values : NodeRowTerms width) (completed : Expr (.bits width))
    (before allocated written joinedDefined completedDefined after : Encoding width)
    (joined retiredNodes : Nat)
    (result : MembershipWritesResult source added values completed before allocated written
      joinedDefined completedDefined after joined retiredNodes)
    (valid : ReferencesValid allocated) :
    ReferencesValid after := by
  have writtenValid :=
    write_node_row_references source values allocated written result.rowRun valid
  have joinedValid :=
    define_references _ written joinedDefined joined result.joinedRun writtenValid
  have completedValid :=
    define_references _ joinedDefined completedDefined retiredNodes
      result.completedRun joinedValid
  rw [result.final]
  have joinedShape :=
    define_success (.bitsOr (.free (.bits width) before.hasJoined) added)
      written joinedDefined joined result.joinedRun
  have completedShape :=
    define_success
      (.store (.free (.array .int (.bits width)) before.retirementCompleted)
        (.integer source.val) completed)
      joinedDefined completedDefined retiredNodes result.completedRun
  cases completedValid
  constructor <;> simp only <;> omega

theorem membership_writes_after_allocation_frame_sound {width : PNat}
    (source : Fin width) (added : Expr (.bits width))
    (values : NodeRowTerms width) (completed : Expr (.bits width))
    (before allocated written joinedDefined completedDefined after : Encoding width)
    (joined retiredNodes : Nat)
    (result : MembershipWritesResult source added values completed before allocated written
      joinedDefined completedDefined after joined retiredNodes)
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (addedSet completedSet : Finset (Fin width))
    (output : NativeArrayCheckQuorum.Local (Fin width) Nat)
    (allocatedRep : FrameColumnsRep assignment allocated.toColumns
      { frame with nodes := NativeArrayAllocation.allocate frame.nodes addedSet })
    (beforeRep : FrameColumnsRep assignment before.toColumns frame)
    (valuesRep : values.Rep assignment output)
    (sameAdded : added.eval assignment Locals.empty = encodeBits addedSet)
    (sameCompleted : completed.eval assignment Locals.empty = encodeBits completedSet) :
    FrameColumnsRep assignment after.toColumns
      (membershipWriteFrame frame source addedSet completedSet output) := by
  have completedHolds : Holds completedDefined.assertions.toList assignment := by
    simpa [result.final] using holds
  have joinedHolds :=
    define_prior_holds _ _ _ _ result.completedRun assignment completedHolds
  have writtenHolds :=
    define_prior_holds _ _ _ _ result.joinedRun assignment joinedHolds
  have rowRep :=
    write_node_row_frame_sound source values output allocated written
      result.rowRun assignment writtenHolds
      { frame with nodes := NativeArrayAllocation.allocate frame.nodes addedSet }
      allocatedRep valuesRep
  have joinedShape :=
    define_success (.bitsOr (.free (.bits width) before.hasJoined) added)
      written joinedDefined joined result.joinedRun
  have completedShape :=
    define_success
      (.store (.free (.array .int (.bits width)) before.retirementCompleted)
        (.integer source.val) completed)
      joinedDefined completedDefined retiredNodes result.completedRun
  have joinedBinding :
      assignment (.bits width) joined =
        (Term.bitsOr (.free (.bits width) before.hasJoined) added).eval
          assignment Locals.empty := by
    apply definition_clause_binding joinedHolds
    rw [joinedShape.2.2.2.2, Array.toList_push]
    simp
  have completedBinding :
      assignment (.array .int (.bits width)) retiredNodes =
        (Term.store (.free (.array .int (.bits width)) before.retirementCompleted)
          (.integer source.val) completed).eval assignment Locals.empty := by
    apply definition_clause_binding completedHolds
    rw [completedShape.2.2.2.2, Array.toList_push]
    simp
  have columns :
      after.toColumns =
        membershipWriteColumns written.toColumns written.next :=
    (membership_writes_shape source added values completed before allocated written
      joinedDefined completedDefined after joined retiredNodes result).2.2.1
  have oldJoined :
      assignment (.bits width) before.hasJoined = encodeBits frame.globals.hasJoined := by
    exact beforeRep.hasJoined
  have retiredId : retiredNodes = written.next + 1 := by
    rw [completedShape.1, joinedShape.2.1]
  constructor
  · rw [columns]
    have nodesRep := rowRep.nodes
    cases nodesRep
    constructor <;> simpa [membershipWriteColumns, membershipWriteFrame]
  · rw [columns]
    simp only [membershipWriteColumns, membershipWriteFrame]
    rw [<- joinedShape.1, joinedBinding]
    change assignment (.bits width) before.hasJoined ||| added.eval assignment Locals.empty =
      encodeBits (frame.globals.hasJoined ∪ addedSet)
    rw [oldJoined, sameAdded, encoded_union]
  · intro peer
    simpa [membershipWriteFrame, columns, membershipWriteColumns] using
      rowRep.preVoteStatus peer
  · intro peer
    rw [columns]
    simp only [membershipWriteColumns, membershipWriteFrame]
    have selected := stored_array_read_correct assignment before.retirementCompleted
      retiredNodes source.val peer.val completed completedBinding
    rw [<- retiredId]
    by_cases same : peer = source
    · subst peer
      simpa [sameCompleted] using selected
    · have different : peer.val ≠ source.val := fun equal => same (Fin.ext equal)
      rw [selected, if_neg different]
      simp only [Function.update, same]
      exact beforeRep.retirementCompleted peer
  · intro txId
    simpa [membershipWriteFrame, columns, membershipWriteColumns] using
      rowRep.submittedTxIds txId
  · intro destination packetSource
    simpa [membershipWriteFrame, columns, membershipWriteColumns, queueRow] using
      rowRep.queues destination packetSource

theorem membership_writes_prior_holds {width : PNat} (source : Fin width)
    (added : Expr (.bits width)) (values : NodeRowTerms width)
    (completed : Expr (.bits width)) (before after : Encoding width)
    (run : (membershipWrites source added values completed).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment) :
    Holds before.assertions.toList assignment := by
  obtain ⟨allocated, written, joinedDefined, completedDefined, joined, retiredNodes,
    result⟩ := membership_writes_success source added values completed before after run
  exact allocate_nodes_prior_holds added before allocated result.allocationRun assignment
    (membership_writes_prior_holds_after_allocation source added values completed before
      allocated written joinedDefined completedDefined after joined retiredNodes result
      assignment holds)

theorem membership_writes_references {width : PNat} (source : Fin width)
    (added : Expr (.bits width)) (values : NodeRowTerms width)
    (completed : Expr (.bits width)) (before after : Encoding width)
    (run : (membershipWrites source added values completed).run before = .ok ((), after))
    (valid : ReferencesValid before) :
    ReferencesValid after := by
  obtain ⟨allocated, written, joinedDefined, completedDefined, joined, retiredNodes,
    result⟩ := membership_writes_success source added values completed before after run
  have allocatedValid :=
    allocate_nodes_references added before allocated result.allocationRun valid
  exact membership_writes_references_after_allocation source added values completed before
    allocated written joinedDefined completedDefined after joined retiredNodes result
    allocatedValid

theorem membership_writes_frame_sound {width : PNat} (source : Fin width)
    (added : Expr (.bits width)) (values : NodeRowTerms width)
    (completed : Expr (.bits width)) (before after : Encoding width)
    (run : (membershipWrites source added values completed).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (output : NativeArrayCheckQuorum.Local (Fin width) Nat)
    (rep : FrameColumnsRep assignment before.toColumns frame)
    (valuesRep : values.Rep assignment output) :
    FrameColumnsRep assignment after.toColumns
      (membershipWriteFrame frame source
        (decodeBits (added.eval assignment Locals.empty))
        (decodeBits (completed.eval assignment Locals.empty)) output) := by
  obtain ⟨allocated, written, joinedDefined, completedDefined, joined, retiredNodes,
    result⟩ := membership_writes_success source added values completed before after run
  have allocationHolds :=
    membership_writes_prior_holds_after_allocation source added values completed before
      allocated written joinedDefined completedDefined after joined retiredNodes result
      assignment holds
  have allocatedRep :=
    allocate_nodes_frame_sound added before allocated result.allocationRun assignment
      allocationHolds frame rep
  exact membership_writes_after_allocation_frame_sound source added values completed before
    allocated written joinedDefined completedDefined after joined retiredNodes result
    assignment holds frame (decodeBits (added.eval assignment Locals.empty))
    (decodeBits (completed.eval assignment Locals.empty)) output allocatedRep rep valuesRep
    (by simp) (by simp)

theorem membership_writes_complete {width : PNat} (source : Fin width)
    (added : Expr (.bits width)) (values : NodeRowTerms width)
    (completed : Expr (.bits width)) (before after : Encoding width)
    (run : (membershipWrites source added values completed).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds before.assertions.toList assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (output : NativeArrayCheckQuorum.Local (Fin width) Nat)
    (rep : FrameColumnsRep assignment before.toColumns frame)
    (valuesRep : values.Rep assignment output)
    (valid : ReferencesValid before) :
    after.next = before.next + 17 * width + 18 /\
      exists extended : Assignment,
        assignment.AgreesBelow before.next extended /\
        Holds after.assertions.toList extended /\
        FrameColumnsRep extended after.toColumns
          (membershipWriteFrame frame source
            (decodeBits (added.eval assignment Locals.empty))
            (decodeBits (completed.eval assignment Locals.empty)) output) := by
  obtain ⟨allocated, written, joinedDefined, completedDefined, joined, retiredNodes,
    result⟩ := membership_writes_success source added values completed before after run
  obtain ⟨allocationNext, allocatedAssignment, allocationAgreement, allocationHolds,
    allocatedRep⟩ :=
    allocate_nodes_complete added before allocated result.allocationRun assignment holds
      frame rep valid
  have valuesBounded :=
    membership_writes_values_bounded source added values completed before allocated written
      joinedDefined completedDefined after joined retiredNodes result
  have allocatedValues :=
    valuesRep.agrees_below assignment allocatedAssignment values output before.next
      valuesBounded allocationAgreement
  have allocatedValid :=
    allocate_nodes_references added before allocated result.allocationRun valid
  obtain ⟨rowAssignment, rowAgreement, rowHolds, _⟩ :=
    write_node_row_complete source values output allocated written result.rowRun
      allocatedAssignment allocationHolds
      { frame with
        nodes := NativeArrayAllocation.allocate frame.nodes
          (decodeBits (added.eval assignment Locals.empty)) }
      allocatedRep allocatedValues allocatedValid
  obtain ⟨joinedAssignment, joinedAgreement, joinedHolds⟩ :=
    define_extension (.bitsOr (.free (.bits width) before.hasJoined) added)
      written joinedDefined joined result.joinedRun rowAssignment rowHolds
  obtain ⟨extended, completedAgreement, completedHolds⟩ :=
    define_extension
      (.store (.free (.array .int (.bits width)) before.retirementCompleted)
        (.integer source.val) completed)
      joinedDefined completedDefined retiredNodes result.completedRun
      joinedAssignment joinedHolds
  have rowShape :=
    write_node_row_success source values allocated written result.rowRun
  have joinedShape :=
    define_success (.bitsOr (.free (.bits width) before.hasJoined) added)
      written joinedDefined joined result.joinedRun
  have allocatedToExtended : allocatedAssignment.AgreesBelow allocated.next extended :=
    rowAgreement.trans
      ((joinedAgreement.trans
        (completedAgreement.restrict (by rw [joinedShape.2.1]; omega))).restrict
          (by rw [rowShape.next]; omega))
  have agreement : assignment.AgreesBelow before.next extended :=
    allocationAgreement.trans
      (allocatedToExtended.restrict (by rw [allocationNext]; omega))
  have finalHolds : Holds after.assertions.toList extended := by
    simpa [result.final] using completedHolds
  have finalRep :=
    rep.agrees_below before assignment extended frame valid agreement
  have finalValues :=
    valuesRep.agrees_below assignment extended values output before.next
      valuesBounded agreement
  have addedBounded :
      forall symbol, symbol ∈ added.symbols -> symbol.2 < before.next := by
    intro symbol member
    simpa using List.all_eq_true.mp result.addedBounded symbol member
  have completedBounded :
      forall symbol, symbol ∈ completed.symbols -> symbol.2 < before.next := by
    intro symbol member
    simpa using List.all_eq_true.mp result.completedBounded symbol member
  have addedSame :
      added.eval extended Locals.empty = added.eval assignment Locals.empty :=
    (added.eval_agrees_below assignment extended Locals.empty before.next
      addedBounded agreement).symm
  have completedSame :
      completed.eval extended Locals.empty = completed.eval assignment Locals.empty :=
    (completed.eval_agrees_below assignment extended Locals.empty before.next
      completedBounded agreement).symm
  have sound :=
    membership_writes_frame_sound source added values completed before after run
      extended finalHolds frame output finalRep finalValues
  exact
    ⟨(membership_writes_shape source added values completed before allocated written
      joinedDefined completedDefined after joined retiredNodes result).1,
      extended, agreement, finalHolds, by
        simpa [addedSame, completedSame] using sound⟩

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
