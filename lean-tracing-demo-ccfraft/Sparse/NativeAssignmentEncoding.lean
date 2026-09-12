-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeTraceEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem Assignment.set_other_index (assignment : Assignment) (updated sort : Ty)
    (id index : Nat) (value : updated.denote) (different : index ≠ id) :
    (assignment.set updated id value) sort index = assignment sort index := by
  by_cases same : sort = updated
  · subst sort
    simp [Assignment.set, different]
  · simp [Assignment.set, same]

structure ReferencesValid {width : PNat} (state : Encoding width) : Prop where
  minimum : 22 <= state.next
  role : state.role < state.next
  newFollower : state.newFollower < state.next
  retirementIndex : state.retirementIndex < state.next
  retirementCommittableIndex : state.retirementCommittableIndex < state.next
  retiredCommittedIndex : state.retiredCommittedIndex < state.next
  votedFor : state.votedFor < state.next
  votesGranted : state.votesGranted < state.next
  preVotesGranted : state.preVotesGranted < state.next
  membershipState : state.membershipState < state.next
  sentIndex : state.sentIndex < state.next
  matchIndex : state.matchIndex < state.next
  hasJoined : state.hasJoined < state.next
  preVoteStatus : state.preVoteStatus < state.next
  retirementCompleted : state.retirementCompleted < state.next
  submittedTxIds : state.submittedTxIds < state.next
  submittedTxLimit : state.submittedTxLimit < state.next
  queueLength : state.queueLength < state.next

theorem ReferencesValid.same_references {width : PNat} {before after : Encoding width}
    (valid : ReferencesValid before) (same : SameReferences before after) :
    ReferencesValid after := by
  rcases before with ⟨columns, bootstrap, next, assertions, bounded⟩
  rcases after with ⟨afterColumns, afterBootstrap, afterNext, afterAssertions, afterBounded⟩
  obtain ⟨_, columnsEqual, nextEqual⟩ := same
  dsimp only at columnsEqual nextEqual
  subst afterColumns
  subst afterNext
  cases valid
  constructor <;> assumption

theorem instruction_references {width : PNat}
    (item : NativeArrayCheckQuorum.Instruction (Fin width) Nat) (before after : Encoding width)
    (run : (instruction item).run before = .ok ((), after)) (valid : ReferencesValid before) :
    ReferencesValid after := by
  rcases instruction_cases item before after run with ⟨node, _, action⟩ | ⟨clauses, _, asserted⟩
  · have shape := quorum_success node.val before after action
    constructor
    · rw [shape.next]
      have minimum := valid.minimum
      omega
    · rw [shape.role, shape.next]
      omega
    · rw [shape.newFollower, shape.next]
      omega
    · have bound := valid.retirementIndex
      simp only [shape.columns, shape.next]
      omega
    · have bound := valid.retirementCommittableIndex
      simp only [shape.columns, shape.next]
      omega
    · have bound := valid.retiredCommittedIndex
      simp only [shape.columns, shape.next]
      omega
    · have bound := valid.votedFor
      simp only [shape.columns, shape.next]
      omega
    · have bound := valid.votesGranted
      simp only [shape.columns, shape.next]
      omega
    · have bound := valid.preVotesGranted
      simp only [shape.columns, shape.next]
      omega
    · have bound := valid.membershipState
      simp only [shape.columns, shape.next]
      omega
    · have bound := valid.sentIndex
      simp only [shape.columns, shape.next]
      omega
    · have bound := valid.matchIndex
      simp only [shape.columns, shape.next]
      omega
    · have bound := valid.hasJoined
      simp only [shape.columns, shape.next]
      omega
    · have bound := valid.preVoteStatus
      simp only [shape.columns, shape.next]
      omega
    · have bound := valid.retirementCompleted
      simp only [shape.columns, shape.next]
      omega
    · have bound := valid.submittedTxIds
      simp only [shape.columns, shape.next]
      omega
    · have bound := valid.submittedTxLimit
      simp only [shape.columns, shape.next]
      omega
    · have bound := valid.queueLength
      simp only [shape.columns, shape.next]
      omega
  · have frame := (assert_all_success clauses before after asserted).1
    exact valid.same_references frame

theorem Encoding.holds_agrees_below {width : PNat} (state : Encoding width)
    (left right : Assignment) (holds : Holds state.assertions.toList left)
    (same : left.AgreesBelow state.next right) : Holds state.assertions.toList right :=
  holds.agrees_below state.next
    (fun formula member => state.symbolsBounded formula (by simpa using member)) same

theorem NodeColumnsRep.agrees_below {width : PNat} (state : Encoding width)
    (left right : Assignment) (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat)
    (rep : NodeColumnsRep left state.toColumns arrays) (valid : ReferencesValid state)
    (same : left.AgreesBelow state.next right) :
    NodeColumnsRep right state.toColumns arrays := by
  have minimum := valid.minimum
  have allocation := same (.array .int .bool) 0 (by omega)
  have roles := same (.array .int .int) state.role valid.role
  have followers := same (.array .int .bool) state.newFollower valid.newFollower
  have lengths := same (.array .int .int) 3 (by omega)
  have commits := same (.array .int .int) 4 (by omega)
  have terms := same (.array .int .int) 5 (by omega)
  have logs := same (.array .int (.array .int (entryTy width))) 6 (by omega)
  have retirement := same (.array .int optionalIntTy) state.retirementIndex valid.retirementIndex
  have committable := same (.array .int optionalIntTy) state.retirementCommittableIndex valid.retirementCommittableIndex
  have committed := same (.array .int optionalIntTy) state.retiredCommittedIndex valid.retiredCommittedIndex
  have voted := same (.array .int optionalIntTy) state.votedFor valid.votedFor
  have votes := same (.array .int (.bits width)) state.votesGranted valid.votesGranted
  have preVotes := same (.array .int (.bits width)) state.preVotesGranted valid.preVotesGranted
  have membership := same (.array .int .int) state.membershipState valid.membershipState
  have sent := same (.array .int (.array .int .int)) state.sentIndex valid.sentIndex
  have matched := same (.array .int (.array .int .int)) state.matchIndex valid.matchIndex
  constructor
  · intro node
    simpa only [NativeEncode.allocated, Term.eval, <- allocation] using rep.allocated node
  · intro node
    simpa only [read, NativeEncode.allocated, Term.eval, <- allocation, <- roles] using rep.role node
  · intro node
    simpa only [read, NativeEncode.allocated, Term.eval, <- allocation, <- followers] using rep.newFollower node
  · intro node
    simpa only [read, NativeEncode.allocated, Term.eval, <- allocation, <- terms] using rep.currentTerm node
  · intro node
    simpa only [NativeEncode.commit, read, NativeEncode.allocated, Term.eval, <- allocation, <- commits] using rep.commit node
  · intro node
    simpa only [NativeEncode.length, read, NativeEncode.allocated, Term.eval, <- allocation, <- lengths] using rep.length node
  · intro node index within
    simpa only [entryAt, Term.eval, <- logs] using rep.entries node index within
  · intro node
    simpa only [read, NativeEncode.allocated, Term.eval, <- allocation, <- retirement] using rep.retirementIndex node
  · intro node
    simpa only [read, NativeEncode.allocated, Term.eval, <- allocation, <- committable] using rep.retirementCommittableIndex node
  · intro node
    simpa only [read, NativeEncode.allocated, Term.eval, <- allocation, <- committed] using rep.retiredCommittedIndex node
  · intro node
    simpa only [read, NativeEncode.allocated, Term.eval, <- allocation, <- voted] using rep.votedFor node
  · intro node
    simpa only [read, NativeEncode.allocated, Term.eval, <- allocation, <- votes] using rep.votesGranted node
  · intro node
    simpa only [read, NativeEncode.allocated, Term.eval, <- allocation, <- preVotes] using rep.preVotesGranted node
  · intro node
    simpa only [read, NativeEncode.allocated, Term.eval, <- allocation, <- membership] using rep.membershipState node
  · intro node peer
    simpa only [peerIndex, NativeEncode.allocated, Term.eval, <- allocation, <- sent] using rep.sentIndex node peer
  · intro node peer
    simpa only [peerIndex, NativeEncode.allocated, Term.eval, <- allocation, <- matched] using rep.matchIndex node peer

theorem NodeDomain.agrees_below {width : PNat} (limit : Nat) (left right : Assignment)
    (node : Nat) (domain : NodeDomain width left node) (minimum : 22 <= limit)
    (same : left.AgreesBelow limit right) : NodeDomain width right node := by
  have allocation := same (.array .int .bool) 0 (by omega)
  have roles := same (.array .int .int) 1 (by omega)
  have lengths := same (.array .int .int) 3 (by omega)
  have commits := same (.array .int .int) 4 (by omega)
  have terms := same (.array .int .int) 5 (by omega)
  have logs := same (.array .int (.array .int (entryTy width))) 6 (by omega)
  have retirement := same (.array .int optionalIntTy) 7 (by omega)
  have committable := same (.array .int optionalIntTy) 8 (by omega)
  have committed := same (.array .int optionalIntTy) 9 (by omega)
  have voted := same (.array .int optionalIntTy) 10 (by omega)
  have membership := same (.array .int .int) 13 (by omega)
  have sent := same (.array .int (.array .int .int)) 14 (by omega)
  have matched := same (.array .int (.array .int .int)) 15 (by omega)
  constructor
  · simpa only [scalarValue, <- allocation, <- roles] using domain.role
  · simpa only [scalarValue, <- allocation, <- lengths] using domain.length
  · simpa only [scalarValue, <- allocation, <- commits] using domain.commit
  · simpa only [scalarValue, <- allocation, <- terms] using domain.term
  · intro index within
    have previous : 0 <= index /\ index < scalarValue left 3 node := by
      simpa only [scalarValue, <- allocation, <- lengths] using within
    simpa only [<- logs] using domain.entries index previous
  · simpa only [read, NativeEncode.allocated, Term.eval, <- allocation, <- retirement] using domain.retirementIndex
  · simpa only [read, NativeEncode.allocated, Term.eval, <- allocation, <- committable] using domain.retirementCommittableIndex
  · simpa only [read, NativeEncode.allocated, Term.eval, <- allocation, <- committed] using domain.retiredCommittedIndex
  · simpa only [read, NativeEncode.allocated, Term.eval, <- allocation, <- voted] using domain.votedFor
  · simpa only [scalarValue, <- allocation, <- membership] using domain.membershipState
  · intro peer
    simpa only [peerIndex, NativeEncode.allocated, Term.eval, <- allocation, <- sent] using domain.sentIndex peer
  · intro peer
    simpa only [peerIndex, NativeEncode.allocated, Term.eval, <- allocation, <- matched] using domain.matchIndex peer

theorem assigned_definition {sort : Ty} (value : Expr sort) (assignment : Assignment)
    (id : Nat) (fresh : (sort, id) ∉ value.symbols) :
    (Term.equal (.free sort id) value).eval
      (assignment.set sort id (value.eval assignment Locals.empty)) Locals.empty = true := by
  simp only [Term.eval, decide_eq_true_eq]
  rw [Term.eval_set_of_fresh value assignment Locals.empty id _ fresh]
  simp [Assignment.set]

theorem quorum_complete {width : PNat} [Bootstrap (Fin width)]
    (node : Fin width) (before after : Encoding width)
    (run : (checkQuorum node.val).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds before.assertions.toList assignment)
    (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat)
    (columns : NodeColumnsRep assignment before.toColumns arrays)
    (valid : ReferencesValid before)
    (sameBootstrap : decodeBits before.bootstrap = INITIAL_CONFIGURATION)
    (enabled : NativeArrayCheckQuorum.enabled arrays node) :
    exists extended : Assignment, assignment.AgreesBelow before.next extended /\
      Holds after.assertions.toList extended /\
      NodeColumnsRep extended after.toColumns (NativeArrayCheckQuorum.step arrays node) := by
  obtain ⟨currentValue, witnessValue, guards⟩ :=
    (node_columns_enabled assignment before.bootstrap before.toColumns arrays node
      before.next (before.next + 1) (by omega) columns sameBootstrap).mpr enabled
  let witnesses := (assignment.set .int before.next currentValue).set .int (before.next + 1) witnessValue
  have witnessAgreement : assignment.AgreesBelow before.next witnesses :=
    (assignment.agrees_below_set before.next .int before.next currentValue (by omega)).trans
      ((assignment.set .int before.next currentValue).agrees_below_set before.next .int
        (before.next + 1) witnessValue (by omega))
  let roleValue := stepDownRole before.role node.val
  let followerValue := stepDownFollower before.newFollower node.val
  let roleAssignment := witnesses.set (.array .int .int) (before.next + 2)
    (roleValue.eval witnesses Locals.empty)
  let extended := roleAssignment.set (.array .int .bool) (before.next + 3)
    (followerValue.eval roleAssignment Locals.empty)
  have storeAgreement : witnesses.AgreesBelow (before.next + 2) extended :=
    (witnesses.agrees_below_set (before.next + 2) (.array .int .int) (before.next + 2)
      (roleValue.eval witnesses Locals.empty) (by omega)).trans
      (roleAssignment.agrees_below_set (before.next + 2) (.array .int .bool) (before.next + 3)
        (followerValue.eval roleAssignment Locals.empty) (by omega))
  have agreement := witnessAgreement.trans (storeAgreement.restrict (by omega))
  have roleFresh : (.array .int .int, before.next + 2) ∉ roleValue.symbols := by
    have bound := valid.role
    simp [roleValue, stepDownRole, Term.symbols]
    omega
  have followerFresh : (.array .int .bool, before.next + 3) ∉ followerValue.symbols := by
    have bound := valid.newFollower
    simp [followerValue, stepDownFollower, Term.symbols]
    omega
  have roleBinding : (Term.equal (.free (.array .int .int) (before.next + 2)) roleValue).eval
      extended Locals.empty = true := by
    rw [Term.eval_set_of_fresh _ roleAssignment Locals.empty (before.next + 3) _ (by
      simp [roleValue, stepDownRole, Term.symbols])]
    exact assigned_definition roleValue witnesses (before.next + 2) roleFresh
  have followerBinding := assigned_definition followerValue roleAssignment (before.next + 3) followerFresh
  have shape := quorum_success node.val before after run
  have afterHolds : Holds after.assertions.toList extended :=
    (quorum_holds node.val before after run extended).mpr
      ⟨before.holds_agrees_below assignment extended holds agreement,
        guards.agrees_below (before.next + 2) shape.guardSymbols storeAgreement, roleBinding, followerBinding⟩
  have afterColumns := (quorum_native_success node before after run extended afterHolds arrays
    (columns.agrees_below before assignment extended arrays valid agreement) sameBootstrap).2.2
  exact ⟨extended, agreement, afterHolds, afterColumns⟩

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
