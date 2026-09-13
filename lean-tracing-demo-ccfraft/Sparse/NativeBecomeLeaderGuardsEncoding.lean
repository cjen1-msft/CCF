-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayBecomeLeader
import Sparse.NativeBecomeLeader
import Sparse.NativeFrameColumns
import Sparse.NativeNodeRowWritesEncoding
import Sparse.NativeVotingMajorityEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem become_leader_guards_correct {width : PNat} [Bootstrap (Fin width)]
    (assignment : Assignment) (bootstrap : BitVec width) (columns : Columns)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment columns frame)
    (source : Fin width) (current membership : Expr .int)
    (currentNat : Nat)
    (output : NativeArrayCheckQuorum.Local (Fin width) Nat)
    (sameBootstrap : bootstrap = encodeBits INITIAL_CONFIGURATION)
    (sameCurrent :
      current.eval assignment Locals.empty = (currentNat : Int))
    (sameMembership :
      membership.eval assignment Locals.empty =
        membershipCode output.membershipState) :
    Holds
        (becomeLeaderGuards bootstrap columns source current membership)
        assignment <->
      NativeArrayBecomeLeader.enabled frame source currentNat output := by
  let old := NativeArrayCheckQuorum.get frame.nodes source
  have oldRep :=
    node_row_snapshot_rep assignment columns frame.nodes rep.nodes source
  have majorityCorrect :=
    voting_majority_term_correct assignment Locals.empty bootstrap
      (nodeRowSnapshot columns source).logLength current
      (nodeRowSnapshot columns source).logEntries
      (nodeRowSnapshot columns source).votesGranted old currentNat
      old.votesGranted sameBootstrap oldRep.logLength sameCurrent
      oldRep.logEntries oldRep.votesGranted
  simp only [becomeLeaderGuards, Holds, List.mem_cons, List.not_mem_nil,
    or_false, or_imp, forall_and, forall_eq]
  rw [majorityCorrect]
  simp only [nodeRowSnapshot, Term.eval, rep.nodes.allocated, rep.nodes.role,
    rep.nodes.membershipState, sameMembership,
    Bool.not_eq_true', decide_eq_false_iff_not, decide_eq_true_eq,
    role_code_eq, membership_code_eq, NativeArrayBecomeLeader.enabled]
  rfl

theorem become_leader_guards_bounded {width : PNat}
    (before : Encoding width) (bootstrap : BitVec width) (source : Fin width)
    (current membership : Expr .int) (valid : ReferencesValid before)
    (currentBounded :
      current.symbols.all (fun symbol => symbol.2 < before.next) = true)
    (membershipBounded :
      membership.symbols.all (fun symbol => symbol.2 < before.next) = true) :
    forall guard,
      guard ∈ becomeLeaderGuards bootstrap before.toColumns source current membership ->
        guard.symbols.all (fun symbol => symbol.2 < before.next) = true := by
  have oldBounded := node_row_snapshot_bounded before source valid
  have majorityBounded :=
    voting_majority_term_bounded bootstrap
      (nodeRowSnapshot before.toColumns source).logLength current
      (nodeRowSnapshot before.toColumns source).logEntries
      (nodeRowSnapshot before.toColumns source).votesGranted before.next
      oldBounded.logLength currentBounded oldBounded.logEntries
      oldBounded.votesGranted
  intro guard member
  simp only [becomeLeaderGuards, List.mem_cons, List.not_mem_nil, or_false] at member
  rcases member with rfl | rfl | rfl | rfl | rfl
  · simp [allocated, Term.symbols, valid.allocated]
  · simp [Term.symbols, oldBounded.role]
  · simp [Term.symbols, oldBounded.membershipState]
  · exact majorityBounded
  · simp [Term.symbols, membershipBounded]

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
