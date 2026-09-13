-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayClientRequest
import Sparse.NativeClientRequestTerms
import Sparse.NativeFrameColumns
import Sparse.NativeNodeRowWritesEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem client_request_guards_correct {width : PNat}
    (assignment : Assignment) (columns : Columns)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment columns frame)
    (source : Fin width) (transaction membership : Expr .int)
    (transactionNat : Nat)
    (output : NativeArrayCheckQuorum.Local (Fin width) Nat)
    (sameTransaction :
      transaction.eval assignment Locals.empty = (transactionNat : Int))
    (sameMembership :
      membership.eval assignment Locals.empty =
        membershipCode output.membershipState) :
    Holds (clientRequestGuards columns source transaction membership) assignment <->
      NativeArrayClientRequest.enabled frame source transactionNat output := by
  have notSubmitted :
      (assignment .int columns.submittedTxLimit <= (transactionNat : Int) \/
          assignment (.array .int (.bits 1)) columns.submittedTxIds transactionNat ≠ 1) <->
        transactionNat ∉ frame.globals.submittedTxIds := by
    have represented := rep.submittedTxIds transactionNat
    constructor
    · intro excluded member
      have included := represented.mpr member
      rcases excluded with beyond | absent
      · exact (not_lt_of_ge beyond) included.1
      · exact absent included.2
    · intro absent
      by_cases within :
          (transactionNat : Int) < assignment .int columns.submittedTxLimit
      · right
        intro present
        exact absent (represented.mp ⟨within, present⟩)
      · left
        exact le_of_not_gt within
  simp only [clientRequestGuards, Holds, List.mem_cons, List.not_mem_nil,
    or_false, or_imp, forall_and, forall_eq]
  simp [nodeRowSnapshot, natSetMember, all, lt, Term.eval, rep.nodes.allocated,
    rep.nodes.role, rep.nodes.membershipState, sameTransaction, sameMembership,
    role_code_eq, membership_code_eq,
    NativeArrayClientRequest.enabled]
  intro _ _ _ _
  exact notSubmitted

theorem client_request_guards_bounded {width : PNat}
    (before : Encoding width) (source : Fin width)
    (transaction membership : Expr .int) (valid : ReferencesValid before)
    (transactionBounded :
      transaction.symbols.all (fun symbol => symbol.2 < before.next) = true)
    (membershipBounded :
      membership.symbols.all (fun symbol => symbol.2 < before.next) = true) :
    forall guard,
      guard ∈ clientRequestGuards before.toColumns source transaction membership ->
        guard.symbols.all (fun symbol => symbol.2 < before.next) = true := by
  have oldBounded := node_row_snapshot_bounded before source valid
  intro guard member
  simp only [clientRequestGuards, List.mem_cons, List.not_mem_nil, or_false] at member
  rcases member with rfl | rfl | rfl | rfl | rfl | rfl
  · simp [allocated, Term.symbols, valid.allocated]
  · simp [Term.symbols, oldBounded.role]
  · simp [Term.symbols, oldBounded.membershipState]
  · simp [Term.symbols, transactionBounded]
  · simp [natSetMember, all, lt, Term.symbols, transactionBounded,
      valid.submittedTxIds, valid.submittedTxLimit]
  · simp [Term.symbols, membershipBounded]

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
