-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayAdvanceCommit
import Sparse.NativeCommitTerms
import Sparse.NativeFrameColumns
import Sparse.NativeNodeRowWritesEncoding
import Sparse.NativeRetirementRefreshEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem commit_row_terms_rep {width : PNat}
    (assignment : Assignment)
    (oldTerms : NodeRowTerms width)
    (oldRow : NativeArrayCheckQuorum.Local (Fin width) Nat)
    (best retirement signature retired : Expr .int)
    (bestNat : Nat)
    (retirementChoice signatureChoice retiredChoice : Option Nat)
    (oldRep : oldTerms.Rep assignment oldRow)
    (sameBest : best.eval assignment Locals.empty = (bestNat : Int))
    (sameRetirement :
      retirement.eval assignment Locals.empty =
        firstMatchValue retirementChoice)
    (sameSignature :
      signature.eval assignment Locals.empty =
        firstMatchValue signatureChoice)
    (sameRetired :
      retired.eval assignment Locals.empty =
        firstMatchValue retiredChoice) :
    (commitRowTerms oldTerms best retirement signature retired).Rep assignment
      (NativeArrayAdvanceCommit.commitRow oldRow bestNat retirementChoice
        (signatureChoice.map (1 + ·)) (retiredChoice.map (1 + ·))) := by
  let committed := { oldRow with commit := bestNat }
  have refreshed :=
    retirement_refresh_terms_eval assignment Locals.empty best retirement signature
      retired committed retirementChoice signatureChoice retiredChoice
      (by simpa [committed] using sameBest) sameRetirement sameSignature sameRetired
  refine { oldRep with
    commit := ?_
    retirementIndex := ?_
    retirementCommittableIndex := ?_
    retiredCommittedIndex := ?_
    membershipState := ?_ }
  · exact sameBest
  · simpa [commitRowTerms, NativeArrayAdvanceCommit.commitRow, committed,
      NativeArrayRetirement.refresh] using refreshed.1
  · simpa [commitRowTerms, NativeArrayAdvanceCommit.commitRow, committed,
      NativeArrayRetirement.refresh] using refreshed.2.1
  · simpa [commitRowTerms, NativeArrayAdvanceCommit.commitRow, committed,
      NativeArrayRetirement.refresh] using refreshed.2.2.1
  · simpa [commitRowTerms, NativeArrayAdvanceCommit.commitRow, committed,
      NativeArrayRetirement.refresh] using refreshed.2.2.2

theorem commit_refresh_constraints_output_sound {width : PNat}
    [Bootstrap (Fin width)]
    (assignment : Assignment)
    (bootstrap : BitVec width)
    (oldTerms : NodeRowTerms width)
    (source : Fin width)
    (best first retirement signature retired : Expr .int)
    (oldRow : NativeArrayCheckQuorum.Local (Fin width) Nat)
    (bestNat : Nat)
    (oldRep : oldTerms.Rep assignment oldRow)
    (sameBootstrap : decodeBits bootstrap = INITIAL_CONFIGURATION)
    (sameBest : best.eval assignment Locals.empty = (bestNat : Int))
    (accepted :
      (retirementRefreshConstraints width bootstrap oldTerms.logLength
        oldTerms.logEntries source first retirement signature retired).eval
          assignment Locals.empty = true) :
    exists output : NativeArrayCheckQuorum.Local (Fin width) Nat,
      (commitRowTerms oldTerms best retirement signature retired).Rep
          assignment output /\
        output.toModel =
          refreshRetirementState source
            { oldRow.toModel with commitIndex := bestNat } := by
  let committed := { oldRow with commit := bestNat }
  let refreshed := refreshRetirementState source committed.toModel
  let output : NativeArrayCheckQuorum.Local (Fin width) Nat :=
    { committed with
      retirementIndex := refreshed.retirementIndex
      retirementCommittableIndex := refreshed.retirementCommittableIndex
      retiredCommittedIndex := refreshed.retiredCommittedIndex
      membershipState := refreshed.membershipState }
  have fields :=
    retirement_refresh_constraints_output_sound assignment Locals.empty bootstrap
      oldTerms.logLength oldTerms.logEntries source best first retirement signature
      retired committed
      (by simpa [committed] using oldRep.logLength)
      (by simpa [committed] using sameBest)
      sameBootstrap
      (by
        intro index live
        simpa [committed] using oldRep.logEntries index live)
      accepted
  refine ⟨output, ?_, ?_⟩
  · refine { oldRep with
      commit := sameBest
      retirementIndex := ?_
      retirementCommittableIndex := ?_
      retiredCommittedIndex := ?_
      membershipState := ?_ }
    · simpa [commitRowTerms, output, refreshed] using fields.1
    · simpa [commitRowTerms, output, refreshed] using fields.2.1
    · simpa [commitRowTerms, output, refreshed] using fields.2.2.1
    · simpa [commitRowTerms, output, refreshed] using fields.2.2.2
  · rfl

theorem commit_guards_correct {width : PNat}
    (assignment : Assignment) (columns : Columns)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment columns frame)
    (source : Fin width) (best membership : Expr .int)
    (bestNat : Nat)
    (output : NativeArrayCheckQuorum.Local (Fin width) Nat)
    (sameBest : best.eval assignment Locals.empty = (bestNat : Int))
    (sameMembership :
      membership.eval assignment Locals.empty =
        membershipCode output.membershipState) :
    Holds (commitGuards columns source best membership) assignment <->
      NativeArrayAdvanceCommit.enabled frame source bestNat output := by
  have commitCorrect :
      (lt (NativeEncode.commit columns source.val) best).eval assignment
          Locals.empty = true <->
        (NativeArrayCheckQuorum.get frame.nodes source).commit < bestNat := by
    simp only [lt, Term.eval, rep.nodes.commit, sameBest, Bool.not_eq_true',
      decide_eq_false_iff_not, not_le]
    exact Int.ofNat_lt
  simp only [commitGuards, Holds, List.mem_cons, List.not_mem_nil, or_false,
    or_imp, forall_and, forall_eq]
  simp only [nodeRowSnapshot, Term.eval, rep.nodes.allocated, rep.nodes.role,
    sameMembership, Bool.not_eq_true', decide_eq_false_iff_not,
    decide_eq_true_eq, role_code_eq, membership_code_eq, commitCorrect,
    NativeArrayAdvanceCommit.enabled]

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
