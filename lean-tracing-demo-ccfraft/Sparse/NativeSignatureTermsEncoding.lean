-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayLeaderLogWrite
import Sparse.NativeArraySignature
import Sparse.NativeCommitTermsEncoding
import Sparse.NativeSignatureTerms

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem leader_log_row_terms_rep {width : PNat}
    (assignment : Assignment)
    (oldTerms : NodeRowTerms width)
    (oldRow : NativeArrayCheckQuorum.Local (Fin width) Nat)
    (content : Expr (contentTy width))
    (concreteContent : EntryContent (Fin width) Nat)
    (outputLength : Expr .int)
    (outputEntries : Expr (.array .int (entryTy width)))
    (oldRep : oldTerms.Rep assignment oldRow)
    (sameContent :
      decodeContent (content.eval assignment Locals.empty) = concreteContent)
    (sameLength :
      outputLength.eval assignment Locals.empty =
        (oldRow.log.length + 1 : Int))
    (sameEntries :
      outputEntries.eval assignment Locals.empty =
        (leaderLogEntriesTerm oldTerms content).eval assignment Locals.empty) :
    (leaderLogRowTerms oldTerms outputLength outputEntries).Rep assignment
      (NativeArrayLeaderLogWrite.appendRow oldRow concreteContent) := by
  refine { oldRep with
    logLength := ?_
    logEntries := ?_ }
  · simpa [leaderLogRowTerms, NativeArrayLeaderLogWrite.appendRow,
      NativeArrayLogWrite.append, NativeArrayCheckQuorum.Log.ofList] using sameLength
  · intro position live
    simp only [leaderLogRowTerms]
    rw [sameEntries]
    simp only [leaderLogEntriesTerm, Term.eval]
    rw [oldRep.logLength]
    by_cases old : position < oldRow.log.length
    · have different : (position : Int) ≠ (oldRow.log.length : Int) := by omega
      simpa [NativeArrayLeaderLogWrite.appendRow, NativeArrayLogWrite.append,
        NativeArrayCheckQuorum.Log.ofList, old, different] using
          oldRep.logEntries position old
    · have last : position = oldRow.log.length := by
        simp [NativeArrayLeaderLogWrite.appendRow, NativeArrayLogWrite.append,
          NativeArrayCheckQuorum.Log.ofList] at live
        omega
      subst position
      simp [NativeArrayLeaderLogWrite.appendRow, NativeArrayLogWrite.append,
        NativeArrayCheckQuorum.Log.ofList, oldRep.currentTerm, sameContent,
        modelEntry, Function.update_apply]

theorem signature_refresh_constraints_output_sound {width : PNat}
    [Bootstrap (Fin width)]
    (assignment : Assignment)
    (bootstrap : BitVec width)
    (appendedTerms : NodeRowTerms width)
    (source : Fin width)
    (first retirement signature retired : Expr .int)
    (appended : NativeArrayCheckQuorum.Local (Fin width) Nat)
    (appendedRep : appendedTerms.Rep assignment appended)
    (sameBootstrap : decodeBits bootstrap = INITIAL_CONFIGURATION)
    (accepted :
      (retirementRefreshConstraints width bootstrap appendedTerms.logLength
        appendedTerms.logEntries source first retirement signature retired).eval
          assignment Locals.empty = true) :
    exists output : NativeArrayCheckQuorum.Local (Fin width) Nat,
      (commitRowTerms appendedTerms appendedTerms.commit retirement signature retired).Rep
          assignment output /\
        output.toModel = refreshRetirementState source appended.toModel := by
  obtain ⟨output, outputRep, outputModel⟩ :=
    commit_refresh_constraints_output_sound assignment bootstrap appendedTerms source
      appendedTerms.commit first retirement signature retired appended appended.commit
      appendedRep sameBootstrap appendedRep.commit accepted
  exact ⟨output, outputRep, by
    simpa [NativeArrayCheckQuorum.Local.toModel] using outputModel⟩

theorem signature_guards_correct {width : PNat}
    (assignment : Assignment) (columns : Columns)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment columns frame)
    (source : Fin width) (membership : Expr .int)
    (output : NativeArrayCheckQuorum.Local (Fin width) Nat)
    (sameMembership :
      membership.eval assignment Locals.empty =
        membershipCode output.membershipState) :
    Holds (signatureGuards columns source membership) assignment <->
      NativeArraySignature.enabled frame source output := by
  have positiveCorrect :
      (lt (.integer 0) (NativeEncode.length columns source.val)).eval assignment
          Locals.empty = true <->
        0 < (NativeArrayCheckQuorum.get frame.nodes source).log.length := by
    simp only [lt, Term.eval, rep.nodes.length, Bool.not_eq_true',
      decide_eq_false_iff_not, not_le]
    exact Int.ofNat_lt
  simp only [signatureGuards, Holds, List.mem_cons, List.not_mem_nil, or_false,
    or_imp, forall_and, forall_eq]
  simp only [nodeRowSnapshot, Term.eval, rep.nodes.allocated, rep.nodes.role,
    rep.nodes.membershipState, sameMembership, Bool.not_eq_true',
    decide_eq_false_iff_not, decide_eq_true_eq, role_code_eq,
    membership_code_eq, positiveCorrect, NativeArraySignature.enabled]

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
