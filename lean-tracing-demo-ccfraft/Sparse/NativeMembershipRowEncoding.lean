-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeMembershipRowTerms
import Sparse.NativeMembershipTermsEncoding
import Sparse.NativeNodeRowWritesEncoding
import Sparse.NativeRetirementRefreshEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt NativeArrayCheckQuorum

private theorem membership_sent_index_fold_eval {width : PNat}
    (assignment : Assignment)
    (old result : Expr (.array .int .int)) (added : Expr (.bits width))
    (oldLength : Expr .int) (peers : List (Fin width)) (target : Fin width)
    (nodup : peers.Nodup) :
    (peers.foldl (fun result peer =>
      .store result (.integer peer.val)
        (.ite (.bit added peer) oldLength
          (.select old (.integer peer.val)))) result).eval
        assignment Locals.empty target.val =
      if target ∈ peers then
        if (added.eval assignment Locals.empty).getLsbD target.val then
          oldLength.eval assignment Locals.empty
        else
          old.eval assignment Locals.empty target.val
      else
        result.eval assignment Locals.empty target.val := by
  induction peers generalizing result with
  | nil =>
      simp
  | cons peer peers ih =>
      have peerNotMem : peer ∉ peers := (List.nodup_cons.mp nodup).1
      have tailNodup : peers.Nodup := (List.nodup_cons.mp nodup).2
      rw [List.foldl_cons, ih _ tailNodup]
      by_cases targetInTail : target ∈ peers
      · have different : target ≠ peer := by
          intro same
          subst target
          exact peerNotMem targetInTail
        simp [targetInTail, different]
      · by_cases same : target = peer
        · subst target
          simp [targetInTail, Term.eval]
        · have differentIndex : (target.val : Int) ≠ peer.val := by
            intro equal
            apply same
            exact Fin.ext (Int.ofNat_inj.mp equal)
          simp [targetInTail, same, Term.eval, differentIndex]

theorem membership_sent_index_term_correct {width : PNat}
    (assignment : Assignment)
    (old : Expr (.array .int .int)) (added : Expr (.bits width))
    (oldLength : Expr .int) (addedSet : Finset (Fin width))
    (oldLengthNat : Nat)
    (sameAdded :
      added.eval assignment Locals.empty = encodeBits addedSet)
    (sameLength :
      oldLength.eval assignment Locals.empty = (oldLengthNat : Int))
    (peer : Fin width) :
    (membershipSentIndexTerm old added oldLength).eval
        assignment Locals.empty peer.val =
      if peer ∈ addedSet then
        (oldLengthNat : Int)
      else
        old.eval assignment Locals.empty peer.val := by
  rw [membershipSentIndexTerm,
    membership_sent_index_fold_eval assignment old old added oldLength
      (List.finRange width) peer (List.nodup_finRange width)]
  simp only [List.mem_finRange, if_true, sameAdded, sameLength, encode_bits_bit]
  by_cases member : peer ∈ addedSet <;> simp [member]

theorem membership_row_terms_correct {width : PNat}
    [Bootstrap (Fin width)]
    (assignment : Assignment) (columns : Columns)
    (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat)
    (rep : NodeColumnsRep assignment columns arrays)
    (source : Fin width) (configuration previousSet : Finset (Fin width))
    (logLength : Expr .int)
    (logEntries : Expr (.array .int (entryTy width)))
    (added : Expr (.bits width))
    (bootstrap : BitVec width)
    (first retirement signature retired : Expr .int)
    (sameLogLength :
      logLength.eval assignment Locals.empty =
        (Term.add (nodeRowSnapshot columns source).logLength (.integer 1)).eval
          assignment Locals.empty)
    (sameLogEntries :
      logEntries.eval assignment Locals.empty =
        (membershipLogEntriesTerm columns source configuration).eval
          assignment Locals.empty)
    (sameAdded :
      added.eval assignment Locals.empty =
        encodeBits (configuration \ previousSet))
    (sameBootstrap : decodeBits bootstrap = INITIAL_CONFIGURATION)
    (refreshAccepted :
      (retirementRefreshConstraints width bootstrap logLength logEntries source
        first retirement signature retired).eval assignment Locals.empty = true) :
    let old := NativeArrayCheckQuorum.get arrays source
    let appended := NativeArrayChangeConfiguration.appendRow old configuration previousSet
    exists output : NativeArrayCheckQuorum.Local (Fin width) Nat,
      (membershipRowTerms columns source logLength logEntries added
        retirement signature retired).Rep assignment output /\
      output.toModel = refreshRetirementState source appended.toModel /\
      output.log = appended.log /\
      output.commit = old.commit := by
  let old := NativeArrayCheckQuorum.get arrays source
  let oldTerms := nodeRowSnapshot columns source
  let appended := NativeArrayChangeConfiguration.appendRow old configuration previousSet
  let candidateTerms : NodeRowTerms width :=
    { oldTerms with
      logLength
      logEntries
      sentIndex := membershipSentIndexTerm oldTerms.sentIndex added oldTerms.logLength }
  have oldRep := node_row_snapshot_rep assignment columns arrays rep source
  have oldLength :
      oldTerms.logLength.eval assignment Locals.empty = (old.log.length : Int) := by
    simpa [oldTerms, old] using oldRep.logLength
  have oldSent : forall peer : Fin width,
      oldTerms.sentIndex.eval assignment Locals.empty peer.val =
        (old.sentIndex peer : Int) := by
    intro peer
    simpa [oldTerms, old] using oldRep.sentIndex peer
  have appendedLength :
      logLength.eval assignment Locals.empty = (appended.log.length : Int) := by
    calc
      logLength.eval assignment Locals.empty =
          (.add oldTerms.logLength (.integer 1) : Expr .int).eval
            assignment Locals.empty := by
        simpa [oldTerms] using sameLogLength
      _ = (old.log.length : Int) + 1 := by
        simp [Term.eval, oldLength]
      _ = (appended.log.length : Int) := by
        simp [appended, NativeArrayChangeConfiguration.appendRow,
          NativeArrayLogWrite.append, NativeArrayChangeConfiguration.configurationLog,
          NativeArrayCheckQuorum.Log.ofList]
  have appendedEntries : forall position, position < appended.log.length ->
      modelEntry (logEntries.eval assignment Locals.empty (position : Int)) =
        appended.log.entries position := by
    intro position live
    have encoded :=
      membership_log_entries_term_correct assignment columns arrays rep source
        configuration previousSet position live
    have selected := congrFun sameLogEntries (position : Int)
    rw [selected]
    exact encoded
  have appendedSent : forall peer : Fin width,
      (membershipSentIndexTerm oldTerms.sentIndex added oldTerms.logLength).eval
          assignment Locals.empty peer.val =
        (appended.sentIndex peer : Int) := by
    intro peer
    rw [membership_sent_index_term_correct assignment oldTerms.sentIndex added
      oldTerms.logLength (configuration \ previousSet) old.log.length sameAdded
      oldLength peer]
    simp [appended, NativeArrayChangeConfiguration.appendRow,
      NativeArrayChangeConfiguration.addedNodes, oldSent peer]
  have candidateRep : candidateTerms.Rep assignment appended := by
    refine { oldRep with
      logLength := ?_
      logEntries := ?_
      sentIndex := ?_ }
    · exact appendedLength
    · exact appendedEntries
    · exact appendedSent
  obtain ⟨firstChoice, retirementChoice, signatureChoice, retiredChoice,
      sameFirst, sameRetirement, sameSignature, sameRetired, firstCorrect,
      retirementCorrect, signatureCorrect, retiredCorrect⟩ :=
    retirement_refresh_constraints_sound assignment Locals.empty bootstrap
      logLength logEntries source first retirement signature retired appended.log
      appendedLength sameBootstrap appendedEntries refreshAccepted
  let output := NativeArrayRetirement.refresh appended retirementChoice
    (signatureChoice.map (1 + ·)) (retiredChoice.map (1 + ·))
  have refreshedTerms :=
    retirement_refresh_terms_eval assignment Locals.empty oldTerms.commit retirement
      signature retired appended retirementChoice signatureChoice retiredChoice
      (by simpa [oldTerms, appended, NativeArrayChangeConfiguration.appendRow] using
        oldRep.commit)
      sameRetirement sameSignature sameRetired
  have outputModel :
      output.toModel = refreshRetirementState source appended.toModel := by
    cases retirementChoice with
    | none =>
        exact NativeArrayRetirement.refresh_from_scans_correct appended source none
          signatureChoice retiredChoice retirementCorrect
          (by simpa [RetirementSignatureScan] using signatureCorrect) retiredCorrect
    | some retirementIndex =>
        exact NativeArrayRetirement.refresh_from_scans_correct appended source
          (some retirementIndex) signatureChoice retiredChoice retirementCorrect
          (by simpa [RetirementSignatureScan] using signatureCorrect) retiredCorrect
  have outputRep :
      (membershipRowTerms columns source logLength logEntries added
        retirement signature retired).Rep assignment output := by
    refine { candidateRep with
      retirementIndex := ?_
      retirementCommittableIndex := ?_
      retiredCommittedIndex := ?_
      membershipState := ?_ }
    · simpa [membershipRowTerms, candidateTerms, oldTerms, output,
        NativeArrayRetirement.refresh] using refreshedTerms.1
    · simpa [membershipRowTerms, candidateTerms, oldTerms, output,
        NativeArrayRetirement.refresh] using refreshedTerms.2.1
    · simpa [membershipRowTerms, candidateTerms, oldTerms, output,
        NativeArrayRetirement.refresh] using refreshedTerms.2.2.1
    · simpa [membershipRowTerms, candidateTerms, oldTerms, output,
        NativeArrayRetirement.refresh] using refreshedTerms.2.2.2
  exact ⟨output, outputRep, outputModel, rfl, rfl⟩

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
