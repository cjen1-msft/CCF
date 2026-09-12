-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayChangeConfiguration
import Sparse.NativeFrameColumns
import Sparse.NativeLogSummaryEncoding
import Sparse.NativeMembershipTerms
import Sparse.NativeRetirementRefreshEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem membership_added_term_correct {width : PNat}
    (assignment : Assignment)
    (configuration previousSet : Finset (Fin width))
    (previous : Expr (.bits width))
    (samePrevious : previous.eval assignment Locals.empty = encodeBits previousSet) :
    (membershipAddedTerm configuration previous).eval assignment Locals.empty =
      encodeBits (configuration \ previousSet) := by
  apply BitVec.eq_of_getLsbD_eq
  intro index live
  let node : Fin width := ⟨index, live⟩
  simp only [membershipAddedTerm, Term.eval, samePrevious]
  change (encodeBits configuration &&& ~~~encodeBits previousSet).getLsbD node.val =
    (encodeBits (configuration \ previousSet)).getLsbD node.val
  rw [BitVec.getLsbD_and, BitVec.getLsbD_not, encode_bits_bit, encode_bits_bit,
    encode_bits_bit]
  simp

theorem encode_bits_eq_zero_iff {width : PNat} (nodes : Finset (Fin width)) :
    encodeBits nodes = 0 <-> nodes = ∅ := by
  rw [<- encode_bits_empty]
  exact encode_bits_eq nodes ∅

theorem encode_bits_and_eq_zero_iff {width : PNat}
    (left right : Finset (Fin width)) :
    encodeBits left &&& encodeBits right = 0 <->
      forall node, node ∈ left -> node ∉ right := by
  constructor
  · intro empty node inLeft inRight
    have same := congrArg (fun bits : BitVec width => bits.getLsbD node.val) empty
    change (encodeBits left &&& encodeBits right).getLsbD node.val =
      (0 : BitVec width).getLsbD node.val at same
    rw [BitVec.getLsbD_and, encode_bits_bit, encode_bits_bit] at same
    simp [inLeft, inRight] at same
  · intro disjoint
    apply BitVec.eq_of_getLsbD_eq
    intro index live
    let node : Fin width := ⟨index, live⟩
    change (encodeBits left &&& encodeBits right).getLsbD node.val =
      (0 : BitVec width).getLsbD node.val
    rw [BitVec.getLsbD_and, encode_bits_bit, encode_bits_bit]
    by_cases inLeft : node ∈ left
    · simp [inLeft, disjoint node inLeft]
    · simp [inLeft]

theorem membership_log_entries_term_correct {width : PNat}
    (assignment : Assignment) (columns : Columns)
    (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat)
    (rep : NodeColumnsRep assignment columns arrays) (source : Fin width)
    (configuration previousSet : Finset (Fin width)) :
    let row := NativeArrayCheckQuorum.get arrays source
    let appended := NativeArrayChangeConfiguration.appendRow row configuration previousSet
    forall position, position < appended.log.length ->
      modelEntry ((membershipLogEntriesTerm columns source configuration).eval
        assignment Locals.empty (position : Int)) = appended.log.entries position := by
  intro row appended position live
  have oldLength := rep.length source
  have currentTerm := rep.currentTerm source
  simp only [membershipLogEntriesTerm, nodeRowSnapshot, Term.eval]
  by_cases old : position < row.log.length
  · have different :
        (position : Int) ≠
          (length columns source.val).eval assignment Locals.empty := by
      rw [oldLength]
      exact_mod_cast (Nat.ne_of_lt old)
    simp only [Function.update_apply, if_neg different]
    simpa [row, appended, NativeArrayChangeConfiguration.appendRow,
      NativeArrayLogWrite.append, NativeArrayChangeConfiguration.configurationLog,
      NativeArrayCheckQuorum.Log.ofList, old, entryAt, Term.eval] using
        rep.entries source position old
  · have last : position = row.log.length := by
      simp [appended, NativeArrayChangeConfiguration.appendRow,
        NativeArrayLogWrite.append, NativeArrayChangeConfiguration.configurationLog,
        NativeArrayCheckQuorum.Log.ofList] at live
      omega
    subst position
    simp only [oldLength, Function.update_apply]
    simp [row, appended, NativeArrayChangeConfiguration.appendRow,
      NativeArrayLogWrite.append, NativeArrayChangeConfiguration.configurationLog,
      NativeArrayChangeConfiguration.configurationEntry, NativeArrayCheckQuorum.Log.ofList,
      currentTerm, modelEntry, content_term_eval]

theorem membership_guards_correct {width : PNat}
    (assignment : Assignment) (columns : Columns)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment columns frame) (source : Fin width)
    (configuration previousSet : Finset (Fin width))
    (previous : Expr (.bits width)) (refreshedMembership : Expr .int)
    (retirement signature retired : Option Nat)
    (samePrevious : previous.eval assignment Locals.empty = encodeBits previousSet)
    (sameRefreshed :
      refreshedMembership.eval assignment Locals.empty =
        membershipCode
          (NativeArrayChangeConfiguration.changeRow
            (NativeArrayCheckQuorum.get frame.nodes source)
            configuration previousSet retirement signature retired).membershipState) :
    Holds (membershipGuards columns source configuration previous refreshedMembership)
        assignment <->
      NativeArrayChangeConfiguration.enabled frame source configuration previousSet
        retirement signature retired := by
  have sameAdded := membership_added_term_correct assignment
    configuration previousSet previous samePrevious
  simp only [membershipGuards, Holds, leadingGuards, List.mem_append, List.mem_cons,
    List.not_mem_nil, or_false, or_imp, forall_and, forall_eq]
  simp only [leaderGuard, Term.eval, rep.nodes.allocated, rep.nodes.role,
    rep.nodes.membershipState,
    rep.hasJoined, samePrevious, sameRefreshed, sameAdded,
    Bool.not_eq_true', decide_eq_false_iff_not, decide_eq_true_eq]
  rw [encode_bits_eq_zero_iff, encode_bits_eq, encode_bits_and_eq_zero_iff]
  simp only [NativeArrayChangeConfiguration.enabled,
    NativeArrayChangeConfiguration.addedNodes,
    role_code_leader, membership_code_eq, Finset.nonempty_iff_ne_empty]
  simp only [and_assoc]

theorem membership_guards_model_correct {width : PNat} [Bootstrap (Fin width)]
    (assignment : Assignment) (columns : Columns)
    (frame : NativeArrayVote.Frame (Fin width) Nat) (state : State (Fin width) Nat)
    (rep : FrameColumnsRep assignment columns frame)
    (model : frame.Rep state)
    (bootstrap : BitVec width) (source : Fin width)
    (configuration : Finset (Fin width))
    (current first retirement signature retired : Expr .int)
    (sameBootstrap : decodeBits bootstrap = INITIAL_CONFIGURATION)
    (currentAccepted :
      (currentConfigurationIndexTerm width
        (nodeRowSnapshot columns source).logLength
        (nodeRowSnapshot columns source).logEntries
        (nodeRowSnapshot columns source).logLength current).eval
          assignment Locals.empty = true)
    (refreshAccepted :
      (retirementRefreshConstraints width bootstrap
        (.add (nodeRowSnapshot columns source).logLength (.integer 1))
        (membershipLogEntriesTerm columns source configuration) source
        first retirement signature retired).eval assignment Locals.empty = true) :
    let previous := currentConfigurationMembersTerm width bootstrap
      (nodeRowSnapshot columns source).logEntries current
    let refreshed := retirementRefreshTerms (nodeRowSnapshot columns source).commit
      retirement signature retired
    Holds (membershipGuards columns source configuration previous refreshed.membershipState)
        assignment <->
      CCFRaft.Enabled state (.changeConfiguration source configuration) := by
  let row := NativeArrayCheckQuorum.get frame.nodes source
  let appended := NativeArrayChangeConfiguration.appendRow row configuration
    (currentConfigurationAt row.log.decode row.log.length).nodes
  have sameLength :
      (nodeRowSnapshot columns source).logLength.eval assignment Locals.empty =
        (row.log.length : Int) := rep.nodes.length source
  have sameEntries : forall position, position < row.log.length ->
      modelEntry ((nodeRowSnapshot columns source).logEntries.eval
        assignment Locals.empty (position : Int)) = row.log.entries position := by
    intro position live
    simpa [nodeRowSnapshot, Term.eval] using rep.nodes.entries source position live
  obtain ⟨currentNat, sameCurrent, currentModel, samePrevious⟩ :=
    current_configuration_terms_sound assignment Locals.empty bootstrap
      (nodeRowSnapshot columns source).logLength
      (nodeRowSnapshot columns source).logEntries
      (nodeRowSnapshot columns source).logLength current row.log row.log.length
      sameBootstrap sameLength sameLength sameEntries currentAccepted
  have currentIndex :=
    (current_configuration_index_term_native_correct assignment Locals.empty
      (nodeRowSnapshot columns source).logLength
      (nodeRowSnapshot columns source).logEntries
      (nodeRowSnapshot columns source).logLength current row.log row.log.length currentNat
      sameLength sameLength sameCurrent sameEntries).mp currentAccepted
  have atPrevious : NativeArrayConfiguration.At row.log currentNat
      (currentConfigurationAt row.log.decode row.log.length).nodes := by
    exact ((NativeArrayConfiguration.current_configuration_correct row.log row.log.length
      currentNat (currentConfigurationAt row.log.decode row.log.length).nodes).mpr (by
        cases hcfg : currentConfigurationAt row.log.decode row.log.length with
        | mk index nodes =>
          rw [hcfg] at currentModel
          simp only at currentModel
          subst index
          rfl)).2
  have appendedEntries : forall position, position < appended.log.length ->
      modelEntry ((membershipLogEntriesTerm columns source configuration).eval
        assignment Locals.empty (position : Int)) = appended.log.entries position := by
    intro position live
    simpa [appended] using membership_log_entries_term_correct assignment columns frame.nodes
      rep.nodes source configuration
        (currentConfigurationAt row.log.decode row.log.length).nodes position live
  have appendedLength :
      (.add (nodeRowSnapshot columns source).logLength (.integer 1) :
        Expr .int).eval assignment Locals.empty = (appended.log.length : Int) := by
    simp [Term.eval, sameLength, appended, NativeArrayChangeConfiguration.appendRow,
      NativeArrayLogWrite.append, NativeArrayChangeConfiguration.configurationLog,
      NativeArrayCheckQuorum.Log.ofList]
  obtain ⟨firstChoice, retirementChoice, signatureChoice, retiredChoice,
      sameFirst, sameRetirement, sameSignature, sameRetired, firstCorrect,
      retirementCorrect, signatureCorrect, retiredCorrect⟩ :=
    retirement_refresh_constraints_sound assignment Locals.empty bootstrap
      (.add (nodeRowSnapshot columns source).logLength (.integer 1))
      (membershipLogEntriesTerm columns source configuration) source
      first retirement signature retired appended.log appendedLength sameBootstrap
      appendedEntries refreshAccepted
  have sameCommit :
      (nodeRowSnapshot columns source).commit.eval assignment Locals.empty =
        (row.commit : Int) := rep.nodes.commit source
  have refreshedCorrect :=
    retirement_refresh_terms_eval assignment Locals.empty
      (nodeRowSnapshot columns source).commit retirement signature retired appended
      retirementChoice signatureChoice retiredChoice sameCommit sameRetirement
      sameSignature sameRetired
  have sameRefreshed :
      (retirementRefreshTerms (nodeRowSnapshot columns source).commit retirement signature retired
        ).membershipState.eval assignment Locals.empty =
        membershipCode
          (NativeArrayChangeConfiguration.changeRow row configuration
            (currentConfigurationAt row.log.decode row.log.length).nodes
            retirementChoice (signatureChoice.map (1 + ·))
            (retiredChoice.map (1 + ·))).membershipState := by
    simpa [NativeArrayChangeConfiguration.changeRow, appended] using refreshedCorrect.2.2.2
  have nativeGuards :=
    membership_guards_correct assignment columns frame rep source configuration
      (currentConfigurationAt row.log.decode row.log.length).nodes
      (currentConfigurationMembersTerm width bootstrap
        (nodeRowSnapshot columns source).logEntries current)
      (retirementRefreshTerms (nodeRowSnapshot columns source).commit
        retirement signature retired).membershipState
      retirementChoice (signatureChoice.map (1 + ·)) (retiredChoice.map (1 + ·))
      samePrevious sameRefreshed
  have signatureModel :
      retirementChoice.bind (retirementCommittableIndexInLog appended.log.decode) =
        signatureChoice.map (1 + ·) := by
    cases retirementChoice with
    | none =>
      simp only [RetirementSignatureScan] at signatureCorrect
      rw [signatureCorrect]
      rfl
    | some retirementIndex =>
      apply (NativeArrayRetirement.signature_scan_correct appended.log retirementIndex
        signatureChoice).mp
      simpa [RetirementSignatureScan] using signatureCorrect
  have retiredModel :
      retiredCommittedIndexInLog source appended.log.decode =
        retiredChoice.map (1 + ·) :=
    (NativeArrayRetirement.retired_index_scan_correct appended.log source retiredChoice).mp
      retiredCorrect
  exact nativeGuards.trans
    (NativeArrayChangeConfiguration.enabled_correct frame state model source configuration
      (currentConfigurationAt row.log.decode row.log.length).nodes currentNat retirementChoice
      (signatureChoice.map (1 + ·)) (retiredChoice.map (1 + ·)) currentIndex atPrevious
      retirementCorrect signatureModel retiredModel)

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
