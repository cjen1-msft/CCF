-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeCampaignWrites

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

structure CampaignPrefix {width : PNat} (before guarded : Encoding width)
    (preVote : Bool) (node : Fin width) : Prop where
  bootstrap : guarded.bootstrap = before.bootstrap
  columns : guarded.toColumns = before.toColumns
  next : guarded.next = before.next + 3
  clauses : guarded.assertions.toList = before.assertions.toList ++
    campaignGuards before.toColumns before.bootstrap preVote node before.next

theorem campaign_guard_success {width : PNat} (columns : Columns) (bootstrap : BitVec width)
    (preVote : Bool) (node : Fin width) (before guarded : Encoding width)
    (run : (campaignGuard columns bootstrap preVote node).run before = .ok ((), guarded)) :
    guarded.bootstrap = before.bootstrap /\
      guarded.toColumns = before.toColumns /\
      guarded.next = before.next + 3 /\
      guarded.assertions.toList = before.assertions.toList ++
        campaignGuards columns bootstrap preVote node before.next := by
  simp only [campaignGuard] at run
  obtain ⟨base, first, firstRun, run⟩ := (bind_run _ _ _ _ _).mp run
  obtain ⟨unused, second, secondRun, run⟩ := (bind_run _ _ _ _ _).mp run
  obtain ⟨unused, third, thirdRun, run⟩ := (bind_run _ _ _ _ _).mp run
  obtain ⟨baseEq, firstNext, firstBootstrap, firstColumns, firstClauses⟩ :=
    fresh_success before first base firstRun
  obtain ⟨_, secondNext, secondBootstrap, secondColumns, secondClauses⟩ :=
    fresh_success first second _ secondRun
  obtain ⟨_, thirdNext, thirdBootstrap, thirdColumns, thirdClauses⟩ :=
    fresh_success second third _ thirdRun
  obtain ⟨guardFrame, guardClauses⟩ := assert_all_success _ third guarded run
  refine ⟨guardFrame.bootstrap.trans (thirdBootstrap.trans (secondBootstrap.trans firstBootstrap)),
    guardFrame.columns.trans (thirdColumns.trans (secondColumns.trans firstColumns)), ?_, ?_⟩
  · rw [guardFrame.next, thirdNext, secondNext, firstNext]
  · rw [guardClauses, thirdClauses, secondClauses, firstClauses, baseEq]

theorem campaign_prefix {width : PNat} (preVote : Bool) (node : Fin width)
    (before after : Encoding width)
    (run : (campaign preVote node).run before = .ok ((), after)) :
    exists guarded : Encoding width, CampaignPrefix before guarded preVote node /\
      (campaignWrites preVote node).run guarded = .ok ((), after) := by
  simp only [campaign, StateT.run, Bind.bind, StateT.bind, Except.bind] at run
  cases guardRun :
      campaignGuard before.toColumns before.bootstrap preVote node before with
  | error message =>
    rw [guardRun] at run
    exact nomatch run
  | ok pair =>
    rcases pair with ⟨value, guarded⟩
    cases value
    have writesRun : (campaignWrites preVote node).run guarded = .ok ((), after) := by
      simpa only [guardRun] using run
    obtain ⟨bootstrap, columns, next, clauses⟩ :=
      campaign_guard_success before.toColumns before.bootstrap preVote node before guarded guardRun
    exact ⟨guarded, ⟨bootstrap, columns, next, clauses⟩, writesRun⟩

theorem CampaignPrefix.references {width : PNat} {before guarded : Encoding width}
    {preVote : Bool} {node : Fin width} (shape : CampaignPrefix before guarded preVote node)
    (valid : ReferencesValid before) : ReferencesValid guarded := by
  cases valid
  constructor <;> simp only [shape.columns, shape.next] <;> omega

theorem CampaignPrefix.holds {width : PNat} {before guarded : Encoding width}
    {preVote : Bool} {node : Fin width} (shape : CampaignPrefix before guarded preVote node)
    (assignment : Assignment) :
    Holds guarded.assertions.toList assignment <->
      Holds before.assertions.toList assignment /\
        Holds (campaignGuards before.toColumns before.bootstrap preVote node before.next) assignment := by
  rw [shape.clauses]
  simp [Holds, or_imp, forall_and]

theorem campaign_references {width : PNat} (preVote : Bool) (node : Fin width)
    (before after : Encoding width) (run : (campaign preVote node).run before = .ok ((), after))
    (valid : ReferencesValid before) : ReferencesValid after := by
  obtain ⟨guarded, shape, written⟩ := campaign_prefix preVote node before after run
  exact campaign_writes_references preVote node guarded after written (shape.references valid)

theorem campaign_bootstrap {width : PNat} (preVote : Bool) (node : Fin width)
    (before after : Encoding width) (run : (campaign preVote node).run before = .ok ((), after)) :
    after.bootstrap = before.bootstrap := by
  obtain ⟨guarded, shape, written⟩ := campaign_prefix preVote node before after run
  exact (campaign_writes_success preVote node guarded after written).bootstrap.trans shape.bootstrap

theorem campaign_holds_before {width : PNat} (preVote : Bool) (node : Fin width)
    (before after : Encoding width) (run : (campaign preVote node).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment) :
    Holds before.assertions.toList assignment := by
  obtain ⟨guarded, shape, written⟩ := campaign_prefix preVote node before after run
  exact ((shape.holds assignment).mp
    ((campaign_writes_holds preVote node guarded after written assignment).mp holds).1).1

theorem campaign_frame_success {width : PNat} [Bootstrap (Fin width)]
    (preVote : Bool) (node : Fin width) (before after : Encoding width)
    (run : (campaign preVote node).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat) (rep : FrameColumnsRep assignment before.toColumns frame)
    (sameBootstrap : decodeBits before.bootstrap = INITIAL_CONFIGURATION) :
    NativeArrayVote.campaignEnabled frame preVote node /\
      FrameColumnsRep assignment after.toColumns (frame.campaign preVote node) := by
  obtain ⟨guarded, shape, written⟩ := campaign_prefix preVote node before after run
  have guardHolds := ((campaign_writes_holds preVote node guarded after written assignment).mp holds).1
  have enabled := campaign_guards_sound assignment before.toColumns frame rep before.bootstrap sameBootstrap
    preVote node before.next ((shape.holds assignment).mp guardHolds).2
  have guardedRep : FrameColumnsRep assignment guarded.toColumns frame := by
    simpa only [shape.columns] using rep
  exact ⟨enabled, campaign_writes_frame preVote node guarded after written assignment holds frame guardedRep enabled.1⟩

theorem campaign_complete {width : PNat} [Bootstrap (Fin width)]
    (preVote : Bool) (node : Fin width) (before after : Encoding width)
    (run : (campaign preVote node).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds before.assertions.toList assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment before.toColumns frame) (valid : ReferencesValid before)
    (sameBootstrap : decodeBits before.bootstrap = INITIAL_CONFIGURATION)
    (enabled : NativeArrayVote.campaignEnabled frame preVote node) :
    exists extended : Assignment, assignment.AgreesBelow before.next extended /\
      Holds after.assertions.toList extended /\
      FrameColumnsRep extended after.toColumns (frame.campaign preVote node) := by
  obtain ⟨guarded, shape, written⟩ := campaign_prefix preVote node before after run
  obtain ⟨witnesses, agreement, guards⟩ :=
    campaign_guards_complete before assignment frame rep valid sameBootstrap preVote node enabled
  have previous := before.holds_agrees_below assignment witnesses holds agreement
  have guardHolds := (shape.holds witnesses).mpr ⟨previous, guards⟩
  have witnessRep := rep.agrees_below before assignment witnesses frame valid agreement
  have guardedRep : FrameColumnsRep witnesses guarded.toColumns frame := by
    simpa only [shape.columns] using witnessRep
  obtain ⟨extended, writeAgreement, finalHolds, finalRep⟩ :=
    campaign_writes_complete preVote node guarded after written witnesses guardHolds frame guardedRep
      (shape.references valid) enabled.1
  refine ⟨extended, agreement.trans (writeAgreement.restrict ?_), finalHolds, finalRep⟩
  rw [shape.next]
  omega

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
