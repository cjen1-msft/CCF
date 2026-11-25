module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.JointWitnesses
import all ConsensusCoverage.ReadersWitnesses
import all ConsensusCoverage.DeepSchedules
import all ConsensusCoverage.DeepElectionCases
import all ConsensusCoverage.DeepLeaderCases
import all ConsensusCoverage.DeepEffectCases
import all ConsensusCoverage.DeepInputCases
import all ConsensusCoverage.DeepGrantCases
import all ConsensusCoverage.DeepActorCases
import all ConsensusCoverage.DeepCampaignCases
import all ConsensusCoverage.DeepReceiveCases
import all ConsensusCoverage.DeepBatchCases
import all ConsensusCoverage.DeepPrefixCases
import all ConsensusCoverage.DeepListCases
import all ConsensusCoverage.DeepObserveCases
import all ConsensusCoverage.DeepHandlerCases
import all ConsensusCoverage.DeepSignedCases
import all ConsensusCoverage.DeepBoundCases
import all ConsensusCoverage.DeepWinningCases
import all ConsensusCoverage.DeepRankingCases
import all ConsensusCoverage.DeepHistoryCases
import all ConsensusCoverage.DeepQuorumCases
import all ConsensusCoverage.DeepCarriedCases
import all ConsensusCoverage.DeepCoreCases
import all ConsensusCoverage.DeepChainCases
import all ConsensusCoverage.ReadersCorpus
import all ConsensusCoverage.EventSupport
import all ConsensusCoverage.JointWitnesses
import all ConsensusCoverage.ActionProfile
import all ConsensusCoverage.SolvedWitnesses
import all ConsensusCoverage.ReadersCompiler
import all ConsensusCoverage.ReadersGenerated
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.ReadersShapes
import all ConsensusCoverage.ReadersIndex
import all ConsensusCoverage.ReadersVoteReply
import all ConsensusCoverage.FrontierWitnesses
import all Consensus.Proofs.VoteFacts

namespace ConsensusCoverage.CaseWitnessesDeep

open Consensus Consensus.Proofs ActionProfile FrontierRows

set_option maxRecDepth 8192
set_option maxHeartbeats 0

private def selected (r : Run) (choices : List (Nat × Nat)) (valid : r.valid)
    (offset : Nat) : Option Step := do
  let steps ← JointWitnesses.recordedAt {r with schedule := r.schedule.take (offset + 1)} valid choices
  return (← steps[offset]?).val

private noncomputable def ordered (s : Step) (b : Classes.StepBranch) : Option Bool :=
  (ReadersAtoms.ofXAction s.cfg s.before s.after s.past s.act).bind fun x =>
    @ReadersCompiler.readView ⟨s.cfg⟩ x b

private abbrev Certificate := {b : Classes.StepBranch // ∃ s : Step, label s (.step b) = true}

private def checkedAt (b : Classes.StepBranch) (chosen : Option Step) (test : Step → Bool)
    (passed : chosen.any test = true) (sound : ∀ s, test s = true → label s (.step b) = true) :
    Certificate := by
  refine ⟨b, ?_⟩
  cases chosen with
  | none => cases passed
  | some s => exact ⟨s, sound s passed⟩

private def inputAt (k : DeepInputCases.InputCase) (chosen : Option Step)
    (passed : chosen.any (DeepInputCases.check · k) = true) : Certificate :=
  checkedAt k.column chosen _ passed (DeepInputCases.correct · k)

private def grantAt (k : DeepGrantCases.GrantCase) (chosen : Option Step) (voter candidate : Nat)
    (passed : chosen.any (DeepGrantCases.check · k voter candidate 3 ⟨3, 2, 2⟩) = true) :
    Certificate :=
  checkedAt k.column chosen _ passed (DeepGrantCases.correct · k voter candidate 3 ⟨3, 2, 2⟩)

private def actorAt (k : DeepActorCases.ActorCase) (chosen : Option Step)
    (passed : chosen.any (DeepActorCases.check · k) = true) : Certificate :=
  checkedAt k.column chosen _ passed (DeepActorCases.correct · k)

private def campaignAt (k : DeepCampaignCases.CampaignCase) (chosen : Option Step) (voter : Nat)
    (passed : chosen.any (DeepCampaignCases.check · k voter) = true) : Certificate :=
  checkedAt k.column chosen _ passed (DeepCampaignCases.correct · k voter)

private def transfer (from_ to_ : Classes.StepBranch) (known : from_ ∈ ReadersWitnesses.witnessed)
    (enter : ∀ s : Step, @SolvedWitnesses.sig ⟨s.cfg⟩ s.frame s.after s.context from_ →
      @SolvedWitnesses.sig ⟨s.cfg⟩ s.frame s.after s.context to_) : Certificate := by
  refine ⟨to_, ?_⟩
  obtain ⟨s, yes⟩ := ReadersWitnesses.occurs known
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  refine ⟨s, (label_true s _).mpr ((SolvedWitnesses.sig_iff s.context _).mpr ?_)⟩
  exact enter s ((SolvedWitnesses.sig_iff s.context _).mp ((label_true s _).mp yes))

private def certify (b : Classes.StepBranch) (chosen : Option Step)
    (checked : chosen.bind (ordered · b) = some true) : Certificate := by
  refine ⟨b, ?_⟩
  cases chosen with
  | none => cases checked
  | some s =>
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    refine ⟨s, (label_true s (.step b)).mpr ((SolvedWitnesses.sig_iff s.context b).mpr ?_)⟩
    obtain ⟨x, made, ok⟩ := ReadersAtoms.ofXAction_matches s
    simp only [Option.bind_some, ordered, made] at checked
    exact (ReadersCompiler.picked_some checked
      (@ReadersCompiler.readView_correct ⟨s.cfg⟩ s.frame s.after s.context b x ok)).mp rfl

private def electionAt (b : Classes.StepBranch) (chosen : Option Step) (positive : Bool)
    (passed : chosen.any (DeepLeaderCases.guardAt · positive) = true)
    (enters : ∀ s : Step, letI : Config.InitialConfiguration := ⟨s.cfg⟩
      s.context.pre.role ≠ .primary → s.context.post.role = .primary → s.context.pre.log ≠ [] →
      decide (0 < s.context.pre.commitIndex) = positive → SolvedWitnesses.sig s.context b) :
    Certificate := by
  refine ⟨b, ?_⟩
  cases chosen with
  | none => cases passed
  | some s =>
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    obtain ⟨prior, role, log, commit⟩ := DeepLeaderCases.ofGuard s positive passed
    exact ⟨s, (label_true s _).mpr ((SolvedWitnesses.sig_iff s.context _).mpr
      (enters s prior role log commit))⟩

-- The first acknowledgment commits the configuration dropping voter 1.
-- The duplicate advances to the next signature using only voter 0.
private def duplicateAck : Run :=
  ⟨{0, 1}, [0, 1], [
    .input 0 (.append [{content := .transaction 1 {configuration := some {0}}},
      {content := .signature, flushes := [(1, 3)]}, {content := .signature}]),
    .deliver 0 1, .input 0 (.sendEntries 1 3), .deliver 0 1, .deliver 1 0, .deliver 1 0]⟩

private theorem validAck : duplicateAck.valid := by
  change duplicateAck.cfg.Nonempty ∧ duplicateAck.nodes.Nodup
  decide

open DeepSchedules in
local macro "observed " sc:term:arg i:num b:term:arg : term =>
  `(certify $b (selected (Script.run $sc) (Script.choices $sc) (by unfold Run.valid; decide) $i)
    (by decide +kernel))

open DeepSchedules in
local macro "election " sc:term:arg i:num b:term:arg positive:term:arg enter:term:arg : term =>
  `(electionAt $b (selected (Script.run $sc) (Script.choices $sc) (by unfold Run.valid; decide) $i)
    $positive (by decide +kernel) $enter)

open DeepSchedules in
local macro "onScript " sc:term:arg i:num : term =>
  `(selected (Script.run $sc) (Script.choices $sc) (by unfold Run.valid; decide) $i)

open DeepSchedules in
private def earlier : List Certificate :=
  [certify .commit_backed_max_eq_or_inl (selected duplicateAck [] validAck 5) (by decide +kernel),
   observed installLater 12 .leader_floor_led_inr,
   observed divergent 8 .new_in_elected_backing_inl,
   observed divergent 11 .accept_persist_inSender_neg,
   observed divergent 11 .persist_persist_inr,
   observed doomed 19 .campaign_backed_pre_split_inr,
   observed doomed 21 .candidate_candidate_inr,
   observed lateCopy 14 .rankedElections_elected_inl,
   observed lateCopy 14 .old_complete_elected_after_inl,
   observed (threeTerms false) 18 .new_in_elected_lt_trichotomy_inl,
   observed (threeTerms true) 20 .new_in_elected_lt_trichotomy_inr_inr,
   observed retireOnAppend 10 .post_log_role_inr,
   transfer .observeTerm_log_message_appendEntriesResponse
     .observeTerm_log_message_proposeRequestVoteRequest (by decide +kernel) (fun _ h => h),
   transfer .observeTerm_commitIndex_message_appendEntriesResponse
     .observeTerm_commitIndex_message_proposeRequestVoteRequest (by decide +kernel) (fun _ h => h),
   transfer .led_cur_led_after_inr .led_after_led_inr (by decide +kernel)
     (fun s => @DeepElectionCases.electedLed ⟨s.cfg⟩ _ _ s.context),
   transfer .led_cur_led_after_inr .led_after_elected_after_inr (by decide +kernel)
     (fun s => @DeepElectionCases.electedNew ⟨s.cfg⟩ _ _ s.context),
   election (threeTerms true) 20 .leader_logs_commit_pos true (fun s a b l h =>
     @DeepLeaderCases.leaderPositive ⟨s.cfg⟩ _ _ s.context a b l (of_decide_eq_true h)),
   election divergent 8 .leader_logs_commit_neg false (fun s a b l h =>
     @DeepLeaderCases.leaderZero ⟨s.cfg⟩ _ _ s.context a b l (of_decide_eq_false h)),
   election (threeTerms true) 20 .wins_elect_committed_pos true (fun s a b _ h =>
     @DeepLeaderCases.electedPositive ⟨s.cfg⟩ _ _ s.context a b (of_decide_eq_true h)),
   election divergent 8 .wins_elect_committed_neg false (fun s a b _ h =>
     @DeepLeaderCases.electedZero ⟨s.cfg⟩ _ _ s.context a b (of_decide_eq_false h)),
   transfer .foldlM__items_nil .foldlM__items_cons (by decide +kernel)
     (fun s => @DeepEffectCases.flushCons ⟨s.cfg⟩ _ _ s.context),
   inputAt .electionTimeout (ReadersCorpus.stepAt 3 2) (by decide +kernel),
   inputAt .emptyBackup (ReadersCorpus.stepAt 19 0) (by decide +kernel),
   inputAt .signedBackup (selected installLater.run installLater.choices
     (by unfold Run.valid; decide) 12) (by decide +kernel),
   grantAt .recorded (selected divergent.run divergent.choices (by unfold Run.valid; decide) 7)
     2 1 (by decide +kernel),
   grantAt .selfVote (selected divergent.run divergent.choices (by unfold Run.valid; decide) 6)
     1 1 (by decide +kernel),
   grantAt .peerVote (selected divergent.run divergent.choices (by unfold Run.valid; decide) 7)
     2 1 (by decide +kernel),
   actorAt .keyHere (onScript installLater 1) (by decide +kernel),
   actorAt .keyOther (onScript installLater 1) (by decide +kernel),
   actorAt .bootstrap (onScript installLater 0) (by decide +kernel),
   actorAt .previousElection (onScript installLater 7) (by decide +kernel),
   campaignAt .newTerm (onScript divergent 6) 1 (by decide +kernel),
   campaignAt .sameTerm (onScript lateCopy 11) 1 (by decide +kernel),
   campaignAt .newVote (onScript divergent 6) 1 (by decide +kernel),
   campaignAt .oldVotes (onScript lateCopy 11) 1 (by decide +kernel),
   campaignAt .retained (onScript lateCopy 11) 1 (by decide +kernel),
   campaignAt .received (onScript lateCopy 11) 2 (by decide +kernel)]

private def certificates : List Certificate :=
  earlier ++ DeepReceiveCases.certificates ++ DeepBatchCases.certificates ++
    DeepPrefixCases.certificates ++ DeepListCases.certificates ++ DeepObserveCases.certificates ++
    DeepHandlerCases.certificates ++ DeepSignedCases.certificates ++ DeepBoundCases.certificates ++
    DeepWinningCases.certificates ++ DeepRankingCases.certificates ++ DeepHistoryCases.certificates ++
    DeepQuorumCases.certificates ++ DeepCarriedCases.certificates ++ DeepCoreCases.certificates ++
    DeepChainCases.certificates

public def witnessed : List Classes.StepBranch := certificates.map Subtype.val

public theorem count : witnessed.Nodup ∧ witnessed.length = 117 := by decide +kernel

public theorem occurs {b : Classes.StepBranch} (mem : b ∈ witnessed) :
    ∃ s : Step, label s (.step b) = true := by
  obtain ⟨c, _, rfl⟩ := List.mem_map.mp mem
  exact c.property

end ConsensusCoverage.CaseWitnessesDeep
