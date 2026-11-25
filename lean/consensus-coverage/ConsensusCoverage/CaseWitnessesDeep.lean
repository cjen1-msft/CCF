module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.JointWitnesses
import all ConsensusCoverage.ReadersWitnesses
import all ConsensusCoverage.DeepSchedules
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

private def samePredicate (from_ to_ : Classes.StepBranch) (known : from_ ∈ ReadersWitnesses.witnessed)
    (same : ∀ s : Step, @SolvedWitnesses.sig ⟨s.cfg⟩ s.frame s.after s.context from_ =
      @SolvedWitnesses.sig ⟨s.cfg⟩ s.frame s.after s.context to_) : Certificate := by
  refine ⟨to_, ?_⟩
  obtain ⟨s, yes⟩ := ReadersWitnesses.occurs known
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  refine ⟨s, (label_true s _).mpr ((SolvedWitnesses.sig_iff s.context _).mpr ?_)⟩
  exact same s ▸ (SolvedWitnesses.sig_iff s.context _).mp ((label_true s _).mp yes)

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
private def certificates : List Certificate :=
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
   samePredicate .observeTerm_log_message_appendEntriesResponse
     .observeTerm_log_message_proposeRequestVoteRequest (by decide +kernel) (fun _ => rfl),
   samePredicate .observeTerm_commitIndex_message_appendEntriesResponse
     .observeTerm_commitIndex_message_proposeRequestVoteRequest (by decide +kernel) (fun _ => rfl)]

public def witnessed : List Classes.StepBranch := certificates.map Subtype.val

public theorem count : witnessed.Nodup ∧ witnessed.length = 14 := by decide +kernel

public theorem occurs {b : Classes.StepBranch} (mem : b ∈ witnessed) :
    ∃ s : Step, label s (.step b) = true := by
  obtain ⟨c, _, rfl⟩ := List.mem_map.mp mem
  exact c.property

end ConsensusCoverage.CaseWitnessesDeep
