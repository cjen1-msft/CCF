module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.NominationRows
import all ConsensusCoverage.ActionProfile
import all ConsensusCoverage.NominationArms
import all ConsensusCoverage.NominationRows
import all ConsensusCoverage.ReducedQuestions
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.NominationRows

open ActionProfile FullProfile ReducedQuestions
open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

private theorem queue (s : Step) (pass : test s.cfg s.before s.act s.after s.past = true) :
    label s (.step .messages_mem_network_inr) = true ∧
    label s (.step .mem_network_mem_append_inl) = false ∧
    label s (.step .mem_network_mem_append_inr) = true ∧
    label s (.step .new_message_h_proposeRequestVoteRequest) = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  have msg := (Bool.and_eq_true_iff.mp pass).2
  obtain ⟨stable, _, e, sent, fresh⟩ := from_test s pass
  have only := stable.only e (pending_of_sent s.context sent) fresh
  have prop : hasKind .proposeRequestVoteRequest e.payload = true := by
    cases h : e.payload <;> simp [h, proposal] at only <;> rfl
  refine ⟨(answer_eq s .message).symm.trans msg, (answer_eq s .retained).symm,
    (answer_eq s .outgoing).symm.trans msg, (label_true s _).mpr ?_⟩
  exact (sent_iff s.context .proposeRequestVoteRequest).mpr ((freshSend_iff ..).mpr ⟨e, sent, fresh, prop⟩)

/-- The complete step signature: a fresh proposal and its four local proof arms. -/
@[expose] public def bits : Classes.StepBranch → Bool
  | .messages_mem_network_inr | .mem_network_mem_append_inr | .new_message_h_proposeRequestVoteRequest
  | .summary_event_internal | .summary_input_nominateSuccessor | .quiet_summary_either_inl
  | .nominate_sends_successor_some => true
  | _ => false

public theorem shape (s : Step) (pass : test s.cfg s.before s.act s.after s.past = true) :
    (label s).step = bits := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  obtain ⟨stable, _, e, sent, fresh⟩ := from_test s pass
  obtain ⟨internal, nom, quiet, notQuiet, successor, notEmpty⟩ :=
    NominationArms.pinned_answers stable.event (e := e) ⟨sent, fresh⟩
  have pos (b : Classes.StepBranch) (h : PinnedClasses.sig s.context b) : label s (.step b) = true :=
    (label_true s _).mpr h
  have neg (b : Classes.StepBranch) (h : ¬ PinnedClasses.sig s.context b) : label s (.step b) = false :=
    Bool.eq_false_iff.mpr (fun yes => h ((label_true s _).mp yes))
  obtain ⟨msg, keep, out, proposal⟩ := queue s pass
  funext b
  change label s (.step b) = bits b
  cases b <;> first | exact excluded s pass _ rfl | exact msg | exact keep | exact out | exact proposal
                    | exact pos _ internal | exact pos _ nom | exact pos _ quiet | exact pos _ successor
                    | exact neg _ notQuiet | exact neg _ notEmpty

public theorem positive_count : (stepBranches.toList.filter bits).length = 7 := by decide +kernel

/-- The seven-positive signature identifies the recorded action, not merely
a call to `nominateSuccessor` within some other action. -/
public theorem test_iff (s : Step) :
    test s.cfg s.before s.act s.after s.past = true ↔ (label s).step = bits := by
  refine ⟨shape s, fun eq => ?_⟩
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  have hit : label s (.step .summary_input_nominateSuccessor) = true := congrFun eq _
  have tag := EventSupport.sig_support s.context _ ((label_true s _).mp hit)
  rw [(s.context_eq s.context).mpr rfl] at tag
  have nom : EventSupport.actionTag s.act = .nominateSuccessor :=
    List.mem_singleton.mp (show EventSupport.actionTag s.act ∈ [.nominateSuccessor] from tag)
  exact Bool.and_eq_true_iff.mpr ⟨Bool.and_eq_true_iff.mpr ⟨decide_eq_true nom,
    SignedQuiet.evidence_of_negatives s (congrFun eq _) (congrFun eq _)⟩,
    (answer_eq s .message).trans (congrFun eq _)⟩

end ConsensusCoverage.NominationRows
