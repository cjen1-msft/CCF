module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ActionProfile
import all ConsensusCoverage.ActionProfile
import all ConsensusCoverage.HandReadersBGate
import all ConsensusCoverage.HandReadersBDispatch
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
meta import Lean

namespace ConsensusCoverage.HandReadersBSummary

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety
open ActionProfile HandReadersBGate HandReadersBDispatch SolvedWitnesses

set_option maxRecDepth 8192

public inductive Kind where
  | internal | append | send | timeout | election | quorum | nominate | install
  | receive | request | ack | vote | ballot | preVote | preBallot | propose
  deriving DecidableEq

public def column : Kind → Classes.StepBranch
  | .internal => .summary_event_internal
  | .append => .summary_input_append
  | .send => .summary_input_sendEntries
  | .timeout => .summary_input_timeout
  | .election => .summary_kind_election
  | .quorum => .summary_kind_checkQuorum
  | .nominate => .summary_input_nominateSuccessor
  | .install => .summary_input_initAsBackup
  | .receive => .summary_event_receive
  | .request => .summary_message_appendEntriesRequest
  | .ack => .summary_message_appendEntriesResponse
  | .vote => .summary_message_requestVoteRequest
  | .ballot => .summary_message_requestVoteResponse
  | .preVote => .summary_message_requestPreVoteRequest
  | .preBallot => .summary_message_requestPreVoteResponse
  | .propose => .summary_message_proposeRequestVoteRequest

private def accepts : Kind → Event → Bool
  | .internal, .internal _ | .receive, .receive .. => true
  | .append, .internal (.append _) | .send, .internal (.sendEntries ..)
  | .timeout, .internal (.timeout _) | .election, .internal (.timeout .election)
  | .quorum, .internal (.timeout .checkQuorum) | .nominate, .internal .nominateSuccessor
  | .install, .internal (.initAsBackup _) => true
  | .request, .receive _ (.appendEntriesRequest _) | .ack, .receive _ (.appendEntriesResponse _)
  | .vote, .receive _ (.requestVoteRequest _) | .ballot, .receive _ (.requestVoteResponse _)
  | .preVote, .receive _ (.requestPreVoteRequest _) | .preBallot, .receive _ (.requestPreVoteResponse _)
  | .propose, .receive _ (.proposeRequestVoteRequest _) => true
  | _,_ => false

open Lean Meta Elab Term in
local elab "dispatch_guard% " q:ident : term => do
  let ci ← getConstInfo (←realizeGlobalConstNoOverloadWithInfo q)
  lambdaTelescope ci.value! fun _ body => do
    let first := body.getArg! 0
    withLocalDeclD `event first.getAppArgs[0]! fun e =>
      mkLambdaFVars #[e] (first.appArg!.beta #[e]).appArg!

private def shape : Kind → Event → Prop
  | .internal => dispatch_guard% step_summary_event_internal
  | .append => dispatch_guard% step_summary_input_append
  | .send => dispatch_guard% step_summary_input_sendEntries
  | .timeout => dispatch_guard% step_summary_input_timeout
  | .election => dispatch_guard% step_summary_kind_election
  | .quorum => dispatch_guard% step_summary_kind_checkQuorum
  | .nominate => dispatch_guard% step_summary_input_nominateSuccessor
  | .install => dispatch_guard% step_summary_input_initAsBackup
  | .receive => dispatch_guard% step_summary_event_receive
  | .request => dispatch_guard% step_summary_message_appendEntriesRequest
  | .ack => dispatch_guard% step_summary_message_appendEntriesResponse
  | .vote => dispatch_guard% step_summary_message_requestVoteRequest
  | .ballot => dispatch_guard% step_summary_message_requestVoteResponse
  | .preVote => dispatch_guard% step_summary_message_requestPreVoteRequest
  | .preBallot => dispatch_guard% step_summary_message_requestPreVoteResponse
  | .propose => dispatch_guard% step_summary_message_proposeRequestVoteRequest

private theorem shape_iff (k : Kind) (e : Event) : shape k e ↔ accepts k e = true := by
  cases e with
  | internal i =>
    cases i
    case timeout sub => cases sub <;> cases k <;> simp [shape, accepts] <;> grind
    all_goals cases k <;> simp [shape, accepts] <;> grind
  | receive n m =>
    cases m <;> cases k <;> simp [shape,accepts] <;> grind

private theorem query_eq [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t) (k : Kind) :
    sig c (column k) ↔ Query f t c (shape k) := by cases k <;> rfl

public def answer (cfg : FullProfile.Configuration) (before : State) (act : Action)
    (after : State) (past : List State) (k : Kind) : Bool :=
  accepts k (ReadersAtoms.eventOf act) && active cfg before act after past

public theorem exact_answer (s : Step) (k : Kind) :
    label s (.step (column k)) = answer s.cfg s.before s.act s.after s.past k := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  have pin : ReadersAtoms.eventOf s.act = s.context.event := by
    rw [← (s.context_eq s.context).mpr rfl]
    change ReadersAtoms.eventOf (ActionContext.encode s.context.tr.actor s.context.tr.event) = s.context.tr.event
    cases s.context.tr.event <;> rfl
  apply Bool.eq_iff_iff.mpr
  rw [label_true,holds,sig_iff,query_eq,query_iff _ (quiet s),answer,Bool.and_eq_true,pin,live,shape_iff,and_comm]

end ConsensusCoverage.HandReadersBSummary
