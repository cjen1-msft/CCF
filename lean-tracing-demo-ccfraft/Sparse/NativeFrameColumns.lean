-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeFrameEncode
import Sparse.NativeAssignmentEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

structure FrameColumnsRep {width : PNat} (assignment : Assignment) (columns : Columns)
    (frame : NativeArrayVote.Frame (Fin width) Nat) : Prop where
  nodes : NodeColumnsRep assignment columns frame.nodes
  hasJoined : assignment (.bits width) columns.hasJoined = encodeBits frame.globals.hasJoined
  preVoteStatus : forall node : Fin width,
    assignment (.array .int .bool) columns.preVoteStatus node.val =
      preVoteBit (frame.globals.preVoteStatus node)
  retirementCompleted : forall node : Fin width,
    assignment (.array .int (.bits width)) columns.retirementCompleted node.val =
      encodeBits (frame.globals.retirementCompleted node)
  submittedTxIds : forall txId : Nat,
    assignment (.array .int (.bits 1)) columns.submittedTxIds txId = 1 <->
      txId ∈ frame.globals.submittedTxIds

noncomputable def initialFrame (width : PNat) [Bootstrap (Fin width)] (assignment : Assignment)
    (domains : forall node : Fin width, NodeDomain width assignment node.val)
    (submitted : NatSetDomain assignment 19 20) :
    NativeArrayVote.Frame (Fin width) Nat :=
  let nodes := initialArrays width assignment domains
  let template := NativeArrayVote.Frame.ofModel (NativeArrayCheckQuorum.realize nodes)
  { template with
    nodes
    globals := { template.globals with
      hasJoined := decodeBits (assignment (.bits width) 16)
      preVoteStatus := fun node => decodePreVote (assignment (.array .int .bool) 17 node.val)
      retirementCompleted := fun node => decodeBits (assignment (.array .int (.bits width)) 18 node.val)
      submittedTxIds := (natSetArray assignment 19 20 submitted).decode } }

theorem initial_frame_rep (width : PNat) [Bootstrap (Fin width)] (assignment : Assignment)
    (domains : forall node : Fin width, NodeDomain width assignment node.val)
    (submitted : NatSetDomain assignment 19 20) :
    FrameColumnsRep assignment {} (initialFrame width assignment domains submitted) := by
  refine ⟨initial_arrays_rep width assignment domains, ?_, ?_, ?_, ?_⟩
  · simp [initialFrame]
  · intro node
    simp [initialFrame]
  · intro node
    simp [initialFrame]
  · intro txId
    exact (nat_set_member_correct assignment 19 20 submitted txId).symm

theorem initial_frame_valid (width : PNat) [Bootstrap (Fin width)] (assignment : Assignment)
    (domains : forall node : Fin width, NodeDomain width assignment node.val)
    (submitted : NatSetDomain assignment 19 20) :
    (initialFrame width assignment domains submitted).Valid :=
  NativeArrayVote.of_model_valid (NativeArrayCheckQuorum.realize (initialArrays width assignment domains))

noncomputable def initialFrameAssignment (width : PNat) (seed : Assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat) : Assignment :=
  let seed := natSetAssignment seed 19 20 frame.globals.submittedTxIds
  let seed := seed.set (.bits width) 16 (encodeBits frame.globals.hasJoined)
  let seed := seed.set (.array .int .bool) 17
    (nodeArray false fun node => preVoteBit (frame.globals.preVoteStatus node))
  let seed := seed.set (.array .int (.bits width)) 18
    (nodeArray 0 fun node => encodeBits (frame.globals.retirementCompleted node))
  initialAssignment width seed frame.nodes

theorem initial_frame_assignment_rep (width : PNat) (seed : Assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat) :
    FrameColumnsRep (initialFrameAssignment width seed frame) {} frame := by
  refine ⟨initial_assignment_rep width _ frame.nodes, ?_, ?_, ?_, ?_⟩
  · simp [initialFrameAssignment, initialAssignment, Assignment.set]
  · intro node
    simp [initialFrameAssignment, initialAssignment, Assignment.set, entryTy, optionalIntTy]
  · intro node
    simp [initialFrameAssignment, initialAssignment, Assignment.set, entryTy, optionalIntTy]
  · intro txId
    simp only [initialFrameAssignment, initialAssignment]
    simp [Assignment.set_other_index]
    simp [natSetAssignment, Assignment.set]

theorem initial_frame_assignment_domains (width : PNat) (seed : Assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat) (node : Fin width) :
    NodeDomain width (initialFrameAssignment width seed frame) node.val :=
  initial_assignment_domains width _ frame.nodes node

theorem initial_frame_assignment_submitted_domain (width : PNat) (seed : Assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat) :
    NatSetDomain (initialFrameAssignment width seed frame) 19 20 := by
  simp only [NatSetDomain, initialFrameAssignment, initialAssignment]
  simpa [NatSetDomain, Assignment.set_other_index] using
    nat_set_assignment_domain seed 19 20 frame.globals.submittedTxIds

theorem initial_frame_domains_success {width : PNat} (before after : Encoding width)
    (run : (initialFrameDomains width).run before = .ok ((), after)) (assignment : Assignment) :
    SameReferences before after /\
      (Holds after.assertions.toList assignment <-> Holds before.assertions.toList assignment /\
        (forall node : Fin width, NodeDomain width assignment node.val) /\
        NatSetDomain assignment 19 20) := by
  refine ⟨(assert_all_success (initialFrameAssertions width) before after run).1, ?_⟩
  rw [assert_all_holds (initialFrameAssertions width) before after run assignment]
  have domains : Holds (initialFrameAssertions width) assignment <->
      Holds (initialAssertions width) assignment /\ NatSetDomain assignment 19 20 := by
    simp [initialFrameAssertions, Holds, or_imp, forall_and]
    exact fun _ => nat_set_domain_correct assignment 19 20
  rw [domains, initial_assertions_domains]

theorem FrameColumnsRep.agrees_below {width : PNat} (state : Encoding width)
    (left right : Assignment) (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep left state.toColumns frame) (valid : ReferencesValid state)
    (same : left.AgreesBelow state.next right) :
    FrameColumnsRep right state.toColumns frame :=
  ⟨rep.nodes.agrees_below state left right frame.nodes valid same,
    (same (.bits width) state.hasJoined valid.hasJoined).symm.trans rep.hasJoined,
    fun node => congrFun (same (.array .int .bool) state.preVoteStatus valid.preVoteStatus).symm
      (node.val : Int) |>.trans (rep.preVoteStatus node),
    fun node => congrFun (same (.array .int (.bits width)) state.retirementCompleted valid.retirementCompleted).symm
      (node.val : Int) |>.trans (rep.retirementCompleted node),
    fun txId => by
      rw [<- same (.array .int (.bits 1)) state.submittedTxIds valid.submittedTxIds]
      exact rep.submittedTxIds txId⟩

theorem FrameColumnsRep.node_step {width : PNat} (assignment : Assignment)
    (before after : Columns) (frame : NativeArrayVote.Frame (Fin width) Nat)
    (item : NativeArrayCheckQuorum.Instruction (Fin width) Nat)
    (rep : FrameColumnsRep assignment before frame)
    (nodes : NodeColumnsRep assignment after (frame.nodeStep item).nodes)
    (joined : after.hasJoined = before.hasJoined)
    (status : after.preVoteStatus = before.preVoteStatus)
    (completed : after.retirementCompleted = before.retirementCompleted)
    (submitted : after.submittedTxIds = before.submittedTxIds) :
    FrameColumnsRep assignment after (frame.nodeStep item) := by
  have globals : (frame.nodeStep item).globals = frame.globals := by cases item <;> rfl
  refine ⟨nodes, ?_, ?_, ?_, ?_⟩
  · simpa only [globals, joined] using rep.hasJoined
  · simpa only [globals, status] using rep.preVoteStatus
  · simpa only [globals, completed] using rep.retirementCompleted
  · simpa only [globals, submitted] using rep.submittedTxIds

theorem observation_node_step {width : PNat} (frame : NativeArrayVote.Frame (Fin width) Nat)
    (columns : Columns) (item : NativeArrayCheckQuorum.Instruction (Fin width) Nat)
    (clauses : List (Expr .bool)) (emitted : observationClauses columns item = .ok clauses) :
    frame.nodeStep item = frame := by
  cases item
  case checkQuorum => cases emitted
  all_goals rfl

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
