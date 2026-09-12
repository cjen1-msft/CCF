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

noncomputable def initialFrame (width : PNat) [Bootstrap (Fin width)] (assignment : Assignment)
    (domains : forall node : Fin width, NodeDomain width assignment node.val) :
    NativeArrayVote.Frame (Fin width) Nat :=
  let nodes := initialArrays width assignment domains
  let template := NativeArrayVote.Frame.ofModel (NativeArrayCheckQuorum.realize nodes)
  { template with
    nodes
    globals := { template.globals with hasJoined := decodeBits (assignment (.bits width) 16) } }

theorem initial_frame_rep (width : PNat) [Bootstrap (Fin width)] (assignment : Assignment)
    (domains : forall node : Fin width, NodeDomain width assignment node.val) :
    FrameColumnsRep assignment {} (initialFrame width assignment domains) := by
  refine ⟨initial_arrays_rep width assignment domains, ?_⟩
  simp [initialFrame]

theorem initial_frame_valid (width : PNat) [Bootstrap (Fin width)] (assignment : Assignment)
    (domains : forall node : Fin width, NodeDomain width assignment node.val) :
    (initialFrame width assignment domains).Valid :=
  NativeArrayVote.of_model_valid (NativeArrayCheckQuorum.realize (initialArrays width assignment domains))

noncomputable def initialFrameAssignment (width : PNat) (seed : Assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat) : Assignment :=
  initialAssignment width (seed.set (.bits width) 16 (encodeBits frame.globals.hasJoined)) frame.nodes

theorem initial_frame_assignment_rep (width : PNat) (seed : Assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat) :
    FrameColumnsRep (initialFrameAssignment width seed frame) {} frame := by
  refine ⟨initial_assignment_rep width _ frame.nodes, ?_⟩
  simp [initialFrameAssignment, initialAssignment, Assignment.set]

theorem initial_frame_assignment_domains (width : PNat) (seed : Assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat) (node : Fin width) :
    NodeDomain width (initialFrameAssignment width seed frame) node.val :=
  initial_assignment_domains width _ frame.nodes node

theorem FrameColumnsRep.agrees_below {width : PNat} (state : Encoding width)
    (left right : Assignment) (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep left state.toColumns frame) (valid : ReferencesValid state)
    (same : left.AgreesBelow state.next right) :
    FrameColumnsRep right state.toColumns frame :=
  ⟨rep.nodes.agrees_below state left right frame.nodes valid same,
    (same (.bits width) state.hasJoined valid.hasJoined).symm.trans rep.hasJoined⟩

theorem FrameColumnsRep.node_step {width : PNat} (assignment : Assignment)
    (before after : Columns) (frame : NativeArrayVote.Frame (Fin width) Nat)
    (item : NativeArrayCheckQuorum.Instruction (Fin width) Nat)
    (rep : FrameColumnsRep assignment before frame)
    (nodes : NodeColumnsRep assignment after (frame.nodeStep item).nodes)
    (joined : after.hasJoined = before.hasJoined) :
    FrameColumnsRep assignment after (frame.nodeStep item) := by
  refine ⟨nodes, ?_⟩
  have globals : (frame.nodeStep item).globals = frame.globals := by cases item <;> rfl
  simpa only [globals, joined] using rep.hasJoined

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
