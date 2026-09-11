-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.StateFrameInitial
import Sparse.NativeNodeSets

set_option autoImplicit false

/-!
Only StateFrame's finite scalar domains are emitted here. Scope and ownership
are separate checks. Graph cells, packet identity, queue/submitted completion,
and action transitions are not encoded by this formula.
Text correspondence uses the reference parser/interpreter, not an external solver proof.
-/

namespace CCFRaft.Sparse.StateFrameEncoding

open Smt (Ty Term Assignment)
open StateFrame

variable {roots versions : Nat}

def refTerm {ty : Ty} (ref : ConstRef ty) : Term ty := .unknown ty ref.id

theorem ref_eval {ty : Ty} (ref : ConstRef ty) (assignment : Assignment) :
    (refTerm ref).eval assignment = ref.eval assignment := rfl

def nonnegative (ref : ConstRef .int) : Term .bool :=
  .le (.integer 0) (refTerm ref)

def localFormula (row : LocalRefs roots versions) : SmtScript.Formula :=
  [nonnegative row.role, .not (.le (.integer 5) (refTerm row.role)),
   nonnegative row.membershipState, .not (.le (.integer 5) (refTerm row.membershipState)),
   nonnegative row.votedFor, .le (refTerm row.votedFor) (.integer (NODE_COUNT : Int))] ++
    row.naturals.map nonnegative

def conjoin (formula : SmtScript.Formula) : Term .bool :=
  formula.foldr Term.and (.boolean true)

theorem conjoin_correct (assignment : Assignment) (formula : SmtScript.Formula) :
    (conjoin formula).eval assignment = true <-> SmtScript.Holds assignment formula := by
  induction formula with
  | nil => simp [conjoin, Term.eval, SmtScript.Holds]
  | cons term rest ih =>
    change (term.eval assignment && (conjoin rest).eval assignment) = true <->
      SmtScript.Holds assignment (term :: rest)
    rw [Bool.and_eq_true, ih]
    simp [SmtScript.Holds]

theorem local_formula_correct (assignment : Assignment) (row : LocalRefs roots versions) :
    SmtScript.Holds assignment (localFormula row) <-> LocalDomains assignment row := by
  simp [localFormula, SmtScript.Holds, nonnegative, refTerm, Term.eval, ConstRef.eval,
    LocalDomains, and_assoc]

def nodeClause (frame : Frame roots versions) (node : Node) : Term .bool :=
  .implies (NativeNodeOperations.member node (refTerm frame.allocated))
    (conjoin (localFormula frame.locals[node.val]))

def encode (frame : Frame roots versions) : SmtScript.Formula :=
  List.ofFn (nodeClause frame)

theorem node_clause_correct (assignment : Assignment) (frame : Frame roots versions) (node : Node) :
    (nodeClause frame node).eval assignment = true <->
      (Membership.mem (allocatedNodes assignment frame) node ->
        LocalDomains assignment frame.locals[node.val]) := by
  have member : (NativeNodeOperations.member node (refTerm frame.allocated)).eval assignment =
      decide (Membership.mem (allocatedNodes assignment frame) node) :=
    NativeNodeOperations.member_eval assignment node (refTerm frame.allocated)
  change ((!((NativeNodeOperations.member node (refTerm frame.allocated)).eval assignment)) ||
    (conjoin (localFormula frame.locals[node.val])).eval assignment) = true <-> _
  rw [member]
  by_cases present : Membership.mem (allocatedNodes assignment frame) node
  next =>
    rw [decide_eq_true present]
    simp only [Bool.not_true, Bool.false_or, present, true_implies]
    exact (conjoin_correct assignment _).trans (local_formula_correct assignment _)
  next =>
    rw [decide_eq_false present]
    simp only [Bool.not_false, Bool.true_or, present, false_implies]

theorem formula_correct (assignment : Assignment) (frame : Frame roots versions) :
    SmtScript.Holds assignment (encode frame) <-> Domains assignment frame := by
  unfold SmtScript.Holds encode
  rw [List.forall_mem_ofFn_iff]
  exact forall_congr' (node_clause_correct assignment frame)

def render (frame : Frame roots versions) : String :=
  SmtScript.render (encode frame)

theorem text_correct (assignment : Assignment) (frame : Frame roots versions) :
    SmtScriptText.runText assignment (render frame) = some true <-> Domains assignment frame :=
  (SmtScriptText.formula_text_iff assignment (encode frame)).symm.trans
    (formula_correct assignment frame)

theorem parse_render (frame : Frame roots versions) :
    SmtScriptText.parse (render frame) = some (SmtScript.compile (encode frame)) :=
  SmtScriptText.parse_render _

theorem text_result (assignment : Assignment) (frame : Frame roots versions) :
    SmtScriptText.runText assignment (render frame) = some (checkDomains assignment frame) := by
  rw [render, SmtScriptText.runText_render, SmtScript.compile_eval]
  apply congrArg some
  apply Bool.eq_iff_iff.mpr
  rw [List.all_eq_true]
  exact (formula_correct assignment frame).trans (check_domains_iff assignment frame).symm

theorem relative_realization (assignment : Assignment) (frame : Frame roots versions)
    (graph : Graph roots versions) (arrays : Roots roots) (network : Network) (submitted : Finset Nat) :
    SmtScript.Holds assignment (encode frame) <->
      exists state, Rep assignment graph arrays submitted frame state /\ state.network = network :=
  (formula_correct assignment frame).trans
    (domains_iff_realizable assignment graph arrays network submitted frame)

theorem text_realization (assignment : Assignment) (frame : Frame roots versions)
    (graph : Graph roots versions) (arrays : Roots roots) (network : Network) (submitted : Finset Nat) :
    SmtScriptText.runText assignment (render frame) = some true <->
      exists state, Rep assignment graph arrays submitted frame state /\ state.network = network :=
  (text_correct assignment frame).trans
    (domains_iff_realizable assignment graph arrays network submitted frame)

theorem canonical_assignment_text (original : Assignment) (state : ModelState)
    (base prior versions : Nat) (old : Roots prior) (graph : Graph (prior + NODE_COUNT) versions) :
    SmtScriptText.runText (StateFrameInitial.install original state base)
      (render (StateFrameInitial.frame base prior versions)) = some true :=
  (text_correct _ _).mpr
    (StateFrameInitial.arbitrary_state_coverage original state base prior versions old graph).domains

theorem encode_globals (frame : Frame roots versions) (joined : ConstRef .nodes)
    (preVote : Vector (ConstRef .bool) NODE_COUNT)
    (completed : Vector (ConstRef .nodes) NODE_COUNT) :
    encode { frame with
      hasJoined := joined
      preVoteEnabled := preVote
      retirementCompleted := completed } = encode frame := rfl

theorem local_nonnumeric (row : LocalRefs roots versions) (follower : ConstRef .bool)
    (votes preVotes : ConstRef .nodes) (address : IntervalReadback.Address roots versions) :
    localFormula { row with
      isNewFollower := follower
      votesGranted := votes
      preVotesGranted := preVotes
      log := { row.log with address } } = localFormula row := rfl

theorem local_formula_length (row : LocalRefs roots versions) :
    (localFormula row).length = 42 := by
  simp [localFormula, LocalRefs.naturals, NODE_COUNT]

theorem formula_length (frame : Frame roots versions) :
    (encode frame).length = NODE_COUNT := List.length_ofFn

def sample (allocationID : Nat) (allocated other : BitVec NODE_COUNT) (codes : Nat -> Int) :
    Assignment where
  constant := fun ty id => match ty with
    | .int => codes id
    | .nodes => if id = allocationID then allocated else other
    | .bool => true
    | .content => .signature
    | .entry => { term := -1, content := .signature }
  unary := fun _ result _ _ => StateFrame.fixtureDefault result

def goodCodes : Nat -> Int
  | 0 => 4
  | 4 => 1
  | 5 => 4
  | 6 => 15
  | _ => 0

def changedCodes (index : Nat) (value : Int) : Nat -> Int :=
  fun id => if id = index then value else goodCodes id

def formulaValue (assignment : Assignment) (frame : Frame roots versions) : Bool :=
  (encode frame).all (Term.eval assignment)

theorem formula_value_correct (assignment : Assignment) (frame : Frame roots versions) :
    formulaValue assignment frame = checkDomains assignment frame := by
  apply Bool.eq_iff_iff.mpr
  rw [formulaValue, List.all_eq_true]
  exact (formula_correct assignment frame).trans (check_domains_iff assignment frame).symm

def invalidCases : List (Prod Nat Int) :=
  [(0, -1), (0, 5), (5, -1), (5, 5), (6, -1), (6, 16),
    (1, -1), (2, -1), (3, -1), (4, -1), (7, -1)]

theorem active_invalid_regression :
    invalidCases.all (fun pair =>
      !(formulaValue (sample 0 16384 32767 (changedCodes pair.1 pair.2)) fixtureFrame)) = true := by
  decide +kernel

theorem dormant_invalid_regression :
    formulaValue (sample 0 0 32767 (fun _ => -1000000)) fixtureFrame = true := by
  decide +kernel

theorem range_edges_regression :
    (List.range 5).all (fun code => formulaValue
      (sample 0 16384 32767 (fun id =>
        if id = 0 \/ id = 5 then (code : Int) else goodCodes id)) fixtureFrame) = true /\
    ([0, 1, 15] : List Int).all (fun code =>
      formulaValue (sample 0 16384 32767 (changedCodes 6 code)) fixtureFrame) = true /\
    ([0, 1, 1000001] : List Int).all (fun code =>
      formulaValue (sample 0 16384 32767 (changedCodes 4 code)) fixtureFrame) = true := by
  decide +kernel

theorem unbounded_numerics_regression :
    ([1, 2, 3, 4, 7] : List Nat).all (fun id =>
      formulaValue (sample 0 16384 32767 (changedCodes id 1000000000)) fixtureFrame) = true := by
  decide +kernel

def aliasFrame : Frame 1 0 :=
  { fixtureFrame with locals :=
      Vector.replicate NODE_COUNT { fixtureRow with currentTerm := fixtureRow.role } }

theorem alias_regression :
    formulaValue (sample 0 16384 32767 goodCodes) aliasFrame = true /\
      formulaValue (sample 0 16384 32767 (changedCodes 0 5)) aliasFrame = false := by
  decide +kernel

def node14Codes (id : Nat) : Int := if id = 546 then 5 else 0

theorem node14_regression :
    formulaValue (sample 615 16384 32767 node14Codes) (StateFrameInitial.frame 0 0 0) = false /\
      formulaValue (sample 615 1 32767 node14Codes) (StateFrameInitial.frame 0 0 0) = true := by
  decide +kernel

theorem node14_native_bytes :
    (NativeNodeOperations.member (Fin.mk 14 (by decide)) (.nodes 16384)).render =
      "(= (bvand #b100000000000000 #b100000000000000) #b100000000000000)" := by
  simp only [NativeNodeOperations.member, Term.render, Term.lower, Smt.call,
    Smt.SExpr.render, Smt.Atom.render, List.map_cons, List.map_nil]
  decide +kernel

theorem dormant_native_text :
    SmtScriptText.runText (sample 0 0 32767 (fun _ => -1000000)) (render fixtureFrame) =
      some true := by
  rw [text_result, <- formula_value_correct]
  exact congrArg some dormant_invalid_regression

theorem node14_native_text :
    SmtScriptText.runText (sample 615 16384 32767 node14Codes)
      (render (StateFrameInitial.frame 0 0 0)) = some false := by
  rw [text_result, <- formula_value_correct]
  exact congrArg some node14_regression.1

theorem canonical_globals_regression :
    SmtScriptText.runText
      (StateFrameInitial.install StateFrameInitial.regressionOriginal StateFrameInitial.regressionState 1000)
      (render (StateFrameInitial.frame 1000 7 0)) = some true :=
  canonical_assignment_text StateFrameInitial.regressionOriginal StateFrameInitial.regressionState
    1000 7 0 StateFrameInitial.regressionRoots .empty

theorem scope_is_separate :
    formulaValue (sample 0 0 32767 (fun _ => -1000000)) fixtureFrame = true /\
      Not (WellScoped {} fixtureFrame) := by
  refine And.intro dormant_invalid_regression ?_
  intro scopeValid
  have member := scopeValid fixtureFrame.allocated.symbol (by simp [Frame.symbols])
  simp at member

end CCFRaft.Sparse.StateFrameEncoding

run_cmd do
  let mut checked := 0
  for (name, info) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.Sparse.StateFrameEncoding).isPrefixOf name then
      match info with
      | .axiomInfo _ => throwError "explicit StateFrameEncoding axiom: {name}"
      | _ =>
        checked := checked + 1
        for axiomName in (<- Lean.collectAxioms name) do
          unless axiomName == ``propext || axiomName == ``Classical.choice ||
              axiomName == ``Quot.sound do
            throwError "unexpected axiom in {name}: {axiomName}"
  Lean.logInfo m!"StateFrameEncoding: {checked} declarations passed the allowed-axiom gate."
