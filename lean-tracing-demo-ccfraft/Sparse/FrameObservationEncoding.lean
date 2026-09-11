-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.ModelInputScalarEncoding

set_option autoImplicit false

namespace CCFRaft.Sparse.FrameObservationEncoding

open Smt (Assignment Term)
open StateFrame (Frame ConstRef Rep Graph Roots ModelState Network)
open StateFrameEncoding (refTerm)
open ModelInputSyntax (NatAtom BoolAtom ObservationSyntax StateObservationSyntax)
open ModelInputScalarEncoding
open ModelTrace (UnknownNatAssignment)

variable {n roots versions : Nat}

def Supported : ObservationSyntax n -> Prop
  | .allocated _ _ | .joined _ _ | .role _ _ | .currentTerm _ _
  | .commitIndex _ _ | .logLength _ _ | .state _ => True
  | .submitted _ _ | .firstMessage _ _ _ | .messageSummary _
  | .queueLength _ _ | .configurationSnapshot _ _ => False

instance (value : ObservationSyntax n) : Decidable (Supported value) := by
  cases value <;> unfold Supported <;> infer_instance

abbrev Observation (n : Nat) := { value : ObservationSyntax n // Supported value }

inductive Rejection where
  | submitted | firstMessage | messageSummary | queueLength | configurationSnapshot | action
  deriving DecidableEq, Repr

def check (value : ObservationSyntax n) : Except Rejection (Observation n) :=
  match found : value with
  | .allocated _ _ | .joined _ _ | .role _ _ | .currentTerm _ _
  | .commitIndex _ _ | .logLength _ _ | .state _ =>
    .ok (Subtype.mk value (by simp [found, Supported]))
  | .submitted _ _ => .error .submitted
  | .firstMessage _ _ _ => .error .firstMessage
  | .messageSummary _ => .error .messageSummary
  | .queueLength _ _ => .error .queueLength
  | .configurationSnapshot _ _ => .error .configurationSnapshot

theorem check_correct (value : ObservationSyntax n) (checked : Observation n) :
    check value = .ok checked <-> checked.val = value := by
  cases checked
  rename_i checked valid
  cases value <;> cases checked <;> simp_all [check, Supported, eq_comm]
  all_goals exact False.elim valid

def checkList : List (ObservationSyntax n) -> Except Rejection (List (Observation n))
  | [] => .ok []
  | value :: rest => do
    let checked <- check value
    let remaining <- checkList rest
    return checked :: remaining

def checkTrace : ModelInputSyntax.Trace n -> Except Rejection (List (Observation n))
  | [] => .ok []
  | .action _ :: _ => .error .action
  | .observation value :: rest => do
    let checked <- check value
    let remaining <- checkTrace rest
    return checked :: remaining

theorem check_list_preserves (values : List (ObservationSyntax n)) (checked : List (Observation n))
    (accepted : checkList values = .ok checked) : checked.map Subtype.val = values := by
  induction values generalizing checked with
  | nil =>
    have same : [] = checked := by simpa [checkList] using accepted
    rw [<- same]
    rfl
  | cons value rest ih =>
    cases first : check value with
    | error reason =>
      simp only [checkList, first] at accepted
      cases accepted
    | ok head =>
      cases remaining : checkList rest with
      | error reason =>
        simp only [checkList, first, remaining] at accepted
        cases accepted
      | ok tail =>
        simp only [checkList, first, remaining] at accepted
        have same : head :: tail = checked := Except.ok.inj accepted
        rw [<- same, List.map_cons, (check_correct value head).mp first, ih tail remaining]

theorem check_list_roundtrip (checked : List (Observation n)) :
    checkList (checked.map Subtype.val) = .ok checked := by
  induction checked with
  | nil => rfl
  | cons head tail ih =>
    simp only [List.map_cons, checkList, (check_correct head.val head).mpr rfl, ih]
    rfl

theorem check_list_correct (values : List (ObservationSyntax n)) (checked : List (Observation n)) :
    checkList values = .ok checked <-> checked.map Subtype.val = values := by
  constructor
  next => exact check_list_preserves values checked
  next =>
    intro same
    rw [<- same]
    exact check_list_roundtrip checked

def observationTrace (observations : List (Observation n)) : ModelInputSyntax.Trace n :=
  observations.map fun observation => .observation observation.val

theorem check_trace_preserves (trace : ModelInputSyntax.Trace n) (checked : List (Observation n))
    (accepted : checkTrace trace = .ok checked) : observationTrace checked = trace := by
  induction trace generalizing checked with
  | nil =>
    have same : [] = checked := by simpa [checkTrace] using accepted
    rw [<- same]
    rfl
  | cons instruction rest ih =>
    cases instruction with
    | action action => simp [checkTrace] at accepted
    | observation value =>
      cases first : check value with
      | error reason =>
        simp only [checkTrace, first] at accepted
        cases accepted
      | ok head =>
        cases remaining : checkTrace rest with
        | error reason =>
          simp only [checkTrace, first, remaining] at accepted
          cases accepted
        | ok tail =>
          simp only [checkTrace, first, remaining] at accepted
          have same : head :: tail = checked := Except.ok.inj accepted
          change (checked.map fun observation =>
            (TraceValidation.Instruction.observation observation.val : ModelInputSyntax.Instruction n)) = _
          rw [<- same, List.map_cons, (check_correct value head).mp first]
          exact congrArg (List.cons (.observation value)) (ih tail remaining)

theorem check_trace_roundtrip (checked : List (Observation n)) :
    checkTrace (observationTrace checked) = .ok checked := by
  induction checked with
  | nil => rfl
  | cons head tail ih =>
    simp only [observationTrace, List.map_cons, checkTrace,
      (check_correct head.val head).mpr rfl] at *
    simpa using congrArg (Except.map (List.cons head)) ih

theorem check_trace_correct (trace : ModelInputSyntax.Trace n) (checked : List (Observation n)) :
    checkTrace trace = .ok checked <-> observationTrace checked = trace := by
  constructor
  next => exact check_trace_preserves trace checked
  next =>
    intro same
    rw [<- same]
    exact check_trace_roundtrip checked

def allocated (frame : Frame roots versions) (node : Node) : Term .bool :=
  NativeNodeOperations.member node (refTerm frame.allocated)

def effectiveInt (frame : Frame roots versions) (node : Node)
    (ref : ConstRef .int) (fresh : Int) : Term .int :=
  .ite (allocated frame node) (refTerm ref) (.integer fresh)

def lowerState (base : Nat) (frame : Frame roots versions) :
    StateObservationSyntax n -> Term .bool
  | .preVoteStatus node value =>
    .equal (refTerm frame.preVoteEnabled[node.val]) (.boolean (decide (value = .enabled)))
  | .membershipState node value =>
    .equal (effectiveInt frame node frame.locals[node.val].membershipState
      (StateFrame.membershipCode .active)) (.integer (StateFrame.membershipCode value))
  | .retirementIndex node value =>
    .equal (effectiveInt frame node frame.locals[node.val].retirementIndex 0)
      (sourceOption base value)
  | .retirementCommittableIndex node value =>
    .equal (effectiveInt frame node frame.locals[node.val].retirementCommittableIndex 0)
      (sourceOption base value)
  | .retiredCommittedIndex node value =>
    .equal (effectiveInt frame node frame.locals[node.val].retiredCommittedIndex 0)
      (sourceOption base value)
  | .retirementCompleted observer retired value =>
    .equal (NativeNodeOperations.member retired (refTerm frame.retirementCompleted[observer.val]))
      (sourceBool base value)

def lower (base : Nat) (frame : Frame roots versions) : Observation n -> Term .bool
  | .mk (.allocated node value) _ => .equal (allocated frame node) (sourceBool base value)
  | .mk (.joined node value) _ =>
    .equal (NativeNodeOperations.member node (refTerm frame.hasJoined)) (sourceBool base value)
  | .mk (.role node value) _ =>
    .equal (effectiveInt frame node frame.locals[node.val].role (StateFrame.roleCode .none))
      (.integer (StateFrame.roleCode value))
  | .mk (.currentTerm node value) _ =>
    .equal (effectiveInt frame node frame.locals[node.val].currentTerm 0) (sourceNat base value)
  | .mk (.commitIndex node value) _ =>
    .equal (effectiveInt frame node frame.locals[node.val].commitIndex 0) (sourceNat base value)
  | .mk (.logLength node value) _ =>
    .equal (effectiveInt frame node frame.locals[node.val].log.length 0) (sourceNat base value)
  | .mk (.state value) _ => lowerState base frame value
  | .mk (.submitted _ _) impossible => False.elim impossible
  | .mk (.firstMessage _ _ _) impossible => False.elim impossible
  | .mk (.messageSummary _) impossible => False.elim impossible
  | .mk (.queueLength _ _) impossible => False.elim impossible
  | .mk (.configurationSnapshot _ _) impossible => False.elim impossible

theorem absent_fresh (state : ModelState) (node : Node) (absent : Not (state.allocated node)) :
    state.nodes node = freshNodeState := by
  change (state.nodes.node? node).getD freshNodeState = _
  change Not ((state.nodes.node? node).isSome = true) at absent
  cases found : state.nodes.node? node <;> simp_all

theorem allocated_eval (assignment : Assignment) (frame : Frame roots versions)
    (graph : Graph roots versions) (arrays : Roots roots) (submitted : Finset Nat)
    (state : ModelState) (rep : Rep assignment graph arrays submitted frame state) (node : Node) :
    (allocated frame node).eval assignment = decide (state.allocated node) := by
  rw [allocated, NativeNodeOperations.member_eval]
  change decide (Membership.mem (StateFrame.allocatedNodes assignment frame) node) = _
  simp only [<- rep.allocation node]

private theorem effective_int_eval (assignment : Assignment) (frame : Frame roots versions)
    (graph : Graph roots versions) (arrays : Roots roots) (submitted : Finset Nat)
    (state : ModelState) (rep : Rep assignment graph arrays submitted frame state)
    (node : Node) (ref : ConstRef .int) (read : NodeState Node Nat -> Int)
    (field : state.allocated node -> ref.eval assignment = read (state.nodes node)) :
    (effectiveInt frame node ref (read freshNodeState)).eval assignment = read (state.nodes node) := by
  change (if (allocated frame node).eval assignment then ref.eval assignment else read freshNodeState) = _
  rw [allocated_eval assignment frame graph arrays submitted state rep node]
  by_cases present : state.allocated node
  next => simpa [present] using field present
  next => simp [present, absent_fresh state node present]

@[simp] theorem role_code_eq (left right : Role) :
    StateFrame.roleCode left = StateFrame.roleCode right <-> left = right := by
  constructor
  next =>
    intro same
    exact SymbolicModel.roleEquiv.symm.injective (Fin.ext (Int.ofNat_inj.mp same))
  next => intro same; rw [same]

@[simp] theorem membership_code_eq (left right : MembershipState) :
    StateFrame.membershipCode left = StateFrame.membershipCode right <-> left = right := by
  constructor
  next =>
    intro same
    exact SymbolicModel.membershipEquiv.symm.injective (Fin.ext (Int.ofNat_inj.mp same))
  next => intro same; rw [same]

@[simp] theorem option_code_eq (left right : Option Nat) :
    StateFrame.optionNatCode left = StateFrame.optionNatCode right <-> left = right := by
  cases left <;> cases right <;> simp [StateFrame.optionNatCode] <;> omega

@[simp] theorem option_none_code : StateFrame.optionNatCode none = 0 := rfl

section Correctness

variable [Bootstrap Node]
variable (assignment : Assignment) (base : Nat) (rho : UnknownNatAssignment)
variable (graph : Graph roots versions) (arrays : Roots roots) (submitted : Finset Nat)
variable (frame : Frame roots versions) (state : ModelState)
variable (source : SourceRep assignment base n rho)
variable (rep : Rep assignment graph arrays submitted frame state)

include source rep

omit [Bootstrap Node] in
theorem lower_state_correct (value : StateObservationSyntax n) :
    (lowerState base frame value).eval assignment = true <-> (value.eval rho).Holds state := by
  have effective := effective_int_eval assignment frame graph arrays submitted state rep
  cases value with
  | preVoteStatus node value =>
    simp only [lowerState, Term.eval, StateFrameEncoding.ref_eval,
      StateObservationSyntax.eval, TraceStateObservation.Observation.Holds, rep.preVoteStatus]
    cases value <;> by_cases enabled : frame.preVoteEnabled[node.val].eval assignment = true <;>
      simp [enabled]
  | membershipState node value =>
    have field := effective node frame.locals[node.val].membershipState
      (fun stored => StateFrame.membershipCode stored.membershipState)
      (fun present => (rep.locals node present).membershipState)
    simp only [freshNodeState] at field
    change (Term.equal _ _).eval assignment = true <-> (state.nodes node).membershipState = value
    simp only [Term.eval, field, membership_code_eq, decide_eq_true_eq]
  | retirementIndex node value =>
    have field := effective node frame.locals[node.val].retirementIndex
      (fun stored => StateFrame.optionNatCode stored.retirementIndex)
      (fun present => (rep.locals node present).retirementIndex)
    simp only [freshNodeState, option_none_code] at field
    change (Term.equal _ _).eval assignment = true <-> _
    simp only [Term.eval, field, source_option_eval assignment base rho source, option_code_eq,
      decide_eq_true_eq, StateObservationSyntax.eval, TraceStateObservation.Observation.Holds]
  | retirementCommittableIndex node value =>
    have field := effective node frame.locals[node.val].retirementCommittableIndex
      (fun stored => StateFrame.optionNatCode stored.retirementCommittableIndex)
      (fun present => (rep.locals node present).retirementCommittableIndex)
    simp only [freshNodeState, option_none_code] at field
    change (Term.equal _ _).eval assignment = true <-> _
    simp only [Term.eval, field, source_option_eval assignment base rho source, option_code_eq,
      decide_eq_true_eq, StateObservationSyntax.eval, TraceStateObservation.Observation.Holds]
  | retiredCommittedIndex node value =>
    have field := effective node frame.locals[node.val].retiredCommittedIndex
      (fun stored => StateFrame.optionNatCode stored.retiredCommittedIndex)
      (fun present => (rep.locals node present).retiredCommittedIndex)
    simp only [freshNodeState, option_none_code] at field
    change (Term.equal _ _).eval assignment = true <-> _
    simp only [Term.eval, field, source_option_eval assignment base rho source, option_code_eq,
      decide_eq_true_eq, StateObservationSyntax.eval, TraceStateObservation.Observation.Holds]
  | retirementCompleted observer retired value =>
    simp only [lowerState, Term.eval, NativeNodeOperations.member_eval,
      StateFrameEncoding.ref_eval, source_bool_eval assignment base rho source,
      StateObservationSyntax.eval, TraceStateObservation.Observation.Holds,
      rep.retirementCompleted, decide_eq_true_eq]

theorem observation_correct (observation : Observation n) :
    (lower base frame observation).eval assignment = true <->
      (observation.val.eval rho).Holds state := by
  have effective := effective_int_eval assignment frame graph arrays submitted state rep
  cases observation
  rename_i observation valid
  cases observation with
  | allocated node value =>
    simp only [lower, Term.eval, allocated_eval assignment frame graph arrays submitted state rep,
      source_bool_eval assignment base rho source, ObservationSyntax.eval,
      ModelTrace.Observation.Holds, decide_eq_true_eq]
  | joined node value =>
    simp only [lower, Term.eval, NativeNodeOperations.member_eval,
      StateFrameEncoding.ref_eval, source_bool_eval assignment base rho source,
      ObservationSyntax.eval, ModelTrace.Observation.Holds, rep.joined, decide_eq_true_eq]
  | role node value =>
    have field := effective node frame.locals[node.val].role
      (fun stored => StateFrame.roleCode stored.role) (fun present => (rep.locals node present).role)
    simp only [freshNodeState] at field
    change (Term.equal _ _).eval assignment = true <-> (state.nodes node).role = value
    simp only [Term.eval, field, role_code_eq, decide_eq_true_eq]
  | currentTerm node value =>
    have field := effective node frame.locals[node.val].currentTerm
      (fun stored => (stored.currentTerm : Int)) (fun present => (rep.locals node present).currentTerm)
    simp only [freshNodeState, Nat.cast_zero] at field
    change (Term.equal _ _).eval assignment = true <-> _
    simp only [Term.eval, field, source_nat_eval assignment base rho source, Int.ofNat_inj,
      decide_eq_true_eq, ObservationSyntax.eval, ModelTrace.Observation.Holds]
  | commitIndex node value =>
    have field := effective node frame.locals[node.val].commitIndex
      (fun stored => (stored.commitIndex : Int)) (fun present => (rep.locals node present).commitIndex)
    simp only [freshNodeState, Nat.cast_zero] at field
    change (Term.equal _ _).eval assignment = true <-> _
    simp only [Term.eval, field, source_nat_eval assignment base rho source, Int.ofNat_inj,
      decide_eq_true_eq, ObservationSyntax.eval, ModelTrace.Observation.Holds]
  | logLength node value =>
    have field := effective node frame.locals[node.val].log.length
      (fun stored => (stored.log.length : Int)) (fun present => (rep.locals node present).logLength)
    simp only [freshNodeState, Nat.cast_zero, List.length_nil] at field
    change (Term.equal _ _).eval assignment = true <-> _
    simp only [Term.eval, field, source_nat_eval assignment base rho source, Int.ofNat_inj,
      decide_eq_true_eq, ObservationSyntax.eval, ModelTrace.Observation.Holds]
  | state value =>
    exact lower_state_correct assignment base rho graph arrays submitted frame state source rep value
  | submitted _ _ | firstMessage _ _ _ | messageSummary _ | queueLength _ _
  | configurationSnapshot _ _ => exact False.elim valid

end Correctness

def observationFormula (base : Nat) (frame : Frame roots versions)
    (observations : List (Observation n)) : SmtScript.Formula :=
  observations.map (lower base frame)

def ObservationsHold [Bootstrap Node] (rho : UnknownNatAssignment) (state : ModelState)
    (observations : List (Observation n)) : Prop :=
  forall observation, Membership.mem observations observation -> (observation.val.eval rho).Holds state

theorem observation_formula_length (base : Nat) (frame : Frame roots versions)
    (observations : List (Observation n)) :
    (observationFormula base frame observations).length = observations.length :=
  List.length_map (lower base frame)

theorem observation_formula_at (base : Nat) (frame : Frame roots versions)
    (observations : List (Observation n)) (index : Nat) :
    (observationFormula base frame observations)[index]? =
      observations[index]?.map (lower base frame) := List.getElem?_map

theorem list_correct [Bootstrap Node] (assignment : Assignment) (base : Nat)
    (rho : UnknownNatAssignment) (graph : Graph roots versions) (arrays : Roots roots)
    (submitted : Finset Nat) (frame : Frame roots versions) (state : ModelState)
    (source : SourceRep assignment base n rho) (rep : Rep assignment graph arrays submitted frame state)
    (observations : List (Observation n)) :
    SmtScript.Holds assignment (observationFormula base frame observations) <->
      ObservationsHold rho state observations := by
  simp only [observationFormula, SmtScript.Holds, List.forall_mem_map, ObservationsHold]
  exact forall_congr' fun observation => imp_congr_right fun _ =>
    observation_correct assignment base rho graph arrays submitted frame state source rep observation

def encode (base : Nat) (frame : Frame roots versions) (observations : List (Observation n)) :
    SmtScript.Formula :=
  encodeDomains base n ++ StateFrameEncoding.encode frame ++ observationFormula base frame observations

def render (base : Nat) (frame : Frame roots versions) (observations : List (Observation n)) : String :=
  SmtScript.render (encode base frame observations)

def encodeChecked (base : Nat) (frame : Frame roots versions) (trace : ModelInputSyntax.Trace n) :
    Except Rejection SmtScript.Formula :=
  (checkTrace trace).map (encode base frame)

def renderChecked (base : Nat) (frame : Frame roots versions) (trace : ModelInputSyntax.Trace n) :
    Except Rejection String :=
  (encodeChecked base frame trace).map SmtScript.render

theorem encode_split (assignment : Assignment) (base : Nat) (frame : Frame roots versions)
    (observations : List (Observation n)) :
    SmtScript.Holds assignment (encode base frame observations) <->
      SmtScript.Holds assignment (encodeDomains base n) /\
      SmtScript.Holds assignment (StateFrameEncoding.encode frame) /\
      SmtScript.Holds assignment (observationFormula base frame observations) := by
  simp [encode, SmtScript.Holds, or_imp, forall_and]

theorem formula_iff [Bootstrap Node] (assignment : Assignment) (base : Nat)
    (frame : Frame roots versions) (graph : Graph roots versions) (arrays : Roots roots)
    (network : Network) (submitted : Finset Nat) (observations : List (Observation n)) :
    SmtScript.Holds assignment (encode base frame observations) <->
      exists rho state, SourceRep assignment base n rho /\
        Rep assignment graph arrays submitted frame state /\ state.network = network /\
        ObservationsHold rho state observations := by
  rw [encode_split, formula_iff_source_rep,
    StateFrameEncoding.relative_realization assignment frame graph arrays network submitted]
  constructor
  next =>
    intro accepted
    cases accepted.1 with
    | intro rho source =>
      cases accepted.2.1 with
      | intro state spec =>
        refine Exists.intro rho (Exists.intro state
          (And.intro source (And.intro spec.1 (And.intro spec.2 ?_))))
        exact (list_correct assignment base rho graph arrays submitted frame state source spec.1
          observations).mp accepted.2.2
  next =>
    intro found
    cases found with
    | intro rho found =>
      cases found with
      | intro state spec =>
        refine And.intro (Exists.intro rho spec.1)
          (And.intro (Exists.intro state (And.intro spec.2.1 spec.2.2.1)) ?_)
        exact (list_correct assignment base rho graph arrays submitted frame state spec.1 spec.2.1
          observations).mpr spec.2.2.2

theorem text_iff [Bootstrap Node] (assignment : Assignment) (base : Nat)
    (frame : Frame roots versions) (graph : Graph roots versions) (arrays : Roots roots)
    (network : Network) (submitted : Finset Nat) (observations : List (Observation n)) :
    SmtScriptText.runText assignment (render base frame observations) = some true <->
      exists rho state, SourceRep assignment base n rho /\
        Rep assignment graph arrays submitted frame state /\ state.network = network /\
        ObservationsHold rho state observations :=
  (SmtScriptText.formula_text_iff assignment (encode base frame observations)).symm.trans
    (formula_iff assignment base frame graph arrays network submitted observations)

theorem observations_follows [Bootstrap Node] (rho : UnknownNatAssignment) (state : ModelState)
    (observations : List (Observation n)) :
    ModelTrace.ConcreteFollows state (ModelInputSyntax.evalTrace rho (observationTrace observations)) <->
      ObservationsHold rho state observations := by
  induction observations with
  | nil => simp [observationTrace, ModelInputSyntax.evalTrace, ModelTrace.ConcreteFollows,
      TraceValidation.follows, ObservationsHold]
  | cons head tail ih =>
    change ((head.val.eval rho).Holds state /\
      ModelTrace.ConcreteFollows state (ModelInputSyntax.evalTrace rho (observationTrace tail))) <-> _
    rw [ih]
    simp [ObservationsHold]

theorem checked_text_iff [Bootstrap Node] (assignment : Assignment) (base : Nat)
    (frame : Frame roots versions) (graph : Graph roots versions) (arrays : Roots roots)
    (network : Network) (submitted : Finset Nat) (trace : ModelInputSyntax.Trace n)
    (checked : List (Observation n)) (accepted : checkTrace trace = .ok checked) :
    renderChecked base frame trace = .ok (render base frame checked) /\
      (SmtScriptText.runText assignment (render base frame checked) = some true <->
        exists rho state, SourceRep assignment base n rho /\
          Rep assignment graph arrays submitted frame state /\ state.network = network /\
          ModelTrace.ConcreteFollows state (ModelInputSyntax.evalTrace rho trace)) := by
  constructor
  next =>
    rw [renderChecked, encodeChecked, accepted]
    rfl
  next =>
    rw [text_iff]
    apply exists_congr
    intro rho
    apply exists_congr
    intro state
    rw [<- check_trace_preserves trace checked accepted, observations_follows]

namespace Regression

def node : Node := Fin.mk 0 (by decide)

def dormantObservations : List (Observation 0) :=
  [Subtype.mk (.allocated node (.literal false)) trivial,
   Subtype.mk (.joined node (.literal true)) trivial,
   Subtype.mk (.role node .none) trivial,
   Subtype.mk (.currentTerm node (.literal 0)) trivial,
   Subtype.mk (.commitIndex node (.literal 0)) trivial,
   Subtype.mk (.logLength node (.literal 0)) trivial,
   Subtype.mk (.state (.preVoteStatus node .enabled)) trivial,
   Subtype.mk (.state (.membershipState node .active)) trivial,
   Subtype.mk (.state (.retirementIndex node none)) trivial,
   Subtype.mk (.state (.retirementCommittableIndex node none)) trivial,
   Subtype.mk (.state (.retiredCommittedIndex node none)) trivial,
   Subtype.mk (.state (.retirementCompleted node node (.literal true))) trivial]

def wrongFreshObservations : List (Observation 0) :=
  [Subtype.mk (.role node .leader) trivial,
   Subtype.mk (.currentTerm node (.literal 1)) trivial,
   Subtype.mk (.commitIndex node (.literal 1)) trivial,
   Subtype.mk (.logLength node (.literal 1)) trivial,
   Subtype.mk (.state (.membershipState node .retirementOrdered)) trivial,
   Subtype.mk (.state (.retirementIndex node (some (.literal 0)))) trivial,
   Subtype.mk (.state (.retirementCommittableIndex node (some (.literal 0)))) trivial,
   Subtype.mk (.state (.retiredCommittedIndex node (some (.literal 0)))) trivial]

def dormantAssignment : Assignment :=
  StateFrameEncoding.sample 0 0 32767 (fun _ => -1000000)

theorem dormant_negatives_and_absent_globals :
    dormantAssignment.constant .int 1 = -1000000 /\
    (encode 100 StateFrame.fixtureFrame dormantObservations).all (Term.eval dormantAssignment) = true /\
    wrongFreshObservations.all (fun observation =>
      !((lower 100 StateFrame.fixtureFrame observation).eval dormantAssignment)) = true := by
  decide +kernel

theorem dormant_relative_witness [Bootstrap Node] (graph : Graph 1 0) (arrays : Roots 1)
    (network : Network) (submitted : Finset Nat) :
    exists rho state, SourceRep dormantAssignment 100 0 rho /\
      Rep dormantAssignment graph arrays submitted StateFrame.fixtureFrame state /\
      state.network = network /\ ObservationsHold rho state dormantObservations := by
  apply (formula_iff dormantAssignment 100 StateFrame.fixtureFrame graph arrays network submitted
    dormantObservations).mp
  exact List.all_eq_true.mp dormant_negatives_and_absent_globals.2.1

def roles : List Role := [.none, .follower, .preVoteCandidate, .candidate, .leader]
def memberships : List MembershipState :=
  [.active, .retirementOrdered, .retirementSigned, .retirementCompleted, .retiredCommitted]

theorem all_role_membership_codes :
    roles.all (fun role => memberships.all (fun membership =>
      (observationFormula 100 StateFrame.fixtureFrame
        ([Subtype.mk (.role node role) trivial,
          Subtype.mk (.state (.membershipState node membership)) trivial] :
          List (Observation 0))).all (Term.eval
            (StateFrame.fixtureAssignment 1 0 0 role membership none none 0 0 0 true false)))) = true := by
  decide +kernel

def optionalObservations : List (Observation 0) :=
  [Subtype.mk (.state (.retirementIndex node none)) trivial,
   Subtype.mk (.state (.retirementIndex node (some (.literal 0)))) trivial]

theorem none_some_zero :
    (observationFormula 100 StateFrame.fixtureFrame optionalObservations).map (Term.eval
      (StateFrame.fixtureAssignment 1 0 0 .follower .active none none 0 0 0 true false)) =
        [true, false] /\
    (observationFormula 100 StateFrame.fixtureFrame optionalObservations).map (Term.eval
      (StateFrame.fixtureAssignment 1 0 0 .follower .active (some 0) none 0 0 0 true false)) =
        [false, true] := by
  decide +kernel

def sharedObservations : List (Observation 1) :=
  [Subtype.mk (.currentTerm node (.unknown 0)) trivial,
   Subtype.mk (.joined node (.isZero (.unknown 0))) trivial,
   Subtype.mk (.state (.retirementIndex node (some (.unknown 0)))) trivial,
   Subtype.mk (.currentTerm node (.unknown 0)) trivial,
   Subtype.mk (.logLength node (.literal 1000000)) trivial]

def sharedAssignment (value : Nat) : Assignment :=
  ScalarExtension.install
    (StateFrame.fixtureAssignment 1 (if value = 0 then 1 else 0) 0 .follower .active
      (some value) none value 1000000 0 true false)
    100 (fun _ : Fin 1 => (value : Int))

theorem shared_source_zero_and_two :
    ([0, 2] : List Nat).all (fun value =>
      (encode 100 StateFrame.fixtureFrame sharedObservations).all
        (Term.eval (sharedAssignment value))) = true := by
  decide +kernel

theorem shared_source_rep (value : Nat) :
    SourceRep (sharedAssignment value) 100 1 (fun _ => value) :=
  install_source_rep _ 100 1 (fun _ => value)

theorem checked_order_duplicates (first second : Observation n) :
    checkList [first.val, second.val, first.val] = .ok [first, second, first] /\
    checkTrace [.observation first.val, .observation second.val, .observation first.val] =
      .ok [first, second, first] :=
  And.intro (check_list_roundtrip [first, second, first]) (check_trace_roundtrip [first, second, first])

theorem rejects_unsupported (value : NatAtom n) (flag : BoolAtom n) (source destination : Node)
    (packet : Option (ModelInputSyntax.MessageSyntax n)) (summary : ModelInputSyntax.SummarySyntax n)
    (configurations : List (ModelInputSyntax.ConfigurationSyntax n)) :
    check (.submitted value flag) = .error .submitted /\
    check (.firstMessage source destination packet) = .error .firstMessage /\
    check (.messageSummary summary) = .error .messageSummary /\
    check (.queueLength destination value) = .error .queueLength /\
    check (.configurationSnapshot source configurations) = .error .configurationSnapshot :=
  And.intro rfl (And.intro rfl (And.intro rfl (And.intro rfl rfl)))

theorem rejects_actions (action : ModelInputSyntax.ActionSyntax n) (rest : ModelInputSyntax.Trace n) :
    checkTrace (.action action :: rest) = .error .action := rfl

theorem no_action_dropped :
    renderChecked 100 StateFrame.fixtureFrame
      ([.observation (.currentTerm node (.literal 0)), .action (.timeout node),
        .observation (.currentTerm node (.literal 0))] : ModelInputSyntax.Trace 0) =
      .error .action := rfl

theorem no_unsupported_dropped :
    renderChecked 100 StateFrame.fixtureFrame
      ([.observation (.currentTerm node (.literal 0)),
        .observation (.queueLength node (.literal 0))] : ModelInputSyntax.Trace 0) =
      .error .queueLength := rfl

def commits (node : Node) (first second : Nat) : List (Observation n) :=
  [Subtype.mk (.commitIndex node (.literal first)) trivial,
   Subtype.mk (.commitIndex node (.literal second)) trivial]

theorem adjacent_conflict [Bootstrap Node] (assignment : Assignment) (base : Nat)
    (frame : Frame roots versions) (graph : Graph roots versions) (arrays : Roots roots)
    (network : Network) (submitted : Finset Nat) (node : Node) (first second : Nat)
    (different : Not (first = second)) :
    Not (SmtScript.Holds assignment (encode base frame (commits (n := n) node first second))) := by
  intro accepted
  have found := (formula_iff assignment base frame graph arrays network submitted
    (commits (n := n) node first second)).mp accepted
  cases found with
  | intro rho found =>
    cases found with
    | intro state spec =>
      have one := spec.2.2.2 (Subtype.mk (.commitIndex node (.literal first)) trivial)
        (List.mem_cons_self)
      have two := spec.2.2.2 (Subtype.mk (.commitIndex node (.literal second)) trivial)
        (List.mem_cons_of_mem _ List.mem_cons_self)
      change (state.nodes node).commitIndex = first at one
      change (state.nodes node).commitIndex = second at two
      exact different (one.symm.trans two)

theorem empty_observations_keep_source_domains (assignment : Assignment)
    (negative : assignment.constant .int 102 < 0) :
    Not (SmtScript.Holds assignment
      (encode 100 StateFrame.fixtureFrame ([] : List (Observation 3)))) := by
  intro accepted
  exact negative_declared_rejected assignment 100 (2 : Fin 3) negative
    ((encode_split assignment 100 StateFrame.fixtureFrame []).mp accepted).1

theorem million_length_shape :
    lower 100 StateFrame.fixtureFrame
      (Subtype.mk (.logLength node (.literal 1000000) : ObservationSyntax 0) trivial) =
      .equal (effectiveInt StateFrame.fixtureFrame node { id := 2 } 0) (.integer 1000000) /\
    (sourceNat 100 (.literal 1000000 : NatAtom 0)).lower = .atom (.numeral 1000000) :=
  And.intro rfl rfl

end Regression

end CCFRaft.Sparse.FrameObservationEncoding

run_cmd do
  let mut checked := 0
  for (name, info) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.Sparse.FrameObservationEncoding).isPrefixOf name then
      match info with
      | .axiomInfo _ => throwError "explicit FrameObservationEncoding axiom: {name}"
      | _ =>
        checked := checked + 1
        for axiomName in (<- Lean.collectAxioms name) do
          unless axiomName == ``propext || axiomName == ``Classical.choice ||
              axiomName == ``Quot.sound do
            throwError "unexpected axiom in {name}: {axiomName}"
  Lean.logInfo m!"FrameObservationEncoding: {checked} declarations passed the transitive axiom gate."
