-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.Smt
import Sparse.QueueModel
import Sparse.IntervalReadback
import MachineGenerated.ModelProofs
import MachineGenerated.SymbolicModel

set_option autoImplicit false

/-!
Finite reference storage and relative initial-state realization. No action
emitter, source AST, queue completion, or submitted-set completion is defined.
The interpreted graph and Entry roots are supplied once, together with concrete
network and submitted-set witnesses. Log reconstruction is proof-only.
Canonical independent slots and coverage of every concrete state are not proved
here. Fixed roots and aliased scalar IDs can constrain the represented states.
-/

namespace CCFRaft.Sparse.StateFrame

open Smt (Ty Assignment Symbol)

structure ConstRef (ty : Ty) where
  id : Nat
  deriving DecidableEq

def ConstRef.eval {ty : Ty} (ref : ConstRef ty) (assignment : Assignment) : ty.denote :=
  assignment.constant ty ref.id

def ConstRef.symbol {ty : Ty} (ref : ConstRef ty) : Symbol :=
  .constant ty ref.id

structure LogRef (roots versions : Nat) where
  length : ConstRef .int
  address : IntervalReadback.Address roots versions

structure LocalRefs (roots versions : Nat) where
  role : ConstRef .int
  currentTerm : ConstRef .int
  log : LogRef roots versions
  commitIndex : ConstRef .int
  sentIndex : Vector (ConstRef .int) NODE_COUNT
  matchIndex : Vector (ConstRef .int) NODE_COUNT
  isNewFollower : ConstRef .bool
  votedFor : ConstRef .int
  votesGranted : ConstRef .nodes
  preVotesGranted : ConstRef .nodes
  membershipState : ConstRef .int
  retirementIndex : ConstRef .int
  retirementCommittableIndex : ConstRef .int
  retiredCommittedIndex : ConstRef .int

structure Frame (roots versions : Nat) where
  allocated : ConstRef .nodes
  locals : Vector (LocalRefs roots versions) NODE_COUNT
  hasJoined : ConstRef .nodes
  preVoteEnabled : Vector (ConstRef .bool) NODE_COUNT
  retirementCompleted : Vector (ConstRef .nodes) NODE_COUNT

abbrev ModelState := State Node Nat
abbrev Network := Node -> List (Message Node Nat)
abbrev Graph (roots versions : Nat) :=
  VersionedIntervals.Graph roots EntryValue.Entry versions
abbrev Roots (roots : Nat) :=
  VersionedIntervals.RootArrays roots EntryValue.Entry

variable {roots versions : Nat}

def LocalRefs.naturals (row : LocalRefs roots versions) : List (ConstRef .int) :=
  [row.currentTerm, row.log.length, row.commitIndex,
    row.retirementIndex, row.retirementCommittableIndex, row.retiredCommittedIndex] ++
    row.sentIndex.toList ++ row.matchIndex.toList

def LocalRefs.symbols (row : LocalRefs roots versions) : List Symbol :=
  [row.role.symbol, row.membershipState.symbol, row.votedFor.symbol,
    row.isNewFollower.symbol, row.votesGranted.symbol, row.preVotesGranted.symbol] ++
    row.naturals.map ConstRef.symbol

def Frame.symbols (frame : Frame roots versions) : List Symbol :=
  [frame.allocated.symbol, frame.hasJoined.symbol] ++
    frame.locals.toList.flatMap LocalRefs.symbols ++
    frame.preVoteEnabled.toList.map ConstRef.symbol ++
    frame.retirementCompleted.toList.map ConstRef.symbol

def WellScoped (scope : Finset Symbol) (frame : Frame roots versions) : Prop :=
  forall symbol, Membership.mem frame.symbols symbol -> Membership.mem scope symbol

def LocalDomains (assignment : Assignment) (row : LocalRefs roots versions) : Prop :=
  (0 <= row.role.eval assignment /\ row.role.eval assignment < 5) /\
  (0 <= row.membershipState.eval assignment /\ row.membershipState.eval assignment < 5) /\
  (0 <= row.votedFor.eval assignment /\ row.votedFor.eval assignment <= (NODE_COUNT : Int)) /\
  (forall ref, Membership.mem row.naturals ref -> 0 <= ref.eval assignment)

def allocatedNodes (assignment : Assignment) (frame : Frame roots versions) : Finset Node :=
  NodeSetCodec.decodeNodes (frame.allocated.eval assignment)

def Domains (assignment : Assignment) (frame : Frame roots versions) : Prop :=
  forall node : Node, Membership.mem (allocatedNodes assignment frame) node ->
    LocalDomains assignment frame.locals[node.val]

instance (scope : Finset Symbol) (frame : Frame roots versions) :
    Decidable (WellScoped scope frame) := by
  unfold WellScoped
  infer_instance

instance (assignment : Assignment) (row : LocalRefs roots versions) :
    Decidable (LocalDomains assignment row) := by
  unfold LocalDomains
  infer_instance

instance (assignment : Assignment) (frame : Frame roots versions) :
    Decidable (Domains assignment frame) := by
  unfold Domains
  infer_instance

def checkDomains (assignment : Assignment) (frame : Frame roots versions) : Bool :=
  decide (Domains assignment frame)

theorem check_domains_iff (assignment : Assignment) (frame : Frame roots versions) :
    checkDomains assignment frame = true <-> Domains assignment frame := by
  simp [checkDomains]

def roleCode (role : Role) : Int :=
  (SymbolicModel.roleEquiv.symm role).val

def membershipCode (membership : MembershipState) : Int :=
  (SymbolicModel.membershipEquiv.symm membership).val

def optionNatCode (value : Option Nat) : Int :=
  (value.map Nat.succ).getD 0

def optionNodeCode (value : Option Node) : Int :=
  optionNatCode (value.map Fin.val)

def decodeRole (code : Int) (valid : 0 <= code /\ code < 5) : Role :=
  SymbolicModel.roleEquiv (Fin.mk code.toNat (by omega))

def decodeMembership (code : Int) (valid : 0 <= code /\ code < 5) : MembershipState :=
  SymbolicModel.membershipEquiv (Fin.mk code.toNat (by omega))

def decodeOptionNat (code : Int) (_valid : 0 <= code) : Option Nat :=
  if code = 0 then none else some (code.toNat - 1)

def decodeOptionNode (code : Int) (valid : 0 <= code /\ code <= (NODE_COUNT : Int)) :
    Option Node :=
  if zero : code = 0 then none
  else some (Fin.mk (code.toNat - 1) (by omega))

-- Neither this list constructor nor decodeFrame is a runtime encoder operation.
noncomputable def decodeLog (assignment : Assignment) (graph : Graph roots versions)
    (arrays : Roots roots) (log : LogRef roots versions) : List ArrayLog.LogEntry :=
  ArrayLog.ArrayLog.decode
    { length := (log.length.eval assignment).toNat
      entries := fun index =>
        EntryValue.decodeEntry (IntervalReadback.actual graph arrays log.address index) }

theorem decode_log_length (assignment : Assignment) (graph : Graph roots versions)
    (arrays : Roots roots) (log : LogRef roots versions) :
    (decodeLog assignment graph arrays log).length = (log.length.eval assignment).toNat :=
  ArrayLog.decode_length _

noncomputable def decodeLocal (assignment : Assignment) (graph : Graph roots versions)
    (arrays : Roots roots) (row : LocalRefs roots versions)
    (valid : LocalDomains assignment row) : NodeState Node Nat where
  role := decodeRole (row.role.eval assignment) valid.1
  currentTerm := (row.currentTerm.eval assignment).toNat
  log := decodeLog assignment graph arrays row.log
  commitIndex := (row.commitIndex.eval assignment).toNat
  sentIndex := fun node => (row.sentIndex[node.val].eval assignment).toNat
  matchIndex := fun node => (row.matchIndex[node.val].eval assignment).toNat
  isNewFollower := row.isNewFollower.eval assignment
  votedFor := decodeOptionNode (row.votedFor.eval assignment) valid.2.2.1
  votesGranted := NodeSetCodec.decodeNodes (row.votesGranted.eval assignment)
  preVotesGranted := NodeSetCodec.decodeNodes (row.preVotesGranted.eval assignment)
  membershipState := decodeMembership (row.membershipState.eval assignment) valid.2.1
  retirementIndex := decodeOptionNat (row.retirementIndex.eval assignment)
    (valid.2.2.2 _ (by simp [LocalRefs.naturals]))
  retirementCommittableIndex := decodeOptionNat (row.retirementCommittableIndex.eval assignment)
    (valid.2.2.2 _ (by simp [LocalRefs.naturals]))
  retiredCommittedIndex := decodeOptionNat (row.retiredCommittedIndex.eval assignment)
    (valid.2.2.2 _ (by simp [LocalRefs.naturals]))

noncomputable def decodeFrame (assignment : Assignment) (graph : Graph roots versions)
    (arrays : Roots roots) (submitted : Finset Nat) (frame : Frame roots versions)
    (valid : Domains assignment frame) : ModelState where
  nodes := NodeStore.ofFinset (allocatedNodes assignment frame) fun node =>
    if present : Membership.mem (allocatedNodes assignment frame) node then
      decodeLocal assignment graph arrays frame.locals[node.val] (valid node present)
    else freshNodeState
  network := fun _ => []
  submittedTxIds := submitted
  hasJoined := NodeSetCodec.decodeNodes (frame.hasJoined.eval assignment)
  preVoteStatus := fun node =>
    if frame.preVoteEnabled[node.val].eval assignment then .enabled else .capable
  retirementCompleted := fun node =>
    NodeSetCodec.decodeNodes (frame.retirementCompleted[node.val].eval assignment)

theorem role_code_bounds (role : Role) : 0 <= roleCode role /\ roleCode role < 5 := by
  have bound := (SymbolicModel.roleEquiv.symm role).isLt
  dsimp [roleCode]
  omega

theorem membership_code_bounds (membership : MembershipState) :
    0 <= membershipCode membership /\ membershipCode membership < 5 := by
  have bound := (SymbolicModel.membershipEquiv.symm membership).isLt
  dsimp [membershipCode]
  omega

theorem option_nat_code_nonnegative (value : Option Nat) : 0 <= optionNatCode value := by
  exact Int.natCast_nonneg _

theorem option_node_code_bounds (value : Option Node) :
    0 <= optionNodeCode value /\ optionNodeCode value <= (NODE_COUNT : Int) := by
  cases value with
  | none => simp [optionNodeCode, optionNatCode]
  | some node =>
    have bound := node.isLt
    simp only [optionNodeCode, optionNatCode, Option.map_some, Option.getD_some]
    omega

@[simp] theorem role_code_decode (code : Int) (valid : 0 <= code /\ code < 5) :
    roleCode (decodeRole code valid) = code := by
  simp [roleCode, decodeRole, Int.toNat_of_nonneg valid.1]

@[simp] theorem membership_code_decode (code : Int) (valid : 0 <= code /\ code < 5) :
    membershipCode (decodeMembership code valid) = code := by
  simp [membershipCode, decodeMembership, Int.toNat_of_nonneg valid.1]

@[simp] theorem option_nat_code_decode (code : Int) (valid : 0 <= code) :
    optionNatCode (decodeOptionNat code valid) = code := by
  by_cases zero : code = 0
  next => simp [decodeOptionNat, zero, optionNatCode]
  next =>
    simp only [decodeOptionNat, if_neg zero, optionNatCode, Option.map_some,
      Option.getD_some]
    omega

@[simp] theorem option_node_code_decode (code : Int)
    (valid : 0 <= code /\ code <= (NODE_COUNT : Int)) :
    optionNodeCode (decodeOptionNode code valid) = code := by
  by_cases zero : code = 0
  next => simp [decodeOptionNode, zero, optionNodeCode, optionNatCode]
  next =>
    simp only [decodeOptionNode, dif_neg zero, optionNodeCode, optionNatCode,
      Option.map_some, Option.getD_some]
    omega

@[simp] theorem decode_role_code (role : Role) (valid) :
    decodeRole (roleCode role) valid = role := by
  simp [decodeRole, roleCode]

@[simp] theorem decode_membership_code (membership : MembershipState) (valid) :
    decodeMembership (membershipCode membership) valid = membership := by
  simp [decodeMembership, membershipCode]

@[simp] theorem decode_option_nat_code (value : Option Nat) (valid) :
    decodeOptionNat (optionNatCode value) valid = value := by
  cases value <;> simp [decodeOptionNat, optionNatCode]
  all_goals omega

@[simp] theorem decode_option_node_code (value : Option Node) (valid) :
    decodeOptionNode (optionNodeCode value) valid = value := by
  cases value <;> simp [decodeOptionNode, optionNodeCode, optionNatCode]
  all_goals omega

structure LocalRep (assignment : Assignment) (graph : Graph roots versions)
    (arrays : Roots roots) (row : LocalRefs roots versions) (state : NodeState Node Nat) : Prop where
  role : row.role.eval assignment = roleCode state.role
  currentTerm : row.currentTerm.eval assignment = (state.currentTerm : Int)
  logLength : row.log.length.eval assignment = (state.log.length : Int)
  log : state.log = decodeLog assignment graph arrays row.log
  commitIndex : row.commitIndex.eval assignment = (state.commitIndex : Int)
  sentIndex : forall node : Node, row.sentIndex[node.val].eval assignment = (state.sentIndex node : Int)
  matchIndex : forall node : Node, row.matchIndex[node.val].eval assignment = (state.matchIndex node : Int)
  isNewFollower : row.isNewFollower.eval assignment = state.isNewFollower
  votedFor : row.votedFor.eval assignment = optionNodeCode state.votedFor
  votesGranted : row.votesGranted.eval assignment = NodeSetCodec.encodeNodes state.votesGranted
  preVotesGranted : row.preVotesGranted.eval assignment = NodeSetCodec.encodeNodes state.preVotesGranted
  membershipState : row.membershipState.eval assignment = membershipCode state.membershipState
  retirementIndex : row.retirementIndex.eval assignment = optionNatCode state.retirementIndex
  retirementCommittableIndex :
    row.retirementCommittableIndex.eval assignment = optionNatCode state.retirementCommittableIndex
  retiredCommittedIndex :
    row.retiredCommittedIndex.eval assignment = optionNatCode state.retiredCommittedIndex

theorem vector_nonnegative {count : Nat} (values : Vector (ConstRef .int) count)
    (assignment : Assignment)
    (nonnegative : forall index : Fin count, 0 <= values[index.val].eval assignment) :
    forall ref, Membership.mem values.toList ref -> 0 <= ref.eval assignment := by
  intro ref member
  cases List.mem_iff_getElem.mp member with
  | intro index witness =>
    cases witness with
    | intro bound equal =>
      have bound' : index < count := by simpa using bound
      have result := nonnegative (Fin.mk index bound')
      simpa only [<- Vector.getElem_toList bound, equal] using result

theorem LocalRep.domains {assignment : Assignment} {graph : Graph roots versions}
    {arrays : Roots roots} {row : LocalRefs roots versions} {state : NodeState Node Nat}
    (rep : LocalRep assignment graph arrays row state) : LocalDomains assignment row := by
  refine And.intro ?_ (And.intro ?_ (And.intro ?_ ?_))
  next => rw [rep.role]; exact role_code_bounds _
  next => rw [rep.membershipState]; exact membership_code_bounds _
  next => rw [rep.votedFor]; exact option_node_code_bounds _
  next =>
    intro ref member
    simp only [LocalRefs.naturals, List.mem_append, List.mem_cons, List.not_mem_nil,
      or_false] at member
    rcases member with ((rfl | rfl | rfl | rfl | rfl | rfl) | member) | member
    next => rw [rep.currentTerm]; exact Int.natCast_nonneg _
    next => rw [rep.logLength]; exact Int.natCast_nonneg _
    next => rw [rep.commitIndex]; exact Int.natCast_nonneg _
    next => rw [rep.retirementIndex]; exact option_nat_code_nonnegative _
    next => rw [rep.retirementCommittableIndex]; exact option_nat_code_nonnegative _
    next => rw [rep.retiredCommittedIndex]; exact option_nat_code_nonnegative _
    next =>
      exact vector_nonnegative row.sentIndex assignment
        (fun node => by rw [rep.sentIndex]; exact Int.natCast_nonneg _) ref member
    next =>
      exact vector_nonnegative row.matchIndex assignment
        (fun node => by rw [rep.matchIndex]; exact Int.natCast_nonneg _) ref member

theorem vector_member {A : Type} {count : Nat} (values : Vector A count) (index : Fin count) :
    Membership.mem values.toList values[index.val] := by
  simp

theorem decode_local_rep (assignment : Assignment) (graph : Graph roots versions)
    (arrays : Roots roots) (row : LocalRefs roots versions) (valid : LocalDomains assignment row) :
    LocalRep assignment graph arrays row (decodeLocal assignment graph arrays row valid) := by
  constructor
  all_goals try (simp [decodeLocal, decode_log_length])
  all_goals try (exact valid.2.2.2 _ (by simp [LocalRefs.naturals]))
  case sentIndex =>
    intro node
    apply valid.2.2.2
    simp [LocalRefs.naturals, vector_member row.sentIndex node]
  case matchIndex =>
    intro node
    apply valid.2.2.2
    simp [LocalRefs.naturals, vector_member row.matchIndex node]

theorem LocalRep.eq_decode {assignment : Assignment} {graph : Graph roots versions}
    {arrays : Roots roots} {row : LocalRefs roots versions} {state : NodeState Node Nat}
    (rep : LocalRep assignment graph arrays row state) :
    state = decodeLocal assignment graph arrays row rep.domains := by
  cases state
  simp only [decodeLocal, NodeState.mk.injEq]
  refine And.intro ?_ (And.intro ?_ (And.intro rep.log (And.intro ?_
    (And.intro ?_ (And.intro ?_ (And.intro rep.isNewFollower.symm (And.intro ?_
      (And.intro ?_ (And.intro ?_ (And.intro ?_ (And.intro ?_ (And.intro ?_ ?_))))))))))))
  all_goals first
    | simp [rep.role]
    | simp [rep.currentTerm]
    | simp [rep.commitIndex]
    | (funext node; simp [rep.sentIndex])
    | (funext node; simp [rep.matchIndex])
    | simp [rep.votedFor]
    | simp [rep.votesGranted]
    | simp [rep.preVotesGranted]
    | simp [rep.membershipState]
    | simp [rep.retirementIndex]
    | simp [rep.retirementCommittableIndex]
    | simp [rep.retiredCommittedIndex]

structure Rep (assignment : Assignment) (graph : Graph roots versions) (arrays : Roots roots)
    (submitted : Finset Nat) (frame : Frame roots versions) (state : ModelState) : Prop where
  allocation : forall node, state.allocated node <-> Membership.mem (allocatedNodes assignment frame) node
  locals : forall node, state.allocated node ->
    LocalRep assignment graph arrays frame.locals[node.val] (state.nodes node)
  joined : state.hasJoined = NodeSetCodec.decodeNodes (frame.hasJoined.eval assignment)
  preVoteStatus : forall node, state.preVoteStatus node =
    if frame.preVoteEnabled[node.val].eval assignment then .enabled else .capable
  retirementCompleted : forall node, state.retirementCompleted node =
    NodeSetCodec.decodeNodes (frame.retirementCompleted[node.val].eval assignment)
  submittedTxIds : state.submittedTxIds = submitted

theorem Rep.domains {assignment : Assignment} {graph : Graph roots versions}
    {arrays : Roots roots} {submitted : Finset Nat} {frame : Frame roots versions} {state : ModelState}
    (rep : Rep assignment graph arrays submitted frame state) : Domains assignment frame :=
  fun node member => (rep.locals node ((rep.allocation node).mpr member)).domains

theorem Rep.with_network {assignment : Assignment} {graph : Graph roots versions}
    {arrays : Roots roots} {submitted : Finset Nat} {frame : Frame roots versions} {state : ModelState}
    (rep : Rep assignment graph arrays submitted frame state) (network : Network) :
    Rep assignment graph arrays submitted frame { state with network } :=
  { allocation := rep.allocation, locals := rep.locals, joined := rep.joined
    preVoteStatus := rep.preVoteStatus, retirementCompleted := rep.retirementCompleted
    submittedTxIds := rep.submittedTxIds }

theorem decode_allocated (assignment : Assignment) (graph : Graph roots versions)
    (arrays : Roots roots) (submitted : Finset Nat) (frame : Frame roots versions)
    (valid : Domains assignment frame) (node : Node) :
    (decodeFrame assignment graph arrays submitted frame valid).allocated node <->
      Membership.mem (allocatedNodes assignment frame) node := by
  by_cases member : Membership.mem (allocatedNodes assignment frame) node
  next => simp [decodeFrame, State.allocated, NodeStore.allocated, member]
  next => simp [decodeFrame, State.allocated, NodeStore.allocated, member]

theorem decode_rep (assignment : Assignment) (graph : Graph roots versions)
    (arrays : Roots roots) (submitted : Finset Nat) (frame : Frame roots versions)
    (valid : Domains assignment frame) :
    Rep assignment graph arrays submitted frame
      (decodeFrame assignment graph arrays submitted frame valid) := by
  refine { allocation := decode_allocated assignment graph arrays submitted frame valid
           locals := ?_, joined := rfl, preVoteStatus := fun _ => rfl
           retirementCompleted := fun _ => rfl, submittedTxIds := rfl }
  intro node present
  have member := (decode_allocated assignment graph arrays submitted frame valid node).mp present
  simpa [decodeFrame, NodeStore.get_ofFinset, member] using
    decode_local_rep assignment graph arrays frame.locals[node.val] (valid node member)

theorem domains_iff_realizable (assignment : Assignment) (graph : Graph roots versions)
    (arrays : Roots roots) (network : Network) (submitted : Finset Nat) (frame : Frame roots versions) :
    Domains assignment frame <->
      exists state, Rep assignment graph arrays submitted frame state /\ state.network = network := by
  constructor
  next =>
    intro valid
    let decoded := decodeFrame assignment graph arrays submitted frame valid
    refine Exists.intro { decoded with network } (And.intro ?_ rfl)
    exact (decode_rep assignment graph arrays submitted frame valid).with_network network
  next =>
    intro witness
    cases witness with
    | intro state evidence => exact evidence.1.domains

theorem rep_unique_frame {assignment : Assignment} {graph : Graph roots versions}
    {arrays : Roots roots} {submitted : Finset Nat} {frame : Frame roots versions}
    {left right : ModelState}
    (leftRep : Rep assignment graph arrays submitted frame left)
    (rightRep : Rep assignment graph arrays submitted frame right) :
    QueueModel.frame left = QueueModel.frame right := by
  have entries : left.nodes.entries = right.nodes.entries := by
    apply Finmap.ext_lookup
    intro node
    change left.nodes.node? node = right.nodes.node? node
    have allocation := (leftRep.allocation node).trans (rightRep.allocation node).symm
    cases hl : left.nodes.node? node <;> cases hr : right.nodes.node? node
    all_goals try rfl
    all_goals try (simp [State.allocated, NodeStore.allocated, hl, hr] at allocation)
    have present : left.allocated node := by simp [State.allocated, NodeStore.allocated, hl]
    have presentRight : right.allocated node := by simp [State.allocated, NodeStore.allocated, hr]
    have same := (leftRep.locals node present).eq_decode.trans
      (rightRep.locals node presentRight).eq_decode.symm
    simpa [NodeStore.get, hl, hr] using congrArg some same
  have nodes : left.nodes = right.nodes := congrArg NodeStore.mk entries
  have transactions := leftRep.submittedTxIds.trans rightRep.submittedTxIds.symm
  have joined := leftRep.joined.trans rightRep.joined.symm
  have preVote := funext fun node =>
    (leftRep.preVoteStatus node).trans (rightRep.preVoteStatus node).symm
  have retired := funext fun node =>
    (leftRep.retirementCompleted node).trans (rightRep.retirementCompleted node).symm
  cases left
  cases right
  simp only [QueueModel.frame, State.mk.injEq]
  exact And.intro nodes (And.intro True.intro (And.intro transactions
    (And.intro joined (And.intro preVote retired))))

theorem rep_unique_with_network {assignment : Assignment} {graph : Graph roots versions}
    {arrays : Roots roots} {submitted : Finset Nat} {frame : Frame roots versions}
    {left right : ModelState} {network : Network}
    (leftRep : Rep assignment graph arrays submitted frame left)
    (rightRep : Rep assignment graph arrays submitted frame right)
    (leftNetwork : left.network = network) (rightNetwork : right.network = network) :
    left = right := by
  have same := rep_unique_frame leftRep rightRep
  have networkEq := leftNetwork.trans rightNetwork.symm
  cases left
  cases right
  simp only [QueueModel.frame, State.mk.injEq, true_and] at same
  simp only [State.mk.injEq]
  exact And.intro same.1 (And.intro networkEq same.2)

def Agree (symbols : List Symbol) (left right : Assignment) : Prop :=
  forall ty id, Membership.mem symbols (.constant ty id) ->
    left.constant ty id = right.constant ty id

theorem Agree.symm {symbols : List Symbol} {left right : Assignment}
    (agree : Agree symbols left right) : Agree symbols right left :=
  fun ty id member => (agree ty id member).symm

theorem Agree.eval {symbols : List Symbol} {left right : Assignment}
    (agree : Agree symbols left right) {ty : Ty} (ref : ConstRef ty)
    (member : Membership.mem symbols ref.symbol) : ref.eval left = ref.eval right :=
  agree ty ref.id member

theorem natural_symbol_member (row : LocalRefs roots versions) (ref : ConstRef .int)
    (member : Membership.mem row.naturals ref) : Membership.mem row.symbols ref.symbol :=
  List.mem_append_right _ (List.mem_map.mpr (Exists.intro ref (And.intro member rfl)))

theorem local_domains_congr {left right : Assignment} (row : LocalRefs roots versions)
    (agree : Agree row.symbols left right) :
    LocalDomains left row <-> LocalDomains right row := by
  have role := agree.eval row.role (by simp [LocalRefs.symbols])
  have membership := agree.eval row.membershipState (by simp [LocalRefs.symbols])
  have voted := agree.eval row.votedFor (by simp [LocalRefs.symbols])
  have naturals : (forall ref, Membership.mem row.naturals ref -> 0 <= ref.eval left) <->
      (forall ref, Membership.mem row.naturals ref -> 0 <= ref.eval right) :=
    forall_congr' fun ref => imp_congr_right fun member =>
      by rw [agree.eval ref (natural_symbol_member row ref member)]
  exact and_congr (by rw [role]) (and_congr (by rw [membership])
    (and_congr (by rw [voted]) naturals))

theorem local_rep_transfer {left right : Assignment} {graph : Graph roots versions}
    {arrays : Roots roots} {row : LocalRefs roots versions} {state : NodeState Node Nat}
    (agree : Agree row.symbols left right) (rep : LocalRep left graph arrays row state) :
    LocalRep right graph arrays row state := by
  have same {ty : Ty} (ref : ConstRef ty) (member : Membership.mem row.symbols ref.symbol) :=
    (agree.eval ref member).symm
  have natSame (ref : ConstRef .int) (member : Membership.mem row.naturals ref) :=
    same ref (natural_symbol_member row ref member)
  constructor
  next => rw [same row.role (by simp [LocalRefs.symbols])]; exact rep.role
  next => rw [natSame row.currentTerm (by simp [LocalRefs.naturals])]; exact rep.currentTerm
  next => rw [natSame row.log.length (by simp [LocalRefs.naturals])]; exact rep.logLength
  next =>
    simpa only [decodeLog, natSame row.log.length (by simp [LocalRefs.naturals])] using rep.log
  next => rw [natSame row.commitIndex (by simp [LocalRefs.naturals])]; exact rep.commitIndex
  next =>
    intro node
    rw [natSame row.sentIndex[node.val] (by simp [LocalRefs.naturals, vector_member row.sentIndex node])]
    exact rep.sentIndex node
  next =>
    intro node
    rw [natSame row.matchIndex[node.val] (by simp [LocalRefs.naturals, vector_member row.matchIndex node])]
    exact rep.matchIndex node
  next => rw [same row.isNewFollower (by simp [LocalRefs.symbols])]; exact rep.isNewFollower
  next => rw [same row.votedFor (by simp [LocalRefs.symbols])]; exact rep.votedFor
  next => rw [same row.votesGranted (by simp [LocalRefs.symbols])]; exact rep.votesGranted
  next => rw [same row.preVotesGranted (by simp [LocalRefs.symbols])]; exact rep.preVotesGranted
  next => rw [same row.membershipState (by simp [LocalRefs.symbols])]; exact rep.membershipState
  next => rw [natSame row.retirementIndex (by simp [LocalRefs.naturals])]; exact rep.retirementIndex
  next =>
    rw [natSame row.retirementCommittableIndex (by simp [LocalRefs.naturals])]
    exact rep.retirementCommittableIndex
  next =>
    rw [natSame row.retiredCommittedIndex (by simp [LocalRefs.naturals])]
    exact rep.retiredCommittedIndex

theorem frame_local_symbols (frame : Frame roots versions) (node : Node)
    (symbol : Symbol) (member : Membership.mem frame.locals[node.val].symbols symbol) :
    Membership.mem frame.symbols symbol := by
  have localMember : Membership.mem (frame.locals.toList.flatMap LocalRefs.symbols) symbol :=
    List.mem_flatMap.mpr (Exists.intro frame.locals[node.val]
      (And.intro (vector_member frame.locals node) member))
  simp [Frame.symbols, localMember]

theorem frame_prevote_symbol (frame : Frame roots versions) (node : Node) :
    Membership.mem frame.symbols frame.preVoteEnabled[node.val].symbol := by
  have member := List.mem_map.mpr (Exists.intro frame.preVoteEnabled[node.val]
    (And.intro (vector_member frame.preVoteEnabled node) (Eq.refl frame.preVoteEnabled[node.val].symbol)))
  simp [Frame.symbols, member]

theorem frame_retired_symbol (frame : Frame roots versions) (node : Node) :
    Membership.mem frame.symbols frame.retirementCompleted[node.val].symbol := by
  have member := List.mem_map.mpr (Exists.intro frame.retirementCompleted[node.val]
    (And.intro (vector_member frame.retirementCompleted node)
      (Eq.refl frame.retirementCompleted[node.val].symbol)))
  simp [Frame.symbols, member]

theorem Agree.local {left right : Assignment} {frame : Frame roots versions}
    (agree : Agree frame.symbols left right) (node : Node) :
    Agree frame.locals[node.val].symbols left right :=
  fun ty id member => agree ty id (frame_local_symbols frame node _ member)

theorem Agree.allocated {left right : Assignment} {frame : Frame roots versions}
    (agree : Agree frame.symbols left right) :
    allocatedNodes left frame = allocatedNodes right frame :=
  congrArg NodeSetCodec.decodeNodes (agree.eval frame.allocated (by simp [Frame.symbols]))

theorem domains_congr {left right : Assignment} (frame : Frame roots versions)
    (agree : Agree frame.symbols left right) :
    Domains left frame <-> Domains right frame := by
  apply forall_congr'
  intro node
  exact imp_congr (by rw [agree.allocated]) (local_domains_congr _ (agree.local node))

theorem rep_transfer {left right : Assignment} {graph : Graph roots versions} {arrays : Roots roots}
    {submitted : Finset Nat} {frame : Frame roots versions} {state : ModelState}
    (agree : Agree frame.symbols left right) (rep : Rep left graph arrays submitted frame state) :
    Rep right graph arrays submitted frame state := by
  refine { allocation := ?_, locals := ?_, joined := ?_, preVoteStatus := ?_
           retirementCompleted := ?_, submittedTxIds := rep.submittedTxIds }
  next => intro node; rw [<- agree.allocated]; exact rep.allocation node
  next => intro node present; exact local_rep_transfer (agree.local node) (rep.locals node present)
  next => rw [<- agree.eval frame.hasJoined (by simp [Frame.symbols])]; exact rep.joined
  next =>
    intro node
    rw [<- agree.eval frame.preVoteEnabled[node.val] (frame_prevote_symbol frame node)]
    exact rep.preVoteStatus node
  next =>
    intro node
    rw [<- agree.eval frame.retirementCompleted[node.val] (frame_retired_symbol frame node)]
    exact rep.retirementCompleted node

theorem rep_congr {left right : Assignment} (graph : Graph roots versions) (arrays : Roots roots)
    (submitted : Finset Nat) (frame : Frame roots versions) (state : ModelState)
    (agree : Agree frame.symbols left right) :
    Rep left graph arrays submitted frame state <-> Rep right graph arrays submitted frame state :=
  Iff.intro (rep_transfer agree) (rep_transfer agree.symm)

theorem decode_scope_locality {left right : Assignment} (graph : Graph roots versions)
    (arrays : Roots roots) (submitted : Finset Nat) (frame : Frame roots versions)
    (agree : Agree frame.symbols left right) (leftValid : Domains left frame)
    (rightValid : Domains right frame) :
    decodeFrame left graph arrays submitted frame leftValid =
      decodeFrame right graph arrays submitted frame rightValid :=
  rep_unique_with_network (decode_rep left graph arrays submitted frame leftValid)
    (rep_transfer agree.symm (decode_rep right graph arrays submitted frame rightValid)) rfl rfl

def checkFrame (scope : Finset Symbol) (assignment : Assignment) (frame : Frame roots versions) :
    Bool :=
  decide (WellScoped scope frame) && checkDomains assignment frame

theorem check_frame_iff (scope : Finset Symbol) (assignment : Assignment)
    (frame : Frame roots versions) :
    checkFrame scope assignment frame = true <-> WellScoped scope frame /\ Domains assignment frame := by
  simp [checkFrame, check_domains_iff]

theorem checked_realization_iff (scope : Finset Symbol) (assignment : Assignment)
    (graph : Graph roots versions) (arrays : Roots roots) (network : Network) (submitted : Finset Nat)
    (frame : Frame roots versions) :
    checkFrame scope assignment frame = true <->
      WellScoped scope frame /\
        exists state, Rep assignment graph arrays submitted frame state /\ state.network = network := by
  rw [check_frame_iff, domains_iff_realizable assignment graph arrays network submitted frame]

theorem scope_includes_unallocated_rows (scope : Finset Symbol) (frame : Frame roots versions)
    (scopeValid : WellScoped scope frame) (node : Node) (symbol : Symbol)
    (member : Membership.mem frame.locals[node.val].symbols symbol) :
    Membership.mem scope symbol :=
  scopeValid symbol (frame_local_symbols frame node symbol member)

theorem empty_allocation_domains (assignment : Assignment) (frame : Frame roots versions)
    (empty : allocatedNodes assignment frame = {}) : Domains assignment frame := by
  simp [Domains, empty]

theorem negative_active_term_rejected (assignment : Assignment) (frame : Frame roots versions)
    (node : Node) (present : Membership.mem (allocatedNodes assignment frame) node)
    (negative : frame.locals[node.val].currentTerm.eval assignment < 0) :
    Not (Domains assignment frame) := by
  intro valid
  have nonnegative := (valid node present).2.2.2 frame.locals[node.val].currentTerm
    (by simp [LocalRefs.naturals])
  exact (not_le_of_gt negative) nonnegative

theorem negative_active_option_rejected (assignment : Assignment) (frame : Frame roots versions)
    (node : Node) (present : Membership.mem (allocatedNodes assignment frame) node)
    (negative : frame.locals[node.val].retirementIndex.eval assignment < 0) :
    Not (Domains assignment frame) := by
  intro valid
  have nonnegative := (valid node present).2.2.2 frame.locals[node.val].retirementIndex
    (by simp [LocalRefs.naturals])
  exact (not_le_of_gt negative) nonnegative

theorem absent_local_fresh (assignment : Assignment) (graph : Graph roots versions)
    (arrays : Roots roots) (submitted : Finset Nat) (frame : Frame roots versions)
    (valid : Domains assignment frame) (node : Node)
    (absent : Not (Membership.mem (allocatedNodes assignment frame) node)) :
    (decodeFrame assignment graph arrays submitted frame valid).nodes node = freshNodeState := by
  simp [decodeFrame, NodeStore.get_ofFinset, absent]

theorem local_symbol_occurrences (row : LocalRefs roots versions) : row.symbols.length = 42 := by
  simp [LocalRefs.symbols, LocalRefs.naturals, NODE_COUNT]

-- Counts reference occurrences. Aliased IDs need not give 662 distinct symbols.
theorem frame_symbol_occurrences (frame : Frame roots versions) : frame.symbols.length = 662 := by
  simp [Frame.symbols, List.length_flatMap, local_symbol_occurrences, NODE_COUNT]

theorem option_zero_codes :
    optionNatCode none = 0 /\ optionNatCode (some 0) = 1 := by decide

theorem voted_for_endpoints :
    optionNodeCode (some (Fin.mk 0 (by decide))) = 1 /\
      optionNodeCode (some (Fin.mk 14 (by decide))) = 15 := by decide

def fixtureRow : LocalRefs 1 0 where
  role := { id := 0 }
  currentTerm := { id := 1 }
  log := { length := { id := 2 }, address := .root (Fin.mk 0 (by decide)) }
  commitIndex := { id := 3 }
  sentIndex := Vector.replicate NODE_COUNT { id := 7 }
  matchIndex := Vector.replicate NODE_COUNT { id := 7 }
  isNewFollower := { id := 0 }
  votedFor := { id := 6 }
  votesGranted := { id := 2 }
  preVotesGranted := { id := 2 }
  membershipState := { id := 5 }
  retirementIndex := { id := 4 }
  retirementCommittableIndex := { id := 4 }
  retiredCommittedIndex := { id := 4 }

def fixtureFrame : Frame 1 0 where
  allocated := { id := 0 }
  locals := Vector.replicate NODE_COUNT fixtureRow
  hasJoined := { id := 1 }
  preVoteEnabled := Vector.replicate NODE_COUNT { id := 1 }
  retirementCompleted := Vector.replicate NODE_COUNT { id := 3 }

def fixtureDefault : (ty : Ty) -> ty.denote
  | .bool => false
  | .int => 0
  | .nodes => 0
  | .content => .signature
  | .entry => { term := 0, content := .signature }

def fixtureAssignment (allocated joined completed : BitVec NODE_COUNT) (role : Role)
    (membership : MembershipState) (retirement : Option Nat) (votedFor : Option Node)
    (term length commit : Nat) (newFollower preVote : Bool) : Assignment where
  constant := fun ty id => match ty with
    | .int => match id with
      | 0 => roleCode role
      | 1 => term
      | 2 => length
      | 3 => commit
      | 4 => optionNatCode retirement
      | 5 => membershipCode membership
      | 6 => optionNodeCode votedFor
      | _ => 0
    | .bool => if id = 0 then newFollower else preVote
    | .nodes => if id = 0 then allocated else if id = 1 then joined else completed
    | .content => .signature
    | .entry => { term := 0, content := .signature }
  unary := fun _ result _ _ => fixtureDefault result

theorem fixture_domains (allocated joined completed : BitVec NODE_COUNT) (role : Role)
    (membership : MembershipState) (retirement : Option Nat) (votedFor : Option Node)
    (term length commit : Nat) (newFollower preVote : Bool) :
    Domains (fixtureAssignment allocated joined completed role membership retirement votedFor
      term length commit newFollower preVote) fixtureFrame := by
  intro node _
  simp [LocalDomains, fixtureFrame, fixtureRow, LocalRefs.naturals, ConstRef.eval,
    fixtureAssignment, role_code_bounds, membership_code_bounds, option_node_code_bounds,
    option_nat_code_nonnegative]

theorem arbitrary_root_fixture (allocated joined completed : BitVec NODE_COUNT) (role : Role)
    (membership : MembershipState) (retirement : Option Nat) (votedFor : Option Node)
    (term length commit : Nat) (newFollower preVote : Bool) (arrays : Roots 1)
    (network : Network) (submitted : Finset Nat) :
    exists state,
      Rep (fixtureAssignment allocated joined completed role membership retirement votedFor
        term length commit newFollower preVote) .empty arrays submitted fixtureFrame state /\
      state.network = network :=
  (domains_iff_realizable _ _ _ _ _ _).mp
    (fixture_domains allocated joined completed role membership retirement votedFor
      term length commit newFollower preVote)

end CCFRaft.Sparse.StateFrame

run_cmd do
  let mut checked := 0
  for (name, info) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.Sparse.StateFrame).isPrefixOf name then
      match info with
      | .axiomInfo _ => throwError "explicit StateFrame axiom: {name}"
      | _ =>
        checked := checked + 1
        for axiomName in (<- Lean.collectAxioms name) do
          unless axiomName == ``propext || axiomName == ``Classical.choice ||
              axiomName == ``Quot.sound do
            throwError "unexpected axiom in {name}: {axiomName}"
  Lean.logInfo m!"StateFrame: {checked} declarations passed the allowed-axiom gate."
