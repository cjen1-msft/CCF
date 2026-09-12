-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeAllocation
import Sparse.NativeArrayAllocation
import Sparse.NativeNodeRowWritesEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def allocationValue {width : PNat} (before : Encoding width) (node : Fin width)
    (enabled : Expr .bool) : Expr (.array .int .bool) :=
  .store (.free (.array .int .bool) before.allocated) (.integer node.val)
    (.or (allocated before.toColumns node.val) enabled)

def allocateNodeColumns (before : Columns) (base : Nat) : Columns :=
  { nodeRowWriteColumns before base with allocated := base + 16 }

def allocateNodeClauses {width : PNat} (before : Encoding width) (node : Fin width)
    (enabled : Expr .bool) : List (Expr .bool) :=
  definitionClauses
      (nodeRowWriteDefinitions before.toColumns node
        (nodeRowSnapshot before.toColumns node))
      before.next ++
    [Term.equal (.free (.array .int .bool) (before.next + 16))
      (allocationValue before node enabled)]

structure AllocateNodeResult {width : PNat} (node : Fin width) (enabled : Expr .bool)
    (before after : Encoding width) : Prop where
  enabledBounded : enabled.symbols.all (fun symbol => symbol.2 < before.next) = true
  next : after.next = before.next + 17
  sameBootstrap : after.bootstrap = before.bootstrap
  columns : after.toColumns = allocateNodeColumns before.toColumns before.next
  clauses : after.assertions.toList =
    before.assertions.toList ++ allocateNodeClauses before node enabled

theorem read_masked {sort : Ty} (assignment : Assignment) (columns newColumns : Columns)
    (column node : Nat) (default : Expr sort) (keep : Nat -> Bool)
    (allocation : forall peer,
      (allocated newColumns peer : Expr .bool).eval assignment Locals.empty =
        ((allocated columns peer : Expr .bool).eval assignment Locals.empty && keep peer)) :
    (read newColumns column node default).eval assignment Locals.empty =
      if keep node then (read columns column node default).eval assignment Locals.empty
      else default.eval assignment Locals.empty := by
  have allocatedSame := allocation node
  cases kept : keep node <;>
    simp [read, allocatedSame, kept, Term.eval]

theorem peer_index_masked (assignment : Assignment) (columns newColumns : Columns)
    (column node : Nat) (peer : Expr .int) (keep : Nat -> Bool)
    (allocation : forall candidate,
      (allocated newColumns candidate : Expr .bool).eval assignment Locals.empty =
        ((allocated columns candidate : Expr .bool).eval assignment Locals.empty &&
          keep candidate)) :
    (peerIndex newColumns column node peer).eval assignment Locals.empty =
      if keep node then (peerIndex columns column node peer).eval assignment Locals.empty
      else 0 := by
  have allocatedSame := allocation node
  cases kept : keep node <;>
    simp [peerIndex, allocatedSame, kept, Term.eval]

theorem node_columns_rep_masked {width : PNat} (assignment : Assignment)
    (columns : Columns) (newAllocated : Nat)
    (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat)
    (keep : Nat -> Bool) (rep : NodeColumnsRep assignment columns arrays)
    (allocation : forall peer : Nat,
      (allocated { columns with allocated := newAllocated } peer : Expr .bool).eval
          assignment Locals.empty =
        ((allocated columns peer : Expr .bool).eval assignment Locals.empty && keep peer)) :
    NodeColumnsRep assignment { columns with allocated := newAllocated }
      (fun peer => if keep peer.val then arrays peer else none) := by
  let newColumns := { columns with allocated := newAllocated }
  have readSame {sort : Ty} (column : Nat) (peer : Fin width) (default : Expr sort) :
      (read newColumns column peer.val default).eval assignment Locals.empty =
        if keep peer.val then (read columns column peer.val default).eval assignment Locals.empty
        else default.eval assignment Locals.empty :=
    read_masked assignment columns newColumns column peer.val default
      keep (by simpa [newColumns] using allocation)
  have peerSame (column : Nat) (node peer : Fin width) :
      (peerIndex newColumns column node.val (.integer peer.val)).eval
          assignment Locals.empty =
        if keep node.val then
          (peerIndex columns column node.val (.integer peer.val)).eval assignment Locals.empty
        else 0 :=
    peer_index_masked assignment columns newColumns column node.val (.integer peer.val)
      keep (by simpa [newColumns] using allocation)
  constructor
  · intro peer
    rw [show (allocated newColumns peer.val : Expr .bool).eval assignment Locals.empty =
      ((allocated columns peer.val : Expr .bool).eval assignment Locals.empty &&
        keep peer.val) by simpa [newColumns] using allocation peer.val, rep.allocated peer]
    cases keep peer.val <;> simp
  · intro peer
    rw [readSame columns.role peer (.integer 0)]
    cases kept : keep peer.val
    · simp [kept, NativeArrayCheckQuorum.get, NativeArrayCheckQuorum.Local.fresh,
        NativeArrayCheckQuorum.Local.ofModel, freshNodeState, roleCode, Term.eval]
    · simpa [kept, NativeArrayCheckQuorum.get] using rep.role peer
  · intro peer
    rw [readSame columns.newFollower peer (.boolean true)]
    cases kept : keep peer.val
    · simp [kept, NativeArrayCheckQuorum.get, NativeArrayCheckQuorum.Local.fresh,
        NativeArrayCheckQuorum.Local.ofModel, freshNodeState, Term.eval]
    · simpa [kept, NativeArrayCheckQuorum.get] using rep.newFollower peer
  · intro peer
    rw [readSame columns.currentTerm peer (.integer 0)]
    cases kept : keep peer.val
    · simp [kept, NativeArrayCheckQuorum.get, NativeArrayCheckQuorum.Local.fresh,
        NativeArrayCheckQuorum.Local.ofModel, freshNodeState, Term.eval]
    · simpa [kept, NativeArrayCheckQuorum.get] using rep.currentTerm peer
  · intro peer
    change (read newColumns newColumns.commit peer.val (.integer 0)).eval
      assignment Locals.empty = _
    rw [show newColumns.commit = columns.commit by simp [newColumns],
      readSame columns.commit peer (.integer 0)]
    cases kept : keep peer.val
    · simp [kept, NativeArrayCheckQuorum.get, NativeArrayCheckQuorum.Local.fresh,
        NativeArrayCheckQuorum.Local.ofModel, freshNodeState, Term.eval]
    · simpa [kept, NativeEncode.commit, NativeArrayCheckQuorum.get] using rep.commit peer
  · intro peer
    change (read newColumns newColumns.logLength peer.val (.integer 0)).eval
      assignment Locals.empty = _
    rw [show newColumns.logLength = columns.logLength by simp [newColumns],
      readSame columns.logLength peer (.integer 0)]
    cases kept : keep peer.val
    · simp [kept, NativeArrayCheckQuorum.get, NativeArrayCheckQuorum.Local.fresh,
        NativeArrayCheckQuorum.Local.ofModel, freshNodeState, Term.eval]
    · simpa [kept, NativeEncode.length, NativeArrayCheckQuorum.get] using rep.length peer
  · intro peer index live
    cases kept : keep peer.val
    · simp [kept, NativeArrayCheckQuorum.get, NativeArrayCheckQuorum.Local.fresh,
        NativeArrayCheckQuorum.Local.ofModel, NativeArrayCheckQuorum.Log.ofList,
        freshNodeState] at live
    · have oldLive : index < (NativeArrayCheckQuorum.get arrays peer).log.length := by
        simpa [kept, NativeArrayCheckQuorum.get] using live
      simpa [newColumns, kept, NativeArrayCheckQuorum.get] using
        rep.entries peer index oldLive
  · intro peer
    rw [show newColumns.retirementIndex = columns.retirementIndex by simp [newColumns],
      readSame columns.retirementIndex peer (.inl .unit)]
    cases kept : keep peer.val
    · simp [kept, NativeArrayCheckQuorum.get, NativeArrayCheckQuorum.Local.fresh,
        NativeArrayCheckQuorum.Local.ofModel, freshNodeState, optionalValue, Term.eval]
    · simpa [kept, NativeArrayCheckQuorum.get] using rep.retirementIndex peer
  · intro peer
    rw [show newColumns.retirementCommittableIndex =
        columns.retirementCommittableIndex by simp [newColumns],
      readSame columns.retirementCommittableIndex peer (.inl .unit)]
    cases kept : keep peer.val
    · simp [kept, NativeArrayCheckQuorum.get, NativeArrayCheckQuorum.Local.fresh,
        NativeArrayCheckQuorum.Local.ofModel, freshNodeState, optionalValue, Term.eval]
    · simpa [kept, NativeArrayCheckQuorum.get] using rep.retirementCommittableIndex peer
  · intro peer
    rw [show newColumns.retiredCommittedIndex =
        columns.retiredCommittedIndex by simp [newColumns],
      readSame columns.retiredCommittedIndex peer (.inl .unit)]
    cases kept : keep peer.val
    · simp [kept, NativeArrayCheckQuorum.get, NativeArrayCheckQuorum.Local.fresh,
        NativeArrayCheckQuorum.Local.ofModel, freshNodeState, optionalValue, Term.eval]
    · simpa [kept, NativeArrayCheckQuorum.get] using rep.retiredCommittedIndex peer
  · intro peer
    rw [show newColumns.votedFor = columns.votedFor by simp [newColumns],
      readSame columns.votedFor peer (.inl .unit)]
    cases kept : keep peer.val
    · simp [kept, NativeArrayCheckQuorum.get, NativeArrayCheckQuorum.Local.fresh,
        NativeArrayCheckQuorum.Local.ofModel, freshNodeState, optionalValue, Term.eval]
    · simpa [kept, NativeArrayCheckQuorum.get] using rep.votedFor peer
  · intro peer
    rw [show newColumns.votesGranted = columns.votesGranted by simp [newColumns],
      readSame columns.votesGranted peer (.bits 0)]
    cases kept : keep peer.val
    · simp [kept, NativeArrayCheckQuorum.get, NativeArrayCheckQuorum.Local.fresh,
        NativeArrayCheckQuorum.Local.ofModel, freshNodeState, Term.eval]
    · simpa [kept, NativeArrayCheckQuorum.get] using rep.votesGranted peer
  · intro peer
    rw [show newColumns.preVotesGranted = columns.preVotesGranted by simp [newColumns],
      readSame columns.preVotesGranted peer (.bits 0)]
    cases kept : keep peer.val
    · simp [kept, NativeArrayCheckQuorum.get, NativeArrayCheckQuorum.Local.fresh,
        NativeArrayCheckQuorum.Local.ofModel, freshNodeState, Term.eval]
    · simpa [kept, NativeArrayCheckQuorum.get] using rep.preVotesGranted peer
  · intro peer
    rw [show newColumns.membershipState = columns.membershipState by simp [newColumns],
      readSame columns.membershipState peer (.integer 0)]
    cases kept : keep peer.val
    · simp [kept, NativeArrayCheckQuorum.get, NativeArrayCheckQuorum.Local.fresh,
        NativeArrayCheckQuorum.Local.ofModel, freshNodeState, membershipCode, Term.eval]
    · simpa [kept, NativeArrayCheckQuorum.get] using rep.membershipState peer
  · intro node peer
    rw [show newColumns.sentIndex = columns.sentIndex by simp [newColumns],
      peerSame columns.sentIndex node peer]
    cases kept : keep node.val
    · simp [kept, NativeArrayCheckQuorum.get, NativeArrayCheckQuorum.Local.fresh,
        NativeArrayCheckQuorum.Local.ofModel, freshNodeState]
    · simpa [kept, NativeArrayCheckQuorum.get] using rep.sentIndex node peer
  · intro node peer
    rw [show newColumns.matchIndex = columns.matchIndex by simp [newColumns],
      peerSame columns.matchIndex node peer]
    cases kept : keep node.val
    · simp [kept, NativeArrayCheckQuorum.get, NativeArrayCheckQuorum.Local.fresh,
        NativeArrayCheckQuorum.Local.ofModel, freshNodeState]
    · simpa [kept, NativeArrayCheckQuorum.get] using rep.matchIndex node peer

theorem allocate_node_success {width : PNat} (node : Fin width) (enabled : Expr .bool)
    (before after : Encoding width)
    (run : (allocateNode node enabled).run before = .ok ((), after)) :
    AllocateNodeResult node enabled before after := by
  simp only [allocateNode, get_bind_run] at run
  split at run
  · rename_i enabledBounded
    obtain ⟨_, written, writeRun, run⟩ := (bind_run _ _ _ _ _).mp run
    obtain ⟨allocation, defined, defineRun, run⟩ := (bind_run _ _ _ _ _).mp run
    have final :
        { defined with allocated := allocation } = after := by
      exact congrArg Prod.snd (Except.ok.inj run)
    have writeShape := write_node_row_success node
      (nodeRowSnapshot before.toColumns node) before written writeRun
    obtain ⟨allocationId, allocationNext, allocationBootstrap, allocationColumns,
      allocationClauses⟩ :=
      define_success (allocationValue before node enabled) written defined allocation defineRun
    constructor
    · exact enabledBounded
    · rw [<- final, allocationNext, writeShape.next]
    · rw [<- final]
      exact allocationBootstrap.trans writeShape.bootstrap
    · rw [<- final, allocationColumns, writeShape.columns, allocationId, writeShape.next]
      rfl
    · rw [<- final, allocationClauses, Array.toList_push, writeShape.clauses,
        allocationId, writeShape.next]
      simp [allocateNodeClauses, allocationValue, List.append_assoc]
  · cases run

theorem allocate_node_prior_holds {width : PNat} (node : Fin width)
    (enabled : Expr .bool) (before after : Encoding width)
    (run : (allocateNode node enabled).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment) :
    Holds before.assertions.toList assignment := by
  rw [(allocate_node_success node enabled before after run).clauses] at holds
  exact fun formula member => holds formula (by simp [member])

theorem allocate_node_holds {width : PNat} (node : Fin width)
    (enabled : Expr .bool) (before after : Encoding width)
    (run : (allocateNode node enabled).run before = .ok ((), after))
    (assignment : Assignment) :
    Holds after.assertions.toList assignment <->
      Holds before.assertions.toList assignment /\
      Holds (allocateNodeClauses before node enabled) assignment := by
  rw [(allocate_node_success node enabled before after run).clauses]
  simp [Holds, or_imp, forall_and]

theorem allocate_node_references {width : PNat} (node : Fin width)
    (enabled : Expr .bool) (before after : Encoding width)
    (run : (allocateNode node enabled).run before = .ok ((), after))
    (valid : ReferencesValid before) : ReferencesValid after := by
  have shape := allocate_node_success node enabled before after run
  cases valid
  constructor <;> simp only [shape.columns, allocateNodeColumns, nodeRowWriteColumns,
    shape.next] <;> omega

def allocateNodeKeep {width : PNat}
    (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat) (node : Fin width)
    (enabled : Bool) (peer : Nat) : Bool :=
  if peer = node.val then (arrays node).isSome || enabled else true

theorem allocate_node_frame_sound {width : PNat} (node : Fin width)
    (enabled : Expr .bool) (before after : Encoding width)
    (run : (allocateNode node enabled).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment before.toColumns frame) :
    FrameColumnsRep assignment after.toColumns
      { frame with nodes := (CCFRaft.NativeArrayAllocation.allocate frame.nodes
          (if enabled.eval assignment Locals.empty then
            ({node} : Finset (Fin width)) else ∅)) } := by
  have shape := allocate_node_success node enabled before after run
  have separated := (allocate_node_holds node enabled before after run assignment).mp holds
  have rowHolds : Holds
      (definitionClauses
        (nodeRowWriteDefinitions before.toColumns node
          (nodeRowSnapshot before.toColumns node))
        before.next) assignment := by
    intro formula member
    exact separated.2 formula (by
      simp [allocateNodeClauses, member])
  have snapshotRep := node_row_snapshot_rep assignment before.toColumns frame.nodes
    rep.nodes node
  have writtenRep : NodeColumnsRep assignment
      (nodeRowWriteColumns before.toColumns before.next)
      (Function.update frame.nodes node
        (some (NativeArrayCheckQuorum.get frame.nodes node))) :=
    node_columns_row_written assignment before.toColumns before.next node
      (nodeRowSnapshot before.toColumns node) frame.nodes
      (NativeArrayCheckQuorum.get frame.nodes node) rep.nodes snapshotRep rowHolds
  have rowAllocationBinding :
      assignment (.array .int .bool) before.next =
        (Term.store (.free (.array .int .bool) before.allocated) (.integer node.val)
          (.boolean true)).eval assignment Locals.empty := by
    apply definition_clause_binding rowHolds
    simp [nodeRowWriteDefinitions, definitionClauses]
  have finalBinding :
      assignment (.array .int .bool) (before.next + 16) =
        (allocationValue before node enabled).eval assignment Locals.empty := by
    apply definition_clause_binding separated.2
    simp [allocateNodeClauses]
  let writtenColumns := nodeRowWriteColumns before.toColumns before.next
  let keep := allocateNodeKeep frame.nodes node (enabled.eval assignment Locals.empty)
  have allocationMask : forall peer : Nat,
      (allocated { writtenColumns with allocated := before.next + 16 } peer :
        Expr .bool).eval assignment Locals.empty =
      ((allocated writtenColumns peer : Expr .bool).eval assignment Locals.empty &&
        keep peer) := by
    intro peer
    have finalRead := stored_array_read_correct assignment before.allocated
      (before.next + 16) node.val peer
      (.or (allocated before.toColumns node.val) enabled) finalBinding
    have rowRead := stored_array_read_correct assignment before.allocated before.next
      node.val peer (.boolean true) rowAllocationBinding
    by_cases same : peer = node.val
    · subst peer
      simp [allocated, writtenColumns, keep, allocateNodeKeep, Term.eval] at finalRead rowRead ⊢
      rw [finalRead]
      change
        (assignment (.array .int .bool) before.allocated node.val ||
          enabled.eval assignment Locals.empty) =
        (assignment (.array .int .bool) before.next node.val &&
          ((frame.nodes node).isSome || enabled.eval assignment Locals.empty))
      have oldAllocated := rep.nodes.allocated node
      simp only [allocated, Term.eval] at oldAllocated
      rw [rowRead, oldAllocated]
      simp
    · simp [allocated, writtenColumns, keep, allocateNodeKeep, Term.eval, same] at finalRead rowRead ⊢
      rw [finalRead]
      change assignment (.array .int .bool) before.allocated peer =
        assignment (.array .int .bool) before.next peer
      exact rowRead.symm
  have maskedRep := node_columns_rep_masked assignment writtenColumns (before.next + 16)
    (Function.update frame.nodes node
      (some (NativeArrayCheckQuorum.get frame.nodes node)))
    keep writtenRep allocationMask
  have arraysEqual :
      (fun peer : Fin width =>
        if keep peer.val then
          Function.update frame.nodes node
            (some (NativeArrayCheckQuorum.get frame.nodes node)) peer
        else none) =
      CCFRaft.NativeArrayAllocation.allocate frame.nodes
        (if enabled.eval assignment Locals.empty then
          ({node} : Finset (Fin width)) else ∅) := by
    funext peer
    by_cases same : peer = node
    · subst peer
      cases found : frame.nodes node <;>
        cases active : enabled.eval assignment Locals.empty <;>
        simp [keep, allocateNodeKeep, CCFRaft.NativeArrayAllocation.allocate, found, active,
          NativeArrayCheckQuorum.get]
    · have different : peer.val ≠ node.val := fun equal => same (Fin.ext equal)
      cases found : frame.nodes peer <;>
        cases active : enabled.eval assignment Locals.empty <;>
        simp [keep, allocateNodeKeep, CCFRaft.NativeArrayAllocation.allocate, same, different,
          found, active]
  constructor
  · rw [shape.columns, allocateNodeColumns]
    simpa [writtenColumns, arraysEqual] using maskedRep
  · simpa [shape.columns, allocateNodeColumns, writtenColumns] using rep.hasJoined
  · intro peer
    simpa [shape.columns, allocateNodeColumns, writtenColumns] using rep.preVoteStatus peer
  · intro peer
    simpa [shape.columns, allocateNodeColumns, writtenColumns] using
      rep.retirementCompleted peer
  · intro txId
    simpa [shape.columns, allocateNodeColumns, writtenColumns] using rep.submittedTxIds txId
  · intro destination source
    simpa [shape.columns, allocateNodeColumns, writtenColumns, queueRow] using
      rep.queues destination source

theorem allocate_node_complete {width : PNat} (node : Fin width)
    (enabled : Expr .bool) (before after : Encoding width)
    (run : (allocateNode node enabled).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds before.assertions.toList assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment before.toColumns frame)
    (valid : ReferencesValid before) :
    exists extended : Assignment, assignment.AgreesBelow before.next extended /\
      Holds after.assertions.toList extended /\
      FrameColumnsRep extended after.toColumns
        { frame with nodes := (CCFRaft.NativeArrayAllocation.allocate frame.nodes
            (if enabled.eval assignment Locals.empty then
              ({node} : Finset (Fin width)) else ∅)) } := by
  have originalRun := run
  simp only [allocateNode, get_bind_run] at run
  split at run
  · rename_i enabledBounded
    obtain ⟨_, written, writeRun, run⟩ := (bind_run _ _ _ _ _).mp run
    obtain ⟨allocation, defined, defineRun, run⟩ := (bind_run _ _ _ _ _).mp run
    have final : { defined with allocated := allocation } = after :=
      congrArg Prod.snd (Except.ok.inj run)
    obtain ⟨first, firstAgreement, writtenHolds, _⟩ :=
      write_node_row_complete node (nodeRowSnapshot before.toColumns node)
        (NativeArrayCheckQuorum.get frame.nodes node) before written writeRun assignment holds
        frame rep (node_row_snapshot_rep assignment before.toColumns frame.nodes rep.nodes node)
        valid
    obtain ⟨extended, secondAgreement, definedHolds⟩ :=
      define_extension (allocationValue before node enabled) written defined allocation defineRun
        first writtenHolds
    have writtenNext :=
      (write_node_row_success node (nodeRowSnapshot before.toColumns node)
        before written writeRun).next
    have agreement : assignment.AgreesBelow before.next extended :=
      firstAgreement.trans (secondAgreement.restrict (by rw [writtenNext]; omega))
    have afterHolds : Holds after.assertions.toList extended := by
      rw [<- final]
      exact definedHolds
    have extendedRep := rep.agrees_below before assignment extended frame valid agreement
    have sound := allocate_node_frame_sound node enabled before after originalRun extended
      afterHolds frame extendedRep
    have enabledSame : enabled.eval extended Locals.empty =
        enabled.eval assignment Locals.empty :=
      (enabled.eval_agrees_below assignment extended Locals.empty before.next
        (fun symbol member => by
          simpa using List.all_eq_true.mp enabledBounded symbol member)
        agreement).symm
    refine ⟨extended, agreement, afterHolds, ?_⟩
    simpa [enabledSame] using sound
  · cases run

noncomputable def allocationSet {width : PNat} (assignment : Assignment)
    (added : Expr (.bits width))
    (peers : List (Fin width)) : Finset (Fin width) :=
  peers.toFinset.filter fun peer => (added.eval assignment Locals.empty).getLsbD peer.val

theorem allocation_set_cons {width : PNat} (assignment : Assignment)
    (added : Expr (.bits width)) (node : Fin width) (rest : List (Fin width)) :
    allocationSet assignment added (node :: rest) =
      (if (Term.bit added node).eval assignment Locals.empty then
        ({node} : Finset (Fin width)) else ∅) ∪ allocationSet assignment added rest := by
  ext peer
  by_cases same : peer = node
  · subst peer
    cases active : (added.eval assignment Locals.empty).getLsbD node.val with
    | false =>
      have conditionFalse :
          (Term.bit added node).eval assignment Locals.empty = false := by
        simpa only [Term.eval] using active
      simp [allocationSet, conditionFalse]
      intro impossible
      have bitTrue : (Term.bit added node).eval assignment Locals.empty = true := by
        simpa only [Term.eval] using impossible
      rw [conditionFalse] at bitTrue
      contradiction
    | true => simp [allocationSet, Term.eval, active]
  · cases active : (added.eval assignment Locals.empty).getLsbD node.val with
    | false =>
      have conditionFalse :
          (Term.bit added node).eval assignment Locals.empty = false := by
        simpa only [Term.eval] using active
      simp [allocationSet, conditionFalse, same]
    | true => simp [allocationSet, Term.eval, active, same]

theorem allocation_set_agrees {width : PNat} (left right : Assignment)
    (added : Expr (.bits width)) (peers : List (Fin width))
    (same : added.eval left Locals.empty = added.eval right Locals.empty) :
    allocationSet left added peers = allocationSet right added peers := by
  simp [allocationSet, same]

theorem native_array_allocate_union {width : PNat}
    (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat)
    (left right : Finset (Fin width)) :
    CCFRaft.NativeArrayAllocation.allocate
        (CCFRaft.NativeArrayAllocation.allocate arrays left) right =
      CCFRaft.NativeArrayAllocation.allocate arrays (left ∪ right) := by
  funext peer
  cases found : arrays peer <;>
    by_cases inLeft : peer ∈ left <;>
    by_cases inRight : peer ∈ right <;>
    simp [CCFRaft.NativeArrayAllocation.allocate, found, inLeft, inRight]

theorem allocate_node_list_next {width : PNat} (added : Expr (.bits width))
    (peers : List (Fin width)) (before after : Encoding width)
    (run : (allocateNodeList added peers).run before = .ok ((), after)) :
    after.next = before.next + 17 * peers.length /\
      after.bootstrap = before.bootstrap := by
  induction peers generalizing before with
  | nil =>
    simp only [allocateNodeList, StateT.run, pure] at run
    obtain ⟨rfl, rfl⟩ := Except.ok.inj run
    simp
  | cons node rest ih =>
    simp only [allocateNodeList] at run
    obtain ⟨_, middle, firstRun, run⟩ := (bind_run _ _ _ _ _).mp run
    have first := allocate_node_success node (.bit added node) before middle firstRun
    have tail := ih middle run
    constructor
    · rw [tail.1, first.next]
      simp
      omega
    · exact tail.2.trans first.sameBootstrap

theorem allocate_node_list_prior_holds {width : PNat} (added : Expr (.bits width))
    (peers : List (Fin width)) (before after : Encoding width)
    (run : (allocateNodeList added peers).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment) :
    Holds before.assertions.toList assignment := by
  induction peers generalizing before assignment with
  | nil =>
    simp only [allocateNodeList, StateT.run, pure] at run
    obtain ⟨rfl, rfl⟩ := Except.ok.inj run
    exact holds
  | cons node rest ih =>
    simp only [allocateNodeList] at run
    obtain ⟨_, middle, firstRun, run⟩ := (bind_run _ _ _ _ _).mp run
    exact allocate_node_prior_holds node (.bit added node) before middle firstRun assignment
      (ih middle run assignment holds)

theorem allocate_node_list_references {width : PNat} (added : Expr (.bits width))
    (peers : List (Fin width)) (before after : Encoding width)
    (run : (allocateNodeList added peers).run before = .ok ((), after))
    (valid : ReferencesValid before) : ReferencesValid after := by
  induction peers generalizing before with
  | nil =>
    simp only [allocateNodeList, StateT.run, pure] at run
    obtain ⟨rfl, rfl⟩ := Except.ok.inj run
    exact valid
  | cons node rest ih =>
    simp only [allocateNodeList] at run
    obtain ⟨_, middle, firstRun, run⟩ := (bind_run _ _ _ _ _).mp run
    exact ih middle run
      (allocate_node_references node (.bit added node) before middle firstRun valid)

theorem allocate_node_list_frame_sound {width : PNat} (added : Expr (.bits width))
    (peers : List (Fin width)) (before after : Encoding width)
    (run : (allocateNodeList added peers).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment before.toColumns frame) :
    FrameColumnsRep assignment after.toColumns
      { frame with nodes := (CCFRaft.NativeArrayAllocation.allocate frame.nodes
          (allocationSet assignment added peers)) } := by
  induction peers generalizing before frame with
  | nil =>
    simp only [allocateNodeList, StateT.run, pure] at run
    obtain ⟨rfl, rfl⟩ := Except.ok.inj run
    have emptyAllocation :
        CCFRaft.NativeArrayAllocation.allocate frame.nodes ∅ = frame.nodes := by
      funext peer
      cases found : frame.nodes peer <;>
        simp [CCFRaft.NativeArrayAllocation.allocate, found]
    simpa [allocationSet, emptyAllocation] using rep
  | cons node rest ih =>
    simp only [allocateNodeList] at run
    obtain ⟨_, middle, firstRun, run⟩ := (bind_run _ _ _ _ _).mp run
    have middleHolds :=
      allocate_node_list_prior_holds added rest middle after run assignment holds
    have firstRep :=
      allocate_node_frame_sound node (.bit added node) before middle firstRun assignment
        middleHolds frame rep
    have tailRep := ih middle run
      { frame with nodes := (CCFRaft.NativeArrayAllocation.allocate frame.nodes
          (if (Term.bit added node).eval assignment Locals.empty then
            ({node} : Finset (Fin width)) else ∅)) }
      firstRep
    rw [native_array_allocate_union] at tailRep
    rw [allocation_set_cons]
    exact tailRep

theorem allocate_node_list_complete {width : PNat} (added : Expr (.bits width))
    (peers : List (Fin width)) (before after : Encoding width)
    (run : (allocateNodeList added peers).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds before.assertions.toList assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment before.toColumns frame)
    (valid : ReferencesValid before)
    (addedBounded : added.symbols.all (fun symbol => symbol.2 < before.next) = true) :
    exists extended : Assignment, assignment.AgreesBelow before.next extended /\
      Holds after.assertions.toList extended /\
      FrameColumnsRep extended after.toColumns
        { frame with nodes := (CCFRaft.NativeArrayAllocation.allocate frame.nodes
            (allocationSet assignment added peers)) } := by
  induction peers generalizing before assignment frame with
  | nil =>
    simp only [allocateNodeList, StateT.run, pure] at run
    obtain ⟨rfl, rfl⟩ := Except.ok.inj run
    have emptyAllocation :
        CCFRaft.NativeArrayAllocation.allocate frame.nodes ∅ = frame.nodes := by
      funext peer
      cases found : frame.nodes peer <;>
        simp [CCFRaft.NativeArrayAllocation.allocate, found]
    exact ⟨assignment, fun _ _ _ => rfl, holds, by
      simpa [allocationSet, emptyAllocation] using rep⟩
  | cons node rest ih =>
    simp only [allocateNodeList] at run
    obtain ⟨_, middle, firstRun, run⟩ := (bind_run _ _ _ _ _).mp run
    obtain ⟨first, firstAgreement, firstHolds, firstRep⟩ :=
      allocate_node_complete node (.bit added node) before middle firstRun assignment holds
        frame rep valid
    have firstShape := allocate_node_success node (.bit added node) before middle firstRun
    have firstValid := allocate_node_references node (.bit added node) before middle firstRun valid
    have addedBoundedMiddle :
        added.symbols.all (fun symbol => symbol.2 < middle.next) = true := by
      apply List.all_eq_true.mpr
      intro symbol member
      have old : symbol.2 < before.next := by
        simpa using List.all_eq_true.mp addedBounded symbol member
      rw [firstShape.next]
      simpa only [decide_eq_true_eq] using Nat.lt_add_right 17 old
    obtain ⟨extended, tailAgreement, tailHolds, tailRep⟩ :=
      ih middle run first firstHolds
        { frame with nodes := (CCFRaft.NativeArrayAllocation.allocate frame.nodes
            (if (Term.bit added node).eval assignment Locals.empty then
              ({node} : Finset (Fin width)) else ∅)) }
        firstRep firstValid addedBoundedMiddle
    have agreement : assignment.AgreesBelow before.next extended :=
      firstAgreement.trans (tailAgreement.restrict (by rw [firstShape.next]; omega))
    have addedSame : added.eval first Locals.empty = added.eval assignment Locals.empty :=
      (added.eval_agrees_below assignment first Locals.empty before.next
        (fun symbol member => by
          simpa using List.all_eq_true.mp addedBounded symbol member)
        firstAgreement).symm
    refine ⟨extended, agreement, tailHolds, ?_⟩
    rw [native_array_allocate_union] at tailRep
    have sets :
        (if (Term.bit added node).eval assignment Locals.empty then
          ({node} : Finset (Fin width)) else ∅) ∪ allocationSet first added rest =
        allocationSet assignment added (node :: rest) := by
      rw [allocation_set_agrees first assignment added rest addedSame,
        allocation_set_cons]
    simpa [sets] using tailRep

structure AllocateNodesResult {width : PNat} (added : Expr (.bits width))
    (before after : Encoding width) : Prop where
  addedBounded : added.symbols.all (fun symbol => symbol.2 < before.next) = true
  next : after.next = before.next + 17 * width
  sameBootstrap : after.bootstrap = before.bootstrap

theorem allocate_nodes_success {width : PNat} (added : Expr (.bits width))
    (before after : Encoding width)
    (run : (allocateNodes added).run before = .ok ((), after)) :
    AllocateNodesResult added before after := by
  simp only [allocateNodes, get_bind_run] at run
  split at run
  · rename_i addedBounded
    have shape := allocate_node_list_next added (List.finRange width) before after run
    exact ⟨addedBounded, by simpa using shape.1, shape.2⟩
  · cases run

theorem allocate_nodes_prior_holds {width : PNat} (added : Expr (.bits width))
    (before after : Encoding width)
    (run : (allocateNodes added).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment) :
    Holds before.assertions.toList assignment := by
  simp only [allocateNodes, get_bind_run] at run
  split at run
  · exact allocate_node_list_prior_holds added (List.finRange width) before after run
      assignment holds
  · cases run

theorem allocate_nodes_references {width : PNat} (added : Expr (.bits width))
    (before after : Encoding width)
    (run : (allocateNodes added).run before = .ok ((), after))
    (valid : ReferencesValid before) : ReferencesValid after := by
  simp only [allocateNodes, get_bind_run] at run
  split at run
  · exact allocate_node_list_references added (List.finRange width) before after run valid
  · cases run

theorem allocate_nodes_frame_sound {width : PNat} (added : Expr (.bits width))
    (before after : Encoding width)
    (run : (allocateNodes added).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment before.toColumns frame) :
    FrameColumnsRep assignment after.toColumns
      { frame with nodes := (CCFRaft.NativeArrayAllocation.allocate frame.nodes
          (decodeBits (added.eval assignment Locals.empty))) } := by
  simp only [allocateNodes, get_bind_run] at run
  split at run
  · have result := allocate_node_list_frame_sound added (List.finRange width) before after
      run assignment holds frame rep
    have setEqual :
        allocationSet assignment added (List.finRange width) =
          decodeBits (added.eval assignment Locals.empty) := by
      ext peer
      simp [allocationSet, decode_bits_member]
    simpa [setEqual] using result
  · cases run

theorem allocate_nodes_complete {width : PNat} (added : Expr (.bits width))
    (before after : Encoding width)
    (run : (allocateNodes added).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds before.assertions.toList assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment before.toColumns frame)
    (valid : ReferencesValid before) :
    after.next = before.next + 17 * width /\
      exists extended : Assignment, assignment.AgreesBelow before.next extended /\
        Holds after.assertions.toList extended /\
        FrameColumnsRep extended after.toColumns
          { frame with nodes := (CCFRaft.NativeArrayAllocation.allocate frame.nodes
              (decodeBits (added.eval assignment Locals.empty))) } := by
  simp only [allocateNodes, get_bind_run] at run
  split at run
  · rename_i addedBounded
    have count := allocate_node_list_next added (List.finRange width) before after run
    obtain ⟨extended, agreement, finalHolds, finalRep⟩ :=
      allocate_node_list_complete added (List.finRange width) before after run assignment holds
        frame rep valid addedBounded
    refine ⟨by simpa using count.1, extended, agreement, finalHolds, ?_⟩
    have setEqual :
        allocationSet assignment added (List.finRange width) =
          decodeBits (added.eval assignment Locals.empty) := by
      ext peer
      simp [allocationSet, decode_bits_member]
    simpa [setEqual] using finalRep
  · cases run

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
