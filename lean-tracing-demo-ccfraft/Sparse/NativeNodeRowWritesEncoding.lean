-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeNodeRowWrites
import Sparse.NativeFrameColumns
import Sparse.NativeDefinitionsEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

structure NodeRowTerms.Rep {width : PNat} (assignment : Assignment)
    (values : NodeRowTerms width) (row : NativeArrayCheckQuorum.Local (Fin width) Nat) : Prop where
  role : values.role.eval assignment Locals.empty = roleCode row.role
  newFollower : values.newFollower.eval assignment Locals.empty = row.isNewFollower
  logLength : values.logLength.eval assignment Locals.empty = (row.log.length : Int)
  commit : values.commit.eval assignment Locals.empty = (row.commit : Int)
  currentTerm : values.currentTerm.eval assignment Locals.empty = (row.currentTerm : Int)
  logEntries : forall index : Nat, index < row.log.length ->
    modelEntry (values.logEntries.eval assignment Locals.empty index) = row.log.entries index
  retirementIndex : values.retirementIndex.eval assignment Locals.empty =
    optionalValue Nat.cast row.retirementIndex
  retirementCommittableIndex : values.retirementCommittableIndex.eval assignment Locals.empty =
    optionalValue Nat.cast row.retirementCommittableIndex
  retiredCommittedIndex : values.retiredCommittedIndex.eval assignment Locals.empty =
    optionalValue Nat.cast row.retiredCommittedIndex
  votedFor : values.votedFor.eval assignment Locals.empty =
    optionalValue (fun peer : Fin width => (peer.val : Int)) row.votedFor
  votesGranted : values.votesGranted.eval assignment Locals.empty = encodeBits row.votesGranted
  preVotesGranted : values.preVotesGranted.eval assignment Locals.empty =
    encodeBits row.preVotesGranted
  membershipState : values.membershipState.eval assignment Locals.empty =
    membershipCode row.membershipState
  sentIndex : forall peer : Fin width,
    values.sentIndex.eval assignment Locals.empty peer.val = (row.sentIndex peer : Int)
  matchIndex : forall peer : Fin width,
    values.matchIndex.eval assignment Locals.empty peer.val = (row.matchIndex peer : Int)

structure NodeRowTerms.Bounded {width : PNat} (values : NodeRowTerms width)
    (limit : Nat) : Prop where
  role : values.role.symbols.all (fun symbol => symbol.2 < limit) = true
  newFollower : values.newFollower.symbols.all (fun symbol => symbol.2 < limit) = true
  logLength : values.logLength.symbols.all (fun symbol => symbol.2 < limit) = true
  commit : values.commit.symbols.all (fun symbol => symbol.2 < limit) = true
  currentTerm : values.currentTerm.symbols.all (fun symbol => symbol.2 < limit) = true
  logEntries : values.logEntries.symbols.all (fun symbol => symbol.2 < limit) = true
  retirementIndex : values.retirementIndex.symbols.all (fun symbol => symbol.2 < limit) = true
  retirementCommittableIndex :
    values.retirementCommittableIndex.symbols.all (fun symbol => symbol.2 < limit) = true
  retiredCommittedIndex :
    values.retiredCommittedIndex.symbols.all (fun symbol => symbol.2 < limit) = true
  votedFor : values.votedFor.symbols.all (fun symbol => symbol.2 < limit) = true
  votesGranted : values.votesGranted.symbols.all (fun symbol => symbol.2 < limit) = true
  preVotesGranted : values.preVotesGranted.symbols.all (fun symbol => symbol.2 < limit) = true
  membershipState : values.membershipState.symbols.all (fun symbol => symbol.2 < limit) = true
  sentIndex : values.sentIndex.symbols.all (fun symbol => symbol.2 < limit) = true
  matchIndex : values.matchIndex.symbols.all (fun symbol => symbol.2 < limit) = true

private theorem term_symbols_bounded_mono {context : List Ty} {sort : Ty}
    (term : Term context sort) {lower upper : Nat}
    (bounded : term.symbols.all (fun symbol => symbol.2 < lower) = true)
    (le : lower <= upper) :
    term.symbols.all (fun symbol => symbol.2 < upper) = true := by
  rw [List.all_eq_true] at bounded ⊢
  intro symbol member
  have below := bounded symbol member
  have below' : symbol.2 < lower := by
    simpa only [decide_eq_true_eq] using below
  simpa only [decide_eq_true_eq] using lt_of_lt_of_le below' le

theorem NodeRowTerms.Bounded.mono {width : PNat}
    {values : NodeRowTerms width} {lower upper : Nat}
    (bounded : values.Bounded lower) (le : lower <= upper) :
    values.Bounded upper := by
  cases bounded
  constructor <;> apply term_symbols_bounded_mono <;> assumption

theorem node_row_snapshot_bounded {width : PNat} (state : Encoding width)
    (node : Fin width) (valid : ReferencesValid state) :
    (nodeRowSnapshot state.toColumns node).Bounded state.next := by
  constructor <;>
    simp [nodeRowSnapshot, read, allocated, NativeEncode.length, NativeEncode.commit,
      Term.symbols, valid.allocated, valid.role, valid.newFollower, valid.logLength,
      valid.commit, valid.currentTerm, valid.logEntries, valid.retirementIndex,
      valid.retirementCommittableIndex, valid.retiredCommittedIndex, valid.votedFor,
      valid.votesGranted, valid.preVotesGranted, valid.membershipState, valid.sentIndex,
      valid.matchIndex]

theorem NodeRowTerms.Rep.agrees_below {width : PNat} (left right : Assignment)
    (values : NodeRowTerms width) (row : NativeArrayCheckQuorum.Local (Fin width) Nat)
    (limit : Nat) (rep : values.Rep left row) (bounded : values.Bounded limit)
    (same : left.AgreesBelow limit right) : values.Rep right row := by
  have preserve {sort : Ty} (value : Expr sort)
      (within : value.symbols.all (fun symbol => symbol.2 < limit) = true) :
      value.eval right Locals.empty = value.eval left Locals.empty := by
    have bounded := List.all_eq_true.mp within
    exact (value.eval_agrees_below left right Locals.empty limit
      (fun symbol member => by simpa using bounded symbol member) same).symm
  constructor
  · exact (preserve values.role bounded.role).trans rep.role
  · exact (preserve values.newFollower bounded.newFollower).trans rep.newFollower
  · exact (preserve values.logLength bounded.logLength).trans rep.logLength
  · exact (preserve values.commit bounded.commit).trans rep.commit
  · exact (preserve values.currentTerm bounded.currentTerm).trans rep.currentTerm
  · intro index within
    rw [preserve values.logEntries bounded.logEntries]
    exact rep.logEntries index within
  · exact (preserve values.retirementIndex bounded.retirementIndex).trans rep.retirementIndex
  · exact (preserve values.retirementCommittableIndex bounded.retirementCommittableIndex).trans
      rep.retirementCommittableIndex
  · exact (preserve values.retiredCommittedIndex bounded.retiredCommittedIndex).trans
      rep.retiredCommittedIndex
  · exact (preserve values.votedFor bounded.votedFor).trans rep.votedFor
  · exact (preserve values.votesGranted bounded.votesGranted).trans rep.votesGranted
  · exact (preserve values.preVotesGranted bounded.preVotesGranted).trans rep.preVotesGranted
  · exact (preserve values.membershipState bounded.membershipState).trans rep.membershipState
  · intro peer
    rw [preserve values.sentIndex bounded.sentIndex]
    exact rep.sentIndex peer
  · intro peer
    rw [preserve values.matchIndex bounded.matchIndex]
    exact rep.matchIndex peer

theorem node_row_snapshot_rep {width : PNat} (assignment : Assignment)
    (columns : Columns) (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat)
    (rep : NodeColumnsRep assignment columns arrays) (node : Fin width) :
    NodeRowTerms.Rep assignment (nodeRowSnapshot columns node)
      (NativeArrayCheckQuorum.get arrays node) := by
  constructor
  · simpa [nodeRowSnapshot] using rep.role node
  · simpa [nodeRowSnapshot] using rep.newFollower node
  · simpa [nodeRowSnapshot] using rep.length node
  · simpa [nodeRowSnapshot] using rep.commit node
  · simpa [nodeRowSnapshot] using rep.currentTerm node
  · intro index within
    simpa [nodeRowSnapshot, Term.eval] using rep.entries node index within
  · simpa [nodeRowSnapshot] using rep.retirementIndex node
  · simpa [nodeRowSnapshot] using rep.retirementCommittableIndex node
  · simpa [nodeRowSnapshot] using rep.retiredCommittedIndex node
  · simpa [nodeRowSnapshot] using rep.votedFor node
  · simpa [nodeRowSnapshot] using rep.votesGranted node
  · simpa [nodeRowSnapshot] using rep.preVotesGranted node
  · simpa [nodeRowSnapshot] using rep.membershipState node
  · intro peer
    have represented := rep.sentIndex node peer
    by_cases present :
        (allocated columns node.val : Expr .bool).eval assignment Locals.empty = true
    · simp [nodeRowSnapshot, read, Term.eval, present]
      simpa [peerIndex, Term.eval, present] using represented
    · simp [nodeRowSnapshot, read, Term.eval, present]
      simpa [peerIndex, Term.eval, present] using represented
  · intro peer
    have represented := rep.matchIndex node peer
    by_cases present :
        (allocated columns node.val : Expr .bool).eval assignment Locals.empty = true
    · simp [nodeRowSnapshot, read, Term.eval, present]
      simpa [peerIndex, Term.eval, present] using represented
    · simp [nodeRowSnapshot, read, Term.eval, present]
      simpa [peerIndex, Term.eval, present] using represented

theorem stored_array_read_correct {sort : Ty} (assignment : Assignment)
    (before after node peer : Nat) (value : Expr sort)
    (binding : assignment (.array .int sort) after =
      (Term.store (.free (.array .int sort) before) (.integer node) value).eval
        assignment Locals.empty) :
    assignment (.array .int sort) after peer =
      if peer = node then value.eval assignment Locals.empty
      else assignment (.array .int sort) before peer := by
  rw [binding]
  by_cases same : peer = node
  · subst peer
    simp [Term.eval]
  · have different : (peer : Int) ≠ (node : Int) := by exact_mod_cast same
    simp [Term.eval, same, different]

theorem stored_allocation_read_correct (assignment : Assignment)
    (before after : Columns) (node peer : Nat)
    (binding : assignment (.array .int .bool) after.allocated =
      (Term.store (.free (.array .int .bool) before.allocated) (.integer node)
        (.boolean true)).eval assignment Locals.empty) :
    (allocated after peer : Expr .bool).eval assignment Locals.empty =
      if peer = node then true
      else (allocated before peer : Expr .bool).eval assignment Locals.empty := by
  simpa only [allocated, Term.eval] using
    stored_array_read_correct assignment before.allocated after.allocated node peer
      (.boolean true) binding

theorem stored_read_after_allocation_correct {sort : Ty} (assignment : Assignment)
    (before after : Columns) (beforeColumn afterColumn node peer : Nat)
    (default value : Expr sort)
    (allocationBinding : assignment (.array .int .bool) after.allocated =
      (Term.store (.free (.array .int .bool) before.allocated) (.integer node)
        (.boolean true)).eval assignment Locals.empty)
    (fieldBinding : assignment (.array .int sort) afterColumn =
      (Term.store (.free (.array .int sort) beforeColumn) (.integer node) value).eval
        assignment Locals.empty) :
    (read after afterColumn peer default).eval assignment Locals.empty =
      if peer = node then value.eval assignment Locals.empty
      else (read before beforeColumn peer default).eval assignment Locals.empty := by
  have allocation :=
    stored_allocation_read_correct assignment before after node peer allocationBinding
  have field :=
    stored_array_read_correct assignment beforeColumn afterColumn node peer value fieldBinding
  by_cases same : peer = node
  · subst peer
    simp [read, allocation, field, Term.eval]
  · simp [read, allocation, field, Term.eval, same]

theorem definition_clause_binding {sort : Ty} {assignment : Assignment}
    {assertions : List (Expr .bool)} {id : Nat} {value : Expr sort}
    (holds : Holds assertions assignment)
    (member : Term.equal (.free sort id) value ∈ assertions) :
    assignment sort id = value.eval assignment Locals.empty := by
  have evaluated := holds _ member
  simpa only [Term.eval, decide_eq_true_eq] using evaluated

theorem node_columns_row_written {width : PNat} (assignment : Assignment)
    (before : Columns) (base : Nat) (node : Fin width) (values : NodeRowTerms width)
    (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat)
    (row : NativeArrayCheckQuorum.Local (Fin width) Nat)
    (beforeRep : NodeColumnsRep assignment before arrays)
    (valuesRep : values.Rep assignment row)
    (holds : Holds (definitionClauses (nodeRowWriteDefinitions before node values) base)
      assignment) :
    NodeColumnsRep assignment (nodeRowWriteColumns before base)
      (Function.update arrays node (some row)) := by
  let after := nodeRowWriteColumns before base
  have binding {sort : Ty} (offset : Nat) (column : Nat) (value : Expr sort)
      (member : Term.equal (.free (.array .int sort) (base + offset))
        (Term.store (.free (.array .int sort) column) (.integer node.val) value) ∈
          definitionClauses (nodeRowWriteDefinitions before node values) base) :
      assignment (.array .int sort) (base + offset) =
        (Term.store (.free (.array .int sort) column) (.integer node.val) value).eval
          assignment Locals.empty :=
    definition_clause_binding holds member
  have allocatedBinding := binding 0 before.allocated (.boolean true) (by
    simp [nodeRowWriteDefinitions, definitionClauses])
  have roleBinding := binding 1 before.role values.role (by
    simp [nodeRowWriteDefinitions, definitionClauses])
  have followerBinding := binding 2 before.newFollower values.newFollower (by
    simp [nodeRowWriteDefinitions, definitionClauses])
  have lengthBinding := binding 3 before.logLength values.logLength (by
    simp [nodeRowWriteDefinitions, definitionClauses])
  have commitBinding := binding 4 before.commit values.commit (by
    simp [nodeRowWriteDefinitions, definitionClauses])
  have termBinding := binding 5 before.currentTerm values.currentTerm (by
    simp [nodeRowWriteDefinitions, definitionClauses])
  have entriesBinding := binding 6 before.logEntries values.logEntries (by
    simp [nodeRowWriteDefinitions, definitionClauses])
  have retirementBinding := binding 7 before.retirementIndex values.retirementIndex (by
    simp [nodeRowWriteDefinitions, definitionClauses])
  have retirementCommittableBinding :=
    binding 8 before.retirementCommittableIndex values.retirementCommittableIndex (by
      simp [nodeRowWriteDefinitions, definitionClauses])
  have retiredCommittedBinding :=
    binding 9 before.retiredCommittedIndex values.retiredCommittedIndex (by
      simp [nodeRowWriteDefinitions, definitionClauses])
  have votedBinding := binding 10 before.votedFor values.votedFor (by
    simp [nodeRowWriteDefinitions, definitionClauses])
  have votesBinding := binding 11 before.votesGranted values.votesGranted (by
    simp [nodeRowWriteDefinitions, definitionClauses])
  have preVotesBinding := binding 12 before.preVotesGranted values.preVotesGranted (by
    simp [nodeRowWriteDefinitions, definitionClauses])
  have membershipBinding := binding 13 before.membershipState values.membershipState (by
    simp [nodeRowWriteDefinitions, definitionClauses])
  have sentBinding := binding 14 before.sentIndex values.sentIndex (by
    simp [nodeRowWriteDefinitions, definitionClauses])
  have matchBinding := binding 15 before.matchIndex values.matchIndex (by
    simp [nodeRowWriteDefinitions, definitionClauses])
  have allocatedRead (peer : Fin width) :
      (allocated after peer.val : Expr .bool).eval assignment Locals.empty =
        if peer = node then true
        else (allocated before peer.val : Expr .bool).eval assignment Locals.empty := by
    have raw := stored_allocation_read_correct assignment before after node.val peer.val
      (by simpa [after, nodeRowWriteColumns] using allocatedBinding)
    by_cases same : peer = node
    · subst peer
      simpa using raw
    · have different : peer.val ≠ node.val := by
        intro equal
        exact same (Fin.ext equal)
      simpa [same, different] using raw
  have fieldRead {sort : Ty} (beforeColumn afterColumn : Nat) (peer : Fin width)
      (default value : Expr sort)
      (fieldBinding : assignment (.array .int sort) afterColumn =
        (Term.store (.free (.array .int sort) beforeColumn) (.integer node.val) value).eval
          assignment Locals.empty) :
      (read after afterColumn peer.val default).eval assignment Locals.empty =
        if peer = node then value.eval assignment Locals.empty
        else (read before beforeColumn peer.val default).eval assignment Locals.empty := by
    by_cases same : peer = node
    · subst peer
      simpa using stored_read_after_allocation_correct assignment before after beforeColumn
        afterColumn node.val node.val default value
        (by simpa [after, nodeRowWriteColumns] using allocatedBinding) fieldBinding
    · have different : peer.val ≠ node.val := by
        intro equal
        exact same (Fin.ext equal)
      simpa [same, different] using stored_read_after_allocation_correct assignment before after
        beforeColumn afterColumn node.val peer.val default value
        (by simpa [after, nodeRowWriteColumns] using allocatedBinding) fieldBinding
  constructor
  · intro peer
    rw [allocatedRead]
    by_cases same : peer = node
    · subst peer
      simp
    · simp [same, beforeRep.allocated]
  · intro peer
    rw [fieldRead before.role after.role peer (.integer 0) values.role
      (by simpa [after, nodeRowWriteColumns] using roleBinding)]
    by_cases same : peer = node
    · subst peer
      simpa [NativeArrayCheckQuorum.get] using valuesRep.role
    · simpa [NativeArrayCheckQuorum.get, same] using beforeRep.role peer
  · intro peer
    rw [fieldRead before.newFollower after.newFollower peer (.boolean true) values.newFollower
      (by simpa [after, nodeRowWriteColumns] using followerBinding)]
    by_cases same : peer = node
    · subst peer
      simpa [NativeArrayCheckQuorum.get] using valuesRep.newFollower
    · simpa [NativeArrayCheckQuorum.get, same] using beforeRep.newFollower peer
  · intro peer
    rw [fieldRead before.currentTerm after.currentTerm peer (.integer 0) values.currentTerm
      (by simpa [after, nodeRowWriteColumns] using termBinding)]
    by_cases same : peer = node
    · subst peer
      simpa [NativeArrayCheckQuorum.get] using valuesRep.currentTerm
    · simpa [NativeArrayCheckQuorum.get, same] using beforeRep.currentTerm peer
  · intro peer
    change (read after after.commit peer.val (.integer 0)).eval assignment Locals.empty = _
    rw [fieldRead before.commit after.commit peer (.integer 0) values.commit
      (by simpa [after, nodeRowWriteColumns] using commitBinding)]
    by_cases same : peer = node
    · subst peer
      simpa [commit, NativeArrayCheckQuorum.get] using valuesRep.commit
    · simpa [commit, NativeArrayCheckQuorum.get, same] using beforeRep.commit peer
  · intro peer
    change (read after after.logLength peer.val (.integer 0)).eval assignment Locals.empty = _
    rw [fieldRead before.logLength after.logLength peer (.integer 0) values.logLength
      (by simpa [after, nodeRowWriteColumns] using lengthBinding)]
    by_cases same : peer = node
    · subst peer
      simpa [length, NativeArrayCheckQuorum.get] using valuesRep.logLength
    · simpa [length, NativeArrayCheckQuorum.get, same] using beforeRep.length peer
  · intro peer index within
    by_cases same : peer = node
    · subst peer
      have selected := stored_array_read_correct assignment before.logEntries after.logEntries
        node.val node.val values.logEntries
        (by simpa [after, nodeRowWriteColumns] using entriesBinding)
      have raw := congrFun selected index
      simp only [if_pos] at raw
      change modelEntry
        (assignment (.array .int (.array .int (entryTy width)))
          after.logEntries node.val index) = _
      rw [raw]
      simpa [NativeArrayCheckQuorum.get] using
        valuesRep.logEntries index (by simpa [NativeArrayCheckQuorum.get] using within)
    · have selected := stored_array_read_correct assignment before.logEntries after.logEntries
        node.val peer.val values.logEntries
        (by simpa [after, nodeRowWriteColumns] using entriesBinding)
      have raw := congrFun selected index
      have different : peer.val ≠ node.val := by
        intro equal
        exact same (Fin.ext equal)
      simp only [if_neg different] at raw
      change modelEntry
        (assignment (.array .int (.array .int (entryTy width)))
          after.logEntries peer.val index) = _
      rw [raw]
      simpa [NativeArrayCheckQuorum.get, same] using
        beforeRep.entries peer index (by simpa [NativeArrayCheckQuorum.get, same] using within)
  · intro peer
    rw [fieldRead before.retirementIndex after.retirementIndex peer (.inl .unit)
      values.retirementIndex (by simpa [after, nodeRowWriteColumns] using retirementBinding)]
    by_cases same : peer = node
    · subst peer
      simpa [NativeArrayCheckQuorum.get] using valuesRep.retirementIndex
    · simpa [NativeArrayCheckQuorum.get, same] using beforeRep.retirementIndex peer
  · intro peer
    rw [fieldRead before.retirementCommittableIndex after.retirementCommittableIndex peer
      (.inl .unit) values.retirementCommittableIndex
      (by simpa [after, nodeRowWriteColumns] using retirementCommittableBinding)]
    by_cases same : peer = node
    · subst peer
      simpa [NativeArrayCheckQuorum.get] using valuesRep.retirementCommittableIndex
    · simpa [NativeArrayCheckQuorum.get, same] using beforeRep.retirementCommittableIndex peer
  · intro peer
    rw [fieldRead before.retiredCommittedIndex after.retiredCommittedIndex peer
      (.inl .unit) values.retiredCommittedIndex
      (by simpa [after, nodeRowWriteColumns] using retiredCommittedBinding)]
    by_cases same : peer = node
    · subst peer
      simpa [NativeArrayCheckQuorum.get] using valuesRep.retiredCommittedIndex
    · simpa [NativeArrayCheckQuorum.get, same] using beforeRep.retiredCommittedIndex peer
  · intro peer
    rw [fieldRead before.votedFor after.votedFor peer (.inl .unit) values.votedFor
      (by simpa [after, nodeRowWriteColumns] using votedBinding)]
    by_cases same : peer = node
    · subst peer
      simpa [NativeArrayCheckQuorum.get] using valuesRep.votedFor
    · simpa [NativeArrayCheckQuorum.get, same] using beforeRep.votedFor peer
  · intro peer
    rw [fieldRead before.votesGranted after.votesGranted peer (.bits 0) values.votesGranted
      (by simpa [after, nodeRowWriteColumns] using votesBinding)]
    by_cases same : peer = node
    · subst peer
      simpa [NativeArrayCheckQuorum.get] using valuesRep.votesGranted
    · simpa [NativeArrayCheckQuorum.get, same] using beforeRep.votesGranted peer
  · intro peer
    rw [fieldRead before.preVotesGranted after.preVotesGranted peer (.bits 0)
      values.preVotesGranted (by simpa [after, nodeRowWriteColumns] using preVotesBinding)]
    by_cases same : peer = node
    · subst peer
      simpa [NativeArrayCheckQuorum.get] using valuesRep.preVotesGranted
    · simpa [NativeArrayCheckQuorum.get, same] using beforeRep.preVotesGranted peer
  · intro peer
    rw [fieldRead before.membershipState after.membershipState peer (.integer 0)
      values.membershipState (by simpa [after, nodeRowWriteColumns] using membershipBinding)]
    by_cases same : peer = node
    · subst peer
      simpa [NativeArrayCheckQuorum.get] using valuesRep.membershipState
    · simpa [NativeArrayCheckQuorum.get, same] using beforeRep.membershipState peer
  · intro peer target
    have selected := stored_array_read_correct assignment before.sentIndex after.sentIndex
      node.val peer.val values.sentIndex
      (by simpa [after, nodeRowWriteColumns] using sentBinding)
    by_cases same : peer = node
    · subst peer
      have present := allocatedRead node
      simp at present selected
      simp [after, peerIndex, Term.eval, present, selected, NativeArrayCheckQuorum.get,
        valuesRep.sentIndex target]
    ·
      have different : peer.val ≠ node.val := fun equal => same (Fin.ext equal)
      have present := allocatedRead peer
      simp [same, different] at present selected
      simpa [after, peerIndex, read, Term.eval, present, selected,
        NativeArrayCheckQuorum.get, same] using beforeRep.sentIndex peer target
  · intro peer target
    have selected := stored_array_read_correct assignment before.matchIndex after.matchIndex
      node.val peer.val values.matchIndex
      (by simpa [after, nodeRowWriteColumns] using matchBinding)
    by_cases same : peer = node
    · subst peer
      have present := allocatedRead node
      simp at present selected
      simp [after, peerIndex, Term.eval, present, selected, NativeArrayCheckQuorum.get,
        valuesRep.matchIndex target]
    ·
      have different : peer.val ≠ node.val := fun equal => same (Fin.ext equal)
      have present := allocatedRead peer
      simp [same, different] at present selected
      simpa [after, peerIndex, read, Term.eval, present, selected,
        NativeArrayCheckQuorum.get, same] using beforeRep.matchIndex peer target

structure NodeRowWriteResult {width : PNat} (node : Fin width)
    (values : NodeRowTerms width) (before after : Encoding width) : Prop where
  symbols : (nodeRowWriteDefinitions before.toColumns node values).all
    (fun item => item.2.symbols.all (fun symbol => symbol.2 < before.next)) = true
  bootstrap : after.bootstrap = before.bootstrap
  columns : after.toColumns = nodeRowWriteColumns before.toColumns before.next
  next : after.next = before.next + 16
  clauses : after.assertions.toList = before.assertions.toList ++
    definitionClauses (nodeRowWriteDefinitions before.toColumns node values) before.next

theorem write_node_row_success {width : PNat} (node : Fin width)
    (values : NodeRowTerms width) (before after : Encoding width)
    (run : (writeNodeRow node values).run before = .ok ((), after)) :
    NodeRowWriteResult node values before after := by
  simp only [writeNodeRow, get_bind_run] at run
  split at run
  · rename_i symbols
    obtain ⟨ids, middle, defined, run⟩ := (bind_run _ _ _ _ _).mp run
    have final : { middle with
      toColumns := nodeRowWriteColumns before.toColumns before.next } = after := by
      exact congrArg Prod.snd (Except.ok.inj run)
    have result := definitions_success
      (nodeRowWriteDefinitions before.toColumns node values) before middle ids defined
    constructor
    · exact symbols
    · rw [<- final]
      exact result.bootstrap
    · rw [<- final]
    · rw [<- final, result.next]
      simp [nodeRowWriteDefinitions]
    · rw [<- final]
      exact result.clauses
  · cases run

theorem write_node_row_holds {width : PNat} (node : Fin width)
    (values : NodeRowTerms width) (before after : Encoding width)
    (run : (writeNodeRow node values).run before = .ok ((), after))
    (assignment : Assignment) :
    Holds after.assertions.toList assignment <->
      Holds before.assertions.toList assignment /\
      Holds (definitionClauses (nodeRowWriteDefinitions before.toColumns node values)
        before.next) assignment := by
  rw [(write_node_row_success node values before after run).clauses]
  simp [Holds, or_imp, forall_and]

theorem write_node_row_references {width : PNat} (node : Fin width)
    (values : NodeRowTerms width) (before after : Encoding width)
    (run : (writeNodeRow node values).run before = .ok ((), after))
    (valid : ReferencesValid before) : ReferencesValid after := by
  have shape := write_node_row_success node values before after run
  cases valid
  constructor <;> simp only [shape.columns, nodeRowWriteColumns, shape.next] <;> omega

theorem node_row_definition_values_bounded {width : PNat} (columns : Columns)
    (node : Fin width) (values : NodeRowTerms width) (limit : Nat)
    (symbols : (nodeRowWriteDefinitions columns node values).all
      (fun item => item.2.symbols.all (fun symbol => symbol.2 < limit)) = true) :
    values.Bounded limit := by
  have itemBound {sort : Ty} (value : Expr sort)
      (member : (⟨sort, value⟩ : TypedDefinition) ∈
        nodeRowWriteDefinitions columns node values) :
      value.symbols.all (fun symbol => symbol.2 < limit) = true :=
    List.all_eq_true.mp symbols _ member
  have storeBound {sort : Ty} (column : Nat) (value : Expr sort)
      (member : (⟨.array .int sort,
        Term.store (.free (.array .int sort) column) (.integer node.val) value⟩ :
        TypedDefinition) ∈ nodeRowWriteDefinitions columns node values) :
      value.symbols.all (fun symbol => symbol.2 < limit) = true := by
    have full := itemBound
      (Term.store (.free (.array .int sort) column) (.integer node.val) value) member
    have extracted : column < limit /\
        forall (symbol : Ty × Nat), symbol ∈ value.symbols -> symbol.2 < limit := by
      simpa [Term.symbols] using full
    exact List.all_eq_true.mpr fun symbol member => by
      simpa using extracted.2 symbol member
  constructor
  · exact storeBound columns.role values.role (by simp [nodeRowWriteDefinitions])
  · exact storeBound columns.newFollower values.newFollower (by simp [nodeRowWriteDefinitions])
  · exact storeBound columns.logLength values.logLength (by simp [nodeRowWriteDefinitions])
  · exact storeBound columns.commit values.commit (by simp [nodeRowWriteDefinitions])
  · exact storeBound columns.currentTerm values.currentTerm (by simp [nodeRowWriteDefinitions])
  · exact storeBound columns.logEntries values.logEntries (by simp [nodeRowWriteDefinitions])
  · exact storeBound columns.retirementIndex values.retirementIndex
      (by simp [nodeRowWriteDefinitions])
  · exact storeBound columns.retirementCommittableIndex values.retirementCommittableIndex
      (by simp [nodeRowWriteDefinitions])
  · exact storeBound columns.retiredCommittedIndex values.retiredCommittedIndex
      (by simp [nodeRowWriteDefinitions])
  · exact storeBound columns.votedFor values.votedFor (by simp [nodeRowWriteDefinitions])
  · exact storeBound columns.votesGranted values.votesGranted
      (by simp [nodeRowWriteDefinitions])
  · exact storeBound columns.preVotesGranted values.preVotesGranted
      (by simp [nodeRowWriteDefinitions])
  · exact storeBound columns.membershipState values.membershipState
      (by simp [nodeRowWriteDefinitions])
  · exact storeBound columns.sentIndex values.sentIndex (by simp [nodeRowWriteDefinitions])
  · exact storeBound columns.matchIndex values.matchIndex (by simp [nodeRowWriteDefinitions])

theorem write_node_row_values_bounded {width : PNat} (node : Fin width)
    (values : NodeRowTerms width) (before after : Encoding width)
    (run : (writeNodeRow node values).run before = .ok ((), after)) :
    values.Bounded before.next :=
  node_row_definition_values_bounded before.toColumns node values before.next
    (write_node_row_success node values before after run).symbols

theorem write_node_row_prior_holds {width : PNat} (node : Fin width)
    (values : NodeRowTerms width) (before after : Encoding width)
    (run : (writeNodeRow node values).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment) :
    Holds before.assertions.toList assignment :=
  ((write_node_row_holds node values before after run assignment).mp holds).1

theorem write_node_row_frame_sound {width : PNat} (node : Fin width)
    (values : NodeRowTerms width) (row : NativeArrayCheckQuorum.Local (Fin width) Nat)
    (before after : Encoding width)
    (run : (writeNodeRow node values).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment before.toColumns frame)
    (valuesRep : values.Rep assignment row) :
    FrameColumnsRep assignment after.toColumns
      { frame with nodes := Function.update frame.nodes node (some row) } := by
  have shape := write_node_row_success node values before after run
  have bindings := ((write_node_row_holds node values before after run assignment).mp holds).2
  constructor
  · rw [shape.columns]
    exact node_columns_row_written assignment before.toColumns before.next node values frame.nodes
      row rep.nodes valuesRep bindings
  · simpa only [shape.columns, nodeRowWriteColumns] using rep.hasJoined
  · intro peer
    simpa only [shape.columns, nodeRowWriteColumns] using rep.preVoteStatus peer
  · intro peer
    simpa only [shape.columns, nodeRowWriteColumns] using rep.retirementCompleted peer
  · intro txId
    simpa only [shape.columns, nodeRowWriteColumns] using rep.submittedTxIds txId
  · intro destination source
    simpa only [shape.columns, nodeRowWriteColumns, queueRow] using rep.queues destination source

theorem write_node_row_complete {width : PNat} (node : Fin width)
    (values : NodeRowTerms width) (row : NativeArrayCheckQuorum.Local (Fin width) Nat)
    (before after : Encoding width)
    (run : (writeNodeRow node values).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds before.assertions.toList assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment before.toColumns frame)
    (valuesRep : values.Rep assignment row) (valid : ReferencesValid before) :
    exists extended : Assignment, assignment.AgreesBelow before.next extended /\
      Holds after.assertions.toList extended /\
      FrameColumnsRep extended after.toColumns
        { frame with nodes := Function.update frame.nodes node (some row) } := by
  have originalRun := run
  simp only [writeNodeRow, get_bind_run] at run
  split at run
  · obtain ⟨ids, middle, defined, run⟩ := (bind_run _ _ _ _ _).mp run
    have final : { middle with
      toColumns := nodeRowWriteColumns before.toColumns before.next } = after := by
      exact congrArg Prod.snd (Except.ok.inj run)
    obtain ⟨extended, agreement, middleHolds⟩ :=
      definitions_extension (nodeRowWriteDefinitions before.toColumns node values)
        before middle ids defined assignment holds
    have afterHolds : Holds after.assertions.toList extended := by
      rw [<- final]
      exact middleHolds
    have extendedRep :=
      rep.agrees_below before assignment extended frame valid agreement
    have extendedValues :=
      valuesRep.agrees_below assignment extended values row before.next
        (write_node_row_values_bounded node values before after originalRun) agreement
    exact ⟨extended, agreement, afterHolds,
      write_node_row_frame_sound node values row before after originalRun extended afterHolds
        frame extendedRep extendedValues⟩
  · cases run

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
