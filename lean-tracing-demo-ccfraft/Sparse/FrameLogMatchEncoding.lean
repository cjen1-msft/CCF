-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.TypedGraphAddress
import Sparse.LogMatchEncoding
import Sparse.FrameObservationEncoding

set_option autoImplicit false

/-!
Prepare the graph before constructing caller queries. This fixed-family fragment
does not install an assignment or emit an outer compiler invocation. Frame
domains do not imply graph endpoint domains; root aliases add no endpoints.
-/

namespace CCFRaft.Sparse.FrameLogMatchEncoding

open Smt (Assignment Term Symbol)
open StateFrame (Frame Roots ModelState Rep)
open TypedGraphAddress (Graph)
open TypedIntervalEncoding (interpret)
open IntervalEncoding (natTerm natValue)
open FrameObservationEncoding (allocated)
open StateFrameEncoding (refTerm)

variable {roots size : Nat}

structure Call where
  enabled : Term .bool
  index : Term .int
  threshold : Term .int
  best : Term .int

def prepare (graph : Graph roots size) (frame : Frame roots size) (node : Node) :=
  TypedGraphAddress.resolve graph frame.locals[node.val].log.address

def spec (graph : Graph roots size) (frame : Frame roots size) (node : Node) (first : Nat) :
    LogMatchEncoding.Spec (prepare graph frame node).newSize :=
  { version := (prepare graph frame node).version
    length := first, index := first + 1, threshold := first + 2, best := first + 3 }

def guarded (enabled : Term .bool) (value : Term .int) : Term .int :=
  .ite enabled value (.integer 0)

def lengthTerm (frame : Frame roots size) (node : Node) (call : Call) : Term .int :=
  .ite (.and call.enabled (allocated frame node)) (refTerm frame.locals[node.val].log.length) (.integer 0)

def bindings (frame : Frame roots size) (node : Node) (call : Call) (first : Nat) : SmtScript.Formula :=
  [.equal (natTerm first) (lengthTerm frame node call),
   .equal (natTerm (first + 1)) (guarded call.enabled call.index),
   .equal (natTerm (first + 2)) (guarded call.enabled call.threshold),
   .equal (natTerm (first + 3)) (guarded call.enabled call.best)]

structure ArgumentsBound (assignment : Assignment) (frame : Frame roots size)
    (node : Node) (call : Call) (first : Nat) : Prop where
  length : assignment.constant .int first = (lengthTerm frame node call).eval assignment
  index : assignment.constant .int (first + 1) = (guarded call.enabled call.index).eval assignment
  threshold : assignment.constant .int (first + 2) = (guarded call.enabled call.threshold).eval assignment
  best : assignment.constant .int (first + 3) = (guarded call.enabled call.best).eval assignment

structure Bindings (assignment : Assignment) (graph : Graph roots size) (frame : Frame roots size)
    (node : Node) (call : Call) (first : Nat) : Prop extends ArgumentsBound assignment frame node call first where
  clip : assignment.constant .int (first + 4) =
    (LogMatchEncoding.clipTerm (spec graph frame node first)).eval assignment
  anchor : assignment.constant .int (first + 4 + 1) =
    (LogMatchEncoding.anchorTerm (spec graph frame node first)).eval assignment

def ActiveResult (assignment : Assignment) (state : ModelState) (node : Node) (call : Call) : Prop :=
  call.enabled.eval assignment = true ->
    0 <= call.index.eval assignment /\ 0 <= call.threshold.eval assignment /\
      call.best.eval assignment =
        (findHighestPossibleMatch (state.nodes node).log
          (call.index.eval assignment).toNat (call.threshold.eval assignment).toNat : Int)

def constraints (graph : Graph roots size) (frame : Frame roots size) (node : Node)
    (call : Call) (first : Nat) : SmtScript.Formula :=
  bindings frame node call first ++ LogMatchEncoding.constraints (spec graph frame node first) (first + 4)

def queries (graph : Graph roots size) (frame : Frame roots size) (node : Node) (first : Nat) :
    List (EntryPredicate.Query (prepare graph frame node).newSize) :=
  [LogMatchEncoding.suffix (spec graph frame node first) (first + 4),
   LogMatchEncoding.anchorQuery (spec graph frame node first) (first + 4)]

def Meaning (assignment : Assignment) (graph : Graph roots size) (arrays : Roots roots)
    (frame : Frame roots size) (node : Node) (call : Call) (first : Nat) : Prop :=
  SmtScript.Holds assignment (bindings frame node call first) /\
    LogMatchEncoding.Meaning assignment (prepare graph frame node).graph arrays
      (spec graph frame node first) (first + 4)

theorem bindings_correct (assignment : Assignment) (frame : Frame roots size)
    (node : Node) (call : Call) (first : Nat) :
    SmtScript.Holds assignment (bindings frame node call first) <->
      ArgumentsBound assignment frame node call first := by
  simp only [bindings, SmtScript.Holds, List.mem_cons, List.not_mem_nil, or_false,
    forall_eq_or_imp, forall_eq, Term.eval, natTerm, decide_eq_true_eq]
  constructor
  next =>
    intro h
    exact { length := h.1, index := h.2.1, threshold := h.2.2.1, best := h.2.2.2 }
  next => intro h; exact And.intro h.length (And.intro h.index (And.intro h.threshold h.best))

theorem meaning_formula (assignment : Assignment) (graph : Graph roots size) (arrays : Roots roots)
    (frame : Frame roots size) (node : Node) (call : Call) (first : Nat) :
    Meaning assignment graph arrays frame node call first <->
      SmtScript.Holds assignment (constraints graph frame node call first) /\
        VersionedIntervals.Realizes (interpret assignment (prepare graph frame node).graph)
          (IntervalQueries.schemas (TypedJointPredicateEncoding.localQueries assignment
            (queries graph frame node first))) arrays := by
  simp only [Meaning, LogMatchEncoding.Meaning, constraints, QueueEncoding.holds_append, queries, and_assoc]

theorem length_eval (assignment : Assignment) (graph : Graph roots size) (arrays : Roots roots)
    (submitted : Finset Nat) (frame : Frame roots size) (state : ModelState)
    (rep : Rep assignment (interpret assignment graph) arrays submitted frame state)
    (node : Node) (call : Call) :
    (lengthTerm frame node call).eval assignment =
      if call.enabled.eval assignment then ((state.nodes node).log.length : Int) else 0 := by
  change (if call.enabled.eval assignment && (allocated frame node).eval assignment
    then frame.locals[node.val].log.length.eval assignment else 0) = _
  rw [FrameObservationEncoding.allocated_eval assignment frame (interpret assignment graph) arrays submitted state rep node]
  by_cases enabled : call.enabled.eval assignment = true
  next =>
    by_cases present : state.allocated node
    next => simp [enabled, present, (rep.locals node present).logLength]
    next => simp [enabled, present, FrameObservationEncoding.absent_fresh state node present, freshNodeState]
  next => simp [enabled]

-- This finite-prefix list is proof-only. The fragment emits two interval queries.
noncomputable def effectiveLog (assignment : Assignment) (graph : Graph roots size) (arrays : Roots roots)
    (frame : Frame roots size) (node : Node) (call : Call) : List ArrayLog.LogEntry :=
  ({ length := ((lengthTerm frame node call).eval assignment).toNat
     entries := fun position => EntryValue.decodeEntry
       (VersionedIntervals.evaluate (interpret assignment (prepare graph frame node).graph)
         arrays position (prepare graph frame node).version) } : ArrayLog.ArrayLog).decode

theorem effective_log_eq (assignment : Assignment) (graph : Graph roots size) (arrays : Roots roots)
    (submitted : Finset Nat) (frame : Frame roots size) (state : ModelState)
    (rep : Rep assignment (interpret assignment graph) arrays submitted frame state)
    (node : Node) (call : Call) :
    effectiveLog assignment graph arrays frame node call =
      if call.enabled.eval assignment then (state.nodes node).log else [] := by
  unfold effectiveLog
  simp only [prepare]
  by_cases enabled : call.enabled.eval assignment = true
  next =>
    simp only [length_eval assignment graph arrays submitted frame state rep node call,
      enabled, if_true, Int.toNat_natCast]
    by_cases present : state.allocated node
    next =>
      rw [(rep.locals node present).log]
      congr 1
      rw [StateFrame.decode_log_length]
      congr 1
      funext position
      exact congrArg EntryValue.decodeEntry
        (TypedGraphAddress.resolved_value assignment graph frame.locals[node.val].log.address arrays position)
    next =>
      simp [FrameObservationEncoding.absent_fresh state node present, freshNodeState, ArrayLog.ArrayLog.decode]
  next =>
    simp [length_eval assignment graph arrays submitted frame state rep node call, enabled, ArrayLog.ArrayLog.decode]

theorem reader_log_eq (assignment : Assignment) (graph : Graph roots size) (arrays : Roots roots)
    (submitted : Finset Nat) (frame : Frame roots size) (state : ModelState)
    (rep : Rep assignment (interpret assignment graph) arrays submitted frame state)
    (node : Node) (call : Call) (first : Nat)
    (bound : ArgumentsBound assignment frame node call first) :
    ({ length := natValue assignment (spec graph frame node first).length
       entries := fun position => EntryValue.decodeEntry
         (LogMatchEncoding.cells assignment (prepare graph frame node).graph arrays
           (spec graph frame node first) position) } : ArrayLog.ArrayLog).decode =
      if call.enabled.eval assignment then (state.nodes node).log else [] := by
  simp only [spec, natValue, bound.length, LogMatchEncoding.cells]
  exact effective_log_eq assignment graph arrays submitted frame state rep node call

theorem source_of_active (assignment : Assignment) (graph : Graph roots size) (arrays : Roots roots)
    (submitted : Finset Nat) (frame : Frame roots size) (state : ModelState)
    (rep : Rep assignment (interpret assignment graph) arrays submitted frame state)
    (node : Node) (call : Call) (first : Nat)
    (bound : ArgumentsBound assignment frame node call first)
    (active : ActiveResult assignment state node call) :
    LogMatchEncoding.Source assignment (spec graph frame node first) := by
  change 0 <= assignment.constant .int first /\ 0 <= assignment.constant .int (first + 1) /\
    0 <= assignment.constant .int (first + 2) /\ 0 <= assignment.constant .int (first + 3)
  rw [bound.length, bound.index, bound.threshold, bound.best,
    length_eval assignment graph arrays submitted frame state rep node call]
  by_cases enabled : call.enabled.eval assignment = true
  next =>
    have facts := active enabled
    simp [guarded, Term.eval, enabled, facts.1, facts.2.1, facts.2.2]
  next => simp [guarded, Term.eval, enabled]

theorem result_iff_active (assignment : Assignment) (graph : Graph roots size) (arrays : Roots roots)
    (submitted : Finset Nat) (frame : Frame roots size) (state : ModelState)
    (rep : Rep assignment (interpret assignment graph) arrays submitted frame state)
    (node : Node) (call : Call) (first : Nat)
    (bound : ArgumentsBound assignment frame node call first)
    (source : LogMatchEncoding.Source assignment (spec graph frame node first)) :
    LogMatchEncoding.Result assignment (prepare graph frame node).graph arrays (spec graph frame node first) <->
      ActiveResult assignment state node call := by
  unfold LogMatchEncoding.Result
  rw [reader_log_eq assignment graph arrays submitted frame state rep node call first bound]
  by_cases enabled : call.enabled.eval assignment = true
  next =>
    have vi : assignment.constant .int (first + 1) = call.index.eval assignment := by
      simpa [guarded, Term.eval, enabled] using bound.index
    have vt : assignment.constant .int (first + 2) = call.threshold.eval assignment := by
      simpa [guarded, Term.eval, enabled] using bound.threshold
    have vb : assignment.constant .int (first + 3) = call.best.eval assignment := by
      simpa [guarded, Term.eval, enabled] using bound.best
    have hi : 0 <= call.index.eval assignment := by simpa only [spec, vi] using source.2.1
    have ht : 0 <= call.threshold.eval assignment := by simpa only [spec, vt] using source.2.2.1
    have hb : 0 <= call.best.eval assignment := by simpa only [spec, vb] using source.2.2.2
    have arithmetic (best : Int) (result : Nat) (nonnegative : 0 <= best) :
        result = best.toNat <-> best = (result : Int) := by omega
    simpa [ActiveResult, enabled, natValue, spec, vi, vt, vb, hi, ht] using
      arithmetic (call.best.eval assignment)
        (findHighestPossibleMatch (state.nodes node).log
          (call.index.eval assignment).toNat (call.threshold.eval assignment).toNat) hb
  next =>
    simp [ActiveResult, enabled, natValue, spec, bound.index, bound.threshold, bound.best,
      guarded, Term.eval, findHighestPossibleMatch]

theorem meaning_correct (assignment : Assignment) (graph : Graph roots size) (arrays : Roots roots)
    (submitted : Finset Nat) (frame : Frame roots size) (state : ModelState)
    (rep : Rep assignment (interpret assignment graph) arrays submitted frame state)
    (node : Node) (call : Call) (first : Nat) :
    Meaning assignment graph arrays frame node call first <->
      Bindings assignment graph frame node call first /\ ActiveResult assignment state node call := by
  rw [Meaning, bindings_correct, LogMatchEncoding.meaning_correct]
  constructor
  next =>
    intro facts
    have bound := facts.1
    have scalars := facts.2.1
    have result := facts.2.2
    refine And.intro
      { toArgumentsBound := bound
        clip := scalars.clip.trans (LogMatchEncoding.clip_eval assignment _ scalars.source).symm
        anchor := scalars.anchor.trans (LogMatchEncoding.anchor_eval assignment _ scalars.source).symm } ?_
    exact (result_iff_active assignment graph arrays submitted frame state rep node call first bound scalars.source).mp result
  next =>
    intro facts
    have bound := facts.1
    have active := facts.2
    have source := source_of_active assignment graph arrays submitted frame state rep node call first
      bound.toArgumentsBound active
    have result := (result_iff_active assignment graph arrays submitted frame state rep node call first
      bound.toArgumentsBound source).mpr active
    refine And.intro bound.toArgumentsBound (And.intro ?_ result)
    refine
      { source := source
        clip := bound.clip.trans (LogMatchEncoding.clip_eval assignment _ source)
        anchor := bound.anchor.trans (LogMatchEncoding.anchor_eval assignment _ source)
        bound := ?_ }
    have within := LogMatchSummary.result_bound
      ({ length := natValue assignment (spec graph frame node first).length
         entries := fun position => EntryValue.decodeEntry
           (LogMatchEncoding.cells assignment (prepare graph frame node).graph arrays
             (spec graph frame node first) position) } : ArrayLog.ArrayLog).decode
      (natValue assignment (spec graph frame node first).index)
      (natValue assignment (spec graph frame node first).threshold)
    rw [show findHighestPossibleMatch _ _ _ = _ from result, ArrayLog.decode_length] at within
    exact within

def ownedIds (first : Nat) : List Nat :=
  [first, first + 1, first + 2, first + 3, first + 4, first + 5]

def nextScalar (first : Nat) : Nat := first + 6

theorem owned_range (first id : Nat) :
    Membership.mem (ownedIds first) id <-> first <= id /\ id < nextScalar first := by
  simp only [ownedIds, nextScalar, List.mem_cons, List.not_mem_nil, or_false]
  omega

theorem owned_distinct (first : Nat) : (ownedIds first).Nodup := by
  simp [ownedIds]

theorem spec_maximum (graph : Graph roots size) (frame : Frame roots size) (node : Node) (first : Nat) :
    (spec graph frame node first).maximum = first + 3 := by
  simp only [spec, LogMatchEncoding.Spec.maximum]
  omega

def Call.symbols (call : Call) : List Symbol :=
  SmtScript.termSymbols call.enabled ++ SmtScript.termSymbols call.index ++
    SmtScript.termSymbols call.threshold ++ SmtScript.termSymbols call.best

def readSymbols (frame : Frame roots size) (node : Node) (call : Call) : List Symbol :=
  [frame.allocated.symbol, frame.locals[node.val].log.length.symbol] ++ call.symbols

-- Reservation includes dormant rows, independent globals, and unused graph nodes.
def sourceSymbols (graph : Graph roots size) (frame : Frame roots size) (call : Call) : List Symbol :=
  frame.symbols ++ TypedGraphAddress.sourceSymbols graph ++ call.symbols

def sourceMaximum (graph : Graph roots size) (frame : Frame roots size) (call : Call) : Nat :=
  (sourceSymbols graph frame call).toFinset.sup SymbolBounds.symbolId

theorem source_reservation (graph : Graph roots size) (frame : Frame roots size)
    (call : Call) (first : Nat) (fresh : sourceMaximum graph frame call < first)
    (symbol : Symbol) (member : Membership.mem (sourceSymbols graph frame call) symbol) :
    SymbolBounds.symbolId symbol < first :=
  Nat.lt_of_le_of_lt (Finset.le_sup (f := SymbolBounds.symbolId) (List.mem_toFinset.mpr member)) fresh

theorem source_disjoint (graph : Graph roots size) (frame : Frame roots size)
    (call : Call) (first : Nat) (fresh : sourceMaximum graph frame call < first)
    (id : Nat) (owned : Membership.mem (ownedIds first) id) :
    Not (Membership.mem (sourceSymbols graph frame call) (.constant .int id)) := by
  intro member
  have below := source_reservation graph frame call first fresh (.constant .int id) member
  have lower := (owned_range first id).mp owned
  change id < first at below
  omega

theorem read_symbols_covered (graph : Graph roots size) (frame : Frame roots size)
    (node : Node) (call : Call) :
    forall symbol, Membership.mem (readSymbols frame node call) symbol ->
      Membership.mem (sourceSymbols graph frame call) symbol := by
  intro symbol member
  have allocation : Membership.mem frame.symbols frame.allocated.symbol := by simp [StateFrame.Frame.symbols]
  have length : Membership.mem frame.symbols frame.locals[node.val].log.length.symbol := by
    apply StateFrame.frame_local_symbols frame node
    simp [StateFrame.LocalRefs.symbols, StateFrame.LocalRefs.naturals]
  simp only [readSymbols, List.mem_append, List.mem_cons, List.not_mem_nil, or_false] at member
  rcases member with (rfl | rfl) | member
  next => simp only [sourceSymbols, List.mem_append]; exact Or.inl (Or.inl allocation)
  next => simp only [sourceSymbols, List.mem_append]; exact Or.inl (Or.inl length)
  next => simp only [sourceSymbols, List.mem_append]; exact Or.inr member

theorem constraints_symbols (graph : Graph roots size) (frame : Frame roots size)
    (node : Node) (call : Call) (first : Nat) (symbol : Symbol) :
    Membership.mem (SmtScript.symbols (constraints graph frame node call first)) symbol <->
      Membership.mem (readSymbols frame node call) symbol \/
        Membership.mem ((ownedIds first).map (Symbol.constant .int)) symbol := by
  simp [constraints, bindings, LogMatchEncoding.constraints, TypedIntervalReadBlock.domainFormula,
    spec, SmtScript.symbols, SmtScript.termSymbols, LogMatchEncoding.clipTerm, LogMatchEncoding.anchorTerm,
    lengthTerm, guarded, allocated, NativeNodeOperations.member, refTerm, natTerm,
    StateFrame.ConstRef.symbol, readSymbols, Call.symbols, ownedIds, Nat.add_assoc]
  aesop

theorem footprint (graph : Graph roots size) (frame : Frame roots size)
    (node : Node) (call : Call) (first : Nat) :
    (constraints graph frame node call first).length = 13 /\
      (queries graph frame node first).length = 2 /\
      (ownedIds first).length = 6 /\
      (spec graph frame node first).maximum < first + 4 /\
      (prepare graph frame node).newSize <= size + 1 := by
  have node_bound := TypedGraphAddress.size_bound graph frame.locals[node.val].log.address
  simp [constraints, bindings, LogMatchEncoding.constraints, TypedIntervalReadBlock.domainFormula,
    spec, queries, ownedIds, LogMatchEncoding.Spec.maximum, prepare]
  exact node_bound

theorem query_footprint (graph : Graph roots size) (frame : Frame roots size) (node : Node) (first : Nat) :
    (queries graph frame node first).map (fun query => (query.lower, query.upper)) =
      [(first + 3, first + 4), (first + 5, first + 3)] /\
    (queries graph frame node first).map (fun query => query.predicate.externalSymbols) =
      [[.constant .int (first + 2)], [.constant .int (first + 2)]] /\
    (queries graph frame node first).map (fun query => query.predicate.references) =
      [[(prepare graph frame node).version], [(prepare graph frame node).version]] := by
  exact And.intro rfl (And.intro rfl rfl)

def ZeroSlots (assignment : Assignment) (first : Nat) : Prop :=
  forall id, Membership.mem (ownedIds first) id -> assignment.constant .int id = 0

theorem inactive_bindings (assignment : Assignment) (graph : Graph roots size)
    (frame : Frame roots size) (node : Node) (call : Call) (first : Nat)
    (disabled : call.enabled.eval assignment = false) :
    Bindings assignment graph frame node call first <-> ZeroSlots assignment first := by
  have zeroLength : (lengthTerm frame node call).eval assignment = 0 := by
    simp [lengthTerm, Term.eval, disabled]
  constructor
  next =>
    intro bound
    have hl : assignment.constant .int first = 0 := bound.length.trans zeroLength
    have hi : assignment.constant .int (first + 1) = 0 := by simpa [guarded, Term.eval, disabled] using bound.index
    have ht : assignment.constant .int (first + 2) = 0 := by simpa [guarded, Term.eval, disabled] using bound.threshold
    have hb : assignment.constant .int (first + 3) = 0 := by simpa [guarded, Term.eval, disabled] using bound.best
    have hc : assignment.constant .int (first + 4) = 0 := by
      simpa [LogMatchEncoding.clipTerm, spec, natTerm, Term.eval, hl, hi] using bound.clip
    have ha : assignment.constant .int (first + 5) = 0 := by
      simpa [LogMatchEncoding.anchorTerm, spec, natTerm, Term.eval, hb, Nat.add_assoc] using bound.anchor
    simpa [ZeroSlots, ownedIds] using And.intro hl (And.intro hi (And.intro ht (And.intro hb (And.intro hc ha))))
  next =>
    intro zero
    have slot_zero (offset : Nat) (within : offset < 6) : assignment.constant .int (first + offset) = 0 :=
      zero _ ((owned_range first _).mpr (by unfold nextScalar; omega))
    refine
      { length := ?_
        index := ?_
        threshold := ?_
        best := ?_
        clip := ?_
        anchor := ?_ }
    next => simpa [zeroLength] using slot_zero 0 (by decide)
    next => simp [guarded, Term.eval, disabled, slot_zero 1 (by decide)]
    next => simp [guarded, Term.eval, disabled, slot_zero 2 (by decide)]
    next => simp [guarded, Term.eval, disabled, slot_zero 3 (by decide)]
    next =>
      simp [LogMatchEncoding.clipTerm, spec, natTerm, Term.eval,
        slot_zero 4 (by decide), slot_zero 1 (by decide),
        show assignment.constant .int first = 0 from slot_zero 0 (by decide)]
    next =>
      simp [LogMatchEncoding.anchorTerm, spec, natTerm, Term.eval, Nat.add_assoc,
        slot_zero 5 (by decide), slot_zero 3 (by decide)]

theorem inactive_iff (assignment : Assignment) (graph : Graph roots size) (arrays : Roots roots)
    (submitted : Finset Nat) (frame : Frame roots size) (state : ModelState)
    (rep : Rep assignment (interpret assignment graph) arrays submitted frame state)
    (node : Node) (call : Call) (first : Nat) (disabled : call.enabled.eval assignment = false) :
    Meaning assignment graph arrays frame node call first <-> ZeroSlots assignment first := by
  rw [meaning_correct assignment graph arrays submitted frame state rep node call first,
    inactive_bindings assignment graph frame node call first disabled]
  simp [ActiveResult, disabled]

theorem active_absent_iff (assignment : Assignment) (graph : Graph roots size) (arrays : Roots roots)
    (submitted : Finset Nat) (frame : Frame roots size) (state : ModelState)
    (rep : Rep assignment (interpret assignment graph) arrays submitted frame state)
    (node : Node) (call : Call) (first : Nat) (enabled : call.enabled.eval assignment = true)
    (absent : Not (state.allocated node)) :
    Meaning assignment graph arrays frame node call first <->
      Bindings assignment graph frame node call first /\
        0 <= call.index.eval assignment /\ 0 <= call.threshold.eval assignment /\
          call.best.eval assignment = 0 := by
  rw [meaning_correct assignment graph arrays submitted frame state rep node call first]
  simp [ActiveResult, enabled, FrameObservationEncoding.absent_fresh state node absent,
    freshNodeState, findHighestPossibleMatch]

theorem prepared_metadata (graph : Graph roots size) (frame : Frame roots size) (node : Node) :
    (prepare graph frame node).graph.endpoints = graph.endpoints /\
      TypedGraphAddress.sourceSymbols (prepare graph frame node).graph =
        TypedGraphAddress.sourceSymbols graph :=
  And.intro (TypedGraphAddress.endpoints_preserved graph frame.locals[node.val].log.address)
    (TypedGraphAddress.sourceSymbols_preserved graph frame.locals[node.val].log.address)

theorem reader_domains_iff (assignment : Assignment) (graph : Graph roots size) (arrays : Roots roots)
    (frame : Frame roots size) (node : Node) (call : Call) (first : Nat)
    (meaning : Meaning assignment graph arrays frame node call first) :
    TypedJointPredicateEncoding.Domains assignment (prepare graph frame node).graph
        (queries graph frame node first) [] <->
      forall id, Membership.mem graph.endpoints id -> 0 <= assignment.constant .int id := by
  have facts := (LogMatchEncoding.constraints_raw assignment (spec graph frame node first) (first + 4)).mp meaning.2.1
  have hb : 0 <= assignment.constant .int (first + 3) := facts.1.2.2.2
  have hc := facts.2.1
  have ha : 0 <= assignment.constant .int (first + 5) := facts.2.2.1
  simp [TypedJointPredicateEncoding.Domains, TypedJointPredicateEncoding.boundIds, queries,
    LogMatchEncoding.suffix, LogMatchEncoding.anchorQuery, spec, (prepared_metadata graph frame node).1,
    Nat.add_assoc, or_imp, forall_and, hb, hc, ha]

namespace Regression

def node : Node := Fin.mk 0 (by decide)

def literalCall (enabled : Bool) (index threshold best : Int) : Call :=
  { enabled := .boolean enabled, index := .integer index, threshold := .integer threshold, best := .integer best }

def sample (rawLength : Int) (present : Bool) (slots : Vector Int 6) : Assignment :=
  StateFrameEncoding.sample 0 (if present then 1 else 0) 0 fun id =>
    match id with
    | 2 => rawLength
    | 100 => slots[0]
    | 101 => slots[1]
    | 102 => slots[2]
    | 103 => slots[3]
    | 104 => slots[4]
    | 105 => slots[5]
    | _ => 0

theorem canonical_prior_root :
    let frame := StateFrameInitial.frame 0 7 0
    let prepared := prepare .empty frame (Fin.mk 3 (by decide) : Node)
    prepared.newSize = 1 /\ prepared.version.val = 0 /\
      TypedGraphAddress.rootTag (IntervalReadback.lookup prepared.graph prepared.version) = some 10 /\
      (spec .empty frame (Fin.mk 3 (by decide)) 100).maximum = 103 := by
  decide +kernel

def versionFrame : Frame 15 1 :=
  let frame := StateFrameInitial.frame 0 0 1
  { frame with locals := frame.locals.map fun row => { row with log := { row.log with address := .version 0 } } }

theorem already_versioned :
    let graph : Graph 15 1 := .push .empty (.root 14)
    (prepare graph versionFrame node).newSize = 1 /\
      (prepare graph versionFrame node).version.val = 0 := by
  decide +kernel

theorem inactive_negative (arrays : Roots 1) :
    let assignment := sample (-7) false #v[0, 0, 0, 0, 0, 0]
    exists state, Rep assignment .empty arrays {} StateFrame.fixtureFrame state /\
      Meaning assignment .empty arrays StateFrame.fixtureFrame node (literalCall false (-8) (-9) (-10)) 100 := by
  dsimp only
  have valid : StateFrame.Domains (sample (-7) false #v[0, 0, 0, 0, 0, 0]) StateFrame.fixtureFrame := by
    apply (StateFrame.check_domains_iff _ _).mp
    decide +kernel
  have rep := StateFrame.decode_rep _ (.empty : StateFrame.Graph 1 0) arrays {} StateFrame.fixtureFrame valid
  refine Exists.intro _ (And.intro rep ?_)
  apply (inactive_iff _ .empty arrays {} _ _ rep node _ 100 rfl).mpr
  simp [ZeroSlots, ownedIds, sample, StateFrameEncoding.sample]

theorem absent_any_dormant_length (rawLength : Int) (arrays : Roots 1) :
    let assignment := sample rawLength false #v[0, 20, 0, 0, 0, 0]
    exists state, Rep assignment .empty arrays {} StateFrame.fixtureFrame state /\
      (state.nodes node).log = [] /\
      Meaning assignment .empty arrays StateFrame.fixtureFrame node (literalCall true 20 0 0) 100 := by
  dsimp only
  have empty : StateFrame.allocatedNodes (sample rawLength false #v[0, 20, 0, 0, 0, 0]) StateFrame.fixtureFrame = {} :=
    NodeSetCodec.decode_zero
  have valid := StateFrame.empty_allocation_domains _ _ empty
  have rep := StateFrame.decode_rep _ (.empty : StateFrame.Graph 1 0) arrays {} StateFrame.fixtureFrame valid
  have absent : Not ((StateFrame.decodeFrame _ .empty arrays {} StateFrame.fixtureFrame valid).allocated node) := by
    rw [rep.allocation, empty]
    simp
  have fresh := FrameObservationEncoding.absent_fresh _ node absent
  refine Exists.intro _ (And.intro rep (And.intro (by rw [fresh]; rfl) ?_))
  apply (active_absent_iff _ .empty arrays {} _ _ rep node _ 100 rfl absent).mpr
  refine And.intro ?_ (by simp [literalCall, Term.eval])
  refine { length := ?_, index := ?_, threshold := ?_, best := ?_, clip := ?_, anchor := ?_ }
  next =>
    have allocation := FrameObservationEncoding.allocated_eval _ StateFrame.fixtureFrame .empty arrays {} _ rep node
    simp only [absent, decide_false] at allocation
    simp only [lengthTerm, Term.eval, literalCall, allocation]
    rfl
  all_goals exact of_decide_eq_true rfl

def unsortedRoots : Roots 1 := fun _ position =>
  EntryValue.encodeEntry { term := match position with | 0 => 2 | 1 => 9 | 2 => 0 | _ => 8, content := .signature }

def activeCases : List (Prod Int (Prod Int Int)) :=
  [(4, 2, 3), (20, 2, 3), (0, 2, 0), (4, 0, 3), (2, 2, 1), (4, 9, 4), (1, 0, 0)]

def activeAssignment (item : Prod Int (Prod Int Int)) : Assignment :=
  sample 4 true #v[4, item.1, item.2.1, item.2.2, min item.1 4, max (item.2.2 - 1) 0]

theorem active_valid (item : Prod Int (Prod Int Int)) :
    StateFrame.Domains (activeAssignment item) StateFrame.fixtureFrame := by
  intro other _
  simp [StateFrame.LocalDomains, StateFrame.fixtureFrame, StateFrame.fixtureRow,
    StateFrame.LocalRefs.naturals, StateFrame.ConstRef.eval, activeAssignment, sample, StateFrameEncoding.sample]

theorem active_cases :
    forall item, Membership.mem activeCases item ->
      exists state, Rep (activeAssignment item) .empty unsortedRoots {} StateFrame.fixtureFrame state /\
        Meaning (activeAssignment item) .empty unsortedRoots StateFrame.fixtureFrame node
          (literalCall true item.1 item.2.1 item.2.2) 100 := by
  intro item member
  have valid := active_valid item
  have rep := StateFrame.decode_rep _ (.empty : StateFrame.Graph 1 0) unsortedRoots {} StateFrame.fixtureFrame valid
  have present := (rep.allocation node).mpr (by
    change Membership.mem (NodeSetCodec.decodeNodes 1) node
    decide +kernel)
  have log_eq := (rep.locals node present).log
  refine Exists.intro _ (And.intro rep ?_)
  apply (meaning_correct _ .empty unsortedRoots {} _ _ rep node _ 100).mpr
  simp only [activeCases, List.mem_cons, List.not_mem_nil, or_false] at member
  rcases member with rfl | rfl | rfl | rfl | rfl | rfl | rfl
  all_goals
    constructor
    next =>
      refine { length := ?_, index := ?_, threshold := ?_, best := ?_, clip := ?_, anchor := ?_ }
      all_goals decide +kernel
    next =>
      unfold ActiveResult
      rw [log_eq]
      decide +kernel

theorem earlier_match_rejected :
    Not (Meaning (activeAssignment (4, 2, 1)) .empty unsortedRoots StateFrame.fixtureFrame node
      (literalCall true 4 2 1) 100) := by
  have rep := StateFrame.decode_rep _ (.empty : StateFrame.Graph 1 0) unsortedRoots {}
    StateFrame.fixtureFrame (active_valid (4, 2, 1))
  have present := (rep.allocation node).mpr (by
    change Membership.mem (NodeSetCodec.decodeNodes 1) node
    decide +kernel)
  have log_eq := (rep.locals node present).log
  intro meaning
  have active := ((meaning_correct _ .empty unsortedRoots {} _ _ rep node _ 100).mp meaning).2
  have reject : Not (ActiveResult (activeAssignment (4, 2, 1))
      (StateFrame.decodeFrame _ .empty unsortedRoots {} StateFrame.fixtureFrame (active_valid (4, 2, 1)))
      node (literalCall true 4 2 1)) := by
    unfold ActiveResult
    rw [log_eq]
    decide +kernel
  exact reject active

theorem allocated_empty (arrays : Roots 1) :
    let assignment := sample 0 true #v[0, 20, 0, 0, 0, 0]
    exists state, Rep assignment .empty arrays {} StateFrame.fixtureFrame state /\
      state.allocated node /\ (state.nodes node).log = [] /\
      Meaning assignment .empty arrays StateFrame.fixtureFrame node (literalCall true 20 0 0) 100 := by
  dsimp only
  have valid : StateFrame.Domains (sample 0 true #v[0, 20, 0, 0, 0, 0]) StateFrame.fixtureFrame := by
    apply (StateFrame.check_domains_iff _ _).mp
    decide +kernel
  have rep := StateFrame.decode_rep _ (.empty : StateFrame.Graph 1 0) arrays {} StateFrame.fixtureFrame valid
  have present := (rep.allocation node).mpr (by
    change Membership.mem (NodeSetCodec.decodeNodes 1) node
    decide +kernel)
  have empty : ((StateFrame.decodeFrame _ .empty arrays {} StateFrame.fixtureFrame valid).nodes node).log = [] := by
    rw [(rep.locals node present).log]
    rfl
  refine Exists.intro _ (And.intro rep (And.intro present (And.intro empty ?_)))
  apply (meaning_correct _ .empty arrays {} _ _ rep node _ 100).mpr
  constructor
  next =>
    refine { length := ?_, index := ?_, threshold := ?_, best := ?_, clip := ?_, anchor := ?_ }
    all_goals decide +kernel
  next =>
    unfold ActiveResult
    rw [empty]
    decide +kernel

def metadataFrame : Frame 22 3 :=
  { StateFrameInitial.frame 0 7 3 with hasJoined := { id := 12000 } }

def metadataCall : Call :=
  { enabled := .and (.boolean false) (.app .content .bool 11000 (.signature))
    index := .unknown .int 7000
    threshold := .unknown .int 7000
    best := .transactionId (.unknown .content 8000) }

theorem disabled_alias_metadata :
    sourceMaximum TypedGraphAddress.Regression.metadataGraph metadataFrame metadataCall = 12000 /\
      Membership.mem (sourceSymbols TypedGraphAddress.Regression.metadataGraph metadataFrame metadataCall)
        (.unary .content .bool 11000) /\
      Membership.mem (sourceSymbols TypedGraphAddress.Regression.metadataGraph metadataFrame metadataCall)
        (.unary .nodes .entry 9001) /\
      Membership.mem (sourceSymbols TypedGraphAddress.Regression.metadataGraph metadataFrame metadataCall)
        (.constant .nodes 12000) /\
      (constraints TypedGraphAddress.Regression.metadataGraph metadataFrame node metadataCall 12001).length = 13 /\
      (prepare TypedGraphAddress.Regression.metadataGraph metadataFrame node).newSize = 3 := by
  decide +kernel

def badEndpointGraph : Graph 15 2 :=
  .push (.push .empty (.root 0)) (.splice 2 2 0 0)

theorem frame_domains_do_not_admit_graph (arrays : Roots 15) :
    let assignment := sample (-7) false #v[0, 0, 0, 0, 0, 0]
    let frame := StateFrameInitial.frame 0 0 2
    exists state, Rep assignment (interpret assignment badEndpointGraph) arrays {} frame state /\
      Meaning assignment badEndpointGraph arrays frame node (literalCall false (-1) (-2) (-3)) 100 /\
      Not (TypedJointPredicateEncoding.Domains assignment (prepare badEndpointGraph frame node).graph
        (queries badEndpointGraph frame node 100) []) := by
  dsimp only
  have empty : StateFrame.allocatedNodes (sample (-7) false #v[0, 0, 0, 0, 0, 0])
      (StateFrameInitial.frame 0 0 2) = {} := NodeSetCodec.decode_zero
  have valid := StateFrame.empty_allocation_domains _ _ empty
  have rep := StateFrame.decode_rep _
    (interpret (sample (-7) false #v[0, 0, 0, 0, 0, 0]) badEndpointGraph)
    arrays {} (StateFrameInitial.frame 0 0 2) valid
  have meaning := (inactive_iff _ badEndpointGraph arrays {} _ _ rep node
    (literalCall false (-1) (-2) (-3)) 100 rfl).mpr
      (by simp [ZeroSlots, ownedIds, sample, StateFrameEncoding.sample])
  refine Exists.intro _ (And.intro rep (And.intro meaning ?_))
  intro domains
  have nonnegative := ((reader_domains_iff _ badEndpointGraph arrays _ node _ 100 meaning).mp domains) 2
    (by decide +kernel)
  change (0 : Int) <= -7 at nonnegative
  omega

end Regression

end CCFRaft.Sparse.FrameLogMatchEncoding

run_cmd do
  let mut checked := 0
  for (name, info) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.Sparse.FrameLogMatchEncoding).isPrefixOf name then
      if let .axiomInfo _ := info then
        throwError "explicit axiom declaration: {name}"
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
      checked := checked + 1
  Lean.logInfo m!"Sparse.FrameLogMatchEncoding: allowed-axiom gate passed for {checked} declarations."

#print axioms CCFRaft.Sparse.FrameLogMatchEncoding.effective_log_eq
#print axioms CCFRaft.Sparse.FrameLogMatchEncoding.meaning_correct
#print axioms CCFRaft.Sparse.FrameLogMatchEncoding.inactive_iff
#print axioms CCFRaft.Sparse.FrameLogMatchEncoding.reader_domains_iff
