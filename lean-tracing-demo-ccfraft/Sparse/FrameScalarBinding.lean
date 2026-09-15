-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.ModelInputScalarEncoding
import Sparse.TypedJointContext

set_option autoImplicit false

namespace CCFRaft.Sparse.FrameScalarBinding

open Smt (Assignment Term Symbol Ty)
open StateFrame
open StateFrameEncoding (refTerm)
open ModelInputScalarEncoding (SourceRep FrameDisjoint)
open ModelTrace (UnknownNatAssignment)

variable {roots versions n : Nat}

def rebindCurrentTerm (frame : Frame roots versions) (node : Node) (fresh : ConstRef .int) :
    Frame roots versions :=
  let row := { frame.locals[node.val] with currentTerm := fresh }
  { frame with locals := frame.locals.set node.val row node.isLt }

def binding (frame : Frame roots versions) (node : Node) (fresh : ConstRef .int) : Term .bool :=
  .equal (refTerm fresh) (refTerm frame.locals[node.val].currentTerm)

theorem binding_correct (assignment : Assignment) (frame : Frame roots versions)
    (node : Node) (fresh : ConstRef .int) :
    (binding frame node fresh).eval assignment = true <->
      fresh.eval assignment = frame.locals[node.val].currentTerm.eval assignment := by
  simp [binding, Term.eval, refTerm, ConstRef.eval]

theorem binding_symbols (frame : Frame roots versions) (node : Node) (fresh : ConstRef .int) :
    SmtScript.termSymbols (binding frame node fresh) =
      [fresh.symbol, frame.locals[node.val].currentTerm.symbol] := rfl

theorem local_at (frame : Frame roots versions) (node : Node) (fresh : ConstRef .int) :
    (rebindCurrentTerm frame node fresh).locals[node.val] =
      { frame.locals[node.val] with currentTerm := fresh } := by
  simp [rebindCurrentTerm]

theorem local_other (frame : Frame roots versions) (node peer : Node) (fresh : ConstRef .int)
    (different : Not (node = peer)) :
    (rebindCurrentTerm frame node fresh).locals[peer.val] = frame.locals[peer.val] := by
  have differentIds : Not (node.val = peer.val) := fun same => different (Fin.ext same)
  simp [rebindCurrentTerm, differentIds]

theorem globals_unchanged (frame : Frame roots versions) (node : Node) (fresh : ConstRef .int) :
    { rebindCurrentTerm frame node fresh with locals := frame.locals } = frame := rfl

theorem other_local_fields (frame : Frame roots versions) (node : Node) (fresh : ConstRef .int) :
    { (rebindCurrentTerm frame node fresh).locals[node.val] with
      currentTerm := frame.locals[node.val].currentTerm } = frame.locals[node.val] := by
  rw [local_at]

theorem log_unchanged (frame : Frame roots versions) (node peer : Node) (fresh : ConstRef .int) :
    (rebindCurrentTerm frame node fresh).locals[peer.val].log = frame.locals[peer.val].log := by
  by_cases same : node = peer
  next => subst peer; rw [local_at]
  next => rw [local_other frame node peer fresh same]

theorem reference_inventory (frame : Frame roots versions) (node : Node) (fresh : ConstRef .int) :
    (rebindCurrentTerm frame node fresh).symbols.length = frame.symbols.length /\
      (rebindCurrentTerm frame node fresh).symbols.length = 662 := by
  simp only [frame_symbol_occurrences, and_self]

theorem overwrite (frame : Frame roots versions) (node : Node) (first last : ConstRef .int) :
    rebindCurrentTerm (rebindCurrentTerm frame node first) node last =
      rebindCurrentTerm frame node last := by
  simp [rebindCurrentTerm, Vector.set_set]

theorem overwrite_many (frame : Frame roots versions) (node : Node)
    (references : List (ConstRef .int)) (last : ConstRef .int) :
    rebindCurrentTerm
      (references.foldl (fun current ref => rebindCurrentTerm current node ref) frame) node last =
      rebindCurrentTerm frame node last := by
  induction references generalizing frame with
  | nil => rfl
  | cons head tail ih =>
    rw [List.foldl_cons, ih, overwrite]

theorem local_domains_iff (assignment : Assignment) (row : LocalRefs roots versions)
    (fresh : ConstRef .int) (same : fresh.eval assignment = row.currentTerm.eval assignment) :
    LocalDomains assignment { row with currentTerm := fresh } <-> LocalDomains assignment row := by
  simp [LocalDomains, LocalRefs.naturals, same]

theorem local_rep_iff (assignment : Assignment) (graph : Graph roots versions) (arrays : Roots roots)
    (row : LocalRefs roots versions) (state : NodeState Node Nat) (fresh : ConstRef .int)
    (same : fresh.eval assignment = row.currentTerm.eval assignment) :
    LocalRep assignment graph arrays { row with currentTerm := fresh } state <->
      LocalRep assignment graph arrays row state := by
  constructor
  next =>
    intro rep
    exact { rep with currentTerm := same.symm.trans rep.currentTerm }
  next =>
    intro rep
    exact { rep with currentTerm := same.trans rep.currentTerm }

theorem domains_iff (assignment : Assignment) (frame : Frame roots versions)
    (node : Node) (fresh : ConstRef .int)
    (same : fresh.eval assignment = frame.locals[node.val].currentTerm.eval assignment) :
    Domains assignment (rebindCurrentTerm frame node fresh) <-> Domains assignment frame := by
  unfold Domains
  apply forall_congr'
  intro peer
  apply imp_congr_right
  intro _
  by_cases equal : node = peer
  next =>
    subst peer
    rw [local_at]
    exact local_domains_iff assignment _ fresh same
  next => rw [local_other frame node peer fresh equal]

theorem rep_iff (assignment : Assignment) (graph : Graph roots versions) (arrays : Roots roots)
    (submitted : Finset Nat) (frame : Frame roots versions) (state : ModelState)
    (node : Node) (fresh : ConstRef .int)
    (same : fresh.eval assignment = frame.locals[node.val].currentTerm.eval assignment) :
    Rep assignment graph arrays submitted (rebindCurrentTerm frame node fresh) state <->
      Rep assignment graph arrays submitted frame state := by
  constructor
  next =>
    intro rep
    refine { rep with locals := ?_ }
    intro peer present
    have stored := rep.locals peer present
    by_cases equal : node = peer
    next =>
      subst peer
      rw [local_at] at stored
      exact (local_rep_iff assignment graph arrays _ _ fresh same).mp stored
    next => simpa only [local_other frame node peer fresh equal] using stored
  next =>
    intro rep
    refine { rep with locals := ?_ }
    intro peer present
    by_cases equal : node = peer
    next =>
      subst peer
      rw [local_at]
      exact (local_rep_iff assignment graph arrays _ _ fresh same).mpr (rep.locals node present)
    next => simpa only [local_other frame node peer fresh equal] using rep.locals peer present

theorem local_symbols_subset (row : LocalRefs roots versions) (fresh : ConstRef .int) (symbol : Symbol)
    (member : Membership.mem ({ row with currentTerm := fresh } : LocalRefs roots versions).symbols symbol) :
    symbol = fresh.symbol \/ Membership.mem row.symbols symbol := by
  simp only [LocalRefs.symbols, LocalRefs.naturals, List.map_append, List.map_cons, List.map_nil,
    List.mem_append, List.mem_cons, List.not_mem_nil, or_false] at *
  tauto

theorem symbols_subset (frame : Frame roots versions) (node : Node) (fresh : ConstRef .int)
    (symbol : Symbol) (member : Membership.mem (rebindCurrentTerm frame node fresh).symbols symbol) :
    symbol = fresh.symbol \/ Membership.mem frame.symbols symbol := by
  have rows :
      forall symbol, Membership.mem ((rebindCurrentTerm frame node fresh).locals.toList.flatMap
        LocalRefs.symbols) symbol ->
        symbol = fresh.symbol \/ Membership.mem (frame.locals.toList.flatMap LocalRefs.symbols) symbol := by
    intro symbol member
    cases List.mem_flatMap.mp member with
    | intro row facts =>
      have stored : Membership.mem
          (frame.locals.set node.val { frame.locals[node.val] with currentTerm := fresh } node.isLt) row := by
        simpa [rebindCurrentTerm] using facts.1
      cases Vector.mem_or_eq_of_mem_set stored with
      | inl old =>
        exact Or.inr (List.mem_flatMap.mpr (Exists.intro row (And.intro (by simpa using old) facts.2)))
      | inr equal =>
        rw [equal] at facts
        cases local_symbols_subset frame.locals[node.val] fresh symbol facts.2 with
        | inl same => exact Or.inl same
        | inr old =>
          exact Or.inr (List.mem_flatMap.mpr (Exists.intro frame.locals[node.val]
            (And.intro (vector_member frame.locals node) old)))
  have lifted := rows symbol
  simp only [Frame.symbols, rebindCurrentTerm, List.mem_append, List.mem_cons,
    List.not_mem_nil, or_false] at *
  tauto

theorem rebind_scoped (scope : Finset Symbol) (frame : Frame roots versions) (node : Node) (fresh : ConstRef .int)
    (old : WellScoped scope frame) (new : Membership.mem scope fresh.symbol) :
    WellScoped scope (rebindCurrentTerm frame node fresh) := by
  intro symbol member
  cases symbols_subset frame node fresh symbol member with
  | inl same => simpa only [same] using new
  | inr previous => exact old symbol previous

theorem source_disjoint (base n : Nat) (frame : Frame roots versions) (node : Node) (fresh : ConstRef .int)
    (old : FrameDisjoint base n frame)
    (outside : fresh.id < base \/ ModelInputScalarEncoding.highwater base n <= fresh.id) :
    FrameDisjoint base n (rebindCurrentTerm frame node fresh) := by
  intro id member
  cases symbols_subset frame node fresh (.constant .int id) member with
  | inl same =>
    have ids : id = fresh.id := by simpa [ConstRef.symbol] using same
    simpa only [ids] using outside
  | inr previous => exact old id previous

def FreshFor (frame : Frame roots versions) (fresh : ConstRef .int) : Prop :=
  forall symbol, Membership.mem frame.symbols symbol -> SymbolBounds.symbolId symbol < fresh.id

instance (frame : Frame roots versions) (fresh : ConstRef .int) : Decidable (FreshFor frame fresh) := by
  unfold FreshFor
  infer_instance

theorem fresh_after (frame : Frame roots versions) (node : Node) (fresh next : ConstRef .int)
    (reserved : FreshFor frame fresh) (advance : fresh.id < next.id) :
    FreshFor (rebindCurrentTerm frame node fresh) next := by
  intro symbol member
  cases symbols_subset frame node fresh symbol member with
  | inl same =>
    rw [same]
    exact advance
  | inr old => exact Nat.lt_trans (reserved symbol old) advance

theorem source_overlap_excluded (base n : Nat) (fresh : ConstRef .int)
    (reserved : ModelInputScalarEncoding.highwater base n <= fresh.id) (index : Fin n) :
    Not (fresh.id = (ModelInputScalarEncoding.sourceRef base index).id) := by
  have bound := (ModelInputScalarEncoding.source_ref_bounds base index).2
  omega

-- A semantic witness only. Runtime builders return the frame and binding term, not this assignment.
noncomputable def installWitness (original : Assignment) (frame : Frame roots versions)
    (node : Node) (fresh : ConstRef .int) : Assignment :=
  ScalarExtension.install original fresh.id
    (fun _ : Fin 1 => frame.locals[node.val].currentTerm.eval original)

theorem witness_value (original : Assignment) (frame : Frame roots versions) (node : Node)
    (fresh : ConstRef .int) :
    fresh.eval (installWitness original frame node fresh) =
      frame.locals[node.val].currentTerm.eval original := by
  simpa only [installWitness, ConstRef.eval, Nat.add_zero] using
    ScalarExtension.at_index original fresh.id
      (fun _ : Fin 1 => frame.locals[node.val].currentTerm.eval original) (0 : Fin 1)

theorem witness_outside (original : Assignment) (frame : Frame roots versions) (node : Node)
    (fresh : ConstRef .int) (ty : Ty) (id : Nat) (outside : Not (id = fresh.id)) :
    (installWitness original frame node fresh).constant ty id = original.constant ty id :=
  ScalarExtension.outside original fresh.id _ ty id (by omega)

theorem witness_other_sort (original : Assignment) (frame : Frame roots versions) (node : Node)
    (fresh : ConstRef .int) (ty : Ty) (id : Nat) (other : Not (ty = .int)) :
    (installWitness original frame node fresh).constant ty id = original.constant ty id := by
  cases ty with
  | int => exact False.elim (other rfl)
  | bool | nodes | content | entry => rfl

theorem witness_nonconstants (original : Assignment) (frame : Frame roots versions)
    (node : Node) (fresh : ConstRef .int) :
    (installWitness original frame node fresh).unary = original.unary /\
      (installWitness original frame node fresh).selectors = original.selectors := And.intro rfl rfl

theorem witness_frame_agree (original : Assignment) (frame : Frame roots versions) (node : Node)
    (fresh : ConstRef .int) (reserved : FreshFor frame fresh) :
    Agree frame.symbols (installWitness original frame node fresh) original := by
  intro ty id member
  have below : id < fresh.id := reserved (.constant ty id) member
  exact witness_outside original frame node fresh ty id (Nat.ne_of_lt below)

theorem witness_binding (original : Assignment) (frame : Frame roots versions) (node : Node)
    (fresh : ConstRef .int) (reserved : FreshFor frame fresh) :
    (binding frame node fresh).eval (installWitness original frame node fresh) = true := by
  apply (binding_correct _ frame node fresh).mpr
  have old := (witness_frame_agree original frame node fresh reserved).eval
    frame.locals[node.val].currentTerm
    (frame_local_symbols frame node _ (by simp [LocalRefs.symbols, LocalRefs.naturals]))
  exact (witness_value original frame node fresh).trans old.symm

theorem witness_source_iff (original : Assignment) (frame : Frame roots versions) (node : Node)
    (fresh : ConstRef .int) (base n : Nat) (rho : UnknownNatAssignment)
    (reserved : ModelInputScalarEncoding.highwater base n <= fresh.id) :
    SourceRep (installWitness original frame node fresh) base n rho <-> SourceRep original base n rho := by
  apply forall_congr'
  intro index
  change (installWitness original frame node fresh).constant .int (base + index.val) = _ <-> _
  rw [witness_outside original frame node fresh .int (base + index.val)
    (Ne.symm (source_overlap_excluded base n fresh reserved index))]
  rfl

theorem witness_rep_iff (original : Assignment) (graph : Graph roots versions) (arrays : Roots roots)
    (submitted : Finset Nat) (frame : Frame roots versions) (state : ModelState)
    (node : Node) (fresh : ConstRef .int) (reserved : FreshFor frame fresh) :
    Rep (installWitness original frame node fresh) graph arrays submitted
      (rebindCurrentTerm frame node fresh) state <-> Rep original graph arrays submitted frame state :=
  (rep_iff _ graph arrays submitted frame state node fresh
    ((binding_correct _ frame node fresh).mp (witness_binding original frame node fresh reserved))).trans
      (StateFrame.rep_congr graph arrays submitted frame state (witness_frame_agree original frame node fresh reserved))

theorem witness_domains_iff (original : Assignment) (frame : Frame roots versions)
    (node : Node) (fresh : ConstRef .int) (reserved : FreshFor frame fresh) :
    Domains (installWitness original frame node fresh) (rebindCurrentTerm frame node fresh) <->
      Domains original frame :=
  (domains_iff _ frame node fresh
    ((binding_correct _ frame node fresh).mp (witness_binding original frame node fresh reserved))).trans
      (StateFrame.domains_congr frame (witness_frame_agree original frame node fresh reserved))

theorem witness_term (original : Assignment) (frame : Frame roots versions) (node : Node)
    (fresh : ConstRef .int) {ty : Ty} (term : Term ty) (reserved : SymbolBounds.termMax term < fresh.id) :
    term.eval (installWitness original frame node fresh) = term.eval original :=
  ScalarExtension.eval_below original fresh.id _ term reserved

theorem witness_input (original : Assignment) (frame : Frame roots versions) (node : Node)
    (fresh : ConstRef .int) (input : SmtScript.Formula)
    (reserved : SymbolBounds.formulaMax input < fresh.id) :
    SmtScript.Holds (installWitness original frame node fresh) input <-> SmtScript.Holds original input :=
  ScalarExtension.formula_below original fresh.id _ input reserved

theorem witness_context (original : Assignment) (frame : Frame roots versions) (node : Node)
    (fresh : ConstRef .int) (input : SmtScript.Formula)
    (graph : TypedIntervalEncoding.SymbolicGraph roots .entry versions)
    (queries : List (EntryPredicate.Query versions))
    (points : List (TypedIntervalEncoding.Observation roots versions .entry))
    (clauses : List (TypedJointPredicateEncoding.Witness.Clause versions)) (arrays : Roots roots)
    (reserved : TypedJointPredicateEncoding.Witness.zero input graph queries points clauses <= fresh.id) :
    TypedJointContext.Context (installWitness original frame node fresh) input graph queries points clauses arrays <->
      TypedJointContext.Context original input graph queries points clauses arrays := by
  unfold installWitness
  exact TypedJointContext.install_context original fresh.id _ input graph queries points clauses arrays reserved

theorem witness_graph (original : Assignment) (frame : Frame roots versions) (node : Node)
    (fresh : ConstRef .int) (graph : TypedIntervalEncoding.SymbolicGraph roots .entry versions)
    (reserved : TypedIntervalEncoding.graphMax graph < fresh.id) :
    TypedIntervalEncoding.interpret (installWitness original frame node fresh) graph =
      TypedIntervalEncoding.interpret original graph :=
  TypedJointPredicateEncoding.graph_congr _ _ fresh.id graph reserved
    (witness_term original frame node fresh)

theorem constructive_binding (original : Assignment) (base n : Nat) (rho : UnknownNatAssignment)
    (frame : Frame roots versions) (state : ModelState) (node : Node) (fresh : ConstRef .int)
    (input : SmtScript.Formula) (graph : TypedIntervalEncoding.SymbolicGraph roots .entry versions)
    (queries : List (EntryPredicate.Query versions))
    (points : List (TypedIntervalEncoding.Observation roots versions .entry))
    (clauses : List (TypedJointPredicateEncoding.Witness.Clause versions))
    (arrays : Roots roots) (submitted : Finset Nat)
    (frame_reserved : FreshFor frame fresh)
    (source_reserved : ModelInputScalarEncoding.highwater base n <= fresh.id)
    (context_reserved : TypedJointPredicateEncoding.Witness.zero input graph queries points clauses <= fresh.id)
    (separate : FrameDisjoint base n frame)
    (source : SourceRep original base n rho)
    (rep : Rep original (TypedIntervalEncoding.interpret original graph) arrays submitted frame state)
    (context : TypedJointContext.Context original input graph queries points clauses arrays) :
    let extended := installWitness original frame node fresh
    (binding frame node fresh).eval extended = true /\
    SourceRep extended base n rho /\
    Rep extended (TypedIntervalEncoding.interpret original graph) arrays submitted frame state /\
    Rep extended (TypedIntervalEncoding.interpret original graph) arrays submitted
      (rebindCurrentTerm frame node fresh) state /\
    Domains extended (rebindCurrentTerm frame node fresh) /\
    FrameDisjoint base n (rebindCurrentTerm frame node fresh) /\
    TypedIntervalEncoding.interpret extended graph = TypedIntervalEncoding.interpret original graph /\
    TypedJointContext.Context extended input graph queries points clauses arrays := by
  dsimp only
  have updated := (witness_rep_iff original _ arrays submitted frame state node fresh frame_reserved).mpr rep
  have graph_below := Nat.lt_of_lt_of_le
    (TypedJointPredicateEncoding.allocation_bounds input graph queries points).2.1
    (Nat.le_trans (TypedJointPredicateEncoding.Witness.old_bound input graph queries points clauses) context_reserved)
  refine And.intro (witness_binding original frame node fresh frame_reserved)
    (And.intro ((witness_source_iff original frame node fresh base n rho source_reserved).mpr source)
      (And.intro ?_ (And.intro updated (And.intro updated.domains
        (And.intro (source_disjoint base n frame node fresh separate (Or.inr source_reserved))
          (And.intro (witness_graph original frame node fresh graph graph_below) ?_))))))
  next =>
    exact (StateFrame.rep_congr _ arrays submitted frame state
      (witness_frame_agree original frame node fresh frame_reserved)).mpr rep
  next =>
    exact (witness_context original frame node fresh input graph queries points clauses arrays context_reserved).mpr context

namespace Regression

def node : Node := Fin.mk 0 (by decide)
def peer : Node := Fin.mk 1 (by decide)
def fresh : ConstRef .int := { id := 100 }

def dormant : Assignment :=
  StateFrameEncoding.sample 0 0 32767 (fun id => if 10 <= id /\ id < 13 then 7 else -9)

theorem reservations :
    FreshFor fixtureFrame fresh /\
    FrameDisjoint 10 3 fixtureFrame /\
    ModelInputScalarEncoding.highwater 10 3 <= fresh.id /\
    Not (FreshFor fixtureFrame { id := 7 }) := by
  refine And.intro (by decide +kernel) (And.intro ?_ (And.intro (by decide) (by decide +kernel)))
  intro id member
  have below : FreshFor fixtureFrame { id := 8 } := by decide +kernel
  have bound : id < 8 := below (.constant .int id) member
  exact Or.inl (by omega)

theorem dormant_domains : Domains dormant fixtureFrame := by
  decide +kernel

theorem dormant_source : SourceRep dormant 10 3 (fun _ => 7) := by
  unfold SourceRep
  decide +kernel

theorem absent_negative :
    allocatedNodes dormant fixtureFrame = {} /\
    fresh.eval (installWitness dormant fixtureFrame node fresh) = -9 /\
    (rebindCurrentTerm fixtureFrame node fresh).locals[node.val].currentTerm.eval
      (installWitness dormant fixtureFrame node fresh) = -9 /\
    (binding fixtureFrame node fresh).eval (installWitness dormant fixtureFrame node fresh) = true /\
    Domains (installWitness dormant fixtureFrame node fresh) (rebindCurrentTerm fixtureFrame node fresh) := by
  refine And.intro (by decide +kernel) (And.intro ?_ (And.intro ?_ (And.intro
    (witness_binding dormant fixtureFrame node fresh reservations.1)
    ((witness_domains_iff dormant fixtureFrame node fresh reservations.1).mpr dormant_domains))))
  next => simpa [dormant, fixtureFrame, fixtureRow, node, ConstRef.eval, StateFrameEncoding.sample] using
    witness_value dormant fixtureFrame node fresh
  next =>
    rw [local_at]
    exact (witness_value dormant fixtureFrame node fresh).trans (by decide +kernel)

theorem same_state_and_roots (graph : Graph 1 0) (arrays : Roots 1) (submitted : Finset Nat)
    (network : Network) :
    exists state,
      Rep dormant graph arrays submitted fixtureFrame state /\
      Rep (installWitness dormant fixtureFrame node fresh) graph arrays submitted
        (rebindCurrentTerm fixtureFrame node fresh) state /\
      state.network = network := by
  cases (domains_iff_realizable dormant graph arrays network submitted fixtureFrame).mp dormant_domains with
  | intro state spec =>
    exact Exists.intro state (And.intro spec.1
      (And.intro ((witness_rep_iff dormant graph arrays submitted fixtureFrame state node fresh
        reservations.1).mpr spec.1) spec.2))

theorem aliased_source_values_and_unused :
    (ModelInputScalarEncoding.sourceNat 10 (.unknown (0 : Fin 3))).eval
      (installWitness dormant fixtureFrame node fresh) = 7 /\
    (ModelInputScalarEncoding.sourceNat 10 (.unknown (1 : Fin 3))).eval
      (installWitness dormant fixtureFrame node fresh) = 7 /\
    (installWitness dormant fixtureFrame node fresh).constant .int 12 = 7 := by
  have source := (witness_source_iff dormant fixtureFrame node fresh 10 3 (fun _ => 7)
    reservations.2.2.1).mpr dormant_source
  exact And.intro (source 0) (And.intro (source 1) (source 2))

theorem overlapping_unused_source :
    FreshFor fixtureFrame { id := 12 } /\
    Not (ModelInputScalarEncoding.highwater 10 3 <= 12) /\
    Not (SourceRep (installWitness dormant fixtureFrame node { id := 12 }) 10 3 (fun _ => 7)) := by
  refine And.intro (by decide +kernel) (And.intro (by decide) ?_)
  intro source
  have impossible := source 2
  change (-9 : Int) = 7 at impossible
  contradiction

def aliasFrame : Frame 1 0 :=
  { fixtureFrame with locals :=
      Vector.replicate NODE_COUNT { fixtureRow with currentTerm := fixtureRow.commitIndex } }

theorem aliased_fields :
    (rebindCurrentTerm aliasFrame node fresh).locals[node.val].currentTerm.id = 100 /\
    (rebindCurrentTerm aliasFrame node fresh).locals[node.val].commitIndex.id = 3 /\
    (rebindCurrentTerm aliasFrame node fresh).locals[peer.val].currentTerm.id = 3 /\
    (rebindCurrentTerm aliasFrame node fresh).locals[node.val].log.length.id = 2 := by
  decide +kernel

def repeated : Frame 1 0 :=
  (List.range 40).foldl (fun frame index => rebindCurrentTerm frame node { id := 100 + index }) fixtureFrame

theorem repeated_lookup :
    repeated.locals[node.val].currentTerm.id = 139 /\
    repeated.locals[peer.val].currentTerm.id = 1 /\
    repeated.locals[node.val].commitIndex.id = 3 /\
    repeated.locals[node.val].sentIndex[14].id = 7 /\
    repeated.locals[node.val].matchIndex[14].id = 7 /\
    repeated.locals[node.val].log.length.id = 2 /\
    repeated.locals[node.val].log.address = fixtureFrame.locals[node.val].log.address /\
    repeated.allocated.id = 0 /\ repeated.hasJoined.id = 1 /\
    repeated.preVoteEnabled[node.val].id = 1 /\
    repeated.retirementCompleted[node.val].id = 3 := by
  decide +kernel

theorem repeated_inventory :
    repeated.symbols.length = 662 /\
    repeated.locals.toArray.size = NODE_COUNT /\
    repeated.locals[node.val].sentIndex.toArray.size = NODE_COUNT /\
    repeated.locals[node.val].matchIndex.toArray.size = NODE_COUNT := by
  simp only [frame_symbol_occurrences, Vector.size_toArray, and_self]

def priorPoints : List (TypedIntervalEncoding.Observation 1 0 .entry) :=
  [{ address := .root 0, position := 1234, expected := .unknown .entry 2000 }]

def priorClauses : List (TypedJointPredicateEncoding.Witness.Clause 0) :=
  [{ lower := 2, upper := 3, predicate := .input (.boolean true),
     enable := .app .int .bool 3000 (.integer 0) }]

theorem prior_context_boundary :
    TypedJointPredicateEncoding.Witness.zero [] (.empty : TypedIntervalEncoding.SymbolicGraph 1 .entry 0)
      [] priorPoints priorClauses = 3001 := by
  decide +kernel

theorem prior_context_preserved (original : Assignment) (arrays : Roots 1) :
    TypedJointContext.Context (installWitness original fixtureFrame node { id := 3001 })
      [] .empty [] priorPoints priorClauses arrays <->
    TypedJointContext.Context original [] .empty [] priorPoints priorClauses arrays :=
  witness_context original fixtureFrame node { id := 3001 } [] .empty [] priorPoints priorClauses arrays
    (Nat.le_of_eq prior_context_boundary)

end Regression

end CCFRaft.Sparse.FrameScalarBinding

run_cmd do
  let mut checked := 0
  for (name, info) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.Sparse.FrameScalarBinding).isPrefixOf name then
      match info with
      | .axiomInfo _ => throwError "explicit FrameScalarBinding axiom: {name}"
      | _ =>
        checked := checked + 1
        for axiomName in (<- Lean.collectAxioms name) do
          unless axiomName == ``propext || axiomName == ``Classical.choice ||
              axiomName == ``Quot.sound do
            throwError "unexpected axiom in {name}: {axiomName}"
  Lean.logInfo m!"FrameScalarBinding: {checked} declarations passed the transitive axiom gate."
