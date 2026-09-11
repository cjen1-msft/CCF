import Sparse.TypedIntervalEncoding
import Sparse.IntervalQueries
import Sparse.BijectiveIntegerLog
import Sparse.NativeNodeSets

set_option autoImplicit false

namespace CCFRaft.Sparse.EntryPredicate

open Smt (Ty Term Assignment Symbol)
open IntervalEncoding (InputNat natValue)

variable {size roots : Nat} {ty : Ty}

def decodeTerm (value : Term .int) : Term .int :=
  .ite (.le (.integer 0) value) (.add value value)
    (.sub (.sub (.integer 0) (.add value value)) (.integer 1))

theorem decodeTerm_eval (assignment : Assignment) (value : Term .int) :
    (decodeTerm value).eval assignment = (BijectiveIntegerLog.decodeNat (value.eval assignment) : Int) := by
  rw [BijectiveIntegerLog.decode_formula]
  simp [decodeTerm, Term.eval, BijectiveIntegerLog.smtDecode, two_mul]

theorem decodeTerm_max (value : Term .int) :
    SymbolBounds.termMax (decodeTerm value) = SymbolBounds.termMax value := by
  simp [decodeTerm, SymbolBounds.termMax]

inductive Operand (size : Nat) : Ty -> Type where
  | cell (version : Fin size) : Operand size .entry
  | input {ty : Ty} (value : Term ty) : Operand size ty
  | entryTerm (value : Operand size .entry) : Operand size .int
  | entryContent (value : Operand size .entry) : Operand size .content
  | decodedTerm (value : Operand size .entry) : Operand size .int
  | decodedInput (value : Term .int) : Operand size .int
  | transactionId (value : Operand size .content) : Operand size .int
  | configurationNodes (value : Operand size .content) : Operand size .nodes
  | retiredNodes (value : Operand size .content) : Operand size .nodes
  | nodesAnd (left right : Operand size .nodes) : Operand size .nodes
  | nodesOr (left right : Operand size .nodes) : Operand size .nodes
  | nodesNot (value : Operand size .nodes) : Operand size .nodes
  | cardinality (value : Operand size .nodes) : Operand size .int

def Operand.referenceOccurrences : {ty : Ty} -> Operand size ty -> List (Fin size)
  | _, .cell version => [version]
  | _, .input _ | _, .decodedInput _ => []
  | _, .entryTerm value | _, .entryContent value | _, .decodedTerm value
  | _, .transactionId value | _, .configurationNodes value | _, .retiredNodes value
  | _, .nodesNot value | _, .cardinality value => value.referenceOccurrences
  | _, .nodesAnd left right | _, .nodesOr left right =>
    left.referenceOccurrences ++ right.referenceOccurrences

def Operand.references (operand : Operand size ty) : List (Fin size) :=
  operand.referenceOccurrences.dedup

def Operand.externalSymbols : {ty : Ty} -> Operand size ty -> List Symbol
  | _, .cell _ => []
  | _, .input value | _, .decodedInput value => SmtScript.termSymbols value
  | _, .entryTerm value | _, .entryContent value | _, .decodedTerm value
  | _, .transactionId value | _, .configurationNodes value | _, .retiredNodes value
  | _, .nodesNot value | _, .cardinality value => value.externalSymbols
  | _, .nodesAnd left right | _, .nodesOr left right => left.externalSymbols ++ right.externalSymbols

def Operand.externalMax : {ty : Ty} -> Operand size ty -> Nat
  | _, .cell _ => 0
  | _, .input value | _, .decodedInput value => SymbolBounds.termMax value
  | _, .entryTerm value | _, .entryContent value | _, .decodedTerm value
  | _, .transactionId value | _, .configurationNodes value | _, .retiredNodes value
  | _, .nodesNot value | _, .cardinality value => value.externalMax
  | _, .nodesAnd left right | _, .nodesOr left right => max left.externalMax right.externalMax

def Operand.eval (assignment : Assignment) (cells : Fin size -> EntryValue.Entry) :
    {ty : Ty} -> Operand size ty -> ty.denote
  | _, .cell version => cells version
  | _, .input value => value.eval assignment
  | _, .entryTerm value => (value.eval assignment cells).term
  | _, .entryContent value => (value.eval assignment cells).content
  | _, .decodedTerm value => (BijectiveIntegerLog.decodeNat (value.eval assignment cells).term : Int)
  | _, .decodedInput value => (BijectiveIntegerLog.decodeNat (value.eval assignment) : Int)
  | _, .transactionId value => EntrySelectorSemantics.rawTx assignment.selectors (value.eval assignment cells)
  | _, .configurationNodes value => EntrySelectorSemantics.rawCfg assignment.selectors (value.eval assignment cells)
  | _, .retiredNodes value => EntrySelectorSemantics.rawRetired assignment.selectors (value.eval assignment cells)
  | _, .nodesAnd left right => left.eval assignment cells &&& right.eval assignment cells
  | _, .nodesOr left right => left.eval assignment cells ||| right.eval assignment cells
  | _, .nodesNot value => ~~~(value.eval assignment cells)
  | _, .cardinality value => Int.ofNat (NodeSetCodec.decodeNodes (value.eval assignment cells)).card

def Operand.lower (roots base : Nat) (position : InputNat) : {ty : Ty} -> Operand size ty -> Term ty
  | _, .cell version => TypedIntervalEncoding.readRef base (IntervalReadback.Address.version (roots := roots) version) position
  | _, .input value => value
  | _, .entryTerm value => .entryTerm (value.lower roots base position)
  | _, .entryContent value => .entryContent (value.lower roots base position)
  | _, .decodedTerm value => decodeTerm (.entryTerm (value.lower roots base position))
  | _, .decodedInput value => decodeTerm value
  | _, .transactionId value => .transactionId (value.lower roots base position)
  | _, .configurationNodes value => .configurationNodes (value.lower roots base position)
  | _, .retiredNodes value => .retiredNodes (value.lower roots base position)
  | _, .nodesAnd left right => .nodesAnd (left.lower roots base position) (right.lower roots base position)
  | _, .nodesOr left right => .nodesOr (left.lower roots base position) (right.lower roots base position)
  | _, .nodesNot value => .nodesNot (value.lower roots base position)
  | _, .cardinality value => NativeNodeSets.cardinality (value.lower roots base position)

theorem Operand.references_mem (operand : Operand size ty) (version : Fin size) :
    Membership.mem operand.references version <-> Membership.mem operand.referenceOccurrences version :=
  List.mem_dedup

theorem Operand.references_nodup (operand : Operand size ty) : operand.references.Nodup :=
  List.nodup_dedup _

theorem Operand.externalMax_correct (operand : Operand size ty) :
    operand.externalMax = operand.externalSymbols.toFinset.sup SymbolBounds.symbolId := by
  induction operand <;>
    simp_all [Operand.externalMax, Operand.externalSymbols, SymbolBounds.termMax_correct, Finset.sup_union]

theorem Operand.locality (operand : Operand size ty) (assignment : Assignment)
    (left right : Fin size -> EntryValue.Entry)
    (agree : forall version, Membership.mem operand.references version -> left version = right version) :
    operand.eval assignment left = operand.eval assignment right := by
  induction operand with
  | cell version => exact agree version (by simp [Operand.references, Operand.referenceOccurrences])
  | input _ | decodedInput _ => rfl
  | entryTerm value ih => exact congrArg EntryValue.Entry.term (ih agree)
  | entryContent value ih => exact congrArg EntryValue.Entry.content (ih agree)
  | decodedTerm value ih =>
    exact congrArg (fun entry : EntryValue.Entry => (BijectiveIntegerLog.decodeNat entry.term : Int)) (ih agree)
  | transactionId value ih | configurationNodes value ih | retiredNodes value ih
  | nodesNot value ih | cardinality value ih => simp only [Operand.eval, ih agree]
  | nodesAnd first second ihl ihr | nodesOr first second ihl ihr =>
    have first_eq := ihl (fun version member => agree version (by
      simpa [Operand.references, Operand.referenceOccurrences] using
        Or.inl (List.mem_dedup.mp member)))
    have second_eq := ihr (fun version member => agree version (by
      simpa [Operand.references, Operand.referenceOccurrences] using
        Or.inr (List.mem_dedup.mp member)))
    simp only [Operand.eval, first_eq, second_eq]

theorem Operand.lower_correct (operand : Operand size ty) (assignment : Assignment) (roots base : Nat)
    (position : InputNat) (nonnegative : 0 <= assignment.constant .int position) :
    (operand.lower roots base position).eval assignment =
      operand.eval assignment (fun version => TypedIntervalEncoding.reads (ty := .entry) assignment base
        (IntervalReadback.Address.version (roots := roots) version) (natValue assignment position)) := by
  induction operand with
  | cell version => exact TypedIntervalEncoding.readRef_eval assignment base _ position nonnegative
  | input _ => rfl
  | entryTerm value ih | entryContent value ih => simp only [Operand.lower, Operand.eval, Term.eval, ih]
  | decodedTerm value ih => simp only [Operand.lower, Operand.eval, decodeTerm_eval, Term.eval, ih]
  | decodedInput value => exact decodeTerm_eval assignment value
  | transactionId value ih | configurationNodes value ih | retiredNodes value ih
  | nodesNot value ih => simp only [Operand.lower, Operand.eval, Term.eval, ih]
  | nodesAnd left right ihl ihr | nodesOr left right ihl ihr =>
    simp only [Operand.lower, Operand.eval, Term.eval, ihl, ihr]
  | cardinality value ih =>
    simp only [Operand.lower, Operand.eval, NativeNodeSets.cardinality_eval, ih]

inductive Predicate (size : Nat) where
  | eq {ty : Ty} (left right : Operand size ty)
  | ne {ty : Ty} (left right : Operand size ty)
  | le (left right : Operand size .int)
  | lt (left right : Operand size .int)
  | input (value : Term .bool)
  | not (value : Predicate size)
  | and (left right : Predicate size)
  | implies (condition body : Predicate size)
  | isContent (tag : Smt.ContentTag) (value : Operand size .content)
  | majority (support configuration : Operand size .nodes)

def Predicate.referenceOccurrences : Predicate size -> List (Fin size)
  | .eq left right | .ne left right | .le left right | .lt left right | .majority left right =>
    left.referenceOccurrences ++ right.referenceOccurrences
  | .isContent _ value => value.referenceOccurrences
  | .input _ => []
  | .not value => value.referenceOccurrences
  | .and left right | .implies left right => left.referenceOccurrences ++ right.referenceOccurrences

def Predicate.references (predicate : Predicate size) : List (Fin size) :=
  predicate.referenceOccurrences.dedup

def Predicate.externalSymbols : Predicate size -> List Symbol
  | .eq left right | .ne left right | .le left right | .lt left right | .majority left right =>
    left.externalSymbols ++ right.externalSymbols
  | .isContent _ value => value.externalSymbols
  | .input value => SmtScript.termSymbols value
  | .not value => value.externalSymbols
  | .and left right | .implies left right => left.externalSymbols ++ right.externalSymbols

def Predicate.externalMax : Predicate size -> Nat
  | .eq left right | .ne left right | .le left right | .lt left right | .majority left right =>
    max left.externalMax right.externalMax
  | .isContent _ value => value.externalMax
  | .input value => SymbolBounds.termMax value
  | .not value => value.externalMax
  | .and left right | .implies left right => max left.externalMax right.externalMax

def Predicate.eval (assignment : Assignment) (cells : Fin size -> EntryValue.Entry) : Predicate size -> Bool
  | .eq left right => decide (left.eval assignment cells = right.eval assignment cells)
  | .ne left right => decide (Not (left.eval assignment cells = right.eval assignment cells))
  | .le left right => decide (left.eval assignment cells <= right.eval assignment cells)
  | .lt left right => decide (left.eval assignment cells < right.eval assignment cells)
  | .input value => value.eval assignment
  | .not value => !(value.eval assignment cells)
  | .and left right => left.eval assignment cells && right.eval assignment cells
  | .implies condition body => !(condition.eval assignment cells) || body.eval assignment cells
  | .isContent tag value => tag.test (value.eval assignment cells)
  | .majority support configuration =>
    decide (hasConfigurationMajority (NodeSetCodec.decodeNodes (support.eval assignment cells))
      { index := 0, nodes := NodeSetCodec.decodeNodes (configuration.eval assignment cells) })

def Predicate.lower (roots base : Nat) (position : InputNat) : Predicate size -> Term .bool
  | .eq left right => .equal (left.lower roots base position) (right.lower roots base position)
  | .ne left right => .not (.equal (left.lower roots base position) (right.lower roots base position))
  | .le left right => .le (left.lower roots base position) (right.lower roots base position)
  | .lt left right => .not (.le (right.lower roots base position) (left.lower roots base position))
  | .input value => value
  | .not value => .not (value.lower roots base position)
  | .and left right => .and (left.lower roots base position) (right.lower roots base position)
  | .implies condition body => .implies (condition.lower roots base position) (body.lower roots base position)
  | .isContent tag value => .isContent tag (value.lower roots base position)
  | .majority support configuration =>
    NativeNodeSets.majority (support.lower roots base position) (configuration.lower roots base position)

theorem Predicate.references_mem (predicate : Predicate size) (version : Fin size) :
    Membership.mem predicate.references version <-> Membership.mem predicate.referenceOccurrences version :=
  List.mem_dedup

theorem Predicate.references_nodup (predicate : Predicate size) : predicate.references.Nodup :=
  List.nodup_dedup _

theorem Predicate.externalMax_correct (predicate : Predicate size) :
    predicate.externalMax = predicate.externalSymbols.toFinset.sup SymbolBounds.symbolId := by
  induction predicate <;>
    simp_all only [Predicate.externalMax, Predicate.externalSymbols, Operand.externalMax_correct,
      SymbolBounds.termMax_correct, List.toFinset_append, Finset.sup_union]

theorem Predicate.external_symbol_bound (predicate : Predicate size) (symbol : Symbol)
    (member : Membership.mem predicate.externalSymbols symbol) :
    SymbolBounds.symbolId symbol <= predicate.externalMax := by
  rw [predicate.externalMax_correct]
  exact Finset.le_sup (f := SymbolBounds.symbolId) (List.mem_toFinset.mpr member)

theorem Predicate.locality (predicate : Predicate size) (assignment : Assignment)
    (left right : Fin size -> EntryValue.Entry)
    (agree : forall version, Membership.mem predicate.references version -> left version = right version) :
    predicate.eval assignment left = predicate.eval assignment right := by
  have occurrences := fun version member => agree version (List.mem_dedup.mpr member)
  clear agree
  induction predicate with
  | eq first second | ne first second | le first second | lt first second | majority first second =>
    have first_eq := first.locality assignment left right (fun version member =>
      occurrences version (List.mem_append.mpr (Or.inl (List.mem_dedup.mp member))))
    have second_eq := second.locality assignment left right (fun version member =>
      occurrences version (List.mem_append.mpr (Or.inr (List.mem_dedup.mp member))))
    simp only [Predicate.eval, first_eq, second_eq]
  | isContent tag value =>
    exact congrArg tag.test (value.locality assignment left right
      (fun version member => occurrences version (List.mem_dedup.mp member)))
  | input _ => rfl
  | not value ih => exact congrArg Bool.not (ih occurrences)
  | and first second ihl ihr | implies first second ihl ihr =>
    have first_eq := ihl (fun version member => occurrences version (List.mem_append.mpr (Or.inl member)))
    have second_eq := ihr (fun version member => occurrences version (List.mem_append.mpr (Or.inr member)))
    simp only [Predicate.eval, first_eq, second_eq]

theorem Predicate.lower_correct (predicate : Predicate size) (assignment : Assignment)
    (roots base : Nat) (position : InputNat) (nonnegative : 0 <= assignment.constant .int position) :
    (predicate.lower roots base position).eval assignment =
      predicate.eval assignment (fun version => TypedIntervalEncoding.reads (ty := .entry) assignment base
        (IntervalReadback.Address.version (roots := roots) version) (natValue assignment position)) := by
  induction predicate with
  | majority support configuration =>
    simp only [Predicate.lower, Predicate.eval, NativeNodeSets.majority_eval assignment _ _ 0,
      Operand.lower_correct _ assignment roots base position nonnegative]
  | _ =>
    simp_all [Predicate.lower, Predicate.eval, Term.eval,
      Operand.lower_correct _ assignment roots base position nonnegative] <;>
      simp only [<- decide_not, not_lt]

theorem Predicate.lower_alias (predicate : Predicate size) (assignment : Assignment)
    (roots base : Nat) (left right : InputNat)
    (left_nonnegative : 0 <= assignment.constant .int left) (right_nonnegative : 0 <= assignment.constant .int right)
    (same : assignment.constant .int left = assignment.constant .int right) :
    (predicate.lower roots base left).eval assignment = (predicate.lower roots base right).eval assignment := by
  rw [predicate.lower_correct assignment roots base left left_nonnegative,
    predicate.lower_correct assignment roots base right right_nonnegative]
  simp only [natValue, same]

def Operand.filterByFixed (value : Operand size .nodes)
    (conditions : Vector (Term .bool) NODE_COUNT) : Operand size .nodes :=
  .nodesAnd value (.input (NativeNodeSets.filter
    (.nodes (NodeSetCodec.encodeNodes Finset.univ)) (fun node => conditions[node])))

theorem Operand.filterByFixed_eval (value : Operand size .nodes)
    (conditions : Vector (Term .bool) NODE_COUNT) (assignment : Assignment)
    (cells : Fin size -> EntryValue.Entry) :
    NodeSetCodec.decodeNodes ((value.filterByFixed conditions).eval assignment cells) =
      (NodeSetCodec.decodeNodes (value.eval assignment cells)).filter
        (fun node => conditions[node].eval assignment = true) := by
  simp only [Operand.filterByFixed, Operand.eval, NativeNodeOperations.decode_and,
    NativeNodeSets.filter_eval, Term.eval, NodeSetCodec.decode_encode_nodes]
  ext node
  simp

theorem Operand.filterByFixed_references (value : Operand size .nodes)
    (conditions : Vector (Term .bool) NODE_COUNT) :
    (value.filterByFixed conditions).references = value.references := by
  simp [Operand.filterByFixed, Operand.references, Operand.referenceOccurrences]

theorem Operand.filterByFixed_max (value : Operand size .nodes)
    (conditions : Vector (Term .bool) NODE_COUNT) :
    (value.filterByFixed conditions).externalMax =
      max value.externalMax
        ((List.ofFn fun node : Node => SymbolBounds.termMax conditions[node]).foldr max 0) := by
  simp only [Operand.filterByFixed, Operand.externalMax, NativeNodeSets.filter_max,
    SymbolBounds.termMax, Nat.zero_max]

theorem Operand.cardinality_bounds (value : Operand size .nodes) (assignment : Assignment)
    (cells : Fin size -> EntryValue.Entry) :
    0 <= (Operand.cardinality value).eval assignment cells /\
      (Operand.cardinality value).eval assignment cells <= 15 := by
  simpa only [NativeNodeSets.cardinality_eval, Term.eval, Operand.eval] using
    NativeNodeSets.cardinality_bounds assignment (.nodes (value.eval assignment cells))

theorem Operand.lower_text (operand : Operand size ty) (assignment : Assignment)
    (roots base : Nat) (position : InputNat) (nonnegative : 0 <= assignment.constant .int position) :
    SmtExpressionText.eval assignment (operand.lower roots base position).render =
      some (Smt.embed ty (operand.eval assignment (fun version =>
        TypedIntervalEncoding.reads (ty := .entry) assignment base
          (IntervalReadback.Address.version (roots := roots) version) (natValue assignment position)))) := by
  rw [SmtExpressionText.typed_render_eval, operand.lower_correct assignment roots base position nonnegative]

theorem Predicate.lower_text (predicate : Predicate size) (assignment : Assignment)
    (roots base : Nat) (position : InputNat) (nonnegative : 0 <= assignment.constant .int position) :
    SmtScriptText.runText assignment (SmtScript.render [predicate.lower roots base position]) =
      some (predicate.eval assignment (fun version => TypedIntervalEncoding.reads (ty := .entry)
        assignment base (IntervalReadback.Address.version (roots := roots) version)
          (natValue assignment position))) := by
  rw [SmtScriptText.runText_render, SmtScript.compile_eval]
  simp only [List.all_cons, List.all_nil, Bool.and_true,
    predicate.lower_correct assignment roots base position nonnegative]

theorem Operand.assignment_congr (operand : Operand size ty) (left right : Assignment)
    (limit : Nat) (below : operand.externalMax < limit) (cells : Fin size -> EntryValue.Entry)
    (selectors : left.selectors = right.selectors)
    (terms : forall {sort : Ty}, forall term : Term sort, SymbolBounds.termMax term < limit ->
      term.eval left = term.eval right) :
    operand.eval left cells = operand.eval right cells := by
  induction operand with
  | cell _ => rfl
  | input value => exact terms value below
  | decodedInput value => simp only [Operand.eval, terms value below]
  | entryTerm value ih | entryContent value ih | decodedTerm value ih
  | transactionId value ih | configurationNodes value ih | retiredNodes value ih
  | nodesNot value ih | cardinality value ih =>
    simp only [Operand.eval, ih below, selectors]
  | nodesAnd a b ihl ihr | nodesOr a b ihl ihr =>
    have bounds := max_lt_iff.mp below
    simp only [Operand.eval, ihl bounds.1, ihr bounds.2]

theorem Predicate.assignment_congr (predicate : Predicate size) (left right : Assignment)
    (limit : Nat) (below : predicate.externalMax < limit) (cells : Fin size -> EntryValue.Entry)
    (selectors : left.selectors = right.selectors)
    (terms : forall {sort : Ty}, forall term : Term sort, SymbolBounds.termMax term < limit ->
      term.eval left = term.eval right) :
    predicate.eval left cells = predicate.eval right cells := by
  induction predicate with
  | eq a b | ne a b | le a b | lt a b | majority a b =>
    have bounds := max_lt_iff.mp below
    simp only [Predicate.eval, a.assignment_congr left right limit bounds.1 cells selectors terms,
      b.assignment_congr left right limit bounds.2 cells selectors terms]
  | isContent tag value =>
    simp only [Predicate.eval, value.assignment_congr left right limit below cells selectors terms]
  | input value => exact terms value below
  | not value ih => simp only [Predicate.eval, ih below]
  | and a b ihl ihr | implies a b ihl ihr =>
    have bounds := max_lt_iff.mp below
    simp only [Predicate.eval, ihl bounds.1, ihr bounds.2]

def Predicate.member (node : Node) (value : Operand size .nodes) : Predicate size :=
  .eq (.nodesAnd value (.input (.nodes (NodeSetCodec.encodeNodes {node}))))
    (.input (.nodes (NodeSetCodec.encodeNodes {node})))

theorem Predicate.member_eval (node : Node) (value : Operand size .nodes)
    (assignment : Assignment) (cells : Fin size -> EntryValue.Entry) :
    (Predicate.member node value).eval assignment cells =
      decide (Membership.mem (NodeSetCodec.decodeNodes (value.eval assignment cells)) node) := by
  simp only [Predicate.member, Predicate.eval, Operand.eval, Term.eval,
    NativeNodeOperations.and_singleton_iff]

def Predicate.guardedConfigurationMajority (support : Operand size .nodes)
    (content : Operand size .content) : Predicate size :=
  .implies (.isContent .reconfiguration content) (.majority support (.configurationNodes content))

theorem Predicate.majority_model (support configuration : Operand size .nodes)
    (assignment : Assignment) (cells : Fin size -> EntryValue.Entry) (index : Nat) :
    (Predicate.majority support configuration).eval assignment cells =
      decide (hasConfigurationMajority (NodeSetCodec.decodeNodes (support.eval assignment cells))
        { index := index, nodes := NodeSetCodec.decodeNodes (configuration.eval assignment cells) }) := rfl

theorem Predicate.guardedConfigurationMajority_eval (support : Operand size .nodes)
    (content : Operand size .content) (assignment : Assignment) (cells : Fin size -> EntryValue.Entry) :
    (Predicate.guardedConfigurationMajority support content).eval assignment cells =
      match content.eval assignment cells with
      | .reconfiguration mask => decide (hasConfigurationMajority
          (NodeSetCodec.decodeNodes (support.eval assignment cells))
          { index := 0, nodes := NodeSetCodec.decodeNodes mask })
      | _ => true := by
  cases h : content.eval assignment cells <;>
    simp [Predicate.guardedConfigurationMajority, Predicate.eval, Operand.eval, h,
      Smt.ContentTag.test, EntryValue.Content.isReconfiguration, EntryValue.Content.reconfiguration?]

theorem decoded_entry_eq_iff (assignment : Assignment) (cells : Fin size -> EntryValue.Entry)
    (left right : Operand size .entry) :
    (Predicate.eq left right).eval assignment cells = true <->
      EntryValue.decodeEntry (left.eval assignment cells) = EntryValue.decodeEntry (right.eval assignment cells) := by
  simp [Predicate.eval, EntryValue.decode_entry_eq_iff]

theorem decoded_entry_ne_iff (assignment : Assignment) (cells : Fin size -> EntryValue.Entry)
    (left right : Operand size .entry) :
    (Predicate.ne left right).eval assignment cells = true <->
      Not (EntryValue.decodeEntry (left.eval assignment cells) = EntryValue.decodeEntry (right.eval assignment cells)) := by
  simp [Predicate.eval, EntryValue.decode_entry_eq_iff]

theorem decoded_term_lt_iff (assignment : Assignment) (cells : Fin size -> EntryValue.Entry)
    (left right : Operand size .entry) :
    (Predicate.lt (.decodedTerm left) (.decodedTerm right)).eval assignment cells = true <->
      (EntryValue.decodeEntry (left.eval assignment cells)).term < (EntryValue.decodeEntry (right.eval assignment cells)).term := by
  simp [Predicate.eval, Operand.eval, EntryValue.decode_entry_term]

theorem decoded_term_le_iff (assignment : Assignment) (cells : Fin size -> EntryValue.Entry)
    (left right : Operand size .entry) :
    (Predicate.le (.decodedTerm left) (.decodedTerm right)).eval assignment cells = true <->
      (EntryValue.decodeEntry (left.eval assignment cells)).term <= (EntryValue.decodeEntry (right.eval assignment cells)).term := by
  simp [Predicate.eval, Operand.eval, EntryValue.decode_entry_term]

theorem decoded_input_lt_iff (assignment : Assignment) (cells : Fin size -> EntryValue.Entry)
    (left right : Term .int) :
    (Predicate.lt (.decodedInput left) (.decodedInput right)).eval assignment cells = true <->
      BijectiveIntegerLog.decodeNat (left.eval assignment) < BijectiveIntegerLog.decodeNat (right.eval assignment) := by
  simp [Predicate.eval, Operand.eval]

theorem decoded_input_le_iff (assignment : Assignment) (cells : Fin size -> EntryValue.Entry)
    (left right : Term .int) :
    (Predicate.le (.decodedInput left) (.decodedInput right)).eval assignment cells = true <->
      BijectiveIntegerLog.decodeNat (left.eval assignment) <= BijectiveIntegerLog.decodeNat (right.eval assignment) := by
  simp [Predicate.eval, Operand.eval]

def references (predicates : List (Predicate size)) : List (Fin size) :=
  (predicates.flatMap Predicate.referenceOccurrences).dedup

theorem references_mem (predicates : List (Predicate size)) (version : Fin size) :
    Membership.mem (references predicates) version <->
      exists predicate, Membership.mem predicates predicate /\ Membership.mem predicate.references version := by
  simp [references, Predicate.references]

theorem references_nodup (predicates : List (Predicate size)) : (references predicates).Nodup :=
  List.nodup_dedup _

structure Query (size : Nat) where
  lower : InputNat
  upper : InputNat
  predicate : Predicate size

def Query.externalMax (query : Query size) : Nat :=
  max query.lower (max query.upper query.predicate.externalMax)

theorem Query.bounds (query : Query size) :
    query.lower <= query.externalMax /\ query.upper <= query.externalMax /\ query.predicate.externalMax <= query.externalMax := by
  unfold Query.externalMax
  exact And.intro (Nat.le_max_left _ _)
    (And.intro (Nat.le_trans (Nat.le_max_left _ _) (Nat.le_max_right _ _))
      (Nat.le_trans (Nat.le_max_right _ _) (Nat.le_max_right _ _)))

def Query.toLocalQuery (assignment : Assignment) (query : Query size) : IntervalQueries.LocalQuery size EntryValue.Entry where
  lower := natValue assignment query.lower
  upper := natValue assignment query.upper
  accepts cells := query.predicate.eval assignment cells = true
  references := query.predicate.references
  locality left right agree := by rw [query.predicate.locality assignment left right agree]

theorem Query.inside_iff (query : Query size) (assignment : Assignment) (position : InputNat)
    (lower_nonnegative : 0 <= assignment.constant .int query.lower)
    (upper_nonnegative : 0 <= assignment.constant .int query.upper)
    (position_nonnegative : 0 <= assignment.constant .int position) :
    (query.toLocalQuery assignment).toQuery.Inside (natValue assignment position) <->
      assignment.constant .int query.lower <= assignment.constant .int position /\
      assignment.constant .int position < assignment.constant .int query.upper := by
  simp only [Query.toLocalQuery, VersionedIntervals.Query.Inside, natValue]
  rw [<- Int.ofNat_le, <- Int.ofNat_lt, Int.toNat_of_nonneg lower_nonnegative,
    Int.toNat_of_nonneg upper_nonnegative, Int.toNat_of_nonneg position_nonnegative]

namespace Regression

def signature : EntryValue.Entry := { term := -1, content := .signature }
def transaction : EntryValue.Entry := { term := 0, content := .transaction (-1) }

def cells (version : Fin 2) : EntryValue.Entry :=
  if version = 0 then signature else transaction

def repeated : Predicate 2 :=
  .and (.eq (.cell 0) (.cell 0))
    (.implies (.input (.boolean true)) (.ne (.cell 1) (.cell 0)))

theorem repeated_references :
    repeated.referenceOccurrences.length = 4 /\ repeated.references.length = 2 /\
      (references [repeated, repeated]).length = 2 /\
      repeated.references.toFinset = {0, 1} := by
  decide +kernel

theorem total_projections_and_constructors (assignment : Assignment) :
    (Predicate.and
      (.eq (.entryTerm (.cell 0)) (.input (.integer (-1))))
      (.and (.eq (.entryContent (.cell 0)) (.input .signature))
        (.eq (.entryContent (.cell 1)) (.input (.transaction (.integer (-1))))))).eval assignment cells = true := by
  dsimp only [Predicate.eval, Operand.eval, Term.eval]
  decide +kernel

theorem complete_masks (assignment : Assignment) (mask : BitVec NODE_COUNT) :
    (Predicate.eq (size := 0)
      (.entryContent (.input (.entry (.integer (-1)) (.reconfiguration (.nodes mask)))))
      (.input (.reconfiguration (.nodes mask)))).eval assignment (fun version => Fin.elim0 version) = true /\
    (Predicate.ne (size := 0)
      (.input (.entry (.integer (-1)) (.reconfiguration (.nodes mask))))
      (.input (.entry (.integer (-1)) (.retiredCommitted (.nodes mask))))).eval
        assignment (fun version => Fin.elim0 version) = true := by
  simp [Predicate.eval, Operand.eval, Term.eval]

theorem raw_and_decoded_order (assignment : Assignment) :
    (Predicate.lt (.entryTerm (.cell 0)) (.entryTerm (.cell 1))).eval assignment cells = true /\
      (Predicate.lt (.decodedTerm (.cell 0)) (.decodedTerm (.cell 1))).eval assignment cells = false /\
      (Predicate.le (.decodedTerm (.cell 1)) (.decodedTerm (.cell 0))).eval assignment cells = true := by
  dsimp only [Predicate.eval, Operand.eval]
  decide +kernel

theorem mathematical_int_not_code (assignment : Assignment) :
    (Predicate.eq (size := 0) (.input (.integer 1)) (.decodedInput (.integer (-1)))).eval
        assignment (fun version => Fin.elim0 version) = true /\
      (Predicate.eq (size := 0) (.input (.integer 1)) (.decodedInput (.integer 1))).eval
        assignment (fun version => Fin.elim0 version) = false := by
  dsimp only [Predicate.eval, Operand.eval, Term.eval]
  decide +kernel

def disabled : Predicate 2 :=
  .implies (.input (.boolean false))
    (.eq (.cell 0) (.input (.entry (.unknown .int 99)
      (.reconfiguration (.app .nodes .nodes 1000 (.unknown .nodes 4))))))

theorem disabled_guard_keeps_metadata (assignment : Assignment) (values : Fin 2 -> EntryValue.Entry) :
    disabled.references = [0] /\ disabled.externalMax = 1000 /\ disabled.eval assignment values = true := by
  refine And.intro (by decide +kernel) (And.intro (by decide +kernel) ?_)
  simp [disabled, Predicate.eval, Term.eval]

def external : Predicate 0 :=
  .input (.equal (.app .int .entry 900 (IntervalEncoding.natTerm 17))
    (.entry (.integer (-1)) .signature))

theorem fixed_external_function (roots base left right : Nat) :
    external.references = [] /\ external.externalMax = 900 /\
      external.lower roots base left = external.lower roots base right := by
  exact And.intro (by decide +kernel) (And.intro (by decide +kernel) rfl)

theorem symbolic_position_aliases (predicate : Predicate size) (roots base : Nat) :
    (predicate.lower roots base 0).eval (TypedIntervalEncoding.Regression.fixtureAssignment 0 0 0) =
      (predicate.lower roots base 1).eval (TypedIntervalEncoding.Regression.fixtureAssignment 0 0 0) :=
  predicate.lower_alias _ roots base 0 1 (by decide +kernel) (by decide +kernel) rfl

def falseQuery : Query 0 :=
  { lower := 0, upper := 1, predicate := .input (.boolean false) }

theorem empty_or_reversed (lower upper : Nat) (reversed : upper <= lower) :
    falseQuery.predicate.references = [] /\
      forall index, Not ((falseQuery.toLocalQuery
        (TypedIntervalEncoding.Regression.fixtureAssignment lower upper 0)).toQuery.Inside index) := by
  refine And.intro (by decide +kernel) ?_
  intro index active
  have bounds : lower <= index /\ index < upper := by
    simpa [falseQuery, Query.toLocalQuery, VersionedIntervals.Query.Inside, natValue,
      TypedIntervalEncoding.Regression.fixtureAssignment] using active
  omega

def twoRoots : VersionedIntervals.Graph 2 EntryValue.Entry 2 :=
  .push (.push .empty (.root 0)) (.root 1)

def arrays (root : Fin 2) (position : Nat) : EntryValue.Entry :=
  if root = 1 /\ position = 1 then transaction else signature

def sameEntry : Predicate 2 := .eq (.cell 0) (.cell 1)
def differentEntry : Predicate 2 := .ne (.cell 0) (.cell 1)

-- Concrete semantic example only, not an existential-query encoding.
theorem interior_mismatch (assignment : Assignment) :
    arrays 0 0 = signature /\ arrays 1 0 = signature /\
      (forall cut, Membership.mem [0, 2] cut -> cut < 2 ->
        sameEntry.eval assignment (VersionedIntervals.evaluate twoRoots arrays cut) = true) /\
      differentEntry.eval assignment (VersionedIntervals.evaluate twoRoots arrays 0) = false /\
      differentEntry.eval assignment (VersionedIntervals.evaluate twoRoots arrays 1) = true := by
  refine And.intro rfl (And.intro rfl (And.intro ?_ (And.intro ?_ ?_)))
  next =>
    intro cut member bound
    have endpoints : cut = 0 \/ cut = 2 := by simpa using member
    have zero : cut = 0 := by omega
    subst cut
    dsimp only [sameEntry, Predicate.eval, Operand.eval]
    decide +kernel
  next => dsimp only [differentEntry, Predicate.eval, Operand.eval]; decide +kernel
  next => dsimp only [differentEntry, Predicate.eval, Operand.eval]; decide +kernel

def nativeCells (mask : BitVec NODE_COUNT) (version : Fin 2) : EntryValue.Entry :=
  { term := -1, content := if version = 0 then .reconfiguration mask else .retiredCommitted mask }

theorem native_matching_masks (assignment : Assignment) (mask : BitVec NODE_COUNT) :
    (Operand.configurationNodes (.entryContent (.cell (0 : Fin 2)))).eval assignment (nativeCells mask) = mask /\
    (Operand.retiredNodes (.entryContent (.cell (1 : Fin 2)))).eval assignment (nativeCells mask) = mask /\
    (Predicate.isContent .reconfiguration (.entryContent (.cell (0 : Fin 2)))).eval assignment (nativeCells mask) = true /\
    (Predicate.isContent .retiredCommitted (.entryContent (.cell (1 : Fin 2)))).eval assignment (nativeCells mask) = true := by
  simp [nativeCells, Operand.eval, Predicate.eval, Smt.ContentTag.test,
    EntryValue.Content.isReconfiguration, EntryValue.Content.reconfiguration?,
    EntryValue.Content.isRetiredCommitted, EntryValue.Content.retiredCommitted?]

theorem raw_transaction_and_wrong_selectors (assignment : Assignment) :
    (Operand.transactionId (.entryContent (.cell (1 : Fin 2)))).eval assignment cells = -1 /\
    (Operand.transactionId (.entryContent (.cell (0 : Fin 2)))).eval assignment cells =
      assignment.selectors.txWrong .signature /\
    (Operand.configurationNodes (.entryContent (.cell (0 : Fin 2)))).eval assignment cells =
      assignment.selectors.cfgWrong .signature /\
    (Operand.retiredNodes (.entryContent (.cell (0 : Fin 2)))).eval assignment cells =
      assignment.selectors.retiredWrong .signature := by
  exact And.intro rfl (And.intro rfl (And.intro rfl rfl))

theorem nested_wrong_count (assignment : Assignment) :
    (Operand.cardinality (.nodesNot (.configurationNodes (.entryContent (.cell (0 : Fin 2)))))).eval
        assignment cells =
      Int.ofNat (NodeSetCodec.decodeNodes (~~~(assignment.selectors.cfgWrong .signature))).card := rfl

theorem every_node_membership (assignment : Assignment) (node other : Node) :
    (Predicate.member node (.configurationNodes (.entryContent (.cell (0 : Fin 2))))).eval
        assignment (nativeCells (NodeSetCodec.encodeNodes {other})) = decide (node = other) := by
  rw [Predicate.member_eval]
  simp [Operand.eval, nativeCells]

theorem every_node_cardinality (assignment : Assignment) (node : Node) :
    (Operand.cardinality (.retiredNodes (.entryContent (.cell (1 : Fin 2))))).eval
        assignment (nativeCells (NodeSetCodec.encodeNodes {node})) = 1 := by
  simp [Operand.eval, nativeCells]

theorem native_algebra (assignment : Assignment) (values : Fin size -> EntryValue.Entry)
    (a b : BitVec NODE_COUNT) :
    (Operand.nodesAnd (size := size) (.input (.nodes a)) (.input (.nodes b))).eval assignment values = a &&& b /\
    (Operand.nodesOr (size := size) (.input (.nodes a)) (.input (.nodes b))).eval assignment values = a ||| b /\
    (Operand.nodesNot (size := size) (.input (.nodes a))).eval assignment values = ~~~a := by
  exact And.intro rfl (And.intro rfl rfl)

theorem cardinality_is_not_decoded (assignment : Assignment) (values : Fin size -> EntryValue.Entry) :
    (Operand.cardinality (size := size) (.input (.nodes 0))).eval assignment values = 0 /\
    (Operand.cardinality (size := size) (.input (.nodes 32767))).eval assignment values = 15 /\
    (Operand.cardinality (size := size) (.input (.nodes 1))).eval assignment values = 1 /\
    (Operand.decodedInput (size := size) (.integer 1)).eval assignment values = 2 := by
  simp only [Operand.eval, Term.eval, NodeSetCodec.decode_zero, NativeNodeSets.decode_full,
    Finset.card_empty, Finset.card_univ, NodeSetCodec.node_card]
  decide +kernel

theorem skip_is_not_empty_configuration (assignment : Assignment) (support : Operand size .nodes)
    (values : Fin size -> EntryValue.Entry) :
    (Predicate.guardedConfigurationMajority support (.input .signature)).eval assignment values = true /\
    (Predicate.guardedConfigurationMajority support (.input (.reconfiguration (.nodes 0)))).eval
      assignment values = false := by
  simp only [Predicate.guardedConfigurationMajority_eval, Operand.eval, Term.eval,
    hasConfigurationMajority, NodeSetCodec.decode_zero, Finset.inter_empty,
    Finset.card_empty, Nat.zero_mul, Nat.lt_irrefl, decide_false]
  simp

theorem majority_tie_and_outsiders (assignment : Assignment) (values : Fin size -> EntryValue.Entry) :
    (Predicate.majority (size := size) (.input (.nodes 1)) (.input (.nodes 16385))).eval assignment values = false /\
    (Predicate.majority (size := size) (.input (.nodes 16385)) (.input (.nodes 16385))).eval assignment values = true /\
    (Predicate.majority (size := size) (.input (.nodes 3)) (.input (.nodes 16387))).eval assignment values = true /\
    (Predicate.majority (size := size) (.input (.nodes 16384)) (.input (.nodes 3))).eval assignment values = false := by
  simpa only [Predicate.eval, Operand.eval, Term.eval, decide_eq_false_iff_not, decide_eq_true_eq] using
    And.intro NativeNodeSets.model_controls.1 (And.intro NativeNodeSets.model_controls.2.1
      (And.intro NativeNodeSets.model_controls.2.2.1 NativeNodeSets.model_controls.2.2.2.1))

theorem fixed_filter_positions (assignment : Assignment) (value : Operand size .nodes)
    (values : Fin size -> EntryValue.Entry) (selected : Node) :
    (value.filterByFixed (Vector.ofFn fun node => .boolean (decide (node = selected)))).eval
        assignment values =
      (Operand.nodesAnd value (.input (.nodes (NodeSetCodec.encodeNodes {selected})))).eval assignment values := by
  rw [<- NodeSetCodec.bits_eq_iff, Operand.filterByFixed_eval]
  simp only [Operand.eval, Term.eval, NativeNodeOperations.decode_and, NodeSetCodec.decode_encode_nodes]
  ext node
  simp [Term.eval]

theorem aliased_native_references (assignment : Assignment) (values : Fin 2 -> EntryValue.Entry)
    (same : values 0 = values 1) :
    (Predicate.ne (.configurationNodes (.entryContent (.cell (0 : Fin 2))))
      (.configurationNodes (.entryContent (.cell (1 : Fin 2))))).eval assignment values = false := by
  simp [Predicate.eval, Operand.eval, same]

def inactiveConditions : Vector (Term .bool) NODE_COUNT :=
  Vector.ofFn fun _ => .ite (.boolean false)
    (.app .nodes .bool 1000000 (.configurationNodes (.unknown .content 99))) (.boolean false)

def nativeInactive : Predicate 2 :=
  .implies (.input (.boolean false))
    (.majority ((Operand.configurationNodes (.entryContent (.cell 0))).filterByFixed inactiveConditions)
      (.retiredNodes (.entryContent (.cell 1))))

theorem inactive_native_metadata :
    nativeInactive.references = [0, 1] /\ nativeInactive.externalMax = 1000000 := by
  constructor
  next => simp [nativeInactive, Predicate.references, Predicate.referenceOccurrences,
    Operand.filterByFixed, Operand.referenceOccurrences]
  next =>
    simp only [nativeInactive, Predicate.externalMax, Operand.filterByFixed_max,
      Operand.externalMax, SymbolBounds.termMax]
    simp [inactiveConditions, NODE_COUNT, SymbolBounds.termMax]

theorem inactive_native_holds (assignment : Assignment) (values : Fin 2 -> EntryValue.Entry) :
    nativeInactive.eval assignment values = true := rfl

theorem filter_conditions_fixed (roots base left right : Nat) :
    ((Operand.input (size := 0) (.nodes 32767)).filterByFixed inactiveConditions).lower roots base left =
      ((Operand.input (size := 0) (.nodes 32767)).filterByFixed inactiveConditions).lower roots base right := rfl

end Regression

end CCFRaft.Sparse.EntryPredicate

run_cmd do
  let mut checked := 0
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.Sparse.EntryPredicate).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
      checked := checked + 1
  Lean.logInfo m!"Sparse.EntryPredicate: allowed-axiom gate passed for {checked} declarations."

#print axioms CCFRaft.Sparse.EntryPredicate.Predicate.lower_correct
#print axioms CCFRaft.Sparse.EntryPredicate.Predicate.locality
#print axioms CCFRaft.Sparse.EntryPredicate.decoded_term_lt_iff
