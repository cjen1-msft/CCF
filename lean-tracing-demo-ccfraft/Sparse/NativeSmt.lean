-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeSExpr

set_option autoImplicit false

namespace CCFRaft.NativeSmt

inductive Ty where
  | bool | int | unit
  | bits (width : PNat)
  | array (key value : Ty)
  | pair (first second : Ty)
  | sum (left right : Ty)
  deriving DecidableEq, Repr

abbrev Ty.denote : Ty -> Type
  | .bool => Bool
  | .int => Int
  | .unit => Unit
  | .bits width => BitVec width
  | .array key value => key.denote -> value.denote
  | .pair first second => first.denote × second.denote
  | .sum left right => Sum left.denote right.denote

def Ty.default : (sort : Ty) -> sort.denote
  | .bool => false
  | .int => 0
  | .unit => ()
  | .bits _ => 0
  | .array _ value => fun _ => value.default
  | .pair first second => (first.default, second.default)
  | .sum left _ => .inl left.default

def Ty.code : Ty -> String
  | .bool => "B"
  | .int => "I"
  | .unit => "U"
  | .bits width => s!"V{width.val}_"
  | .array key value => "A" ++ key.code ++ value.code
  | .pair first second => "P" ++ first.code ++ second.code
  | .sum left right => "S" ++ left.code ++ right.code

def Ty.syntax : Ty -> NativeSExpr.Expr
  | .bool => .atom "Bool"
  | .int => .atom "Int"
  | .unit => .atom "NativeUnit"
  | .bits width => .list [.atom "_", .atom "BitVec", .atom (toString width.val)]
  | .array key value => .list [.atom "Array", key.syntax, value.syntax]
  | .pair first second => .list [.atom "NativePair", first.syntax, second.syntax]
  | .sum left right => .list [.atom "NativeSum", left.syntax, right.syntax]

def Ty.render (sort : Ty) : String := sort.syntax.render

inductive Variable : List Ty -> Ty -> Type where
  | here {context : List Ty} {sort : Ty} : Variable (sort :: context) sort
  | there {context : List Ty} {sort other : Ty} :
      Variable context sort -> Variable (other :: context) sort

def Variable.index {context : List Ty} {sort : Ty} : Variable context sort -> Nat
  | .here => 0
  | .there ref => ref.index + 1

theorem Variable.index_lt {context : List Ty} {sort : Ty} (ref : Variable context sort) :
    ref.index < context.length := by
  induction ref <;> simp_all [index]

abbrev Assignment := (sort : Ty) -> Nat -> sort.denote
abbrev Locals (context : List Ty) := (sort : Ty) -> Variable context sort -> sort.denote

def Assignment.default : Assignment := fun sort _ => sort.default

def Locals.empty : Locals [] := fun _ ref => nomatch ref

def Locals.cons {context : List Ty} {sort : Ty}
    (locals : Locals context) (value : sort.denote) : Locals (sort :: context) :=
  fun _ ref => match ref with
    | .here => value
    | .there ref => locals _ ref

inductive Term : List Ty -> Ty -> Type where
  | boolean {context : List Ty} (value : Bool) : Term context .bool
  | integer {context : List Ty} (value : Int) : Term context .int
  | unit {context : List Ty} : Term context .unit
  | bits {context : List Ty} {width : PNat} (value : BitVec width) : Term context (.bits width)
  | free {context : List Ty} (sort : Ty) (id : Nat) : Term context sort
  | bound {context : List Ty} {sort : Ty} (ref : Variable context sort) : Term context sort
  | add {context : List Ty} (left right : Term context .int) : Term context .int
  | sub {context : List Ty} (left right : Term context .int) : Term context .int
  | le {context : List Ty} (left right : Term context .int) : Term context .bool
  | equal {context : List Ty} {sort : Ty} (left right : Term context sort) : Term context .bool
  | not {context : List Ty} (value : Term context .bool) : Term context .bool
  | and {context : List Ty} (left right : Term context .bool) : Term context .bool
  | or {context : List Ty} (left right : Term context .bool) : Term context .bool
  | ite {context : List Ty} {sort : Ty} (condition : Term context .bool) (yes no : Term context sort) : Term context sort
  | forall_ {context : List Ty} (sort : Ty) (body : Term (sort :: context) .bool) : Term context .bool
  | select {context : List Ty} {key value : Ty} (array : Term context (.array key value)) (index : Term context key) :
      Term context value
  | store {context : List Ty} {key value : Ty} (array : Term context (.array key value))
      (index : Term context key) (element : Term context value) : Term context (.array key value)
  | pair {context : List Ty} {first second : Ty} (left : Term context first) (right : Term context second) :
      Term context (.pair first second)
  | fst {context : List Ty} {first second : Ty} (value : Term context (.pair first second)) : Term context first
  | snd {context : List Ty} {first second : Ty} (value : Term context (.pair first second)) : Term context second
  | inl {context : List Ty} {first second : Ty} (value : Term context first) : Term context (.sum first second)
  | inr {context : List Ty} {first second : Ty} (value : Term context second) : Term context (.sum first second)
  | cases {context : List Ty} {first second result : Ty} (value : Term context (.sum first second))
      (left : Term (first :: context) result) (right : Term (second :: context) result) : Term context result
  | bitsAnd {context : List Ty} {width : PNat} (left right : Term context (.bits width)) : Term context (.bits width)
  | bitsOr {context : List Ty} {width : PNat} (left right : Term context (.bits width)) : Term context (.bits width)
  | bitsNot {context : List Ty} {width : PNat} (value : Term context (.bits width)) : Term context (.bits width)
  | bit {context : List Ty} {width : PNat} (value : Term context (.bits width)) (index : Fin width) : Term context .bool

attribute [local instance] Classical.propDecidable

noncomputable def Term.eval (assignment : Assignment) :
    {context : List Ty} -> {sort : Ty} -> Locals context -> Term context sort -> sort.denote
  | _, _, _, .boolean value => value
  | _, _, _, .integer value => value
  | _, _, _, .unit => ()
  | _, _, _, .bits value => value
  | _, _, _, .free sort id => assignment sort id
  | _, _, locals, .bound ref => locals _ ref
  | _, _, locals, .add left right => left.eval assignment locals + right.eval assignment locals
  | _, _, locals, .sub left right => left.eval assignment locals - right.eval assignment locals
  | _, _, locals, .le left right => decide (left.eval assignment locals <= right.eval assignment locals)
  | _, _, locals, .equal left right => decide (left.eval assignment locals = right.eval assignment locals)
  | _, _, locals, .not value => !(value.eval assignment locals)
  | _, _, locals, .and left right => left.eval assignment locals && right.eval assignment locals
  | _, _, locals, .or left right => left.eval assignment locals || right.eval assignment locals
  | _, _, locals, .ite condition yes no =>
      if condition.eval assignment locals then yes.eval assignment locals else no.eval assignment locals
  | _, _, locals, .forall_ sort body =>
      decide (forall value : sort.denote, body.eval assignment (locals.cons value) = true)
  | _, _, locals, .select array index => array.eval assignment locals (index.eval assignment locals)
  | _, _, locals, .store array index element =>
      Function.update (array.eval assignment locals) (index.eval assignment locals) (element.eval assignment locals)
  | _, _, locals, .pair left right => (left.eval assignment locals, right.eval assignment locals)
  | _, _, locals, .fst value => (value.eval assignment locals).1
  | _, _, locals, .snd value => (value.eval assignment locals).2
  | _, _, locals, .inl value => Sum.inl (value.eval assignment locals)
  | _, _, locals, .inr value => Sum.inr (value.eval assignment locals)
  | _, _, locals, .cases value left right =>
      match value.eval assignment locals with
      | Sum.inl value => left.eval assignment (locals.cons value)
      | Sum.inr value => right.eval assignment (locals.cons value)
  | _, _, locals, .bitsAnd left right => left.eval assignment locals &&& right.eval assignment locals
  | _, _, locals, .bitsOr left right => left.eval assignment locals ||| right.eval assignment locals
  | _, _, locals, .bitsNot value => ~~~(value.eval assignment locals)
  | _, _, locals, .bit value index => (value.eval assignment locals).getLsbD index

def symbolName (sort : Ty) (id : Nat) : String := s!"c_{sort.code}_{id}"

def Term.syntax : {context : List Ty} -> {sort : Ty} -> Term context sort -> NativeSExpr.Expr
  | _, _, .boolean value => .atom (if value then "true" else "false")
  | _, _, .integer (.ofNat value) => .atom (toString value)
  | _, _, .integer (.negSucc value) => .list [.atom "-", .atom (toString (value + 1))]
  | _, _, .unit => .atom "native_unit"
  | _, _, .bits (width := width) value =>
    .list [.atom "_", .atom s!"bv{value.toNat}", .atom (toString width.val)]
  | _, _, .free sort id => .atom (symbolName sort id)
  | context, _, .bound ref => .atom s!"b{context.length - (ref.index + 1)}"
  | _, _, .add left right => .list [.atom "+", left.syntax, right.syntax]
  | _, _, .sub left right => .list [.atom "-", left.syntax, right.syntax]
  | _, _, .le left right => .list [.atom "<=", left.syntax, right.syntax]
  | _, _, .equal left right => .list [.atom "=", left.syntax, right.syntax]
  | _, _, .not value => .list [.atom "not", value.syntax]
  | _, _, .and left right => .list [.atom "and", left.syntax, right.syntax]
  | _, _, .or left right => .list [.atom "or", left.syntax, right.syntax]
  | _, _, .ite condition yes no => .list [.atom "ite", condition.syntax, yes.syntax, no.syntax]
  | context, _, .forall_ sort body =>
    .list [.atom "forall", .list [.list [.atom s!"b{context.length}", sort.syntax]], body.syntax]
  | _, _, .select array index => .list [.atom "select", array.syntax, index.syntax]
  | _, _, .store array index value => .list [.atom "store", array.syntax, index.syntax, value.syntax]
  | _, _, .pair left right => .list [.atom "native_pair", left.syntax, right.syntax]
  | _, _, .fst value => .list [.atom "native_fst", value.syntax]
  | _, _, .snd value => .list [.atom "native_snd", value.syntax]
  | _, .sum first second, .inl value =>
    .list [.list [.atom "as", .atom "native_left", (Ty.sum first second).syntax], value.syntax]
  | _, .sum first second, .inr value =>
    .list [.list [.atom "as", .atom "native_right", (Ty.sum first second).syntax], value.syntax]
  | context, _, .cases value left right =>
    .list [.atom "match", value.syntax, .list [
      .list [.list [.atom "native_left", .atom s!"b{context.length}"], left.syntax],
      .list [.list [.atom "native_right", .atom s!"b{context.length}"], right.syntax]]]
  | _, _, .bitsAnd left right => .list [.atom "bvand", left.syntax, right.syntax]
  | _, _, .bitsOr left right => .list [.atom "bvor", left.syntax, right.syntax]
  | _, _, .bitsNot value => .list [.atom "bvnot", value.syntax]
  | _, _, .bit value index =>
    .list [.atom "=", .list [.list [
      .atom "_", .atom "extract", .atom (toString index.val), .atom (toString index.val)], value.syntax], .atom "#b1"]

def Term.render {context : List Ty} {sort : Ty} (expression : Term context sort) : String :=
  expression.syntax.render

def prelude : List String := [
  "(set-logic ALL)",
  "(declare-datatype NativeUnit ((native_unit)))",
  "(declare-datatypes ((NativePair 2)) ((par (A B) ((native_pair (native_fst A) (native_snd B))))))",
  "(declare-datatypes ((NativeSum 2)) ((par (A B) ((native_left (native_left_value A)) (native_right (native_right_value B))))))"]

def Term.symbols : {context : List Ty} -> {sort : Ty} -> Term context sort -> List (Ty × Nat)
  | _, _, .free sort id => [(sort, id)]
  | _, _, .boolean _ | _, _, .integer _ | _, _, .unit | _, _, .bits _ | _, _, .bound _ => []
  | _, _, .add left right | _, _, .sub left right | _, _, .le left right
  | _, _, .equal left right | _, _, .and left right | _, _, .or left right
  | _, _, .select left right | _, _, .pair left right
  | _, _, .bitsAnd left right | _, _, .bitsOr left right => left.symbols ++ right.symbols
  | _, _, .not value | _, _, .forall_ _ value
  | _, _, .fst value | _, _, .snd value | _, _, .inl value | _, _, .inr value
  | _, _, .bitsNot value | _, _, .bit value _ => value.symbols
  | _, _, .ite first second third | _, _, .store first second third
  | _, _, .cases first second third => first.symbols ++ second.symbols ++ third.symbols

def assertionName (index : Nat) : String := s!"assertion_{index}"

def renderScript (assertions : List (Term [] .bool)) (named : Bool := false) : String :=
  let symbols := (assertions.flatMap Term.symbols).dedup
  let declarations := symbols.map fun (sort, id) =>
    s!"(declare-const {symbolName sort id} {sort.render})"
  String.intercalate "\n" (prelude ++ declarations ++
    assertions.mapIdx (fun index expression =>
      if named then s!"(assert (! {expression.render} :named {assertionName index}))"
      else s!"(assert {expression.render})") ++ ["(check-sat)", ""])

theorem select_store (assignment : Assignment) {context : List Ty} {key value : Ty}
    (locals : Locals context) (array : Term context (.array key value))
    (index : Term context key) (element : Term context value) :
    (Term.select (Term.store array index element) index).eval assignment locals =
      element.eval assignment locals := by
  simp [Term.eval]

theorem Term.eval_congr {context : List Ty} {sort : Ty} (expression : Term context sort)
    (left right : Assignment) (locals : Locals context)
    (same : forall ty id, (ty, id) ∈ expression.symbols -> left ty id = right ty id) :
    expression.eval left locals = expression.eval right locals := by
  match expression with
  | .boolean _ | .integer _ | .unit | .bits _ | .bound _ => rfl
  | .free ty id => exact same ty id (by simp [symbols])
  | .add first second | .sub first second | .le first second
  | .equal first second | .and first second | .or first second
  | .select first second | .pair first second
  | .bitsAnd first second | .bitsOr first second =>
    simp only [symbols, List.mem_append, or_imp, forall_and] at same
    simp only [eval, eval_congr first left right locals same.1,
      eval_congr second left right locals same.2]
  | .not value | .fst value | .snd value | .inl value | .inr value
  | .bitsNot value | .bit value _ =>
    simp only [symbols] at same
    simp only [eval, eval_congr value left right locals same]
  | .ite first second third | .store first second third =>
    simp only [symbols, List.mem_append, or_imp, forall_and] at same
    simp only [eval, eval_congr first left right locals same.1.1,
      eval_congr second left right locals same.1.2,
      eval_congr third left right locals same.2]
  | .forall_ _ body =>
    simp only [symbols] at same
    simp only [eval]
    simp_rw [eval_congr body left right _ same]
  | .cases value first second =>
    simp only [symbols, List.mem_append, or_imp, forall_and] at same
    simp only [eval, eval_congr value left right locals same.1.1]
    cases value.eval right locals with
    | inl argument => exact eval_congr first left right (locals.cons argument) same.1.2
    | inr argument => exact eval_congr second left right (locals.cons argument) same.2
termination_by structural expression

def Assignment.set (assignment : Assignment) (sort : Ty) (id : Nat) (value : sort.denote) : Assignment :=
  Function.update assignment sort (Function.update (assignment sort) id value)

theorem Term.eval_set_of_fresh {context : List Ty} {sort updated : Ty}
    (expression : Term context sort) (assignment : Assignment) (locals : Locals context)
    (id : Nat) (value : updated.denote) (fresh : (updated, id) ∉ expression.symbols) :
    expression.eval (assignment.set updated id value) locals = expression.eval assignment locals := by
  apply expression.eval_congr
  intro ty name occurs
  by_cases sameSort : ty = updated
  · subst ty
    have different : name ≠ id := by
      intro same
      subst name
      exact fresh occurs
    simp [Assignment.set, different]
  · simp [Assignment.set, sameSort]

def Holds (assertions : List (Term [] .bool)) (assignment : Assignment) : Prop :=
  forall formula, formula ∈ assertions -> formula.eval assignment Locals.empty = true

def Assignment.AgreesBelow (limit : Nat) (left right : Assignment) : Prop :=
  forall sort id, id < limit -> left sort id = right sort id

theorem Assignment.AgreesBelow.trans {limit : Nat} {first middle last : Assignment}
    (left : first.AgreesBelow limit middle) (right : middle.AgreesBelow limit last) :
    first.AgreesBelow limit last :=
  fun sort id within => (left sort id within).trans (right sort id within)

theorem Assignment.AgreesBelow.restrict {small large : Nat} {left right : Assignment}
    (same : left.AgreesBelow large right) (within : small <= large) :
    left.AgreesBelow small right :=
  fun sort id bound => same sort id (Nat.lt_of_lt_of_le bound within)

theorem Assignment.agrees_below_set (assignment : Assignment) (limit : Nat) (sort : Ty)
    (id : Nat) (value : sort.denote) (fresh : limit <= id) :
    assignment.AgreesBelow limit (assignment.set sort id value) := by
  intro other index within
  by_cases same : other = sort
  · subst other
    have different : index ≠ id := by omega
    simp [Assignment.set, different]
  · simp [Assignment.set, same]

theorem Term.eval_agrees_below {context : List Ty} {sort : Ty} (expression : Term context sort)
    (left right : Assignment) (locals : Locals context) (limit : Nat)
    (bounded : forall symbol, symbol ∈ expression.symbols -> symbol.2 < limit)
    (same : left.AgreesBelow limit right) :
    expression.eval left locals = expression.eval right locals := by
  apply expression.eval_congr
  intro ty id occurs
  exact same ty id (bounded (ty, id) occurs)

theorem Holds.agrees_below {assertions : List (Term [] .bool)} {left right : Assignment}
    (holds : Holds assertions left) (limit : Nat)
    (bounded : forall formula, formula ∈ assertions ->
      forall symbol, symbol ∈ formula.symbols -> symbol.2 < limit)
    (same : left.AgreesBelow limit right) : Holds assertions right := by
  intro formula member
  rw [<- formula.eval_agrees_below left right Locals.empty limit (bounded formula member) same]
  exact holds formula member

theorem fresh_binding_exists (assertions : List (Term [] .bool)) {sort : Ty}
    (expression : Term [] sort) (id : Nat)
    (freshAssertions : forall formula, formula ∈ assertions -> (sort, id) ∉ formula.symbols)
    (freshExpression : (sort, id) ∉ expression.symbols) :
    (exists assignment, Holds assertions assignment) <->
      (exists assignment, Holds assertions assignment /\
        (Term.equal (.free sort id) expression).eval assignment Locals.empty = true) := by
  constructor
  · rintro ⟨assignment, holds⟩
    let value := expression.eval assignment Locals.empty
    let extended := assignment.set sort id value
    refine ⟨extended, ?_, ?_⟩
    · intro formula member
      rw [Term.eval_set_of_fresh formula assignment Locals.empty id value
        (freshAssertions formula member)]
      exact holds formula member
    · simp only [Term.eval, decide_eq_true_eq]
      rw [Term.eval_set_of_fresh expression assignment Locals.empty id value freshExpression]
      simp [extended, Assignment.set, value]
  · rintro ⟨assignment, holds, _⟩
    exact ⟨assignment, holds⟩

theorem asserted_ite (assignment : Assignment) {context : List Ty} (locals : Locals context)
    (condition yes no : Term context .bool) :
    (condition.eval assignment locals = true /\
      (Term.ite condition yes no).eval assignment locals = true) <->
    (condition.eval assignment locals = true /\ yes.eval assignment locals = true) := by
  cases observed : condition.eval assignment locals <;> simp [Term.eval, observed]

theorem asserted_replacement (assignment : Assignment) {context : List Ty} {sort : Ty}
    (locals : Locals context) (observed known : Term context sort)
    (continuation : sort.denote -> Prop) :
    ((Term.equal observed known).eval assignment locals = true /\ continuation (observed.eval assignment locals)) <->
    ((Term.equal observed known).eval assignment locals = true /\ continuation (known.eval assignment locals)) := by
  simp only [Term.eval, decide_eq_true_eq]
  constructor <;> rintro ⟨same, holds⟩
  · exact ⟨same, same ▸ holds⟩
  · exact ⟨same, same.symm ▸ holds⟩

end CCFRaft.NativeSmt

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeSmt).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
