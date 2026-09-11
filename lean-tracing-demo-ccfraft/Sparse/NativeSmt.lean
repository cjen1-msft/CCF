-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Mathlib

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

def Ty.code : Ty -> String
  | .bool => "B"
  | .int => "I"
  | .unit => "U"
  | .bits width => s!"V{width.val}_"
  | .array key value => "A" ++ key.code ++ value.code
  | .pair first second => "P" ++ first.code ++ second.code
  | .sum left right => "S" ++ left.code ++ right.code

def Ty.render : Ty -> String
  | .bool => "Bool"
  | .int => "Int"
  | .unit => "NativeUnit"
  | .bits width => s!"(_ BitVec {width.val})"
  | .array key value => s!"(Array {key.render} {value.render})"
  | .pair first second => s!"(NativePair {first.render} {second.render})"
  | .sum left right => s!"(NativeSum {left.render} {right.render})"

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

def Term.render : {context : List Ty} -> {sort : Ty} -> Term context sort -> String
  | _, _, .boolean value => if value then "true" else "false"
  | _, _, .integer (.ofNat value) => toString value
  | _, _, .integer (.negSucc value) => s!"(- {value + 1})"
  | _, _, .unit => "native_unit"
  | _, _, .bits (width := width) value => s!"(_ bv{value.toNat} {width.val})"
  | _, _, .free sort id => symbolName sort id
  | context, _, .bound ref => s!"b{context.length - (ref.index + 1)}"
  | _, _, .add left right => s!"(+ {left.render} {right.render})"
  | _, _, .sub left right => s!"(- {left.render} {right.render})"
  | _, _, .le left right => s!"(<= {left.render} {right.render})"
  | _, _, .equal left right => s!"(= {left.render} {right.render})"
  | _, _, .not value => s!"(not {value.render})"
  | _, _, .and left right => s!"(and {left.render} {right.render})"
  | _, _, .or left right => s!"(or {left.render} {right.render})"
  | _, _, .ite condition yes no => s!"(ite {condition.render} {yes.render} {no.render})"
  | context, _, .forall_ sort body => s!"(forall ((b{context.length} {sort.render})) {body.render})"
  | _, _, .select array index => s!"(select {array.render} {index.render})"
  | _, _, .store array index value => s!"(store {array.render} {index.render} {value.render})"
  | _, _, .pair left right => s!"(native_pair {left.render} {right.render})"
  | _, _, .fst value => s!"(native_fst {value.render})"
  | _, _, .snd value => s!"(native_snd {value.render})"
  | _, .sum first second, .inl value =>
      s!"((as native_left {(Ty.sum first second).render}) {value.render})"
  | _, .sum first second, .inr value =>
      s!"((as native_right {(Ty.sum first second).render}) {value.render})"
  | context, _, .cases value left right =>
      s!"(match {value.render} (((native_left b{context.length}) {left.render}) ((native_right b{context.length}) {right.render})))"
  | _, _, .bitsAnd left right => s!"(bvand {left.render} {right.render})"
  | _, _, .bitsOr left right => s!"(bvor {left.render} {right.render})"
  | _, _, .bitsNot value => s!"(bvnot {value.render})"
  | _, _, .bit value index => s!"(= ((_ extract {index.val} {index.val}) {value.render}) #b1)"

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

def renderScript (assertions : List (Term [] .bool)) : String :=
  let symbols := (assertions.flatMap Term.symbols).dedup
  let declarations := symbols.map fun (sort, id) =>
    s!"(declare-const {symbolName sort id} {sort.render})"
  String.intercalate "\n" (prelude ++ declarations ++
    assertions.map (fun expression => s!"(assert {expression.render})") ++ ["(check-sat)", ""])

theorem select_store (assignment : Assignment) {context : List Ty} {key value : Ty}
    (locals : Locals context) (array : Term context (.array key value))
    (index : Term context key) (element : Term context value) :
    (Term.select (Term.store array index element) index).eval assignment locals =
      element.eval assignment locals := by
  simp [Term.eval]

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
