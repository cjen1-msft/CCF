-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Shared.SymbolicNormalize

set_option autoImplicit false

namespace Symbolic

def Ty.name : Ty → String
  | .nat => "Int"
  | .bool => "Bool"
  | .unit => "U"
  | .pair a b => s!"P_{a.name}_{b.name}_E"
  | .sum a b => s!"S_{a.name}_{b.name}_E"
  | .seq a => s!"Q_{a.name}_E"

def Ty.smt : Ty → String
  | .seq a => s!"(Seq {a.smt})"
  | a => a.name

def Ty.dependencies : Ty → List Ty
  | .pair a b => a.dependencies ++ b.dependencies ++ [.pair a b]
  | .sum a b => a.dependencies ++ b.dependencies ++ [.sum a b]
  | .seq a => a.dependencies
  | a => [a]

def Ty.declaration : Ty → List String
  | .nat | .bool | .seq _ => []
  | .unit => ["(declare-datatype U ((unit)))"]
  | .pair a b =>
      let n := (Ty.pair a b).name
      [s!"(declare-datatype {n} ((mk_{n} (fst_{n} {a.smt}) (snd_{n} {b.smt}))))"]
  | .sum a b =>
      let n := (Ty.sum a b).name
      [s!"(declare-datatype {n} ((left_{n} (getLeft_{n} {a.smt})) (right_{n} (getRight_{n} {b.smt}))))"]

def Expr.sorts {s : Ty} (e : Expr s) : List Ty :=
  let children := match e with
    | .nat _ | .bool _ | .unit | .unknown _ | .nil => []
    | .add a b | .sub a b | .lt a b | .eq a b
    | .and a b | .pair a b | .append a b | .cons a b
    | .take a b | .drop a b | .get? a b | .contains a b
    | .leftD a b | .rightD a b => a.sorts ++ b.sorts
    | .not a | .fst a | .snd a | .inl a | .inr a
    | .isLeft a | .length a => a.sorts
    | .ite c a b | .set c a b => c.sorts ++ a.sorts ++ b.sorts
  children ++ s.dependencies

def Expr.unknowns : {s : Ty} → Expr s → List Nat
  | _, .unknown i => [i]
  | _, .nat _ | _, .bool _ | _, .unit | _, .nil => []
  | _, .add a b | _, .sub a b | _, .lt a b | _, .eq a b
  | _, .and a b | _, .pair a b | _, .append a b | _, .cons a b
  | _, .take a b | _, .drop a b | _, .get? a b | _, .contains a b
  | _, .leftD a b | _, .rightD a b => a.unknowns ++ b.unknowns
  | _, .not a | _, .fst a | _, .snd a | _, .inl a | _, .inr a
  | _, .isLeft a | _, .length a => a.unknowns
  | _, .ite c a b | _, .set c a b => c.unknowns ++ a.unknowns ++ b.unknowns

structure Printing where
  terms : Std.HashMap (String × String) Nat := {}
  definitions : Array String := #[]
  declared : Std.HashSet String := {}
  sorts : Array String := #[]
  unknowns : Std.HashSet Nat := {}
  unknownDeclarations : Array String := #[]

private def intern (s : Ty) (body : String) : StateM Printing String := do
  let state ← get
  let key := (s.smt, body)
  if let some i := state.terms[key]? then return s!"e_{i}"
  let i := state.definitions.size
  let mut declared := state.declared
  let mut sorts := state.sorts
  if !declared.contains s.name then
    for t in s.dependencies do
      if !declared.contains t.name then
        declared := declared.insert t.name
        sorts := sorts ++ t.declaration.toArray
    declared := declared.insert s.name
  MonadStateOf.set { state with
    terms := state.terms.insert key i
    definitions := state.definitions.push s!"(define-fun e_{i} () {s.smt} {body})"
    declared, sorts }
  return s!"e_{i}"

-- Generated definitions share subterms; they do not identify trace actions.
def Expr.emit {s : Ty} (e : Expr s) : StateM Printing String := do
  let body ← match e with
    | .nat n => pure (toString n)
    | .bool b => pure (if b then "true" else "false")
    | .unit => pure "unit"
    | .unknown i => do
        let state ← get
        if !state.unknowns.contains i then
          MonadStateOf.set { state with
            unknowns := state.unknowns.insert i
            unknownDeclarations := state.unknownDeclarations ++
              #[s!"(declare-const u_{i} Int)", s!"(assert (>= u_{i} 0))"] }
        pure s!"u_{i}"
    | .add a b => do pure s!"(+ {← a.emit} {← b.emit})"
    | .sub a b => do
        let x ← a.emit
        let y ← b.emit
        pure s!"(ite (< {x} {y}) 0 (- {x} {y}))"
    | .lt a b => do pure s!"(< {← a.emit} {← b.emit})"
    | .eq a b => do pure s!"(= {← a.emit} {← b.emit})"
    | .not a => do pure s!"(not {← a.emit})"
    | .and a b => do pure s!"(and {← a.emit} {← b.emit})"
    | .ite c a b => do pure s!"(ite {← c.emit} {← a.emit} {← b.emit})"
    | @Expr.pair a b x y => do pure s!"(mk_{(Ty.pair a b).name} {← x.emit} {← y.emit})"
    | @Expr.fst a b x => do pure s!"(fst_{(Ty.pair a b).name} {← x.emit})"
    | @Expr.snd a b x => do pure s!"(snd_{(Ty.pair a b).name} {← x.emit})"
    | @Expr.inl a b x => do pure s!"(left_{(Ty.sum a b).name} {← x.emit})"
    | @Expr.inr a b x => do pure s!"(right_{(Ty.sum a b).name} {← x.emit})"
    | @Expr.isLeft a b x => do pure s!"((_ is left_{(Ty.sum a b).name}) {← x.emit})"
    | @Expr.leftD a b x d => do
        let value ← x.emit
        pure s!"(ite ((_ is left_{(Ty.sum a b).name}) {value}) (getLeft_{(Ty.sum a b).name} {value}) {← d.emit})"
    | @Expr.rightD a b x d => do
        let value ← x.emit
        pure s!"(ite ((_ is left_{(Ty.sum a b).name}) {value}) {← d.emit} (getRight_{(Ty.sum a b).name} {value}))"
    | @Expr.nil a => pure s!"(as seq.empty (Seq {a.smt}))"
    | .cons a b => do pure s!"(seq.++ (seq.unit {← a.emit}) {← b.emit})"
    | .append a b => do pure s!"(seq.++ {← a.emit} {← b.emit})"
    | .length a => do pure s!"(seq.len {← a.emit})"
    | .take n a => do pure s!"(seq.extract {← a.emit} 0 {← n.emit})"
    | .drop n a => do
        let xs ← a.emit
        pure s!"(seq.extract {xs} {← n.emit} (seq.len {xs}))"
    | @Expr.get? a xs n => do
        let name := (Ty.sum .unit a).name
        let values ← xs.emit
        let index ← n.emit
        pure s!"(ite (< {index} (seq.len {values})) (right_{name} (seq.nth {values} {index})) (left_{name} unit))"
    | .set xs n v => do
        let values ← xs.emit
        let index ← n.emit
        pure s!"(ite (< {index} (seq.len {values})) (seq.update {values} {index} (seq.unit {← v.emit})) {values})"
    | .contains xs v => do pure s!"(seq.contains {← xs.emit} (seq.unit {← v.emit}))"
  intern s body

def prepare (assertions : List (Expr .bool)) : List String × Printing :=
  let emitAll : StateM Printing (List String) :=
    assertions.mapM (fun e => e.normalize.emit)
  emitAll.run {}

def script (assertions : List (Expr .bool)) : String :=
  let (roots, printed) := prepare assertions
  String.intercalate "\n" <|
    ["(set-logic ALL)"] ++ printed.sorts.toList ++ printed.unknownDeclarations.toList ++
    printed.definitions.toList ++ roots.map (fun e => s!"(assert {e})") ++ ["(check-sat)", ""]

end Symbolic
