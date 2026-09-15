-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.ModelInputSyntax
import Lean.Data.Json

set_option autoImplicit false

/-!
JSON-value codecs only. They do not validate original text, duplicate keys erased
by an earlier parser, number spellings, or Unicode escapes. Object fields are
checked through their complete member list, without assuming TreeMap.Raw.WF.
-/

namespace CCFRaft.Sparse.ModelInputJson

open Lean
open ModelInputSyntax (NatAtom BoolAtom)
open ModelTrace (UnknownNatAssignment)

inductive PathStep where
  | field (name : String)
  | index (value : Nat)
  deriving DecidableEq, Repr

abbrev Path := List PathStep

inductive ErrorKind where
  | expectedArray
  | expectedString
  | expectedObject
  | expectedNatural
  | expectedNatAtom
  | expectedBoolAtom
  | emptyName
  | duplicateNames
  | undeclaredName (name : String)
  | fields (expected actual : List String)
  deriving DecidableEq, Repr

structure DecodeError where
  path : Path
  kind : ErrorKind
  deriving DecidableEq, Repr

structure NameTable where
  values : List String
  nonempty : Not (Membership.mem values "")
  distinct : values.Nodup
  deriving DecidableEq

@[ext] theorem NameTable.ext {left right : NameTable}
    (same : left.values = right.values) : left = right := by
  cases left
  cases right
  cases same
  rfl

def validateNames (values : List String) (path : Path := []) : Except DecodeError NameTable :=
  if empty : Membership.mem values "" then
    .error { path := path ++ [.index (values.idxOf "")], kind := .emptyName }
  else if distinct : values.Nodup then
    .ok { values, nonempty := empty, distinct }
  else
    .error { path, kind := .duplicateNames }

theorem validate_names_roundtrip (table : NameTable) (path : Path) :
    validateNames table.values path = .ok table := by
  simp [validateNames, table.nonempty, table.distinct]

theorem validate_names_preserves {values : List String} {path : Path} {table : NameTable}
    (decoded : validateNames values path = .ok table) : table.values = values := by
  unfold validateNames at decoded
  split at decoded <;> try contradiction
  split at decoded <;> simp_all
  cases decoded
  rfl

def decodeNameList (path : Path) (index : Nat) : List Json -> Except DecodeError (List String)
  | [] => .ok []
  | .str name :: rest => (decodeNameList path (index + 1) rest).map (fun names => name :: names)
  | _ :: _ => .error { path := path ++ [.index index], kind := .expectedString }

theorem decode_name_list_roundtrip (values : List String) (path : Path) (index : Nat) :
    decodeNameList path index (values.map Json.str) = .ok values := by
  induction values generalizing index with
  | nil => rfl
  | cons name rest ih => simp [decodeNameList, ih, Except.map]

theorem decode_name_list_preserves (values : List Json) (path : Path) (index : Nat)
    (names : List String) (decoded : decodeNameList path index values = .ok names) :
    values = names.map Json.str := by
  induction values generalizing index names with
  | nil => simpa [decodeNameList] using decoded
  | cons value rest ih =>
    cases value <;> try simp [decodeNameList] at decoded
    case str name =>
      cases tail : decodeNameList path (index + 1) rest with
      | error error => simp [tail, Except.map] at decoded
      | ok result =>
        have same : name :: result = names := by
          simpa [decodeNameList, tail, Except.map] using decoded
        rw [<- same, List.map_cons, ih _ _ tail]

def decodeNames (json : Json) (path : Path := []) : Except DecodeError NameTable :=
  match json with
  | .arr values =>
    match decodeNameList path 0 values.toList with
    | .ok names => validateNames names path
    | .error error => .error error
  | _ => .error { path, kind := .expectedArray }

def encodeNames (table : NameTable) : Json := .arr (table.values.map Json.str).toArray

theorem names_roundtrip (table : NameTable) (path : Path) :
    decodeNames (encodeNames table) path = .ok table := by
  simp [decodeNames, encodeNames, decode_name_list_roundtrip, validate_names_roundtrip]

theorem names_decode_exact (json : Json) (path : Path) (table : NameTable)
    (decoded : decodeNames json path = .ok table) : json = encodeNames table := by
  cases json <;> try simp [decodeNames] at decoded
  case arr values =>
    cases result : decodeNameList path 0 values.toList with
    | error error => simp [result] at decoded
    | ok names =>
      have valid : validateNames names path = .ok table := by
        simpa [decodeNames, result] using decoded
      have exact_names := decode_name_list_preserves values.toList path 0 names result
      rw [<- validate_names_preserves valid] at exact_names
      have same := congrArg List.toArray exact_names
      simpa [encodeNames] using congrArg Json.arr same

def resolveName (table : NameTable) (name : String) (path : Path := []) :
    Except DecodeError (Fin table.values.length) :=
  let index := table.values.idxOf name
  if bound : index < table.values.length then .ok (Fin.mk index bound)
  else .error { path, kind := .undeclaredName name }

theorem name_index_unique (table : NameTable) (left right : Fin table.values.length)
    (same : table.values[left.val] = table.values[right.val]) : left = right := by
  apply Fin.ext
  exact table.distinct.getElem_inj_iff.mp same

theorem resolve_name_sound (table : NameTable) (name : String) (path : Path)
    (index : Fin table.values.length) (resolved : resolveName table name path = .ok index) :
    table.values[index.val] = name := by
  dsimp only [resolveName] at resolved
  split at resolved
  next bound =>
    have same := Except.ok.inj resolved
    rw [<- same]
    exact List.getElem_idxOf bound
  next => cases resolved

theorem resolve_name_complete (table : NameTable) (name : String) (path : Path)
    (index : Fin table.values.length) (matched : table.values[index.val] = name) :
    resolveName table name path = .ok index := by
  have position : table.values.idxOf name = index.val := by
    rw [<- matched]
    exact table.distinct.idxOf_getElem index.val index.isLt
  simp [resolveName, position, index.isLt]

theorem resolve_name_iff (table : NameTable) (name : String) (path : Path)
    (index : Fin table.values.length) :
    resolveName table name path = .ok index <-> table.values[index.val] = name :=
  Iff.intro (resolve_name_sound table name path index) (resolve_name_complete table name path index)

theorem resolve_name_roundtrip (table : NameTable) (index : Fin table.values.length) (path : Path) :
    resolveName table table.values[index.val] path = .ok index :=
  resolve_name_complete table _ path index rfl

theorem resolve_name_failure (table : NameTable) (name : String) (path : Path) :
    resolveName table name path = .error { path, kind := .undeclaredName name } <->
      forall index : Fin table.values.length, Not (table.values[index.val] = name) := by
  constructor
  next =>
    intro failed index matched
    have success := resolve_name_complete table name path index matched
    rw [failed] at success
    cases success
  next =>
    intro absent
    dsimp only [resolveName]
    split
    next bound =>
      exact False.elim (absent (Fin.mk _ bound) (List.getElem_idxOf bound))
    next => rfl

/-- Exact member-list semantics, including when the supplied raw map is not WF. -/
def HasField (json : Json) (name : String) (value : Json) : Prop :=
  match json with
  | .obj fields => fields.toList = [(name, value)]
  | _ => False

def singleField (json : Json) (name : String) (path : Path) : Except DecodeError Json :=
  match json with
  | .obj fields =>
    match fields.toList with
    | [(key, value)] =>
      if key = name then .ok value
      else .error { path, kind := .fields [name] [key] }
    | members => .error { path, kind := .fields [name] (members.map Prod.fst) }
  | _ => .error { path, kind := .expectedObject }

theorem single_field_iff (json : Json) (name : String) (path : Path) (value : Json) :
    singleField json name path = .ok value <-> HasField json name value := by
  cases json <;> try simp [singleField, HasField]
  case obj fields =>
    cases members : fields.toList with
    | nil => simp
    | cons member rest =>
      cases member with
      | mk key item =>
        cases rest with
        | nil =>
          by_cases same : key = name
          next => simp [same]
          next => simp [same]
        | cons head tail =>
          cases tail <;> simp

theorem single_field_roundtrip (name : String) (value : Json) (path : Path) :
    singleField (Json.mkObj [(name, value)]) name path = .ok value := by
  apply (single_field_iff _ _ _ _).mpr
  rfl

def encodeNat (table : NameTable) : NatAtom table.values.length -> Json
  | .literal value => .num (JsonNumber.fromNat value)
  | .unknown index => Json.mkObj [("unknown", .str table.values[index.val])]

def decodeNat (table : NameTable) (json : Json) (path : Path := []) :
    Except DecodeError (NatAtom table.values.length) :=
  match json with
  | .num { mantissa := .ofNat value, exponent := 0 } => .ok (.literal value)
  | .num _ => .error { path, kind := .expectedNatural }
  | .obj _ =>
    match singleField json "unknown" path with
    | .ok (.str name) =>
      (resolveName table name (path ++ [.field "unknown"])).map NatAtom.unknown
    | .ok _ => .error { path := path ++ [.field "unknown"], kind := .expectedString }
    | .error error => .error error
  | _ => .error { path, kind := .expectedNatAtom }

def encodeBool (table : NameTable) : BoolAtom table.values.length -> Json
  | .literal value => .bool value
  | .isZero value => Json.mkObj [("isZero", encodeNat table value)]

def decodeBool (table : NameTable) (json : Json) (path : Path := []) :
    Except DecodeError (BoolAtom table.values.length) :=
  match json with
  | .bool value => .ok (.literal value)
  | .obj _ =>
    match singleField json "isZero" path with
    | .ok value => (decodeNat table value (path ++ [.field "isZero"])).map BoolAtom.isZero
    | .error error => .error error
  | _ => .error { path, kind := .expectedBoolAtom }

theorem nat_roundtrip (table : NameTable) (atom : NatAtom table.values.length) (path : Path) :
    decodeNat table (encodeNat table atom) path = .ok atom := by
  cases atom with
  | literal value => rfl
  | unknown index =>
    simp [encodeNat, decodeNat, single_field_roundtrip, resolve_name_roundtrip, Except.map]
    rfl

theorem bool_roundtrip (table : NameTable) (atom : BoolAtom table.values.length) (path : Path) :
    decodeBool table (encodeBool table atom) path = .ok atom := by
  cases atom with
  | literal value => rfl
  | isZero value =>
    simp [encodeBool, decodeBool, single_field_roundtrip, nat_roundtrip, Except.map]
    rfl

def NatValue (table : NameTable) (json : Json) : NatAtom table.values.length -> Prop
  | .literal value => json = .num (JsonNumber.fromNat value)
  | .unknown index => HasField json "unknown" (.str table.values[index.val])

theorem decode_nat_iff (table : NameTable) (json : Json) (path : Path)
    (atom : NatAtom table.values.length) :
    decodeNat table json path = .ok atom <-> NatValue table json atom := by
  cases json <;> try (solve | cases atom <;> simp [decodeNat, NatValue, HasField])
  case num number =>
    cases number with
    | mk mantissa exponent =>
      cases mantissa <;> cases exponent <;> cases atom <;>
        simp [decodeNat, NatValue, HasField, JsonNumber.fromNat]
  case obj fields =>
    cases read : singleField (.obj fields) "unknown" path with
    | error error =>
      cases atom with
      | literal value => simp [decodeNat, read, NatValue]
      | unknown index =>
        rw [NatValue, <- single_field_iff _ _ path _, read]
        simp [decodeNat, read]
    | ok value =>
      cases atom with
      | literal number =>
        cases value <;> simp [decodeNat, read, NatValue]
        case str name =>
          cases resolveName table name (path ++ [.field "unknown"]) <;> simp [Except.map]
      | unknown index =>
        rw [NatValue, <- single_field_iff _ _ path _, read]
        cases value <;> simp [decodeNat, read]
        case str name =>
          have resolved := resolve_name_iff table name (path ++ [.field "unknown"]) index
          cases result : resolveName table name (path ++ [.field "unknown"]) <;>
            simp_all [Except.map, eq_comm]

def BoolValue (table : NameTable) (json : Json) : BoolAtom table.values.length -> Prop
  | .literal value => json = .bool value
  | .isZero atom =>
    exists value, HasField json "isZero" value /\ NatValue table value atom

theorem decode_bool_iff (table : NameTable) (json : Json) (path : Path)
    (atom : BoolAtom table.values.length) :
    decodeBool table json path = .ok atom <-> BoolValue table json atom := by
  cases json <;> try (solve | cases atom <;> simp [decodeBool, BoolValue, HasField])
  case obj fields =>
    cases read : singleField (.obj fields) "isZero" path with
    | error error =>
      cases atom with
      | literal value => simp [decodeBool, read, BoolValue]
      | isZero atom =>
        simp only [BoolValue]
        simp_rw [<- single_field_iff _ _ path _, read]
        simp [decodeBool, read]
    | ok value =>
      cases atom with
      | literal result =>
        simp only [decodeBool, read, BoolValue]
        cases decodeNat table value (path ++ [.field "isZero"]) <;> simp [Except.map]
      | isZero atom =>
        simp only [BoolValue]
        simp_rw [<- single_field_iff _ _ path _, read]
        simp only [Except.ok.injEq]
        conv_rhs => simp
        rw [<- decode_nat_iff table value (path ++ [.field "isZero"]) atom]
        simp only [decodeBool, read]
        cases decodeNat table value (path ++ [.field "isZero"]) <;> simp [Except.map]

theorem named_evaluation (table : NameTable) (name : String)
    (index : Fin table.values.length) (path : Path) (rho : UnknownNatAssignment)
    (resolved : resolveName table name path = .ok index) :
    (decodeNat table (Json.mkObj [("unknown", .str name)]) path).map (NatAtom.eval rho) =
        .ok (rho index.val) /\
      (decodeBool table (Json.mkObj [("isZero", Json.mkObj [("unknown", .str name)])]) path).map
        (BoolAtom.eval rho) = .ok (decide (rho index.val = 0)) := by
  have same := resolve_name_sound table name path index resolved
  rw [<- same]
  change
    (decodeNat table (encodeNat table (.unknown index)) path).map (NatAtom.eval rho) =
        .ok (rho index.val) /\
      (decodeBool table (encodeBool table (.isZero (.unknown index))) path).map (BoolAtom.eval rho) =
        .ok (decide (rho index.val = 0))
  rw [nat_roundtrip, bool_roundtrip]
  exact And.intro rfl rfl

namespace Regression

local instance {A : Type} [DecidableEq A] : DecidableEq (Except DecodeError A) :=
  fun left right =>
    match left, right with
    | .ok a, .ok b =>
      if same : a = b then isTrue (congrArg Except.ok same)
      else isFalse (fun same_result => same (Except.ok.inj same_result))
    | .error a, .error b =>
      if same : a = b then isTrue (congrArg Except.error same)
      else isFalse (fun same_result => same (Except.error.inj same_result))
    | .ok _, .error _ => isFalse (fun same => nomatch same)
    | .error _, .ok _ => isFalse (fun same => nomatch same)

def emptyTable : NameTable := { values := [], nonempty := by simp, distinct := by simp }

def names : NameTable :=
  { values := ["y", "x", "unused"], nonempty := by decide, distinct := by decide }

def reference (name : String) : Json := Json.mkObj [("unknown", .str name)]

def zeroTest (value : Json) : Json := Json.mkObj [("isZero", value)]

def controls : List (Prod String Bool) :=
  [ ("empty table", decide (decodeNames (.arr #[]) = .ok emptyTable)),
    ("ordered complete declarations", decide
      (decodeNames (.arr #[.str "y", .str "x", .str "unused"]) = .ok names)),
    ("second declared name", decide (resolveName names "x" = .ok (Fin.mk 1 (by decide)))),
    ("unused declaration retained", decide
      (resolveName names "unused" = .ok (Fin.mk 2 (by decide)))),
    ("name roundtrip", decide (decodeNames (encodeNames names) = .ok names)),
    ("empty name", decide
      (decodeNames (.arr #[.str "x", .str ""]) [.field "unknowns"] =
        .error { path := [.field "unknowns", .index 1], kind := .emptyName })),
    ("duplicate declarations", decide
      (decodeNames (.arr #[.str "x", .str "x"]) [.field "unknowns"] =
        .error { path := [.field "unknowns"], kind := .duplicateNames })),
    ("name element type", decide
      (decodeNames (.arr #[.str "x", .bool true]) [.field "unknowns"] =
        .error { path := [.field "unknowns", .index 1], kind := .expectedString })),
    ("name table type", decide
      (decodeNames (.str "x") = .error { path := [], kind := .expectedArray })),
    ("empty table unresolved", decide
      (resolveName emptyTable "x" = .error { path := [], kind := .undeclaredName "x" })),
    ("undeclared reference", decide
      (decodeNat names (reference "missing") [.field "term"] =
        .error { path := [.field "term", .field "unknown"], kind := .undeclaredName "missing" })),
    ("shared repeated reference", decide
      (decodeNat names (reference "x") = .ok (.unknown (Fin.mk 1 (by decide))))),
    ("aliases allowed", decide
      ((decodeNat names (reference "y")).map (NatAtom.eval (fun _ => 2)) = .ok 2 /\
        (decodeNat names (reference "x")).map (NatAtom.eval (fun _ => 2)) = .ok 2)),
    ("isZero shares numeric value two", decide
      ((decodeNat names (reference "x")).map (NatAtom.eval (fun _ => 2)) = .ok 2 /\
        (decodeBool names (zeroTest (reference "x"))).map (BoolAtom.eval (fun _ => 2)) = .ok false)),
    ("isZero shares numeric zero", decide
      ((decodeBool names (zeroTest (reference "x"))).map (BoolAtom.eval (fun _ => 0)) = .ok true)),
    ("unbounded natural literal", decide
      (decodeNat emptyTable (.num (JsonNumber.fromNat 18446744073709551616)) =
        .ok (.literal 18446744073709551616))),
    ("zero literal", decide (decodeNat emptyTable (.num 0) = .ok (.literal 0))),
    ("negative number", decide
      (decodeNat names (.num (JsonNumber.fromInt (-1))) =
        .error { path := [], kind := .expectedNatural })),
    ("decimal representation", decide
      (decodeNat names (.num { mantissa := 10, exponent := 1 }) =
        .error { path := [], kind := .expectedNatural })),
    ("numeric string", decide
      (decodeNat names (.str "2") = .error { path := [], kind := .expectedNatAtom })),
    ("Bool is not Nat", decide
      (decodeNat names (.bool true) = .error { path := [], kind := .expectedNatAtom })),
    ("Nat is not Bool", decide
      (decodeBool names (.num 0) = .error { path := [], kind := .expectedBoolAtom })),
    ("Bool literal", decide (decodeBool names (.bool false) = .ok (.literal false))),
    ("reference is not Bool", decide
      (decodeBool names (reference "x") =
        .error { path := [], kind := .fields ["isZero"] ["unknown"] })),
    ("isZero literal shape retained", decide
      (decodeBool names (zeroTest (.num 0)) = .ok (.isZero (.literal 0)))),
    ("reference payload type", decide
      (decodeNat names (Json.mkObj [("unknown", .num 0)]) =
        .error { path := [.field "unknown"], kind := .expectedString })),
    ("missing field", decide
      (decodeNat names (Json.mkObj []) = .error { path := [], kind := .fields ["unknown"] [] })),
    ("extra Nat field", decide
      (decodeNat names (Json.mkObj [("unknown", .str "x"), ("extra", .bool true)]) =
        .error { path := [], kind := .fields ["unknown"] ["extra", "unknown"] })),
    ("extra Bool field", decide
      (decodeBool names (Json.mkObj [("isZero", .num 0), ("extra", .bool true)]) =
        .error { path := [], kind := .fields ["isZero"] ["extra", "isZero"] })),
    ("nested zero test rejected", decide
      (decodeBool names (zeroTest (zeroTest (.num 0))) =
        .error { path := [.field "isZero"], kind := .fields ["unknown"] ["isZero"] })),
    ("nested unknown error path", decide
      (decodeBool names (zeroTest (reference "missing")) [.index 4] =
        .error
          { path := [.index 4, .field "isZero", .field "unknown"]
            kind := .undeclaredName "missing" })),
    ("null is not an atom", decide
      (decodeNat names .null = .error { path := [], kind := .expectedNatAtom } /\
        decodeBool names .null = .error { path := [], kind := .expectedBoolAtom })) ]

theorem controls_pass : controls.all Prod.snd = true := by decide +kernel

theorem unused_assignment_irrelevant (left right : UnknownNatAssignment)
    (same : left 1 = right 1) :
    NatAtom.eval left (NatAtom.unknown (n := names.values.length) (Fin.mk 1 (by decide))) =
      NatAtom.eval right (NatAtom.unknown (n := names.values.length) (Fin.mk 1 (by decide))) /\
    BoolAtom.eval left (BoolAtom.isZero (NatAtom.unknown (n := names.values.length) (Fin.mk 1 (by decide)))) =
      BoolAtom.eval right (BoolAtom.isZero (NatAtom.unknown (n := names.values.length) (Fin.mk 1 (by decide)))) := by
  simp only [NatAtom.eval, BoolAtom.eval, same, and_self]

end Regression

end CCFRaft.Sparse.ModelInputJson

run_cmd do
  let mut count := 0
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.Sparse.ModelInputJson).isPrefixOf name then
      count := count + 1
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
  Lean.logInfo m!"ModelInputJson: {count} declarations passed the transitive axiom gate"
