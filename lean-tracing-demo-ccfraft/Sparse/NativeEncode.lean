-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeValues
import Sparse.NativeArrayCheckQuorum
import Lean.Data.Json

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open Lean NativeSmt

abbrev Expr (sort : Ty) := Term [] sort

def implies {context : List Ty} (premise conclusion : Term context .bool) : Term context .bool :=
  .or (.not premise) conclusion

def lt {context : List Ty} (left right : Term context .int) : Term context .bool :=
  .not (.le right left)

def all {context : List Ty} (values : List (Term context .bool)) : Term context .bool :=
  values.foldr Term.and (.boolean true)

def isConfiguration {context : List Ty} {width : PNat}
    (content : Term context (contentTy width)) : Term context .bool :=
  .cases content (.boolean false)
    (.cases (.bound .here) (.boolean false)
      (.cases (.bound .here) (.boolean true) (.boolean false)))

def members {context : List Ty} {width : PNat}
    (content : Term context (contentTy width)) : Term context (.bits width) :=
  .cases content (.bits 0)
    (.cases (.bound .here) (.bits 0)
      (.cases (.bound .here) (.bound .here) (.bits 0)))

structure Encoding (width : PNat) where
  bootstrap : BitVec width
  role : Nat := 1
  newFollower : Nat := 2
  next : Nat := 7
  assertions : Array (Expr .bool) := #[]
  symbolsBounded : forall formula, formula ∈ assertions ->
    forall symbol, symbol ∈ formula.symbols -> symbol.2 < next

abbrev EncodeM (width : PNat) := StateT (Encoding width) (Except String)

def assertion {width : PNat} (formula : Expr .bool) : EncodeM width Unit := fun state =>
  if known : formula.symbols.all (fun symbol => symbol.2 < state.next) then
    .ok ((), { state with
      assertions := state.assertions.push formula
      symbolsBounded := by
        intro expression member symbol occurs
        rcases Array.mem_push.mp member with previous | rfl
        · exact state.symbolsBounded expression previous symbol occurs
        · simpa only [decide_eq_true_eq] using List.all_eq_true.mp known symbol occurs })
  else .error "internal encoder error: assertion references an unallocated SMT symbol"

def assertAll {width : PNat} : List (Expr .bool) -> EncodeM width Unit
  | [] => pure ()
  | formula :: rest => do
    assertion formula
    assertAll rest

def fresh {width : PNat} : EncodeM width Nat := fun state =>
  .ok (state.next, { state with
    next := state.next + 1
    symbolsBounded := by
      intro formula member symbol occurs
      exact Nat.lt_trans (state.symbolsBounded formula member symbol occurs) (Nat.lt_succ_self _) })

def define {width : PNat} {sort : Ty} (value : Expr sort) : EncodeM width Nat := do
  let state <- get
  unless value.symbols.all (fun symbol => symbol.2 < state.next) do
    throw "internal encoder error: definition references an unallocated SMT symbol"
  let id <- fresh
  assertion (.equal (.free sort id) value)
  return id

def allocated {context : List Ty} (node : Nat) : Term context .bool :=
  .select (.free (.array .int .bool) 0) (.integer node)

def read {context : List Ty} {sort : Ty} (column node : Nat)
    (default : Term context sort) : Term context sort :=
  .ite (allocated node) (.select (.free (.array .int sort) column) (.integer node)) default

def length {context : List Ty} (node : Nat) : Term context .int := read 3 node (.integer 0)
def commit {context : List Ty} (node : Nat) : Term context .int := read 4 node (.integer 0)

def entryAt {context : List Ty} (width : PNat) (node : Nat)
    (index : Term context .int) : Term context (entryTy width) :=
  .select (.select (.free (.array .int (.array .int (entryTy width))) 6) (.integer node)) index

def leaderGuard (column node : Nat) : Expr .bool :=
  .equal (read column node (.integer 0)) (.integer 4)

def stepDownRole (column node : Nat) : Expr (.array .int .int) :=
  .store (.free (.array .int .int) column) (.integer node) (.integer 1)

def stepDownFollower (column node : Nat) : Expr (.array .int .bool) :=
  .store (.free (.array .int .bool) column) (.integer node) (.boolean true)

def initialNodeDomains (width : PNat) (node : Nat) : List (Expr .bool) :=
  [all [.le (.integer 0) (read 1 node (.integer 0)),
      .le (read 1 node (.integer 0)) (.integer 4)],
    .le (.integer 0) (read 3 node (.integer 0)),
    .le (.integer 0) (read 4 node (.integer 0)),
    .le (.integer 0) (read 5 node (.integer 0)),
    .forall_ .int (implies
      (.and (.le (.integer 0) (.bound .here)) (lt (.bound .here) (length node)))
      (entryDomain (entryAt width node (.bound .here))))]

def initialAssertions (width : PNat) : List (Expr .bool) :=
  (List.range width.val).flatMap (initialNodeDomains width)

def initialDomains (width : PNat) : EncodeM width Unit :=
  assertAll (initialAssertions width)

def currentCandidate (width : PNat) (node currentId : Nat) : Expr .bool :=
  let current : Expr .int := .free .int currentId
  all [.le (.integer 0) current, .le current (length node), .le current (commit node),
    .or (.equal current (.integer 0))
      (isConfiguration (.snd (entryAt width node (.sub current (.integer 1)))))]

def noLaterConfiguration (width : PNat) (node currentId : Nat) : Expr .bool :=
  .forall_ .int (implies
    (all [lt (.free .int currentId) (.bound .here),
      .le (.bound .here) (length node), .le (.bound .here) (commit node)])
    (.not (isConfiguration (.snd (entryAt width node (.sub (.bound .here) (.integer 1)))))))

def otherConfiguration (width : PNat) (bootstrap : BitVec width)
    (node currentId witnessId : Nat) : Expr .bool :=
  let current : Expr .int := .free .int currentId
  let witness : Expr .int := .free .int witnessId
  let others : Expr (.bits width) := .bitsNot (.bits (BitVec.ofNat width (2 ^ node)))
  let hasOther := fun (nodes : Expr (.bits width)) =>
    Term.not (.equal (.bitsAnd nodes others) (.bits 0))
  .or (.and (.equal current (.integer 0)) (hasOther (.bits bootstrap)))
    (all [.le (.integer 1) witness, .le current witness, .le witness (length node),
      isConfiguration (.snd (entryAt width node (.sub witness (.integer 1)))),
      hasOther (members (.snd (entryAt width node (.sub witness (.integer 1)))))])

def leadingGuards (roleColumn node : Nat) : List (Expr .bool) :=
  [allocated node, leaderGuard roleColumn node]

def configurationGuards (width : PNat) (bootstrap : BitVec width)
    (node currentId witnessId : Nat) : List (Expr .bool) :=
  [currentCandidate width node currentId, noLaterConfiguration width node currentId,
    otherConfiguration width bootstrap node currentId witnessId]

def checkQuorum {width : PNat} (node : Nat) : EncodeM width Unit := do
  let before <- get
  assertAll (leadingGuards before.role node)
  let currentId <- fresh
  let witnessId <- fresh
  assertAll (configurationGuards width before.bootstrap node currentId witnessId)
  let roleId <- define (stepDownRole before.role node)
  let followerId <- define (stepDownFollower before.newFollower node)
  modify fun state => { state with role := roleId, newFollower := followerId }

def fields (value : Json) (expected : List String) : Except String Unit := do
  let object <- value.getObj?
  let actual := object.toList.map Prod.fst
  unless actual.length = expected.length && expected.all actual.contains do
    throw s!"expected fields {expected}; got {actual}"

def field (value : Json) (key : String) : Except String Json := value.getObjVal? key

def natural (value : Json) : Except String Nat := do
  match value with
  | .num number =>
    unless number.exponent = 0 do throw "expected a natural number, not a decimal"
    match number.mantissa with
    | .ofNat number => return number
    | _ => throw "expected a natural number, not a negative number"
  | _ => throw "expected a natural number"

def resolve (width : PNat) (names : Array String) (value : Json) : Except String (Fin width) := do
  let name <- value.getStr?
  match names.toList.idxOf? name with
  | some index =>
    if within : index < width.val then return ⟨index, within⟩
    else throw "internal encoder error: identity index exceeds the declared width"
  | none => throw s!"undeclared node {name}"

def decodeNodeSet (width : PNat) (names : Array String) (value : Json) :
    Except String (Finset (Fin width)) := do
  let mut result : Finset (Fin width) := {}
  for node in <- value.getArr? do
    result := insert (<- resolve width names node) result
  return result

def decodeEntry (width : PNat) (names : Array String) (value : Json) :
    Except String (Entry (Fin width) Nat) := do
  fields value ["term", "content"]
  let term <- natural (<- field value "term")
  let content <- field value "content"
  let decoded <- match content with
    | .str "signature" => pure EntryContent.signature
    | .obj object => do
      match object.toList with
      | [("transaction", value)] => pure (.transaction (<- natural value))
      | [("reconfiguration", value)] => pure (.reconfiguration (<- decodeNodeSet width names value))
      | [("retiredCommitted", value)] => pure (.retiredCommitted (<- decodeNodeSet width names value))
      | _ => throw "expected one typed entry payload"
    | _ => throw "expected signature or one typed entry payload"
  return { term, content := decoded }

def decodeInstruction (width : PNat) (names : Array String) (value : Json) :
    Except String (NativeArrayCheckQuorum.Instruction (Fin width) Nat) := do
  let kind <- (<- field value "kind").getStr?
  let node <- resolve width names (<- field value "node")
  match kind with
  | "checkQuorum" =>
    fields value ["kind", "node"]
    return .checkQuorum node
  | "allocated" | "newFollower" =>
    fields value ["kind", "node", "value"]
    let expected <- (<- field value "value").getBool?
    return if kind = "allocated" then .allocated node expected else .newFollower node expected
  | "role" =>
    fields value ["kind", "node", "value"]
    let expected <- (<- field value "value").getStr?
    let role <- match expected with
      | "none" => pure Role.none
      | "follower" => pure .follower
      | "preVoteCandidate" => pure .preVoteCandidate
      | "candidate" => pure .candidate
      | "leader" => pure .leader
      | _ => throw s!"unknown role {expected}"
    return .role node role
  | "logLength" | "commit" | "currentTerm" =>
    fields value ["kind", "node", "value"]
    let expected <- natural (<- field value "value")
    return if kind = "logLength" then .logLength node expected
      else if kind = "commit" then .commit node expected else .currentTerm node expected
  | "entry" =>
    fields value ["kind", "node", "index", "value"]
    let index <- natural (<- field value "index")
    let expected <- decodeEntry width names (<- field value "value")
    return .entry node index expected
  | _ => throw s!"unsupported native Lean instruction {kind}"

def observationClauses {width : PNat} (roleColumn followerColumn : Nat) :
    NativeArrayCheckQuorum.Instruction (Fin width) Nat -> Except String (List (Expr .bool))
  | .allocated node expected => .ok [.equal (allocated node.val) (.boolean expected)]
  | .role node expected => .ok [.equal (read roleColumn node.val (.integer 0)) (.integer (roleCode expected))]
  | .newFollower node expected => .ok [.equal (read followerColumn node.val (.boolean true)) (.boolean expected)]
  | .logLength node expected => .ok [.equal (length node.val) (.integer expected)]
  | .commit node expected => .ok [.equal (commit node.val) (.integer expected)]
  | .currentTerm node expected => .ok [.equal (read 5 node.val (.integer 0)) (.integer expected)]
  | .entry node index expected => .ok [lt (.integer index) (length node.val),
      .equal (entryAt width node.val (.integer index)) (entryTerm expected)]
  | _ => .error "unsupported native Lean observation"

def instruction {width : PNat} (item : NativeArrayCheckQuorum.Instruction (Fin width) Nat) :
    EncodeM width Unit := do
  match item with
  | .checkQuorum node => checkQuorum node.val
  | _ =>
    let state <- get
    assertAll (<- observationClauses state.role state.newFollower item)

structure Group where
  instruction : Option Nat
  start : Nat
  stop : Nat
  deriving ToJson

structure Compiled where
  assertions : Array (Expr .bool)
  groups : Array Group

def compile (document : Json) : Except String Compiled := do
  fields document ["nodes", "bootstrap", "instructions"]
  let names <- (<- (<- field document "nodes").getArr?).mapM Json.getStr?
  unless names.toList.Nodup && names.all (fun name => !name.isEmpty) do
    throw "nodes must be distinct nonempty strings"
  if positive : 0 < names.size then
    let width : PNat := ⟨names.size, positive⟩
    let bootstrap <- field document "bootstrap"
    if (<- bootstrap.getArr?).isEmpty then throw "bootstrap must be nonempty"
    let initial : Encoding width := {
      bootstrap := encodeBits (<- decodeNodeSet width names bootstrap)
      symbolsBounded := by simp }
    let instructions <- (<- field document "instructions").getArr?
    let (groups, final) <- (do
      initialDomains width
      let mut groups : Array Group := #[{ instruction := none, start := 0, stop := (← get).assertions.size }]
      for index in [:instructions.size] do
        let start := (← get).assertions.size
        try instruction (<- decodeInstruction width names instructions[index]!)
        catch error => throw s!"instruction {index}: {error}"
        groups := groups.push { instruction := some index, start, stop := (← get).assertions.size }
      return groups).run initial
    return { assertions := final.assertions, groups }
  else throw "nodes must be nonempty"

def encode (document : Json) : Except String String := do
  return renderScript (← compile document).assertions.toList

def encodeDetails (document : Json) : Except String Json := do
  let compiled <- compile document
  let clauses := compiled.assertions.mapIdx fun index expression =>
    Json.mkObj [("name", toJson (assertionName index)), ("expression", toJson expression.render)]
  return Json.mkObj [
    ("schema", toJson "ccfraft-native-encoding/v1"),
    ("input", document),
    ("script", toJson (renderScript compiled.assertions.toList true)),
    ("groups", toJson compiled.groups),
    ("clauses", toJson clauses)]

end CCFRaft.NativeEncode
