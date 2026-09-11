import Sparse.EntryPredicate
import Lean.Data.Json

set_option autoImplicit false

namespace CCFRaft.Sparse.EntryPredicateFixtures

open Smt EntryPredicate Lean

private def cell (version : Fin 2) : Term .entry :=
  TypedIntervalEncoding.readRef 100 (IntervalReadback.Address.version (roots := 0) version) 2

private def fixture (name : String) (input : SmtScript.Formula) (predicate : Predicate 2)
    (metadata : List (Prod String Json)) : Json :=
  let formula := input ++ [predicate.lower 0 100 2]
  let script := SmtScript.render formula
  Json.mkObj ([
    ("name", toJson name), ("script", toJson script),
    ("references", toJson (predicate.references.map Fin.val)),
    ("external_max", toJson predicate.externalMax),
    ("parsed_script", toJson ((SmtScriptText.parse script).map SmtScript.renderCommands)),
    ("command_value", toJson (SmtScript.run QueueEncoding.regressionInput (SmtScript.compile formula))),
    ("parsed_value", toJson (SmtScriptText.runText QueueEncoding.regressionInput script))] ++ metadata)

private def operators : List (Prod String (Operand 2 .int -> Operand 2 .int -> Predicate 2)) :=
  [("eq", .eq), ("ne", .ne), ("le", .le), ("lt", .lt)]

def comparisons : List Json :=
  ([-3, -2, -1, 0, 1, 2, 3] : List Int).flatMap fun left =>
    ([-3, -2, -1, 0, 1, 2, 3] : List Int).flatMap fun right =>
      ["raw", "decoded-term", "decoded-input"].flatMap fun view =>
        operators.map fun (operator, comparison) =>
          let operands : Prod (Operand 2 .int) (Operand 2 .int) :=
            if view == "raw" then (.entryTerm (.cell 0), .entryTerm (.cell 1))
            else if view == "decoded-term" then (.decodedTerm (.cell 0), .decodedTerm (.cell 1))
            else (.decodedInput (.unknown .int 10), .decodedInput (.unknown .int 11))
          fixture s!"{view}-{operator}-{left}-{right}"
            [.equal (.unknown .int 2) (.integer 1000000),
             .equal (cell 0) (.entry (.integer left) .signature),
             .equal (cell 1) (.entry (.integer right) .signature),
             .equal (.unknown .int 10) (.integer left),
             .equal (.unknown .int 11) (.integer right)]
            (comparison operands.1 operands.2)
            [("kind", toJson "comparison"), ("view", toJson view),
             ("operator", toJson operator), ("left", toJson left), ("right", toJson right)]

def identities : List Json :=
  let values : List (Term .content) :=
    [.transaction (.integer 0), .signature, .reconfiguration (.nodes 1), .retiredCommitted (.nodes 1)]
  (values.mapIdx fun leftIndex left =>
    (values.mapIdx fun rightIndex right =>
      ["eq", "ne"].map fun operator =>
        fixture s!"identity-{operator}-{leftIndex}-{rightIndex}"
          [.equal (.unknown .int 2) (.integer 0),
           .equal (cell 0) (.entry (.integer (-1)) left),
           .equal (cell 1) (.entry (.integer (-1)) right)]
          (if operator == "eq" then .eq (.cell 0) (.cell 1) else .ne (.cell 0) (.cell 1))
          [("kind", toJson "identity"), ("operator", toJson operator),
           ("left", toJson leftIndex), ("right", toJson rightIndex)]).flatten).flatten

private def masks : List (BitVec NODE_COUNT) := [0, 1, 16384, 16385, 32767]
private def cfg : Operand 2 .nodes := .configurationNodes (.entryContent (.cell 0))
private def retired : Operand 2 .nodes := .retiredNodes (.entryContent (.cell 1))
private def count (mask : BitVec NODE_COUNT) : Nat :=
  ((List.ofFn fun node : Node => if mask.getLsbD node.val then 1 else 0) : List Nat).sum
private def maskInput (left right : BitVec NODE_COUNT) : SmtScript.Formula :=
  [.equal (.unknown .int 2) (.integer 1000000),
   .equal (cell 0) (.entry (.integer (-1)) (.reconfiguration (.nodes left))),
   .equal (cell 1) (.entry (.integer 0) (.retiredCommitted (.nodes right)))]
private def wanted (predicate : Predicate 2) (answer : Bool) : Predicate 2 :=
  if answer then predicate else .not predicate
private def nativeMetadata (operation : String) (left right : Nat) (answer : Json) : List (Prod String Json) :=
  [("operation", toJson operation), ("left", toJson left), ("right", toJson right), ("answer", answer)]

def nativeMasks : List Json :=
  masks.flatMap fun left =>
    masks.flatMap fun right =>
      [true, false].flatMap fun valid =>
        let proposed := fun mask : BitVec NODE_COUNT => if valid then mask else mask ^^^ 1
        let build := fun operation operand answer =>
          fixture s!"{operation}-{left.toNat}-{right.toNat}-{valid}" (maskInput left right)
            (.eq operand (.input (.nodes answer))) (nativeMetadata operation left.toNat right.toNat (toJson answer.toNat))
        let conditions : Vector (Term .bool) NODE_COUNT :=
          Vector.ofFn fun node => .unknown .bool (1000 + node.val)
        let conditionInput := List.ofFn fun node : Node =>
          Term.equal conditions[node] (.boolean (right.getLsbD node.val))
        [build "and" (.nodesAnd cfg retired) (proposed (left &&& right)),
         build "or" (.nodesOr cfg retired) (proposed (left ||| right)),
         build "difference" (.nodesAnd cfg (.nodesNot retired)) (proposed (left &&& ~~~right)),
         fixture s!"majority-{left.toNat}-{right.toNat}-{valid}" (maskInput left right)
           (wanted (.majority cfg retired) valid) (nativeMetadata "majority" left.toNat right.toNat (toJson valid)),
         fixture s!"filter-{left.toNat}-{right.toNat}-{valid}" (maskInput left right ++ conditionInput)
           (.eq (cfg.filterByFixed conditions) (.input (.nodes (proposed (left &&& right)))))
           (nativeMetadata "filter" left.toNat right.toNat (toJson (proposed (left &&& right)).toNat))]

def nativeUnary : List Json :=
  masks.flatMap (fun mask =>
    [true, false].flatMap fun valid =>
      let amount := count mask + if valid then 0 else 1
      let complement := if valid then ~~~mask else (~~~mask) ^^^ 1
      [fixture s!"cfg-card-{mask.toNat}-{valid}" (maskInput mask mask)
         (.eq (.cardinality cfg) (.input (.integer amount)))
         (nativeMetadata "cardinality" mask.toNat 0 (toJson amount)),
       fixture s!"retired-card-{mask.toNat}-{valid}" (maskInput mask mask)
         (.eq (.cardinality retired) (.input (.integer amount)))
         (nativeMetadata "cardinality" mask.toNat 1 (toJson amount)),
       fixture s!"not-{mask.toNat}-{valid}" (maskInput mask mask)
         (.eq (.nodesNot cfg) (.input (.nodes complement)))
         (nativeMetadata "not" mask.toNat 0 (toJson complement.toNat))]) ++
  masks.flatMap (fun mask =>
    (List.ofFn fun node : Node =>
      [true, false].map fun answer =>
        fixture s!"member-{mask.toNat}-{node.val}-{answer}" (maskInput mask mask)
          (wanted (Predicate.member node cfg) answer)
          (nativeMetadata "member" mask.toNat node.val (toJson answer))).flatten)

private def contents : List (Prod Nat (Term .content)) :=
  [(0, .transaction (.integer (-1))), (1, .signature), (2, .reconfiguration (.nodes 0)),
   (2, .reconfiguration (.nodes 16385)), (3, .retiredCommitted (.nodes 0)),
   (3, .retiredCommitted (.nodes 32767))]

def nativeTags : List Json :=
  (contents.mapIdx fun index (tag, content) =>
    ([(0, ContentTag.transaction), (1, .signature), (2, .reconfiguration), (3, .retiredCommitted)].flatMap
      fun (testTag, test) =>
        [true, false].map fun answer =>
          fixture s!"tag-{index}-{testTag}-{answer}"
            [.equal (.unknown .int 2) (.integer 0), .equal (cell 0) (.entry (.integer 0) content)]
            (wanted (.isContent test (.entryContent (.cell 0))) answer)
            (nativeMetadata "tag" tag testTag (toJson answer)))).flatten ++
  (contents.mapIdx fun index (tag, content) =>
    masks.flatMap fun support =>
      [true, false].map fun answer =>
        fixture s!"guarded-{index}-{support.toNat}-{answer}"
          [.equal (.unknown .int 2) (.integer 0), .equal (cell 0) (.entry (.integer 0) content)]
          (wanted (Predicate.guardedConfigurationMajority (.input (.nodes support)) (.entryContent (.cell 0))) answer)
          (nativeMetadata "guarded" support.toNat (if index == 3 then 16385 else 0) (toJson answer) ++
            [("tag", toJson tag)])).flatten

def nativeSelectors : List Json :=
  ([-1, 0, 1] : List Int).flatMap (fun value =>
    [true, false].map fun valid =>
      let answer := value + if valid then 0 else 1
      fixture s!"transaction-{value}-{valid}"
        [.equal (.unknown .int 2) (.integer 0),
         .equal (cell 0) (.entry (.integer 0) (.transaction (.integer value)))]
        (.eq (.transactionId (.entryContent (.cell 0))) (.input (.integer answer)))
        [("operation", toJson "selector"), ("value", toJson value), ("answer", toJson answer)]) ++
  [true, false].flatMap (fun valid =>
    let input : SmtScript.Formula :=
      [.equal (.unknown .int 2) (.integer 0), .equal (cell 0) (.entry (.integer 0) .signature),
       .equal (.transactionId .signature) (.integer (-7)),
       .equal (.configurationNodes .signature) (.nodes 21845),
       .equal (.retiredNodes .signature) (.nodes 16384),
       .equal (.app .content .int 0 .signature) (.integer 0),
       .equal (.app .content .nodes 0 .signature) (.nodes 0)]
    [fixture s!"wrong-tx-{valid}" input
       (.eq (.transactionId (.entryContent (.cell 0))) (.input (.integer (if valid then -7 else 0))))
       [("operation", toJson "selector"), ("value", toJson (-7 : Int)), ("answer", toJson (if valid then (-7 : Int) else 0))],
     fixture s!"wrong-cfg-{valid}" input
       (.eq (.configurationNodes (.entryContent (.cell 0))) (.input (.nodes (if valid then 21845 else 0))))
       [("operation", toJson "selector"), ("value", toJson (21845 : Nat)), ("answer", toJson (if valid then (21845 : Nat) else 0))],
     fixture s!"wrong-retired-{valid}" input
       (.eq (.retiredNodes (.entryContent (.cell 0))) (.input (.nodes (if valid then 16384 else 0))))
       [("operation", toJson "selector"), ("value", toJson (16384 : Nat)), ("answer", toJson (if valid then (16384 : Nat) else 0))]])

end CCFRaft.Sparse.EntryPredicateFixtures

def main (args : List String) : IO UInt32 := do
  let cases := match args with
    | [] => some (CCFRaft.Sparse.EntryPredicateFixtures.comparisons ++ CCFRaft.Sparse.EntryPredicateFixtures.identities)
    | ["--native"] => some (CCFRaft.Sparse.EntryPredicateFixtures.nativeMasks ++
        CCFRaft.Sparse.EntryPredicateFixtures.nativeUnary ++ CCFRaft.Sparse.EntryPredicateFixtures.nativeTags ++
        CCFRaft.Sparse.EntryPredicateFixtures.nativeSelectors)
    | _ => none
  let some cases := cases |
    ( <- IO.getStderr).putStrLn "usage: EntryPredicateFixtureMain.lean [--native]"
    return 1
  IO.println (Lean.toJson cases).compress
  return 0
