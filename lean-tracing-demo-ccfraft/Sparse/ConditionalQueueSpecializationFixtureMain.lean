import Sparse.ConditionalQueueSpecialization
import Lean.Data.Json

set_option autoImplicit false

namespace CCFRaft.Sparse.ConditionalQueueSpecializationFixtures

open Smt Lean
open QueueEncoding (InputInt)

private def fact (kind id : Nat) (value : Bool) : Term .bool :=
  match kind with
  | 0 => if value then .unknown .bool id else .not (.unknown .bool id)
  | 1 => .equal (.unknown .bool id) (.boolean value)
  | 2 => .equal (.boolean value) (.unknown .bool id)
  | _ => .equal (.unknown .bool id) (.boolean (!value))

private def guard (kind id : Nat) : Term .bool :=
  if kind == 3 then .not (.unknown .bool id) else .unknown .bool id

private def fixture (name : String) (input : SmtScript.Formula)
    (entries : List ConditionalQueueSpecialization.Entry)
    (length : InputInt) (metadata : List (String × Json)) : Json :=
  let selected := ConditionalQueueSpecialization.selectKnown input entries
  let script := ConditionalQueueSpecialization.render input entries length
  let reference := match selected with
    | none => ConditionalQueueTraceEncoding.render input entries length
    | some trace => QueueSummaryEncoding.render input trace length
  Json.mkObj ([
    ("name", toJson name), ("script", toJson script), ("known", toJson selected.isSome),
    ("same_selected_backend", toJson (script == reference)),
    ("selected_events", toJson (selected.map List.length)),
    ("encoded_events", toJson (selected.map (fun trace => (QueueSummaryEncoding.normalize trace).length))),
    ("parsed_script", toJson ((SmtScriptText.parse script).map SmtScript.renderCommands))] ++ metadata)

def matrix : List Json :=
  (List.range 4).flatMap fun kind =>
    (List.range 3).flatMap fun initial =>
      (List.range 4).flatMap fun mask =>
        [false, true].flatMap fun aliases =>
          (List.range 4).map fun finalLength =>
            let sendActive := mask % 2 == 1
            let popActive := mask / 2 == 1
            fixture s!"finite-{kind}-{initial}-{mask}-{aliases}-{finalLength}"
              [fact kind 10 sendActive, fact kind 11 popActive,
               .equal (.unknown .int 0) (.integer 0),
               .equal (.unknown .int 1) (.integer (if aliases then 0 else 1))]
              [(guard kind 10, .send (.symbolic 0)), (guard kind 11, .pop (.symbolic 1)),
               (.boolean true, .length finalLength)]
              (.literal initial)
              [("initial_length", toJson initial), ("mask", toJson mask),
               ("aliases", toJson aliases), ("final_length", toJson finalLength)]

private def verdict (expected : String) (known : Bool) : List (String × Json) :=
  [("expected", toJson expected), ("expected_known", toJson known)]

def edges : List Json :=
  [fixture "unknown-guard" []
    [(.unknown .bool 50, .send (.literal 0)), (.boolean true, .length 0)]
    (.literal 0) (verdict "sat" false),
   fixture "unknown-required" [.unknown .bool 51]
    [(.unknown .bool 50, .send (.literal 0)), (.unknown .bool 51, .length 1)]
    (.literal 0) (verdict "sat" false),
   fixture "inactive-uf-guard" []
    [(.ite (.boolean false) (.app .int .bool 1000000 (.integer 0)) (.boolean true),
      .length 0)]
    (.literal 0) (verdict "sat" false),
   fixture "contradictory-input" [.unknown .bool 10, .not (.unknown .bool 10)]
    [(.unknown .bool 10, .send (.literal 0))] (.literal 0) (verdict "unsat" true),
   fixture "negative-length" [] [] (.literal (-1)) (verdict "unsat" true),
   fixture "empty-trace" [] [] (.literal 0) (verdict "sat" true),
   fixture "double-negation" [.unknown .bool 10]
    [(.not (.not (.unknown .bool 10)), .length 0)]
    (.literal 0) (verdict "sat" true),
   fixture "million-symbolic-length" [.equal (.unknown .int 0) (.integer 1000000)]
    [(.boolean true, .length 1000000)] (.symbolic 0) (verdict "sat" true),
   fixture "duplicate-initial" []
    [(.boolean true, .peek (.literal 0)), (.boolean true, .send (.literal 0)),
     (.boolean true, .pop (.literal 0)), (.boolean true, .peek (.literal 0)),
     (.boolean true, .length 1)]
    (.literal 2) (verdict "sat" true),
   fixture "duplicate-initial-too-short" []
    [(.boolean true, .peek (.literal 0)), (.boolean true, .send (.literal 0)),
     (.boolean true, .pop (.literal 0)), (.boolean true, .peek (.literal 0))]
    (.literal 1) (verdict "unsat" true),
   fixture "redundant-sends" []
    [(.boolean true, .send (.symbolic 0)), (.boolean true, .send (.symbolic 0)),
     (.boolean true, .send (.symbolic 0)), (.boolean true, .length 1)]
    (.literal 0) (verdict "sat" true)]

end CCFRaft.Sparse.ConditionalQueueSpecializationFixtures

def main : IO Unit :=
  IO.println (Lean.toJson (CCFRaft.Sparse.ConditionalQueueSpecializationFixtures.matrix ++
    CCFRaft.Sparse.ConditionalQueueSpecializationFixtures.edges)).compress
