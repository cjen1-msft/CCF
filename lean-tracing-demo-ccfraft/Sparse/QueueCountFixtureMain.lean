import Sparse.QueueEncoding
import Sparse.QueueScalarEncoding
import Sparse.QueueInitialEncoding
import Sparse.QueueTraceEncoding
import Sparse.QueueSummaryEncoding
import Sparse.ConditionalQueueTraceEncoding
import Sparse.SmtScriptText
import Lean.Data.Json

set_option autoImplicit false

namespace CCFRaft.Sparse.QueueCountFixtures

open QueueEncoding QueueStream Smt Lean

private def formulaFields (formula : SmtScript.Formula) : List (Prod String Json) :=
  let script := SmtScript.render formula
  [("script", toJson script),
    ("parsed_script", toJson ((SmtScriptText.parse script).map SmtScript.renderCommands)),
    ("command_value", toJson (SmtScript.run regressionInput (SmtScript.compile formula))),
    ("parsed_value", toJson (SmtScriptText.runText regressionInput script))]

private def fixture (name expected : String) (input : SmtScript.Formula)
    (trace : List (Event InputInt)) (observations : List (Observation trace)) : Json :=
  Json.mkObj ([("name", toJson name), ("expected", toJson expected),
    ("scope", toJson "count-read"),
    ("query_pairs", toJson (syntaxQueries [] trace observations).length)] ++
    formulaFields (encode input [] trace observations))

private def scalarFixture (name expected : String) (input : SmtScript.Formula)
    (trace : List (Event InputInt)) (observations : List (Observation trace))
    (length : InputInt) : Json :=
  Json.mkObj ([("name", toJson name), ("expected", toJson expected),
    ("scope", toJson "count-and-scalar"),
    ("count_range_end", toJson (freshBase input + QueueReadback.writeCount trace + 1)),
    ("scalar_base", toJson (QueueScalarEncoding.scalarBase input [] trace observations))] ++
    formulaFields (QueueScalarEncoding.encode input [] trace observations length))

private def initialFixture (summarize : Bool) (name expected : String) (input : SmtScript.Formula)
    (trace : List (Event InputInt)) (length : InputInt) : Json :=
  Json.mkObj ([("name", toJson name), ("expected", toJson expected),
    ("scope", toJson (if summarize then "summary-whole-queue" else "count-scalar-initial")),
    ("encoded_events", toJson (if summarize then QueueSummaryEncoding.normalize trace else trace).length),
    ("tracked_keys", toJson (QueueInitialEncoding.eventKeys trace).length)] ++
    formulaFields (if summarize then QueueSummaryEncoding.encode input trace length
      else QueueInitialEncoding.encode input trace length))

private def sendOne : List (Event InputInt) := [.send (.literal 1)]
private def sendSymbol : List (Event InputInt) := [.send (.symbolic 0)]
private def popOne : List (Event InputInt) := [.pop (.literal 1)]
private def sameKeys : Term .bool := .equal (.unknown .int 0) (.unknown .int 1)

private def otherKey (expected : Int) : List (Observation sendOne) :=
  [{ version := 0, key := .literal 2, expected := .literal 7 },
   { version := 1, key := .literal 2, expected := .literal expected }]

private def aliasCounts : List (Observation []) :=
  [{ version := 0, key := .symbolic 0, expected := .literal 0 },
   { version := 0, key := .symbolic 1, expected := .literal 1 }]

private def storedAlias : List (Observation sendSymbol) :=
  [{ version := 0, key := .symbolic 0, expected := .literal 0 },
   { version := 0, key := .symbolic 1, expected := .literal 0 },
   { version := 1, key := .symbolic 1, expected := .literal 0 }]

private def symbolicExpected : List (Observation sendOne) :=
  [{ version := 0, key := .literal 1, expected := .literal 0 },
   { version := 1, key := .literal 1, expected := .symbolic 9 }]

def fixtures : List Json :=
  [
    fixture "duplicate-send" "sat" [] regressionTrace regressionObservations,
    fixture "duplicate-send-contradiction" "unsat" [] regressionTrace
      (regressionObservations ++
        [{ version := 2, key := .literal (-2), expected := .literal 2 }]),
    fixture "other-key-preserved" "sat" [] sendOne (otherKey 7),
    fixture "other-key-contradiction" "unsat" [] sendOne (otherKey 8),
    fixture "aliased-root-counts" "unsat" [sameKeys] [] aliasCounts,
    fixture "distinct-root-counts" "sat" [.not sameKeys] [] aliasCounts,
    fixture "aliased-store-hit" "unsat" [sameKeys] sendSymbol storedAlias,
    fixture "distinct-store-miss" "sat" [.not sameKeys] sendSymbol storedAlias,
    fixture "fresh-function-namespace" "sat"
      [.equal (.app .int .int 1 (.integer 1)) (.integer 99)] sendOne
      [{ version := 0, key := .literal 1, expected := .literal 0 },
       { version := 1, key := .literal 1, expected := .literal 1 }],
    fixture "symbolic-expected-count" "sat"
      [.equal (.unknown .int 9) (.integer 1)] sendOne symbolicExpected,
    fixture "symbolic-expected-contradiction" "unsat"
      [.equal (.unknown .int 9) (.integer 2)] sendOne symbolicExpected,
    fixture "count-only-allows-pop-underflow" "sat" [] popOne
      [{ version := 0, key := .literal 1, expected := .literal 0 },
       { version := 1, key := .literal 1, expected := .literal (-1) }],
    fixture "count-only-does-not-check-fifo" "sat" []
      [.peek (.literal 1), .length 0]
      [{ version := 0, key := .literal 1, expected := .literal 0 }]
  ]

def scalarFixtures : List Json :=
  [
    scalarFixture "duplicate-send-and-pop" "sat" [] regressionTrace regressionObservations
      (.literal 0),
    scalarFixture "duplicate-send-wrong-length" "unsat" []
      [.send (.literal (-2)), .send (.literal (-2)), .pop (.literal (-2)), .length 1]
      [{ version := 0, key := .literal (-2), expected := .literal 0 }] (.literal 0),
    scalarFixture "empty-peek" "unsat" [] [.peek (.literal 1)] [] (.literal 0),
    scalarFixture "empty-pop" "unsat" [] popOne
      [{ version := 0, key := .literal 1, expected := .literal 1 }] (.literal 0),
    scalarFixture "nonpositive-pop-count" "unsat" [] popOne
      [{ version := 0, key := .literal 1, expected := .literal 0 }] (.literal 1),
    scalarFixture "negative-initial-length" "unsat" [] [] [] (.literal (-1)),
    scalarFixture "unknown-million-initial-length" "sat" []
      [.length 1000000, .peek (.symbolic 0), .pop (.symbolic 0), .length 999999]
      [{ version := 0, key := .symbolic 0, expected := .literal 1 }] (.symbolic 10),
    scalarFixture "repeated-peeks-cannot-differ" "unsat" [.not sameKeys]
      [.peek (.symbolic 0), .peek (.symbolic 1)] [] (.literal 1),
    scalarFixture "repeated-peeks-can-alias" "sat" [sameKeys]
      [.peek (.symbolic 0), .peek (.symbolic 1)] [] (.literal 1),
    scalarFixture "send-order-cannot-differ" "unsat" [.not sameKeys]
      [.send (.symbolic 0), .peek (.symbolic 1)]
      [{ version := 0, key := .symbolic 0, expected := .literal 0 }] (.literal 0),
    scalarFixture "send-order-can-alias" "sat" [sameKeys]
      [.send (.symbolic 0), .peek (.symbolic 1)]
      [{ version := 0, key := .symbolic 0, expected := .literal 0 }] (.literal 0),
    scalarFixture "initial-budget-still-missing" "sat" []
      [.length 0, .send (.literal 1), .length 0]
      [{ version := 0, key := .literal 1, expected := .literal 1 }] (.literal 0),
    scalarFixture "initial-histogram-still-missing" "sat" [] [.peek (.literal 1)]
      [{ version := 0, key := .literal 1, expected := .literal 0 }] (.literal 1),
    scalarFixture "unrendered-count-version-reserved" "sat"
      [.equal (.app .int .int 1 (.integer 0)) (.integer 44)] sendOne [] (.literal 0)
  ]

def initialFixtures (summarize : Bool := false) : List Json :=
  let initialFixture := initialFixture summarize
  [
    initialFixture "empty-queue" "sat" [] [] (.literal 0),
    initialFixture "negative-length" "unsat" [] [] (.literal (-1)),
    initialFixture "unknown-million-length" "sat" [] [.length 1000000] (.symbolic 10),
    initialFixture "empty-peek" "unsat" [] [.peek (.symbolic 0)] (.literal 0),
    initialFixture "sent-key-remains-present" "sat" []
      [.send (.symbolic 0), .peek (.symbolic 0), .send (.symbolic 0), .length 1] (.literal 0),
    initialFixture "duplicate-send-cannot-grow" "unsat" []
      [.send (.symbolic 0), .peek (.symbolic 0), .send (.symbolic 0), .length 2] (.literal 0),
    initialFixture "initial-head-is-present" "sat" []
      [.peek (.symbolic 0), .send (.symbolic 0), .length 1] (.literal 1),
    initialFixture "initial-head-cannot-be-fresh" "unsat" []
      [.peek (.symbolic 0), .send (.symbolic 0), .length 2] (.literal 1),
    initialFixture "aliased-keys-count-once" "sat" [sameKeys]
      [.peek (.symbolic 0), .peek (.symbolic 1)] (.literal 1),
    initialFixture "distinct-keys-cannot-share-head" "unsat" [.not sameKeys]
      [.peek (.symbolic 0), .peek (.symbolic 1)] (.literal 1),
    initialFixture "distinct-key-cannot-fit-budget" "unsat" [.not sameKeys]
      [.peek (.symbolic 0), .send (.symbolic 1), .length 1] (.literal 1),
    initialFixture "distinct-key-is-appended" "sat" [.not sameKeys]
      [.peek (.symbolic 0), .send (.symbolic 1), .length 2] (.literal 1),
    initialFixture "initial-duplicates-allowed" "sat" []
      [.pop (.symbolic 0), .pop (.symbolic 0), .length 0] (.literal 2),
    initialFixture "insufficient-initial-duplicates" "unsat" []
      [.pop (.symbolic 0), .pop (.symbolic 0), .length 0] (.literal 1),
    initialFixture "new-send-not-in-initial-histogram" "sat" []
      [.pop (.symbolic 0), .pop (.symbolic 0), .send (.symbolic 0),
       .peek (.symbolic 0), .length 1] (.literal 2),
    initialFixture "last-unconsumed-peek" "sat"
      [.equal (.unknown .int 1) (.unknown .int 2)]
      [.pop (.symbolic 0), .peek (.symbolic 1), .peek (.symbolic 2)] (.literal 2),
    initialFixture "earlier-peek-still-constrains-order" "unsat"
      [.not (.equal (.unknown .int 1) (.unknown .int 2))]
      [.pop (.symbolic 0), .peek (.symbolic 1), .peek (.symbolic 2)] (.literal 2),
    initialFixture "first-send-can-already-be-present" "sat" []
      [.send (.symbolic 0), .length 1] (.literal 1),
    initialFixture "empty-budget-forces-append" "unsat" []
      [.length 0, .send (.symbolic 0), .length 0] (.literal 0),
    initialFixture "unknown-large-prefix" "sat" []
      [.peek (.symbolic 0), .pop (.symbolic 0), .length 999999] (.symbolic 10)
  ]

def summaryRegressions : List Json :=
  let fixture := initialFixture true
  [
    fixture "alias-pop-requires-send" "sat" [sameKeys]
      [.send (.symbolic 0), .pop (.symbolic 1), .send (.symbolic 0), .length 1] (.literal 0),
    fixture "alias-pop-final-zero-impossible" "unsat" [sameKeys]
      [.send (.symbolic 0), .pop (.symbolic 1), .send (.symbolic 0), .length 0] (.literal 0),
    fixture "distinct-literal-pop-preserves-present" "sat" []
      [.send (.literal 0), .pop (.literal 1), .send (.literal 0), .length 1] (.literal 1),
    fixture "distinct-literal-pop-cannot-grow" "unsat" []
      [.send (.literal 0), .pop (.literal 1), .send (.literal 0), .length 2] (.literal 1),
    fixture "contradictory-earlier-length-retained" "unsat" []
      [.send (.literal 0), .length 2, .send (.literal 0), .length 1] (.literal 0)
  ]

private def exhaustiveChoices : List (Prod String (Prod Nat (Event InputInt))) :=
    [("send", 0, .send (.symbolic 0)), ("send", 1, .send (.symbolic 1)),
     ("pop", 0, .pop (.symbolic 0)), ("pop", 1, .pop (.symbolic 1)),
     ("peek", 0, .peek (.symbolic 0)), ("peek", 1, .peek (.symbolic 1)),
     ("length", 0, .length 0), ("length", 1, .length 1), ("length", 2, .length 2)]

def exhaustiveFixtures (summarize : Bool := false) : List Json :=
  let choices := exhaustiveChoices
  ([0, 1, 2] : List Nat).flatMap fun length =>
    [false, true].flatMap fun aliases =>
      choices.flatMap fun left =>
        choices.map fun right =>
          let input := [if aliases then sameKeys else .not sameKeys]
          let trace := [left.2.2, right.2.2]
          let name := s!"{length}-{aliases}-{left.1}{left.2.1}-{right.1}{right.2.1}"
          Json.mkObj ([("name", toJson name), ("initial_length", toJson length),
            ("aliases", toJson aliases),
            ("events", toJson [(left.1, left.2.1), (right.1, right.2.1)])] ++
            formulaFields (if summarize then QueueSummaryEncoding.encode input trace (.literal length)
              else QueueInitialEncoding.encode input trace (.literal length)))

def conditionalExhaustiveFixtures : List Json :=
  ([0, 1, 2] : List Nat).flatMap fun length =>
    [false, true].flatMap fun aliases =>
      exhaustiveChoices.flatMap fun left =>
        exhaustiveChoices.flatMap fun right =>
          [false, true].flatMap fun leftActive =>
            [false, true].map fun rightActive =>
              let leftGuard := Term.unknown .bool 10
              let rightGuard := Term.unknown .bool 11
              let input := [if aliases then sameKeys else .not sameKeys,
                .equal leftGuard (.boolean leftActive), .equal rightGuard (.boolean rightActive)]
              let name := s!"{length}-{aliases}-{left.1}{left.2.1}-{right.1}{right.2.1}-{leftActive}-{rightActive}"
              Json.mkObj ([("name", toJson name), ("initial_length", toJson length),
                ("aliases", toJson aliases), ("active", toJson [leftActive, rightActive]),
                ("events", toJson [(left.1, left.2.1), (right.1, right.2.1)])] ++
                formulaFields (ConditionalQueueTraceEncoding.encode input
                  [(leftGuard, left.2.2), (rightGuard, right.2.2)] (.literal length)))

def conditionalFixtures : List Json :=
  let fixed := fun (active : Bool) (event : Event InputInt) => (Term.boolean active, event)
  let guard := Term.equal (.app .int .int 500 (.integer 0)) (.integer 7)
  let nativeGuard := Term.isContent .signature (.unknown .content 30)
  let fixture := fun name expected input entries length =>
    Json.mkObj ([("name", toJson name), ("expected", toJson expected),
      ("scope", toJson "conditional-whole-queue")] ++
      formulaFields (ConditionalQueueTraceEncoding.encode input entries length))
  [
    fixture "inactive-pop-preserves-head" "sat" [.not sameKeys]
      [fixed true (.peek (.symbolic 0)), fixed false (.pop (.symbolic 1)),
       fixed true (.peek (.symbolic 0)), fixed true (.length 1)] (.literal 1),
    fixture "inactive-pop-cannot-shrink" "unsat" []
      [fixed false (.pop (.literal 0)), fixed true (.length 0)] (.literal 1),
    fixture "inactive-last-peek" "sat" [.not sameKeys]
      [fixed true (.peek (.symbolic 0)), fixed false (.peek (.symbolic 1))] (.literal 1),
    fixture "alias-initial-duplicates" "sat" [sameKeys]
      [fixed true (.pop (.symbolic 0)), fixed false (.pop (.literal 9)),
       fixed true (.pop (.symbolic 1)), fixed true (.length 0)] (.literal 2),
    fixture "active-send-suppresses-duplicate" "sat" []
      [fixed true (.send (.literal 0)), fixed false (.pop (.literal 0)),
       fixed true (.send (.literal 0)), fixed true (.length 1)] (.literal 0),
    fixture "active-send-cannot-grow-duplicate" "unsat" []
      [fixed true (.send (.literal 0)), fixed false (.pop (.literal 0)),
       fixed true (.send (.literal 0)), fixed true (.length 2)] (.literal 0),
    fixture "last-peek-outside-initial-prefix" "sat" []
      [fixed true (.pop (.literal 0)), fixed true (.send (.literal 1)),
       fixed true (.peek (.literal 1))] (.literal 1),
    fixture "guard-only-source-uf" "sat" []
      [(guard, .send (.literal 0)), (guard, .pop (.literal 0)),
       (.not guard, .pop (.literal 0))] (.literal 0),
    fixture "shared-source-guard-forced-false" "unsat" [.not guard]
      [(guard, .send (.literal 0)), (guard, .pop (.literal 0)),
       (.not guard, .pop (.literal 0))] (.literal 0),
    fixture "native-guard-true" "sat" [.equal (.unknown .content 30) .signature]
      [(nativeGuard, .send (.literal 0)), (nativeGuard, .pop (.literal 0)),
       fixed true (.length 0)] (.literal 0),
    fixture "native-guard-false" "sat" [.equal (.unknown .content 30) (.transaction (.integer 7))]
      [(nativeGuard, .pop (.literal 0)), fixed true (.length 0)] (.literal 0),
    fixture "negative-initial-length" "unsat" [] [] (.literal (-1)),
    fixture "million-initial-entries" "sat" []
      [fixed true (.peek (.literal 0)), fixed true (.pop (.literal 0)),
       fixed true (.length 999999)] (.literal 1000000),
    fixture "million-initial-contradiction" "unsat" []
      [fixed true (.peek (.literal 0)), fixed true (.pop (.literal 0)),
       fixed true (.length 1000000)] (.literal 1000000),
    fixture "symbolic-million-length" "sat" [.equal (.unknown .int 1000000) (.integer 1000000)]
      [fixed false (.pop (.literal 0)), fixed true (.length 1000000)] (.symbolic 1000000)
  ]

@[noinline] private def referenceInitialEncode (input : SmtScript.Formula)
    (trace : List (Event InputInt)) (length : InputInt) : SmtScript.Formula :=
  QueueScalarEncoding.encode input (QueueInitialEncoding.eventKeys trace) trace [] length ++
    QueueInitialEncoding.initialBlock (QueueEncoding.freshBase input)
      (QueueInitialEncoding.auxBase input trace length) length
      (CountedQueue.readHeads trace) (QueueInitialEncoding.eventKeys trace)

private theorem reference_initial_exact (input : SmtScript.Formula)
    (trace : List (Event InputInt)) (length : InputInt) :
    referenceInitialEncode input trace length = QueueInitialEncoding.encode input trace length := rfl

@[noinline] private def referenceCount (keys : List InputInt) (trace : List (Event InputInt))
    (observations : List (Observation trace)) (base : Nat) : SmtScript.Formula :=
  (syntaxQueries keys trace observations).map (readEquation trace base) ++
    observations.map (observationEquation base)

private theorem reference_count_exact (keys : List InputInt) (trace : List (Event InputInt))
    (observations : List (Observation trace)) (base : Nat) :
    referenceCount keys trace observations base = countFormula keys trace observations base := rfl

def cacheEquivalenceFixtures : IO (List Json) := do
  let traces : List (List (Event InputInt)) :=
    [[], [.peek (.symbolic 0)],
      [.send (.symbolic 0), .send (.symbolic 1), .pop (.symbolic 0), .peek (.symbolic 1), .length 1],
      [.pop (.literal (-2)), .peek (.literal (-2)), .length 1]]
  let inputs : List SmtScript.Formula :=
    [[], [.equal (.unknown .int 0) (.unknown .int 1),
      .equal (.app .int .int 2001 (.integer (-8))) (.integer 5), .unknown .bool 7]]
  let lengths : List InputInt := [.literal 0, .literal (-1), .symbolic 9999]
  let mut results := []
  for trace in traces do
    for input in inputs do
      for length in lengths do
        let current <- IO.mkRef (QueueInitialEncoding.render input trace length)
        let reference <- IO.mkRef (SmtScript.render (referenceInitialEncode input trace length))
        let script <- current.get
        if script != ( <- reference.get) then
          throw (IO.userError s!"cached queue script mismatch in case {results.length}")
        results := Json.mkObj [("case", toJson results.length), ("bytes", toJson script.utf8ByteSize)] :: results
  let countTraces : List (List (Event InputInt)) :=
    [[], [.peek (.symbolic 0)], [.length 1000000],
      [.send (.literal (-2)), .send (.symbolic 0), .pop (.literal (-2)), .peek (.symbolic 1)],
      [.pop (.symbolic 0), .send (.symbolic 1), .length 2]]
  for trace in countTraces do
    let keys := [.symbolic 0, .literal (-2), .symbolic 0, .symbolic 1]
    let observations : List (Observation trace) :=
      [{ version := 0, key := .symbolic 0, expected := .symbolic 9999 },
       { version := Fin.mk (QueueReadback.writeCount trace) (Nat.lt_succ_self _),
         key := .literal (-2), expected := .literal (-7) },
       { version := 0, key := .symbolic 0, expected := .literal 1 },
       { version := 0, key := .symbolic 1, expected := .literal 0 }]
    for base in [0, 1, 2002] do
      for observations in [[], observations] do
        let current <- IO.mkRef (SmtScript.render (countFormula keys trace observations base))
        let reference <- IO.mkRef (SmtScript.render (referenceCount keys trace observations base))
        let script <- current.get
        if script != ( <- reference.get) then
          throw (IO.userError s!"cached count script mismatch in case {results.length}")
        results := Json.mkObj [("case", toJson results.length), ("bytes", toJson script.utf8ByteSize)] :: results
  return results.reverse

end CCFRaft.Sparse.QueueCountFixtures

def main (args : List String) : IO UInt32 := do
  if args == ["--cache-equivalence"] then
    IO.println (Lean.toJson ( <- CCFRaft.Sparse.QueueCountFixtures.cacheEquivalenceFixtures)).compress
    return 0
  let fixtures := match args with
    | [] => some CCFRaft.Sparse.QueueCountFixtures.fixtures
    | ["--scalar"] => some CCFRaft.Sparse.QueueCountFixtures.scalarFixtures
    | ["--initial"] => some CCFRaft.Sparse.QueueCountFixtures.initialFixtures
    | ["--exhaustive"] => some CCFRaft.Sparse.QueueCountFixtures.exhaustiveFixtures
    | ["--summary-initial"] => some (CCFRaft.Sparse.QueueCountFixtures.initialFixtures true ++
        CCFRaft.Sparse.QueueCountFixtures.summaryRegressions)
    | ["--summary-exhaustive"] => some (CCFRaft.Sparse.QueueCountFixtures.exhaustiveFixtures true)
    | ["--conditional"] => some CCFRaft.Sparse.QueueCountFixtures.conditionalFixtures
    | ["--conditional-exhaustive"] => some CCFRaft.Sparse.QueueCountFixtures.conditionalExhaustiveFixtures
    | _ => none
  let some fixtures := fixtures |
    let stderr <- IO.getStderr
    stderr.putStrLn "usage: QueueCountFixtureMain.lean [--scalar | --initial | --exhaustive | --summary-initial | --summary-exhaustive | --conditional | --conditional-exhaustive | --cache-equivalence]"
    return 1
  IO.println (Lean.Json.arr fixtures.toArray).compress
  return 0
