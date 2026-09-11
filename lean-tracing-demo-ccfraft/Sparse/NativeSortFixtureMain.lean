import Sparse.NativeConstructors
import Sparse.NativeSelectors
import Lean.Data.Json

set_option autoImplicit false

namespace CCFRaft.Sparse.NativeSortFixtures

open Smt

private def assignment : Assignment where
  constant ty _ := match ty with
    | .bool => false | .int => 0 | .nodes => 0
    | .content => .signature | .entry => { term := 0, content := .signature }
  unary _ result _ _ := match result with
    | .bool => false | .int => 0 | .nodes => 0
    | .content => .signature | .entry => { term := 0, content := .signature }

private def fixture (name expected : String) (formula : SmtScript.Formula) : Lean.Json :=
  let script := SmtScript.render formula
  Lean.Json.mkObj [
    ("name", Lean.toJson name), ("expected", Lean.toJson expected),
    ("declarations", Lean.toJson (SmtScript.declarations formula).length),
    ("prelude", Lean.toJson ((SmtScript.prelude formula).map SmtScript.Command.render)),
    ("script", Lean.toJson script),
    ("reference_script", Lean.toJson (SmtScript.renderCommands
      (SmtScript.prelude formula ++ SmtScript.compiledBody formula))),
    ("parsed_script", Lean.toJson ((SmtScriptText.parse script).map SmtScript.renderCommands)),
    ("command_value", Lean.toJson (SmtScript.run assignment (SmtScript.compile formula))),
    ("parsed_value", Lean.toJson (SmtScriptText.runText assignment script))]

def fixtures : List Lean.Json :=
  [fixture "all-signatures" "sat" NativeSorts.signatures,
   fixture "inactive-native" "sat" NativeSorts.deadNativeBranch,
   fixture "false-before-native" "unsat" (.boolean false :: NativeSorts.deadNativeBranch)] ++
  (NativeSorts.allTypes.mapIdx fun index ty =>
    let left := Term.unknown ty 0
    let right := Term.unknown ty 1
    let selected := Term.ite (.boolean false) left right
    [fixture s!"self-{index}-sat" "sat" [.equal left left],
     fixture s!"self-{index}-unsat" "unsat" [.not (.equal left left)],
     fixture s!"ite-{index}-sat" "sat" [.not (.equal left right), .equal selected right],
     fixture s!"ite-{index}-unsat" "unsat" [.not (.equal selected right)]]).flatten ++
  (NativeSorts.allTypes.mapIdx fun domainIndex domain =>
    (NativeSorts.allTypes.mapIdx fun resultIndex result =>
      let left := Term.unknown domain 0
      let right := Term.unknown domain 1
      let outputsDiffer := Term.not (.equal (.app domain result 7 left) (.app domain result 7 right))
      [fixture s!"function-{domainIndex}-{resultIndex}-sat" "sat"
         [.not (.equal left right), outputsDiffer],
       fixture s!"function-{domainIndex}-{resultIndex}-unsat" "unsat"
         [.equal left right, outputsDiffer]]).flatten).flatten

private def contents : List (Term .content) :=
  [.transaction (.integer (-5)), .transaction (.integer 0), .signature,
   .reconfiguration (.nodes 0), .reconfiguration (.nodes 1),
   .reconfiguration (.nodes 16384), .reconfiguration (.nodes 32767),
   .retiredCommitted (.nodes 0), .retiredCommitted (.nodes 1),
   .retiredCommitted (.nodes 16384), .retiredCommitted (.nodes 32767)]

def constructorFixtures : List Lean.Json :=
  let unknown := Term.unknown .entry 0
  let reconstruct := Term.equal (.entry (.entryTerm unknown) (.entryContent unknown)) unknown
  [fixture "literal-only" "sat" NativeConstructors.literalFormula,
   fixture "false-before-literal" "unsat" (.boolean false :: NativeConstructors.literalFormula),
   fixture "dead-literal" "sat" [NativeConstructors.deadLiteralBranch],
   fixture "unknown-reconstruct" "sat" [reconstruct],
   fixture "unknown-reconstruct-false" "unsat" [.not reconstruct],
   fixture "constructed-uf-alias" "unsat"
     [.not (.equal
       (.app .entry .int 7 (.entry (.add (.integer (-3)) (.integer 1)) (.transaction (.integer (-5)))))
       (.app .entry .int 7 (.entry (.integer (-2)) (.transaction (.integer (-5))))))]] ++
  (contents.mapIdx fun leftIndex left =>
    (contents.mapIdx fun rightIndex right =>
      [fixture s!"content-eq-{leftIndex}-{rightIndex}" (if leftIndex = rightIndex then "sat" else "unsat")
         [.equal left right],
       fixture s!"content-ne-{leftIndex}-{rightIndex}" (if leftIndex = rightIndex then "unsat" else "sat")
         [.not (.equal left right)]]).flatten).flatten ++
  (contents.mapIdx fun index content =>
    ([-2, 0, 7] : List Int).flatMap fun term =>
      let entry := Term.entry (.integer term) content
      let correct := Term.and (.equal (.entryTerm entry) (.integer term))
        (.equal (.entryContent entry) content)
      [fixture s!"projections-{index}-{term}-sat" "sat" [correct],
       fixture s!"projections-{index}-{term}-unsat" "unsat" [.not correct]]).flatten

def maskFixtures : Lean.Json :=
  let masks := (List.range 32768).map fun value =>
    let text := (Term.nodes (BitVec.ofNat NODE_COUNT value)).render
    let parsed := match SmtExpressionText.parseAtom text with
      | some (.nodes nodes) => some nodes.toNat
      | _ => none
    Lean.Json.arr #[Lean.toJson value, Lean.toJson text, Lean.toJson parsed]
  let invalid := ["#b", "#b0", "#b00000000000000", "#b0000000000000000",
    "#b000000000000002", "#B000000000000000", "#x0000", "#b000000000000000junk"]
  Lean.Json.mkObj [("masks", Lean.toJson masks),
    ("invalid", Lean.toJson (invalid.map fun text =>
      (text, (SmtExpressionText.parseAtom text).isNone)))]

private def checkPair (name : String) (claim : Term .bool) : List Lean.Json :=
  [fixture (name ++ "-sat") "sat" [claim],
   fixture (name ++ "-unsat") "unsat" [.not claim]]

private def selectorCases {ty : Ty} (name : String)
    (raw guarded : Term .content -> Term ty) (proper : Term .content) (payload : Term ty)
    (wrong : List (Term .content)) (first second : Term ty) : List Lean.Json :=
  checkPair (name ++ "-proper") (.equal (raw proper) payload) ++
  (wrong.mapIdx fun index value =>
    [fixture s!"{name}-wrong-{index}-first" "sat" [.equal (raw value) first],
     fixture s!"{name}-wrong-{index}-second" "sat" [.equal (raw value) second],
     fixture s!"{name}-coherence-{index}" "unsat"
       [.equal (raw value) first, .equal (raw value) second]]).flatten ++
  [fixture (name ++ "-alias") "unsat"
     [.equal (.unknown .content 10) .signature,
      .not (.equal (raw (.unknown .content 10)) (raw .signature))]] ++
  checkPair (name ++ "-guarded-proper") (.equal (guarded proper) payload) ++
  (wrong.mapIdx fun index value =>
    checkPair s!"{name}-guarded-{index}" (.equal (guarded value) first)).flatten

def selectorFixtures : List Lean.Json :=
  let tx := Term.transaction (.integer (-5))
  let sig := Term.signature
  let cfg := Term.reconfiguration (.nodes 16384)
  let retired := Term.retiredCommitted (.nodes 32767)
  let tags : List ContentTag := [.transaction, .signature, .reconfiguration, .retiredCommitted]
  (tags.mapIdx fun tagIndex tag =>
    ([tx, sig, cfg, retired].mapIdx fun valueIndex value =>
      checkPair s!"tester-{tagIndex}-{valueIndex}"
        (.equal (.isContent tag value) (.boolean (tagIndex == valueIndex)))).flatten).flatten ++
  (tags.mapIdx fun index tag =>
    let test := Term.isContent tag (.unknown .content 10)
    checkPair s!"unknown-tester-{index}" (.equal test test)).flatten ++
  selectorCases "tx" Term.transactionId (fun value => NativeSelectors.txOr value (.integer (-9)))
    tx (.integer (-5)) [sig, cfg, retired] (.integer (-9)) (.integer 7) ++
  selectorCases "cfg" Term.configurationNodes (fun value => NativeSelectors.cfgOr value (.nodes 1))
    cfg (.nodes 16384) [tx, sig, retired] (.nodes 1) (.nodes 2) ++
  selectorCases "retired" Term.retiredNodes (fun value => NativeSelectors.retiredOr value (.nodes 2))
    retired (.nodes 32767) [tx, sig, cfg] (.nodes 2) (.nodes 3) ++
  [fixture "tx-independent-uf" "sat"
     [.equal (.app .content .int 0 sig) (.integer 0),
      .equal (.transactionId sig) (.integer 7)],
   fixture "cfg-independent-uf" "sat"
     [.equal (.app .content .nodes 0 sig) (.nodes 0),
      .equal (.configurationNodes sig) (.nodes 1)],
   fixture "retired-independent-uf" "sat"
     [.equal (.app .content .nodes 1 sig) (.nodes 0),
      .equal (.retiredNodes sig) (.nodes 2)],
   fixture "guarded-forced-wrong-values" "sat"
     [.equal (.transactionId sig) (.integer 7),
      .equal (.configurationNodes sig) (.nodes 32767),
      .equal (.retiredNodes sig) (.nodes 16384),
      .equal (NativeSelectors.txOr sig (.integer (-9))) (.integer (-9)),
      .equal (NativeSelectors.cfgOr sig (.nodes 1)) (.nodes 1),
      .equal (NativeSelectors.retiredOr sig (.nodes 2)) (.nodes 2)],
   fixture "different-guard-operand" "sat"
     [.equal (.ite (.isContent .transaction tx) (.transactionId sig) (.integer 0)) (.integer 7)]]

end CCFRaft.Sparse.NativeSortFixtures

def main (args : List String) : IO UInt32 := do
  let result := match args with
    | [] => some (Lean.toJson CCFRaft.Sparse.NativeSortFixtures.fixtures)
    | ["--constructors"] => some (Lean.toJson CCFRaft.Sparse.NativeSortFixtures.constructorFixtures)
    | ["--masks"] => some CCFRaft.Sparse.NativeSortFixtures.maskFixtures
    | ["--selectors"] => some (Lean.toJson CCFRaft.Sparse.NativeSortFixtures.selectorFixtures)
    | _ => none
  let some result := result |
    ( <- IO.getStderr).putStrLn "usage: NativeSortFixtureMain.lean [--constructors | --masks | --selectors]"
    return 1
  IO.println result.compress
  return 0
