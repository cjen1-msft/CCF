import Sparse.NativeConstructors
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

end CCFRaft.Sparse.NativeSortFixtures

def main (args : List String) : IO UInt32 := do
  let result := match args with
    | [] => some (Lean.toJson CCFRaft.Sparse.NativeSortFixtures.fixtures)
    | ["--constructors"] => some (Lean.toJson CCFRaft.Sparse.NativeSortFixtures.constructorFixtures)
    | ["--masks"] => some CCFRaft.Sparse.NativeSortFixtures.maskFixtures
    | _ => none
  let some result := result |
    ( <- IO.getStderr).putStrLn "usage: NativeSortFixtureMain.lean [--constructors | --masks]"
    return 1
  IO.println result.compress
  return 0
