import Sparse.NativeSorts
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

end CCFRaft.Sparse.NativeSortFixtures

def main : IO Unit :=
  IO.println (Lean.toJson CCFRaft.Sparse.NativeSortFixtures.fixtures).compress
