module

import all ConsensusCoverage.CrossCheck
import all ConsensusCoverage.Classes
meta import Lean

#print axioms ConsensusCoverage.CrossCheck.left_backed_inl_initial
#print axioms ConsensusCoverage.CrossCheck.left_backed_inr_initial
#print axioms ConsensusCoverage.CrossCheck.leader_led_now_after_inl_s1
#print axioms ConsensusCoverage.CrossCheck.leader_led_now_after_inl_s2

-- A bare `cases event` used to leave the generated receive and internal
-- predicates definitionally identical. Check the actual equation in each
-- generated summary/act branch, not just how many branches the ledger lists.
open Lean in
run_cmd do
  let .lit (.strVal table) := (← getConstInfo `ConsensusCoverage.Classes.table).value!
    | throwError "expected the generated branch ledger"
  let mut checked := 0
  for row in table.splitOn "\n" do
    let "class" :: label :: "step" :: _ :: _ :: tag :: _ := row.splitOn "\t" | continue
    unless label.startsWith "step_summary_" || label.startsWith "step_act_" do continue
    let pred ← getConstInfo (`ConsensusCoverage.Classes ++ label.toName)
    let found := pred.value!.find? fun e => Id.run do
      unless e.isAppOfArity ``Eq 3 do return false
      let args := e.getAppArgs
      let some (.str _ rhs) := args[2]!.getAppFn.constName? | return false
      return args[1]!.isBVar && rhs == tag
    if found.isNone then throwError "missing constructor equation in {label}: {tag}"
    checked := checked + 1
  unless checked == 23 do throwError "expected 23 annotated constructor branches, checked {checked}"
  logInfo m!"checked {checked} constructor equations in generated step predicates"
