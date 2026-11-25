module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ActionProfile
import all ConsensusCoverage.FrontierWitnesses
import all ConsensusCoverage.JointWitnesses
import all ConsensusCoverage.MessageWitnesses
import all ConsensusCoverage.ExploredWitnesses
import all ConsensusCoverage.BoundedWitnesses
import all ConsensusCoverage.CaseWitnesses
import all ConsensusCoverage.CensusWidth
meta import Lean

namespace ConsensusCoverage.ReadersCorpus

open ActionProfile FrontierRows

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxRecDepth 8192
set_option maxHeartbeats 0

private structure Schedule where
  run : Run
  choices : List (Nat × Nat)
  valid : run.valid

private def Schedule.steps (s : Schedule) : Option (List Step) :=
  (JointWitnesses.recordedAt s.run s.valid s.choices).map (List.map Subtype.val)

private def Schedule.at (s : Schedule) (offset : Nat) : Option Step := do
  let shortened := { s with run.schedule := s.run.schedule.take (offset + 1) }
  (← shortened.steps)[offset]?

private def joint : List Schedule :=
  ⟨MessageWitnesses.solo.run, [], MessageWitnesses.solo.valid⟩ ::
    JointWitnesses.multiRuns.map fun r => ⟨r.val, [], r.property.1⟩

open Lean Meta Elab Term in
/-- Recover the replay inputs, including sparse queue overrides, from the
same applications that certify the witness modules. -/
local elab "certificate_schedules%" table:ident "from" certify:ident "validAt" valid:num : term => do
  let table ← realizeGlobalConstNoOverloadWithInfo table
  let certify ← realizeGlobalConstNoOverloadWithInfo certify
  let mut list := (← getConstInfo table).value!
  let mut out := #[]
  repeat
    let list' := (← whnf list).consumeMData
    if list'.isAppOf ``List.nil then break
    unless list'.isAppOfArity ``List.cons 3 do
      throwError "expected a literal certificate list, got {list'.getAppFn}"
    let cert := list'.getArg! 1
    let .const name _ := cert.consumeMData | throwError "expected a named certificate"
    let call := (← getConstInfo name).value!.consumeMData
    unless call.isAppOf certify do throwError "unexpected certificate producer for {name}"
    let args := call.getAppArgs
    let some valid := args[valid.getNat]? | throwError "missing schedule validity proof"
    out := out.push (← mkAppM ``Schedule.mk #[args[0]!, args[1]!, valid])
    list := list'.appArg!
  mkListLit (mkConst ``Schedule) out.toList

private def explored : List Schedule :=
  certificate_schedules% ExploredWitnesses.certificates from ExploredWitnesses.certify validAt 3

private def bounded : List Schedule :=
  certificate_schedules% BoundedWitnesses.certificates from BoundedWitnesses.certify validAt 3

private def cases : List Schedule :=
  certificate_schedules% CaseWitnesses.certificates from CaseWitnesses.certify validAt 2

private def widthSchedule (commands : List Command) : Schedule :=
  ⟨CensusWidth.onTwo commands, [], by
    change (CensusWidth.onTwo []).cfg.Nonempty ∧ (CensusWidth.onTwo []).nodes.Nodup
    decide⟩

open Lean Meta Elab Term in
/-- Recover both schedules from every certified wider-label split. -/
local elab "width_schedules%" : term => do
  let mut list := (← getConstInfo ``CensusWidth.splits).value!
  let mut out := #[]
  repeat
    let cell := (← whnf list).consumeMData
    if cell.isAppOf ``List.nil then break
    unless cell.isAppOfArity ``List.cons 3 do
      throwError "expected a literal wider-label certificate list"
    let call := (cell.getArg! 1).consumeMData
    unless call.isAppOfArity ``CensusWidth.splitAt 6 do
      throwError "expected a wider-label split with two schedules"
    for i in [2, 3] do
      out := out.push (mkApp (mkConst ``widthSchedule) (call.getArg! i))
    list := cell.appArg!
  mkListLit (mkConst ``Schedule) out.toList

private def width : List Schedule := width_schedules%

/-- Every schedule used by the witness modules, in certificate order. -/
private def schedules : List Schedule := joint ++ explored ++ bounded ++ cases ++ width

public def scheduleCount : Nat := schedules.length

/-- Replay the entire indexed schedule, including its recorded queue choices. -/
public def steps (schedule : Nat) : Option (List Step) :=
  schedules[schedule]?.bind Schedule.steps

/-- Replay just enough of a schedule to recover its initialized step at `offset`. -/
public def stepAt (schedule offset : Nat) : Option Step :=
  schedules[schedule]?.bind (·.at offset)

/-- Case certificates keep their own indices when earlier families grow. -/
public def caseStepAt (schedule offset : Nat) : Option Step :=
  cases[schedule]?.bind (·.at offset)

/-- Wider-label certificates keep their own indices when earlier families grow. -/
public def widthStepAt (schedule offset : Nat) : Option Step :=
  width[schedule]?.bind (·.at offset)

end ConsensusCoverage.ReadersCorpus
