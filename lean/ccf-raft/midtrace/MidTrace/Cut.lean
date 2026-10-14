module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import CCFRaft.Replay

public section

/-!
Simulates a trace whose start is missing by dropping a prefix of a replay
document. The cut removes the first `count` actions, and the observations
recorded for the last removed action, so the suffix starts at the first raw
log record after that action's records.
-/

namespace CCFRaft.MidTrace

open Lean

private def originLines (instruction : Json) : List Nat :=
  match instruction.getObjVal? "origin" >>= Json.getArr? with
  | .ok origins =>
      origins.toList.filterMap
        fun origin =>
          (origin.getObjVal? "line" >>= Json.getNat?).toOption
  | .error _ => []

private def isAction (instruction : Json) : Bool :=
  (instruction.getObjVal? "kind" >>= Json.getStr?).toOption == some "action"

/-- The index of the first kept instruction, or `none` if fewer than `count` actions exist. -/
def cutIndex (instructions : Array Json) (count : Nat) : Option Nat :=
  Id.run do
    if count == 0 then return some 0
    let mut seen := 0
    for index in [:instructions.size] do
      let instruction := instructions[index]!
      if isAction instruction then
        seen := seen + 1
        if seen == count then
          let last := (originLines instruction).foldl max 0
          let mut next := index + 1
          while next < instructions.size
                && !isAction instructions[next]!
                && (originLines instructions[next]!).all (· <= last) do
            next := next + 1
          return some next
    return none

/-- Number of actions in a list of instructions. -/
def actionCount (instructions : Array Json) : Nat :=
  (instructions.filter isAction).size

end CCFRaft.MidTrace
