module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ClauseCensus
import all ConsensusCoverage.ClauseCensus
import all ConsensusCoverage.ClauseQuestions

namespace ConsensusCoverage.ClauseCensusStats

open ClauseQuestions

/-- Recompute counts and the greedy cover from the stdout of `ClauseCensus.run`.
Accept shards in any order; ties always go to the earliest distinct prefix.
Reject partial or accidentally mixed-width input rather than counting a
fallback `none` as a negative answer. -/
public def summarize (input : String) : Except String String := do
  let mut rows : Array (Option Nat) := #[]
  let mut initialized := false
  for line in input.splitOn "\n" do
    match line.splitOn "\t" with
    | ["corpus", steps, size, width] =>
      unless width == "435" && steps == "2184" && size == "1374" do
        throw s!"unexpected corpus/width: {line}"
      unless initialized do rows := Array.replicate 1374 none
      initialized := true
    | ["row", slot, _, _, word] =>
      let some slot := slot.toNat? | throw "bad prefix index"
      let some word := word.toNat? | throw "bad packed label"
      unless rows[slot]? == some none do throw s!"duplicate or invalid prefix: {slot}"
      rows := rows.set! slot (some word)
    | "clause" :: _ | [""] => pure ()
    | _ => throw s!"unrecognized census output: {line}"
  unless initialized && rows.all Option.isSome do throw "incomplete census"
  let words := rows.map (·.getD 0)
  let masks := Clause.all.toArray.map fun c => (15 <<< 516) ||| ClauseCensus.mask (readable c)
  let keys := words.map fun w => masks.map (fun m => w &&& m)
  let distinct := words.foldl (fun (s : Std.HashSet Nat) w => s.insert w) {}
  let count := masks.map fun m => (words.foldl (fun (s : Std.HashSet Nat) w => s.insert (m &&& w)) {}).size
  let mut output := "clause\tquestions\treadable\tunread\tdistinct\n"
  for (c,i) in Clause.all.zipIdx do
    output := output ++ s!"{repr c}\t{(questions c).length}\t{readableCount c}\t{unreadCount c}\t{count[i]!}\n"
  let mut seen : Array (Std.HashSet Nat) := Array.replicate masks.size {}
  let mut chosen := 0
  let mut remaining := count.toList.sum
  while remaining > 0 do
    let mut best := 0
    let mut score := 0
    for i in [:keys.size] do
      let row := keys[i]!
      let mut gain := 0
      for j in [:row.size] do
        unless seen[j]!.contains row[j]! do gain := gain + 1
      if gain > score then
        score := gain
        best := i
    if score == 0 then throw "incomplete greedy cover"
    let row := keys[best]!
    for j in [:row.size] do
      seen := seen.modify j (·.insert row[j]!)
    remaining := remaining - score
    chosen := chosen + 1
  return output ++ s!"global\t{distinct.size}\nsum\t{count.toList.sum}\ngreedy\t{chosen}\n"

end ConsensusCoverage.ClauseCensusStats
