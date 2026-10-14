module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import MidTrace.Cut
public import MidTrace.StateJson
public import MidTrace.SymDriver

public section

open Lean CCFRaft CCFRaft.MidTrace

private def readJson (path : String) : IO Json := do
  let input ← if path == "-" then (← IO.getStdin).readToEnd else IO.FS.readFile path
  match Json.parse input with
  | .ok value => return value
  | .error error => throw (IO.userError s!"{path}: {error}")

private def orThrow {α : Type} (result : Except String α) : IO α :=
  match result with
  | .ok value => pure value
  | .error error => throw (IO.userError error)

/-- The header, the dropped prefix, and the kept suffix of a document. -/
private def split (path : String) (count : Nat)
    : IO (Replay.Header × Array Json × Array Json) := do
  let (header, instructions) ← orThrow (Replay.parseDocument (← readJson path))
  let some index := cutIndex instructions count
  | throw (IO.userError s!"{path}: fewer than {count} actions")
  return (header, instructions.extract 0 index, instructions.extract index)

private def document (bootstrap : Json) (instructions : Array Json) : Json :=
  Json.mkObj
    [
      ("schema", "ccfraft-replay/v4"),
      ("bootstrap", bootstrap),
      ("instructions", Json.arr instructions)
    ]

/-- The state after replaying the prefix that a cut drops. -/
private def trueState (header : Replay.Header) (prefix_ : Array Json)
    : Except String Replay.ReplayState :=
  prefix_.foldlM
    (fun state instruction => Prod.fst <$> Replay.runInstruction header state instruction)
    { state := header.initial }

private def usage : String :=
  "usage: ccfraft-midtrace (cut | true-state) DOC N\n"
  ++ "       ccfraft-midtrace replay-from DOC N STATE\n"
  ++ "       ccfraft-midtrace validate DOC N [--no-invariants] [--no-dedup] [--closing] [--global]\n"
  ++ "         [--cap K] [--witness] [--sizes] [--dump K] [--dump-node NODE]"

structure ValidateOptions where
  settings : Sym.Settings := {}
  witness : Bool := false
  sizes : Bool := false

private def validateOptions (options : List String) (parsed : ValidateOptions)
    : Option ValidateOptions :=
  let set (f : Sym.Settings → Sym.Settings) :=
    { parsed with settings := f parsed.settings }
  match options with
  | [] => some parsed
  | "--no-invariants" :: rest =>
      validateOptions rest (set ({ · with invariants := false }))
  | "--closing" :: rest => validateOptions rest (set ({ · with phantoms := false }))
  | "--global" :: rest => validateOptions rest (set ({ · with perNode := false }))
  | "--no-dedup" :: rest => validateOptions rest (set ({ · with dedup := false }))
  | "--witness" :: rest => validateOptions rest { parsed with witness := true }
  | "--sizes" :: rest => validateOptions rest { parsed with sizes := true }
  | "--dump" :: value :: rest =>
      value.toNat?.bind
        fun index => validateOptions rest (set ({ · with dumpAt := some index }))
  | "--dump-node" :: node :: rest =>
      validateOptions rest (set ({ · with dumpNode := some node }))
  | "--cap" :: value :: rest =>
      value.toNat?.bind fun cap => validateOptions rest (set ({ · with cap }))
  | _ => none

def main (args : List String) : IO UInt32 := do
  let stderr ← IO.getStderr
  try
    match args with
    | ["cut", path, count] =>
        let raw ← readJson path
        let (_, _, suffix) ← split path count.toNat!
        IO.println (document ((raw.getObjValD "bootstrap")) suffix).compress
        return 0
    | ["true-state", path, count] =>
        let (header, prefix_, _) ← split path count.toNat!
        let state ← orThrow (trueState header prefix_)
        IO.println (replayStateJson header.declared state).compress
        return 0
    | ["replay-from", path, count, statePath] =>
        let (header, _, suffix) ← split path count.toNat!
        let initial ← orThrow (parseReplayState header (← readJson statePath))
        match Replay.replayFrom header initial suffix with
        | .ok result =>
            IO.println
              s!"ok: {result.actions} actions, {result.observations} observations"
            return 0
        | .error error =>
            IO.println s!"rejected: {error}"
            return 1
    | "validate" :: path :: count :: options =>
        let some options := validateOptions options {} | stderr.putStrLn usage; return 2
        let (header, _, suffix) ← split path count.toNat!
        let start ← IO.monoMsNow
        let settings := options.settings
        -- The search space only factors per node when deliveries are phantoms.
        let settings := { settings with perNode := settings.perNode && settings.phantoms }
        let outcome := Sym.run header suffix settings
        let verdict := outcome.verdict.name
        let elapsed := (← IO.monoMsNow) - start
        IO.println
          s!"{verdict} time_ms={elapsed} instructions={suffix.size} processed={outcome.processed} max_frontier={outcome.maxFrontier} {outcome.detail}"
        if options.sizes then
          IO.println s!"sizes {outcome.sizes.toList}"
        if options.witness then
          if let some state := outcome.witness then
            IO.println (replayStateJson header.declared state).compress
        return  if outcome.verdict == .valid then
                  0
                else if outcome.verdict == .invalid then
                  1
                else
                  3
    | _ =>
        stderr.putStrLn usage
        return 2
  catch error =>
    stderr.putStrLn s!"{error}"
    return 2
