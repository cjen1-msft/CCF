module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import MidTrace.Cut
public import MidTrace.StateJson
public import MidTrace.SymDriver
public import MidTrace.SmtDriver
public import MidTrace.GenDriver

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
  ++ "         [--cap K] [--witness] [--sizes] [--dump K] [--dump-node NODE]\n"
  ++ "       ccfraft-midtrace smt DOC N [--solver PATH] [--no-invariants] [--no-refine]\n"
  ++ "         [--explain] [--named] [--pin] [--Q n] [--slack n] [--dump-smt PATH] [--witness]\n"
  ++ "         [--profile]\n"
  ++ "       ccfraft-midtrace gen DOC N [--solver PATH] [--no-refine] [--Q n] [--slack n] [--retry k]\n"
  ++ "         [--dump-smt PATH] [--dump-ir PATH] [--witness] [--profile]"

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

structure SmtOptions where
  settings : Smt.Settings := {}
  pin : Bool := false
  witness : Bool := false
  profile : Bool := false
  /-- On invalid, find a small invalid window and print a minimal unsat core over it. -/
  explain : Bool := false

private def smtOptions (options : List String) (parsed : SmtOptions)
    : Option SmtOptions :=
  let set (f : Smt.Settings → Smt.Settings) :=
    { parsed with settings := f parsed.settings }
  match options with
  | [] => some parsed
  | "--solver" :: path :: rest => smtOptions rest (set ({ · with solver := path }))
  | "--no-invariants" :: rest => smtOptions rest (set ({ · with invariants := false }))
  | "--no-refine" :: rest => smtOptions rest (set ({ · with refine := false }))
  | "--explain" :: rest => smtOptions rest { parsed with explain := true }
  | "--named" :: rest => smtOptions rest (set ({ · with explain := true }))
  | "--dump-smt" :: path :: rest => smtOptions rest (set ({ · with dump := some path }))
  | "--pin" :: rest => smtOptions rest { parsed with pin := true }
  | "--witness" :: rest => smtOptions rest { parsed with witness := true }
  | "--profile" :: rest => smtOptions rest { parsed with profile := true }
  | "--Q" :: value :: rest =>
      value.toNat?.bind fun q => smtOptions rest (set ({ · with Q := q }))
  | "--slack" :: value :: rest =>
      value.toNat?.bind fun slack => smtOptions rest (set ({ · with slack }))
  | _ => none

structure GenOptions where
  settings : Gen.Settings := {}
  witness : Bool := false
  profile : Bool := false

private def genOptions (options : List String) (parsed : GenOptions)
    : Option GenOptions :=
  let set (f : Gen.Settings → Gen.Settings) :=
    { parsed with settings := f parsed.settings }
  match options with
  | [] => some parsed
  | "--solver" :: path :: rest => genOptions rest (set ({ · with solver := path }))
  | "--no-refine" :: rest => genOptions rest (set ({ · with refine := false }))
  | "--backbone" :: value :: rest =>
      value.toNat?.bind fun backbone => genOptions rest (set ({ · with backbone }))
  | "--retry" :: value :: rest =>
      value.toNat?.bind fun retry => genOptions rest (set ({ · with retry }))
  | "--dump-smt" :: path :: rest => genOptions rest (set ({ · with dump := some path }))
  | "--dump-ir" :: path :: rest => genOptions rest (set ({ · with irDump := some path }))
  | "--fix-len" :: src :: dst :: n :: rest =>
      match src.toNat?, dst.toNat?, n.toNat? with
      | some s, some d, some n =>
          genOptions rest (set fun o => { o with fixLen := ((s, d), n) :: o.fixLen })
      | _, _, _ => none
  | "--witness" :: rest => genOptions rest { parsed with witness := true }
  | "--profile" :: rest => genOptions rest { parsed with profile := true }
  | "--Q" :: value :: rest =>
      value.toNat?.bind fun q => genOptions rest (set ({ · with Q := q }))
  | "--slack" :: value :: rest =>
      value.toNat?.bind fun slack => genOptions rest (set ({ · with slack }))
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
    | "smt" :: path :: count :: options =>
        let some options := smtOptions options {} | stderr.putStrLn usage; return 2
        let (header, prefix_, suffix) ← split path count.toNat!
        let mut settings := options.settings
        if options.pin then
          settings :=
            { settings with pinned := some (← orThrow (trueState header prefix_)) }
        let start ← IO.monoMsNow
        let outcome ← Smt.run header suffix settings
        let elapsed := (← IO.monoMsNow) - start
        IO.println
          s!"{outcome.verdict.name} time_ms={elapsed} encode_ms={outcome.encodeMs} solve_ms={outcome.solveMs} instructions={suffix.size} processed={outcome.processed} declared={outcome.declared} defined={outcome.defined} asserts={outcome.asserts} {outcome.detail}"
        if options.explain && outcome.verdict == .invalid then
          let diagnosis ← Smt.diagnose header suffix settings outcome
          let explanation := diagnosis.explanation
          let window := explanation.outcome
          IO.println
            s!"window instructions {diagnosis.start + 1}..{diagnosis.failing} actions={diagnosis.actions} checks={diagnosis.checks} search_ms={diagnosis.searchMs} encode_ms={window.encodeMs} defined={window.defined} load_ms={explanation.loadMs} first_ms={explanation.firstMs} groups={explanation.groups} group_checks={explanation.groupChecks} label_checks={explanation.labelChecks} timeouts={explanation.timeouts} time_ms={(← IO.monoMsNow) - start} {window.verdict.name} {window.detail}"
          let assumption :=
            if window.detail.startsWith "unsat (assuming invariants)" then
              " (assuming invariants)"
            else
              ""
          IO.println s!"core {window.core.size}{assumption}:"
          for (index, description) in window.core do
            let origin :=
              (suffix[index]?.map fun i => (Replay.originLabel i).toOption.getD "?").getD
                "?"
            IO.println s!"  instruction {index + 1} at {origin}: {description}"
        if options.profile then
          IO.println s!"K={outcome.K}"
          let mut previous := 0
          for h : i in [0:outcome.sizes.size] do
            let size := outcome.sizes[i]
            IO.println
              s!"profile {i} {size - previous} {((suffix[i]?.map Json.compress).getD "").take 160}"
            previous := size
        if options.witness then
          if let some state := outcome.witness then
            IO.println (replayStateJson header.declared state).compress
        return  if outcome.verdict == .valid then
                  0
                else if outcome.verdict == .invalid then
                  1
                else
                  3
    | "gen" :: path :: count :: options =>
        let some options := genOptions options {} | stderr.putStrLn usage; return 2
        let (header, _, suffix) ← split path count.toNat!
        let start ← IO.monoMsNow
        let outcome ← Gen.run header suffix options.settings
        let elapsed := (← IO.monoMsNow) - start
        IO.println
          s!"{outcome.verdict.name} time_ms={elapsed} build_ms={outcome.buildMs} lower_ms={outcome.lowerMs} solve_ms={outcome.solveMs} probe_ms={outcome.probeMs} probes={outcome.probes} pinned={outcome.pinned} instructions={suffix.size} processed={outcome.processed} ir_nodes={outcome.irNodes} smt_lines={outcome.smtLines} L={outcome.L} {outcome.detail}"
        if options.profile then
          let smt :=
            outcome.smtSizes.foldl (fun m (i, size) => m.insert i size)
              (∅ : Std.HashMap Nat Nat)
          for h : i in [0:outcome.irSizes.size] do
            let smtDelta :=
              match smt[i]?, smt[i + 1]? with
              | some a, some b => s!"{b - a}"
              | _, _ => "?"
            IO.println
              s!"profile {i} ir={outcome.irSizes[i]} smt={smtDelta} us={outcome.lowerUs[i]?.getD 0} {((suffix[i]?.map Json.compress).getD "").take 140}"
        if options.profile then
          for (i, node, width) in outcome.wide do
            IO.println s!"wide {i} v{node} {width}"
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
