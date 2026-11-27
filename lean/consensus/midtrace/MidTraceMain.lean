module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import MidTrace.GenDriver
public import MidTrace.GroupJson
public import MidTrace.StateJson

@[expose] public section

open Lean (Json toJson fromJson?)
open Consensus Consensus.MidTrace

private def usage :=
  "usage:
  consensus-midtrace check [OPTIONS] [GROUPS.ndjson]
  consensus-midtrace replay-from [--invariant on|off] [--bootstrap NODE] STATE.json
    [GROUPS.ndjson]
Groups are read as NDJSON from GROUPS.ndjson or, if it is absent or -, standard input, as
`consensus-reduction --trace` writes them; any slice of its lines is a valid input.
OPTIONS:
  --solver PATH  --timeout N  --Q N  --slack N  --retry N  --backbone N
  --gaps literal|uniform|off  --invariant on|off  --reuse on|off  --no-refine
  --bootstrap NODE  --node NODE  --dump PATH  --ir-dump PATH  --dump-witness PATH  --json
EXIT CODES (check):
  0 validCertified  1 invalidBounded  2 usage or input error  3 unknown"

private structure Options where
  settings : Gen.Settings := {}
  bootstrap : List String := []
  nodes : List String := []
  json : Bool := false
  witness : Option String := none
  paths : Array String := #[]

private def number (s : String) :=
  s.toNat?.elim (Except.error s!"expected a natural number, got '{s}'") Except.ok

private def toggle : String → Except String Bool
  | "on" => .ok true
  | "off" => .ok false
  | s => .error s!"expected on or off, got '{s}'"

/-- Options of `check`, or of `replay-from` if not `check`. -/
private def parse (check : Bool) (args : List String) (o : Options := {})
    : Except String Options := do
  let s := o.settings
  match args with
  | [] => return o
  | "--invariant" :: value :: rest =>
      parse check rest { o with settings.invariant := ← toggle value }
  | "--bootstrap" :: node :: rest =>
      parse check rest { o with bootstrap := o.bootstrap ++ [node] }
  | "--node" :: node :: rest =>
      parse check rest { o with nodes := o.nodes ++ [node] }
  | "--json" :: rest =>
      if check then parse check rest { o with json := true } else throw usage
  | "--no-refine" :: rest =>
      if check then parse check rest { o with settings.refine := false } else throw usage
  | key :: value :: rest =>
      if key == "-" || !key.startsWith "--" then
        return ← parse check (value :: rest) { o with paths := o.paths.push key }
      unless check do
        throw usage
      if key == "--dump-witness" then
        return ← parse check rest { o with witness := some value }
      let settings ←
        match key with
        | "--solver" => pure { s with solver := value }
        | "--timeout" => do
            let secs ← number value
            pure { s with timeout := if secs == 0 then none else some secs }
        | "--Q" => do pure { s with Q := ← number value }
        | "--slack" => do pure { s with slack := ← number value }
        | "--retry" => do pure { s with retry := ← number value }
        | "--backbone" => do pure { s with backbone := ← number value }
        | "--gaps" =>
            match value with
            | "literal" => pure { s with gaps := some .literal }
            | "uniform" => pure { s with gaps := some .uniform }
            | "off" => pure { s with gaps := none }
            | _ => throw "expected --gaps literal, uniform or off"
        | "--reuse" => do pure { s with reuse := ← toggle value }
        | "--dump" => pure { s with dump := some value }
        | "--ir-dump" => pure { s with irDump := some value }
        | _ => throw s!"unknown option {key}"
      parse check rest { o with settings }
  | [path] =>
      if path.startsWith "--" then throw s!"invalid or incomplete option {path}"
      parse check [] { o with paths := o.paths.push path }

/-- Read NDJSON groups from `path`, or from standard input if it is absent or `-`. -/
private def readGroups (path : Option String) : IO String :=
  match path with
  | some path =>
      if path == "-" then do
        (← IO.getStdin).readToEnd
      else
        IO.FS.readFile path
  | none => do (← IO.getStdin).readToEnd

private def name : Verdict → String
  | .validCertified => "validCertified"
  | .invalidBounded => "invalidBounded"
  | .unknown => "unknown"

private def resultJson (r : Gen.Outcome) (o : Options) (header : Replay.Header)
    (groups : Nat)
    : Json :=
  Json.mkObj
    [
      ("schemaVersion", toJson 2),
      ("verdict", toJson (name r.verdict)),
      ("certified", toJson (r.verdict == .validCertified)),
      ("detail", toJson r.detail),
      ("assumptions", toJson r.assumptions),
      ("groups", toJson groups),
      ("declaredNodes", toJson header.declared),
      ("bootstrap", toJson o.bootstrap.mergeSort.eraseDups),
      ("solver", toJson o.settings.solver),
      (
        "timings",
        Json.mkObj
          [
            ("buildMs", toJson r.buildMs),
            ("lowerMs", toJson r.lowerMs),
            ("probeMs", toJson r.probeMs),
            ("solveMs", toJson r.solveMs),
            ("certifyMs", toJson r.certifyMs)
          ]
      ),
      (
        "stats",
        Json.mkObj
          [
            ("irNodes", toJson r.irNodes),
            ("smtLines", toJson r.smtLines),
            ("probes", toJson r.probes),
            ("pinned", toJson r.pinned),
            ("gapProbed", toJson r.gapProbed),
            ("gapEnumerated", toJson r.gapEnumerated),
            ("foldPoints", toJson r.foldPoints),
            ("foldReused", toJson r.foldReused),
            ("scansSeeded", toJson r.scansSeeded)
          ]
      )
    ]

/-- Write `text` to `path` through a temporary file, so `path` is never partly written. -/
private def writeAtomically (path text : String) : IO Unit := do
  let tmp := path ++ ".tmp"
  IO.FS.writeFile tmp text
  IO.FS.rename tmp path

/--
Write a certified witness. Otherwise, write nothing and remove any earlier file at `path`,
so that a caller cannot mistake it for this run's witness.
-/
private def dumpWitness (path : String) (header : Replay.Header) (result : Gen.Outcome)
    : IO Unit := do
  if result.verdict == .validCertified then
    if let some s := result.witness then
      return ← writeAtomically path ((encodeState header s).compress ++ "\n")
  if ← System.FilePath.pathExists path then IO.FS.removeFile path
  IO.eprintln s!"no witness written to {path}: verdict {name result.verdict}"

@[no_expose]
def main (args : List String) : IO UInt32 := do
  try
    match args with
    | "replay-from" :: rest =>
        let o ← IO.ofExcept (parse false rest)
        let (state, path) ←
          match o.paths with
          | #[state] => pure (state, none)
          | #[state, path] => pure (state, some path)
          | _ => throw (IO.userError usage)
        let json ← IO.ofExcept (Json.parse (← IO.FS.readFile state))
        let snapshot : StateJson.Snapshot ← IO.ofExcept (fromJson? json)
        let (header, groups) ←
          IO.ofExcept
            (decodeGroups (← readGroups path) o.bootstrap (snapshot.declared ++ o.nodes))
        let s ← IO.ofExcept (decodeState header json)
        if o.settings.invariant then
          IO.ofExcept (InitInvariant.check header.bootstrap s)
        discard <| IO.ofExcept (Replay.replayFrom header { state := s } groups)
        IO.println s!"ok: {groups.size} groups"
        return 0
    | "check" :: rest =>
        let o ← IO.ofExcept (parse true rest)
        let path ←
          match o.paths with
          | #[] => pure none
          | #[path] => pure (some path)
          | _ => throw (IO.userError usage)
        if let some file := o.witness then
          if ← System.FilePath.pathExists file then IO.FS.removeFile file
        let (header, groups) ←
          IO.ofExcept (decodeGroups (← readGroups path) o.bootstrap o.nodes)
        let result ← Gen.run header groups o.settings
        if let some file := o.witness then dumpWitness file header result
        if o.json then
          IO.println (resultJson result o header groups.size).compress
        else
          IO.println
            s!"{name result.verdict}: {groups.size} groups; {result.detail} assumptions={(toJson result.assumptions).compress}"
        match result.verdict with
        | .validCertified => return 0
        | .invalidBounded => return 1
        | .unknown => return 3
    | _ => IO.eprintln usage; return 2
  catch e =>
    IO.eprintln (toString e); return 2
