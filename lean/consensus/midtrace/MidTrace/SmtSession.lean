module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Lean.Data.Json
public import Std.Data.HashMap

@[expose] public section

namespace Consensus.MidTrace

inductive Verdict where
  | validCertified
  | invalidBounded
  | unknown
deriving DecidableEq, Repr

structure Assumptions where
  Q : Nat
  L : Nat
  slack : Nat
  gapPolicy : String
  invariant : String
  retried : Bool
  /-- The solver time limit in seconds, if any. -/
  timeout : Option Nat := none
deriving Lean.ToJson

namespace Smt

inductive SExp where
  | atom (text : String)
  | list (items : Array SExp)
deriving Inhabited

/-- Lexical state for SMT-LIB output: string literals, `|quoted|` symbols and comments
may contain parentheses that do not nest. -/
inductive Lex where
  | code
  | string
  /-- A `"` inside a string: its end, or the first half of an escaped `""`. -/
  | stringQuote
  | quoted
  | comment
deriving BEq

/-- Whether a delimiter here is code: outside literals and comments. -/
def Lex.inCode : Lex → Bool
  | .code | .stringQuote => true
  | _ => false

/-- The lexical state after `c`, and whether `c` is code (outside literals and comments). -/
def Lex.step : Lex → Char → Lex × Bool
  | .string, c => (if c == '"' then .stringQuote else .string, false)
  | .stringQuote, '"' => (.string, false)
  | .quoted, c => (if c == '|' then .code else .quoted, false)
  | .comment, c => (if c == '\n' then .code else .comment, false)
  | _, c =>
      if c == '"' then
        (.string, false)
      else if c == '|' then
        (.quoted, false)
      else if c == ';' then
        (.comment, false)
      else
        (.code, true)

partial def parseSExps (input : String) : Array SExp :=
  let chars := input.toList.toArray
  let push (stack : List (Array SExp)) (out : Array SExp) (item : SExp) :=
    match stack with
    | top :: rest => (top.push item :: rest, out)
    | [] => ([], out.push item)
  -- The end of the atom starting at `j`, past any literal it contains.
  let rec word (j : Nat) (lex : Lex) : Nat :=
    if h : j < chars.size then
      let d := chars[j]
      if lex.inCode && (d == '(' || d == ')' || d == ';' || d.isWhitespace) then
        j
      else
        word (j + 1) (lex.step d).1
    else
      j
  let rec go (i : Nat) (stack : List (Array SExp)) (out : Array SExp) : Array SExp :=
    if h : i < chars.size then
      let c := chars[i]
      if c == '(' then
        go (i + 1) (#[] :: stack) out
      else if c == ')' then
        match stack with
        | top :: rest =>
            let (stack, out) := push rest out (SExp.list top)
            go (i + 1) stack out
        | [] => go (i + 1) [] out
      else if c == ';' then
        let rec eol (j : Nat) : Nat :=
          if h : j < chars.size then if chars[j] == '\n' then j else eol (j + 1) else j
        go (eol i) stack out
      else if c.isWhitespace then
        go (i + 1) stack out
      else
        let j := word i .code
        let (stack, out) :=
          push stack out (SExp.atom (String.ofList (chars.extract i j).toList))
        go j stack out
    else
      out
  go 0 [] #[]

def SExp.toInt? : SExp → Option Int
  | .atom "true" => some 1
  | .atom "false" => some 0
  | .atom text => text.toInt?
  | .list #[.atom "-", inner] => inner.toInt?.map (- ·)
  | _ => none

/-- Interactive-mode flags for the supported solvers, with an optional time limit in
seconds. Other solvers get no flags, and no time limit. -/
def solverArgs (solver : String) (timeoutSecs : Option Nat := none) : Array String :=
  let name := (solver.splitOn "/").getLast!
  let limit (flag : Nat → String) := (timeoutSecs.map fun secs => #[flag secs]).getD #[]
  if name.startsWith "yices" then
    #["--incremental"] ++ limit fun secs => s!"--timeout={secs}"
  else if name.startsWith "cvc5" then
    #["--incremental", "--lang", "smt2"] ++ limit fun secs => s!"--tlimit={secs * 1000}"
  else if name.startsWith "z3" then
    #["-in"] ++ limit fun secs => s!"-T:{secs}"
  else
    #[]

abbrev SolverProcess :=
  IO.Process.Child { stdin := .piped, stdout := .piped, stderr := .piped }

structure Session where
  solver : String
  child : SolverProcess
  /-- Drains standard error, so a solver that writes much of it cannot block on the pipe. -/
  stderr : Task (Except IO.Error String)
  /-- Set once the session ends, to stop `watchdog`. -/
  done : IO.Ref Bool
  /-- Whether `watchdog` killed the solver at its time limit. -/
  timedOut : IO.Ref Bool
  watchdog : Task (Except IO.Error Unit)

/-- The first executable named `cmd`, searching `PATH` if it has no directory. -/
def findExecutable (cmd : String) : IO (Option System.FilePath) := do
  if cmd.contains '/' then
    return if ← System.FilePath.pathExists cmd then some cmd else none
  for dir in ((← IO.getEnv "PATH").getD "").splitOn ":" do
    let candidate := System.FilePath.mk (if dir.isEmpty then "." else dir) / cmd
    if ← candidate.pathExists then return some candidate
  return none

/-- Runs `act`, ignoring failure. -/
def ignoring (act : IO Unit) : IO Unit :=
  try
    act
  catch _ =>
    pure ()

/-- Kills `child` once `ms` milliseconds pass, unless `done` is set first. -/
partial def watch (child : SolverProcess) (done timedOut : IO.Ref Bool) (ms : Nat)
    : IO Unit := do
  if ← done.get then return
  if ms == 0 then
    timedOut.set true
    ignoring child.kill
    return
  IO.sleep 50
  watch child done timedOut (ms - 50)

/--
Starts `solver`. With `timeoutSecs`, the solver also gets its own per-query limit if it is
supported, and is killed if the session outlasts the limit, so every solver is bounded.
-/
def Session.spawn (solver : String) (timeoutSecs : Option Nat := none) : IO Session := do
  let fail (why : String) := IO.userError s!"solver '{solver}' failed to start: {why}"
  if (← findExecutable solver).isNone then throw (fail "not found")
  let child ←
    try
      IO.Process.spawn
        {
          cmd := solver
          args := solverArgs solver timeoutSecs
          stdin := .piped
          stdout := .piped
          stderr := .piped
        }
    catch err =>
      throw (fail (toString err))
  let stderr ← IO.asTask child.stderr.readToEnd (prio := .dedicated)
  let done ← IO.mkRef false
  let timedOut ← IO.mkRef false
  let watchdog ←
    match timeoutSecs with
    | some secs =>
        IO.asTask (watch child done timedOut (secs * 1000)) (prio := .dedicated)
    | none => pure (.pure (.ok ()))
  return { solver, child, stderr, done, timedOut, watchdog }

def Session.send (session : Session) (text : String) : IO Unit := do
  try
    session.child.stdin.putStr text
    session.child.stdin.flush
  catch err =>
    throw (IO.userError s!"solver '{session.solver}': {err}")

/-- Reads one balanced response; empty at end of output. -/
partial def Session.response (session : Session) : IO String := do
  let mut text := ""
  let mut depth : Int := 0
  let mut lex := Lex.code
  let mut content := false
  repeat
    let line ← session.child.stdout.getLine
    if line.isEmpty then break
    text := text ++ line
    for c in line.toList do
      let (next, code) := lex.step c
      lex := next
      if code then
        if c == '(' then
          depth := depth + 1
        else if c == ')' then
          depth := depth - 1
        if !c.isWhitespace then content := true
    if depth <= 0 && content && lex.inCode then break
  return text.trimAscii.toString

/-- Whether `answer` to `check-sat` is an error, not `sat`, `unsat` or `unknown`. -/
def failed (answer : String) : Bool :=
  !["sat", "unsat", "unknown"].contains answer

def Session.check (session : Session) (assumptions : List String) : IO String := do
  session.send s!"(check-sat-assuming ({" ".intercalate assumptions}))\n"
  session.response

/-- Waits up to `ms` milliseconds for `child` to exit; whether it has been reaped. -/
partial def reap (child : SolverProcess) (ms : Nat) : IO Bool := do
  -- `tryWait` fails once the child has been reaped.
  let status ←
    try
      child.tryWait
    catch _ =>
      pure (some 0)
  match status with
  | some _ => return true
  | none =>
      if ms == 0 then return false
      IO.sleep 10
      reap child (ms - min ms 10)

/--
Ends the session without throwing, and returns the solver's standard error. Unless
`abort`, the solver gets a second to exit on `(exit)`; then it is killed.
-/
def Session.close (session : Session) (abort : Bool := false) : IO String := do
  session.done.set true
  -- The watchdog must not kill a reaped, and possibly reused, process ID.
  discard <| IO.wait session.watchdog
  unless abort do
    ignoring (session.send "(exit)\n")
  let child := session.child
  let exited ← if abort then pure false else reap child 1000
  unless exited do
    ignoring child.kill
    ignoring (discard child.wait)
  let stderr := (← IO.wait session.stderr).toOption.getD ""
  return stderr.trimAscii.toString

/-- The values of `vN` for each `N` in `ids`; an error if any is missing or malformed. -/
def Session.values (session : Session) (ids : Array Nat)
    : IO (Except String (Std.HashMap Nat Int)) := do
  let mut values : Std.HashMap Nat Int := {}
  -- Batches keep responses small.
  let mut start := 0
  while start < ids.size do
    let batch := ids.extract start (start + 2000)
    start := start + 2000
    session.send
      s!"(get-value ({" ".intercalate (batch.toList.map fun id => s!"v{id}")}))\n"
    let response ← session.response
    let malformed := Except.error s!"malformed get-value response: {response.take 200}"
    if response.isEmpty then return .error "no get-value response"
    let #[SExp.list pairs] := parseSExps response | return malformed
    for pair in pairs do
      let SExp.list #[.atom name, value] := pair | return malformed
      let some id := if name.startsWith "v" then (name.drop 1).toNat? else none
      | return malformed
      let some v := value.toInt? | return malformed
      values := values.insert id v
    for id in batch do
      unless values.contains id do
        return .error s!"no value for v{id}"
  return .ok values

end Smt
end Consensus.MidTrace
