import Lean
import Relevance.Generate
import Consensus.Properties

/-!
# Case splits of the consensus safety proofs, report only

Runs the relevance walker (`Relevance.analyse`) over the proofs behind the public theorems of
`Consensus.Properties`. The proof has no recorded splits, so every split the walker finds is
reported as unrecorded. Two walks:

- `inlined`: scope `Consensus.Proofs`, so every theorem of the proof is inlined at each use, as
  the generator would; theorems taking a step context (`Safety.Ctx`) are step-level and theorems
  taking the invariant (`Safety.Inv`) are state-level. Counts are per call path.
- `own`: each theorem of the kernel closure walked once with nothing inlined (an empty scope).
  Counts are per declaration, as written.

Run from the repository root (the workspace is out of tree):

    WS=$(python3 lean/relevance/scripts/workspace.py common consensus relevance consensus-coverage)
    lake -d $WS/consensus-coverage env lean $PWD/lean/consensus-coverage/scripts/splits.lean

`SPLITS_OUT` names the directory for the TSV tables (default: the current directory);
`SPLITS_WALK` selects `own`, `inlined` or `both` (default). `SPLITS_ROOTS`, a comma-separated
list of last name components of `roots`, restricts the roots (default: all).
-/

open Lean Meta Elab Command

namespace ConsensusCoverage

/-- The constant whose name, private prefix removed, is `n`. -/
def resolve (n : Name) : CoreM Name := do
  let env ← getEnv
  if env.contains n then return n
  let some (c, _) := env.constants.toList.find? fun (c, _) => privateToUserName? c == some n
    | throwError "no constant {n}"
  return c

/-- `fun xs => C xs` over every parameter of the type former `C`. -/
def patternOf (n : Name) : MetaM Expr := do
  let c ← resolve n
  let ci ← getConstInfo c
  forallTelescope ci.type fun xs _ => mkLambdaFVars xs (mkAppN (mkConst c) xs)

def roots : List Name :=
  [`Consensus.Proofs.CommittedLogs.committed_logs_prefix,
   `Consensus.Proofs.Election.election_safety,
   `Consensus.Proofs.Direct.single_node_committed_log_monotonic,
   `Consensus.Proofs.Direct.committed_frontier_is_signature]

def userName (c : Name) : Name := (privateToUserName? c).getD c

/-- Theorems of `Consensus.Proofs` in the kernel closure of `root`. -/
def closureOf (root : Name) : CoreM (Array Name) := do
  let env ← getEnv
  let mut seen : NameSet := {}
  let mut todo := #[root]
  let mut out := #[]
  while !todo.isEmpty do
    let c := todo.back!
    todo := todo.pop
    if seen.contains c then continue
    seen := seen.insert c
    let some ci := env.find? c | continue
    if ci matches .thmInfo _ && (`Consensus.Proofs).isPrefixOf (userName c) then
      out := out.push c
    let es := match ci with
      | .thmInfo v => #[v.type, v.value]
      | .defnInfo v => #[v.type, v.value]
      | .opaqueInfo v => #[v.type, v.value]
      | _ => #[ci.type]
    if let .inductInfo v := ci then todo := todo ++ v.ctors.toArray
    for e in es do todo := todo ++ e.getUsedConstants
  return out

/-- Number of alternatives of a split head. -/
def arity (c : Name) : MetaM Nat := do
  if [``dite, ``ite, ``Decidable.byCases, ``Classical.byCases, ``Or.elim, ``Or.by_cases].contains c
  then return 2
  let info ← match ← getMatcherInfo? c with
    | some i => pure (some i)
    | none => if c.isStr && c.getString! == "splitter" then getMatcherInfo? c.getPrefix
              else pure none
  if let some i := info then return i.numAlts
  if let some (.inductInfo iv) := (← getEnv).find? c.getPrefix then return iv.ctors.length
  return 0

def tally {α} [BEq α] [Hashable α] (xs : Array α) : Array (α × Nat) :=
  let m : Std.HashMap α Nat := xs.foldl (fun m x => m.insert x (m.getD x 0 + 1)) {}
  m.toArray.qsort (fun a b => a.2 > b.2)

def headKind (c : Name) : String :=
  if c.isStr && (c.getString! == "casesOn" || c.getString! == "rec" || c.getString! == "recOn"
      || c.getString! == "brecOn") then s!"{c.getPrefix}.{c.getString!}"
  else if c.isStr && c.getString! == "splitter" then "match splitter"
  else if c.isStr && (c.getString!.startsWith "match_") then "match"
  else toString c

def report (label : String) (r : Relevance.Result) (out : System.FilePath) : MetaM Unit := do
  let us := r.unrecorded
  let mut rows := #["root\tdecl\thead\tarity\tinternal\tdepth\tcondition"]
  let mut alts := 0
  let mut altsP := 0
  for u in us do
    let a ← arity u.head
    alts := alts + a
    unless u.internal do altsP := altsP + a
    rows := rows.push <| "\t".intercalate [toString (userName u.root),
      toString (userName u.decl), toString u.head, toString a, toString u.internal,
      toString u.path.size, (u.cond.take 300).toString]
  IO.FS.writeFile (out / s!"splits-{label}.tsv") ("\n".intercalate rows.toList ++ "\n")
  let prot := us.filter (!·.internal)
  IO.println s!"[{label}] unrecorded splits {us.size} ({prot.size} protocol, \
    {us.size - prot.size} internal); alternatives {alts} ({altsP} protocol); \
    theorems without value {r.noValue.size}: {r.noValue.toList.map userName |>.take 10}"
  let lv := r.levels
  IO.println s!"[{label}] theorems seen {lv.size}: step {(lv.filter (·.2.1 == .step)).size}, \
    state {(lv.filter (·.2.1 == .state)).size}, other {(lv.filter (·.2.1 == .other)).size}; \
    walked as roots: {(lv.filter (·.2.2)).toList.map (fun x => userName x.1)}"
  IO.println s!"[{label}] by root: {tally (us.map fun u => toString (userName u.root))}"
  IO.println s!"[{label}] by head (all): {(tally (us.map (headKind ·.head))).toList.take 25}"
  IO.println s!"[{label}] by head (protocol): {(tally (prot.map (headKind ·.head))).toList.take 25}"
  let decls := tally (us.map fun u => toString (userName u.decl))
  IO.println s!"[{label}] declaring theorems {decls.size}; top 25: {decls.toList.take 25}"
  let declsP := tally (prot.map fun u => toString (userName u.decl))
  IO.println s!"[{label}] declaring theorems (protocol) {declsP.size}; top 25: {declsP.toList.take 25}"
  let maxDepth := us.foldl (fun m u => max m u.path.size) 0
  IO.println s!"[{label}] deepest call path {maxDepth}"

def timed (k : MetaM α) : MetaM (α × Float) := do
  let t0 ← IO.monoMsNow
  let a ← k
  let t1 ← IO.monoMsNow
  return (a, (t1 - t0).toFloat / 1000.0)

end ConsensusCoverage

open ConsensusCoverage in
set_option maxHeartbeats 0 in
set_option maxRecDepth 100000 in
run_cmd liftTermElabM do
  let out : System.FilePath := (← IO.getEnv "SPLITS_OUT").getD "."
  let walk := (← IO.getEnv "SPLITS_WALK").getD "both"
  let stepPat ← patternOf `Consensus.Proofs.Safety.Ctx
  let statePat ← patternOf `Consensus.Proofs.Safety.Inv
  let only := ((← IO.getEnv "SPLITS_ROOTS").map (·.splitOn ",")).getD []
  let chosen := roots.filter fun r => only.isEmpty || only.contains r.getString!
  let rs ← chosen.toArray.mapM (resolve ·)
  let mut closure : Array Name := #[]
  for r in rs do
    let c ← closureOf r
    IO.println s!"closure of {userName r}: {c.size} theorems"
    for x in c do unless closure.contains x do closure := closure.push x
  IO.println s!"closure of all roots: {closure.size} theorems"
  if walk == "own" || walk == "both" then
    let cfg : Relevance.Config := { scope := `ConsensusCoverage.Nothing, package := #[`Consensus],
                                    stepPat, statePat }
    let (r, t) ← timed (Relevance.analyse cfg closure)
    IO.println s!"[own] walk {t} s"
    report "own" r out
  if walk == "inlined" || walk == "both" then
    let cfg : Relevance.Config := { scope := `Consensus.Proofs, package := #[`Consensus],
                                    stepPat, statePat }
    let (r, t) ← timed (Relevance.analyse cfg rs)
    IO.println s!"[inlined] walk {t} s"
    report "inlined" r out
