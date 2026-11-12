import Lean
import Relevance.Walk
import Consensus.Properties

/-!
# Which invariant clauses each public theorem needs

For the safety invariant `Consensus.Proofs.Safety.Inv` (a structure, one field per clause):

- the use side: the clauses that each public theorem's proof reads from the invariant, outside
  the proof that every step preserves it (`Safety.Ctx.inv_step` and what only it uses);
- the preservation side: for every clause `X`, the clauses of the pre-state that its
  preservation proof `Safety.Ctx.X` reads;
- the clauses each theorem needs: the use side closed under the preservation side;
- the theorems of `Consensus.Proofs` each property needs: the use side's theorems and the
  preservation proofs of its clauses with their closures. Printed as a table, one row per
  theorem, with the properties that need it.

- the shape of each clause as the generator reads it (`Relevance.clauseShape`: leading data
  binders and premises), from the field's type as written and after unfolding its head.

A clause is read when its projection occurs (as `Inv.X` or as a structure projection of `Inv`).
Run from the repository root:

    WS=$(python3 lean/relevance/scripts/workspace.py common consensus relevance consensus-coverage)
    lake -d $WS/consensus-coverage env lean $PWD/lean/consensus-coverage/scripts/clauses.lean

`CLAUSES_OUT` names the file for the per-theorem table (default: `clauses.tsv`).
-/

open Lean Meta Elab Command

namespace ConsensusCoverage.Clauses

def userName (c : Name) : Name := (privateToUserName? c).getD c

def resolve (n : Name) : CoreM Name := do
  let env ← getEnv
  if env.contains n then return n
  let some (c, _) := env.constants.toList.find? fun (c, _) => privateToUserName? c == some n
    | throwError "no constant {n}"
  return c

def valuesOf (ci : ConstantInfo) : Array Expr :=
  match ci with
  | .thmInfo v => #[v.type, v.value]
  | .defnInfo v => #[v.type, v.value]
  | .opaqueInfo v => #[v.type, v.value]
  | _ => #[ci.type]

/-- Constants in `e`, and the fields of `inv` read by projection in `e`. -/
def scan (inv : Name) (fields : Array Name) (e : Expr) : CoreM (Array Name × Array Name) := do
  let projFns := fields.map (inv ++ ·)
  let cs := e.getUsedConstants
  let fs := (cs.filterMap fun c => (projFns.idxOf? c).map (fields[·]!))
  let (_, fs) ← (e.forEachWhere Expr.isProj fun sub => match sub with
      | .proj S i _ => if S == inv then modify (·.push fields[i]!) else pure ()
      | _ => pure () : StateRefT (Array Name) CoreM Unit).run fs
  return (cs, fs)

/-- Theorems of `Consensus.Proofs` reachable from `root` without entering `stop`, and the clauses
they read. -/
def closure (inv : Name) (fields : Array Name) (root : Name) (stop : Array Name)
    : CoreM (Array Name × Array Name) := do
  let env ← getEnv
  let mut seen : NameSet := {}
  let mut todo := #[root]
  let mut thms := #[]
  let mut read := #[]
  while !todo.isEmpty do
    let c := todo.back!
    todo := todo.pop
    if seen.contains c || (c != root && stop.contains c) then continue
    seen := seen.insert c
    let some ci := env.find? c | continue
    if ci matches .thmInfo _ && (`Consensus.Proofs).isPrefixOf (userName c) then
      thms := thms.push c
    if let .inductInfo v := ci then todo := todo ++ v.ctors.toArray
    for e in valuesOf ci do
      let (cs, fs) ← scan inv fields e
      todo := todo ++ cs
      for f in fs do unless read.contains f do read := read.push f
  return (thms, read)

def fixpoint (start : Array Name) (deps : Std.HashMap Name (Array Name)) : Array Name := Id.run do
  let mut out := start
  let mut changed := true
  while changed do
    changed := false
    for x in out do
      for y in deps.getD x #[] do
        unless out.contains y do out := out.push y; changed := true
  return out

def tally (xs : Array String) : Array (String × Nat) :=
  let m : Std.HashMap String Nat := xs.foldl (fun m x => m.insert x (m.getD x 0 + 1)) {}
  m.toArray.qsort (fun a b => a.1 < b.1)

end ConsensusCoverage.Clauses

open ConsensusCoverage.Clauses in
run_cmd liftTermElabM do
  let inv ← resolve `Consensus.Proofs.Safety.Inv
  let some info := getStructureInfo? (← getEnv) inv | throwError "Inv is not a structure"
  let fields := info.fieldNames
  -- clause shapes, as written in `Inv` and with the clause definition unfolded
  let ctor := (getStructureCtor (← getEnv) inv).name
  forallTelescope (← getConstInfo ctor).type fun xs _ => do
    for x in xs do
      let ty ← inferType x
      unless ← isProp ty do continue
      let raw ← Relevance.clauseShape ty
      let unfolded ← match ← unfoldDefinition? ty with
        | some u => Relevance.clauseShape u
        | none => pure raw
      IO.println s!"shape {(← x.fvarId!.getUserName)}: as written {raw}, unfolded {unfolded}"
  let invStep ← resolve `Consensus.Proofs.Safety.Ctx.inv_step
  let invInitial ← resolve `Consensus.Proofs.Safety.inv_initial
  let preserve ← fields.mapM fun f => resolve (`Consensus.Proofs.Safety.Ctx ++ f)
  -- the use side stops at the induction over executions
  let stop := #[invStep, invInitial]
  let roots := [(`committed_logs_prefix, `Consensus.Proofs.CommittedLogs.committed_logs_prefix),
    (`election_safety, `Consensus.Proofs.Election.election_safety),
    (`single_node_committed_log_monotonic,
      `Consensus.Proofs.Direct.single_node_committed_log_monotonic),
    (`committed_frontier_is_signature, `Consensus.Proofs.Direct.committed_frontier_is_signature)]
  -- preservation side: the clauses each preservation proof reads, not entering the others
  let mut deps : Std.HashMap Name (Array Name) := {}
  let mut ownThms : Std.HashMap Name (Array Name) := {}
  for (f, p) in fields.zip preserve do
    let (thms, read) ← closure inv fields p (preserve ++ stop)
    deps := deps.insert f read
    ownThms := ownThms.insert f thms
    IO.println s!"preserve {f}: reads {read.toList}; {thms.size} theorems"
  -- initial side
  let (initThms, _) ← closure inv fields invInitial (preserve ++ #[invStep])
  let mut tags : Std.HashMap Name (Array Name) := {}
  for (label, r) in roots do
    let (useThms, useRead) ← closure inv fields (← resolve r) stop
    let need := fixpoint useRead deps
    IO.println s!"{label}: use side reads {useRead.toList} ({useThms.size} theorems); \
      needs {need.size} of {fields.size} clauses: {need.toList}; \
      not needed: {(fields.filter (!need.contains ·)).toList}"
    let mut thms := useThms
    unless need.isEmpty do
      thms := thms ++ initThms ++ #[invStep]
      for f in need do thms := thms ++ ownThms.getD f #[]
    for t in thms do
      let ts := tags.getD t #[]
      unless ts.contains label do tags := tags.insert t (ts.push label)
  let mut rows := #["theorem\tproperties"]
  for (t, ls) in tags.toArray.qsort (fun a b => a.1.toString < b.1.toString) do
    rows := rows.push s!"{userName t}\t{",".intercalate (ls.toList.map toString)}"
  let out := (← IO.getEnv "CLAUSES_OUT").getD "clauses.tsv"
  IO.FS.writeFile out ("\n".intercalate rows.toList ++ "\n")
  let groups := tally (tags.toArray.map fun (_, ls) =>
    ",".intercalate ((ls.map toString).qsort (· < ·)).toList)
  IO.println s!"theorems by the set of properties needing them: {groups}"
