import Lean
import Relevance.Generate
import Consensus

/-!
# Data for the marking checker (`check.py`), report only

Writes, into the directory `CHECK_OUT`:

- `decls.tsv`: every declaration of a `Consensus.*` module except compiler and elaborator
  auxiliaries (`_proof_N`, matchers, equation lemmas): name, kind, module, first and last line,
  and a fingerprint of its elaborated type (with the names of its leading binders) and, for
  everything but theorems, of its value.
- `walk.tsv`: the case splits of the walked theorems, found by the relevance walker with nothing
  inlined: `unmarked` rows (an eliminator outside any `split_rel`), `split` and `branch` rows (the
  `split_rel` markers).
- `selected.tsv`: the walked theorems with their lines and modules.
- `axioms.tsv` (`final` only): the axioms of each public theorem.

`CHECK_MODE` is `decls` (no walk), `range` (walk the theorems of module `CHECK_MODULE` that start
between the first line of `CHECK_FROM` and the last line of `CHECK_TO`, with their auxiliary
theorems), or `final` (walk every theorem of a `Consensus.*` module in the kernel closure of the
public theorems of `Consensus.Properties`).
-/

open Lean Meta Elab Command

namespace ConsensusCheck

/-- Matches no hypothesis, so every walked theorem has level `other` and only counts are made. -/
structure Never : Prop where

def userName (c : Name) : Name := (privateToUserName? c).getD c

def auxComponent (s : String) : Bool :=
  s.startsWith "_" || s.startsWith "match_" || s.startsWith "proof_" || s == "eq_def" ||
    s == "eq_unfold" || s == "splitter" ||
    (s.startsWith "eq_" && (s.drop 3).all Char.isDigit)

/-- Compiler and elaborator auxiliaries, which a changed proof may add or drop. -/
def isAux (c : Name) : Bool :=
  c.hasMacroScopes || (userName c).components.any fun
    | .str _ s => auxComponent s
    | _ => true

partial def binderNames : Expr → List Name
  | .forallE n _ b _ => n :: binderNames b
  | .mdata _ b => binderNames b
  | _ => []

def fingerprint (ci : ConstantInfo) : UInt64 :=
  let t := mixHash ci.type.hash (hash (binderNames ci.type))
  match ci with
  | .thmInfo _ => t
  | _ => match ci.value? (allowOpaque := true) with
    | some v => mixHash t v.hash
    | none => t

def kind : ConstantInfo → String
  | .thmInfo _ => "theorem" | .defnInfo _ => "def" | .opaqueInfo _ => "opaque"
  | .axiomInfo _ => "axiom" | .inductInfo _ => "inductive" | .ctorInfo _ => "ctor"
  | .recInfo _ => "rec" | .quotInfo _ => "quot"

def lines (c : Name) : MetaM (Nat × Nat) := do
  match ← findDeclarationRanges? c with
  | some r => return (r.range.pos.line, r.range.endPos.line)
  | none => return (0, 0)

/-- Every constant of every `Consensus.*` module, with its module. -/
def consensusConstants : CoreM (Array (Name × Name)) := do
  let env ← getEnv
  let mut out := #[]
  for i in [0:env.header.moduleNames.size] do
    let m := env.header.moduleNames[i]!
    unless (`Consensus).isPrefixOf m do continue
    for c in env.header.moduleData[i]!.constNames do
      out := out.push (c, m)
  return out

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

def clean (s : String) : String :=
  (s.replace "\t" " ").replace "\n" " "

/-- The constant of `module` whose name, private prefix removed, is `n` (or ends with `n`). -/
def resolveIn (consts : Array (Name × Name)) (module n : Name) : CoreM Name := do
  let here := consts.filter (·.2 == module) |>.map (·.1)
  if let some c := here.find? (userName · == n) then return c
  let ends := here.filter fun c => n.isSuffixOf (userName c) && !isAux c
  match ends.toList with
  | [c] => return c
  | [] => throwError "check: no declaration {n} in {module}"
  | cs => throwError "check: {n} is ambiguous in {module}: {cs.map userName}"

def publicTheorems : List Name :=
  [`Consensus.Properties.committed_logs_prefix, `Consensus.Properties.election_safety,
   `Consensus.Properties.single_node_committed_log_monotonic,
   `Consensus.Properties.committed_frontier_is_signature]

/-- Theorems of `Consensus.*` modules in the kernel closure of `roots`. -/
def closureOf (roots : Array Name) (inConsensus : NameSet) : CoreM (Array Name) := do
  let env ← getEnv
  let mut seen : NameSet := {}
  let mut todo := roots
  let mut out := #[]
  while !todo.isEmpty do
    let c := todo.back!
    todo := todo.pop
    if seen.contains c then continue
    seen := seen.insert c
    let some ci := env.find? c | continue
    if ci matches .thmInfo _ && inConsensus.contains c then out := out.push c
    let es := match ci with
      | .thmInfo v => #[v.type, v.value]
      | .defnInfo v => #[v.type, v.value]
      | .opaqueInfo v => #[v.type, v.value]
      | _ => #[ci.type]
    if let .inductInfo v := ci then todo := todo ++ v.ctors.toArray
    for e in es do todo := todo ++ e.getUsedConstants
  return out

def run : MetaM Unit := do
  let out : System.FilePath := (← IO.getEnv "CHECK_OUT").getD "."
  let mode := (← IO.getEnv "CHECK_MODE").getD "decls"
  let env ← getEnv
  let consts ← consensusConstants
  let mut rows := #["name\tkind\tmodule\tfirst\tlast\tfingerprint"]
  for (c, m) in consts do
    if isAux c then continue
    let ci ← getConstInfo c
    let (a, b) ← lines c
    rows := rows.push s!"{userName c}\t{kind ci}\t{m}\t{a}\t{b}\t{fingerprint ci}"
  IO.FS.writeFile (out / "decls.tsv") ("\n".intercalate rows.toList ++ "\n")
  if mode == "decls" then return
  let roots ← if mode == "range" then do
      let module := ((← IO.getEnv "CHECK_MODULE").getD "").toName
      let first ← resolveIn consts module ((← IO.getEnv "CHECK_FROM").getD "").toName
      let last ← resolveIn consts module ((← IO.getEnv "CHECK_TO").getD "").toName
      let lo := (← lines first).1
      let hi := (← lines last).2
      if lo == 0 || hi < lo then throwError "check: bad range {first} .. {last}"
      let mut sel := #[]
      for (c, m) in consts do
        if m != module || isAux c then continue
        unless (env.find? c) matches some (.thmInfo _) do continue
        let (a, _) ← lines c
        if lo ≤ a && a ≤ hi then sel := sel.push c
      let tops := sel.map userName
      let aux := consts.filter fun (c, m) => m == module && isAux c &&
        (env.find? c) matches some (.thmInfo _) &&
        tops.any fun t => t.isPrefixOf (userName c) && t != userName c
      pure (sel ++ aux.map (·.1))
    else if mode == "final" then do
      let inConsensus := consts.foldl (fun s (c, _) => s.insert c) ({} : NameSet)
      let roots := publicTheorems.toArray
      let mut ax := #["theorem\taxioms"]
      for r in roots do
        let as ← collectAxioms r
        ax := ax.push s!"{r}\t{" ".intercalate (as.toList.map toString |>.mergeSort (· ≤ ·))}"
      IO.FS.writeFile (out / "axioms.tsv") ("\n".intercalate ax.toList ++ "\n")
      closureOf roots inConsensus
    else throwError "check: unknown CHECK_MODE {mode}"
  let mut sel := #["name\tfirst\tlast\tmodule"]
  for c in roots do
    let (a, b) ← lines c
    let m := (env.getModuleIdxFor? c).map (env.header.moduleNames[·]!) |>.getD .anonymous
    sel := sel.push s!"{userName c}\t{a}\t{b}\t{m}"
  IO.FS.writeFile (out / "selected.tsv") ("\n".intercalate sel.toList ++ "\n")
  let cfg : Relevance.Config := { scope := `ConsensusCheck.Nothing, package := #[`Consensus],
                                  stepPat := mkConst ``Never, statePat := mkConst ``Never }
  let r ← Relevance.analyse cfg roots
  let mut w := #["row\tdecl\tname\ttag\tflag\ttext"]
  for u in r.unrecorded do
    w := w.push s!"unmarked\t{userName u.decl}\t{u.head}\t{← arity u.head}\t\
      {if u.internal then "internal" else "protocol"}\t{clean (u.cond.take 400).toString}"
  for s in r.splits do
    w := w.push s!"split\t{userName s.decl}\t{s.name}\t{s.branches.size}\t\
      {if s.coveredBy == "" then "-" else s.coveredBy}\t-"
  for b in r.branches do
    w := w.push s!"branch\t{userName b.decl}\t{b.split}\t{b.tag}\t\
      {if b.dead then "dead" else "live"}\t{clean (" ; ".intercalate b.conds.toList)}"
  IO.FS.writeFile (out / "walk.tsv") ("\n".intercalate w.toList ++ "\n")

end ConsensusCheck

set_option maxHeartbeats 0 in
set_option maxRecDepth 100000 in
run_cmd liftTermElabM ConsensusCheck.run
