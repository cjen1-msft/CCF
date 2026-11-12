import Lean
import Consensus.Properties

/-!
# Theorem uses in the consensus proofs, with multiplicity

For each theorem of `Consensus.Proofs` in the kernel closure of the public theorems, the number
of occurrences of each other such theorem in its proof term. With the per-theorem split counts
of `splits.lean`'s `own` walk, this predicts the per-call-path counts of its `inlined` walk:
`N(t) = own(t) + sum over occurrences u in t of N(u)` (an estimate: the walker also walks a
proof argument where the callee uses it, which can repeat or drop it).

Run from the repository root (the workspace is out of tree):

    WS=$(python3 lean/relevance/scripts/workspace.py common consensus relevance consensus-coverage)
    USES_OUT=uses.tsv lake -d $WS/consensus-coverage env lean $PWD/lean/consensus-coverage/scripts/uses.lean

Writes `caller<TAB>callee<TAB>occurrences` rows to `USES_OUT` (default `uses.tsv`).
-/

open Lean Meta Elab Command

namespace ConsensusCoverage.Uses

def inProofs (c : Name) : Bool :=
  `Consensus.Proofs |>.isPrefixOf ((privateToUserName? c).getD c)

def isProofThm (env : Environment) (c : Name) : Bool :=
  inProofs c && (env.find? c matches some (.thmInfo _))

/-- Occurrences of theorems of `Consensus.Proofs` in `e` outside binder types, counted with
multiplicity (shared subterms counted at each occurrence). -/
partial def occurrences (env : Environment) (e : Expr) : StateM (Std.HashMap Name Nat) Unit := do
  match e with
  | .const c _ => if isProofThm env c then modify fun m => m.insert c (m.getD c 0 + 1)
  | .app f a => occurrences env f; occurrences env a
  | .lam _ _ b _ => occurrences env b
  | .letE _ _ v b _ => occurrences env v; occurrences env b
  | .mdata _ b | .proj _ _ b => occurrences env b
  | _ => pure ()

def roots : List Name :=
  [`Consensus.Proofs.CommittedLogs.committed_logs_prefix,
   `Consensus.Proofs.Election.election_safety,
   `Consensus.Proofs.Direct.single_node_committed_log_monotonic,
   `Consensus.Proofs.Direct.committed_frontier_is_signature]

end ConsensusCoverage.Uses

open ConsensusCoverage.Uses in
run_cmd liftTermElabM do
  let env ← getEnv
  let out : System.FilePath := (← IO.getEnv "USES_OUT").getD "uses.tsv"
  let mut seen : NameSet := {}
  let mut todo : Array Name := #[]
  for r in roots do
    let some (c, _) := env.constants.toList.find? fun (c, _) => c == r || privateToUserName? c == some r
      | throwError "no constant {r}"
    todo := todo.push c
  let mut rows := #["caller\tcallee\toccurrences"]
  while !todo.isEmpty do
    let c := todo.back!
    todo := todo.pop
    if seen.contains c then continue
    seen := seen.insert c
    let some v := (env.find? c).bind (·.value? (allowOpaque := true)) | continue
    let ((), m) := (occurrences env v).run {}
    for (d, n) in m.toList do
      rows := rows.push s!"{c}\t{d}\t{n}"
      todo := todo.push d
  IO.FS.writeFile out ("\n".intercalate rows.toList ++ "\n")
  IO.println s!"theorems {seen.size}, edges {rows.size - 1}"
