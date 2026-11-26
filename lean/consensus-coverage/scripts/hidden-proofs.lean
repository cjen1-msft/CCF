module

meta import Lean
public import Consensus.Proofs.SafetyInvariant
public import Consensus.Proofs.Direct
import all Consensus.Proofs.SafetyInvariant
import all Consensus.Proofs.Direct

/-!
# No proof is hidden from the coverage generator

`ConsensusCoverage.Classes` reads proof bodies only from the modules it imports with
`import all`. A theorem proved in any other module reaches it as an axiom without a value.
The generator treats that as a leaf, so the case splits of such a proof are neither counted
nor audited, and `requireRecorded` does not notice.

This file has the imports of `Classes.lean`, so it sees what the generator sees. It fails if
any `Consensus.Proofs` constant in the kernel closure of the four coverage roots has no
visible body, other than the ones named in `allowed`. Keep its imports in step with
`Classes.lean`.

Run from the repository root:

    WS=$(python3 lean/relevance/scripts/workspace.py consensus-coverage)
    lake -d "$WS/consensus-coverage" env lean lean/consensus-coverage/scripts/hidden-proofs.lean
-/

open Lean Meta Elab Command in
run_cmd liftTermElabM do
  let env ← getEnv
  let user (c : Name) : Name := (privateToUserName? c).getD c
  let roots := #[`Consensus.Proofs.CommittedLogs.committed_logs_prefix,
    `Consensus.Proofs.Election.election_safety,
    `Consensus.Proofs.Direct.single_node_committed_log_monotonic,
    `Consensus.Proofs.Direct.committed_frontier_is_signature]
  -- The derived decidable equality on ballot stamps. `VoteFacts.advance` needs it to drop
  -- duplicates, so it stays beside `Stamp`. Its body is compiler-generated and holds only
  -- the proofs that a stamp equals itself and that stamps differing in a field differ.
  let allowed := #[`Consensus.Proofs.VoteFacts.instDecidableEqStamp.decEq]
  let mut seen : NameSet := {}
  let mut todo := roots
  let mut hidden : Array String := #[]
  let mut visible := 0
  while let some c := todo.back? do
    todo := todo.pop
    if seen.contains c then continue
    seen := seen.insert c
    let some ci := env.find? c | throwError "unknown constant {c}"
    todo := todo ++ ci.type.getUsedConstants
    if let .inductInfo v := ci then todo := todo ++ v.ctors.toArray
    let own := (`Consensus.Proofs).isPrefixOf (user c)
    match ci.value? (allowOpaque := true) with
    | some v =>
      todo := todo ++ v.getUsedConstants
      if own && ci matches .thmInfo _ then visible := visible + 1
    | none =>
      if allowed.contains c then
        IO.println s!"allowed without a visible body: {c}"
      else if own && ci matches .axiomInfo _ | .thmInfo _ | .defnInfo _ | .opaqueInfo _ then
        let module := (env.getModuleIdxFor? c).map fun i => env.header.moduleNames[i.toNat]!
        hidden := hidden.push s!"{user c} (in {module.getD .anonymous})"
  unless hidden.isEmpty do
    throwError "{hidden.size} Consensus.Proofs constant(s) in the root closure have no body \
      visible to the coverage generator:{String.join (hidden.qsort (· < ·) |>.toList.map ("\n  " ++ ·))}"
  IO.println s!"{visible} Consensus.Proofs theorems in the root closure, no other constant hidden"
