module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all scripts.explore
import all ConsensusCoverage.GuardedDomain

/-! Native bounded exploration: `scripts/build-explorer.sh` builds this entry
point outside the checkout. `--scale` enumerates exact interned triples
(ordered node table, finite ghost, queue). `--symbolic` instead computes
one exact family of queues per (table, ghost) using decision diagrams.
`--queue-ladder` annotates each queue with the smallest peak queue length
on a path to it, and counts every cap in one fixpoint. Symbolic counts
must not be reported as explicit exploration rates.

All three use one copy per envelope value. `MultiNodeTransitionSystem.next`
only consults the pending queue to remove a delivery, and appends sends.
On an admitted edge every send except a re-sent delivered value is fresh.
The remaining queue-dependent reader input is the set of pre-sources and
post-targets used to probe progress fields. Unlike the cached reader, the
witness replay below uses the actual ordered queues and history. Use
`--exhaust --check-ghost` for an independent differential validation.
None of these search reductions is a kernel proof of exhaustion. -/

open Consensus Consensus.Model Consensus.Model.Node ConsensusCoverage ConsensusCoverage.Explore

namespace ConsensusCoverage.Scale

private partial def natBytes (out : ByteArray) (n : Nat) : ByteArray :=
  if n < 128 then out.push n.toUInt8
  else natBytes (out.push ((n % 128).toUInt8 ||| 128)) (n / 128)

private def rows (out : ByteArray) (xs : List (List Nat)) : ByteArray :=
  xs.foldl (fun buf row => row.foldl natBytes (natBytes buf row.length)) (natBytes out xs.length)

@[export ccf_scale_initial] def initial (b : Bounds) := b.deployment.initial

@[export ccf_scale_start] def start (b : Bounds) (s : Model.State) :=
  ExplorerGhost.start (b.deployment.cfg.min?.getD 0) s

@[export ccf_scale_node_key] def nodeKey (b : Bounds) (s : Model.State) :=
  rows .empty (s.nodes.map fun (n, st) => nodeCode b.deployment.nodes n st)

@[export ccf_scale_ghost_key] def ghostKey (b : Bounds) (g : ExplorerGhost.Ghost) :=
  let k := ghostFrameKey b.deployment {nodes := []} g
  [k.observations, k.canonical, k.commits, k.elections, k.grants, k.votes].foldl rows .empty

@[export ccf_scale_env_key] def envKey (e : Model.Envelope) :=
  (envelopeCode e).foldl natBytes .empty

@[export ccf_scale_source] def source (e : Model.Envelope) := e.source
@[export ccf_scale_target] def target (e : Model.Envelope) := e.target
@[export ccf_scale_delivery] def delivery (e : Model.Envelope) : Model.Action := .deliver e

@[export ccf_scale_locals] def locals (b : Bounds) (s : Model.State) :=
  (boundCandidates b s).toArray.map (·.act)

@[export ccf_scale_step] def step (b : Bounds) (s : Model.State) (a : Model.Action) :
    Option (Model.State × Array Model.Envelope) := do
  let src := match a with
    | .deliver e => {s with network := [e]}
    | .local .. => s
  let t ← (transitionSystem b.deployment.cfg b.deployment.nodes).step src a
  guard (t.nodes.all fun (_, n) => n.currentTerm ≤ b.maxTerm && n.log.length ≤ b.maxLog)
  return ({t with network := []}, t.network.toArray)

@[export ccf_scale_state] def state (s : Model.State) (q : Array Model.Envelope) :=
  {s with network := q.toList}

private structure Reading where
  ghost : ExplorerGhost.Ghost
  key : String
  family : String
  cases : ByteArray

@[export ccf_scale_read] def read (b : Bounds) (g : ExplorerGhost.Ghost)
    (s t : Model.State) (a : Model.Action) : Option Reading := do
  let r ← ExplorerGhost.read b.deployment.cfg g s t a
  let cases := if b.caseOut.isNone then ByteArray.empty else Id.run do
    let decoded := (keyAnswers r.key).toArray
    let evidence := finiteCaseEvidence b {state := s, ghost := g}
      {state := t, ghost := r.ghost} a r.key decoded
    let mut out := ByteArray.empty
    for h : i in [:FullProfile.stepBranches.size] do
      let projected := if evidence.nomination then none
        else caseProjection[i]!.bind fun j => decoded[j]?.map Prod.snd
      let value := projected.orElse fun _ =>
        ReplayAnswers.answer evidence (.step FullProfile.stepBranches[i])
      out := out.push (value.elim 0 (fun v => if v then 2 else 1))
    return out
  return ⟨r.ghost, toString (encode r.key), r.family, cases⟩

@[export ccf_scale_case_names] def caseNames (_ : Bounds) :=
  FullProfile.stepBranches.map branchName

-- Reconstruct the actual delivery offset in the *ordered concrete queue*.
-- In particular the compact BFS queue's ordering is not a witness.
@[export ccf_scale_witness] def witness (b : Bounds) (actions : Array Model.Action)
    (expected : String) (expectedFamily : String) (caseIndex : Nat) : Option String := do
  let d := b.deployment
  let mut p : FramePath := {state := d.initial}
  let mut i := 0
  for a in actions do
    let c ← (boundCandidates b p.state).find? (·.act == a)
    let t ← (transitionSystem d.cfg d.nodes).step p.state a
    guard (b.allows t)
    let k ← JointWitnesses.readKey d.cfg p.state a t p.past
    if i + 1 == actions.size then
      guard (toString (encode k) == expected &&
        Families.code (Families.classify d.cfg p.state a t p.past) == expectedFamily)
      if let some branch := FullProfile.stepBranches[caseIndex]? then
        guard (ReplayAnswers.answer (ReplayAnswers.read d.cfg p.state a t p.past) (.step branch) == some true)
    p := p.advance ⟨c, t⟩ k true {}
    i := i + 1
  return boundedWitness d p

@[extern "ccf_scale_run"] private opaque run (b : @& Bounds) (params : @& Array Nat)
    (out cases : @& String) : IO Unit

end ConsensusCoverage.Scale

public def main (args : List String) : IO Unit := do
  if args == ["--help"] then
    explorerMain args
    IO.println "--scale | --symbolic | --queue-ladder: native exact-ID search for one-copy queues"
    IO.println "  accept --voters, --nodes (IDs < 64), --max-log, --max-term, --max-network,"
    IO.println "  --palette, --case-out TSV, --out TSV. --scale also accepts --step-budget."
    IO.println "  --max-seconds limits exploration, not the final accounting and witness replay."
    IO.println "  --queue-ladder requires a fixpoint and reports all queue caps at once."
    return
  let ranked := args.head? == some "--queue-ladder"
  let symbolic := ranked || args.head? == some "--symbolic"
  if !symbolic && args.head? != some "--scale" then return ← explorerMain args
  let b ← IO.ofExcept (boundOptions args.tail! {})
  unless b.allows b.deployment.initial do throw (IO.userError "initial state outside bounds")
  unless b.maxCopies == 1 do throw (IO.userError "--scale requires one copy per envelope")
  unless b.deployment.nodes.all (· < 64) do throw (IO.userError "--scale requires node IDs < 64")
  unless b.ghostMode == .history && !b.frontierOnly && !b.compact && b.mergeWorkers == 1 &&
      b.mergeEvery == 1 do throw (IO.userError "use --exhaust for differential/merge audits")
  if symbolic && b.stepBudget.isSome then throw (IO.userError "symbolic search accepts a time limit, not an edge budget")
  if ranked && b.maxSeconds.isSome then throw (IO.userError "--queue-ladder requires a fixpoint")
  let params := #[b.maxNetwork.elim 0 (· + 1), b.stepBudget.elim 0 (· + 1),
    b.maxSeconds.elim 0 (· + 1), symbolic.toNat + ranked.toNat]
  unless params.all (· < 2^63) do throw (IO.userError "bound exceeds native counter width")
  IO.println s!"scale bounds: voters={b.deployment.voters} nodes={b.deployment.nodes} \
    log={b.maxLog} term={b.maxTerm} copies=1 network={repr b.maxNetwork} palette={b.palette.name} \
    budget={repr b.stepBudget} seconds={repr b.maxSeconds}; exact interned IDs, no merge audit"
  (← IO.getStdout).flush
  Scale.run b params b.out (b.caseOut.getD "")
