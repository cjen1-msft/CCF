module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all scripts.explore
import all ConsensusCoverage.GuardedDomain
import all ConsensusCoverage.ReplayAnswers
import all ConsensusCoverage.ScaleCensus
import ConsensusCoverage.CensusGhost

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
  -- The native census forces the row once per (key, caseCode), never once per key alone.
  caseCode : Nat
  cases : Unit → ByteArray
  extend : Option (ByteArray → ByteArray)

-- A future unconditional reader must join the packed schema or get its own
-- coordinate before it can be excluded from the finite residual census.
set_option maxRecDepth 8192 in
example : ReplayAnswers.unconditional.all (fun branch =>
    ((keyAnswers (decode 0)).map Prod.fst).contains (.step branch)) = true := by decide +kernel

private def caseVector (c : ScaleCensus.Context) (decoded : Array (FullProfile.Question × Bool)) :
    ByteArray := Id.run do
  let mut out := ByteArray.empty
  for h : i in [:FullProfile.stepBranches.size] do
    let projected := if c.nomination then none
      else caseProjection[i]!.bind fun j => decoded[j]?.map Prod.snd
    let value := projected.orElse fun _ => c.other FullProfile.stepBranches[i]
    out := out.push (value.elim 0 (fun v => if v then 2 else 1))
  return out

private def censusInput (b : Bounds) (p next : FramePath) (a : Model.Action) (key : JointWitnesses.Key) :=
  ScaleCensus.context (finiteCaseEvidence b p next a key #[])

-- Only the backing fields need the decoded coordinates. The finite context
-- discards those fields, so decode once per new census row, not per edge.
example (b : Bounds) (p next : FramePath) (a : Model.Action) (key : JointWitnesses.Key) (decoded) :
    censusInput b p next a key = ScaleCensus.context (finiteCaseEvidence b p next a key decoded) := rfl

@[export ccf_scale_read] def read (b : Bounds) (g : ExplorerGhost.Ghost)
    (s t : Model.State) (a : Model.Action) : Option Reading := do
  let r ← ExplorerGhost.read b.deployment.cfg g s t a
  let key := toString (encode r.key)
  if b.caseOut.isNone then return ⟨r.ghost, key, r.family, 0, fun _ => .empty, none⟩
  let c := censusInput b {state := s, ghost := g} {state := t, ghost := r.ghost} a r.key
  let extend ← if !b.readerCensus then pure none else do
    let answer ← CensusGhost.answers b.deployment.cfg g r.ghost s t a
    pure <| some fun (old : ByteArray) => Id.run do
      let mut row := old
      for h : i in [:FullProfile.stepBranches.size] do
        if old[i]! != 0 then continue
        if let some v := answer FullProfile.stepBranches[i] then
          row := row.set! i (if v then 2 else 1)
      return row
  return ⟨r.ghost, key, r.family, c.code, fun _ => caseVector c (keyAnswers r.key).toArray, extend⟩

@[export ccf_scale_case_names] def caseNames (_ : Bounds) :=
  FullProfile.stepBranches.map branchName

@[export ccf_scale_wide_columns] def wideColumns (_ : Bounds) :=
  FullProfile.stepBranches.zipIdx.filterMap fun (branch, i) =>
    if Readers.covered.contains branch && !ReplayAnswers.unconditional.contains branch then some i else none

/-- Audit one native row without the interned ghost, probe mask, or memo. -/
@[export ccf_scale_history_row] def historyRow (b : Bounds) (actions : Array Model.Action) :
    Option ByteArray := do
  let d := b.deployment
  let mut before := d.initial
  let mut past := []
  for h : i in [:actions.size] do
    let a := actions[i]
    let after ← (transitionSystem d.cfg d.nodes).step before a
    if i + 1 == actions.size then
      let old := ReplayAnswers.read d.cfg before a after past
      let gen := Readers.read d.cfg before a after past
      return FullProfile.stepBranches.foldl (fun row branch =>
        let v := CensusReplay.answer old gen branch
        row.push (v.elim 0 (fun yes => if yes then 2 else 1))) .empty
    past := before :: past
    before := after
  none

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
        let old := ReplayAnswers.read d.cfg p.state a t p.past
        let v := (ReplayAnswers.answer old (.step branch)).orElse fun _ =>
          if b.readerCensus then Readers.read? (Readers.read d.cfg p.state a t p.past) branch else none
        guard (v == some true)
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
    IO.println "  --scale --audit-reader-every N --reader-census replays every Nth counted row."
    return
  let ranked := args.head? == some "--queue-ladder"
  let symbolic := ranked || args.head? == some "--symbolic"
  if !symbolic && args.head? != some "--scale" then return ← explorerMain args
  let (audit, options) ← match args.tail! with
    | "--audit-reader-every" :: s :: rest => do
      let some n := s.toNat? | throw (IO.userError "expected a positive reader audit interval")
      if n == 0 then throw (IO.userError "expected a positive reader audit interval")
      pure (n, rest)
    | rest => pure (0, rest)
  let b ← IO.ofExcept (boundOptions options {})
  if audit > 0 && (symbolic || !b.readerCensus) then
    throw (IO.userError "--audit-reader-every requires --scale and --reader-census")
  unless b.allows b.deployment.initial do throw (IO.userError "initial state outside bounds")
  unless b.maxCopies == 1 do throw (IO.userError "--scale requires one copy per envelope")
  unless b.deployment.nodes.all (· < 64) do throw (IO.userError "--scale requires node IDs < 64")
  unless b.ghostMode == .history && !b.frontierOnly && !b.compact && b.mergeWorkers == 1 &&
      b.mergeEvery == 1 do throw (IO.userError "use --exhaust for differential/merge audits")
  if symbolic && b.stepBudget.isSome then throw (IO.userError "symbolic search accepts a time limit, not an edge budget")
  if ranked && b.maxSeconds.isSome then throw (IO.userError "--queue-ladder requires a fixpoint")
  let params := #[b.maxNetwork.elim 0 (· + 1), b.stepBudget.elim 0 (· + 1),
    b.maxSeconds.elim 0 (· + 1), symbolic.toNat + ranked.toNat, b.readerCensus.toNat, audit]
  unless params.all (· < 2^63) do throw (IO.userError "bound exceeds native counter width")
  IO.println s!"scale bounds: voters={b.deployment.voters} nodes={b.deployment.nodes} \
    log={b.maxLog} term={b.maxTerm} copies=1 network={repr b.maxNetwork} palette={b.palette.name} \
    budget={repr b.stepBudget} seconds={repr b.maxSeconds}; exact interned IDs, no merge audit"
  (← IO.getStdout).flush
  Scale.run b params b.out (b.caseOut.getD "")
