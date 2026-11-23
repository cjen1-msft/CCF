module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public meta import ConsensusCoverage.JointWitnesses
public meta import ConsensusCoverage.GuardedDomain
public meta import ConsensusCoverage.GrantFrontier
public meta import ConsensusCoverage.EventSupport
public meta import Std.Data.HashSet
public meta import Std.Data.HashMap.Basic

/-!
Run from the repository root with `lake -d "$WS/consensus-coverage" env lean
--run "$PWD/lean/consensus-coverage/scripts/explore.lean" --out FILE`.
To keep artifacts out of the source tree, pass an absolute output path.

This is bounded discovery, not exhaustion. BFS does not merge snapshots
(even identical snapshots may have different histories). Walks sample with
replacement. "Shortest" means shortest among paths actually explored.
-/

open Consensus Consensus.Model Consensus.Model.Node ConsensusCoverage
open JointWitnesses (Key)

meta section

namespace ConsensusCoverage.Explore

structure Deployment where
  voters : List NodeID
  nodes : List NodeID
  deriving Repr

def deployments : Array Deployment :=
  #[⟨[0], [0]⟩, ⟨[0], [0, 1]⟩, ⟨[0, 1], [0, 1]⟩, ⟨[0, 1], [0, 1, 2]⟩,
    ⟨[0, 1, 2], [0, 1, 2]⟩]

def Deployment.cfg (d : Deployment) : CCF.Finset NodeID :=
  d.voters.foldl (fun acc n => insert n acc) ∅

def Deployment.initial (d : Deployment) : Model.State :=
  {nodes := d.nodes.map fun n => (n, initialNodeState d.cfg n)}

def palette : List String :=
  ["delivery: every distinct queued envelope (not merely the first per source/target)",
   "append: tx(1), sig, tx(1)+sig; sig/full flush and tx(1)+sig/partial or full flush per peer",
   "append configuration: toggle one deployed voter in latest config (nonempty result); bare, +sig,",
   "  +sig/full flush, or +sig/full flush+sig (flush before final signature), per peer",
   "sendEntries per peer: send frontier f, min(f+1, length), min(f+2, length), midpoint, length",
   "timeout: election, checkQuorum; nominateSuccessor",
   "initAsBackup: empty prefix and each other node's whole committed prefix",
   "all generated inputs are deduplicated and filtered by the actual model step"]

def localInputs (s : Model.State) (self : NodeID) (st : NodeState) : List Input := Id.run do
  let tx : AppendEntryInput := {content := .transaction 1 {}}
  let sig : AppendEntryInput := {content := .signature}
  let len := st.log.length
  let peers := s.nodes.filter (·.1 != self)
  let members := latestConfigurationMembers (configurationHistory st.log)
  let sets := s.nodes.filterMap fun (n, _) =>
    let m := if n ∈ members then members.erase n else insert n members
    if m.Nonempty then some m else none
  let configs := sets.map fun m => ({content := .transaction 1 {configuration := some m}} : AppendEntryInput)
  return ([Input.append [tx], .append [sig], .append [tx, sig]] ++
    (configs.flatMap fun c => [Input.append [c], .append [c, sig]]) ++
    (peers.flatMap fun (peer, other) =>
      let f := st.sentIndex peer
      let sent := [f, min (f+1) len, min (f+2) len, (f+len)/2, len].map (Input.sendEntries peer)
      let flush1 := {sig with flushes := [(peer, len+1)]}
      let flush2 := {sig with flushes := [(peer, len+2)]}
      sent ++ [Input.append [flush1], .append [tx, flush1], .append [tx, flush2],
        .initAsBackup other.committedLog] ++
        (configs.flatMap fun c => [Input.append [c, flush2], .append [c, flush2, sig]])) ++
    [Input.timeout .election, .timeout .checkQuorum, .nominateSuccessor, .initAsBackup []]).eraseDups

structure Candidate where
  act : Model.Action
  -- .deliver resolves to the first envelope on this route. Store the exact
  -- queue index only when plain FrontierRows.Run would select a different value.
  choice : Option Nat := none

def candidates (s : Model.State) : List Candidate := Id.run do
  let mut seen : List Model.Envelope := []
  let mut deliveries := []
  for (e, i) in s.network.zipIdx do
    unless seen.contains e do
      let later := seen.any fun p => p.source == e.source && p.target == e.target
      deliveries := ⟨.deliver e, if later then some i else none⟩ :: deliveries
      seen := e :: seen
  return deliveries.reverse ++ (s.nodes.flatMap fun (n, st) =>
    (localInputs s n st).map fun i => ⟨.local n i, none⟩)

structure Enabled extends Candidate where
  after : Model.State

structure Evidence where
  changed : Bool
  freshKinds : List String
  grant : Bool
  commit : Bool
  pre : String
  post : String
  deriving Repr

def Evidence.pattern (e : Evidence) : String :=
  s!"actor={e.changed} envelopes={repr e.freshKinds} grant={e.grant} commit={e.commit} {e.pre}->{e.post}"

def kind (a : Model.Action) : String :=
  (reprStr (EventSupport.actionTag a)).splitOn "." |>.getLast!

def kindNames : List String :=
  ["append", "appendEntriesRequest", "appendEntriesResponse", "initAsBackup", "nominateSuccessor",
    "proposeRequestVoteRequest", "requestPreVoteRequest", "requestPreVoteResponse",
    "requestVoteRequest", "requestVoteResponse", "sendEntries", "timeout"]

def context (zero backed : Bool) : String :=
  s!"{zero.toNat}{backed.toNat}"

def evidence (v : GuardedDomain.View) (k : Key) : Evidence :=
  let messages := v.after.network.filter fun e => !v.before.network.contains e
  let kinds := (messages.map fun e => kind (.deliver e)).eraseDups.mergeSort (· ≤ ·)
  -- The high six bits of MessageWitnesses.pack are the endpoint/leader key.
  ⟨v.changed, kinds, !GrantFrontier.noNewGrant v.after (v.before :: v.past), k.2.1,
    context (k.1.testBit 21) (k.1.testBit 20), context (k.1.testBit 18) (k.1.testBit 17)⟩

structure Hit extends Candidate where
  key : Key
  facts : Evidence

structure Path where
  deployment : Deployment
  state : Model.State
  past : List Model.State := []
  hits : List Hit := []
  id : Nat := 0

def Path.depth (p : Path) : Nat := p.hits.length
def Path.multi (p : Path) : Bool := p.deployment.nodes.length ≥ 2
def Path.plain (p : Path) : Bool := p.hits.all fun h => h.choice.isNone

abbrev KeySet := Std.HashSet Key
abbrev Witnesses := Std.HashMap Key Path

def keepShorter (ws : Witnesses) (k : Key) (p : Path) : Witnesses :=
  match ws[k]? with
  | some old => if p.depth < old.depth then ws.insert k p else ws
  | none => ws.insert k p

/-- Falsification hook: pass a Boolean family test and its expected *projected*
keys. Each reported step is a counterexample to that projected table. Nothing
is inferred from silence, including for differences outside the projection. -/
structure FamilyCheck where
  member : Deployment → Model.State → Model.Action → Model.State → List Model.State → Evidence → Bool
  expected : List Key

def FamilyCheck.outside (f : FamilyCheck) (p : Path) (before : Model.State) (h : Hit) : Bool :=
  f.member p.deployment before h.act p.state p.past.tail h.facts && !f.expected.contains h.key

-- Worked example: an intentionally overbroad claim that every nomination
-- has a quiet 10->10 key. `--check-family` reports distinct falsifying keys.
def nominationExample : FamilyCheck :=
  ⟨fun _ _ a _ _ _ => kind a == "nominateSuccessor", [(0x240000, false, List.replicate 18 false)]⟩

def hazardNames : Array String :=
  #["unchanged nodes + fresh commit", "unchanged nodes + fresh grant",
    "CONTRADICTION: unchanged nodes + changed endpoint context",
    "CONTRADICTION: unchanged nodes + fresh base-zero commit",
    "CONTRADICTION: consecutive unchanged nodes + fresh grant",
    "CONTRADICTION: second stutter adds commit after first did not"]

structure Score where
  all : Witnesses := {}
  multi : Witnesses := {}
  plain : Witnesses := {}
  plainMulti : Witnesses := {}
  tags : Std.HashMap String KeySet := {}
  patterns : Std.HashMap String KeySet := {}
  outside : Witnesses := {}
  hazards : Array (Nat × Option Path) := hazardNames.map fun _ => (0, none)
  steps : Nat := 0
  checked : Nat := 0
  enabled : Nat := 0
  stuck : Nat := 0
  later : Nat := 0

def Score.menu (score : Score) (p : Path) : Score × Array Enabled := Id.run do
  let mut menu := #[]
  let mut checked := score.checked
  for c in candidates p.state do
    checked := checked + 1
    if let some after := (transitionSystem p.deployment.cfg p.deployment.nodes).step p.state c.act then
      menu := menu.push ⟨c, after⟩
  return ({score with checked, enabled := score.enabled + menu.size}, menu)

def insertGroup (groups : Std.HashMap String KeySet) (name : String) (key : Key) :
    Std.HashMap String KeySet :=
  groups.alter name fun old => some ((old.getD {}).insert key)

def visit (family : Option FamilyCheck) (score : Score) (p : Path) (c : Enabled) :
    IO (Score × Path) := do
  let cfg := p.deployment.cfg
  let some key := JointWitnesses.readKey cfg p.state c.act c.after p.past
    | throw (IO.userError s!"reader failed on enabled step {score.steps + 1}")
  let some v := GuardedDomain.ofAction cfg p.state c.after p.past c.act
    | throw (IO.userError "actor lookup failed on enabled step")
  let facts := evidence v key
  let h : Hit := ⟨c.toCandidate, key, facts⟩
  let next : Path := ⟨p.deployment, c.after, p.state :: p.past, h :: p.hits, score.steps + 1⟩
  let still := !facts.changed
  let consecutive := still && (p.hits.head?.any (! ·.facts.changed))
  let baseZero := key.2.2[15]?.getD false -- after rooted-now and the 14 guarded bits
  let flags := #[still && facts.commit, still && facts.grant,
    still && facts.pre != facts.post, still && baseZero,
    consecutive && facts.grant, consecutive && facts.commit &&
      p.hits.head?.any (! ·.facts.commit)]
  let hazards := score.hazards.mapIdx fun i (n, witness) =>
    if flags[i]! then (n + 1, witness.orElse fun _ => some next) else (n, witness)
  return ({score with
    steps := next.id
    later := score.later + c.choice.isSome.toNat
    all := keepShorter score.all key next
    multi := if next.multi then keepShorter score.multi key next else score.multi
    plain := if next.plain then keepShorter score.plain key next else score.plain
    plainMulti := if next.plain && next.multi then keepShorter score.plainMulti key next else score.plainMulti
    tags := insertGroup score.tags (kind c.act) key
    patterns := insertGroup score.patterns facts.pattern key
    outside := if family.any (fun f => f.outside next p.state h)
      then keepShorter score.outside key next else score.outside
    hazards}, next)

structure Options where
  depth : Nat := 2
  walks : Nat := 120
  length : Nat := 14
  seed : Nat := 20261123
  every : Nat := 20
  out : Option String := none
  checkFamily : Bool := false
  deriving Repr

def usage :=
  "explore.lean [--depth N] [--walks N] [--length N] [--seed N] [--every N] --out FILE [--check-family]"

def options : List String → Options → Except String Options
  | [], o => if o.out.isSome then .ok o else .error usage
  | "--check-family" :: more, o => options more {o with checkFamily := true}
  | "--out" :: file :: more, o => options more {o with out := some file}
  | flag :: value :: more, o => do
    let some n := value.toNat? | throw s!"expected a natural after {flag}\n{usage}"
    match flag with
    | "--depth" => options more {o with depth := n}
    | "--walks" => options more {o with walks := n}
    | "--length" => options more {o with length := n}
    | "--seed" => options more {o with seed := n}
    | "--every" => if n > 0 then options more {o with every := n} else throw "--every must be positive"
    | _ => throw usage
  | _, _ => .error usage

def lcg (x : Nat) : Nat := (1664525 * x + 1013904223) % 4294967296

def growth (phase : String) (score : Score) : IO Unit := do
  IO.println s!"{phase}: {score.steps} steps; {score.all.size} keys, {score.multi.size} multi"
  (← IO.getStdout).flush

def search (o : Options) : IO Score := do
  let family := if o.checkFamily then some nominationExample else none
  let roots := deployments.map fun d => ({deployment := d, state := d.initial} : Path)
  let mut score := {}
  let mut todo := roots
  for i in [:o.depth] do
    let mut next := #[]
    for p in todo do
      let (s, menu) := score.menu p
      score := s
      for c in menu do
        let (s, q) ← visit family score p c
        score := s
        if i + 1 < o.depth then next := next.push q
    growth s!"BFS depth {i+1}" score
    todo := next
  let mut rng := o.seed % 4294967296
  for i in [:o.walks] do
    let some root := roots[i % roots.size]? | throw (IO.userError "no deployment")
    let mut p := root
    for _ in [:o.length] do
      let (s, menu) := score.menu p
      score := s
      if menu.isEmpty then
        score := {score with stuck := score.stuck + 1}
        break
      -- Give each enabled constructor equal weight, then choose within it.
      -- This avoids drowning elections/deliveries in flush/membership variants.
      let kinds := (menu.toList.map fun c => kind c.act).eraseDups.toArray
      rng := lcg rng
      let tag := kinds[(rng / 65536) % kinds.size]!
      let sameKind := menu.filter fun c => kind c.act == tag
      rng := lcg rng
      let some chosen := sameKind[(rng / 65536) % sameKind.size]?
        | throw (IO.userError "sampled an empty action kind")
      let (s, q) ← visit family score p chosen
      score := s
      p := q
    if (i+1) % o.every == 0 || i+1 == o.walks then growth s!"walks {i+1}" score
  return score

def finsetText (ns : List Nat) : String :=
  if ns.isEmpty then "∅" else "{" ++ String.intercalate ", " (ns.map toString) ++ "}"

def contentText : EntryContent → String
  | .signature => ".signature"
  | .transaction n metadata =>
    let cfg := metadata.configuration.map (fun xs => "configuration := some " ++ finsetText xs.sort)
    let retired := if metadata.retirementConfirmations.Nonempty then
      some ("retirementConfirmations := " ++ finsetText metadata.retirementConfirmations.sort) else none
    s!".transaction {n} " ++ "{" ++ String.intercalate ", " ([cfg, retired].filterMap id) ++ "}"

def listText (xs : List String) : String := "[" ++ String.intercalate ", " xs ++ "]"

def inputText : Input → String
  | .append entries => ".append " ++ listText (entries.map fun e =>
      "{content := " ++ contentText e.content ++
        (if e.flushes.isEmpty then "" else s!", flushes := {repr e.flushes}") ++ "}")
  | .sendEntries n i => s!".sendEntries {n} {i}"
  | .timeout .election => ".timeout .election"
  | .timeout .checkQuorum => ".timeout .checkQuorum"
  | .nominateSuccessor => ".nominateSuccessor"
  | .initAsBackup entries => ".initAsBackup " ++ listText (entries.map fun e =>
      "{term := " ++ toString e.term ++ ", content := " ++ contentText e.content ++ "}")

def commandText : Model.Action → String
  | .local n i => s!".input {n} ({inputText i})"
  | .deliver e => s!".deliver {e.source} {e.target}"

def runText (p : Path) : String :=
  s!"⟨{finsetText p.deployment.voters}, {repr p.deployment.nodes}, [\n    " ++
  String.intercalate ",\n    " (p.hits.reverse.map fun h => commandText h.act) ++ "]⟩"

def choices (p : Path) : List (Nat × Nat) :=
  p.hits.reverse.zipIdx.filterMap fun (h, step) => h.choice.map fun i => (step, i)

-- The integer encoding is only an export format for kernel certificates;
-- discovery and all counters above use the full, structured JointWitnesses.Key.
def encode (k : Key) : Nat :=
  k.2.2.foldl (fun n bit => 2 * n + bit.toNat) (k.1 * 2 + k.2.1.toNat)

def ordered (ws : Witnesses) : List (Key × Path) :=
  ws.toList.mergeSort (fun a b => a.2.id ≤ b.2.id)

-- Separate multi-node and overall coverage. For the kernel prefer a plain Run
-- wherever one was seen, even when the unrestricted witness is shorter.
def greedy (todo : KeySet) (paths : List Path) : List Path := Id.run do
  let mut remaining := todo
  let mut selected := []
  for _ in [:todo.size] do
    if remaining.isEmpty then break
    let mut best : Option (Path × List Key) := none
    for p in paths do
      let gain := (p.hits.map (·.key)).eraseDups.filter remaining.contains
      if !gain.isEmpty && (best.all fun (old, keys) =>
          gain.length > keys.length || (gain.length == keys.length && p.depth < old.depth)) then
        best := some (p, gain)
    let some (p, gain) := best | break
    remaining := gain.foldl (·.erase ·) remaining
    selected := p :: selected
  return selected.reverse

def cover (score : Score) : List Path :=
  let pool (ws plain : Witnesses) := (ordered ws).map fun (k, w) => plain[k]?.getD w
  let multi := greedy (Std.HashSet.ofList (score.multi.toList.map Prod.fst)) (pool score.multi score.plainMulti)
  let done := Std.HashSet.ofList (multi.flatMap fun p => p.hits.map (·.key))
  let left := (score.all.toList.map Prod.fst).filter (!done.contains ·)
  multi ++ greedy (Std.HashSet.ofList left) (pool score.all score.plain)

def witnessText (label : String) (h : Hit) (p : Path) : String :=
  s!"-- {label} key {encode h.key}; {kind h.act}; depth {p.depth}; {h.facts.pattern}\n" ++
    s!"({runText p}, {repr (choices p)}),\n"

def report (o : Options) (s : Score) (ms : Nat) : IO Unit := do
  IO.println s!"search: {s.steps} explored steps, {ms} ms, {s.steps * 1000 / max 1 ms} steps/s"
  IO.println s!"menu probes: {s.checked} ({s.checked - s.enabled} disabled; {s.enabled - s.steps} enabled but not followed)"
  IO.println s!"walks ended with empty menu: {s.stuck}; explored non-first-route deliveries: {s.later}"
  IO.println s!"distinct keys: {s.all.size} overall / {s.multi.size} multi; plain Run: {s.plain.size}/{s.plainMulti.size}"
  for name in kindNames do
    IO.println s!"  {name}: {(s.tags[name]?.getD {}).size}"
  IO.println "Most frequent evidence patterns (by distinct keys; groups can overlap):"
  for (name, keys) in (s.patterns.toList.mergeSort (fun a b =>
      a.2.size > b.2.size || (a.2.size == b.2.size && a.1 ≤ b.1))).take 10 do
    IO.println s!"  {keys.size}: {name}"
  for ((n, witness), i) in s.hazards.toList.zipIdx do
    IO.println s!"{hazardNames[i]!}: {n}"
    if let some (p, h) := witness.bind (fun p => p.hits.head?.map (p, ·)) then
      IO.println (witnessText "example" h p)
  if o.checkFamily then
    IO.println s!"nomination example: {s.outside.size} distinct out-of-table keys (see witness file)"
  let runs := cover s
  let observed (rs : List Path) := Std.HashSet.ofList (rs.flatMap fun p => p.hits.map (·.key))
  unless (observed runs).size == s.all.size && (observed (runs.filter Path.multi)).size == s.multi.size do
    throw (IO.userError "greedy witness export did not cover all keys")
  IO.println s!"cover: {runs.length} schedules, {(runs.filter (·.multi)).length} multi, \
    {(runs.filter (! ·.plain)).length} with queue choices, {runs.foldl (fun n p => n + p.depth) 0} steps"
  let text (label : String) (ws : Witnesses) :=
    s!"private def {label} : List (FrontierRows.Run × List (Nat × Nat)) := [\n" ++
    String.join ((ordered ws).filterMap fun (_, p) => p.hits.head?.map (witnessText label · p)) ++ "]\n"
  let certs := runs.zipIdx.map fun (p, i) =>
    let multi := if p.multi then "(some ⟨⟨0, by decide, 1, by decide, by decide⟩⟩)" else "none"
    let codes := p.hits.reverse.map fun h => encode h.key
    s!"private def cert{i} : Certificate := certify\n  ({runText p})\n  {repr (choices p)}\n  {repr codes}\n  \
      (by decide) {multi} (by decide +kernel)\n"
  let file := o.out.getD ""
  IO.FS.writeFile file <| "-- Shortest explored witnesses; (FrontierRows.Run, [(step, queue index)]).\n" ++
    "-- Both indices are zero-based. Nonempty choices are required for exact replay.\n" ++
    "-- Overall:\n" ++ text "overall" s.all ++ "-- Multi-node:\n" ++ text "multiNode" s.multi ++
    "-- Falsifying witnesses:\n" ++ text "outside" s.outside ++
    "-- Greedy cover (paste into ExploredWitnesses):\n" ++ String.intercalate "\n" certs ++
    "\nprivate def certificates : List Certificate := " ++
    listText ((List.range runs.length).map fun i => s!"cert{i}") ++ "\n"
  IO.println s!"wrote {file}"

end ConsensusCoverage.Explore

open ConsensusCoverage.Explore in
public def main (args : List String) : IO Unit := do
  if args == ["--help"] then IO.println usage else do
    let opts ← IO.ofExcept (options args {})
    IO.println s!"{repr opts}"
    IO.println "Deployments (voters, deployed nodes):"
    for d in deployments do IO.println s!"  {repr d.voters}, {repr d.nodes}"
    IO.println "Action palette:"
    for line in palette do IO.println s!"  {line}"
    let start ← IO.monoMsNow
    let score ← search opts
    let stop ← IO.monoMsNow
    report opts score (stop - start)

end
