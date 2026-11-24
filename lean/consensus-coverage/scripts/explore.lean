module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public meta import ConsensusCoverage.JointWitnesses
public meta import ConsensusCoverage.GuardedDomain
public meta import ConsensusCoverage.EventSupport
public meta import ConsensusCoverage.DelayedNominationRead
public meta import ConsensusCoverage.Timely
public meta import ConsensusCoverage.Families
public meta import ConsensusCoverage.ReplayAnswers
public meta import ConsensusCoverage.PairWitnesses
meta import all ConsensusCoverage.CanonicalLogs
meta import all ConsensusCoverage.CommitMonitor
meta import all ConsensusCoverage.GrantFrontier
meta import all ConsensusCoverage.GuardedDomain
meta import all Consensus.Proofs.SafetyInvariant
public meta import Consensus.Proofs.VoteFacts
public meta import Std.Data.HashSet
public meta import Std.Data.HashMap.Basic

/-!
Run from the repository root with `lake -d "$WS/consensus-coverage" env lean
--run "$PWD/lean/consensus-coverage/scripts/explore.lean" --out FILE`.
To keep artifacts out of the source tree, pass an absolute output path.

This is bounded discovery, not exhaustion. BFS does not merge snapshots
(even identical snapshots may have different histories). Walks sample with
replacement. "Shortest" means shortest among paths actually explored.

`--check-timely` and `--check-delayed` run independent falsifiers in the
same search. `--seed-prefixes` adds built-in delayed-commit and retirement
starts. Repeat `--prefix NAME[:N]` to select individual starts or truncate
them to the first N commands. The prefix is replayed from initialization;
`--length` is the number of additional walk steps. `--four-nodes` adds two
four-node deployments. `--retirement` adds the targeted palette below.
An optional `--budget-seconds` stops between walks (not during BFS). Repeat
the reported completed walk count without that flag for deterministic replay.
`--families` prints a closure census using `Families.classify`. Unknown
step-answer ranges sample the first 20 distinct keys in each family. Its
shortest explored family witnesses are included in `--out`.
`--cases` counts each question's known true, known false, and unknown
answers on every explored step. `--sample-cases` instead reads only the
first occurrence of each new key or family code. Shortest positive
witnesses (among the evaluated steps) and a greedy schedule cover are
written to `--out`.

`--exhaust` explores a single bounded deployment by breadth-first search,
merging equal finite proof-frame keys. On every merge it checks the
enabled action signatures of both concrete histories. Counts are not
proofs of key sufficiency or exhaustion of the unbounded model.
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

def fourNodeDeployments : Array Deployment :=
  #[⟨[0, 1], [0, 1, 2, 3]⟩, ⟨[0, 1, 2, 3], [0, 1, 2, 3]⟩]

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

def retirementInputs (self : NodeID) (st : NodeState) : List Input := Id.run do
  let sig : AppendEntryInput := {content := .signature}
  let len := st.log.length
  let singleton : CCF.Finset NodeID := {self}
  let mut batches := []
  if latestConfigurationMembers (configurationHistory st.log) != singleton then
    let c : AppendEntryInput := {content := .transaction 1 {configuration := some singleton}}
    -- Flush the signed change to the current peers, before the final
    -- signature. Delivering real responses can advance the leader's commit.
    let peers := (eligiblePeers st self).sort
    let flush := {sig with flushes := peers.map fun n => (n, len + 2)}
    batches := [[c], [c, sig], [c, flush], [c, flush, sig]] ++
      peers.flatMap (fun n =>
        let one := {sig with flushes := [(n, len + 2)]}
        [[c, one], [c, one, sig]])
  -- Removal alone retains completed retirees as eligible successors.
  -- The only retirement input is an append with confirmation metadata.
  let confirmable := st.retirementCompletedNodes \ retiredCommittedNodes st.log
  if confirmable.Nonempty then
    for confirmed in confirmable :: (confirmable.sort.map fun n => ({n} : CCF.Finset NodeID)) do
      let c : AppendEntryInput := {content := .transaction 1 {retirementConfirmations := confirmed}}
      let flush := {sig with flushes := confirmed.sort.map fun n => (n, len + 2)}
      batches := batches ++ [[c], [c, sig], [c, sig, sig], [c, flush]]
  return batches.map .append

def localInputs (retirement : Bool) (s : Model.State) (self : NodeID) (st : NodeState) : List Input := Id.run do
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
    [Input.timeout .election, .timeout .checkQuorum, .nominateSuccessor, .initAsBackup []] ++
    (if retirement && st.role == .primary then retirementInputs self st else [])).eraseDups

structure Candidate where
  act : Model.Action
  -- .deliver resolves to the first envelope on this route. Store the exact
  -- queue index only when plain FrontierRows.Run would select a different value.
  choice : Option Nat := none

def candidates (retirement : Bool) (s : Model.State) : List Candidate := Id.run do
  let mut seen : List Model.Envelope := []
  let mut deliveries := []
  for (e, i) in s.network.zipIdx do
    unless seen.contains e do
      let later := seen.any fun p => p.source == e.source && p.target == e.target
      deliveries := ⟨.deliver e, if later then some i else none⟩ :: deliveries
      seen := e :: seen
  return deliveries.reverse ++ (s.nodes.flatMap fun (n, st) =>
    (localInputs retirement s n st).map fun i => ⟨.local n i, none⟩)

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
  trueCases : List Nat := []

structure Path where
  deployment : Deployment
  state : Model.State
  past : List Model.State := []
  hits : List Hit := []
  id : Nat := 0

def Path.depth (p : Path) : Nat := p.hits.length
def Path.multi (p : Path) : Bool := p.deployment.nodes.length ≥ 2
def Path.plain (p : Path) : Bool := p.hits.all fun h => h.choice.isNone

inductive SeedCommand where
  | input (n : NodeID) (i : Input)
  | deliver (source target : NodeID) (index : Option Nat := none)

structure Seed where
  name : String
  deployment : Deployment
  commands : List SeedCommand

def SeedCommand.resolve (s : Model.State) : SeedCommand → Option Candidate
  | .input n i => some ⟨.local n i, none⟩
  | .deliver source target choice => do
    let onRoute := fun (e : Model.Envelope) => e.source == source && e.target == target
    let e ← match choice with
      | none => s.network.find? onRoute
      | some n => (s.network[n]?).filter onRoute
    return ⟨.deliver e, choice⟩

-- Keep these as ordinary schedules so users can add seeds (including exact
-- queue overrides) without an interpreter for a separate input language.
def seeds : List Seed :=
  let sig : AppendEntryInput := {content := .signature}
  let cfg := fun n ns => ({content := .transaction n {configuration := some ns}} : AppendEntryInput)
  let flush := fun p i => ({sig with flushes := [(p, i)]} : AppendEntryInput)
  let nom := SeedCommand.input 0 .nominateSuccessor
  let two : Deployment := ⟨[0, 1], [0, 1]⟩
  let three : Deployment := ⟨[0, 1], [0, 1, 2]⟩
  let delayed := [SeedCommand.input 0 (.append [cfg 1 {0}, flush 1 3, sig]), .deliver 0 1]
  let chain := [SeedCommand.input 0 (.append [cfg 1 {0, 2}, flush 1 3, cfg 2 {0}, sig, sig]),
    .deliver 0 2, .deliver 2 0, .input 0 (.sendEntries 2 5), .deliver 0 2, .deliver 0 1]
  let confirm := fun ns => ({content := .transaction 1 {retirementConfirmations := ns}} : AppendEntryInput)
  [⟨"delayed", two, delayed ++ [nom, nom]⟩,
   ⟨"chained", three, chain ++ [nom, nom, nom]⟩,
   ⟨"cert31", two, delayed ++ [.input 0 (.sendEntries 1 3)]⟩,
   ⟨"retired", two, delayed ++ [.deliver 1 0, .input 0 (.append [confirm {1}, sig]), nom]⟩]

def defaultPrefixes : List String :=
  ["delayed:2", "delayed", "chained:6", "chained", "cert31", "retired:3", "retired"]

def findSeed (spec : String) : Except String Seed := do
  let parts := spec.splitOn ":"
  let name := parts.head!
  let some seed := seeds.find? (·.name == name)
    | throw s!"unknown prefix {name}; choose delayed, chained, cert31, or retired"
  match parts with
  | [_] => return seed
  | [_, size] =>
    let some n := size.toNat? | throw s!"invalid prefix length in {spec}"
    if n > seed.commands.length then throw s!"prefix {spec} is longer than its schedule"
    return {seed with name := spec, commands := seed.commands.take n}
  | _ => throw s!"invalid prefix {spec}"

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

structure Tally where
  count : Nat := 0
  shortest : Option Path := none

def Tally.hit (t : Tally) (p : Path) : Tally :=
  ⟨t.count + 1, if t.shortest.all (p.depth < ·.depth) then some p else t.shortest⟩

def familySampleCap : Nat := 20

structure FamilyTally where
  closed : Bool
  tally : Tally := {}
  keys : KeySet := {}
  samples : Nat := 0
  unknown : Option (Nat × Nat) := none

structure CaseTally where
  yes : Tally := {}
  no : Nat := 0
  unknown : Nat := 0

def CaseTally.hit (row : CaseTally) (p : Path) : Option Bool → CaseTally
  | some true => {row with yes := row.yes.hit p}
  | some false => {row with no := row.no + 1}
  | none => {row with unknown := row.unknown + 1}

def FamilyTally.hit (row : FamilyTally) (before next : Path) (h : Hit) : FamilyTally :=
  let newSample := row.samples < familySampleCap && !row.keys.contains h.key
  let row := {row with tally := row.tally.hit next, keys := row.keys.insert h.key}
  if newSample then
    let reader := JointWitnesses.caseReader
    let e := reader.prepare before.deployment.cfg before.state h.act next.state before.past
    let n := FullProfile.stepBranches.foldl (fun n b =>
      n + (reader.answer e b).isNone.toNat) 0
    let (lo, hi) := row.unknown.getD (n, n)
    {row with samples := row.samples + 1, unknown := some (min lo n, max hi n)}
  else row

structure Score where
  all : Witnesses := {}
  multi : Witnesses := {}
  plain : Witnesses := {}
  plainMulti : Witnesses := {}
  tags : Std.HashMap String KeySet := {}
  patterns : Std.HashMap String KeySet := {}
  outside : Witnesses := {}
  hazards : Array (Nat × Option Path) := hazardNames.map fun _ => (0, none)
  timelyChecked : Nat := 0
  timelyFailures : Nat := 0
  timelyExamples : Array Path := #[]
  delayed : Std.HashMap (Bool × StateCoverage.Row) Tally := {}
  nominationsWithoutSuccessor : Nat := 0
  families : Std.HashMap String FamilyTally := {}
  cases : Array CaseTally := #[]
  caseCodes : Std.HashSet String := {}
  caseSamples : Nat := 0
  caseReadMs : Nat := 0
  walksCompleted : Nat := 0
  steps : Nat := 0
  checked : Nat := 0
  enabled : Nat := 0
  stuck : Nat := 0
  later : Nat := 0

def Score.menu (score : Score) (p : Path) (retirement : Bool) : Score × Array Enabled := Id.run do
  let mut menu := #[]
  let mut checked := score.checked
  for c in candidates retirement p.state do
    checked := checked + 1
    if let some after := (transitionSystem p.deployment.cfg p.deployment.nodes).step p.state c.act then
      menu := menu.push ⟨c, after⟩
  return ({score with checked, enabled := score.enabled + menu.size}, menu)

def insertGroup (groups : Std.HashMap String KeySet) (name : String) (key : Key) :
    Std.HashMap String KeySet :=
  groups.alter name fun old => some ((old.getD {}).insert key)

structure Options where
  depth : Nat := 2
  walks : Nat := 120
  length : Nat := 14
  seed : Nat := 20261123
  every : Nat := 20
  budgetSeconds : Option Nat := none
  out : Option String := none
  checkFamily : Bool := false
  checkTimely : Bool := false
  checkDelayed : Bool := false
  families : Bool := false
  cases : Bool := false
  sampleCases : Bool := false
  prefixes : List String := []
  retirement : Bool := false
  fourNodes : Bool := false
  deriving Repr

def Score.checkTimely (score : Score) (p : Path) : Score :=
  let checks := score.timelyChecked + 1
  if Timely.check (p.deployment.cfg.min?.getD 0) p.state p.past then
    {score with timelyChecked := checks}
  else
    let examples := if score.timelyExamples.size < 5 then score.timelyExamples.push p
      else score.timelyExamples
    {score with timelyChecked := checks, timelyFailures := score.timelyFailures + 1, timelyExamples := examples}

def visit (o : Options) (family : Option FamilyCheck) (score : Score) (p : Path) (c : Enabled) :
    IO (Score × Path) := do
  let cfg := p.deployment.cfg
  let some key := JointWitnesses.readKey cfg p.state c.act c.after p.past
    | throw (IO.userError s!"reader failed on enabled step {score.steps + 1}")
  let some v := GuardedDomain.ofAction cfg p.state c.after p.past c.act
    | throw (IO.userError "actor lookup failed on enabled step")
  let facts := evidence v key
  let classification := if o.families || o.sampleCases then
    some (Families.classify cfg p.state c.act c.after p.past) else none
  let code := classification.map Families.code
  let sample := o.cases && (!o.sampleCases || !score.all.contains key ||
    code.any (!score.caseCodes.contains ·))
  let (answers, readMs) ← if sample then do
      let start ← IO.monoMsNow
      let reader := JointWitnesses.caseReader
      let e := reader.prepare cfg p.state c.act c.after p.past
      let answers := FullProfile.stepBranches.map (reader.answer e)
      pure (answers, (← IO.monoMsNow) - start)
    else pure (#[], 0)
  let trueCases := answers.toList.zipIdx.filterMap fun (v, i) => if v == some true then some i else none
  let h : Hit := ⟨c.toCandidate, key, facts, trueCases⟩
  let next : Path := ⟨p.deployment, c.after, p.state :: p.past, h :: p.hits, score.steps + 1⟩
  let score := if sample then {score with
    cases := score.cases.mapIdx fun i row => row.hit next answers[i]!
    caseCodes := code.elim score.caseCodes score.caseCodes.insert
    caseSamples := score.caseSamples + 1
    caseReadMs := score.caseReadMs + readMs} else score
  let score ← if let (true, some family, some code) := (o.families, classification, code) then do
      let row := score.families[code]?.getD {closed := family.closed}
      unless row.closed == family.closed do
        throw (IO.userError s!"family code {code} changed closure status")
      pure {score with families := score.families.insert code (row.hit p next h)}
    else pure score
  let previousFailures := score.timelyFailures
  let score := if o.checkTimely then score.checkTimely next else score
  if score.timelyFailures > previousFailures && score.timelyFailures ≤ 5 then
    IO.println s!"TIMELY FAILURE at explored step {next.id}, schedule depth {next.depth}"
    (← IO.getStdout).flush
  let score ← if o.checkDelayed then do
      let nomination := match c.act with | .local _ .nominateSuccessor => true | _ => false
      let sends := DelayedNomination.sends p.state c.act
      let score := if nomination && !sends then
        {score with nominationsWithoutSuccessor := score.nominationsWithoutSuccessor + 1} else score
      if DelayedNomination.test cfg p.state c.act c.after p.past then
        let group := (sends, StateCoverage.read cfg p.state p.past)
        let t := score.delayed[group]?.getD {}
        if !sends && t.count == 0 then
          IO.println s!"OPEN ROW HIT at explored step {next.id}, schedule depth {next.depth}"
          (← IO.getStdout).flush
        pure {score with delayed := score.delayed.insert group (t.hit next)}
      else pure score
    else pure score
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

def usage :=
  "explore.lean [--depth N] [--walks N] [--length N] [--seed N] [--every N] [--budget-seconds N] --out FILE\n" ++
  "  [--families] [--cases | --sample-cases] [--check-family] [--check-timely] [--check-delayed]\n" ++
  "  [--four-nodes] [--retirement]\n" ++
  "  [--seed-prefixes] [--prefix NAME[:N]]... (delayed, chained, cert31, retired)"

def options : List String → Options → Except String Options
  | [], o => if o.out.isSome then .ok o else .error usage
  | "--families" :: more, o => options more {o with families := true}
  | "--cases" :: more, o => options more {o with cases := true}
  | "--sample-cases" :: more, o => options more {o with cases := true, sampleCases := true}
  | "--check-family" :: more, o => options more {o with checkFamily := true}
  | "--check-timely" :: more, o => options more {o with checkTimely := true}
  | "--check-delayed" :: more, o => options more {o with checkDelayed := true}
  | "--four-nodes" :: more, o => options more {o with fourNodes := true}
  | "--retirement" :: more, o => options more {o with retirement := true}
  | "--seed-prefixes" :: more, o => options more {o with prefixes := o.prefixes ++ defaultPrefixes}
  | "--prefix" :: spec :: more, o => options more {o with prefixes := o.prefixes ++ [spec]}
  | "--out" :: file :: more, o => options more {o with out := some file}
  | flag :: value :: more, o => do
    let some n := value.toNat? | throw s!"expected a natural after {flag}\n{usage}"
    match flag with
    | "--depth" => options more {o with depth := n}
    | "--walks" => options more {o with walks := n}
    | "--length" => options more {o with length := n}
    | "--seed" => options more {o with seed := n}
    | "--budget-seconds" => options more {o with budgetSeconds := some n}
    | "--every" => if n > 0 then options more {o with every := n} else throw "--every must be positive"
    | _ => throw usage
  | _, _ => .error usage

def lcg (x : Nat) : Nat := (1664525 * x + 1013904223) % 4294967296

def growth (phase : String) (score : Score) : IO Unit := do
  IO.println s!"{phase}: {score.steps} steps; {score.all.size} keys, {score.multi.size} multi"
  unless score.timelyChecked == 0 do
    IO.println s!"  Timely so far: {score.timelyChecked} snapshots, {score.timelyFailures} failures"
  (← IO.getStdout).flush

def backgrounds (o : Options) : Array Deployment :=
  if o.fourNodes then deployments ++ fourNodeDeployments else deployments

def search (o : Options) : IO Score := do
  let start ← IO.monoMsNow
  let family := if o.checkFamily then some nominationExample else none
  let roots := (backgrounds o).map fun d => ({deployment := d, state := d.initial} : Path)
  let selected ← IO.ofExcept (o.prefixes.mapM findSeed)
  let mut score := {}
  if o.cases then
    score := {score with cases := FullProfile.stepBranches.map fun _ => {}}
  if o.checkTimely then
    for p in roots do
      let old := score.timelyFailures
      score := score.checkTimely p
      if score.timelyFailures > old then IO.println s!"TIMELY FAILURE at initialization: {repr p.deployment}"
  let mut walkRoots := roots
  for seed in selected do
    let d := seed.deployment
    let some root := roots.find? (fun p => p.deployment.voters == d.voters && p.deployment.nodes == d.nodes)
      | throw (IO.userError s!"missing deployment for prefix {seed.name}")
    let mut p := root
    for cmd in seed.commands do
      let some c := cmd.resolve p.state | throw (IO.userError s!"unresolved prefix {seed.name} at depth {p.depth}")
      let some after := (transitionSystem d.cfg d.nodes).step p.state c.act
        | throw (IO.userError s!"disabled prefix {seed.name} at depth {p.depth}")
      let (s, q) ← visit o family {score with checked := score.checked + 1, enabled := score.enabled + 1}
        p ⟨c, after⟩
      score := s
      p := q
    walkRoots := walkRoots.push p
  unless selected.isEmpty do growth s!"Replayed {selected.length} walk prefixes" score
  let mut todo := roots
  for i in [:o.depth] do
    let mut next := #[]
    for p in todo do
      let (s, menu) := score.menu p o.retirement
      score := s
      for c in menu do
        let (s, q) ← visit o family score p c
        score := s
        if i + 1 < o.depth then next := next.push q
    growth s!"BFS depth {i+1}" score
    todo := next
  let mut rng := o.seed % 4294967296
  for i in [:o.walks] do
    if let some limit := o.budgetSeconds then
      if (← IO.monoMsNow) - start ≥ 1000 * limit then
        growth s!"Budget reached after {score.walksCompleted} walks" score
        break
    let some root := walkRoots[i % walkRoots.size]? | throw (IO.userError "no deployment")
    let mut p := root
    for _ in [:o.length] do
      let (s, menu) := score.menu p o.retirement
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
      let (s, q) ← visit o family score p chosen
      score := s
      p := q
    score := {score with walksCompleted := i + 1}
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

def scheduleText (d : Deployment) (hits : List Candidate) : String :=
  let commands := hits.reverse.map fun h => commandText h.act
  let schedule := if commands.isEmpty then "[]" else "[\n    " ++ String.intercalate ",\n    " commands ++ "]"
  s!"⟨{finsetText d.voters}, {repr d.nodes}, {schedule}⟩"

def runText (p : Path) : String := scheduleText p.deployment (p.hits.map (·.toCandidate))

def deliveryChoices (hits : List Candidate) : List (Nat × Nat) :=
  hits.reverse.zipIdx.filterMap fun (h, step) => h.choice.map fun i => (step, i)

def choices (p : Path) : List (Nat × Nat) := deliveryChoices (p.hits.map (·.toCandidate))

-- The integer encoding is only an export format for kernel certificates;
-- discovery and all counters above use the full, structured JointWitnesses.Key.
def encode (k : Key) : Nat :=
  k.2.2.foldl (fun n bit => 2 * n + bit.toNat) (k.1 * 2 + k.2.1.toNat)

def ordered (ws : Witnesses) : List (Key × Path) :=
  ws.toList.mergeSort (fun a b => a.2.id ≤ b.2.id)

-- Separate multi-node and overall coverage. For the kernel prefer a plain Run
-- wherever one was seen, even when the unrestricted witness is shorter.
def greedy [BEq α] [Hashable α] (keys : Path → List α)
    (todo : Std.HashSet α) (paths : List Path) : List Path := Id.run do
  let mut remaining := todo
  let mut selected := []
  for _ in [:todo.size] do
    if remaining.isEmpty then break
    let mut best : Option (Path × List α) := none
    for p in paths do
      let gain := (keys p).eraseDups.filter remaining.contains
      if !gain.isEmpty && (best.all fun (old, keys) =>
          gain.length > keys.length || (gain.length == keys.length && p.depth < old.depth)) then
        best := some (p, gain)
    let some (p, gain) := best | break
    remaining := gain.foldl (·.erase ·) remaining
    selected := p :: selected
  return selected.reverse

def cover (score : Score) : List Path :=
  let pool (ws plain : Witnesses) := (ordered ws).map fun (k, w) => plain[k]?.getD w
  let keys := fun p : Path => p.hits.map (·.key)
  let multi := greedy keys (Std.HashSet.ofList (score.multi.toList.map Prod.fst)) (pool score.multi score.plainMulti)
  let done := Std.HashSet.ofList (multi.flatMap keys)
  let left := (score.all.toList.map Prod.fst).filter (!done.contains ·)
  multi ++ greedy keys (Std.HashSet.ofList left) (pool score.all score.plain)

def witnessText (label : String) (h : Hit) (p : Path) : String :=
  s!"-- {label} key {encode h.key}; {kind h.act}; depth {p.depth}; {h.facts.pattern}\n" ++
    s!"({runText p}, {repr (choices p)}),\n"

def scheduleType := " : List (FrontierRows.Run × List (Nat × Nat)) := [\n"

def reportCases (o : Options) (s : Score) : IO String := do
  let rows := (FullProfile.stepBranches.zip s.cases).toList.zipIdx
  unless rows.length == FullProfile.stepBranches.size &&
      rows.all (fun ((_, r), _) => r.yes.count + r.no + r.unknown == s.caseSamples) &&
      (o.sampleCases || s.caseSamples == s.steps) do
    throw (IO.userError "case totals disagree with evaluation count")
  let yes := rows.filter (fun ((_, r), _) => r.yes.count > 0)
  let unseen := rows.filter (fun ((_, r), _) => r.yes.count == 0)
  let no := unseen.filter (fun ((_, r), _) => r.unknown == 0 && s.caseSamples > 0)
  let unknown := unseen.filter (fun ((_, r), _) => r.unknown > 0 || s.caseSamples == 0)
  IO.println s!"Case census: {s.caseSamples}/{s.steps} explored steps fully evaluated \
    ({s.caseReadMs} ms in case reads, including unknowns)"
  IO.println (if o.sampleCases then "Selection: first occurrence of each new key or family code."
    else "Selection: every explored step, counting occurrences, including prefix replay.")
  let shortName (b : Classes.StepBranch) :=
    (reprStr b).splitOn "." |>.getLast!
  let witnesses := yes.filterMap fun ((_, r), _) => r.yes.shortest
  let trueCases (p : Path) := p.hits.flatMap (·.trueCases)
  let runs := greedy trueCases (Std.HashSet.ofList (yes.map Prod.snd)) witnesses
  unless (Std.HashSet.ofList (runs.flatMap trueCases)).size == yes.length do
    throw (IO.userError "greedy case export did not cover all positive answers")
  let groups := [("(a) witnessed true", yes), ("(b) false in every evaluated step", no),
    ("(c) never witnessed true, unknown or not evaluated", unknown)]
  let mut text := "-- Case census (bounded search, not an unreachability proof).\n"
  for (group, rs) in groups do
    IO.println s!"{group}: {rs.length}"
    IO.println "question\tknown_true\tknown_false\tunknown\tshortest_depth\twitness"
    for ((b, r), _) in rs do
      let p := r.yes.shortest
      let depth := (p.map fun p => toString p.depth).getD "-"
      let witness := (p.map fun p => toString p.id).getD "-"
      IO.println s!"{shortName b}\t{r.yes.count}\t{r.no}\t{r.unknown}\t{depth}\t{witness}"
  text := text ++ "-- Shortest positive witness by explored step ID (both override indices zero-based).\n" ++
    "private def caseWitnesses : List (Nat × FrontierRows.Run × List (Nat × Nat)) := [\n"
  for p in (witnesses.mergeSort (·.id ≤ ·.id)).eraseDupsBy (·.id == ·.id) do
    text := text ++ s!"({p.id}, {runText p}, {repr (choices p)}),\n"
  IO.println s!"Case cover: {runs.length} schedules, {runs.foldl (fun n p => n + p.depth) 0} steps"
  let mut claimed : Std.HashSet Nat := {}
  let mut certs := #[]
  for (p, i) in runs.zipIdx do
    let mut claims := #[]
    for (h, j) in p.hits.reverse.zipIdx do
      let cases := h.trueCases.filter (!claimed.contains ·)
      unless cases.isEmpty do
        claims := claims.push (j, cases)
        claimed := cases.foldl (·.insert ·) claimed
    let run := s!"run{i}"
    let choicesName := s!"choices{i}"
    let valid := s!"valid{i}"
    let names := claims.toList.map fun (j, _) => s!"run{i}At{j}"
    let proofs := claims.toList.zipWith (fun (j, cases) name =>
      s!"private def {name} : Claim {run} {choicesName} {valid} := caseAt {j} {repr cases}\n") names
    certs := certs.push <| s!"private def {run} : FrontierRows.Run := {runText p}\n\
      private def {choicesName} : List (Nat × Nat) := {repr (choices p)}\n\
      private theorem {valid} : {run}.valid := by decide\n" ++ String.join proofs ++
      s!"private def cert{i} : Certificate := certify {run} {choicesName} {valid}\n  {listText names}\n"
  return text ++ "]\n-- Greedy positive cover (paste into CaseWitnesses):\n" ++
    String.intercalate "\n" certs.toList ++
    "private def certificates : List Certificate := " ++
    listText ((List.range runs.length).map fun i => s!"cert{i}") ++ "\n"

def reportChecks (o : Options) (s : Score) : IO String := do
  let mut text := ""
  if o.checkTimely then
    let expected := s.steps + (backgrounds o).size
    unless s.timelyChecked == expected do
      throw (IO.userError s!"Timely check count {s.timelyChecked} disagrees with {expected} snapshots")
    IO.println s!"Timely: {s.timelyChecked} snapshots checked; {s.timelyFailures} failures"
    text := text ++ "private def timelyFailures" ++ scheduleType
    for p in s.timelyExamples do
      let schedule := s!"({runText p}, {repr (choices p)}),\n"
      IO.println s!"Timely failure at step {p.id} (depth {p.depth}):\n{schedule}"
      text := text ++ schedule
    text := text ++ "]\n"
  if o.checkDelayed then
    let rows : List StateCoverage.Row := [(true, false), (true, true), (false, true)]
    let allGroups := [false, true].flatMap fun sends => rows.map (sends, ·)
    if s.delayed.toList.any (fun (group, _) => !allGroups.contains group) then
      throw (IO.userError "delayed nomination hit an unexpected initialized endpoint context")
    let total := s.delayed.toList.foldl (fun n (_, t) => n + t.count) 0
    IO.println s!"Delayed nomination test: {total} steps passed; \
      {s.nominationsWithoutSuccessor} nominations without a successor before filtering by test"
    text := text ++ "private def delayedWitnesses" ++ scheduleType
    for (sends, pre) in allGroups do
      let t := s.delayed[(sends, pre)]?.getD {}
      let label := s!"sends={sends}, pre={context pre.1 pre.2}"
      IO.println s!"  {label}: {t.count} steps"
      if let some (p, h) := t.shortest.bind (fun p => p.hits.head?.map (p, ·)) then
        let schedule := witnessText label h p
        IO.println schedule
        text := text ++ schedule
    text := text ++ "]\n"
  return text

def reportFamilies (s : Score) : IO String := do
  let rows := s.families.toList.mergeSort fun (a, x) (b, y) =>
    x.tally.count > y.tally.count || (x.tally.count == y.tally.count && a ≤ b)
  let closed := rows.filter (·.2.closed)
  let opened := rows.filter (! ·.2.closed)
  let steps (rs : List (String × FamilyTally)) := rs.foldl (fun n (_, r) => n + r.tally.count) 0
  let keys (rs : List (String × FamilyTally)) :=
    rs.foldl (fun ks (_, r) => r.keys.toList.foldl (·.insert ·) ks) ({} : KeySet)
  let closedKeys := keys closed
  let openKeys := keys opened
  unless steps rows == s.steps && (keys rows).size == s.all.size do
    throw (IO.userError "family totals disagree with explored steps or keys")
  IO.println s!"Family census: {s.steps} steps, {s.all.size} distinct sound keys"
  IO.println s!"  closed: {steps closed} steps, {closedKeys.size} keys, {closed.length} codes"
  IO.println s!"  open: {steps opened} steps, {openKeys.size} keys, {opened.length} codes"
  IO.println s!"  keys seen in both groups: {closedKeys.size + openKeys.size - s.all.size}"
  IO.println s!"Open evidence bit order: {Families.evidenceOrder}"
  IO.println s!"Unknowns: first {familySampleCap} distinct keys per code (first encountered step for each), \
    over {FullProfile.stepBranches.size} step questions. Sample extrema, not exhaustion."
  let header := "family\tstatus\tsteps\tkeys\tsampled\tunknown_min\tunknown_max\tshortest_depth"
  let line (code : String) (r : FamilyTally) :=
    let status := if r.closed then "closed" else "open"
    let (lo, hi) := r.unknown.getD (0, 0)
    let depth := (r.tally.shortest.map Path.depth).getD 0
    s!"{code}\t{status}\t{r.tally.count}\t{r.keys.size}\t{r.samples}\t{lo}\t{hi}\t{depth}"
  IO.println "Families by explored steps:"
  IO.println header
  let mut witnesses := ""
  for (code, r) in rows do
    let some p := r.tally.shortest | throw (IO.userError s!"missing witness for {code}")
    let some (lo, hi) := r.unknown | throw (IO.userError s!"missing unknown samples for {code}")
    unless r.samples == min familySampleCap r.keys.size && lo ≤ hi &&
        hi ≤ FullProfile.stepBranches.size do
      throw (IO.userError s!"invalid unknown samples for {code}")
    IO.println (line code r)
    witnesses := witnesses ++ s!"({repr code}, {runText p}, {repr (choices p)}),\n"
  IO.println "Open closure priorities (fewest keys, then fewest minimum unknowns):"
  IO.println header
  for (code, r) in opened.mergeSort (fun (a, x) (b, y) =>
      let xmin := (x.unknown.getD (0, 0)).1
      let ymin := (y.unknown.getD (0, 0)).1
      x.keys.size < y.keys.size || (x.keys.size == y.keys.size &&
        (xmin < ymin || (xmin == ymin && a ≤ b)))) do
    IO.println (line code r)
  return "-- Shortest explored witness for each family code, in first table order.\n" ++
    "private def familyWitnesses : List (String × FrontierRows.Run × List (Nat × Nat)) := [\n" ++
    witnesses ++ "]\n"

def report (o : Options) (s : Score) (ms : Nat) : IO Unit := do
  IO.println s!"search: {s.steps} explored steps, {ms} ms, {s.steps * 1000 / max 1 ms} steps/s"
  IO.println s!"completed walks: {s.walksCompleted}/{o.walks}"
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
  let checkText ← reportChecks o s
  let familyText ← if o.families then reportFamilies s else pure ""
  let caseText ← if o.cases then reportCases o s else pure ""
  let runs := cover s
  let observed (rs : List Path) := Std.HashSet.ofList (rs.flatMap fun p => p.hits.map (·.key))
  unless (observed runs).size == s.all.size && (observed (runs.filter Path.multi)).size == s.multi.size do
    throw (IO.userError "greedy witness export did not cover all keys")
  IO.println s!"cover: {runs.length} schedules, {(runs.filter (·.multi)).length} multi, \
    {(runs.filter (! ·.plain)).length} with queue choices, {runs.foldl (fun n p => n + p.depth) 0} steps"
  let text (label : String) (ws : Witnesses) :=
    s!"private def {label}{scheduleType}" ++
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
    "-- Falsifying witnesses:\n" ++ text "outside" s.outside ++ checkText ++ familyText ++
    "-- Greedy cover (paste into ExploredWitnesses):\n" ++ String.intercalate "\n" certs ++
    "\nprivate def certificates : List Certificate := " ++
    listText ((List.range runs.length).map fun i => s!"cert{i}") ++ "\n" ++ caseText
  IO.println s!"wrote {file}"

inductive BoundPalette where
  | core | reconfig | retirement
  deriving Repr, BEq

def BoundPalette.name : BoundPalette → String
  | .core => "core"
  | .reconfig => "reconfig"
  | .retirement => "retirement"

structure Bounds where
  deployment : Deployment := ⟨[0, 1], [0, 1]⟩
  maxLog : Nat := 2
  maxTerm : Nat := 3
  maxCopies : Nat := 1
  maxNetwork : Option Nat := none
  palette : BoundPalette := .core
  stepBudget : Option Nat := none
  out : String := ""
  deriving Repr

def exhaustUsage :=
  "explore.lean --exhaust [--voters 0,1] [--nodes 0,1] [--max-log 2] [--max-term 3]\n" ++
  "  [--max-copies 1] [--max-network N] [--palette core|reconfig|retirement] [--step-budget N] --out FILE"

def boundOptions : List String → Bounds → Except String Bounds
  | [], b => do
    let d := b.deployment
    unless !d.voters.isEmpty && d.voters == d.voters.eraseDups &&
        d.nodes == d.nodes.eraseDups && d.voters.all d.nodes.contains do
      throw "voters must be a nonempty set of distinct deployed node IDs; node IDs must be distinct"
    if b.out.isEmpty then throw exhaustUsage else return b
  | "--out" :: file :: more, b => boundOptions more {b with out := file}
  | "--palette" :: value :: more, b => do
    let p ← match value with
      | "core" => pure .core
      | "reconfig" => pure .reconfig
      | "retirement" => pure .retirement
      | _ => throw exhaustUsage
    boundOptions more {b with palette := p}
  | flag :: value :: more, b => do
    if flag == "--voters" || flag == "--nodes" then
      let some ns := (value.splitOn ",").mapM String.toNat?
        | throw s!"expected comma-separated node IDs after {flag}"
      let d := b.deployment
      let d := if flag == "--voters" then {d with voters := ns.mergeSort (· ≤ ·)} else {d with nodes := ns}
      boundOptions more {b with deployment := d}
    else
      let some n := value.toNat? | throw s!"expected a natural after {flag}\n{exhaustUsage}"
      match flag with
      | "--max-log" => boundOptions more {b with maxLog := n}
      | "--max-term" => boundOptions more {b with maxTerm := n}
      | "--max-copies" => boundOptions more {b with maxCopies := n}
      | "--max-network" => boundOptions more {b with maxNetwork := some n}
      | "--step-budget" => boundOptions more {b with stepBudget := some n}
      | _ => throw exhaustUsage
  | _, _ => .error exhaustUsage

-- Field lengths separate variable-width parts; these are structural keys,
-- not hash digests. CCF finsets are serialized in increasing order.
def field (xs : List Nat) : List Nat := xs.length :: xs

def optional (n : Option Nat) : List Nat := n.toList

def logCode (l : List Entry) : List Nat := field (l.flatMap fun e =>
  e.term :: match e.content with
  | .signature => [0]
  | .transaction n m =>
    [1, n] ++ field (m.configuration.toList.flatMap fun c => field c.sort) ++
      field m.retirementConfirmations.sort)

def nodeCode (ns : List NodeID) (n : NodeID) (s : NodeState) : List Nat :=
  let role := match s.role with
    | .none => 0 | .follower => 1 | .preVoteCandidate => 2 | .candidate => 3 | .primary => 4
  [n, role, s.currentTerm, s.commitIndex, s.isNewFollower.toNat, s.primaryKnown.toNat] ++
    logCode s.log ++ ns.map s.sentIndex ++ ns.map s.matchIndex ++
    field (optional s.votedFor) ++ field s.votesGranted.sort ++ field s.preVotesGranted.sort ++
    field (optional s.retiredCommittedIndex)

def envelopeCode (e : Model.Envelope) : List Nat :=
  e.source :: e.target :: match e.payload with
  | .appendEntriesRequest r => [0, r.term, r.prevLogIndex, r.prevLogTerm, r.primaryCommit] ++ logCode r.entries
  | .appendEntriesResponse r => [1, r.term, r.success.toNat, r.lastLogIndex]
  | .requestVoteRequest r => [2, r.term, r.lastCommittableTerm, r.lastCommittableIndex]
  | .requestVoteResponse r => [3, r.term, r.voteGranted.toNat]
  | .requestPreVoteRequest r => [4, r.term, r.lastCommittableTerm, r.lastCommittableIndex]
  | .requestPreVoteResponse r => [5, r.term, r.voteGranted.toNat]
  | .proposeRequestVoteRequest k => [6, k]

def setCode (xs : List (List Nat)) : List (List Nat) :=
  xs.eraseDups.mergeSort (fun a b => compare a b != .gt)

def Bounds.allows (b : Bounds) (s : Model.State) : Bool :=
  s.nodes.all (fun (_, st) => st.currentTerm ≤ b.maxTerm && st.log.length ≤ b.maxLog) &&
  b.maxNetwork.all (fun n => s.network.length ≤ n) &&
  s.network.all (fun e => s.network.count e ≤ b.maxCopies)

structure FrameKey where
  deployment : List NodeID × List NodeID
  nodes : List (List Nat)
  queue : List (List Nat)
  observations : List (List Nat)
  canonical : List (List Nat)
  commits : List (List Nat)
  elections : List (List Nat)
  grants : List (List Nat)
  votes : List (List Nat)
  deriving BEq, Hashable

def elections : List Model.State → List (List Nat)
  | t :: s :: past =>
    (t.nodes.filterMap fun (n, y) => do
      let x ← s.nodes.lookup n
      if CommitMonitor.election t s past n y.currentTerm then
        some ([n, y.currentTerm, x.commitIndex] ++ logCode x.log) else none) ++ elections (s :: past)
  | _ => []

open Consensus.Proofs in
def grantThresholds : List Model.State → List ((Nat × Nat × Nat) × (Nat × Nat))
  | t :: s :: past =>
    (t.nodes.filterMap fun (v, y) => do
      let c ← y.votedFor
      let x ← s.nodes.lookup v
      let k := y.currentTerm
      let r := GrantFrontier.minimum x k
      let q : GrantMonitor.Query := ⟨v, c, k, r⟩
      let old := (GuardedDomain.observations (s :: past) c).any fun o => o.currentTerm == k
      if (GrantMonitor.advance q ⟨old, false⟩ s t).granted then
        some ((v, c, k), (r.lastCommittableTerm, r.lastCommittableIndex)) else none) ++
      grantThresholds (s :: past)
  | _ => []

def grants (hist : List Model.State) : List (List Nat) := Id.run do
  let mut mins : Std.HashMap (Nat × Nat × Nat) (Nat × Nat) := {}
  for (key, threshold) in grantThresholds hist do
    mins := mins.alter key fun old => some (old.elim threshold fun best =>
      if threshold.1 < best.1 || (threshold.1 == best.1 && threshold.2 < best.2)
      then threshold else best)
  return setCode (mins.toList.map fun ((v, c, k), (term, idx)) => [v, c, k, term, idx])

open Consensus.Proofs in
def frameKey (d : Deployment) (s : Model.State) (past : List Model.State) : FrameKey :=
  let hist := s :: past
  let bootstrap := d.cfg.min?.getD 0
  let logKeys (xs : List (Nat × List Entry)) := setCode (xs.map fun (k, l) => k :: logCode l)
  ⟨(d.voters, d.nodes), s.nodes.map fun (n, st) => nodeCode d.nodes n st,
    (s.network.map envelopeCode).mergeSort (fun a b => compare a b != .gt),
    setCode (d.nodes.flatMap fun n => (GuardedDomain.observations hist n).map fun o =>
      n :: o.currentTerm :: logCode o.log),
    logKeys (CanonicalLogs.keys bootstrap hist), logKeys (CommitKeys.keys bootstrap hist),
    setCode (elections hist), grants hist,
    setCode ((hist.foldr (fun snap g => VoteFacts.advance g snap) []).map fun st =>
      st.voter :: st.term :: optional st.vote)⟩

structure FramePath where
  state : Model.State := {nodes := []}
  past : List Model.State := []
  hits : List Candidate := []
  codes : List Nat := []
  deriving Inhabited

def FramePath.advance (p : FramePath) (e : Enabled) (k : Key) : FramePath :=
  ⟨e.after, p.state :: p.past, e.toCandidate :: p.hits, encode k :: p.codes⟩

def boundCandidates (b : Bounds) (s : Model.State) : List Candidate :=
  (candidates (b.palette == .retirement) s).filter fun c =>
    b.palette != .core || match c.act with
    | .local _ (.append xs) => xs.all fun x => x.content.metadata.configuration.isNone
    | _ => true

-- Sort by the actual selected action: queue offsets are replay data, not
-- action identity. commandText preserves all local inputs in the palette.
def actionCode : Model.Action → String × List Nat
  | .deliver e => ("", envelopeCode e)
  | a => (commandText a, [])

structure EdgeRead where
  action : String × List Nat
  key : Key
  family : String
  inside : Bool
  deriving BEq, Repr

structure Probe where
  edges : Array (Enabled × EdgeRead) := #[]
  excluded : Nat := 0
  menuNs : Nat := 0
  readerNs : Nat := 0

def probe (b : Bounds) (p : FramePath) (compareAll : Bool) : IO Probe := do
  let start ← IO.monoNanosNow
  let cfg := b.deployment.cfg
  let menu := (boundCandidates b p.state).filterMap fun c =>
    ((transitionSystem cfg b.deployment.nodes).step p.state c.act).map fun t =>
      ((⟨c, t⟩ : Enabled), b.allows t)
  let mapped ← IO.monoNanosNow
  let mut edges := #[]
  let mut excluded := 0
  for (e, inside) in menu do
    if !inside then
      excluded := excluded + 1
      unless compareAll do continue
    let some key := JointWitnesses.readKey cfg p.state e.act e.after p.past
      | throw (IO.userError "reader failed on enabled bounded-search action")
    let family := Families.code (Families.classify cfg p.state e.act e.after p.past)
    edges := edges.push (e, ⟨actionCode e.act, key, family, inside⟩)
  return ⟨edges, excluded, mapped - start, (← IO.monoNanosNow) - mapped⟩

def signature (p : Probe) : List EdgeRead :=
  (p.edges.toList.map Prod.snd).mergeSort fun a b =>
    a.action.1 < b.action.1 ||
      (a.action.1 == b.action.1 && compare a.action.2 b.action.2 != .gt)

def boundedWitness (d : Deployment) (p : FramePath) : String :=
  let oneLine (s : String) := s.replace "\n" " "
  s!"{p.codes.head!}\t{p.hits.length}\t{oneLine (scheduleText d p.hits)}\t\
    {oneLine (reprStr (deliveryChoices p.hits))}\t{oneLine (reprStr p.codes.reverse)}\n"

def exhaust (b : Bounds) : IO Unit := do
  let d := b.deployment
  IO.println s!"bounds: voters={d.voters} nodes={d.nodes} log={b.maxLog} term={b.maxTerm} \
    copies={b.maxCopies} network={repr b.maxNetwork} palette={b.palette.name} budget={repr b.stepBudget}"
  IO.println "Bounded frame-merge search; equality of keys has not been proved to imply equality of labels."
  IO.println "Action palette:"
  for (line, i) in palette.zipIdx do
    if b.palette != .core || (i != 2 && i != 3) then IO.println s!"  {line}"
  if b.palette == .retirement then
    IO.println "  singleton actor configuration, optionally signed/flushed to one or all eligible peers (+ optional trailing signature)"
    IO.println "  confirm retirement (each eligible retiree or all); bare, signed, two signatures, or signed with flush to retirees"
  (← IO.getStdout).flush
  let start ← IO.monoNanosNow
  let initial : FramePath := ⟨d.initial, [], [], []⟩
  unless b.allows initial.state do throw (IO.userError "initial state is outside the selected bounds")
  let mut seen : Std.HashMap FrameKey Nat := ({} : Std.HashMap FrameKey Nat).insert
    (frameKey d initial.state []) 0
  let mut frames := #[initial]
  let mut signatures : Std.HashMap Nat (List EdgeRead) := {}
  let mut witnesses : Std.HashMap Key FramePath := {}
  let mut families := {}
  let mut depthCounts := #[1]
  let mut head := 0
  let mut steps := 0
  let mut excluded := 0
  let mut pairs := 0
  let mut checkedEdges := 0
  let mut menuNs := 0
  let mut readerNs := 0
  let mut frameNs := 0
  let mut compareNs := 0
  while head < frames.size do
    let p := frames[head]!
    let depth := p.hits.length + 1
    let reads ← probe b p false
    excluded := excluded + reads.excluded
    menuNs := menuNs + reads.menuNs
    readerNs := readerNs + reads.readerNs
    let mut complete := true
    for (e, row) in reads.edges do
      if b.stepBudget.any (· ≤ steps) then
        complete := false
        break
      steps := steps + 1
      let next := p.advance e row.key
      unless witnesses.contains row.key do
        witnesses := witnesses.insert row.key next
      families := insertGroup families row.family row.key
      let tick ← IO.monoNanosNow
      let k := frameKey d next.state next.past
      let existing := seen[k]?
      frameNs := frameNs + (← IO.monoNanosNow) - tick
      if let some i := existing then
        let tick ← IO.monoNanosNow
        let old ← if let some cached := signatures[i]? then pure cached else do
          pure (signature (← probe b frames[i]! true))
        signatures := signatures.insert i old
        let new := signature (← probe b next true)
        pairs := pairs + 1
        checkedEdges := checkedEdges + new.length
        unless old == new do
          IO.println s!"Merge disagreement at pair {pairs}:\nold {repr old}\nnew {repr new}"
          for path in [frames[i]!, next] do
            IO.println (scheduleText d path.hits)
            IO.println s!"queue choices: {repr (deliveryChoices path.hits)}"
          throw (IO.userError "equal frame keys had different enabled action signatures")
        compareNs := compareNs + (← IO.monoNanosNow) - tick
      else
        seen := seen.insert k frames.size
        frames := frames.push next
        if depthCounts.size == depth then depthCounts := depthCounts.push 0
        depthCounts := depthCounts.modify depth (· + 1)
      if steps % 1000 == 0 then
        IO.println s!"progress: {steps} steps, {frames.size} frames, {frames.size - head} frontier, {witnesses.size} keys"
        (← IO.getStdout).flush
    if !complete then break
    head := head + 1
  let stop ← IO.monoNanosNow
  let ms := (stop - start) / 1000000
  IO.println s!"frames: {frames.size}; expanded: {head}; frontier: {frames.size - head}; fixpoint: {head == frames.size}"
  IO.println s!"frames by depth: {repr depthCounts}"
  IO.println s!"steps: {steps}; excluded by bounds: {excluded}; keys: {witnesses.size}; {ms} ms; {steps * 1000 / max 1 ms} steps/s"
  IO.println s!"merge self-check: {pairs} history pairs, {checkedEdges} enabled action pairs, 0 disagreements"
  IO.println s!"time ms: menus/bounds {menuNs / 1000000}, key+family {readerNs / 1000000}, \
    frame keys {frameNs / 1000000}, merge checks {compareNs / 1000000}"
  for (code, keys) in families.toList.mergeSort (fun a b => a.1 ≤ b.1) do
    IO.println s!"family: {code} {keys.size}"
  let rows := witnesses.toList.mergeSort fun a b => encode a.1 ≤ encode b.1
  IO.FS.writeFile b.out <| "key\tdepth\tschedule\tqueue_choices\tprefix_keys\n" ++
    String.join (rows.map fun (_, p) => boundedWitness d p)
  IO.println s!"wrote {b.out}"

end ConsensusCoverage.Explore

open ConsensusCoverage.Explore in
public def main (args : List String) : IO Unit := do
  if args == ["--help"] then IO.println (usage ++ "\n" ++ exhaustUsage)
  else if args.head? == some "--exhaust" then
    exhaust (← IO.ofExcept (boundOptions args.tail! {}))
  else do
    let opts ← IO.ofExcept (options args {})
    IO.println s!"{repr opts}"
    IO.println "Deployments (voters, deployed nodes):"
    for d in backgrounds opts do IO.println s!"  {repr d.voters}, {repr d.nodes}"
    IO.println "Action palette:"
    for line in palette do IO.println s!"  {line}"
    if opts.retirement then
      IO.println "  singleton actor configuration, optionally signed/flushed to one or all eligible peers (+ optional trailing signature)"
      IO.println "  confirm retirement (each eligible retiree or all); bare, signed, two signatures, or signed with flush to retirees"
    let start ← IO.monoMsNow
    let score ← search opts
    let stop ← IO.monoMsNow
    report opts score (stop - start)

end
