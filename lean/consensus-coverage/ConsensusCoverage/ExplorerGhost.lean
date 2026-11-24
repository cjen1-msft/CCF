module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

meta import Lean
public import ConsensusCoverage.JointWitnesses
public import ConsensusCoverage.Families
public import Consensus.Proofs.VoteFacts
import all ConsensusCoverage.GuardedQuestions
import all ConsensusCoverage.GuardedDomain
import all ConsensusCoverage.CommitMonitor
import all ConsensusCoverage.GrantFrontier
import all ConsensusCoverage.CommitKeys
import all ConsensusCoverage.ReducedQuestions
import all ConsensusCoverage.PairQuestions
import all Consensus.Proofs.SafetyInvariant

/-! The bounded explorer's finite log and vote ghost. The differential
explorer checks these executable updates against independent history readers;
this module does not assert the equivalence as a theorem. -/

namespace ConsensusCoverage.ExplorerGhost

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

public structure Ghost where
  seen : List (NodeID × Nat × List Entry) := []
  canonical : List (Nat × List Entry) := []
  committed : List (Nat × List Entry) := []
  elected : List (NodeID × Nat × List Entry × Nat) := []
  grants : List ((NodeID × NodeID × Nat) × (Nat × Nat)) := []
  votes : VoteFacts.Ghost := []
  deriving Inhabited

private def union [BEq α] (old new : List α) : List α :=
  new.foldl (fun xs x => if xs.contains x then xs else x :: xs) old

private def Ghost.led (g : Ghost) (bootstrap n k : Nat) : Bool :=
  (k == BOOTSTRAP_TERM && n == bootstrap) || g.elected.any fun (id, term, _, _) =>
    n == id && k == term

private def Ghost.terms (g : Ghost) (bootstrap n : Nat) : List Nat :=
  let terms := g.elected.filterMap fun (id, k, _, _) => if id == n then some k else none
  if n == bootstrap then BOOTSTRAP_TERM :: terms else terms

private def thresholdLE (x y : Nat × Nat) : Bool :=
  x.1 < y.1 || (x.1 == y.1 && x.2 ≤ y.2)

private def Ghost.granted (g : Ghost) (v c k : Nat) (r : RequestVoteRequest) : Bool :=
  (g.grants.lookup (v, c, k)).any fun min =>
    thresholdLE min (r.lastCommittableTerm, r.lastCommittableIndex)

private def extendGrants (g : Ghost) (before after : Model.State) :
    List ((NodeID × NodeID × Nat) × (Nat × Nat)) × Bool := Id.run do
  let mut grants := g.grants
  let mut fresh := false
  for (v, y) in after.nodes do
    let some c := y.votedFor | continue
    let some x := before.nodes.lookup v | continue
    let k := y.currentTerm
    if x.currentTerm ≤ k &&
        (v == c || g.seen.any fun (n, term, _) => n == c && term == k) then
      let minimum := GrantFrontier.minimum x k
      let key := (v, c, k)
      unless g.granted v c k minimum do
        grants := (key, (minimum.lastCommittableTerm, minimum.lastCommittableIndex)) ::
          grants.filter (·.1 != key)
        fresh := true
  return (grants, fresh)

private def elections (g : Ghost) (before after : Model.State) :
    List (NodeID × Nat × List Entry × Nat) :=
  after.nodes.filterMap fun (n, y) => do
    let k := y.currentTerm
    unless 3 ≤ k && (y.role == .primary || y.role == .none) do none
    let x ← before.nodes.lookup n
    unless x.commitIndex ≤ x.log.length &&
        (x.currentTerm < k || (x.currentTerm == k && x.role == .candidate)) &&
        decide (x.log.take (maxCommittableIndex x.log) <+: y.log) do none
    let request := LogFacts.requestAt k x.log x.commitIndex
    guard (CommitMonitor.quorum (activeConfigurations x.log x.commitIndex)
      (fun v => g.granted v n k request))
    return (n, k, x.log, x.commitIndex)

private def logDelta (g : Ghost) (bootstrap : NodeID) (after : Model.State) :
    Ghost × Bool × Bool × (Bool × Bool) := Id.run do
  let seen := union g.seen (after.nodes.map fun (n, st) => (n, st.currentTerm, st.log))
  let mut canonical := g.canonical
  let mut committed := g.committed
  let mut zero := false
  let mut prior := false
  for (n, st) in after.nodes do
    let term := st.currentTerm
    if st.role != .candidate && g.led bootstrap n term then
      canonical := union canonical [(term, st.log)]
      for i in [:st.log.length + 1] do
        if isSignatureAt st.log i && termAt st.log i == term then
          let part := st.log.take i
          let key := (term, part)
          unless g.committed.contains key do
            let ack (v : NodeID) := seen.any fun (id, k, log) =>
              id == v && k == term && decide (part <+: log)
            let quorum (base : Nat) :=
              CommitMonitor.quorum ((activeConfigurations st.log base).filter (·.index ≤ i)) ack
            let fromZero := quorum 0
            let fromPrior := !g.committed.isEmpty && (List.range (i + 1)).any fun base =>
              CommitKeys.prior g.committed st base && quorum base
            if fromZero || fromPrior then
              committed := union committed [key]
              zero := zero || fromZero
              prior := prior || fromPrior
  return ({g with seen, canonical, committed, votes := VoteFacts.advance g.votes after},
    seen.length != g.seen.length, canonical.length != g.canonical.length, (zero, prior))

@[expose] public def start (bootstrap : NodeID) (initial : Model.State) : Ghost :=
  (logDelta {} bootstrap initial).1

private structure GuardedInputs where
  ledBefore : List Nat
  ledAfter : List Nat
  seenBefore : List Observation
  seenAfter : List Observation
  canonicalBefore : Bool

meta section

open Lean Meta in
private def compileGhostGuards : MetaM Unit := do
  let f ← getConstInfo ``GuardedQuestions.readView
  lambdaTelescope f.value! fun args body => do
    let #[v, b] := args | throwError "unexpected guarded reader arguments"
    withLocalDeclD `ghost (mkConst ``GuardedInputs) fun g => do
      let actor := mkApp (mkConst ``GuardedDomain.View.actor) v
      let bootstrap := mkApp (mkConst ``GuardedDomain.View.bootstrap) v
      let st := mkConst ``Model.State
      let cons := mkApp (mkConst ``List.cons [.zero]) st
      let hist := mkApp2 cons (mkApp (mkConst ``GuardedDomain.View.before) v)
        (mkApp (mkConst ``GuardedDomain.View.past) v)
      let next := mkApp2 cons (mkApp (mkConst ``GuardedDomain.View.after) v) hist
      let post := mkApp (mkConst ``GuardedDomain.View.post) v
      let replace (e : Expr) : Option Expr := do
        let name ← e.getAppFn.constName?
        let field ←
          if name == ``GuardedDomain.ledTerms then
            if e.getAppArgs == #[bootstrap, hist, actor] then some ``GuardedInputs.ledBefore
            else if e.getAppArgs == #[bootstrap, next, actor] then some ``GuardedInputs.ledAfter
            else none
          else if name == ``GuardedDomain.observations then
            if e.getAppArgs == #[hist, actor] then some ``GuardedInputs.seenBefore
            else if e.getAppArgs == #[next, actor] then some ``GuardedInputs.seenAfter
            else none
          else if name == ``GuardedDomain.canonAt && e.getAppArgs ==
              #[bootstrap, mkApp (mkConst ``NodeState.currentTerm) post,
                mkApp (mkConst ``NodeState.log) post, hist] then some ``GuardedInputs.canonicalBefore
          else none
        return mkApp (mkConst field) g
      let compiled := body.replace replace
      if let some residual := compiled.find? (fun e =>
          e.isConst && #[``GuardedDomain.ledTerms, ``GuardedDomain.observations,
            ``GuardedDomain.canonAt, ``GuardedDomain.View.past].contains e.constName!) then
        throwError "unreplaced guarded-history expression: {residual}"
      let value ← mkLambdaFVars #[v, g, b] compiled
      addAndCompile <| .defnDecl {
        name := `ConsensusCoverage.ExplorerGhost.answerGuards
        levelParams := []
        type := ← inferType value
        value
        hints := .abbrev
        safety := .safe
      }

end

local elab "compile_ghost_guards" : command => Lean.Elab.Command.liftTermElabM compileGhostGuards
compile_ghost_guards

private def observations (g : Ghost) (n : NodeID) : List Observation :=
  g.seen.filterMap fun (id, k, l) => if id == n then some ⟨k, l⟩ else none

public structure Edge where
  ghost : Ghost
  key : JointWitnesses.Key
  family : String

@[expose] public def read (cfg : FullProfile.Configuration) (g : Ghost)
    (before after : Model.State) (act : Model.Action) : Option Edge := do
  let view ← GuardedDomain.ofAction cfg before after [] act
  let bootstrap := view.bootstrap
  let (grants, grant) := extendGrants g before after
  let vote := {g with grants}
  let elected := elections vote before after
  let (next, seen, canon, backing) :=
    logDelta {vote with elected := union g.elected elected} bootstrap after
  let input : GuardedInputs := ⟨g.terms bootstrap view.actor, next.terms bootstrap view.actor,
    observations g view.actor, observations next view.actor,
    g.canonical.contains (view.post.currentTerm, view.post.log)⟩
  let guards ← GuardedQuestions.covered.mapM (answerGuards view input)
  let commit := backing.1 || backing.2
  let rooted ← ActorLogRows.read? view commit .rooted_now_after_inl
  let post ← ActorLogRows.read? view commit .rooted_post_log_inl
  let fresh := ReducedQuestions.freshPayloads before after.network
  let stable := !grant && !commit
  let tag := EventSupport.actionTag act
  let family :=
    if SignedQuiet.test (some view) before after stable then .quiet
    else if tag == .nominateSuccessor && stable && !fresh.isEmpty then .freshNomination
    else if tag == .nominateSuccessor && commit && !grant && next.elected.isEmpty then .delayedNomination
    else Families.Family.open tag ⟨!fresh.isEmpty, view.changed, seen, grant, !elected.isEmpty, canon, commit⟩
  let row := FrontierRows.Row.ofPair (PairQuestions.label before after)
    (!g.committed.isEmpty) (!next.committed.isEmpty)
  let packed := ([row.zeroBefore, row.backedBefore, row.wonPrimary, row.zeroAfter,
    row.backedAfter, LeaderEffect.changedPrimary before after] ++
    ReducedQuestions.columns.map (ReducedQuestions.answerFrom fresh)).foldl
      (fun bits b => 2 * bits + b.toNat) 0
  return ⟨next, (packed, commit, rooted :: guards ++ [backing.1, backing.2, post]),
    Families.code family⟩

end ConsensusCoverage.ExplorerGhost
