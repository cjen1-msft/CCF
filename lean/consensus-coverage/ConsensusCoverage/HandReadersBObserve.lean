module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.HandReadersBSummary
import all ConsensusCoverage.HandReadersBSummary
import all ConsensusCoverage.HandReadersBGate
import all ConsensusCoverage.HandReadersBFactor
import all ConsensusCoverage.GuardedDomain
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
public meta import ConsensusCoverage.HandReadersBFactor

namespace ConsensusCoverage.HandReadersBObserve

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety
open ActionProfile HandReadersBGate GuardedDomain SolvedWitnesses

set_option maxRecDepth 8192

public inductive Kind where
  | appendOld | voteNew | voteOld | ballotNew | ballotOld
  | preNew | preOld | preBallotNew | preBallotOld
  | ackPrimary | ackOther | ackNew | ackOld | bump | stable
  | appendTag | voteTag | ballotTag | preTag | preBallotTag
  | grant | deny | inserted | previous
  | ackSame | ackOtherPeer | ackOldMax | ackReportedMax
  deriving DecidableEq

public def column : Kind → Classes.StepBranch
  | .appendOld => .appendEntriesRequest_summary_observe_bumping_inr
  | .voteNew => .voteRequest_summary_observe_bumping_inl
  | .voteOld => .voteRequest_summary_observe_bumping_inr
  | .ballotNew => .voteResponse_summary_observe_bumping_inl
  | .ballotOld => .voteResponse_summary_observe_bumping_inr
  | .preNew => .preVoteRequest_summary_observe_bumping_inl
  | .preOld => .preVoteRequest_summary_observe_bumping_inr
  | .preBallotNew => .preVoteResponse_summary_observe_bumping_inl
  | .preBallotOld => .preVoteResponse_summary_observe_bumping_inr
  | .ackPrimary => .observe_response_leader_pos
  | .ackOther => .observe_response_leader_neg
  | .ackNew => .observe_response_bump_pos
  | .ackOld => .observe_response_bump_neg
  | .bump => .observe_bumping_bump_pos
  | .stable => .observe_bumping_bump_neg
  | .appendTag => .observe_bumping_message_appendEntriesRequest
  | .voteTag => .observe_bumping_message_requestVoteRequest
  | .ballotTag => .observe_bumping_message_requestVoteResponse
  | .preTag => .observe_bumping_message_requestPreVoteRequest
  | .preBallotTag => .observe_bumping_message_requestPreVoteResponse
  | .grant => .voteRequest_summary_granted_pos
  | .deny => .voteRequest_summary_granted_neg
  | .inserted => .voteResponse_summary_mem_insert_inl
  | .previous => .voteResponse_summary_mem_insert_inr
  | .ackSame => .appendEntriesResponse_summary_same_pos
  | .ackOtherPeer => .appendEntriesResponse_summary_same_neg
  | .ackOldMax => .appendEntriesResponse_summary_max_eq_or_inl
  | .ackReportedMax => .appendEntriesResponse_summary_max_eq_or_inr

private def accepts (k : Kind) (self : NodeID) (st : NodeState) : Event → Bool
  | .internal _ => false
  | .receive src msg =>
    let peer := decide (src ∈ eligiblePeers st self)
    let newTerm := decide (st.currentTerm < msg.term)
    match msg with
    | .appendEntriesRequest _ => match k with
      | .appendOld | .stable => !newTerm | .bump => newTerm | .appendTag => true | _ => false
    | .requestVoteRequest q =>
      let observed := observeTerm st msg
      let granted := decide (q.term = observed.currentTerm ∧ voteLogUpToDate observed q ∧
        !observed.primaryKnown ∧ (observed.votedFor = none ∨ observed.votedFor = some src))
      match k with
      | .voteOld | .stable => !newTerm | .voteNew | .bump => newTerm | .voteTag => true
      | .grant => granted | .deny => !granted | _ => false
    | .requestPreVoteRequest _ => match k with
      | .preOld | .stable => !newTerm | .preNew | .bump => newTerm | .preTag => true | _ => false
    | .requestVoteResponse q =>
      let add := peer && st.role == .candidate && q.term == st.currentTerm && q.voteGranted
      match k with
      | .ballotOld | .stable => peer && !newTerm | .ballotNew | .bump => peer && newTerm
      | .ballotTag => peer | .inserted => add | .previous => add && decide st.votesGranted.Nonempty | _ => false
    | .requestPreVoteResponse _ => match k with
      | .preBallotOld | .stable => peer && !newTerm | .preBallotNew | .bump => peer && newTerm
      | .preBallotTag => peer | _ => false
    | .appendEntriesResponse q =>
      let primary := st.role == .primary
      let ok := peer && primary && q.success && q.term == st.currentTerm
      match k with
      | .ackPrimary => peer && primary | .ackOther => peer && !primary
      | .ackNew => peer && primary && newTerm | .ackOld => peer && primary && !newTerm
      | .ackSame | .ackOtherPeer => ok
      | .ackOldMax => ok && decide (q.lastLogIndex ≤ st.matchIndex src)
      | .ackReportedMax => ok && decide (st.matchIndex src ≤ q.lastLogIndex)
      | _ => false
    | .proposeRequestVoteRequest _ => false

public def answer (cfg : FullProfile.Configuration) (before : State) (act : Action)
    (after : State) (past : List State) (k : Kind) : Bool :=
  activeWith cfg before act after past (fun v => accepts k v.actor v.pre (ReadersAtoms.eventOf act))

open Lean Meta Elab Command

meta section
private def names : MetaM (Array (Name × Name)) := do
  let .inductInfo info ← getConstInfo ``Kind | throwError "expected reader enumeration"
  info.ctors.toArray.mapM fun k => do
    let b ← whnf (mkApp (mkConst ``column) (mkConst k))
    return (k, (`ConsensusCoverage.SolvedWitnesses).str ("step_" ++ b.constName!.getString!))

private def pureName (n : Name) := (`ConsensusCoverage.HandReadersBObserve.Pure).str n.getString!

private def compile : MetaM Unit := do
  for (_,n) in ←names do
    HandReadersBFactor.compile n
    let tail := HandReadersBFactor.factorName n
    lambdaTelescope (←getConstInfo tail).value! fun xs body => do
      let tr ← mkAppM ``Ctx.tr #[xs[3]!]
      let fields ← #[``LocalTransition.actor,``LocalTransition.pre,``LocalTransition.event].mapM fun field => mkAppM field #[tr]
      withLocalDeclD `actor (←inferType fields[0]!) fun actor => do
        withLocalDeclD `pre (←inferType fields[1]!) fun pre => do
          withLocalDeclD `event (←inferType fields[2]!) fun event => do
            let vars := #[actor,pre,event]
            let b := body.replace fun e => (fields.idxOf? e).map fun i => vars[i]!
            let pr ← mkLambdaFVars vars b
            unless !pr.hasFVar do throwError "{n} needs more than the local fields"
            addDecl (.defnDecl {
              name := pureName n, levelParams := [],type := ←inferType pr
              value := pr, hints := .abbrev, safety := .safe })
end

run_cmd liftTermElabM compile

private theorem higher (st : NodeState) (m : Node.Message) (h : Bumping m) :
    (st.currentTerm < m.term ∧ observeTerm st m = bumpedState st m.term) ↔ st.currentTerm < m.term :=
  ⟨And.left, fun lt => (observe_bumping st h).resolve_right (fun p => (Nat.not_le_of_lt lt) p.1)⟩

private theorem lower (st : NodeState) (m : Node.Message) (h : Bumping m) :
    (m.term ≤ st.currentTerm ∧ observeTerm st m = st) ↔ m.term ≤ st.currentTerm :=
  ⟨And.left, fun le => (observe_bumping st h).resolve_left (fun p => (Nat.not_lt_of_ge le) p.1)⟩

private theorem bumped (st : NodeState) (m : Node.Message) (lt : st.currentTerm < m.term) (h : Bumping m) :
    observeTerm st m = bumpedState st m.term := ((higher st m h).mpr lt).2

private theorem unchanged (st : NodeState) (m : Node.Message) (le : m.term ≤ st.currentTerm) (h : Bumping m) :
    observeTerm st m = st := ((lower st m h).mpr le).2

private meta def correctName (n : Name) := (`ConsensusCoverage.HandReadersBObserve.Local).str n.getString!

private def matchBound (k : Kind) (before : NodeState) (src : NodeID) (q : AppendEntriesResponse) : Prop :=
  match k with
  | .ackOldMax => q.lastLogIndex ≤ before.matchIndex src
  | .ackReportedMax => before.matchIndex src ≤ q.lastLogIndex
  | _ => True

private def allowedAck (k : Kind) (n : NodeID) (before : NodeState) (e : Event) : Prop :=
  ∃ src q, e = .receive src (.appendEntriesResponse q) ∧ src ∈ eligiblePeers before n ∧
    before.role = .primary ∧ q.success = true ∧ q.term = before.currentTerm ∧ matchBound k before src q

private theorem ackState (self src : NodeID) (st : NodeState) (q : AppendEntriesResponse)
    (leader : st.role = .primary) (term : q.term = st.currentTerm) :
    let mid := {st with matchIndex := CCF.Function.update st.matchIndex src (max (st.matchIndex src) q.lastLogIndex)}
    ((st.role = .primary → q.term ≤ st.currentTerm) ∧ observeTerm st (.appendEntriesResponse q) = st) ∧
    (¬(st.role != .primary) = true) ∧ Advance self mid mid ∧
    (∀ e ∈ ([] : List Model.Envelope), e.source = self ∧ e.payload = .proposeRequestVoteRequest mid.currentTerm) ∧
    (∀ a : NodeState, a.role = st.role → a.currentTerm = st.currentTerm → a.log = st.log →
      a.commitIndex = st.commitIndex → a.votedFor = st.votedFor → a.votesGranted = st.votesGranted →
      a.matchIndex = st.matchIndex → Summary self st (.receive src (.appendEntriesResponse q)) a []) ∧
    mid.role ≠ .candidate := by
  have kept := (observe_response st q).resolve_left (fun h => (Nat.not_lt_of_ge (Nat.le_of_eq term)) h.2.1)
  exact ⟨kept, by simp [leader], .inl rfl, by simp, fun _ a b c d e f g =>
    quiet_summary a b c d e f g no_bumping_sends (by simp), by simp [leader]⟩

private meta def isAck (k : Name) := ["ackSame","ackOtherPeer","ackOldMax","ackReportedMax"].contains k.getString!

set_option maxHeartbeats 1200000 in
run_cmd
  for (k,n) in ←liftTermElabM names do
    let ack := isAck k
    let k := mkIdent k
    let tail := mkIdent (pureName n)
    let law := mkIdent (correctName n)
    if ack then
      elabCommand (←`(set_option linter.unusedSimpArgs false in
        theorem $law (n : NodeID) (st : NodeState) (e : Event) :
            $tail n st e ↔ accepts $k n st e = true := by
          refine Iff.trans (b := allowedAck $k n st e) ?_ ?_
          · delta $tail
            constructor
            · rintro ⟨a,b,src,q,caller,passed,_,_,_,leader,success,term,_,_,_,_,_,_,_,_,rest⟩
              obtain ⟨v,⟨ha,hb,hv⟩,m,ev,_,hm⟩ := caller
              subst a; subst b; subst v; subst m
              refine ⟨src,q,ev,by simpa using passed,by simpa using leader,success,term,?_⟩
              first | exact True.intro | (have eq := rest.2.2.2.2.2.1; simp only [matchBound]; omega)
            · rintro ⟨src,q,he,peer,leader,success,term,bound⟩
              subst e
              obtain ⟨kept,notOther,adv,empty,quiet,nc⟩ := ackState n src st q leader term
              have passed : ¬(True ∧ ¬src ∈ eligiblePeers st n) := fun h => h.2 peer
              refine ⟨n,st,src,q,⟨_,⟨rfl,rfl,rfl⟩,_,rfl,rfl,rfl⟩,passed,kept,kept.1,kept.2,
                notOther,success,term,_,[],⟨adv,empty⟩,adv,empty,leader,leader,rfl,?_⟩
              first | exact ⟨quiet,nc⟩ | exact ⟨src+1,Nat.succ_ne_self _,quiet,nc⟩
                    | exact ⟨passed,quiet,⟨adv,empty⟩,adv,empty,Nat.max_eq_left bound,quiet,nc⟩
                    | exact ⟨passed,quiet,⟨adv,empty⟩,adv,empty,Nat.max_eq_right bound,quiet,nc⟩
          · cases e with
            | internal => simp [allowedAck,accepts]
            | receive src m => cases m <;> simp [allowedAck,accepts,matchBound,and_assoc]))
      continue
    elabCommand (←`(set_option linter.unusedSimpArgs false in
      theorem $law (n : NodeID) (st : NodeState) (e : Event) :
          $tail n st e ↔ accepts $k n st e = true := by
        delta $tail
        cases e with
        | internal i => simp [accepts, and_assoc]
        | receive src m =>
          cases m <;> simp [accepts, and_assoc, or_and_right, exists_or, Bool.and_eq_true,
            CCF.Finset.mem_insert, CCF.Finset.Nonempty]
          all_goals first
            | exact fun h => bumped _ _ h trivial
            | exact fun h => unchanged _ _ h trivial
            | (rename_i req
               have branches := observe_bumping st (message := .requestVoteRequest req) trivial
               rcases branches with ⟨lt,eq⟩ | ⟨le,eq⟩
               all_goals simp only [Node.Message.term] at *
               all_goals simp [eq, *, Nat.not_lt_of_ge, Nat.not_le_of_lt, bumpedState, Bumping] <;> grind)
            | grind [bumped, unchanged, Bumping, Node.Message.term]))

private theorem recorded (s : Step) (k : Kind)
    (h : letI : Config.InitialConfiguration := ⟨s.cfg⟩
      sig s.context (column k) ↔ Source s.context ∧ accepts k s.context.actor s.context.pre s.context.event = true) :
    label s (.step (column k)) = answer s.cfg s.before s.act s.after s.past k := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  obtain ⟨v, made, ok⟩ := ofAction_matches s
  have pre : v.pre = s.context.pre := congrArg View.pre ok.1
  have actor : v.actor = s.context.actor := congrArg View.actor ok.1
  have event : ReadersAtoms.eventOf s.act = s.context.event := by
    rw [← (s.context_eq s.context).mpr rfl]
    change ReadersAtoms.eventOf (ActionContext.encode s.context.tr.actor s.context.tr.event) = s.context.tr.event
    cases s.context.tr.event <;> rfl
  apply Bool.eq_iff_iff.mpr
  rw [label_true,holds,sig_iff,h,answer,activeWith_eq,made,Option.any_some,Bool.and_eq_true,live,pre,actor,event,and_comm]

run_cmd
  let mut proofs := #[]
  for (k,n) in ←liftTermElabM names do
    let spec := mkIdent (HandReadersBFactor.iffName n)
    let localSpec := mkIdent (correctName n)
    let closed := mkIdent ((`ConsensusCoverage.HandReadersBObserve.Closed).str k.getString!)
    let k := mkIdent k
    elabCommand (←`(theorem $closed (s : Step) :
        label s (.step (column $k)) = answer s.cfg s.before s.act s.after s.past $k := by
      letI : Config.InitialConfiguration := ⟨s.cfg⟩
      apply recorded
      exact ($spec _ _ _ (quiet s)).trans (and_congr_right fun _ =>
        $localSpec s.context.actor s.context.pre s.context.event)))
    proofs := proofs.push closed
  let name := mkIdent `exact_answer
  elabCommand (←`(public theorem $name (s : Step) (k : Kind) :
      label s (.step (column k)) = answer s.cfg s.before s.act s.after s.past k := by
    cases k <;> first $[| exact $proofs s]*))

end ConsensusCoverage.HandReadersBObserve
