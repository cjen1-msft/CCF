module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersElectionCarried
import all ConsensusCoverage.HandReadersAFacts
import all ConsensusCoverage.HandReadersAElection
import all ConsensusCoverage.BackingRead
import all ConsensusCoverage.CommitKeys
import all ConsensusCoverage.CommitMonitor
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.GuardedDomain
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersElection.Pairs

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety
open ActionProfile SolvedWitnesses HandReadersA ReadersAtoms GuardedDomain
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxRecDepth 8192

abbrev Test := List Entry → Nat → Nat → Nat → List Entry → Nat → Bool

abbrev Vote := NodeID × Nat × List Entry × Nat

private def elections : List State → List Vote
  | t :: s :: h =>
    let here := s.nodes.flatMap fun (n,pre) => t.nodes.filterMap fun (m,post) =>
      if n == m && electionExact t s h n post.currentTerm pre.log pre.commitIndex then
        some (n,post.currentTerm,pre.log,pre.commitIndex)
      else none
    here ++ elections (s :: h)
  | _ => []

private def now (bootstrap : NodeID) (after : State) (hist : List State)
    (old : List (Nat × List Entry)) (p : Test) : Bool :=
  let votes := elections (after :: hist)
  let previous := elections hist
  after.nodes.any fun (n,st) =>
    CommitKeys.leader bootstrap (after :: hist) n st &&
    (List.range (st.log.length+1)).any fun i =>
      isSignatureAt st.log i && (termAt st.log i == st.currentTerm) &&
        votes.any (fun v => decide (st.currentTerm < v.2.1 ∧
          ¬ ((st.currentTerm,st.log.take i) ∈ old ∧ v ∈ previous))) &&
        (List.range (i+1)).any fun b =>
          CommitKeys.backed old st b &&
          CommitMonitor.quorum ((activeConfigurations st.log b).filter (·.index ≤ i))
            (CommitKeys.acknowledges (after :: hist) st.currentTerm (st.log.take i)) &&
          votes.any (fun (_,later,log,commit) =>
            decide (st.currentTerm < later) && p st.log st.currentTerm b i log commit)

def reader (p : Test) : Reader := fun cfg before act after past =>
  let hist := before :: past
  let old := CommitKeys.keys (cfg.min?.getD 0) hist
  (Election.reader cfg before act after past &&
    actorRead (fun _ pre _ post => Facts.any cfg hist fun l k b i =>
      decide (k < post.currentTerm ∧ (k,l.take i) ∈ old) && p l k b i pre.log pre.commitIndex)
      cfg before act after past) ||
  now (cfg.min?.getD 0) after hist old p

inductive Kind where | small | large | covered | uncovered | ahead | tied

def test (kind : Kind) : Test := fun l k b i log commit =>
  let eq := l.take (max b commit) == log.take (max b commit)
  let j := max commit (maxCommittableIndex log)
  match kind with
  | .small => decide (commit ≤ i)
  | .large => decide (b < commit)
  | .covered => eq && decide (i ≤ commit)
  | .uncovered => eq && decide (commit < i)
  | .ahead => eq && decide (commit < i ∧ k < termAt log j)
  | .tied => eq && decide (commit < i ∧ k = termAt log j ∧ i ≤ j)

private theorem mem_elections (v : Vote) : ∀ h, v ∈ elections h ↔ electedExact v.1 v.2.1 v.2.2.1 v.2.2.2 h
  | [] | [_] => by simp [elections,electedExact]
  | t :: s :: h => by
    obtain ⟨n,k,l,i⟩ := v
    rw [elections,List.mem_append,electedExact,Bool.or_eq_true,mem_elections _ (s :: h)]
    apply or_congr_left
    simp only [List.mem_flatMap,List.mem_filterMap,Prod.exists]
    constructor
    · rintro ⟨a,st,_,b,post,_,eq⟩
      split at eq
      next yes =>
        cases eq
        simp only [Bool.and_eq_true] at yes
        exact yes.2
      next => contradiction
    · intro yes
      obtain ⟨⟨st,m,rfl,rfl⟩,post,m',rfl⟩ := electionExact_mem yes
      exact ⟨n,st,m,n,post,m',by simp [yes]⟩

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)

abbrev Ticket (n : NodeID) (st : NodeState) (k b i : Nat) :=
  CommitStep (f.advance t) n st k b i ∧ Backed f st.log b k ∧
  ∃ node later log commit, Elected (f.advance t) node later log commit ∧ k < later ∧
    ¬ (Committed f k (st.log.take i) ∧ Elected f node later log commit)

abbrev Pair (l : List Entry) (k b i : Nat) (log : List Entry) (commit : Nat) :=
  (Carried.ElectedHere c ∧ log = c.pre.log ∧ commit = c.pre.commitIndex ∧
    CommitFacts f.logs l k b i ∧ Committed f k (l.take i) ∧ k < c.post.currentTerm) ∨
  (∃ n st node later, Ticket (f := f) (t := t) n st k b i ∧ l = st.log ∧
    Elected (f.advance t) node later log commit ∧ k < later)

abbrev Evidence (p : Test) := ∃ l k b i log commit, Pair c l k b i log commit ∧ p l k b i log commit

abbrev CommitSite (n : NodeID) (st : NodeState) (k b i : Nat) :=
  (reach% step_core_covered_pos[0,0]) f t c n st k b i

theorem ticket_iff {n st k b i} : CommitSite c n st k b i ↔ Ticket (f := f) (t := t) n st k b i := by
  constructor
  · rintro ⟨part,node,later,log,commit,gate,_,_,_,_,_,step,_,rfl,back,_⟩
    obtain ⟨_,e,lt,delta⟩ := gate
    exact ⟨step,back,node,later,log,commit,e,lt,fun h => delta ⟨h.1,h.2,lt⟩⟩
  · rintro ⟨step,back,node,later,log,commit,e,lt,delta⟩
    have key : Committed (f.advance t) k (st.log.take i) := .inr ⟨n,st,b,i,step,rfl,back⟩
    have pack := And.intro step (And.intro (rfl : st.log.take i = st.log.take i) back)
    exact ⟨_,node,later,log,commit,⟨key,e,lt,fun h => delta ⟨h.1,h.2.1⟩⟩,
      ⟨n,st,b,i,pack⟩,⟨st,b,i,pack⟩,⟨b,i,pack⟩,⟨i,pack⟩,pack,step,pack.2,rfl,back,key,lt,e⟩
end

theorem reader_iff (s : Step) (p : Test) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    reader p s.cfg s.before s.act s.after s.past = true ↔ Evidence s.context p := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  let hist := s.before :: s.past
  have election := Bool.eq_iff_iff.mp (Election.exactReader.eq_label s)
  rw [label_true,holds,sig_iff] at election
  change step_led_after_elected_after_inr _ _ c ↔ Election.reader s.cfg s.before s.act s.after s.past = true at election
  rw [Election.iff_election] at election
  have bef (v : Vote) : v ∈ elections hist ↔ Elected s.frame v.1 v.2.1 v.2.2.1 v.2.2.2 := by
    rw [mem_elections,electedExact_iff]
    change _ ↔ (StateCoverage.frame s.before s.past).logs.elected ..
    rw [StateCoverage.frame_logs,(Historical.logFacts_correct hist).elected]
  have aft (v : Vote) : v ∈ elections (s.after :: hist) ↔ Elected (s.frame.advance s.after) v.1 v.2.1 v.2.2.1 v.2.2.2 := by
    rw [mem_elections,electedExact_iff]
    change _ ↔ (StateCoverage.frame s.after hist).logs.elected ..
    rw [StateCoverage.frame_logs,(Historical.logFacts_correct (s.after :: hist)).elected]
  have prior (st : NodeState) (b : Nat) :
      CommitKeys.backed (CommitKeys.keys (s.cfg.min?.getD 0) hist) st b = true ↔ Backed s.frame st.log b st.currentTerm := by
    simp only [hist,CommitKeys.backed,CommitKeys.prior,Bool.or_eq_true,decide_eq_true_eq,List.any_eq_true,
      Prod.exists,CommitKeys.step_mem s]
    rfl
  have live (n : NodeID) (st : NodeState) (b i : Nat) :
      (n,st) ∈ s.after.nodes ∧ CommitKeys.leader Config.INITIAL_PRIMARY (s.after :: hist) n st = true ∧
      i ≤ st.log.length ∧ (isSignatureAt st.log i = true ∧ termAt st.log i = st.currentTerm) ∧ b ≤ i ∧
      CommitMonitor.quorum ((activeConfigurations st.log b).filter (·.index ≤ i))
        (CommitKeys.acknowledges (s.after :: hist) st.currentTerm (st.log.take i)) = true ↔
      CommitStep (s.frame.advance s.after) n st st.currentTerm b i := by
    rw [← BackingRead.step_at s]
    simp only [CommitKeys.leader_iff,CommitMonitor.quorum_iff,CommitKeys.acknowledges_iff,
      Historical.CommitStep,Historical.CanonNow,Historical.Now]
    constructor
    · rintro ⟨m,⟨role,led⟩,len,⟨signed,eq⟩,base,acks⟩
      exact ⟨⟨m,trivial,role,led⟩,base,len,signed,eq,acks⟩
    · rintro ⟨⟨m,_,role,led⟩,base,len,signed,eq,acks⟩
      exact ⟨m,⟨role,led⟩,len,⟨signed,eq⟩,base,acks⟩
  simp only [reader,Bool.or_eq_true,Bool.and_eq_true,← election,actorRead_at,Facts.any_iff,decide_eq_true_eq,
    CommitKeys.step_mem]
  change (_ ∧ _) ∨ now _ _ hist _ p = true ↔ _
  simp only [now,List.any_eq_true,Prod.exists,Bool.and_eq_true,decide_eq_true_eq,beq_iff_eq,List.mem_range,
    Nat.lt_succ_iff,CommitKeys.step_mem s,bef,aft]
  have backed := prior
  dsimp only [hist] at backed
  simp only [backed]
  constructor
  · rintro (⟨e,l,k,b,i,facts,⟨lt,old⟩,yes⟩ | ⟨n,st,m,led,i,len,⟨sig,trigger⟩,b,base,⟨back,acks⟩,node,later,log,commit,win,lt,yes⟩)
    · exact ⟨_,_,_,_,_,_,.inl ⟨e,rfl,rfl,facts,old,lt⟩,yes⟩
    · have step := (live n st b i).mp ⟨m,led,len,sig,base,acks⟩
      exact ⟨_,_,_,_,_,_,.inr ⟨n,st,node,later,⟨step,back,trigger⟩,rfl,win,lt⟩,yes⟩
  · rintro ⟨l,k,b,i,log,commit,origin,yes⟩
    rcases origin with ⟨e,rfl,rfl,facts,m,lt⟩ | ⟨n,st,node,later,⟨step,back,trigger⟩,rfl,win,lt⟩
    · exact .inl ⟨e,_,_,_,_,facts,⟨lt,m⟩,yes⟩
    · obtain rfl : st.currentTerm = k := step.1.2.1
      obtain ⟨m,led,len,sig,base,acks⟩ := (live n st b i).mpr step
      exact .inr ⟨n,st,m,led,i,len,⟨sig,trigger⟩,b,base,⟨back,acks⟩,node,later,log,commit,win,lt,yes⟩

end ConsensusCoverage.HandReadersElection.Pairs
