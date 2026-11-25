module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ClauseMatchAck
import all ConsensusCoverage.AckAdvance
import all ConsensusCoverage.ClauseExactTables
import all ConsensusCoverage.ClauseMatchAck
import all ConsensusCoverage.ClauseQuestions
import all ConsensusCoverage.ExploredWitnesses
import all ConsensusCoverage.FrontierRows
import all ConsensusCoverage.FrontierWitnesses
import all ConsensusCoverage.JointWitnesses
import all ConsensusCoverage.ReadersCorpus
import all ConsensusCoverage.SolvedWitnesses
import all ConsensusCoverage.StateCoverage
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.ClauseMatchAckBounds

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety
open CCF CCF.MultiNodeTransitionSystem
open ClauseQuestions ClauseExactTables ClauseMatchAck ActionProfile

set_option maxHeartbeats 0
set_option maxRecDepth 8192

private theorem same_observations (s : Step) (hit : label s (.step ack) = true) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    let c := s.context
    c.pre.role = .primary ∧ c.post.currentTerm = c.pre.currentTerm ∧ c.post.log = c.pre.log := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  obtain ⟨peer,_,_,_,_,_,_,⟨leader,term⟩,_,_,⟨r,event,ok,stamp,_⟩,_⟩ :=
    (SolvedWitnesses.sig_iff c ack).mp ((label_true s _).mp hit)
  refine ⟨leader,term,?_⟩
  by_cases allowed : peer ∈ eligiblePeers c.pre c.actor
  · exact (AckAdvance.actual_advance c event ⟨leader,ok,stamp,allowed⟩).log
  · have ran := c.tr.ran
    change ((Model.Node.step (Capabilities.record c.actor) c.actor c.pre c.event).run {}) = _ at ran
    rw [event] at ran
    simp [Model.Node.step,receive,allowed] at ran
    exact congrArg NodeState.log ran.1.symm

/-- A same-term primary ACK can advance the physical commit index. It cannot
create the *first backing*: it adds no observation or election. A positive-base
certificate already has earlier backing; every zero-base certificate can be
replayed on the same pre-step log. -/
public theorem ack_old_backing (s : Step) (hit : label s (.step .match_ack_matchIndex_inr) = true)
    (after : (endpoints s).2.2 = true) : (endpoints s).1.2 = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  obtain ⟨primary,term,log⟩ := same_observations s hit
  have obs : observe c.post = observe c.pre := by
    change Observation.mk _ _ = Observation.mk _ _
    exact (congrArg (fun k => Observation.mk k c.post.log) term).trans
      (congrArg (Observation.mk c.pre.currentTerm) log)
  have seen {n o} (h : Seen (s.frame.advance s.after) n o) : Seen s.frame n o := by
    rcases c.seen_after h with old | ⟨rfl,rfl⟩
    · exact old
    · rw [obs]
      exact c.inv.observed _ _ c.pre_now
  have led {n k} (h : Led (s.frame.advance s.after) n k) : Led s.frame n k := by
    obtain old | ⟨_,_,e⟩ := c.led_after h
    · exact old
    · obtain ⟨_,_,_,lt | ⟨_,cand⟩,same,_⟩ := c.electStep e
      · have same' : c.post.currentTerm = c.pre.currentTerm := term
        omega
      · rw [primary] at cand
        contradiction
  have post := (StateCoverage.backed_iff _ c.inv_step).mp
    ((StateCoverage.read_iff s.after (s.before :: s.past) c.inv_step).2.mp after)
  apply (StateCoverage.read_iff s.before s.past c.inv).2.mpr
  apply (StateCoverage.backed_iff _ c.inv).mpr
  refine ⟨List.ne_nil_of_mem c.pre_now,?_⟩
  obtain ⟨_, k,p,old | ⟨n,st,base,i,cert,rfl,backing⟩⟩ := post
  · exact ⟨k,p,old⟩
  rcases backing with rfl | ⟨a,l,past,_⟩
  · obtain ⟨⟨mem,stamp,nc,leader⟩,baseLe,bound,signed,atI,voters,quorum,observed⟩ := cert
    obtain ⟨pre,old,teq,logs,role⟩ : ∃ pre, Now s.frame n pre ∧ pre.currentTerm = k ∧
        pre.log = st.log ∧ pre.role ≠ .candidate := by
      rcases c.now_after mem with ⟨rfl,rfl⟩ | ⟨_,prior⟩
      · exact ⟨c.pre,c.pre_now,term.symm.trans stamp,log.symm,by rw [primary]; decide⟩
      · exact ⟨st,prior,stamp,rfl,nc⟩
    refine ⟨k,pre.log.take i,FrontierRows.fresh_commit (n := n) ?_⟩
    refine ⟨⟨old,teq,role,led leader⟩,baseLe,logs ▸ bound,logs ▸ signed,logs ▸ atI,
      voters,logs ▸ quorum,?_⟩
    intro v hv
    obtain ⟨l,o,sub⟩ := observed v hv
    exact ⟨l,seen (o := ⟨k,l⟩) o,logs ▸ sub⟩
  · exact ⟨a,l,past⟩

private abbrev z : StateCoverage.Row := (true,false)
private abbrev b : StateCoverage.Row := (true,true)
private abbrev p : StateCoverage.Row := (false,true)
private def entry (from_ to_ : StateCoverage.Row) (left right : Bool) : RestrictedProfile :=
  ⟨from_,pack left right false,to_⟩

public def witnessed : List RestrictedProfile :=
  StateCoverage.activeTable.flatMap fiberRows ++
    [entry z p false false, entry z b false false, entry b p false false,
     entry b p false true, entry b p true true]

/-- Only these two retained-without-reply rows are not classified by the
endpoint, election, peer-presence and first-backing arguments. -/
public def remaining : List RestrictedProfile := [entry z b true false, entry b p true false]

public theorem counts : witnessed.length = 20 ∧ remaining.length = 2 ∧ (witnessed ++ remaining).Nodup :=
  by decide +kernel

open ExploredWitnesses in
private def bothRun : FrontierRows.Run := {ReadersCorpus.threeTerms with
  schedule := ReadersCorpus.threeTerms.schedule.take 14 ++
    [deliver 1 0,deliver 1 0,deliver 0 1,deliver 0 1,deliver 2 1]}

private def bothStep : Option Step := do
  let r ← JointWitnesses.recordedAt bothRun (by unfold FrontierRows.Run.valid; decide) []
  return (← r.getLast?).val

private def offSteps := bothStep.toList ++ [(0,0),(1,0),(46,1),(110,11)].filterMap
  fun (i,j) => ReadersCorpus.stepAt i j

private theorem off_checked :
    [entry z p false false, entry z b false false, entry b p false false,
     entry b p false true, entry b p true true].all (offSteps.map realRead).contains = true := by decide +kernel

public theorem witnessed_realized {r : RestrictedProfile} (mem : r ∈ witnessed) :
    ∃ s : Step, restrictedLabel (nonTrunk .match_ack) s = r := by
  rcases List.mem_append.mp mem with diag | off
  · obtain ⟨e,he,member⟩ := List.mem_flatMap.mp diag
    obtain ⟨s,_,eq⟩ := (diagonal_exact e he r).mp member
    exact ⟨s,eq⟩
  · obtain ⟨s,_,eq⟩ := List.mem_map.mp (List.contains_iff_mem.mp (List.all_eq_true.mp off_checked _ off))
    exact ⟨s,(realRead_eq s).symm.trans eq⟩

private theorem shape (s : Step) :
    bits s = pack (label s (.step kept)) (label s (.step ack)) (label s (.step win)) := by
  have no (k : Classes.StepBranch) (h : ReadersRefuted.read? k = some false) := ReadersRefuted.read?_correct s h
  simp only [bits, restrictedLabel, columns, List.map_cons, List.map_nil, pack, (semantics s).1,
    no .facts_advance_inr_2 (by decide +kernel), no .facts_role_inl (by decide +kernel),
    no .facts_role_inr (by decide +kernel)]

public theorem upper (s : Step) : restrictedLabel (nonTrunk .match_ack) s ∈ witnessed ++ remaining := by
  let ep := endpoints s
  have mem := (endpoint_exact ep).mpr ⟨s,rfl⟩
  have bitsOk := ClauseMatchAck.complete s
  have winOk := win_diagonal s
  have first := first_no_zero s
  have old := ack_old_backing s
  change label s (.step win) = true → ep.1 = ep.2 at winOk
  change label s (.step ack) = true → ep.2.2 = true → ep.1.2 = true at old
  change ep = _ → _ at first
  change (⟨ep.1,bits s,ep.2⟩ : RestrictedProfile) ∈ witnessed ++ remaining
  rw [shape] at bitsOk first ⊢
  generalize ep = e at *
  generalize label s (.step kept) = l at *
  generalize label s (.step ack) = r at *
  generalize label s (.step win) = w at *
  exact (by decide +kernel : ∀ e ∈ endpointRows, ∀ l r w : Bool,
    pack l r w ∈ patterns → (w = true → e.1 = e.2) →
    (e = (z,p) → pack l r w = List.replicate 7 false) →
    (r = true → e.2.2 = true → e.1.2 = true) →
    RestrictedProfile.mk e.1 (pack l r w) e.2 ∈ witnessed ++ remaining) e mem l r w bitsOk winOk first old

end ConsensusCoverage.ClauseMatchAckBounds
