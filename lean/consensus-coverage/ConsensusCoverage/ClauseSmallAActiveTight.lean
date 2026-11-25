module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ClauseSmallAActive
import all ConsensusCoverage.ClauseExactTables
import all ConsensusCoverage.ClauseQuestions
import all ConsensusCoverage.CaseWitnesses
import all ConsensusCoverage.ClauseSmallA
import all ConsensusCoverage.ClauseSmallAActive
import all ConsensusCoverage.FrontierWitnesses
import all ConsensusCoverage.FullProfile
import all ConsensusCoverage.Historical
import all ConsensusCoverage.JointWitnesses
import all ConsensusCoverage.LeaderCoverage
import all ConsensusCoverage.NoBackingWitness
import all ConsensusCoverage.ReadersTotal
import all ConsensusCoverage.SolvedWitnesses
import all ConsensusCoverage.StateCoverage
import all Consensus.Proofs.SafetyInvariant
public meta import ConsensusCoverage.ReachPath

namespace ConsensusCoverage.ClauseSmallA.ActiveTight

open CCF CCF.MultiNodeTransitionSystem
open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety
open ActionProfile ClauseExactTables ClauseQuestions SolvedWitnesses Active

set_option maxHeartbeats 2000000
set_option maxRecDepth 8192

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)

private theorem received_of_inactive_pre (none : c.pre.role = .none) (term : 2 ≤ c.pre.currentTerm)
    (fire : Fired c) : Received c := by
  have ran := c.tr.ran
  change ((Model.Node.step (Capabilities.record c.actor) c.actor c.pre c.event).run {}) =
    some (c.post,c.tr.outputs) at ran
  have unchanged (h : c.post = c.pre ∧ c.sent = []) : False := by
    rcases h with ⟨same,empty⟩
    rcases fire with engaged | ⟨e,mem,_⟩
    · exact engaged.1 ((congrArg NodeState.role same).trans none)
    · rw [empty] at mem
      contradiction
  have pureFalse (h : ((pure c.pre : NodeEffect NodeState).run {}) = some (c.post,c.tr.outputs)) :
      False := by
    change some (c.pre, ({} : Outputs NodeID Message Notification)) = _ at h
    obtain ⟨state, out⟩ := Prod.mk.inj (Option.some.inj h)
    exact unchanged ⟨state.symm,congrArg Outputs.outgoing out.symm⟩
  cases ev : c.event with
  | internal i =>
    rw [ev] at ran
    have notFresh : ¬ c.pre.isFresh := fun h => by have eq := h.2.1; omega
    cases i with
    | append => simp [Model.Node.step,act,appendBatch,none,guard,Bind.bind,StateT.bind,
        StateT.run,failure,StateT.failure] at ran
    | sendEntries => simp [Model.Node.step,act,sendEntries,none,guard,Bind.bind,StateT.bind,
        StateT.run,failure,StateT.failure] at ran
    | timeout k =>
      cases k <;> simp [Model.Node.step,act,startElection,checkQuorum,canStartElection,none,
        guard,Bind.bind,StateT.bind,StateT.run,failure,StateT.failure] at ran
    | nominateSuccessor => simp [Model.Node.step,act,nominateSuccessor,none,guard,Bind.bind,
        StateT.bind,StateT.run,failure,StateT.failure] at ran
    | initAsBackup => simp [Model.Node.step,act,initAsBackup,notFresh,guard,Bind.bind,StateT.bind,
        StateT.run,failure,StateT.failure] at ran
  | receive src m =>
    by_cases bump : Bumping m
    · rcases observe_bumping c.pre bump with ⟨lt,equal⟩ | ⟨bound,equal⟩
      · refine ⟨src,m,ev,bump,?_⟩
        have same : observeTerm (bumpedState c.pre m.term) m = bumpedState c.pre m.term := by
          cases m <;> simp_all [Bumping,observeTerm,updateTerm,bumpedState,becomeAwareOfNewTerm]
        have peers : eligiblePeers (bumpedState c.pre m.term) c.actor = eligiblePeers c.pre c.actor := rfl
        have accepted (z : NodeState) : ((Node.step (Capabilities.record c.actor) c.actor z
            (.receive src m)).run {}) = some (c.post,c.tr.outputs) → z.currentTerm ≤ c.post.currentTerm := by
          intro executed
          obtain ⟨_,_,result⟩ := summary c.actor z (.receive src m) _ _ _ executed
          exact Summary.term_le result
        rw [ev] at ran
        apply accepted (bumpedState c.pre m.term)
        cases m <;> simp only [Bumping] at bump <;> try contradiction
        all_goals
          first
          | simpa only [Node.step,receive,peers,equal,same,false_and,↓reduceIte, Bool.false_eq_true]
              using ran
          | by_cases known : src ∈ eligiblePeers c.pre c.actor
            · simpa only [Node.step,receive,peers,equal,same,known,not_true_eq_false,and_false,
                ↓reduceIte] using ran
            · exact (pureFalse (by simpa [Node.step,receive,known] using ran)).elim
      · exact ⟨src,m,ev,bump,Nat.le_trans bound c.term_le⟩
    · rw [ev] at ran
      cases m <;> simp only [Bumping] at bump <;> try contradiction
      · apply (pureFalse ?_).elim
        simpa [Model.Node.step,receive,observeTerm,none,handleAppendEntriesResponse] using ran
      · apply (pureFalse ?_).elim
        simpa [Model.Node.step,receive,observeTerm,handleProposeRequestVoteRequest,
          canStartElection,none] using ran

private theorem pre_floor_split (h : sig c cc) : sig c bb ∨ sig c dd := by
  rcases h with h | h
  all_goals
    obtain ⟨site, _, bound, fire, le⟩ := h
    by_cases engaged : Engaged c.pre
    · left
      first | exact .inl ⟨site,engaged,fire,le⟩ | exact .inr ⟨site,engaged,fire,le⟩
    · right
      have none : c.pre.role = .none := by
        apply Classical.not_not.mp
        intro different
        exact engaged ⟨different, fun eq => by omega⟩
      apply receive_arm c _ (received_of_inactive_pre c none bound fire) fire
      first | exact .inl site | exact .inr site

private abbrev FloorSites (n : NodeID) (k : Nat) :=
  (reach% step_leader_floor_led_inl[0]) f t c n k ∨
  (reach% step_leader_floor_led_inl[1]) f t c n k ∨
  (reach% step_leader_floor_led_inl[2]) f t c n k ∨
  (reach% step_leader_floor_led_inl[3]) f t c n k ∨
  (reach% step_leader_floor_led_inl[4]) f t c n k ∨
  (reach% step_leader_floor_led_inl[5]) f t c n k ∨
  (reach% step_leader_floor_led_inl[6]) f t c n k ∨
  (reach% step_leader_floor_led_inl[7]) f t c n k ∨
  (reach% step_leader_floor_led_inl[8]) f t c n k

private abbrev NewCompletenessPair (k : Nat) :=
  ∃ p n later l i, Committed (f.advance t) k p ∧ Elected (f.advance t) n later l i ∧ k < later ∧
    ¬ (Committed f k p ∧ Elected f n later l i ∧ k < later)

private theorem floor_sites {n k} (h : FloorSites c n k) :
    Installed c ∨ @NewCompletenessPair _ f t k := by
  rcases h with a | b | d | e | g | i | j | l | m
  · reach_unfold step_leader_floor_led_inl[0] at a
    rcases a with a | a
    all_goals
      obtain ⟨_,_,_,entries,ev,pos,sig_,_,_,_,term,_,_⟩ := a
      exact .inl ⟨entries,ev,pos,sig_,term⟩
  · reach_unfold step_leader_floor_led_inl[1] at b
    rcases b with b | b
    all_goals
      obtain ⟨_,_,_,entries,ev,pos,sig_,_,_,_,term,_,_⟩ := b
      exact .inl ⟨entries,ev,pos,sig_,term⟩
  · reach_unfold step_leader_floor_led_inl[2] at d
    exact .inl d.2.2.2.1
  · reach_unfold step_leader_floor_led_inl[3] at e
    exact .inl e.2.2.2.1
  · reach_unfold step_leader_floor_led_inl[4] at g
    obtain ⟨_,entries,ev,pos,sig_,_,_,_,term,_,_⟩ := g
    exact .inl ⟨entries,ev,pos,sig_,term⟩
  · reach_unfold step_leader_floor_led_inl[5] at i
    obtain ⟨_,entries,ev,pos,sig_,_,_,_,term,_,_⟩ := i
    exact .inl ⟨entries,ev,pos,sig_,term⟩
  · reach_unfold step_leader_floor_led_inl[6] at j
    rcases j with inst | j | j | j | j | j
    · obtain ⟨_,entries,ev,pos,sig_,_,_,_,term,_,_⟩ := inst
      exact .inl ⟨entries,ev,pos,sig_,term⟩
    all_goals
      obtain ⟨_,_,_,source,_⟩ := j
      reach_unfold step_leader_floor_led_inl[6,1] at source
      obtain ⟨p,node,later,log,commit,basis,_⟩ := source
      exact .inr ⟨p,node,later,log,commit,basis⟩
  · reach_unfold step_leader_floor_led_inl[7] at l
    obtain ⟨_,entries,ev,pos,sig_,_,_,_,term,_,_⟩ := l
    exact .inl ⟨entries,ev,pos,sig_,term⟩
  · reach_unfold step_leader_floor_led_inl[8] at m
    obtain ⟨_,entries,ev,pos,sig_,_,_,_,term,_,_⟩ := m
    exact .inl ⟨entries,ev,pos,sig_,term⟩

local macro "provideFloor " h:term : tactic => `(tactic|
  repeat' first | exact $h | exact Or.inl $h | apply Or.inr)

private theorem floor_source_class (h : sig c ff ∨ sig c gg) :
    ∃ n k, FloorSites c n k := by
    rcases h with h | h
    · rcases h with a | a | a | a | a | a | a | a | a
      all_goals exact ⟨_,_,by provideFloor a.1⟩
    · rcases h with a | a | a | a | a | a | a | a | a
      all_goals
        obtain ⟨n,k,site,_⟩ := a
        exact ⟨n,k,by provideFloor site⟩

private theorem floor_source (h : sig c ff ∨ sig c gg) :
    Installed c ∨ ∃ k, @NewCompletenessPair _ f t k := by
  obtain ⟨n,k,site⟩ := floor_source_class c h
  exact (floor_sites c site).imp_right (fun h => ⟨k,h⟩)

theorem elected_floor_source (h : sig c gg) :
    Installed c ∨ ∃ k, 3 ≤ k ∧ @NewCompletenessPair _ f t k := by
  have sites : ∃ n k, FloorSites c n k ∧ ∃ l i, Elected f n k l i := by
    rcases h with a | a | a | a | a | a | a | a | a
    all_goals
      obtain ⟨n,k,site,won,_⟩ := a
      exact ⟨n,k,by provideFloor site,won⟩
  obtain ⟨n,k,site,l,i,won⟩ := sites
  exact (floor_sites c site).imp_right
    (fun h => ⟨k,(c.inv.electionCerts n k l i won).above,h⟩)

private theorem floor_backed (h : sig c ff ∨ sig c gg) :
    ∃ k p, Committed (f.advance t) k p := by
  rcases floor_source c h with ⟨l,ev,pos,sig_,_⟩ | ⟨k,p,_,_,_,_,com,_,_,_⟩
  · obtain ⟨_,_,_,term,p,old,_⟩ := c.snap_available ev pos sig_
    exact ⟨term,p,.inl old⟩
  · exact ⟨k,p,com⟩
end

private def tighter (bits : List Bool) : Bool :=
  !bits[2]! || bits[1]! || bits[3]!

private def floorOK (r : RestrictedProfile) : Bool :=
  !(r.bits[5]! || r.bits[6]!) || (r.post.2 && (r.pre.2 || r.post.1))

public def upperPatterns : List (List Bool) :=
  Active.upperPatterns.filter tighter

public def upperRows : List RestrictedProfile :=
  Active.upperRows.filter (fun r => tighter r.bits && floorOK r)

private theorem tighter_step (s : Step) : tighter (nonTrunkLabel .active s).bits = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  have spec (b : Classes.StepBranch) := (label_true s (.step b)).trans (sig_iff s.context b)
  have bound (yes : label s (.step cc) = true) :
      label s (.step bb) = true ∨ label s (.step dd) = true :=
    (pre_floor_split s.context ((spec cc).mp yes)).imp (spec bb).mpr (spec dd).mpr
  unfold tighter
  change (!(((nonTrunk .active).map (fun b => label s (.step b)))[2]!) ||
    ((nonTrunk .active).map (fun b => label s (.step b)))[1]! ||
    ((nonTrunk .active).map (fun b => label s (.step b)))[3]!) = true
  rw [show nonTrunk .active = _ from Active.columns]
  change (!label s (.step cc) || label s (.step bb) || label s (.step dd)) = true
  cases h : label s (.step cc) with
  | false => rfl
  | true =>
    rcases bound h with hit | hit <;> simp [hit]

public theorem patterns_upper (s : Step) : (nonTrunkLabel .active s).bits ∈ upperPatterns :=
  List.mem_filter.mpr ⟨Active.patterns_upper s,tighter_step s⟩

private theorem floors_after (s : Step)
    (h : label s (.step ff) = true ∨ label s (.step gg) = true) : (endpoints s).2.2 = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  have spec (b : Classes.StepBranch) := (label_true s (.step b)).trans (sig_iff s.context b)
  obtain ⟨k,p,committed⟩ := floor_backed c (h.imp (spec ff).mp (spec gg).mp)
  exact (StateCoverage.read_iff s.after (s.before :: s.past) c.inv_step).2.mpr
    ((StateCoverage.backed_iff _ c.inv_step).mpr ⟨List.ne_nil_of_mem c.post_now,k,p,committed⟩)

private theorem floor_no_leap (s : Step) (noBack : (endpoints s).1.2 = false)
    (noZero : (endpoints s).2.1 = false)
    (hit : label s (.step ff) = true ∨ label s (.step gg) = true) : False := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  have old : ∀ k p, ¬ Committed s.frame k p := by
    intro k p commit
    have yes := (StateCoverage.read_iff s.before s.past c.inv).2.mpr
      ((StateCoverage.backed_iff _ c.inv).mpr ⟨List.ne_nil_of_mem c.pre_now,k,p,commit⟩)
    exact Bool.noConfusion (noBack.symm.trans yes)
  have mono : ¬ LeaderCoverage.MultiNode s.nodes := fun multi =>
    Bool.noConfusion (noZero.symm.trans (LeaderCoverage.unbacked_keeps_zero s multi noBack))
  have spec (b : Classes.StepBranch) := (label_true s (.step b)).trans (sig_iff s.context b)
  rcases floor_source c (hit.imp (spec ff).mp (spec gg).mp) with
    ⟨l,ev,pos,sig_,_⟩ | ⟨k,p,v,later,l,i,commit,election,lt,_⟩
  · obtain ⟨_,_,_,term,p,committed,_⟩ := c.snap_available ev pos sig_
    exact old term p committed
  · change Committed (s.frame.advance s.after) k p at commit
    rcases commit with was | ⟨n,st,j,index,cert,_,backed⟩
    · exact old k p was
    · have now := cert.1.1
      have stamp := cert.1.2.1
      have electLed : Led (s.frame.advance s.after) v later := .inr ⟨l,i,election⟩
      have vIn : v ∈ s.nodes := by
        rcases c.elected_after election with earlier | next
        · rcases (Historical.logFacts_correct (s.before :: s.past)).elected v later l i |>.mp
            (by rwa [← StateCoverage.frame_logs]) with ⟨after,before,hist,sub,run⟩
          obtain ⟨_,value,_,hit,_,_⟩ := run
          have elem := List.mem_map_of_mem (f := Prod.fst) hit
          rw [NoBackingWitness.run_keys s.run after (sub.subset List.mem_cons_self)] at elem
          exact elem
        · have actor := (c.electStep next).1
          rw [actor, ← NoBackingWitness.run_keys (.step s.run s.ran) s.after List.mem_cons_self]
          exact List.mem_map_of_mem (f := Prod.fst) c.post_now
      have nIn : n ∈ s.nodes := by
        rw [← NoBackingWitness.run_keys (.step s.run s.ran) s.after List.mem_cons_self]
        exact List.mem_map_of_mem (f := Prod.fst) now
      have eq : n = v := Classical.not_not.mp (fun neq => mono ⟨n,nIn,v,vIn,neq⟩)
      rw [← eq] at electLed
      rcases (c.inv_step.led_cur n st later now electLed) with smaller | ⟨same,_⟩ <;> omega

private theorem floor_step (s : Step) : floorOK (nonTrunkLabel .active s) = true := by
  unfold floorOK nonTrunkLabel restrictedLabel
  change (!(((nonTrunk .active).map (fun b => label s (.step b)))[5]! ||
    ((nonTrunk .active).map (fun b => label s (.step b)))[6]!) ||
      ((endpoints s).2.2 && ((endpoints s).1.2 || (endpoints s).2.1))) = true
  rw [show nonTrunk .active = _ from Active.columns]
  change (!(label s (.step ff) || label s (.step gg)) ||
    ((endpoints s).2.2 && ((endpoints s).1.2 || (endpoints s).2.1))) = true
  by_cases hit : label s (.step ff) = true ∨ label s (.step gg) = true
  · have ep : ((endpoints s).1.2 || (endpoints s).2.1) = true := by
      cases hb : (endpoints s).1.2 <;> cases hz : (endpoints s).2.1 <;>
        first | rfl | exact (floor_no_leap s hb hz hit).elim
    simp [floors_after s hit,ep]
  · have no : (label s (.step ff) || label s (.step gg)) = false :=
      Bool.eq_false_iff.mpr (fun yes => hit (by simpa only [Bool.or_eq_true] using yes))
    simp [no]

public theorem upper (s : Step) : nonTrunkLabel .active s ∈ upperRows :=
  List.mem_filter.mpr ⟨Active.upper s, Bool.and_eq_true_iff.mpr ⟨tighter_step s,floor_step s⟩⟩

private noncomputable def laterInstall : FrontierRows.Run :=
  { CaseWitnesses.bounded30 with nodes := [0,1,2,3] }

private noncomputable def installer : Option Step := do
  let trace ← JointWitnesses.recordedAt laterInstall (by unfold FrontierRows.Run.valid; decide) []
  return (← trace.getLast?).val

private def extraRow : RestrictedProfile :=
  ⟨(true,true), [true,false,false,false,true,false,true], (true,true)⟩

set_option maxHeartbeats 0 in
private theorem checkedExtra :
    installer.map (readRow (nonTrunk .active)) = some extraRow := by decide +kernel

public def witnessed : List RestrictedProfile := Active.witnessed ++ [extraRow]

public noncomputable def remainingPatterns : List (List Bool) := upperPatterns.filter (· ∉ Active.patterns)
public def remainingRows : List RestrictedProfile := upperRows.filter (· ∉ witnessed)

public theorem counts :
    upperPatterns.Nodup ∧ upperPatterns.length = 39 ∧
    witnessed.Nodup ∧ witnessed.length = 26 ∧ upperRows.Nodup ∧ upperRows.length = 160 ∧
    remainingPatterns.length = 31 ∧ remainingRows.length = 134 :=
  by decide +kernel

public theorem lower (r : RestrictedProfile) (mem : r ∈ witnessed) :
    ∃ s : Step, nonTrunkLabel .active s = r := by
  rcases List.mem_append.mp mem with known | added
  · exact Active.lower r known
  · have eq := List.mem_singleton.mp added
    obtain ⟨s,_,hit⟩ := Option.map_eq_some_iff.mp checkedExtra
    exact ⟨s, (readRow_eq _ (by rw [show nonTrunk .active = _ from Active.columns]; decide +kernel) s).symm.trans
      (hit.trans eq.symm)⟩

end ConsensusCoverage.ClauseSmallA.ActiveTight
