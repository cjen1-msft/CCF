module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ClauseSmallA
import all ConsensusCoverage.ClauseExactTables
import all ConsensusCoverage.ClauseMatchAck
import all ConsensusCoverage.ClauseQuestions
import all ConsensusCoverage.ClauseSmallA
import all ConsensusCoverage.PairQuestions
import all ConsensusCoverage.ReadersCorpus
import all ConsensusCoverage.SolvedWitnesses
import all ConsensusCoverage.StateCoverage
import all Consensus.Proofs.SafetyInvariant
public meta import ConsensusCoverage.ReachPath

namespace ConsensusCoverage.ClauseSmallA.Active

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety
open CCF CCF.MultiNodeTransitionSystem
open ActionProfile ClauseQuestions ClauseExactTables SolvedWitnesses

set_option maxHeartbeats 0
set_option maxRecDepth 8192

public theorem columns : nonTrunk .active =
    [.active_now_after_inl, .post_two_active_inl, .post_two_active_inr_inl,
     .post_two_active_inr_inr_inl, .post_two_active_inr_inr_inr,
     .leader_floor_led_inl, .leader_floor_led_inr] := by decide +kernel

private abbrev aa := Classes.StepBranch.active_now_after_inl
private abbrev bb := Classes.StepBranch.post_two_active_inl
private abbrev cc := Classes.StepBranch.post_two_active_inr_inl
private abbrev dd := Classes.StepBranch.post_two_active_inr_inr_inl
private abbrev ee := Classes.StepBranch.post_two_active_inr_inr_inr
private abbrev ff := Classes.StepBranch.leader_floor_led_inl
private abbrev gg := Classes.StepBranch.leader_floor_led_inr

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)

private abbrev Site₁ := (reach% step_post_two_active_inl[0]) f t c c
private abbrev Site₂ := (reach% step_post_two_active_inl[1]) f t c c
private abbrev Fired := Engaged c.post ∨ ∃ e, e ∈ c.sent ∧ Bumping e.payload
private abbrev Received := ∃ n m, c.event = .receive n m ∧ Bumping m ∧ m.term ≤ c.post.currentTerm
private abbrev Installed := ∃ l, c.event = .internal (.initAsBackup l) ∧
  0 < l.length ∧ isSignatureAt l l.length = true ∧ c.post.currentTerm = termAt l l.length

private theorem early (h : sig c bb) : sig c cc := by
  rcases h with ⟨site, pre, fire, le⟩ | ⟨site, pre, fire, le⟩
  all_goals
    have bound := c.pre_two pre
  · exact .inl ⟨site, .inl bound, bound, fire, le⟩
  · exact .inr ⟨site, .inl bound, bound, fire, le⟩

private theorem receive_arm (site : Site₁ c ∨ Site₂ c) (ev : Received c) (fire : Fired c) :
    sig c dd := by
  obtain ⟨n, m, event, bump, bound⟩ := ev
  have ev : Received c := ⟨n,m,event,bump,bound⟩
  have tail := And.intro (Or.inr (Or.inl ev) : 2 ≤ c.pre.currentTerm ∨ Received c ∨ Installed c)
    (And.intro (Or.inl ev : Received c ∨ Installed c) (And.intro ev
      (show ∃ n, (∃ m, c.event = .receive n m ∧ Bumping m ∧ m.term ≤ c.post.currentTerm) ∧
        ∃ m, (c.event = .receive n m ∧ Bumping m ∧ m.term ≤ c.post.currentTerm) ∧
          c.event = .receive n m ∧ (Bumping m ∧ m.term ≤ c.post.currentTerm) ∧
            Bumping m ∧ m.term ≤ c.post.currentTerm ∧ Fired c ∧ c.pre.currentTerm ≤ c.post.currentTerm
      from ⟨n, ⟨m,event,bump,bound⟩, m, ⟨event,bump,bound⟩, event, ⟨bump,bound⟩, bump,
        bound, fire, c.term_le⟩)))
  exact site.elim (fun a => .inl ⟨a, tail⟩) (fun b => .inr ⟨b, tail⟩)

private theorem install_arm (site : Site₁ c ∨ Site₂ c) (ev : Installed c) (fire : Fired c) :
    sig c ee := by
  obtain ⟨l, event, pos, sig_, term⟩ := ev
  have ev : Installed c := ⟨l,event,pos,sig_,term⟩
  have tail := And.intro (Or.inr (Or.inr ev) : 2 ≤ c.pre.currentTerm ∨ Received c ∨ Installed c)
    (And.intro (Or.inr ev : Received c ∨ Installed c) (And.intro ev
      (show ∃ l, (c.event = .internal (.initAsBackup l) ∧ 0 < l.length ∧
        isSignatureAt l l.length = true ∧ c.post.currentTerm = termAt l l.length) ∧
        c.event = .internal (.initAsBackup l) ∧
        (0 < l.length ∧ isSignatureAt l l.length = true ∧ c.post.currentTerm = termAt l l.length) ∧
        0 < l.length ∧ (isSignatureAt l l.length = true ∧ c.post.currentTerm = termAt l l.length) ∧
        isSignatureAt l l.length = true ∧ c.post.currentTerm = termAt l l.length ∧
        Fired c ∧ c.pre.currentTerm ≤ c.post.currentTerm
      from ⟨l,⟨event,pos,sig_,term⟩,event,⟨pos,sig_,term⟩,pos,⟨sig_,term⟩,sig_,term,
        fire,c.term_le⟩)))
  exact site.elim (fun a => .inl ⟨a, tail⟩) (fun b => .inr ⟨b, tail⟩)

private theorem active_arm (h : sig c aa) : sig c cc ∨ sig c dd ∨ sig c ee := by
  obtain ⟨root, now, engaged⟩ := h
  have site : Site₁ c := ⟨root,now,engaged,now,now,engaged,rfl⟩
  have fire : Fired c := .inl engaged
  rcases Summary.active c.sum fire with pre | bound | received | installed
  · exact .inl (early c (.inl ⟨site,pre,fire,c.term_le⟩))
  · exact .inl (.inl ⟨site,.inl bound,bound,fire,c.term_le⟩)
  · exact .inr (.inl (receive_arm c (.inl site) received fire))
  · exact .inr (.inr (install_arm c (.inl site) installed fire))

private theorem install_of_sig (h : sig c ee) : Installed c := by
  rcases h with h | h
  all_goals exact h.2.2.2.1

private theorem receive_of_sig (h : sig c dd) : Received c := by
  rcases h with h | h
  all_goals exact h.2.2.2.1

private theorem receive_prebound (h : sig c dd) (bound : 2 ≤ c.pre.currentTerm) : sig c cc := by
  rcases h with h | h
  · obtain ⟨site,_,_,_,_,_,_,_,_,_,_,_,fire,le⟩ := h
    exact .inl ⟨site,.inl bound,bound,fire,le⟩
  · obtain ⟨site,_,_,_,_,_,_,_,_,_,_,_,fire,le⟩ := h
    exact .inr ⟨site,.inl bound,bound,fire,le⟩

private theorem active_prebound (h : sig c aa) (bound : 2 ≤ c.pre.currentTerm) : sig c cc := by
  obtain ⟨root, now, engaged⟩ := h
  exact .inl ⟨⟨root,now,engaged,now,now,engaged,rfl⟩,
    .inl bound,bound,.inl engaged,c.term_le⟩

private theorem install_state (h : Installed c) :
    ∃ l, c.pre.isFresh ∧ l ≠ [] ∧ c.post.log = l ∧ c.post.role = .follower := by
  obtain ⟨l,ev,positive,_,_⟩ := h
  have ran := c.tr.ran
  change ((Node.step (Capabilities.record c.actor) c.actor c.pre c.event).run {}) = _ at ran
  rw [ev] at ran
  change (initAsBackup c.pre l : NodeEffect NodeState).run {} = _ at ran
  have effect : Sends (fun post _ => c.pre.isFresh ∧ post.log = l ∧ post.role = .follower)
      (initAsBackup c.pre l : NodeEffect NodeState) := by
    unfold initAsBackup
    exact Sends.bind' Sends.guard' fun _ _ good => Sends.pure' ⟨good.1.1,rfl,rfl⟩
  obtain ⟨_, _, fresh,log,role⟩ := effect _ _ _ ran
  exact ⟨l,fresh,List.length_pos_iff.mp positive,log,role⟩

private theorem install_pre (h : Installed c) : c.pre.isFresh := by
  obtain ⟨_,fresh,_⟩ := install_state c h
  exact fresh

private theorem install_changes (h : sig c ee) : sig c aa := by
  obtain ⟨l,fresh,nonempty,log,role⟩ := install_state c (install_of_sig c h)
  have engaged : Engaged c.post := ⟨by rw [role]; decide, fun eq => nonempty (log.symm.trans eq.2.2)⟩
  have new : ¬ Now f c.actor c.post := by
    intro old
    have same := c.now_pre old
    exact nonempty (log.symm.trans ((congrArg NodeState.log same).trans fresh.2.2.1))
  exact ⟨⟨c.post_now,engaged,fun old => new old.1,rfl⟩,c.post_now,engaged⟩

private theorem install_not_early (h : sig c ee) : ¬ sig c cc := by
  have zero := (install_pre c (install_of_sig c h)).2.1
  rintro (⟨_, _, bound, _⟩ | ⟨_, _, bound, _⟩) <;> omega

private theorem install_not_received (h : sig c ee) : ¬ sig c dd := by
  intro recv
  obtain ⟨_, ev, _⟩ := install_of_sig c h
  obtain ⟨_,_,ev',_⟩ := receive_of_sig c recv
  rw [ev] at ev'
  contradiction

private theorem install_backing (h : sig c ee) : ∃ k p, Committed f k p := by
  obtain ⟨l, ev, positive, signed, _⟩ := install_of_sig c h
  obtain ⟨_, _, _, k, p, committed, _⟩ := c.snap_available ev positive signed
  exact ⟨k,p,committed⟩

private theorem install_floor (h : sig c ee) : sig c ff ∨ sig c gg := by
  obtain ⟨l, ev, positive, signed, _⟩ := install_of_sig c h
  have snap := c.snap_available ev positive signed
  obtain ⟨_, _, ⟨w,can,sub⟩, committed⟩ := snap
  obtain ⟨n, owner⟩ := c.inv.owner can
  have path₁ (site : Site₁ c) : (reach% step_leader_floor_led_inl[2]) f t c n (termAt l l.length) := by
    reach_unfold step_leader_floor_led_inl[2]
    rcases h with h | h
    all_goals
      refine ⟨site, h.2.1, h.2.2.1, h.2.2.2.1, ?_⟩
      obtain ⟨l', root, rest⟩ := h.2.2.2.2
      have same := Input.initAsBackup.inj (Event.internal.inj (ev.symm.trans root.1))
      subst l'
      exact ⟨l,root,rest.1,rest.2.1,rest.2.2.1,rest.2.2.2.1,rest.2.2.2.2.1,
        rest.2.2.2.2.2.1,positive,⟨signed,⟨w,can,sub⟩,committed⟩,
        signed,⟨⟨w,can,sub⟩,committed⟩,⟨w,can,sub⟩,committed,
        ⟨w,⟨can,sub⟩,can,sub,owner,rest.2.2.2.2.2.2.1,c.term_le,rfl⟩⟩
  obtain ⟨root, now, engaged⟩ := install_changes c h
  have path := path₁ ⟨root,now,engaged,now,now,engaged,rfl⟩
  rcases owner with ⟨stamp,rfl⟩ | ⟨log, idx, elected⟩
  · exact .inl (.inr (.inr (.inl ⟨stamp ▸ path,.inl ⟨rfl,rfl⟩⟩)))
  · exact .inr (.inr (.inr (.inl
      ⟨n,termAt l l.length,path,⟨log,idx,elected⟩,log,⟨idx,elected⟩,
        idx,elected,.inr ⟨log,idx,elected⟩⟩)))
end

private def allBits : Nat → List (List Bool)
  | 0 => [[]]
  | k + 1 => (allBits k).flatMap fun bs => [false :: bs, true :: bs]

private theorem mem_allBits (bs : List Bool) : bs ∈ allBits bs.length := by
  induction bs with
  | nil => exact List.mem_cons_self
  | cons b bs ih =>
    apply List.mem_flatMap.mpr
    refine ⟨bs,ih,?_⟩
    cases b <;> simp

private def conforms : List Bool → Bool
  | [a,b,c,d,e,f,g] => (!b || c) && (!a || c || d || e) && (!e || (a && !c && !d && (f || g)))
  | _ => false

public def upperPatterns : List (List Bool) := (allBits 7).filter conforms

private theorem conforms_of :
    ∀ a b c d e f g : Bool, (b = true → c = true) →
      (a = true → c = true ∨ d = true ∨ e = true) →
      (e = true → c = false) → (e = true → d = false) → (e = true → a = true) →
      (e = true → f = true ∨ g = true) → conforms [a,b,c,d,e,f,g] = true :=
  by decide +kernel

public theorem patterns_upper (s : Step) : (nonTrunkLabel .active s).bits ∈ upperPatterns := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  have spec (b : Classes.StepBranch) := (label_true s (.step b)).trans (sig_iff s.context b)
  have early' : label s (.step bb) = true → label s (.step cc) = true :=
    fun h => (spec cc).mpr (early _ ((spec bb).mp h))
  have active' : label s (.step aa) = true →
      label s (.step cc) = true ∨ label s (.step dd) = true ∨ label s (.step ee) = true :=
    fun h => (active_arm _ ((spec aa).mp h)).imp (spec cc).mpr
      (Or.imp (spec dd).mpr (spec ee).mpr)
  have installBound : label s (.step ee) = true → label s (.step cc) = false :=
    fun h => Bool.eq_false_iff.mpr fun pre => install_not_early _ ((spec ee).mp h) ((spec cc).mp pre)
  have installRecv : label s (.step ee) = true → label s (.step dd) = false :=
    fun h => Bool.eq_false_iff.mpr fun recv => install_not_received _ ((spec ee).mp h) ((spec dd).mp recv)
  have installChanged : label s (.step ee) = true → label s (.step aa) = true :=
    fun h => (spec aa).mpr (install_changes _ ((spec ee).mp h))
  have installFloor : label s (.step ee) = true → label s (.step ff) = true ∨ label s (.step gg) = true :=
    fun h => (install_floor _ ((spec ee).mp h)).imp (spec ff).mpr (spec gg).mpr
  simp only [nonTrunkLabel, columns, restrictedLabel, List.map_cons, List.map_nil, upperPatterns,
    List.mem_filter]
  exact ⟨mem_allBits _, conforms_of _ _ _ _ _ _ _ early' active' installBound installRecv installChanged
    installFloor⟩

private theorem install_before (s : Step)
    (yes : label s (.step ee) = true) : (endpoints s).1 = (true,true) := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  have hit := ((label_true s (.step ee)).trans (sig_iff s.context ee)).mp yes
  obtain ⟨k,p,backed⟩ := install_backing c hit
  apply Prod.ext
  · have mem : (c.actor,c.pre) ∈ s.before.nodes := by
      rw [← show s.frame.current = s.before from s.current_eq]
      exact c.pre_now
    exact (PairQuestions.zero_mem _).mpr ⟨_,_,mem,(install_pre c (install_of_sig c hit)).2.2.2⟩
  · exact (StateCoverage.read_iff _ _ c.inv).2.mpr
      ((StateCoverage.backed_iff _ c.inv).mpr ⟨List.ne_nil_of_mem c.pre_now,k,p,backed⟩)

private theorem no_zero_early (s : Step) (zero : (endpoints s).1.1 = false)
    (yes : label s (.step aa) = true ∨ label s (.step dd) = true) :
    label s (.step cc) = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  have mem : (c.actor,c.pre) ∈ s.before.nodes := by
    rw [← show s.frame.current = s.before from s.current_eq]
    exact c.pre_now
  have positive : 0 < c.pre.commitIndex := Nat.pos_of_ne_zero fun eq =>
    Bool.noConfusion (zero.symm.trans ((PairQuestions.zero_mem s.before).mpr ⟨_,_,mem,eq⟩))
  have len := c.frontier_pre
  have nonempty : c.pre.log ≠ [] := by
    intro nil
    rw [nil, List.length_nil] at len
    omega
  have root := (c.inv.rooted _ _ c.pre_now).resolve_left nonempty
  have genesis : Config.GENESIS ∈ c.pre.log := List.mem_of_mem_take
    (by rw [root]; exact List.mem_cons_self)
  have bound : 2 ≤ c.pre.currentTerm := c.inv.terms _ _ c.pre_now _ genesis
  have spec (b : Classes.StepBranch) := (label_true s (.step b)).trans (sig_iff s.context b)
  exact (spec cc).mpr (yes.elim (fun h => active_prebound c ((spec aa).mp h) bound)
    (fun h => receive_prebound c ((spec dd).mp h) bound))

private def endpointOK (e : Endpoints) (bs : List Bool) : Bool :=
  (!bs[4]! || decide (e.1 = (true,true))) &&
    (e.1.1 || !(bs[0]! || bs[3]!) || bs[2]!)

public def upperRows : List RestrictedProfile :=
  endpointRows.flatMap fun e => (upperPatterns.filter (endpointOK e)).map fun bs => ⟨e.1,bs,e.2⟩

public theorem upper (s : Step) : nonTrunkLabel .active s ∈ upperRows := by
  apply List.mem_flatMap.mpr
  refine ⟨endpoints s, (endpoint_exact _).mpr ⟨s,rfl⟩, List.mem_map.mpr ⟨_,?_,rfl⟩⟩
  refine List.mem_filter.mpr ⟨patterns_upper s,?_⟩
  have hit : (nonTrunkLabel .active s).bits[4]! = label s (.step ee) := by
    simp only [nonTrunkLabel, columns, restrictedLabel, List.map_cons, List.map_nil]
    rfl
  refine Bool.and_eq_true_iff.mpr ⟨?_,?_⟩
  · change (!(nonTrunkLabel .active s).bits[4]! || decide ((endpoints s).1 = (true,true))) = true
    rw [hit]
    cases h : label s (.step ee) with
    | false => rfl
    | true => simp [install_before s h]
  · rw [columns]
    change ((endpoints s).1.1 || !(label s (.step aa) || label s (.step dd)) ||
      label s (.step cc)) = true
    cases h : (endpoints s).1.1 with
    | true => rfl
    | false =>
      by_cases positive : label s (.step aa) = true ∨ label s (.step dd) = true
      · simp [no_zero_early s h positive]
      · have no : (label s (.step aa) || label s (.step dd)) = false :=
          Bool.eq_false_iff.mpr (fun yes => positive (by simpa only [Bool.or_eq_true] using yes))
        simp [no]

private def pattern (n : Nat) : List Bool :=
  (List.range 7).map fun i => n.testBit (6 - i)

private def row (e : Endpoints) (n : Nat) : RestrictedProfile := ⟨e.1,pattern n,e.2⟩

private abbrev z : StateCoverage.Row := (true,false)
private abbrev b : StateCoverage.Row := (true,true)
private abbrev p : StateCoverage.Row := (false,true)

public def witnessed : List RestrictedProfile :=
  [row (z,z) 0, row (z,z) 48, row (z,z) 56, row (z,z) 72, row (z,z) 112, row (z,z) 120,
   row (z,b) 112, row (z,b) 120, row (z,p) 112,
   row (b,b) 0, row (b,b) 48, row (b,b) 56, row (b,b) 70, row (b,b) 72, row (b,b) 112, row (b,b) 120,
   row (b,p) 69, row (b,p) 70, row (b,p) 112, row (b,p) 120,
   row (p,p) 0, row (p,p) 48, row (p,p) 56, row (p,p) 112, row (p,p) 120]

public def patterns : List (List Bool) := [0,48,56,69,70,72,112,120].map pattern

/-- Candidates left by the upper proof for which the sample has no witness. -/
public def remainingPatterns : List (List Bool) :=
  upperPatterns.filter (· ∉ patterns)

public def remainingRows : List RestrictedProfile :=
  upperRows.filter (· ∉ witnessed)

private def picks : List (Nat × Nat) :=
  [(0,0),(0,1),(1,0),(2,0),(2,2),(2,3),(2,4),(2,5),(3,3),(3,4),(4,6),(4,9),(4,10),
   (5,5),(5,6),(5,9),(6,15),(15,0),(18,0),(21,1),(24,3),(25,8),(46,1)]

private noncomputable def steps :=
  ([(14,3),(32,12)].filterMap fun (i,j) => ReadersCorpus.caseStepAt i j) ++
    picks.filterMap (fun (i,j) => ReadersCorpus.stepAt i j)

private theorem checked : witnessed.all (steps.map (readRow (nonTrunk .active))).contains = true :=
  by decide +kernel

public theorem lower (r : RestrictedProfile) (mem : r ∈ witnessed) :
    ∃ s : Step, nonTrunkLabel .active s = r :=
  sampled _ (by rw [columns]; decide +kernel) _ _ checked mem

public theorem counts :
    patterns.length = 8 ∧ patterns.Nodup ∧ upperPatterns.length = 47 ∧ upperPatterns.Nodup ∧
    witnessed.length = 25 ∧ witnessed.Nodup ∧ upperRows.length = 262 ∧ upperRows.Nodup ∧
    remainingPatterns.length = 39 ∧ remainingRows.length = 237 :=
  by decide +kernel

public theorem patterns_lower (bits : List Bool) (mem : bits ∈ patterns) :
    ∃ s : Step, (nonTrunkLabel .active s).bits = bits := by
  obtain ⟨r, hr, rfl⟩ :=
    (by decide +kernel : ∀ q ∈ patterns, ∃ r ∈ witnessed, r.bits = q) bits mem
  obtain ⟨s, eq⟩ := lower r hr
  exact ⟨s, congrArg RestrictedProfile.bits eq⟩

end ConsensusCoverage.ClauseSmallA.Active
