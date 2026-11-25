module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ClauseExactTables
import all ConsensusCoverage.ClauseExactTables
import all ConsensusCoverage.ClauseQuestions
import all ConsensusCoverage.ExploredWitnesses
import all ConsensusCoverage.FrontierWitnesses
import all ConsensusCoverage.HandReadersAPrimary
import all ConsensusCoverage.JointWitnesses
import all ConsensusCoverage.LeaderCoverage
import all ConsensusCoverage.NoBackingWitness
import all ConsensusCoverage.PinnedLeader
import all ConsensusCoverage.ReadersCorpus
import all ConsensusCoverage.ReadersRefuted
import all ConsensusCoverage.ReadersTotal
import all ConsensusCoverage.ReadersShapes
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.ClauseMatchAck

open Consensus Consensus.Proofs Consensus.Proofs.Safety
open ClauseQuestions ClauseExactTables ActionProfile

set_option maxHeartbeats 0
set_option maxRecDepth 8192

open Lean Meta in
/-- Build the frequency index once, directly from the generated clause lists. -/
local elab "frequencies%" : term => do
  let branches := (← getConstInfoInduct ``Classes.StepBranch).ctors
  let mut freq := Array.replicate branches.length 0
  for c in (← getConstInfoInduct ``Clause).ctors do
    let mut row ← mkAppM ``questions #[mkConst c]
    repeat
      let cell ← whnf row
      if cell.isAppOf ``List.nil then break
      unless cell.isAppOfArity ``List.cons 3 do throwError "nonliteral questions list for {c}"
      let some i := branches.idxOf? (cell.getArg! 1).constName! | throwError "unknown branch"
      freq := freq.modify i (· + 1)
      row := cell.appArg!
  mkArrayLit (mkConst ``Nat) (freq.toList.map mkNatLit)

private def frequencies : Array Nat := frequencies%

public def trunk (b : Classes.StepBranch) : Bool := frequencies[b.ctorIdx]?.getD 0 ≥ 26
public def nonTrunk (c : Clause) := (questions c).filter (!trunk ·)

public theorem trunk_count : (FullProfile.stepBranches.toList.filter trunk).length = 164 :=
  by decide +kernel

private abbrev now := Classes.StepBranch.match_ack_now_after_inl
private abbrev kept := Classes.StepBranch.match_ack_matchIndex_inl
private abbrev ack := Classes.StepBranch.match_ack_matchIndex_inr
private abbrev win := Classes.StepBranch.facts_advance_inl_2

public theorem columns : nonTrunk .match_ack =
    [.match_ack_now_after_inl, .match_ack_matchIndex_inl, .match_ack_matchIndex_inr,
     .facts_advance_inl_2, .facts_advance_inr_2, .facts_role_inl, .facts_role_inr] := by
  decide +kernel

public noncomputable def bits (s : Step) := (restrictedLabel (nonTrunk .match_ack) s).bits

private def pack (l r w : Bool) : List Bool := [l || r, l, r, w, false, false, false]

public def patterns : List (List Bool) :=
  [pack false false false, pack false false true, pack true false false,
   pack false true false, pack true true false]

public theorem pattern_count : patterns.Nodup ∧ patterns.length = 5 := by decide +kernel

section
variable [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t)

open SolvedWitnesses in
private theorem split_iff : sig c now ↔ sig c kept ∨ sig c ack := by
  constructor
  · rintro ⟨peer, root, mem, leader, other, pos⟩
    obtain old | wins := Summary.leader c.sum leader
    · obtain same | ⟨r,event,success,term,idx⟩ := Summary.matchIndex c.sum leader old.1 old.2 peer
      · exact .inl ⟨peer,root,mem,other,leader,pos,mem,old,old.1,old.2,same,mem,leader,other,pos⟩
      · have recv := And.intro event (And.intro success (And.intro term idx))
        exact .inr ⟨peer,root,mem,other,leader,pos,mem,old,old.1,old.2,⟨r,recv⟩,r,recv,event,
          recv.2,success,recv.2.2,term,idx,mem,leader,other,pos⟩
    · obtain ⟨_,_,_,_,_,_,z,_⟩ := Wins.facts wins
      rw [z] at pos
      exact (Nat.lt_irrefl 0 pos).elim
  · rintro (⟨p,root,mem,other,role,pos,_⟩ | ⟨p,root,mem,other,role,pos,_⟩)
    all_goals exact ⟨p,root,mem,role,other,pos⟩

open SolvedWitnesses in
private theorem win_excludes : sig c win → ¬sig c now := by
  intro h ⟨p,_,_,_,_,pos⟩
  obtain ⟨_,_,_,_,_,_,z,_⟩ := Wins.facts ((HandReadersA.Primary.identity_iff c).mp h)
  rw [z] at pos
  exact Nat.lt_irrefl 0 pos
end

private theorem semantics (s : Step) :
    let p := label s
    p (.step now) = (p (.step kept) || p (.step ack)) ∧
      (p (.step win) = true → p (.step now) = false) := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  have spec (b) := (label_true s (.step b)).trans (SolvedWitnesses.sig_iff s.context b)
  constructor
  · apply Bool.eq_iff_iff.mpr
    rw [Bool.or_eq_true, spec, spec, spec]
    exact split_iff s.context
  · intro h
    exact Bool.eq_false_iff.mpr fun a => win_excludes s.context ((spec _).mp h) ((spec _).mp a)

public theorem complete (s : Step) : bits s ∈ patterns := by
  have ⟨eq, ban⟩ := semantics s
  have nope (b : Classes.StepBranch) (h : ReadersRefuted.read? b = some false) :=
    ReadersRefuted.read?_correct s h
  simp only [bits, restrictedLabel, columns, List.map_cons, List.map_nil,
    nope .facts_advance_inr_2 (by decide +kernel), nope .facts_role_inl (by decide +kernel),
    nope .facts_role_inr (by decide +kernel), eq] at *
  cases l : label s (.step kept) <;> cases r : label s (.step ack) <;> cases w : label s (.step win) <;>
    simp_all [patterns, pack]

private def realRead (s : Step) : RestrictedProfile :=
  ⟨(endpoints s).1, [now, kept, ack, win].map
    (fun b => (ReadersTotal.read s.cfg s.before s.act s.after s.past b).getD false) ++
      [false,false,false], (endpoints s).2⟩

private theorem realRead_eq (s : Step) : realRead s = restrictedLabel (nonTrunk .match_ack) s := by
  have yes (b : Classes.StepBranch) (h : b ∈ ReadersTotal.covered) := ReadersTotal.read_total s h
  have no (b : Classes.StepBranch) (h : ReadersRefuted.read? b = some false) :=
    ReadersRefuted.read?_correct s h
  simp only [realRead, columns, restrictedLabel, endpoints, List.map_cons, List.map_nil,
    yes now (by decide +kernel), yes kept (by decide +kernel), yes ack (by decide +kernel),
    yes win (by decide +kernel), Option.getD_some, List.cons_append, List.nil_append,
    no .facts_advance_inr_2 (by decide +kernel), no .facts_role_inl (by decide +kernel),
    no .facts_role_inr (by decide +kernel)]

private def picks : List (Nat × Nat) :=
  [(0,1),(168,5),(2,6),(70,5),(175,8), (25,1),(166,5),(70,3),(52,2),(175,4),
   (2,0),(3,6),(26,2),(26,3)]

open ExploredWitnesses in
private def unsigned : FrontierRows.Run :=
  ⟨{0,1,2}, [0,1,2], [append 0 [{tx with flushes := [(1,2),(2,2)]}],
    deliver 0 1, deliver 0 2, deliver 1 0, deliver 2 0]⟩

private def unsignedStep : Option Step := do
  let ss ← JointWitnesses.recordedAt unsigned (by unfold FrontierRows.Run.valid; decide) []
  return (← ss.getLast?).val

private def steps := unsignedStep.toList ++ picks.filterMap fun (i,j) => ReadersCorpus.stepAt i j
private def samples := steps.map realRead

public def fiberRows (e : StateCoverage.Row) := patterns.map fun b => RestrictedProfile.mk e b e

private theorem sampled :
    (StateCoverage.activeTable.flatMap fiberRows).all samples.contains = true := by decide +kernel

/-- On each of the three reachable diagonals all five compatible patterns occur, and there
are no others. Endpoint hypotheses are part of the equivalence. -/
public theorem diagonal_exact (e : StateCoverage.Row) (active : e ∈ StateCoverage.activeTable)
    (p : RestrictedProfile) :
    p ∈ fiberRows e ↔ ∃ s : Step, endpoints s = (e,e) ∧
      restrictedLabel (nonTrunk .match_ack) s = p := by
  constructor
  · intro mem
    have all := List.mem_flatMap.mpr ⟨e,active,mem⟩
    have hit := List.contains_iff_mem.mp (List.all_eq_true.mp sampled p all)
    obtain ⟨s,_,eq⟩ := List.mem_map.mp hit
    have labelEq := (realRead_eq s).symm.trans eq
    obtain ⟨b,_,row⟩ := List.mem_map.mp mem
    exact ⟨s, congrArg (fun r : RestrictedProfile => (r.pre,r.post)) (labelEq.trans row.symm), labelEq⟩
  · rintro ⟨s,ep,rfl⟩
    exact List.mem_map.mpr ⟨bits s, complete s, by
      have l := congrArg Prod.fst ep
      have r := congrArg Prod.snd ep
      exact (congrArg (fun a => RestrictedProfile.mk a (bits s) e) l.symm).trans
        (congrArg (fun b => RestrictedProfile.mk (endpoints s).1 (bits s) b) r.symm)⟩

public theorem patterns_exact (b : List Bool) : b ∈ patterns ↔ ∃ s : Step, bits s = b := by
  constructor
  · intro mem
    have hm : (⟨(false,true),b,(false,true)⟩ : RestrictedProfile) ∈ fiberRows (false,true) :=
      List.mem_map.mpr ⟨_,mem,rfl⟩
    obtain ⟨s,_,eq⟩ := (diagonal_exact (false,true) (by decide +kernel) _).mp hm
    exact ⟨s,congrArg RestrictedProfile.bits eq⟩
  · rintro ⟨s,rfl⟩
    exact complete s

private theorem win_diagonal (s : Step) (h : label s (.step win) = true) :
    (endpoints s).1 = (endpoints s).2 := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  have won := (HandReadersA.Primary.identity_iff s.context).mp
    ((SolvedWitnesses.sig_iff s.context _).mp ((label_true s _).mp h))
  have primary := ((ReadersShapes.wins_recorded s.context).mp won).1
  have new := PinnedLeader.wins_newPrimary s.context primary won
  rw [show s.frame.current = s.before from s.current_eq] at new
  have finite : ∀ r ∈ FrontierRows.table, r.wonPrimary = true →
      (r.zeroBefore,r.backedBefore) = (r.zeroAfter,r.backedAfter) := by decide +kernel
  exact finite _ (FrontierRows.complete s.run s.ran) new

private theorem has_peer (s : Step) (h : label s (.step now) = true) : LeaderCoverage.MultiNode s.nodes := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  obtain ⟨peer,_,mem,role,other,positive⟩ :=
    (SolvedWitnesses.sig_iff s.context now).mp ((label_true s _).mp h)
  obtain ⟨o,_,seen,_⟩ := s.context.inv_step.match_ack _ _ _ mem role other positive
  change (StateCoverage.frame s.after (s.before :: s.past)).logs.seen peer o.currentTerm o.log at seen
  rw [StateCoverage.frame_logs,(Historical.logFacts_correct _).seen] at seen
  obtain ⟨_,⟨snap,hist,old⟩,_⟩ := seen
  have run := StateCoverage.Run.step s.run s.ran
  have p := List.mem_map_of_mem (f := Prod.fst) old
  have a := List.mem_map_of_mem (f := Prod.fst) s.context.tr.post_mem
  rw [NoBackingWitness.run_keys run snap hist] at p
  rw [NoBackingWitness.run_keys run s.after List.mem_cons_self] at a
  exact ⟨_,p,_,a,other⟩

/-- The direct transition from no backing to no zero must be on a singleton
deployment. Neither a positive match with another deployed peer nor a win
is possible. -/
public theorem first_no_zero (s : Step) (ep : endpoints s = ((true,false),(false,true))) :
    bits s = List.replicate 7 false := by
  have a : label s (.step now) = false := Bool.eq_false_iff.mpr fun h => by
    have before := congrArg (fun p : Endpoints => p.1.2) ep
    have after := congrArg (fun p : Endpoints => p.2.1) ep
    exact Bool.noConfusion (after.symm.trans (LeaderCoverage.unbacked_keeps_zero s (has_peer s h) before))
  have w : label s (.step win) = false := Bool.eq_false_iff.mpr fun h => by
    have eq := win_diagonal s h
    rw [ep] at eq
    contradiction
  have cut := (semantics s).1
  rw [a, eq_comm, Bool.or_eq_false_iff] at cut
  have no (b : Classes.StepBranch) (h : ReadersRefuted.read? b = some false) := ReadersRefuted.read?_correct s h
  simp only [bits, restrictedLabel, columns, List.map_cons, List.map_nil, a, cut.1, cut.2, w,
    no .facts_advance_inr_2 (by decide +kernel), no .facts_role_inl (by decide +kernel),
    no .facts_role_inr (by decide +kernel)]
  rfl

public theorem first_no_zero_exact (b : List Bool) :
    b = List.replicate 7 false ↔ ∃ s : Step, endpoints s = ((true,false),(false,true)) ∧ bits s = b := by
  constructor
  · rintro rfl
    obtain ⟨s,ep⟩ := (endpoint_exact ((true,false),(false,true))).mp (by rw [endpoint_rows]; decide)
    exact ⟨s,ep,first_no_zero s ep⟩
  · rintro ⟨s,ep,rfl⟩
    exact first_no_zero s ep

end ConsensusCoverage.ClauseMatchAck
