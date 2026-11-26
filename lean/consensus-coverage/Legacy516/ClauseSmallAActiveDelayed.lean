module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ClauseSmallAActiveTight
import all ConsensusCoverage.ActionContext
import all ConsensusCoverage.ClauseQuestions
import all ConsensusCoverage.ClauseSmallA
import all ConsensusCoverage.ClauseSmallAActive
import all ConsensusCoverage.ClauseSmallAActiveTight
import all ConsensusCoverage.ClauseSmallATermMonoExact
import all ConsensusCoverage.CommitKeys
import all ConsensusCoverage.EventSupport
import all ConsensusCoverage.SolvedWitnesses
import all ConsensusCoverage.StateCoverage
import all Consensus.Proofs.SafetyInvariant
public meta import ConsensusCoverage.ReachPath

namespace ConsensusCoverage.ClauseSmallA.ActiveDelayed

open CCF CCF.MultiNodeTransitionSystem
open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety
open ActionProfile ClauseQuestions Active SolvedWitnesses

set_option maxRecDepth 8192
set_option maxHeartbeats 2000000

private theorem negative_nomination [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (c : Ctx f t) (nom : c.event = .internal .nominateSuccessor) :
    (¬ sig c aa) ∧ (¬ sig c bb) ∧ (¬ sig c cc) ∧ (¬ sig c dd) ∧ (¬ sig c ee) := by
  have ran := c.tr.ran
  change ((Node.step (Capabilities.record c.actor) c.actor c.pre c.event).run {}) = _ at ran
  rw [nom] at ran
  obtain ⟨sent,all,same,_,only⟩ := nominate_sends c.actor c.pre _ _ _ ran
  have equal : c.post = c.pre := same
  have old : Now f c.actor c.post := equal.symm ▸ c.pre_now
  have noActor : ¬sig c aa := by
    intro h
    obtain ⟨root,_,engaged⟩ := h
    exact root.2.2.1 ⟨old,engaged⟩
  have noSite : ¬Site₂ c := by
    intro h
    change (reach% step_post_two_active_inl[1]) f t c c at h
    reach_unfold step_post_two_active_inl[1] at h
    rcases h with h | h | h | h | h
    all_goals
      obtain ⟨e,_,member,_,_,_,_,_,_,bumps,_⟩ := h
      have realSent : e ∈ sent := by
        change e ∈ c.tr.outputs.outgoing at member
        simpa only [all,List.nil_append] using member
      obtain ⟨_,payload⟩ := only e realSent
      rw [payload] at bumps
      exact bumps
  have noCaller : ¬ (Site₁ c ∨ Site₂ c) := by
    rintro (h | h)
    · exact noActor ⟨h.1,h.2.1,h.2.2.1⟩
    · exact noSite h
  have noReceive : ¬sig c dd := fun h => by
    obtain ⟨_,_,ev,_⟩ := receive_of_sig c h
    rw [nom] at ev
    exact Event.noConfusion ev
  have noInstall : ¬sig c ee := fun h => by
    obtain ⟨_,ev,_⟩ := install_of_sig c h
    rw [nom] at ev
    exact Input.noConfusion (Event.internal.inj ev)
  refine ⟨noActor,?_,?_,noReceive,noInstall⟩
  · exact fun h => noCaller (h.elim (fun a => .inl a.1) (fun b => .inr b.1))
  · exact fun h => noCaller (h.elim (fun a => .inl a.1) (fun b => .inr b.1))

private def delayedRow (zero : Bool) : RestrictedProfile :=
  ⟨(zero,true),[false,false,false,false,false,true,false],(zero,true)⟩

private theorem active_on_replay (s : Step) {zero : Bool} (boot : s.cfg.min?.getD 0 = 0)
    (ep : ClauseExactTables.endpoints s = ((zero,true),(zero,true)))
    (nom : EventSupport.actionTag s.act = .nominateSuccessor)
    (floor : label s (.step ff) = true)
    (all : ∀ k p, (k,p) ∈ CommitKeys.keys 0 (s.after :: s.before :: s.past) → k = 2) :
    nonTrunkLabel .active s = delayedRow zero := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  have tagged := nom
  rw [← (s.context_eq c).mpr rfl, EventSupport.actionTag_eq] at tagged
  change EventSupport.eventTag c.event = .nominateSuccessor at tagged
  have event : c.event = .internal .nominateSuccessor := by
    cases eq : c.event with
    | internal i =>
      rw [eq] at tagged
      cases i <;> first | rfl | contradiction
    | receive src msg => rw [eq] at tagged; cases msg <;> contradiction
  obtain ⟨a,b,d,e,g⟩ := negative_nomination c event
  have false_bit (q : Classes.StepBranch) (h : ¬sig c q) : label s (.step q) = false :=
    Bool.eq_false_iff.mpr fun yes =>
      h (((label_true s (.step q)).trans (sig_iff s.context q)).mp yes)
  have noElected : label s (.step gg) = false := by
    apply false_bit
    intro h
    rcases ActiveTight.elected_floor_source c h with ⟨_,ev,_⟩ | ⟨k,bound,p,_,_,_,_,committed,_⟩
    · rw [event] at ev
      exact Input.noConfusion (Event.internal.inj ev)
    · have folded : (s.frame.advance s.after).logs = CommitKeys.historicalFold s.cfg
          (s.after :: s.before :: s.past) := StateCoverage.frame_logs s.after (s.before :: s.past)
      change (s.frame.advance s.after).logs.committed k p at committed
      rw [folded] at committed
      have mem := (CommitKeys.mem_iff s.cfg (s.after :: s.before :: s.past) k p).mpr committed
      rw [boot] at mem
      have eq := all k p mem
      omega
  change (⟨(ClauseExactTables.endpoints s).1,(nonTrunk .active).map (fun q => label s (.step q)),
    (ClauseExactTables.endpoints s).2⟩ : RestrictedProfile) = _
  rw [ep,show nonTrunk .active = _ from Active.columns]
  simp only [List.map_cons,List.map_nil,false_bit aa a,false_bit bb b,false_bit cc d,
    false_bit dd e,false_bit ee g,floor,noElected,delayedRow]

open TermMonoExact in
private theorem delayed (zero : Bool) : ∃ s : Step, nonTrunkLabel .active s = delayedRow zero := by
  refine ⟨replay zero, active_on_replay (replay zero) (bootstrap zero) (closed_endpoints zero)
    (recorded_nomination zero) (replay_answers zero).2 (fun k p h => ?_)⟩
  rw [TermMonoExact.replay_commits] at h
  simp only [List.mem_cons, List.not_mem_nil, or_false, Prod.mk.injEq] at h
  exact h.elim And.left (fun h => h.elim And.left And.left)

public noncomputable def witnessed := ActiveTight.witnessed ++ [delayedRow true, delayedRow false]
public noncomputable def patterns := Active.patterns ++ [[false,false,false,false,false,true,false]]

public noncomputable def remainingRows := ActiveTight.upperRows.filter (· ∉ witnessed)
public noncomputable def remainingPatterns := ActiveTight.upperPatterns.filter (· ∉ patterns)

public theorem counts :
    witnessed.Nodup ∧ witnessed.length = 28 ∧ patterns.Nodup ∧ patterns.length = 9 ∧
    remainingRows.length = 132 ∧ remainingPatterns.length = 30 := by decide +kernel

public theorem lower (r : RestrictedProfile) (mem : r ∈ witnessed) :
    ∃ s : Step, nonTrunkLabel .active s = r := by
  rcases List.mem_append.mp mem with old | extra
  · exact ActiveTight.lower r old
  · have either := List.mem_cons.mp extra
    rcases either with rfl | same
    · exact delayed true
    · have eq := List.mem_singleton.mp same
      exact eq.symm ▸ delayed false

public theorem patterns_lower (bits : List Bool) (mem : bits ∈ patterns) :
    ∃ s : Step, (nonTrunkLabel .active s).bits = bits := by
  rcases List.mem_append.mp mem with old | hit
  · exact Active.patterns_lower bits old
  · obtain ⟨s,eq⟩ := delayed false
    exact ⟨s,(congrArg RestrictedProfile.bits eq).trans (List.mem_singleton.mp hit).symm⟩

end ConsensusCoverage.ClauseSmallA.ActiveDelayed
