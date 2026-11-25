module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.GuardedDomain
public import ConsensusCoverage.CommitKeys
import all ConsensusCoverage.GuardedDomain
import all ConsensusCoverage.CommitKeys
import all ConsensusCoverage.DelayedNominationArms
import all ConsensusCoverage.EvidenceSupport
import all ConsensusCoverage.InertProfile
import all ConsensusCoverage.NominationArms
import all ConsensusCoverage.StutterProfile
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersBGate

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety
open ActionProfile GuardedDomain SolvedWitnesses EvidenceSupport

set_option maxRecDepth 8192

public def active (cfg : FullProfile.Configuration) (before : State) (act : Action)
    (after : State) (past : List State) : Bool :=
  (ofAction cfg before after past act).any fun v =>
    v.changed || !(after.network.all before.network.contains) ||
      !CommitKeys.noNew (cfg.min?.getD 0) after (before :: past)

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} {c : Ctx f t}

inductive Source (c : Ctx f t) : Prop where
  | node (new : ¬ Now f c.actor c.post)
  | packet (e : Model.Envelope) (post : Pending (f.advance t) e) (new : ¬ Pending f e)
  | key (n : Nat) (l : List Entry) (post : Committed (f.advance t) n l) (new : ¬ Committed f n l)

omit [Config.InitialConfiguration] in
theorem live (s : Step) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    active s.cfg s.before s.act s.after s.past = true ↔ Source s.context := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  obtain ⟨v,made,ok⟩ := ofAction_matches s
  have changed := View.old_post ok
  have queue : s.after.network.all s.before.network.contains = true ↔
      ∀ e, Pending (s.frame.advance s.after) e → Pending s.frame e := by
    rw [← s.current_eq]
    simp only [List.all_eq_true,List.contains_iff_mem]
    rfl
  rw [active,made,Option.any_some,Bool.or_eq_true,Bool.or_eq_true,Bool.not_eq_true',
    Bool.not_eq_true',← Bool.not_eq_true,← Bool.not_eq_true,queue,CommitKeys.step_noNew]
  constructor
  · rintro ((node | packet) | key)
    · exact .node (fun old => Bool.noConfusion (node.symm.trans (changed.mp old)))
    · simp only [Classical.not_forall] at packet
      obtain ⟨e,h,g⟩ := packet
      exact .packet e h g
    · simp only [Classical.not_forall] at key
      obtain ⟨n,l,h,g⟩ := key
      exact .key n l h g
  · rintro (new | ⟨e,h,g⟩ | ⟨n,l,h,g⟩)
    · apply Or.inl; apply Or.inl
      cases hv : v.changed with
      | false => exact (new (changed.mpr hv)).elim
      | true => rfl
    · exact .inl (.inr fun all => g (all e h))
    · exact .inr fun all => g (all n l h)

inductive Site (c : Ctx f t) : Prop where
  | node (entered : (reach% step_summary_event_receive[15,0]) f t c t c.tr)
  | packet (entered : (reach% step_summary_event_receive[16,0]) f t c t c.tr)
  | key (entered : (reach% step_summary_event_receive[9,0]) f t c t c.tr)

theorem site (yes : Source c) : Site c := by
  rcases yes with new | ⟨e,h,g⟩ | ⟨n,l,h,g⟩
  · exact .node ⟨.inl ⟨⟨c.post_now,new,rfl⟩,c.post_now,c.post_now,c.post_now,
      fun backing => ⟨⟨_,backing⟩,fun _ _ => backing⟩,rfl⟩,rfl,HEq.rfl⟩
  · have sent : e ∈ c.sent := by
      exact (c.tr.mem_network h).resolve_left g
    exact .packet (NominationArms.reach434 sent g)
  · exact .key (DelayedNomination.r427 ⟨n,l,h,g⟩)

-- A new grant's only route into dispatch needs an observation of this
-- voter in a strictly older term in the very same post-state.
theorem grantClosed (other : Ctx f t)
    (h : (reach% step_summary_event_receive[10,0,0,0]) f t c other) : False := by
  obtain ⟨v,n,term,r,_,_,p,_,_,_,_,_,_,_,_,w,_,post,_,_,_,mem,_,_,_,teq,_,_,_,k,l,i,_,lt,_,_,_,
    st,_,mem',_,keq,_,_,_,stamp,_⟩ := h
  have le := c.ballots.bounds _ stamp st mem'
  change term ≤ st.currentTerm at le
  omega

structure Quiet (f : Frame) (t : State) : Prop where
  pending : Stable f t .pending
  now : Stable f t .now
  seen : Stable f t .seen
  elected : Stable f t .elected
  canon : Stable f t .canon
  committed : Stable f t .committed

omit [Config.InitialConfiguration] in
theorem quiet (s : Step) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    ¬ Source s.context → Quiet s.frame s.after := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  intro no
  have prior : Now s.frame s.context.actor s.context.post := Classical.byContradiction fun h => no (.node h)
  have same := s.context.now_pre prior
  have nodes : s.after.nodes = s.frame.current.nodes := by
    change s.context.tr.post = s.context.tr.pre at same
    rw [s.context.tr.nodesEq,same]
    exact InertProfile.replace_eq s.context.inv.distinct s.context.tr.found
  have eq := StutterProfile.advance_logs_nodes nodes
  have se := (congrArg LogFacts.Ghost.seen eq).trans (StutterProfile.frozenSeen s.folded.invariant)
  have el := (congrArg LogFacts.Ghost.elected eq).trans (StutterProfile.frozenElection s.folded.invariant)
  have ca := (congrArg LogFacts.Ghost.canon eq).trans (StutterProfile.frozenCanon s.folded)
  refine ⟨fun e h => Classical.byContradiction fun g => no (.packet e h g), ?_, ?_, ?_, ?_,
    fun n l h => Classical.byContradiction fun g => no (.key n l h g)⟩
  · intro n st h
    change (n,st) ∈ s.after.nodes at h
    change (n,st) ∈ s.frame.current.nodes
    rwa [← nodes]
  · intro n o h
    simpa only [Seen,se] using h
  · intro n k l i h
    simpa only [Elected,el] using h
  · intro k l h
    simpa only [Canon,ca] using h

end
end ConsensusCoverage.HandReadersBGate
