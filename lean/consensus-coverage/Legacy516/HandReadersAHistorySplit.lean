module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersAFacts
import all ConsensusCoverage.HandReadersAPreBacking
import all ConsensusCoverage.HandReadersAElection
import all ConsensusCoverage.CommitKeys
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersA.HistorySplit

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety ActionProfile SolvedWitnesses
set_option maxRecDepth 8192
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

inductive Case where | fresh | backed | low | high | short | long

def column : Case → Classes.StepBranch
  | .fresh => .backing_split_cert_fresh
  | .backed => .backing_split_cert_backed
  | .low => .backing_split_low_pos
  | .high => .backing_split_low_neg
  | .short => .backing_split_baseLe_pos
  | .long => .backing_split_baseLe_neg

def cut (kind : Case) (commit bound k b : Nat) : Bool :=
  match kind with
  | .fresh => b == 0
  | .backed => true
  | .low => decide (k ≤ bound)
  | .high => decide (bound < k)
  | .short => decide (bound < k ∧ b ≤ commit)
  | .long => decide (bound < k ∧ commit < b)

private def certRead (kind : Case) : Reader := fun cfg before act after past =>
  let hist := before :: past
  actorRead (fun _ pre _ post => decide (pre.currentTerm < post.currentTerm)) cfg before act after past &&
  (actorRead (fun _ _ _ post => post.role == .candidate) cfg before act after past || Election.reader cfg before act after past) &&
  actorRead (fun _ pre _ post =>
    let old := CommitKeys.keys (cfg.min?.getD 0) hist
    Facts.any cfg hist fun l k b i => cut kind pre.commitIndex (post.currentTerm - 1) k b &&
      decide ((k,l.take i) ∈ old ∧ pre.log.take pre.commitIndex <+: l.take i)) cfg before act after past

def reader (kind : Case) : Reader := fun cfg before act after past =>
  match kind with
  | .backed => PreBacking.reader .covered cfg before act after past
  | .low => PreBacking.reader .prior cfg before act after past
  | .high =>
    actorRead (fun _ pre _ post => decide (pre.currentTerm < post.currentTerm) &&
      (CommitKeys.keys (cfg.min?.getD 0) (before :: past)).any fun (k,p) =>
        decide (post.currentTerm - 1 < k ∧ pre.log.take pre.commitIndex <+: p)) cfg before act after past &&
    (actorRead (fun _ _ _ post => post.role == .candidate) cfg before act after past || Election.reader cfg before act after past)
  | _ => certRead kind cfg before act after past

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)

private abbrev Result (kind : Case) := ∃ l k b i, CommitFacts f.logs l k b i ∧
  f.logs.committed k (l.take i) ∧ PreBacking.Part c <+: l.take i ∧
    cut kind c.pre.commitIndex (c.post.currentTerm - 1) k b = true

local macro "along " h:term : tactic => `(tactic| {
  have tail := $h
  repeat' first | exact tail | exact tail.1 | obtain ⟨_,tail⟩ := tail })

-- The eleven origins all transport the actor's prior log and commit index.
-- Some origins are disjunctions of two different higher-term election sites.
local macro "fromSite " c:ident site:ident log:ident i:ident bound:ident : tactic => `(tactic| {
  have source := $site
  try (change _ ∨ _ at source; rcases source with source | source)
  all_goals
    obtain ⟨term,call,_,_,_,_,spine⟩ := source
    have gate : PreBacking.Gate $c ∧ term = ($c).post.currentTerm := by
      first | exact PreBacking.local_site $c call
            | exact ⟨⟨by along call,.inr (by along call)⟩,by along call⟩
    have logEq : $log = ($c).pre.log := by along spine
    have idxEq : $i = ($c).pre.commitIndex := by along spine
    refine ⟨gate.1,logEq,idxEq,?_⟩
    first | rfl
          | have b : $bound = term - 1 := by along spine
            rw [b,gate.2] })

set_option maxHeartbeats 1800000 in
private theorem necessary (kind : Case) (yes : sig c (column kind)) : PreBacking.Gate c ∧ Result c kind := by
  cases kind
  all_goals
    rcases yes with h | h | h | h | h | h | h | h | h | h | h
    all_goals
      try (change _ ∨ _ at h; rcases h with h | h | h | h | h | h | h | h | h | h | h | h)
    all_goals
      first
      | obtain ⟨log,idx,term,p,site,l,k,i,facts,old,sub,rest⟩ := h
        have gate : PreBacking.Gate c ∧ log = c.pre.log ∧ idx = c.pre.commitIndex ∧ () = () := by
          fromSite c site log idx idx
        obtain ⟨g,rfl,rfl,_⟩ := gate
        exact ⟨g,l,k,0,i,facts,old,sub,rfl⟩
      | obtain ⟨log,idx,term,bound,p,site,tail⟩ := h
        have gate : PreBacking.Gate c ∧ log = c.pre.log ∧ idx = c.pre.commitIndex ∧ bound = c.post.currentTerm - 1 := by
          fromSite c site log idx bound
        obtain ⟨g,rfl,rfl,rfl⟩ := gate
        first
        | obtain ⟨l,k,i,facts,old,sub,side,_⟩ := tail
          refine ⟨g,l,k,0,i,facts,old,sub,?_⟩
          first | exact decide_eq_true side | exact decide_eq_true (Nat.lt_of_not_ge side)
        | obtain ⟨l,k,b,i,_,_,facts,_,_,_,_,_,old,sub,sides⟩ := tail
          refine ⟨g,l,k,b,i,facts,old,sub,?_⟩
          first | rfl | exact decide_eq_true sides.1 | exact decide_eq_true (Nat.lt_of_not_ge sides.1)
                      | exact decide_eq_true ⟨Nat.lt_of_not_ge sides.1,sides.2.1⟩
                      | exact decide_eq_true ⟨Nat.lt_of_not_ge sides.1,Nat.lt_of_not_ge sides.2.1⟩

private abbrev Root (elected : Bool) (k : Nat) (p : List Entry) :=
  if elected then (reach% step_backing_split_cert_fresh[3]) f t c c.pre.log c.pre.commitIndex k p
  else (reach% step_backing_split_cert_fresh[0]) f t c c.pre.log c.pre.commitIndex k p
private abbrev RootWithBound (elected : Bool) (k : Nat) (p : List Entry) :=
  if elected then (reach% step_backing_split_cert_backed[3]) f t c c.pre.log c.pre.commitIndex k (c.post.currentTerm-1) p
  else (reach% step_backing_split_cert_backed[0]) f t c c.pre.log c.pre.commitIndex k (c.post.currentTerm-1) p

private theorem roots {k p} (gate : PreBacking.Gate c) (old : Committed f k p) (sub : PreBacking.Part c <+: p) :
    ∃ e, Root c e k p ∧ RootWithBound c e k p := by
  have all_ := c.inv.commit_backed c.actor c.pre c.pre_now
  have lt := gate.1
  have pack := And.intro old (And.intro (Nat.le_refl k) sub)
  obtain call | call := PreBacking.sources c gate
  · refine ⟨false,?_,?_⟩
    all_goals
      refine ⟨_,call,all_.1,all_.2,k,.inr ⟨k,p,pack⟩,⟨k,p,pack⟩,⟨p,pack⟩,pack,
        old,pack.2,Nat.le_refl _,sub,lt,old,rfl,?_⟩ <;> first | rfl | exact ⟨rfl,rfl⟩
  · refine ⟨true,?_,?_⟩
    all_goals
      refine ⟨_,call,all_.1,all_.2,k,.inr ⟨k,p,pack⟩,⟨k,p,pack⟩,⟨p,pack⟩,pack,
        old,pack.2,Nat.le_refl _,sub,lt,old,rfl,?_⟩ <;> first | rfl | exact ⟨rfl,rfl⟩

private theorem sufficient (kind : Case) (gate : PreBacking.Gate c) (h : Result c kind) : sig c (column kind) := by
  obtain ⟨l,k,b,i,facts,old,sub,guard⟩ := h
  obtain ⟨e,root,full⟩ := roots c gate old sub
  have bound := c.frontier_pre
  have len := List.length_take_of_le bound
  have chain := c.inv.commitChains _ _ old
  have within := take_prefix_take l facts.baseLe
  have ih := fun (m : f.logs.committed k (l.take i)) (p : PreBacking.Part c <+: l.take i) =>
    backing_split (bound := c.post.currentTerm-1) chain m p c.frontier_pre
  cases e <;> cases kind
  all_goals
    first
    | change sig c .backing_split_low_pos
      iterate 11 right
    | change sig c .backing_split_low_neg
      iterate 11 right
    | skip
    first
    | left; first | refine ⟨_,_,_,_,root,?_⟩ | refine ⟨_,_,_,_,_,full,?_⟩
    | iterate 3 right
      left
      first | refine ⟨_,_,_,_,root,?_⟩ | refine ⟨_,_,_,_,_,full,?_⟩
    first
    | have zero : b = 0 := beq_iff_eq.mp guard
      subst b
      exact ⟨l,k,i,facts,old,sub,sub,bound,len,chain,old⟩
    | refine ⟨l,k,b,i,k,l.take i,facts,old,chain,Nat.le_refl _,within,ih,old,sub,?_⟩
      first | exact ⟨sub,bound,len,chain,old⟩
            | exact ⟨of_decide_eq_true guard,sub,bound,len,chain,old⟩
            | exact ⟨Nat.not_le_of_gt (of_decide_eq_true guard),sub,bound,len,chain,old⟩
            | have g := of_decide_eq_true guard
              first | exact ⟨Nat.not_le_of_gt g.1,g.2,sub,bound,len,chain,old⟩
                    | exact ⟨Nat.not_le_of_gt g.1,Nat.not_le_of_gt g.2,sub,bound,len,chain,old⟩
private theorem keyed (kind : Case) (q : Nat → Prop)
    (guard : ∀ k b, cut kind c.pre.commitIndex (c.post.currentTerm - 1) k b = true ↔ q k) :
    Result c kind ↔ ∃ k p, Committed f k p ∧ q k ∧ PreBacking.Part c <+: p := by
  constructor
  · rintro ⟨l,k,b,i,_,old,sub,side⟩
    exact ⟨_,_,old,(guard k b).mp side,sub⟩
  · rintro ⟨k,p,old,side,sub⟩
    have tip : ∃ l b i, CommitFacts f.logs l k b i ∧ p = l.take i := by
      cases c.inv.commitChains k p old with
      | fresh f => exact ⟨_,_,_,f,rfl⟩
      | backed f _ _ _ _ => exact ⟨_,_,_,f,rfl⟩
    obtain ⟨l,b,i,facts,rfl⟩ := tip
    exact ⟨_,_,_,_,facts,old,sub,(guard k b).mpr side⟩
end

private def certExact (kind : Case) : Exact (column kind) where
  eval := certRead kind
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    let c := s.context
    have elect := Bool.eq_iff_iff.mp (Election.exactReader.eq_label s)
    rw [label_true,holds,sig_iff] at elect
    change step_led_after_elected_after_inr _ _ c ↔ Election.reader s.cfg s.before s.act s.after s.past = true at elect
    rw [Election.iff_election] at elect
    apply Bool.eq_iff_iff.mpr
    simp only [label_true,holds,sig_iff,certRead,Bool.and_eq_true,Bool.or_eq_true,actorRead_at,Facts.any_iff,
      decide_eq_true_eq,beq_iff_eq,CommitKeys.step_mem,←elect]
    change sig c (column kind) ↔ _
    rw [show sig c (column kind) ↔ PreBacking.Gate c ∧ Result c kind from
      ⟨necessary c kind,fun g => sufficient c kind g.1 g.2⟩]
    simp only [Result,PreBacking.Gate,PreBacking.Part,CommitKeys.committedBefore,c]
    grind

def exactReader (kind : Case) : Exact (column kind) where
  eval := reader kind
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    let c := s.context
    have mode (k : Case) : sig c (column k) ↔ PreBacking.Gate c ∧ Result c k :=
      ⟨necessary c k,fun h => sufficient c k h.1 h.2⟩
    have pre (k : PreBacking.Case) : sig c (PreBacking.column k) ↔ PreBacking.Gate c ∧ PreBacking.Condition c k :=
      ⟨PreBacking.necessary c k,fun h => PreBacking.sufficient c k h.1 h.2⟩
    cases kind
    case fresh | short | long => exact (certExact _).eq_label s
    case backed =>
      refine Eq.trans ?_ ((PreBacking.exactReader .covered).eq_label s)
      apply Bool.eq_iff_iff.mpr
      rw [label_true,label_true,holds,holds,sig_iff,sig_iff,mode,pre,
        keyed c .backed (fun _ => True) (by intros; simp [cut])]
      simp only [true_and,PreBacking.Condition]
    case low =>
      refine Eq.trans ?_ ((PreBacking.exactReader .prior).eq_label s)
      apply Bool.eq_iff_iff.mpr
      rw [label_true,label_true,holds,holds,sig_iff,sig_iff,mode,pre,
        keyed c .low (fun k => k ≤ c.post.currentTerm - 1) (by intros; simp [cut])]
      rfl
    case high =>
      have elect := Bool.eq_iff_iff.mp (Election.exactReader.eq_label s)
      rw [label_true,holds,sig_iff] at elect
      change step_led_after_elected_after_inr _ _ c ↔ Election.reader s.cfg s.before s.act s.after s.past = true at elect
      rw [Election.iff_election] at elect
      apply Bool.eq_iff_iff.mpr
      rw [label_true,holds,sig_iff,mode,keyed c .high (fun k => c.post.currentTerm - 1 < k) (by intros; simp [cut])]
      simp only [reader,Bool.and_eq_true,Bool.or_eq_true,actorRead_at,decide_eq_true_eq,beq_iff_eq,
        List.any_eq_true,Prod.exists,CommitKeys.step_mem,←elect,PreBacking.Gate,PreBacking.Part,CommitKeys.committedBefore,Committed,c]
      grind

end ConsensusCoverage.HandReadersA.HistorySplit
