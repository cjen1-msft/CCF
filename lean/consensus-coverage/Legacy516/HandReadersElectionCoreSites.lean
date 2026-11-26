module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersElectionPairs
import all ConsensusCoverage.HandReadersElectionCarried
import all ConsensusCoverage.DeepCarriedCases
import all ConsensusCoverage.BackingArms
import all ConsensusCoverage.ReachPath
public meta import ConsensusCoverage.ReachPath
public meta import Lean
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersElection.CoreSites

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety Ledger SolvedWitnesses
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxRecDepth 8192

open Lean Elab Term Meta in
local elab "coreSites% " a:term:arg* : term => do
  let root := ``step_core_covered_pos
  let sites := ReachPath.children root.getPrefix (← getConstInfo root).value!
  let mut arms := #[]
  for site in sites do
    let name := mkIdent site
    arms := arms.push (← elabTerm (← `($name $a*)) (some (.sort .zero)))
  return arms.pop.foldr (mkApp2 (mkConst ``Or)) arms.back!

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)

abbrev Sites (g : LogFacts.Ghost) (n k b i later d bound j : Nat) (l log : List Entry) :=
  coreSites% f t c g n k b i later d bound j l log

local macro "along " h:term : tactic => `(tactic| {
  have spine := $h
  repeat' first | exact spine | exact spine.1
                | change _ ∧ _ at spine; obtain ⟨_,spine⟩ := spine
                | change Exists _ at spine; obtain ⟨_,spine⟩ := spine })

theorem necessary {g n k b i later d bound j l log} (site : Sites c g n k b i later d bound j l log) :
    Pairs.Pair c l k b i log d ∧ l.take (max b d) = log.take (max b d) := by
  rcases site with h | h | h | h | h | h | h | h | h
  all_goals repeat' (change _ ∨ _ at h; rcases h with h | h)
  all_goals
    first
    | obtain ⟨leader,st,src,_,win,lt,_,eq,tail⟩ := h
      obtain rfl : l = st.log := by along tail
      exact ⟨.inr ⟨leader,st,n,later,(Pairs.ticket_iff c).mp src,rfl,win,lt⟩,
        beq_iff_eq.mp (Carried.shorten eq.1 eq.2.1 eq.2.2)⟩
    | obtain ⟨_,_,src,rest⟩ := h
      have elect : ElectStep f t n later log d := src.2.2.1
      obtain ⟨rfl,rfl,rfl,_,rfl,_⟩ := c.electStep elect
      first
      | obtain ⟨facts,old,lt,_,eq,tail⟩ := rest
        obtain rfl : b = 0 := by along tail
        exact ⟨.inl ⟨elect,rfl,rfl,facts,old,lt⟩,beq_iff_eq.mp (Carried.shorten eq.1 eq.2.1 eq.2.2)⟩
      | obtain ⟨_,_,facts,_,_,_,_,_,old,lt,_,eq,_⟩ := rest
        exact ⟨.inl ⟨elect,rfl,rfl,facts,old,lt⟩,beq_iff_eq.mp (Carried.shorten eq.1 eq.2.1 eq.2.2)⟩

structure Ready (l : List Entry) (k b i : Nat) (log : List Entry) (d j : Nat) where
  ghost : LogFacts.Ghost
  node : NodeID
  later : Nat
  bound : Nat
  site : (reach% step_core_covered_pos[0]) f t c ghost node k b i later d bound j l log ∨
    (reach% step_core_covered_pos[8]) f t c ghost node k b i later d bound j l log
  facts : CommitFacts ghost l k b i
  campaign : CampaignFacts ghost (f.advance t).votes ghost.canon node later log d bound
  earlier : k < later
  clean : ∀ e a, k < e → e ≤ bound → ghost.canon e a → l.take i <+: a
  chain : LogFacts.Chain ghost
  window : later - 1 ≤ bound
  sub : l.take i <+: log

theorem readyAt {l k b i log d j} (pair : Pairs.Pair c l k b i log d) (eq : l.take j = log.take j)
    (bl : b ≤ j) (dl : d ≤ j) : Nonempty (Ready c l k b i log d j) := by
  have wit := And.intro eq (And.intro bl dl)
  rcases pair with ⟨elect,rfl,rfl,facts,old,lt⟩ | ⟨n,st,node,later,ticket,rfl,win,lt⟩
  · have root := DeepCarriedCases.source c old lt elect
    have camp := root.2.2.2.2
    have back : c.pre.commitIndex = 0 ∨ ∃ e p, f.logs.committed e p ∧ c.pre.log.take c.pre.commitIndex <+: p :=
      (c.elect_backed elect).imp_right fun ⟨e,p,m,_,sub⟩ => ⟨e,p,m,sub⟩
    have sub := c.old_in_new elect old lt
    have high (_ : b < c.pre.commitIndex) : ∃ p, c.pre.log.take c.pre.commitIndex <+: p ∧
        (l.take i <+: p ∨ p <+: l.take i) := ⟨_,List.take_prefix _ _,.inl sub⟩
    have chain := c.inv.commitChains _ _ old
    refine ⟨⟨f.logs,c.actor,c.post.currentTerm,c.post.currentTerm,.inr (.inr ?_),facts,camp,lt,
      (fun e a above _ canon => c.inv.later _ e _ a old canon above),c.inv.chains,Nat.sub_le _ _,sub⟩⟩
    exact ⟨k,l.take i,root,k,l.take i,facts,old,chain,Nat.le_refl _,take_prefix_take l facts.baseLe,
      (fun m h => c.old_in_new elect m h),old,lt,⟨_,wit⟩,wit,eq,wit.2,wit.2.1,wit.2.2,camp,back,
      lt,high,chain,old,rfl,rfl⟩
  · obtain ⟨step,back,_⟩ := id ticket
    have parent := (Pairs.ticket_iff c).mpr ticket
    have key : Committed (f.advance t) k (st.log.take i) := .inr ⟨_,_,_,_,step,rfl,back⟩
    have facts := BackingArms.commitFacts c step
    have camp := c.rankedElections _ _ _ _ win
    have sub := c.completeness _ _ _ _ _ _ key win lt
    have low (_ : d ≤ b) := (take_prefix_take st.log facts.baseLe).trans sub
    have high (_ : b < d) : ∃ p, log.take d <+: p ∧ (st.log.take i <+: p ∨ p <+: st.log.take i) :=
      ⟨_,List.take_prefix _ _,.inl sub⟩
    have clean := fun e a above (_ : e ≤ later-1) canon => c.inv_step.later _ e _ a key canon above
    refine ⟨⟨_,node,later,later-1,.inl (.inl ?_),facts,camp,lt,clean,c.inv_step.chains,Nat.le_refl _,sub⟩⟩
    exact ⟨n,st,parent,(fun m _ v l d w lt => c.completeness _ _ v m l d key w lt),win,lt,⟨_,wit⟩,wit,
      eq,wit.2,wit.2.1,wit.2.2,step,back,facts.floor,facts,take_signature facts.signature,win,camp,
      clean,low,high,rfl,rfl,rfl⟩

theorem ready {l k b i log d} (pair : Pairs.Pair c l k b i log d) (eq : l.take (max b d) = log.take (max b d)) :
    Nonempty (Ready c l k b i log d (max b d)) :=
  readyAt c pair eq (Nat.le_max_left _ _) (Nat.le_max_right _ _)
end

end ConsensusCoverage.HandReadersElection.CoreSites
