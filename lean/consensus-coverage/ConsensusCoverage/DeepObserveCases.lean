module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.DeepSchedules
import all ConsensusCoverage.FrontierWitnesses
import all ConsensusCoverage.QueueSamplesA
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.DeepObserveCases

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety
open ActionProfile ReadersAtoms GuardedDomain SolvedWitnesses QueueSamplesA

set_option maxRecDepth 8192

inductive Test where | primary | notPrimary | higher | stable | other

private def column : Bool → Test → Classes.StepBranch
  | true, .primary => .observeTerm_log_primary_pos
  | true, .notPrimary => .observeTerm_log_primary_neg
  | true, .higher => .observeTerm_log_newer_pos
  | true, .stable => .observeTerm_log_newer_neg
  | true, .other => .observeTerm_log_message_other
  | false, .primary => .observeTerm_commitIndex_primary_pos
  | false, .notPrimary => .observeTerm_commitIndex_primary_neg
  | false, .higher => .observeTerm_commitIndex_newer_pos
  | false, .stable => .observeTerm_commitIndex_newer_neg
  | false, .other => .observeTerm_commitIndex_message_other

private def condition (st : NodeState) (q : AppendEntriesRequest) : Test → Bool
  | .primary => decide (st.role = .primary)
  | .notPrimary => decide (st.role ≠ .primary)
  | .higher => decide (st.currentTerm < q.term)
  | .stable => decide (¬st.currentTerm < q.term)
  | .other => true

private def check (s : Step) (k : Test) : Bool :=
  (ofXAction s.cfg s.before s.after s.past s.act).any fun x => x.base.changed &&
    match x.event with
    | .receive _ (.appendEntriesRequest q) => condition x.base.pre q k
    | _ => false

private theorem casesAt [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)
    (fresh : ¬ Now f c.actor c.post) (n : NodeID) (q : AppendEntriesRequest)
    (ev : c.event = .receive n (.appendEntriesRequest q)) (k : Test)
    (h : condition c.pre q k = true) (log : Bool) : sig c (column log k) := by
  let m := Message.appendEntriesRequest q
  have frontier := c.inv.frontier _ _ c.pre_now
  have origin : (reach% step_observeTerm_log_message_other[0,0]) f t c c.actor c.pre n m :=
    ⟨c.event,c.post,c.tr.outputs,⟨c.post_now,c.post_now,c.post_now,fresh,rfl,rfl,rfl,rfl,rfl⟩,
      ev,ev ▸ c.tr.ran,frontier,c.tr.ran⟩
  have forRole : (reach% step_observeTerm_log_primary_pos[0]) f t c c.pre :=
    Or.inl ⟨c.actor,n,m,origin,fun h => Bool.noConfusion h.1,q,rfl,
      fun h => Bool.noConfusion h.1,frontier⟩
  have forOrder : (reach% step_observeTerm_log_newer_pos[0]) f t c c.pre m :=
    Or.inl ⟨c.actor,n,m,origin,fun h => Bool.noConfusion h.1,q,rfl,
      fun h => Bool.noConfusion h.1,frontier,rfl⟩
  have forMessage : (reach% step_observeTerm_log_message_other[0]) f t c m :=
    Or.inl ⟨c.actor,c.pre,n,m,origin,fun h => Bool.noConfusion h.1,q,rfl,
      fun h => Bool.noConfusion h.1,frontier,rfl⟩
  have notNom : ∀ u, m = .proposeRequestVoteRequest u → False := fun _ h => Message.noConfusion h
  have notAck : ∀ u, m = .appendEntriesResponse u → False := fun _ h => Message.noConfusion h
  cases k <;> cases log
  all_goals first
    | exact Or.inl ⟨m,forMessage,notNom,notAck,notNom,notAck⟩
    | exact Or.inl ⟨c.pre,forRole,of_decide_eq_true h⟩
    | exact Or.inr (Or.inr (Or.inl ⟨c.pre,m,forOrder,notNom,notAck,notNom,notAck,of_decide_eq_true h⟩))

private theorem correct (s : Step) (k : Test) (log : Bool) (yes : check s k = true) :
    label s (.step (column log k)) = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  obtain ⟨x,made,ok⟩ := ofXAction_matches s
  simp only [check,made,Option.any_some,Bool.and_eq_true] at yes
  obtain ⟨changed,yes⟩ := yes
  have fresh : ¬ Now s.frame c.actor c.post := fun h =>
    Bool.noConfusion (changed.symm.trans ((View.old_post ok.1).mp h))
  split at yes <;> try contradiction
  rename_i n q ev
  rw [← View.pre_eq ok.1] at yes
  exact (label_true s _).mpr ((sig_iff c _).mpr (casesAt c fresh n q ((X.event_eq ok).trans ev) k yes log))

open FrontierRows DeepSchedules in
local macro "observe_at " k:term:arg sc:term:arg i:num : term =>
  `([true,false].map fun log => checked (column log $k) (selected $sc (by unfold Run.valid; decide) $i)
    (check · $k) (by decide +kernel) (correct · $k log))

open DeepSchedules in
def certificates : List Certificate :=
  observe_at .primary divergent 10 ++ observe_at .notPrimary installLater 1 ++
  observe_at .higher divergent 10 ++ observe_at .stable installLater 1 ++ observe_at .other installLater 1

end ConsensusCoverage.DeepObserveCases
