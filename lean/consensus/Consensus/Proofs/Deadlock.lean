module

public import Consensus.Model
public import Consensus.Properties.Bootstrap

import all Consensus.Proofs.SafetyInvariant
import CCF.Proofs.Finset

/-!
Deadlock freedom after bootstrapping: once a signature has been committed,
some node can always act.
-/

namespace Consensus.Proofs.Deadlock.Total

open CCF
open Model.Node

/-- `m` never disables the step, whatever has already been emitted. -/
private def Total {α : Type} (m : NodeEffect α) : Prop :=
  forall outputs, (m.run outputs).isSome

private theorem pure' {α : Type} (value : α) : Total (pure value : NodeEffect α) :=
  fun _ => rfl

private theorem bind' {α β : Type} {m : NodeEffect α} {f : α -> NodeEffect β}
    (first : Total m) (rest : forall value, Total (f value))
    : Total (m >>= f) := by
  intro outputs
  simp only [StateT.run_bind]
  obtain ⟨⟨value, middle⟩, ran⟩ := Option.isSome_iff_exists.mp (first outputs)
  simp only [ran]
  exact rest value middle

private theorem send (self target : NodeID) (payload : Message)
    : Total ((Capabilities.record self).send payload target) := by
  intro outputs
  simp [Capabilities.record, modify, modifyGet, StateT.run]
  rfl

private theorem ite' {α : Type} {c : Prop} [Decidable c] {m n : NodeEffect α}
    (yes : c -> Total m) (no : Not c -> Total n)
    : Total (if c then m else n) := by
  split
  · exact yes ‹_›
  · exact no ‹_›

private theorem guard_bind {α : Type} {c : Prop} [Decidable c] {m : NodeEffect α}
    (holds : c) (rest : Total m)
    : Total (guard c >>= fun _ => m) := by
  intro outputs
  simpa [guard, holds] using rest outputs

private theorem forIn' {β γ : Type} {items : List γ} {init : β}
    {f : γ -> β -> NodeEffect (ForInStep β)}
    (each : forall item value, Total (f item value))
    : Total (forIn items init f) := by
  induction items generalizing init with
  | nil => exact pure' init
  | cons head tail ih =>
      rw [List.forIn_cons]
      refine bind' (each head init) fun step => ?_
      cases step with
      | done value => exact pure' value
      | yield value => exact ih

end Consensus.Proofs.Deadlock.Total

namespace Consensus.Proofs.Deadlock.Total

open CCF
open Model.Node
variable (self : NodeID)

private theorem nominateSuccessor (state : NodeState) (primary : state.role = .primary)
    (excluded : Finset NodeID := ∅)
    : Total
        (Model.Node.nominateSuccessor (Capabilities.record self) state self
          excluded) := by
  unfold Model.Node.nominateSuccessor
  refine guard_bind primary ?_
  split
  · exact bind' (send _ _ _) fun _ => pure' _
  · exact pure' _

private theorem advanceCommit (state : NodeState)
    : Total (Model.Node.advanceCommit (Capabilities.record self) state self) := by
  unfold Model.Node.advanceCommit
  refine ite' (fun _ => pure' _) fun _ => ?_
  refine ite' (fun _ => ?_) fun _ => pure' _
  refine ite' (fun primary => ?_) fun _ => pure' _
  exact bind' (nominateSuccessor self state primary _) fun _ => pure' _

private theorem broadcastToOthers (state : NodeState) (message : Message)
    : Total
        (Model.Node.broadcastToOthers (Capabilities.record self) self state message) := by
  unfold Model.Node.broadcastToOthers
  exact bind' (forIn' fun _ _ => bind' (send _ _ _) fun _ => pure' _) fun _ => pure' _

private theorem becomePrimary (state : NodeState)
    : Total (Model.Node.becomePrimary (Capabilities.record self) self state) := by
  unfold Model.Node.becomePrimary
  exact bind' (advanceCommit self _) fun _ =>
    bind' (forIn' fun _ _ => bind' (send _ _ _) fun _ => pure' _) fun _ => pure' _

private theorem electIfQuorum (state : NodeState)
    : Total (Model.Node.electIfQuorum (Capabilities.record self) self state) := by
  unfold Model.Node.electIfQuorum
  exact ite' (fun _ => becomePrimary self _) fun _ => pure' _

private theorem becomeCandidate (state : NodeState)
    : Total (Model.Node.becomeCandidate (Capabilities.record self) state self) := by
  unfold Model.Node.becomeCandidate
  exact bind' (electIfQuorum self _) fun _ =>
    bind' (broadcastToOthers self _ _) fun _ => pure' _

private theorem becomePreVoteCandidate (state : NodeState)
    : Total
        (Model.Node.becomePreVoteCandidate (Capabilities.record self) state self) := by
  unfold Model.Node.becomePreVoteCandidate
  exact ite' (fun _ => becomeCandidate self _) fun _ =>
    bind' (broadcastToOthers self _ _) fun _ => pure' _

private theorem startElection (state : NodeState) (eligible : canStartElection state self)
    : Total (Model.Node.startElection (Capabilities.record self) state self) := by
  unfold Model.Node.startElection
  exact guard_bind eligible (becomePreVoteCandidate self _)

end Consensus.Proofs.Deadlock.Total

namespace Consensus.Proofs.Deadlock

open CCF CCF.MultiNodeTransitionSystem
open Model.Node

/-- A local input other than initialization that the node's step accepts is an
enabled global action. -/
private theorem enabled_of_total {config : Finset NodeID} {nodes : List NodeID}
    {state : Model.State} {node : NodeID} {local_ : NodeState} {input : Input}
    (distinct : (state.nodes.map Prod.fst).Nodup) (member : (node, local_) ∈ state.nodes)
    (notInit : forall entries, Not (input = .initAsBackup entries))
    (total
      : Total.Total
          (Model.Node.step (Capabilities.record node) node local_ (.internal input)))
    : exists action nextState,
        (Model.transitionSystem config nodes).step state action = some nextState := by
  obtain ⟨⟨after, outputs⟩, ran⟩ := Option.isSome_iff_exists.mp (total {})
  refine ⟨.local node input, {
    nodes := state.nodes.map fun entry => if entry.1 == node then (node, after) else entry
    network := state.network ++ outputs.outgoing
  }, ?_⟩
  let _ : Config.InitialConfiguration := ⟨config⟩
  have found := Direct.nodeState_of_mem distinct member
  have global : Model.networkStep config state (.local node input)
      = next (Model.protocol config) state (.local node input) := by
    unfold Model.networkStep
    split
    · rename_i entries eq
      cases eq
      exact (notInit entries rfl).elim
    · rfl
  simp only [Model.transitionSystem, global]
  simp [next, Model.protocol, found, ran]

/-- A primary can always nominate a successor; an eligible node can campaign. -/
private theorem enabled_of_member {config : Finset NodeID} {nodes : List NodeID}
    {state : Model.State} {node : NodeID} {local_ : NodeState}
    (distinct : (state.nodes.map Prod.fst).Nodup) (member : (node, local_) ∈ state.nodes)
    (acts : local_.role = .primary \/ canStartElection local_ node)
    : exists action nextState,
        (Model.transitionSystem config nodes).step state action = some nextState := by
  rcases acts with primary | eligible
  · exact enabled_of_total distinct member (input := .nominateSuccessor) (by simp)
      (Total.nominateSuccessor node local_ primary)
  · exact enabled_of_total distinct member (input := .timeout .election) (by simp)
      (Total.startElection node local_ eligible)

end Consensus.Proofs.Deadlock

namespace Consensus.Proofs.Deadlock

open CCF
open Model.Node

private theorem mem_retiredCommittedNodes_foldl {node : NodeID} (log : List Entry)
    (init : Finset NodeID)
    : node
        ∈ log.foldl
            (fun retired entry =>
              retired ∪ entry.content.metadata.retirementConfirmations)
            init
      <-> node ∈ init
          \/ exists entry,
              entry ∈ log /\ node ∈ entry.content.metadata.retirementConfirmations := by
  induction log generalizing init with
  | nil => simp
  | cons head tail ih =>
      simp only [List.foldl_cons, ih, Finset.mem_union, List.mem_cons]
      constructor
      · rintro ((old | new) | ⟨entry, member, confirmed⟩)
        · exact Or.inl old
        · exact Or.inr ⟨head, Or.inl rfl, new⟩
        · exact Or.inr ⟨entry, Or.inr member, confirmed⟩
      · rintro (old | ⟨entry, rfl | member, confirmed⟩)
        · exact Or.inl (Or.inl old)
        · exact Or.inl (Or.inr confirmed)
        · exact Or.inr ⟨entry, member, confirmed⟩

/-- A node is retired-committed by a log exactly when some entry confirms it. -/
private theorem mem_retiredCommittedNodes {node : NodeID} {log : List Entry}
    : node ∈ retiredCommittedNodes log
      <-> exists entry,
            entry ∈ log /\ node ∈ entry.content.metadata.retirementConfirmations := by
  unfold retiredCommittedNodes
  rw [mem_retiredCommittedNodes_foldl]
  simp

private theorem retiredCommittedNodes_mono {left right : List Entry}
    (sub : left <+: right) {node : NodeID} (member : node ∈ retiredCommittedNodes left)
    : node ∈ retiredCommittedNodes right := by
  obtain ⟨entry, inLeft, confirmed⟩ := mem_retiredCommittedNodes.mp member
  exact mem_retiredCommittedNodes.mpr ⟨entry, sub.subset inLeft, confirmed⟩

end Consensus.Proofs.Deadlock

namespace Consensus.Proofs.Deadlock.Local

open CCF
open Model.Node
open Direct (Extends Keeps)

/--
How one step may change a node's retirement latch and role: the committed log
extends, a latch is set only when the committed log confirms the node, and the
role becomes `none` only by that latch.
-/
private def Rel (self : NodeID) (before after : NodeState) : Prop :=
  Extends before after
  /\ (before.retiredCommittedIndex.isSome
      -> after.retiredCommittedIndex = before.retiredCommittedIndex)
  /\ (after.retiredCommittedIndex.isSome
      -> before.retiredCommittedIndex.isSome
          \/ self ∈ retiredCommittedNodes after.committedLog)
  /\ (after.role = .none
      -> (before.role = .none /\ after.currentTerm <= before.currentTerm)
          \/ after.retiredCommittedIndex.isSome)

variable {self : NodeID}

private theorem Rel.refl (state : NodeState) : Rel self state state :=
  ⟨
    Extends.refl _,
    fun _ => rfl,
    fun some => Or.inl some,
    fun none => Or.inl ⟨none, (Nat.le_refl _)⟩
  ⟩

private theorem Rel.trans {first second third : NodeState}
    (left : Rel self first second) (right : Rel self second third)
    : Rel self first third := by
  obtain ⟨extendsLeft, keepLeft, setLeft, roleLeft⟩ := left
  obtain ⟨extendsRight, keepRight, setRight, roleRight⟩ := right
  refine ⟨extendsLeft.trans extendsRight, fun some => ?_, fun some => ?_, fun none => ?_⟩
  · have middle := keepLeft some
    rw [keepRight (middle ▸ some), middle]
  · rcases setRight some with middle | confirmed
    · rcases setLeft middle with old | confirmed
      · exact Or.inl old
      · exact Or.inr (retiredCommittedNodes_mono extendsRight.committedLog confirmed)
    · exact Or.inr confirmed
  · rcases roleRight none with ⟨middleNone, le⟩ | some
    · rcases roleLeft middleNone with ⟨firstNone, le'⟩ | middleSome
      · exact Or.inl ⟨firstNone, Nat.le_trans le le'⟩
      · exact Or.inr (keepRight middleSome ▸ middleSome)
    · exact Or.inr some

/-- A step that keeps the latch, extends the committed log and does not newly
clear the role. -/
private theorem Rel.of_fields {before after : NodeState} (extended : Extends before after)
    (latch : after.retiredCommittedIndex = before.retiredCommittedIndex)
    (role
      : after.role = .none
        -> before.role = .none /\ after.currentTerm <= before.currentTerm)
    : Rel self before after :=
  ⟨
    extended,
    fun _ => latch,
    fun some => Or.inl (latch ▸ some),
    fun none => Or.inl (role none)
  ⟩

private theorem Rel.same {before after : NodeState} (logEq : after.log = before.log)
    (commitEq : after.commitIndex = before.commitIndex)
    (latch : after.retiredCommittedIndex = before.retiredCommittedIndex)
    (roleEq : after.role = before.role) (termEq : after.currentTerm = before.currentTerm)
    : Rel self before after :=
  Rel.of_fields (Extends.of_log logEq commitEq) latch
    fun none =>
      ⟨roleEq ▸ none, Nat.le_of_eq termEq⟩

/-- A step whose resulting role is not `none`. -/
private theorem Rel.active {before after : NodeState} (logEq : after.log = before.log)
    (commitEq : after.commitIndex = before.commitIndex)
    (latch : after.retiredCommittedIndex = before.retiredCommittedIndex)
    (role : Not (after.role = .none))
    : Rel self before after :=
  Rel.of_fields (Extends.of_log logEq commitEq) latch fun none => (role none).elim

/-- Being retired-committed requires the retirement latch. -/
private theorem latch_of_retired {state : NodeState}
    (retired : state.isRetiredCommitted self)
    : state.retiredCommittedIndex.isSome := by
  revert retired
  unfold NodeState.isRetiredCommitted NodeState.retirement
  dsimp only
  split
  · simp
  · repeat' split
    all_goals simp_all

private theorem Rel.recordCommit (state : NodeState) {index : Nat}
    (grows : state.commitIndex <= index)
    : Rel self state (state.recordCommit self index) := by
  unfold NodeState.recordCommit
  dsimp only
  have extended : Extends state
      { state with
          commitIndex := index
          retiredCommittedIndex :=
            state.retiredCommittedIndex.orElse fun _ =>
              firstLogIndexAfter (state.log.take index) 0
                fun content => decide (self ∈ content.metadata.retirementConfirmations) } :=
    ⟨grows, List.take_prefix _ _⟩
  have latchKeep : state.retiredCommittedIndex.isSome
      -> (state.retiredCommittedIndex.orElse fun _ =>
            firstLogIndexAfter (state.log.take index) 0
              fun content => decide (self ∈ content.metadata.retirementConfirmations))
        = state.retiredCommittedIndex := by
    intro some
    obtain ⟨value, eq⟩ := Option.isSome_iff_exists.mp some
    rw [eq]
    rfl
  have latchSet : (state.retiredCommittedIndex.orElse fun _ =>
        firstLogIndexAfter (state.log.take index) 0
          fun content => decide (self ∈ content.metadata.retirementConfirmations)).isSome
      -> state.retiredCommittedIndex.isSome
          \/ self ∈ retiredCommittedNodes (state.log.take index) := by
    intro some
    cases old : state.retiredCommittedIndex with
    | some _ => exact Or.inl rfl
    | none =>
        right
        rw [old] at some
        simp only [Option.orElse] at some
        obtain ⟨found, eq⟩ := Option.isSome_iff_exists.mp some
        unfold firstLogIndexAfter at eq
        obtain ⟨pair, located, -⟩ := Option.map_eq_some_iff.mp eq
        have holds := List.find?_some located
        have member := List.mem_of_find?_eq_some located
        obtain ⟨entry, position⟩ := pair
        simp only [Bool.and_eq_true, decide_eq_true_eq] at holds
        exact mem_retiredCommittedNodes.mpr
          ⟨entry, List.fst_mem_of_mem_zipIdx member, holds.2⟩
  split
  · next retiring =>
      exact ⟨extended, fun some => latchKeep some, fun some => latchSet some,
        fun _ => Or.inr (latch_of_retired retiring.2)⟩
  · exact ⟨extended, fun some => latchKeep some, fun some => latchSet some,
      fun none => Or.inl ⟨none, (Nat.le_refl _)⟩⟩

end Consensus.Proofs.Deadlock.Local

namespace Consensus.Proofs.Deadlock.Local

open CCF
open Model.Node
open Direct (Extends Keeps)
section Handlers
variable (caps : Caps) (self : NodeID)

private theorem Rel.advanced (state : NodeState)
    : Keeps (Rel self state) (Model.Node.advanceCommit caps state self) := by
  unfold Model.Node.advanceCommit
  refine Keeps.ite' (fun _ => Keeps.pure' (Rel.refl _)) fun ahead => ?_
  have advanced : Rel self state (state.recordCommit self (highestCommittableIndex state self)) :=
    Rel.recordCommit state (Nat.le_of_lt (Nat.lt_of_not_le ahead))
  dsimp only
  exact Keeps.ite'
    (fun _ => Keeps.ite' (fun _ => Keeps.seq' fun _ => Keeps.pure' advanced)
      fun _ => Keeps.pure' advanced)
    fun _ => Keeps.pure' advanced

private theorem Rel.appendEntry (state : NodeState) (content : EntryContent)
    : Keeps (Rel self state) (Model.Node.appendEntry caps self state content) := by
  unfold Model.Node.appendEntry
  simp only [pure_bind]
  repeat'
    first
    | exact Keeps.pure' (Rel.of_fields
        ((Extends.append _).trans (Extends.of_log rfl rfl)) rfl
        fun none => ⟨none, (Nat.le_refl _)⟩)
    | refine Keeps.ite' (fun _ => ?_) fun _ => ?_
    | refine Keeps.seq' fun _ => ?_
    | split

private theorem Rel.becomePrimary (state : NodeState)
    : Keeps (Rel self state) (Model.Node.becomePrimary caps self state) := by
  unfold Model.Node.becomePrimary Model.Node.primaryState
  have promoted : Rel self state
      {
        state with
          role := .primary
          log :=
            if state.commitIndex > 0 then state.log.take (lastCommittableIndex state)
            else state.log
          primaryKnown := true
          sentIndex := fun _ =>
            (if state.commitIndex > 0 then state.log.take (lastCommittableIndex state)
              else state.log).length
          matchIndex := fun _ => 0
      } := by
    refine Rel.of_fields ?_ rfl fun none => nomatch none
    split
    · exact Extends.of_prefix (by unfold lastCommittableIndex; exact Nat.le_max_left _ _)
        (List.prefix_refl _) (Nat.le_refl _)
    · exact Extends.of_log rfl rfl
  exact Keeps.bind' (Rel.advanced caps self _) fun _ kept =>
    Keeps.seq' fun _ => Keeps.pure' (promoted.trans kept)

private theorem Rel.electIfQuorum (state : NodeState)
    : Keeps (Rel self state) (Model.Node.electIfQuorum caps self state) := by
  unfold Model.Node.electIfQuorum
  exact Keeps.ite' (fun _ => Rel.becomePrimary caps self state)
    fun _ => Keeps.pure' (Rel.refl _)

private theorem Rel.becomeCandidate (state : NodeState)
    : Keeps (Rel self state) (Model.Node.becomeCandidate caps state self) := by
  unfold Model.Node.becomeCandidate
  refine Keeps.bind' (Rel.electIfQuorum caps self _) fun _ kept =>
    Keeps.seq' fun _ => Keeps.pure' (Rel.trans ?_ kept)
  exact Rel.active rfl rfl rfl (by simp)

private theorem Rel.becomePreVoteCandidate (state : NodeState)
    : Keeps (Rel self state) (Model.Node.becomePreVoteCandidate caps state self) := by
  unfold Model.Node.becomePreVoteCandidate
  have pre : Rel self state
      { state with
          role := .preVoteCandidate, primaryKnown := false, preVotesGranted := {self} } :=
    Rel.active rfl rfl rfl (by simp)
  refine Keeps.ite' (fun _ => ?_) fun _ => Keeps.seq' fun _ => Keeps.pure' pre
  exact (Rel.becomeCandidate caps self _).mono fun _ kept => pre.trans kept

private theorem Rel.act (state : NodeState) (input : Input)
    : Keeps (Rel self state) (Model.Node.act caps self state input) := by
  cases input with
  | append entries =>
      unfold Model.Node.act Model.Node.appendBatch
      refine Keeps.seq' fun _ => ?_
      exact Keeps.bind'
        (Keeps.foldlM' (P := Rel self state) (fun current entry kept =>
          Keeps.bind' (Rel.appendEntry caps self current entry.content)
            fun appended next => Keeps.foldlM'
              (fun current (destination, endIndex) kept => by
                unfold Model.Node.sendEntries
                exact Keeps.seq' fun _ => Keeps.seq' fun _ =>
                  Keeps.pure' (kept.trans (Rel.same rfl rfl rfl rfl rfl)))
              entry.flushes appended (kept.trans next))
          entries state (Rel.refl _))
        fun current kept => (Rel.advanced caps self current).mono fun _ next =>
          kept.trans next
  | sendEntries destination endIndex =>
      unfold Model.Node.act Model.Node.sendEntries
      exact Keeps.seq' fun _ => Keeps.seq' fun _ => Keeps.pure' (Rel.same rfl rfl rfl rfl rfl)
  | timeout kind =>
      cases kind with
      | election =>
          unfold Model.Node.act Model.Node.startElection
          exact Keeps.seq' fun _ => Rel.becomePreVoteCandidate caps self state
      | checkQuorum =>
          unfold Model.Node.act Model.Node.checkQuorum
          exact Keeps.seq'
            fun _ =>
              Keeps.pure' (Rel.active rfl rfl rfl (by simp))
  | nominateSuccessor =>
      exact (Direct.Keeps.nominateSuccessor caps self state).mono fun _ same =>
        same ▸ Rel.refl _
  | initAsBackup entries =>
      unfold Model.Node.act Model.Node.initAsBackup
      refine Keeps.bind' Keeps.guard' fun _ ⟨fresh, _⟩ => Keeps.pure' ?_
      refine Rel.of_fields ⟨?_, ?_⟩ rfl (by simp [becomeAwareOfNewTerm])
      · simp [becomeAwareOfNewTerm, fresh.2.2.2]
      · simp [NodeState.committedLog, fresh.2.2.2]

/-- The follower append loop, which may record commits after signatures. -/
private theorem Rel.fromLeaderLoop (limit : Nat) (entries : List Entry)
    : forall (state : NodeState),
        Rel self state
          (entries.foldl
            (fun state entry =>
              let state := { state with log := state.log ++ [entry] }
              if entry.content.isSignature then
                state.recordCommit self
                  (max state.commitIndex (maxCommittableIndexUpTo state.log limit))
              else
                state)
            state) := by
  induction entries with
  | nil => intro state; exact Rel.refl _
  | cons entry entries ih =>
      intro state
      simp only [List.foldl_cons]
      have appended : Rel self state { state with log := state.log ++ [entry] } :=
        Rel.of_fields (Extends.append _) rfl fun none => ⟨none, (Nat.le_refl _)⟩
      refine Rel.trans ?_ (ih _)
      split
      · exact appended.trans (Rel.recordCommit _ (Nat.le_max_left _ _))
      · exact appended

private theorem Rel.fromLeader (state : NodeState) (request : AppendEntriesRequest)
    : Rel self state (handleAppendEntiresFromPrimary self state request).1 := by
  unfold handleAppendEntiresFromPrimary
  dsimp only
  exact (Rel.fromLeaderLoop self _ _ state).trans (Rel.recordCommit _ (Nat.le_max_left _ _))

private theorem Rel.handleAppendEntriesRequest (source : NodeID) (state : NodeState)
    (request : AppendEntriesRequest)
    : Keeps (Rel self state)
        (Model.Node.handleAppendEntriesRequest caps self source state request) := by
  unfold Model.Node.handleAppendEntriesRequest
  have stepped : Rel self state (if request.term = state.currentTerm /\
      (state.role = .candidate \/ state.role = .preVoteCandidate) then
        becomeAwareOfNewTerm state request.term else state) := by
    split
    · exact Rel.active rfl rfl rfl (by simp [becomeAwareOfNewTerm])
    · exact Rel.refl _
  generalize (if request.term = state.currentTerm /\
      (state.role = .candidate \/ state.role = .preVoteCandidate) then
        becomeAwareOfNewTerm state request.term else state) = current
    at stepped
  refine Keeps.ite' (fun _ => by
    dsimp only
    split <;> exact Keeps.seq' fun _ => Keeps.pure' stepped) fun _ => ?_
  dsimp only
  refine Keeps.ite'
    (fun _ => Keeps.pure' (stepped.trans (Rel.same rfl rfl rfl rfl rfl)))
    fun notBefore => ?_
  have within : current.commitIndex <= request.prevLogIndex :=
    Nat.le_of_not_lt fun lt => notBefore (Or.inl lt)
  split
  · exact Keeps.seq' fun _ => Keeps.pure'
      ((stepped.trans (Rel.same (after := { current with primaryKnown := true }) rfl rfl rfl
        rfl rfl)).trans (Rel.fromLeader self _ _))
  · rename_i index conflict
    have := Ledger.firstTermConflictIndex_ge conflict
    have truncated : Rel self current {
        current with
          primaryKnown := true, log := current.log.take (index - 1), isNewFollower := false
      } :=
      Rel.of_fields
        (Extends.of_prefix (count := index - 1)
          (Nat.le_trans within (Nat.le_sub_of_add_le this)) (List.prefix_refl _) (Nat.le_refl _))
        rfl fun none => ⟨none, (Nat.le_refl _)⟩
    exact Keeps.seq' fun _ =>
      Keeps.pure' ((stepped.trans truncated).trans (Rel.fromLeader self _ _))

private theorem Rel.receive (state : NodeState) (source : NodeID) (message : Message)
    : Keeps (Rel self state) (Model.Node.receive caps self source state message) := by
  have observed : Rel self state (observeTerm state message) := by
    unfold observeTerm updateTerm becomeAwareOfNewTerm
    split
    · exact Rel.refl _
    · split
      · split
        · exact Rel.active rfl rfl rfl (by simp)
        · exact Rel.refl _
      · exact Rel.refl _
    all_goals
      split
      · exact Rel.active rfl rfl rfl (by simp)
      · exact Rel.refl _
  unfold Model.Node.receive
  refine Keeps.ite' (fun _ => Keeps.pure' (Rel.refl _)) fun _ => ?_
  dsimp only
  generalize observeTerm state message = current at observed ⊢
  refine Keeps.mono (P := Rel self current) ?_ fun _ next => observed.trans next
  cases message with
  | appendEntriesRequest request =>
      exact Rel.handleAppendEntriesRequest caps self source current request
  | appendEntriesResponse response =>
      unfold Model.Node.handleAppendEntriesResponse
      refine Keeps.ite' (fun _ => Keeps.pure' (Rel.refl _)) fun _ => ?_
      refine Keeps.ite' (fun _ => ?_) fun _ => Keeps.pure' (Rel.same rfl rfl rfl rfl rfl)
      refine Keeps.ite' (fun _ => ?_) fun _ => Keeps.pure' (Rel.refl _)
      exact (Rel.advanced caps self _).mono fun _ next =>
        (Rel.same rfl rfl rfl rfl rfl).trans next
  | requestVoteRequest request =>
      unfold Model.Node.handleRequestVoteRequest
      exact Keeps.seq'
        fun _ => Keeps.pure' (by split <;> exact Rel.same rfl rfl rfl rfl rfl)
  | requestVoteResponse response =>
      unfold Model.Node.handleRequestVoteResponse
      refine Keeps.ite' (fun _ => ?_) fun _ => Keeps.pure' (Rel.refl _)
      exact (Rel.electIfQuorum caps self _).mono fun _ next =>
        (Rel.same rfl rfl rfl rfl rfl).trans next
  | requestPreVoteRequest request =>
      unfold Model.Node.handleRequestPreVoteRequest
      exact Keeps.seq' fun _ => Keeps.pure' (Rel.refl _)
  | requestPreVoteResponse response =>
      unfold Model.Node.handleRequestPreVoteResponse
      refine Keeps.ite' (fun _ => ?_) fun _ => Keeps.pure' (Rel.refl _)
      dsimp only
      refine Keeps.ite' (fun _ => ?_) fun _ => Keeps.pure' (Rel.same rfl rfl rfl rfl rfl)
      exact (Rel.becomeCandidate caps self _).mono fun _ next =>
        (Rel.same rfl rfl rfl rfl rfl).trans next
  | proposeRequestVoteRequest term =>
      unfold Model.Node.handleProposeRequestVoteRequest
      exact Keeps.ite' (fun _ => Rel.becomeCandidate caps self current)
        fun _ => Keeps.pure' (Rel.refl _)

private theorem Rel.step (state : NodeState) (event : Event)
    : Keeps (Rel self state) (Model.Node.step caps self state event) := by
  cases event with
  | internal input => exact Rel.act caps self state input
  | receive source message => exact Rel.receive caps self state source message

end Handlers
end Consensus.Proofs.Deadlock.Local

namespace Consensus.Proofs.Deadlock.Local

open CCF
open Model.Node
open Direct (Extends Keeps)

/--
A latched retirement is confirmed by the committed log, and a node without a
role either is latched or has never joined a term.
-/
private def Loc (self : NodeID) (state : NodeState) : Prop :=
  (state.retiredCommittedIndex.isSome -> self ∈ retiredCommittedNodes state.committedLog)
  /\ (state.role = .none -> state.retiredCommittedIndex.isSome \/ state.currentTerm < 2)

private theorem Loc.of_rel {self : NodeID} {before after : NodeState}
    (holds : Loc self before) (rel : Rel self before after)
    : Loc self after := by
  obtain ⟨extended, keep, set, role⟩ := rel
  refine ⟨fun some => ?_, fun none => ?_⟩
  · rcases set some with old | confirmed
    · exact retiredCommittedNodes_mono extended.committedLog (holds.1 old)
    · exact confirmed
  · rcases role none with ⟨beforeNone, le⟩ | some
    · rcases holds.2 beforeNone with old | young
      · exact Or.inl (keep old ▸ old)
      · exact Or.inr (Nat.lt_of_le_of_lt le young)
    · exact Or.inl some

private theorem loc_of_reachable [Config.InitialConfiguration] {nodes : List NodeID}
    {state : Model.State}
    (reachable : (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes).Reachable state)
    {node : NodeID} {local_ : NodeState} (member : (node, local_) ∈ state.nodes)
    : Loc node local_ := by
  induction reachable using
    (@TransitionSystem.Reachable.rec (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes))
      generalizing node local_ with
  | initial initialized =>
      rw [Safety.initial_state initialized member]
      unfold Safety.initialLocal
      refine ⟨fun some => by split at some <;> simp at some, fun none => Or.inr ?_⟩
      split at none
      · simp at none
      · split at none
        · simp at none
        · simp only [*, ite_false]
          decide
  | step _ stepped ih =>
      obtain ⟨tr⟩ := Safety.LocalTransition.ofStep stepped
      rw [tr.nodesEq] at member
      rcases Concrete.mem_replaceNode member with ⟨rfl, rfl⟩ | ⟨_, old⟩
      · exact (ih tr.pre_mem).of_rel (Rel.step (Capabilities.record _) _ _ _ _ _ _ tr.ran)
      · exact ih old

end Consensus.Proofs.Deadlock.Local

namespace Consensus.Proofs.Deadlock.Logs

open CCF
open Model.Node

/-- An appended entry neither re-adds nor confirms a node outside `removedNodes front`. -/
private def EntryOK (front : List Entry) (entry : Entry) : Prop :=
  (forall nodes,
    entry.content.metadata.configuration = some nodes
    -> Finset.Disjoint nodes (removedNodes front))
  /\ entry.content.metadata.retirementConfirmations ⊆ removedNodes front

/-- Every entry of the log is `EntryOK` for the entries before it. -/
private def LogOK (log : List Entry) : Prop :=
  forall n (bound : n < log.length), EntryOK (log.take n) log[n]

private theorem LogOK.nil : LogOK [] := fun _ bound => absurd bound (Nat.not_lt_zero _)

private theorem LogOK.take {log : List Entry} (ok : LogOK log) (count : Nat)
    : LogOK (log.take count) := by
  intro n bound
  have within : n < count := by simp at bound; omega
  have inLog : n < log.length := by simp at bound; omega
  rw [List.take_take, Nat.min_eq_left (Nat.le_of_lt within), List.getElem_take]
  exact ok n inLog

private theorem LogOK.prefix {small large : List Entry} (ok : LogOK large)
    (sub : small <+: large)
    : LogOK small := by
  rw [List.prefix_iff_eq_take.mp sub]
  exact ok.take _

private theorem LogOK.append {log : List Entry} {entry : Entry} (ok : LogOK log)
    (entryOK : EntryOK log entry)
    : LogOK (log ++ [entry]) := by
  intro n bound
  simp only [List.length_append, List.length_singleton] at bound
  rcases Nat.lt_or_ge n log.length with inLog | atEnd
  · rw [List.take_append_of_le_length (Nat.le_of_lt inLog), List.getElem_append_left inLog]
    exact ok n inLog
  · have : n = log.length := by omega
    subst this
    simp only [List.take_left', List.getElem_append_right (Nat.le_refl _), Nat.sub_self,
      List.getElem_cons_zero]
    exact entryOK

private theorem configurationHistory_append (log : List Entry) (entry : Entry)
    : configurationHistory (log ++ [entry])
      = configurationHistory log
        ++ (entry.content.metadata.configuration.map
              fun nodes =>
                ({ index := log.length + 1, nodes } : Configuration)).toList := by
  unfold configurationHistory
  rw [List.zipIdx_append, List.filterMap_append]
  congr 1
  simp only [List.zipIdx_cons, List.zipIdx_nil, List.filterMap_cons, List.filterMap_nil]
  cases entry.content.metadata.configuration <;> simp [Nat.add_comm]

private theorem configurationMembers_append (history : List Configuration)
    (configuration : Configuration)
    : configurationMembers (history ++ [configuration])
      = configurationMembers history ∪ configuration.nodes := by
  unfold configurationMembers
  rw [List.foldl_append]
  rfl

private theorem latestConfigurationMembers_append (history : List Configuration)
    (configuration : Configuration)
    : latestConfigurationMembers (history ++ [configuration]) = configuration.nodes := by
  simp [latestConfigurationMembers]

private theorem removedNodes_append_none {log : List Entry} {entry : Entry}
    (none : entry.content.metadata.configuration = none)
    : removedNodes (log ++ [entry]) = removedNodes log := by
  simp [removedNodes, configurationHistory_append, none]

private theorem removedNodes_append_some {log : List Entry} {entry : Entry}
    {nodes : Finset NodeID} (some : entry.content.metadata.configuration = some nodes)
    : removedNodes (log ++ [entry])
      = (configurationMembers (configurationHistory log) ∪ nodes) \ nodes := by
  simp only [removedNodes, configurationHistory_append, some, Option.map_some,
    Option.toList_some]
  rw [configurationMembers_append, latestConfigurationMembers_append]

/-- A permitted entry never returns a removed node to membership. -/
private theorem removedNodes_grow {log : List Entry} {entry : Entry}
    (entryOK : EntryOK log entry)
    : removedNodes log ⊆ removedNodes (log ++ [entry]) := by
  intro node removed
  cases config : entry.content.metadata.configuration with
  | none => rwa [removedNodes_append_none config]
  | some nodes =>
      rw [removedNodes_append_some config]
      have disjoint := entryOK.1 nodes config
      have absent : node ∉ nodes := fun present =>
        Finset.disjoint_left.mp disjoint present removed
      simp only [removedNodes, Finset.mem_sdiff] at removed
      exact Finset.mem_sdiff.mpr ⟨Finset.mem_union.mpr (Or.inl removed.1), absent⟩

private theorem removedNodes_take_mono {log : List Entry} (ok : LogOK log)
    : forall {small large : Nat},
        small <= large
        -> removedNodes (log.take small) ⊆ removedNodes (log.take large) := by
  intro small large le
  induction le with
  | refl => exact Finset.Subset.refl _
  | @step large _ ih =>
      refine Finset.Subset.trans ih ?_
      rcases Nat.lt_or_ge large log.length with inLog | beyond
      · rw [List.take_succ_eq_append_getElem inLog]
        exact removedNodes_grow (ok large inLog)
      · rw [List.take_of_length_le beyond, List.take_of_length_le (by omega)]
        exact Finset.Subset.refl _

/-- Under `LogOK`, a node removed by a prefix stays removed. -/
private theorem removedNodes_prefix {small large : List Entry} (ok : LogOK large)
    (sub : small <+: large)
    : removedNodes small ⊆ removedNodes large := by
  have eq : large.take small.length = small := (List.prefix_iff_eq_take.mp sub).symm
  have grown := removedNodes_take_mono ok sub.length_le
  rwa [eq, List.take_length] at grown

end Consensus.Proofs.Deadlock.Logs

namespace Consensus.Proofs.Deadlock.Logs

open CCF
open Model.Node
open Direct (Keeps)

private theorem guardBind {α : Type} {P : α -> Prop} {c : Prop} [Decidable c]
    {m : NodeEffect α} (rest : c -> Keeps P m)
    : Keeps P (guard c >>= fun _ => m) := by
  intro outputs result after ran
  by_cases holds : c
  · simp only [guard, holds, ite_true] at ran
    exact rest holds outputs result after (by simpa using ran)
  · simp [guard, holds] at ran

/-- Nodes retired by committed configurations are removed in the whole log. -/
private theorem retirementCompleted_removed {state : NodeState} (ok : LogOK state.log)
    : state.retirementCompletedNodes ⊆ removedNodes state.log := by
  intro node member
  simp only [NodeState.retirementCompletedNodes, Finset.mem_sdiff] at member
  have removed : node ∈ removedNodes state.committedLog := by
    simp only [removedNodes, Finset.mem_sdiff]
    exact member.1
  exact removedNodes_prefix ok (List.take_prefix _ _) removed

private theorem entryOK_of {state : NodeState} (ok : LogOK state.log) {term : Nat}
    {content : EntryContent}
    (confirmations
      : content.metadata.retirementConfirmations.Nonempty
        -> content.metadata.retirementConfirmations
            ⊆ state.retirementCompletedNodes \ retiredCommittedNodes state.log)
    (configured
      : forall nodes,
          content.metadata.configuration = some nodes
          -> Finset.Disjoint nodes (removedNodes state.log))
    : EntryOK state.log { term, content } := by
  refine ⟨configured, ?_⟩
  by_cases nonempty : content.metadata.retirementConfirmations.Nonempty
  · refine Finset.Subset.trans (confirmations nonempty) fun node member => ?_
    exact retirementCompleted_removed ok (Finset.mem_sdiff.mp member).1
  · exact Finset.subset_iff.mpr fun node member => (nonempty ⟨node, member⟩).elim

private theorem appendEntry_ok (caps : Caps) (self : NodeID) (state : NodeState)
    (content : EntryContent) (ok : LogOK state.log)
    : Keeps (fun after : NodeState => LogOK after.log)
        (Model.Node.appendEntry caps self state content) := by
  unfold Model.Node.appendEntry
  simp only [pure_bind]
  repeat'
    first
    | refine guardBind fun _ => ?_
    | refine Keeps.ite' (fun _ => ?_) fun _ => ?_
    | refine Keeps.seq' fun _ => ?_
    | split
  all_goals
    refine Keeps.pure' (LogOK.append ok (entryOK_of ok ?_ ?_))
  all_goals
    first
    | intro nonempty; first | assumption | contradiction
    | intro nodes configured; simp_all

end Consensus.Proofs.Deadlock.Logs

namespace Consensus.Proofs.Deadlock.Logs

open CCF
open Model.Node
open Direct (Keeps)
section Handlers
variable (caps : Caps) (self : NodeID)

/-- The step only shortens the log, as elections and commits do. -/
private abbrev Shrinks (state after : NodeState) : Prop := after.log <+: state.log

private theorem shrinks_refl (state : NodeState) : Shrinks state state :=
  List.prefix_refl _

private theorem Shrinks.advanced (state : NodeState)
    : Keeps (Shrinks state) (Model.Node.advanceCommit caps state self) := by
  unfold Model.Node.advanceCommit
  refine Keeps.ite' (fun _ => Keeps.pure' (shrinks_refl _)) fun _ => ?_
  have same : Shrinks state (state.recordCommit self (highestCommittableIndex state self)) := by
    simp [Shrinks, Ledger.NodeState.recordCommit_log]
  dsimp only
  exact Keeps.ite'
    (fun _ => Keeps.ite' (fun _ => Keeps.seq' fun _ => Keeps.pure' same)
      fun _ => Keeps.pure' same)
    fun _ => Keeps.pure' same

private theorem Shrinks.becomePrimary (state : NodeState)
    : Keeps (Shrinks state) (Model.Node.becomePrimary caps self state) := by
  unfold Model.Node.becomePrimary
  refine Keeps.bind' (Shrinks.advanced caps self _) fun _ kept =>
    Keeps.seq' fun _ => Keeps.pure' (List.IsPrefix.trans kept ?_)
  simp only [primaryState]
  split
  · exact List.take_prefix _ _
  · exact List.prefix_refl _

private theorem Shrinks.electIfQuorum (state : NodeState)
    : Keeps (Shrinks state) (Model.Node.electIfQuorum caps self state) := by
  unfold Model.Node.electIfQuorum
  exact Keeps.ite' (fun _ => Shrinks.becomePrimary caps self state)
    fun _ => Keeps.pure' (shrinks_refl _)

private theorem Shrinks.becomeCandidate (state : NodeState)
    : Keeps (Shrinks state) (Model.Node.becomeCandidate caps state self) := by
  unfold Model.Node.becomeCandidate
  exact Keeps.bind' (Shrinks.electIfQuorum caps self _) fun _ kept =>
    Keeps.seq' fun _ => Keeps.pure' kept

private theorem Shrinks.becomePreVoteCandidate (state : NodeState)
    : Keeps (Shrinks state) (Model.Node.becomePreVoteCandidate caps state self) := by
  unfold Model.Node.becomePreVoteCandidate
  exact Keeps.ite' (fun _ => Shrinks.becomeCandidate caps self _)
    fun _ => Keeps.seq' fun _ => Keeps.pure' (shrinks_refl _)

private theorem act_ok (state : NodeState) (input : Input) (ok : LogOK state.log)
    (notInit : forall entries, Not (input = .initAsBackup entries))
    : Keeps (fun after : NodeState => LogOK after.log)
        (Model.Node.act caps self state input) := by
  have viaShrinks : forall {m : NodeEffect NodeState}, Keeps (Shrinks state) m
      -> Keeps (fun after : NodeState => LogOK after.log) m :=
    fun kept => kept.mono fun _ shrunk => ok.prefix shrunk
  cases input with
  | append entries =>
      unfold Model.Node.act Model.Node.appendBatch
      refine Keeps.seq' fun _ => ?_
      exact Keeps.bind'
        (Keeps.foldlM' (P := fun current : NodeState => LogOK current.log)
          (fun current entry kept =>
            Keeps.bind' (appendEntry_ok caps self current entry.content kept)
              fun appended next => Keeps.foldlM'
                (fun current (destination, endIndex) kept => by
                  unfold Model.Node.sendEntries
                  exact Keeps.seq' fun _ => Keeps.seq' fun _ => Keeps.pure' kept)
                entry.flushes appended next)
          entries state ok)
        fun current kept => (Shrinks.advanced caps self current).mono fun _ shrunk =>
          kept.prefix shrunk
  | sendEntries destination endIndex =>
      unfold Model.Node.act Model.Node.sendEntries
      exact Keeps.seq' fun _ => Keeps.seq' fun _ => Keeps.pure' ok
  | timeout kind =>
      cases kind with
      | election =>
          unfold Model.Node.act Model.Node.startElection
          exact Keeps.seq' fun _ => viaShrinks (Shrinks.becomePreVoteCandidate caps self state)
      | checkQuorum =>
          unfold Model.Node.act Model.Node.checkQuorum
          exact Keeps.seq' fun _ => Keeps.pure' ok
  | nominateSuccessor =>
      exact (Direct.Keeps.nominateSuccessor caps self state).mono fun _ same => same ▸ ok
  | initAsBackup entries => exact (notInit entries rfl).elim

/-- Accepting AppendEntries leaves the follower in the request's term. -/
private theorem handleAppendEntriesRequest_term (source : NodeID) (state : NodeState)
    (request : AppendEntriesRequest) (observed : request.term <= state.currentTerm)
    : Keeps
        (fun after : NodeState =>
          after.log = state.log \/ after.currentTerm = request.term)
        (Model.Node.handleAppendEntriesRequest caps self source state request) := by
  unfold Model.Node.handleAppendEntriesRequest
  have stepped : (if request.term = state.currentTerm /\
      (state.role = .candidate \/ state.role = .preVoteCandidate) then
        becomeAwareOfNewTerm state request.term else state).log = state.log
      /\ request.term <= (if request.term = state.currentTerm /\
      (state.role = .candidate \/ state.role = .preVoteCandidate) then
        becomeAwareOfNewTerm state request.term else state).currentTerm := by
    split
    · exact ⟨rfl, by simp [becomeAwareOfNewTerm]⟩
    · exact ⟨rfl, observed⟩
  generalize (if request.term = state.currentTerm /\
      (state.role = .candidate \/ state.role = .preVoteCandidate) then
        becomeAwareOfNewTerm state request.term else state) = current
    at stepped
  obtain ⟨logEq, termLe⟩ := stepped
  refine Keeps.ite' (fun _ => by
    dsimp only
    split <;> exact Keeps.seq' fun _ => Keeps.pure' (Or.inl logEq)) fun accepted => ?_
  have termEq : current.currentTerm = request.term :=
    Nat.le_antisymm (Nat.le_of_not_lt fun lt => accepted (Or.inl lt)) termLe
  dsimp only
  have fromLeader : forall (middle : NodeState), middle.currentTerm = request.term
      -> (handleAppendEntiresFromPrimary self middle request).1.currentTerm = request.term := by
    intro middle middleTerm
    obtain ⟨_, _, _, eq, _⟩ := Ledger.handleAppendEntiresFromPrimary_eq self middle request
    rw [eq]
    exact middleTerm
  refine Keeps.ite' (fun _ => Keeps.pure' (Or.inr termEq)) fun _ => ?_
  split
  · exact Keeps.seq' fun _ => Keeps.pure' (Or.inr (fromLeader _ termEq))
  · exact Keeps.seq' fun _ => Keeps.pure' (Or.inr (fromLeader _ termEq))

private theorem updateTerm_ge (state : NodeState) (term : Nat)
    : term <= (updateTerm state term).currentTerm := by
  unfold updateTerm becomeAwareOfNewTerm
  split
  · exact (Nat.le_refl _)
  · exact Nat.le_of_not_lt ‹_›

/-- Only accepting AppendEntries may produce a log that is not `LogOK`. -/
private theorem step_ok (state : NodeState) (event : Event) (ok : LogOK state.log)
    : Keeps
        (fun after : NodeState =>
          LogOK after.log
          \/ (exists source request,
                event = .receive source (.appendEntriesRequest request)
                /\ after.currentTerm = request.term)
          \/ exists entries,
              event = .internal (.initAsBackup entries) /\ after.log = entries)
        (Model.Node.step caps self state event) := by
  cases event with
  | internal input =>
      by_cases init : exists entries, input = .initAsBackup entries
      · obtain ⟨entries, rfl⟩ := init
        unfold Model.Node.step Model.Node.act Model.Node.initAsBackup
        exact Keeps.bind' Keeps.guard' fun _ _ =>
          Keeps.pure' (Or.inr (Or.inr ⟨entries, rfl, by simp [becomeAwareOfNewTerm]⟩))
      · exact (act_ok caps self state input ok fun entries eq => init ⟨entries, eq⟩).mono
          fun _ kept => Or.inl kept
  | receive source message =>
      unfold Model.Node.step Model.Node.receive
      refine Keeps.ite' (fun _ => Keeps.pure' (Or.inl ok)) fun _ => ?_
      dsimp only
      have observedLog : (observeTerm state message).log = state.log :=
        Concrete.observeTerm_log _ _
      have viaShrinks : forall {m : NodeEffect NodeState},
          Keeps (Shrinks (observeTerm state message)) m
          -> Keeps (fun after : NodeState =>
                LogOK after.log
                \/ (exists source' request,
                    Event.receive source message
                      = .receive source' (.appendEntriesRequest request)
                    /\ after.currentTerm = request.term)
                \/ exists entries,
                    Event.receive source message = .internal (.initAsBackup entries)
                    /\ after.log = entries) m :=
        fun kept => kept.mono fun _ shrunk => Or.inl (ok.prefix (observedLog ▸ shrunk))
      cases message with
      | appendEntriesRequest request =>
          have observed : request.term <= (observeTerm state
              (.appendEntriesRequest request)).currentTerm := updateTerm_ge _ _
          refine (handleAppendEntriesRequest_term caps self source _ request observed).mono
            fun _ result => ?_
          rcases result with logEq | termEq
          · exact Or.inl (logEq.trans observedLog ▸ ok)
          · exact Or.inr (Or.inl ⟨source, request, rfl, termEq⟩)
      | appendEntriesResponse response =>
          refine viaShrinks ?_
          unfold Model.Node.handleAppendEntriesResponse
          refine Keeps.ite' (fun _ => Keeps.pure' (shrinks_refl _)) fun _ => ?_
          refine Keeps.ite' (fun _ => ?_) fun _ => Keeps.pure' (shrinks_refl _)
          refine Keeps.ite' (fun _ => ?_) fun _ => Keeps.pure' (shrinks_refl _)
          exact Shrinks.advanced caps self _
      | requestVoteRequest request =>
          refine viaShrinks ?_
          unfold Model.Node.handleRequestVoteRequest
          exact Keeps.seq' fun _ => Keeps.pure' (by split <;> exact shrinks_refl _)
      | requestVoteResponse response =>
          refine viaShrinks ?_
          unfold Model.Node.handleRequestVoteResponse
          refine Keeps.ite' (fun _ => ?_) fun _ => Keeps.pure' (shrinks_refl _)
          exact Shrinks.electIfQuorum caps self _
      | requestPreVoteRequest request =>
          refine viaShrinks ?_
          unfold Model.Node.handleRequestPreVoteRequest
          exact Keeps.seq' fun _ => Keeps.pure' (shrinks_refl _)
      | requestPreVoteResponse response =>
          refine viaShrinks ?_
          unfold Model.Node.handleRequestPreVoteResponse
          refine Keeps.ite' (fun _ => ?_) fun _ => Keeps.pure' (shrinks_refl _)
          dsimp only
          refine Keeps.ite' (fun _ => ?_) fun _ => Keeps.pure' (shrinks_refl _)
          exact Shrinks.becomeCandidate caps self _
      | proposeRequestVoteRequest term =>
          refine viaShrinks ?_
          unfold Model.Node.handleProposeRequestVoteRequest
          exact Keeps.ite' (fun _ => Shrinks.becomeCandidate caps self _)
            fun _ => Keeps.pure' (shrinks_refl _)

end Handlers
end Consensus.Proofs.Deadlock.Logs

namespace Consensus.Proofs.Deadlock.Logs

open CCF
open Model.Node
open Safety (Frame Inv Now Seen Canon CanonNow Ctx MessageOK)
variable [Config.InitialConfiguration]

/-- Extra state carried alongside `Safety.Inv` for the deadlock-freedom proof. -/
private structure ExtraInv (nodes : List NodeID) (f : Frame) : Prop where
  keys : f.current.nodes.map Prod.fst = nodes
  seenKeys : forall n o, Seen f n o -> n ∈ nodes
  canonLogsOK : forall k l, Canon f k l -> LogOK l
  canonBound : exists bound, forall k l, Canon f k l -> l.length <= bound

private theorem initial_logs_ok {nodes : List NodeID} {initial : Model.State}
    (initialized
      : (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes).init initial)
    {node : NodeID} {state : NodeState} (member : (node, state) ∈ initial.nodes)
    : LogOK state.log := by
  rw [Safety.initial_state initialized member]
  unfold Safety.initialLocal
  split
  · intro n bound
    simp only [List.length_singleton, Nat.lt_one_iff] at bound
    subst bound
    have none : forall node, node ∉ removedNodes ([] : List Entry) :=
      fun node removed =>
        Finset.notMem_empty node
          (by
            simpa [removedNodes, configurationHistory, configurationMembers]
              using (Finset.mem_sdiff.mp removed).1)
    refine ⟨
      fun nodes _ => Finset.disjoint_left.mpr fun node _ removed => none node removed,
      Finset.subset_iff.mpr fun node removed => ?_
    ⟩
    simp only [List.getElem_cons_zero, Config.GENESIS, EntryContent.metadata] at removed
    exact (Finset.notMem_empty node removed).elim
  · exact LogOK.nil

private theorem extra_initial {nodes : List NodeID} {initial : Model.State}
    (initialized
      : (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes).init initial)
    : ExtraInv nodes (Frame.start initial) where
  keys := initialized.2.1
  seenKeys := by
    rintro n o (h | ⟨st, mem, _, _⟩)
    · cases h
    · rw [← initialized.2.1]
      exact List.mem_map.mpr ⟨(n, st), mem, rfl⟩
  canonLogsOK := by
    rintro k l (h | ⟨n, st, now, rfl⟩)
    · cases h
    · exact initial_logs_ok initialized now.1
  canonBound := by
    refine ⟨1, ?_⟩
    rintro k l (h | ⟨n, st, now, rfl⟩)
    · cases h
    · rw [Safety.initial_state initialized now.1]
      unfold Safety.initialLocal
      split <;> simp

end Consensus.Proofs.Deadlock.Logs

namespace Consensus.Proofs.Deadlock.Logs.Ctx

open CCF
open Model.Node
open Safety (Frame Inv Now Seen Canon CanonNow Ctx MessageOK)
variable [Config.InitialConfiguration]
variable {nodes : List NodeID} {f : Frame} {after : Model.State} (c : Ctx f after)
include c

/-- Every current log is a prefix of a leader log, so is `LogOK`. -/
private theorem pre_ok (ih : ExtraInv nodes f) {node : NodeID}
    {state : NodeState} (now : Now f node state)
    : LogOK state.log := by
  rcases Nat.eq_zero_or_pos state.log.length with empty | positive
  · rw [List.length_eq_zero_iff.mp empty]
    exact LogOK.nil
  obtain ⟨log, canon, _, eq⟩ :=
    c.inv.anchor node state state.log.length now positive (Nat.le_refl _)
  have leaderOk := ih.canonLogsOK _ _ canon
  rw [List.take_length] at eq
  rw [eq]
  exact leaderOk.take _

private theorem extra_step (ih : ExtraInv nodes f)
    : ExtraInv nodes (f.advance after) where
  keys := by
    change after.nodes.map Prod.fst = nodes
    rw [c.tr.nodesEq, Concrete.replaceNode_keys, ih.keys]
  seenKeys := by
    rintro n o (old | ⟨st, mem, _, _⟩)
    · exact ih.seenKeys n o old
    · rw [← ih.keys, ← Concrete.replaceNode_keys (node := c.actor) (value := c.post),
        ← c.tr.nodesEq]
      exact List.mem_map.mpr ⟨(n, st), mem, rfl⟩
  canonLogsOK := by
    rintro k l (old | ⟨node, state, ⟨now, termEq, role, led⟩, rfl⟩)
    · exact ih.canonLogsOK k l old
    · rcases c.now_after now with ⟨rfl, rfl⟩ | ⟨different, oldNow⟩
      · have preOk := Logs.Ctx.pre_ok c ih c.pre_now
        rcases step_ok (Capabilities.record c.actor) c.actor c.pre c.event preOk _ _ _ c.tr.ran with
          ok | ⟨source, request, received, termEq'⟩ | ⟨entries, initialized, logEq⟩
        · exact ok
        · exfalso
          obtain ⟨envelope, ok, sourceEq, targetEq, payload⟩ := c.received_ok received
          simp only [MessageOK, payload] at ok
          obtain ⟨senderLog, aeok⟩ := ok
          have ledSender : Safety.Led (f.advance after) envelope.source request.term :=
            aeok.led.imp_right fun ⟨p, i, e⟩ => ⟨p, i, .inl e⟩
          have ledActor : Safety.Led (f.advance after) c.actor request.term := by
            rw [← termEq', termEq]
            exact led
          have same := c.election_safety _ _ _ ledSender ledActor
          exact aeok.different (targetEq.trans same.symm)
        · have available := c.tr.available entries initialized
          simp only [Model.committedPrefixOf, List.any_eq_true, Bool.and_eq_true,
            decide_eq_true_eq, beq_iff_eq] at available
          obtain ⟨⟨other, otherState⟩, member, _, prefixEq⟩ := available
          have otherOk := Logs.Ctx.pre_ok c ih member
          rw [logEq, ← prefixEq]
          exact otherOk.take _
      · exact Logs.Ctx.pre_ok c ih oldNow
  canonBound := by
    obtain ⟨b, hb⟩ := ih.canonBound
    refine ⟨max b (after.nodes.map fun e => e.2.log.length).sum, ?_⟩
    rintro k l (old | ⟨node, state, ⟨now, _⟩, rfl⟩)
    · exact Nat.le_trans (hb k l old) (Nat.le_max_left _ _)
    · refine Nat.le_trans ?_ (Nat.le_max_right _ _)
      have mem : state.log.length ∈ after.nodes.map fun e => e.2.log.length :=
        List.mem_map.mpr ⟨(node, state), now, rfl⟩
      clear hb
      generalize after.nodes.map (fun e => e.2.log.length) = vs at mem ⊢
      induction vs with
      | nil => cases mem
      | cons hd tl ihs =>
        rw [List.sum_cons]
        rcases List.mem_cons.mp mem with rfl | tail
        · exact Nat.le_add_right _ _
        · exact Nat.le_trans (ihs tail) (Nat.le_add_left _ _)

end Consensus.Proofs.Deadlock.Logs.Ctx

namespace Consensus.Proofs.Deadlock.Logs

open CCF
open Model.Node
open Safety (Frame Inv LocalTransition Ctx)
variable [Config.InitialConfiguration]

/-- Every reachable state has a frame satisfying `Safety.Inv` and `ExtraInv`. -/
private theorem frame_of_reachable {nodes : List NodeID} {state : Model.State}
    (reachable : (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes).Reachable state)
    : exists f : Frame, f.current = state /\ Inv f /\ ExtraInv nodes f := by
  induction reachable using
    (@TransitionSystem.Reachable.rec (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes)) with
  | initial initialized =>
      exact ⟨Frame.start _, rfl, Safety.inv_initial initialized, extra_initial initialized⟩
  | step _ stepped ih =>
      obtain ⟨f, rfl, inv, extra⟩ := ih
      obtain ⟨tr⟩ := LocalTransition.ofStep stepped
      have c : Ctx f _ := ⟨tr, inv⟩
      exact ⟨f.advance _, rfl, c.inv_step, Logs.Ctx.extra_step c extra⟩

end Consensus.Proofs.Deadlock.Logs

namespace Consensus.Proofs.Deadlock.Configs

open CCF (Finset)
open Model.Node

private theorem mem_configurationHistory {log : List Entry}
    {configuration : Configuration}
    : configuration ∈ configurationHistory log
      <-> exists n,
      exists bound : n < log.length,
        configuration.index = n + 1
        /\ log[n].content.metadata.configuration = some configuration.nodes := by
  unfold configurationHistory
  rw [List.mem_filterMap]
  constructor
  · rintro ⟨⟨entry, index⟩, member, eq⟩
    obtain ⟨low, high, entryEq⟩ := List.mem_zipIdx member
    obtain ⟨nodes, configured, rfl⟩ := Option.map_eq_some_iff.mp eq
    refine ⟨index - 1, by omega, by simp; omega, ?_⟩
    rw [← entryEq]
    exact configured
  · rintro ⟨n, bound, indexEq, configured⟩
    have inZip : n < (log.zipIdx 1).length := by rw [List.length_zipIdx]; exact bound
    refine ⟨(log[n], n + 1), ?_, ?_⟩
    · have := List.getElem_mem inZip
      rwa [List.getElem_zipIdx, Nat.add_comm 1 n] at this
    · obtain ⟨index, nodes⟩ := configuration
      simp only at indexEq configured
      simp [configured, indexEq]

private theorem index_bounds {log : List Entry} {configuration : Configuration}
    (member : configuration ∈ configurationHistory log)
    : 1 <= configuration.index /\ configuration.index <= log.length := by
  obtain ⟨n, bound, indexEq, _⟩ := mem_configurationHistory.mp member
  omega

private theorem pairwise_zipIdx {α : Type} (xs : List α) (k : Nat)
    : (xs.zipIdx k).Pairwise fun first second => first.2 < second.2 := by
  induction xs generalizing k with
  | nil => simp
  | cons head tail ih =>
      rw [List.zipIdx_cons, List.pairwise_cons]
      refine ⟨fun ⟨_, index⟩ member => ?_, ih (k + 1)⟩
      have := (List.mem_zipIdx member).1
      simp only
      omega

/-- Configuration indices strictly increase along the history. -/
private theorem history_sorted (log : List Entry)
    : (configurationHistory log).Pairwise
        fun first second => first.index < second.index := by
  unfold configurationHistory
  refine (pairwise_zipIdx log 1).filterMap _ ?_
  rintro ⟨_, i⟩ ⟨_, j⟩ lt first firstEq second secondEq
  obtain ⟨_, _, rfl⟩ := Option.map_eq_some_iff.mp firstEq
  obtain ⟨_, _, rfl⟩ := Option.map_eq_some_iff.mp secondEq
  exact lt

/-- A configuration of a prefix is a configuration of the whole log. -/
private theorem history_of_prefix {small large : List Entry} (sub : small <+: large)
    {configuration : Configuration} (member : configuration ∈ configurationHistory small)
    : configuration ∈ configurationHistory large := by
  obtain ⟨n, bound, indexEq, configured⟩ := mem_configurationHistory.mp member
  have inLarge : n < large.length := Nat.lt_of_lt_of_le bound sub.length_le
  refine mem_configurationHistory.mpr ⟨n, inLarge, indexEq, ?_⟩
  rw [← sub.getElem bound]
  exact configured

/-- A configuration of the whole log within a prefix belongs to the prefix. -/
private theorem history_to_prefix {small large : List Entry} (sub : small <+: large)
    {configuration : Configuration} (member : configuration ∈ configurationHistory large)
    (within : configuration.index <= small.length)
    : configuration ∈ configurationHistory small := by
  obtain ⟨n, bound, indexEq, configured⟩ := mem_configurationHistory.mp member
  have inSmall : n < small.length := by omega
  refine mem_configurationHistory.mpr ⟨n, inSmall, indexEq, ?_⟩
  rw [sub.getElem inSmall]
  exact configured

/-- Every element of a strictly sorted list is at most its last element. -/
private theorem le_getLast {history : List Configuration}
    (sorted : history.Pairwise fun first second => first.index < second.index)
    (nonempty : history ≠ []) {configuration : Configuration}
    (member : configuration ∈ history)
    : configuration.index <= (history.getLast nonempty).index := by
  have split := List.dropLast_concat_getLast nonempty
  rw [← split] at sorted member
  rcases List.mem_append.mp member with early | last
  · exact Nat.le_of_lt ((List.pairwise_append.mp sorted).2.2 _ early _ (List.mem_singleton_self _))
  · rw [List.mem_singleton.mp last]
    exact Nat.le_refl _

private theorem latest_eq {history : List Configuration} (nonempty : history ≠ [])
    : latestConfigurationMembers history = (history.getLast nonempty).nodes := by
  simp [latestConfigurationMembers, List.getLast?_eq_some_getLast nonempty]

private theorem mem_configurationMembers_foldl {node : NodeID}
    (history : List Configuration) (init : Finset NodeID)
    : node ∈ history.foldl (fun nodes configuration => nodes ∪ configuration.nodes) init
      <-> node ∈ init
          \/ exists configuration,
              configuration ∈ history /\ node ∈ configuration.nodes := by
  induction history generalizing init with
  | nil => simp
  | cons head tail ih =>
      simp only [List.foldl_cons, ih, Finset.mem_union, List.mem_cons]
      constructor
      · rintro ((old | new) | ⟨configuration, member, present⟩)
        · exact Or.inl old
        · exact Or.inr ⟨head, Or.inl rfl, new⟩
        · exact Or.inr ⟨configuration, Or.inr member, present⟩
      · rintro (old | ⟨configuration, rfl | member, present⟩)
        · exact Or.inl (Or.inl old)
        · exact Or.inl (Or.inr present)
        · exact Or.inr ⟨configuration, member, present⟩

private theorem mem_configurationMembers {history : List Configuration}
    {configuration : Configuration} (member : configuration ∈ history) {node : NodeID}
    (present : node ∈ configuration.nodes)
    : node ∈ configurationMembers history := by
  unfold configurationMembers
  exact (mem_configurationMembers_foldl history ∅).mpr
    (Or.inr ⟨configuration, member, present⟩)

/-- A configuration at or after the last one with index at most `bound` is active. -/
private theorem mem_drop_of_latest {history : List Configuration}
    (sorted : history.Pairwise fun first second => first.index < second.index)
    {configuration : Configuration} (member : configuration ∈ history) {bound : Nat}
    (latest
      : forall other,
          other ∈ history -> other.index <= bound -> other.index <= configuration.index)
    : configuration
      ∈ history.drop
          ((history.filter fun other => decide (other.index <= bound)).length - 1) := by
  induction history with
  | nil => simp at member
  | cons head tail ih =>
      rw [List.pairwise_cons] at sorted
      rw [List.filter_cons]
      by_cases headIn : head.index <= bound
      · simp only [headIn, decide_true, ite_true, List.length_cons, Nat.add_sub_cancel]
        cases count : (tail.filter fun other => decide (other.index <= bound)).length with
        | zero => simpa using member
        | succ count =>
            obtain ⟨other, otherMem⟩ :=
              List.exists_mem_of_length_pos (by omega : 0 < (tail.filter fun other =>
                decide (other.index <= bound)).length)
            have ⟨otherTail, otherIn⟩ := List.mem_filter.mp otherMem
            have notHead : configuration ≠ head := by
              rintro rfl
              have := latest other (List.mem_cons_of_mem _ otherTail) (by simpa using otherIn)
              have := sorted.1 other otherTail
              omega
            have inTail : configuration ∈ tail := by
              rcases List.mem_cons.mp member with rfl | inner
              · exact (notHead rfl).elim
              · exact inner
            have rest := ih sorted.2 inTail fun other otherMem =>
              latest other (List.mem_cons_of_mem _ otherMem)
            rw [count] at rest
            simpa [List.drop_succ_cons] using rest
      · have none : (tail.filter fun other => decide (other.index <= bound)) = [] := by
          refine List.filter_eq_nil_iff.mpr fun other otherTail => ?_
          have := sorted.1 other otherTail
          simp only [decide_eq_true_eq]
          omega
        simp only [headIn, decide_false, Bool.false_eq_true, ite_false, none,
          List.length_nil, Nat.zero_sub, List.drop_zero]
        exact member

end Consensus.Proofs.Deadlock.Configs

namespace Consensus.Proofs.Deadlock.Witness

set_option linter.unusedSectionVars false
open CCF CCF.MultiNodeTransitionSystem
open Model.Node
open Safety (Frame Now Seen Canon Committed Commit CommitFacts Inv)
open Configs Logs
variable [Config.InitialConfiguration]

/-- A bounded, satisfiable predicate on naturals has a greatest solution. -/
private theorem exists_greatest {P : Nat -> Prop} {bound : Nat}
    (bounded : forall n, P n -> n <= bound) {n : Nat} (holds : P n)
    : exists greatest, P greatest /\ forall m, P m -> m <= greatest := by
  induction bound generalizing n with
  | zero =>
      have := bounded n holds
      refine ⟨0, Nat.le_zero.mp this ▸ holds, fun m held => bounded m held⟩
  | succ bound ih =>
      by_cases top : P (bound + 1)
      · exact ⟨bound + 1, top, bounded⟩
      · refine ih (fun m held => ?_) holds
        have := bounded m held
        rcases Nat.lt_or_eq_of_le this with lt | rfl
        · omega
        · exact (top held).elim

private theorem nonempty_of_card_pos {nodes : Finset NodeID} (positive : 0 < nodes.card)
    : nodes.Nonempty := by
  obtain ⟨node, member⟩ := List.exists_mem_of_length_pos positive
  exact ⟨node, Finset.mem_def.mpr member⟩

private theorem committed_length_le {f : Frame} {bound : Nat}
    (hb : forall k l, Canon f k l -> l.length <= bound)
    {term : Nat} {part : List Entry} (committed : Committed f term part)
    : part.length <= bound := by
  cases committed with
  | base => exact Nat.zero_le _
  | link facts _ _ _ =>
      exact Nat.le_trans (List.length_take_le' _ _) (hb _ _ facts.canon)

/-- Some committed part contains every other committed part. -/
private theorem longest_committed {nodes : List NodeID} {f : Frame}
    (inv : Inv f) (extra : ExtraInv nodes f) {term : Nat} {part : List Entry}
    (committed : Committed f term part)
    : exists term' longest,
        Committed f term' longest
        /\ part.length <= longest.length
        /\ forall term'' other, Committed f term'' other -> other <+: longest := by
  obtain ⟨bound, hb⟩ := extra.canonBound
  obtain ⟨length, ⟨term', longest, longestCommitted, lengthEq⟩, greatest⟩ :=
    exists_greatest (P := fun n => exists term' other,
        Committed f term' other /\ other.length = n)
      (fun _ ⟨_, _, other, lengthEq⟩ => lengthEq ▸ committed_length_le hb other)
      ⟨term, part, committed, rfl⟩
  refine ⟨term', longest, longestCommitted, ?_, fun term'' other otherCommitted => ?_⟩
  · rw [lengthEq]
    exact greatest _ ⟨term, part, committed, rfl⟩
  · rcases inv.comparable _ _ _ _ otherCommitted longestCommitted with sub | sub
    · exact sub
    · have le : other.length <= longest.length := by
        rw [lengthEq]
        exact greatest _ ⟨term'', other, otherCommitted, rfl⟩
      rw [sub.eq_of_length (Nat.le_antisymm sub.length_le le)]
      exact List.prefix_refl _

/-- Every nonempty committed prefix is contained in every later-term leader log. -/
private theorem committed_in_canon {f : Frame} (inv : Inv f)
    {term later : Nat} {part log : List Entry}
    (committed : Committed f term part) (canon : Canon f later log) (lt : term < later)
    : part <+: log := by
  cases committed with
  | base => exact List.nil_prefix
  | link facts prior le within =>
      have whole : Committed f term _ := .link facts prior le within
      have floor : ∀ k l, f.logs.canon k l → 2 ≤ k := fun k l c => by
        obtain ⟨n, led⟩ := inv.owner c
        exact Safety.led_floor inv.electionCerts led
      have two := floor term _ facts.canon
      have complete := Safety.complete_of inv.rankedElections inv.electionCerts
        inv.winningPrefix inv.chains inv.copyLogs floor
      obtain ⟨n, electedLog, commit, elected, sub⟩ :=
        inv.winningPrefix later log canon (Nat.lt_of_le_of_lt two lt)
      have inElected := complete term _ n later electedLog commit whole elected lt
      have partSig := Safety.take_signature facts.signature
      exact (Safety.prefix_committable inElected partSig).trans sub

/-- The latest configuration of a log prefix, if it is the latest one at or below `bound`. -/
private theorem active_of_latest {log part : List Entry} (sub : part <+: log)
    (nonempty : configurationHistory part ≠ []) {bound : Nat}
    (within : bound <= part.length)
    : (configurationHistory part).getLast nonempty ∈ activeConfigurations log bound := by
  unfold activeConfigurations
  dsimp only
  refine mem_drop_of_latest (history_sorted log)
    (history_of_prefix sub (List.getLast_mem nonempty)) fun other otherMem otherLe => ?_
  exact le_getLast (history_sorted part) nonempty
    (history_to_prefix sub otherMem (Nat.le_trans otherLe within))

end Consensus.Proofs.Deadlock.Witness

namespace Consensus.Proofs.Deadlock.Witness

set_option linter.unusedSectionVars false
open CCF CCF.MultiNodeTransitionSystem
open Model.Node
open Safety (Frame Now Seen Canon Committed Commit CommitFacts Inv)
open Configs Logs
variable [Config.InitialConfiguration]

/--
Once some committed prefix is nonempty, the longest committed prefix has a latest
configuration, and an acknowledging member of it holds that prefix: that member
is primary or may campaign.
-/
private theorem witness {nodes : List NodeID} {f : Frame}
    (reachable : (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes).Reachable f.current)
    (inv : Inv f) (extra : ExtraInv nodes f)
    {term₀ : Nat} {part₀ : List Entry}
    (committed₀ : Committed f term₀ part₀) (partPos : 0 < part₀.length)
    : exists node local_,
        (node, local_) ∈ f.current.nodes
        /\ (local_.role = .primary \/ canStartElection local_ node) := by
  obtain ⟨term, part, committed, longer, longest⟩ :=
    longest_committed inv extra committed₀
  -- The commit step behind the longest committed part (it is nonempty, so it is a link).
  cases committed with
  | base =>
      rw [List.length_nil] at longer
      omega
  | @link leaderLog _ base idx earlier priorPart facts prior le within =>
      have whole : Committed f term (leaderLog.take idx) := .link facts prior le within
      have lenEq : (leaderLog.take idx).length = idx :=
        List.length_take_of_le facts.indexLe
      have leaderOk : LogOK leaderLog := extra.canonLogsOK term leaderLog facts.canon
      have partOk : LogOK (leaderLog.take idx) := leaderOk.take idx
      have partPrefix : leaderLog.take idx <+: leaderLog := List.take_prefix _ _
      have partSignature : isSignatureAt (leaderLog.take idx) idx = true :=
        Ledger.isSignatureAt_take_of_le (Nat.le_refl _) facts.signature
      obtain ⟨voters, quorum, acks⟩ := facts.acks
      -- The part's latest configuration is among those whose quorum acknowledged it.
      obtain ⟨some, someMem⟩ := List.exists_mem_of_ne_nil _ quorum.1
      have someActive := (List.mem_filter.mp someMem).1
      have someLe : some.index <= idx := by simpa using (List.mem_filter.mp someMem).2
      have someHistory : some ∈ configurationHistory leaderLog := by
        unfold activeConfigurations at someActive
        exact List.mem_of_mem_drop someActive
      have historyNonempty : configurationHistory (leaderLog.take idx) ≠ [] :=
        List.ne_nil_of_mem (history_to_prefix partPrefix someHistory (by rw [lenEq]; exact someLe))
      have latestLe : ((configurationHistory (leaderLog.take idx)).getLast historyNonempty).index <= idx := by
        have h := (index_bounds (List.getLast_mem historyNonempty)).2
        rwa [lenEq] at h
      have latestFiltered : (configurationHistory (leaderLog.take idx)).getLast historyNonempty
          ∈ (activeConfigurations leaderLog base).filter
              fun configuration => configuration.index <= idx :=
        List.mem_filter.mpr ⟨active_of_latest partPrefix historyNonempty (by rw [lenEq]; exact facts.baseLe),
          by simpa using latestLe⟩
      have majority := List.all_eq_true.mp quorum.2 _ latestFiltered
      simp only [decide_eq_true_eq, hasConfigurationMajority] at majority
      obtain ⟨voter, voterMem⟩ : (voters ∩ ((configurationHistory (leaderLog.take idx)).getLast
          historyNonempty).nodes).Nonempty :=
        nonempty_of_card_pos (by omega)
      obtain ⟨inVoters, inLatest⟩ := Finset.mem_inter.mp voterMem
      obtain ⟨ackerLog, seen, subLog⟩ := acks voter inVoters
      -- The acknowledging voter is a declared node.
      have voterKey : voter ∈ f.current.nodes.map Prod.fst := by
        rw [extra.keys]
        exact extra.seenKeys voter ⟨term, ackerLog⟩ seen
      obtain ⟨⟨key, voterState⟩, voterMember, keyEq⟩ := List.mem_map.mp voterKey
      simp only at keyEq
      subst keyEq
      -- The voter still holds the committed part.
      have ackerTake : ackerLog.take idx = leaderLog.take idx := by
        have h := (List.prefix_iff_eq_take.mp subLog).symm
        rwa [lenEq] at h
      have ackerSignature : isSignatureAt ackerLog idx = true :=
        Ledger.isSignatureAt_of_prefix subLog partSignature
      have partInVoter : leaderLog.take idx <+: voterState.log := by
        rcases inv.persist key voterState ⟨term, ackerLog⟩ idx voterMember seen ackerSignature with
          kept | ⟨later, log, lt, _, canon, missing⟩
        · rwa [ackerTake] at kept
        · exfalso
          have ackerTermAt : termAt ackerLog idx = term := by
            rw [← Safety.termAt_take (Nat.le_refl idx), ackerTake,
              Safety.termAt_take (Nat.le_refl idx), facts.termAtIndex]
          rw [ackerTake] at missing
          rw [ackerTermAt] at lt
          exact missing (committed_in_canon inv whole canon lt)
      -- Its committed log lies within the longest committed part.
      have committedInPart : voterState.committedLog <+: leaderLog.take idx := by
        obtain ⟨_, _, other, otherCommitted, _, withinOther⟩ :=
          (inv.commit_backed key voterState voterMember).1
        exact withinOther.trans (longest _ _ otherCommitted)
      have frontier : voterState.commitIndex <= voterState.log.length :=
        (inv.frontier key voterState voterMember).1
      have commitLe : voterState.commitIndex <= (leaderLog.take idx).length := by
        have := committedInPart.length_le
        rwa [NodeState.committedLog, List.length_take, Nat.min_eq_left frontier] at this
      -- It is not retired, so it has a role.
      have loc := Local.loc_of_reachable reachable voterMember
      have notRemoved : key ∉ removedNodes (leaderLog.take idx) := by
        intro removed
        simp only [removedNodes, latest_eq historyNonempty] at removed
        exact (Finset.mem_sdiff.mp removed).2 inLatest
      have latchNone : voterState.retiredCommittedIndex = none := by
        cases latch : voterState.retiredCommittedIndex with
        | none => rfl
        | some _ =>
            exfalso
            have confirmed := retiredCommittedNodes_mono committedInPart (loc.1 (by simp [latch]))
            obtain ⟨entry, entryMem, inConfirmations⟩ := mem_retiredCommittedNodes.mp confirmed
            obtain ⟨n, bound, rfl⟩ := List.getElem_of_mem entryMem
            exact notRemoved
              (removedNodes_prefix partOk (List.take_prefix _ _)
                ((partOk n bound).2 inConfirmations))
      have two : 2 <= voterState.currentTerm := by
        have mono := inv.term_mono key voterState ⟨term, ackerLog⟩ voterMember seen
        obtain ⟨owner, led⟩ := inv.owner facts.canon
        exact Nat.le_trans (Safety.led_floor inv.electionCerts led) mono
      have active : Not (voterState.role = .none) := by
        intro none
        rcases loc.2 none with some | young
        · simp [latchNone] at some
        · omega
      refine ⟨key, voterState, voterMember, ?_⟩
      by_cases primary : voterState.role = .primary
      · exact Or.inl primary
      right
      refine ⟨?_, Or.inl ?_, fun retired => ?_⟩
      · cases role : voterState.role <;> simp_all
      · refine mem_configurationMembers (configuration :=
          (configurationHistory (leaderLog.take idx)).getLast historyNonempty) ?_ inLatest
        unfold NodeState.signedActiveConfigurations NodeState.activeConfigurations
        refine List.mem_filter.mpr ⟨active_of_latest partInVoter historyNonempty commitLe, ?_⟩
        have signed : idx <= maxCommittableIndex voterState.log :=
          Ledger.signatureIndex_le_maxCommittableIndex
            (Ledger.isSignatureAt_of_prefix partInVoter partSignature)
        simpa using Nat.le_trans latestLe signed
      · have := Local.latch_of_retired retired
        simp [latchNone] at this

end Consensus.Proofs.Deadlock.Witness

namespace Consensus.Proofs.Deadlock

open CCF
open Model.Node

public theorem deadlock_free_after_bootstrap (config : Finset NodeID)
    (nodes : List NodeID)
    : ({
            Model.transitionSystem config nodes with
              init :=
                fun state =>
                  (Model.transitionSystem config nodes).Reachable state
                  /\ Properties.Bootstrapped state
          }
        : TransitionSystem).DeadlockFree := by
  let _ : Config.InitialConfiguration := ⟨config⟩
  intro state reachable
  have traced : exists f : Safety.Frame,
      f.current = state
      /\ (Model.transitionSystem config nodes).Reachable state
      /\ Safety.Inv f
      /\ Logs.ExtraInv nodes f
      /\ exists term part, Safety.Committed f term part /\ 0 < part.length := by
    induction reachable with
    | initial initialized =>
        obtain ⟨original, node, local_, member, positive⟩ := initialized
        obtain ⟨f, eq, inv, extra⟩ := Logs.frame_of_reachable original
        subst eq
        obtain ⟨_, term, part, committed, _, within⟩ := (inv.commit_backed node local_ member).1
        have frontier := (inv.frontier node local_ member).1
        have partPos : 0 < part.length := by
          have := within.length_le
          rw [List.length_take, Nat.min_eq_left frontier] at this
          omega
        exact ⟨f, rfl, original, inv, extra, term, part, committed, partPos⟩
    | step _ stepped ih =>
        obtain ⟨f, rfl, reach, inv, extra, term, part, committed, partPos⟩ := ih
        obtain ⟨tr⟩ := Safety.LocalTransition.ofStep (nodes := nodes) stepped
        have c : Safety.Ctx f _ := ⟨tr, inv⟩
        exact ⟨f.advance _, rfl, .step reach stepped, c.inv_step, Logs.Ctx.extra_step c extra,
          term, part, Safety.Commit.advance committed, partPos⟩
  obtain ⟨f, eq, reach, inv, extra, term, part, committed, partPos⟩ := traced
  subst eq
  obtain ⟨node, local_, member, acts⟩ := Witness.witness reach inv extra committed partPos
  exact enabled_of_member (config := config) (nodes := nodes) inv.distinct member acts

end Consensus.Proofs.Deadlock
