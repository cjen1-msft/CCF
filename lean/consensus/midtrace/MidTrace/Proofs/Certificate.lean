module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import MidTrace.Model
public import MidTrace.Properties.Certificate

import all MidTrace.Model.InitInvariant
import all Consensus.Replay.Interpreter
import all Consensus.Proofs.SafetyInvariant

namespace Consensus.MidTrace.Proofs.Certificate

open Model.Node
open Replay (Envelope Group Header Instruction NativeSend Packet ReplayState Step)
open CCF.MultiNodeTransitionSystem (removeOne)
open Consensus.MidTrace.Properties

/-- Erasing observations leaves a model run, with no assumption about the start state. -/
public theorem ValidInstructions.run {header : Header} {before after : ReplayState}
    {instructions : List Instruction} {actions : List Model.Action}
    (execution : ValidInstructions header before instructions actions after)
    : CCF.Execution.Run (Model.transitionSystem header.bootstrap []) before.state actions
        after.state := by
  induction execution with
  | nil => exact .nil _
  | cons first _ ih =>
      cases first with
      | action _ transition _ => exact .cons transition ih
      | node _ => exact ih
      | sends _ => exact ih

private theorem bind_ok {α β ε : Type} {value : Except ε α} {f : α -> Except ε β}
    {result : β} (success : value >>= f = .ok result)
    : ∃ a, value = .ok a /\ f a = .ok result := by
  cases value <;> simp_all [Bind.bind, Except.bind]

private theorem mapError_ok {α ε δ : Type} {value : Except ε α} {f : ε -> δ}
    {result : α} (success : value.mapError f = .ok result)
    : value = .ok result := by
  cases value <;> simp_all [Except.mapError]

private theorem removeOne_eq_erase {α : Type} [BEq α] (value : α) (items : List α)
    : removeOne value items = items.erase value := by
  induction items with
  | nil => rfl
  | cons head tail ih =>
      cases eq : head == value <;> simp [removeOne, List.erase, eq, ih]

private theorem pendingAfter_length {header : Header} {before after : Model.State}
    {action : Model.Action}
    (transition : Model.networkStep header.bootstrap before action = some after)
    : (pendingAfter before action).length
      = before.network.length
        - (match action with
            | .deliver _ => 1
            | .local .. => 0) := by
  cases action with
  | «local» => simp [pendingAfter]
  | deliver envelope =>
      let _ : Proofs.Config.InitialConfiguration := ⟨header.bootstrap⟩
      have queued := (Proofs.Concrete.step_deliver (nodes := []) transition).1
      apply Nat.eq_sub_of_add_eq
      simpa [pendingAfter, removeOne_eq_erase] using (List.perm_cons_erase queued).length_eq.symm

private theorem network_suffix {header : Header} {before after : Model.State}
    {action : Model.Action}
    (transition : Model.networkStep header.bootstrap before action = some after)
    : exists sent, after.network = pendingAfter before action ++ sent := by
  let _ : Proofs.Config.InitialConfiguration := ⟨header.bootstrap⟩
  cases action with
  | «local» node input =>
      obtain ⟨_, _, outputs, _, _, rfl⟩ :=
        Proofs.Concrete.step_local (nodes := []) transition
      exact ⟨outputs.outgoing, rfl⟩
  | deliver envelope =>
      obtain ⟨_, _, _, outputs, _, _, rfl⟩ :=
        Proofs.Concrete.step_deliver (nodes := []) transition
      exact ⟨outputs.outgoing, rfl⟩

private theorem action_sound {header : Header} {before after : ReplayState}
    {action : Model.Action} {step : Step} {origin : Replay.Origin} {name : String}
    (resolved : ActionMatches header before.state step action)
    (success : before.run header action name = .ok after)
    : ValidInstruction header before (.action step origin) [action] after := by
  unfold Replay.ReplayState.run at success
  split at success
  · rename_i state transition
    obtain ⟨sent, network⟩ := network_suffix (header := header) transition
    have length := pendingAfter_length (header := header) transition
    simp only [Pure.pure, Except.pure, Except.ok.injEq] at success
    cases action <;> simp only [Bool.false_eq_true, ite_false, ite_true] at length success
    all_goals rw [← length, network, List.drop_left] at success
    all_goals rw [← success]
    all_goals exact .action resolved transition network
  · cases success

private theorem checkPacket_ok {packet : Packet} {payload : Message}
    (success : Replay.checkPacket packet payload = .ok ())
    : (packet == Packet.ofMessage payload) = true := by
  unfold Replay.checkPacket at success
  dsimp only at success
  split at success
  · assumption
  · cases success

private theorem closest_mem {packet : Packet} {envelopes : List Envelope} {e : Envelope}
    (found : Replay.closest packet envelopes = some e)
    : e ∈ envelopes := by
  unfold Replay.closest at found
  cases first : envelopes.find? (fun e => (Replay.checkPacket packet e.payload).isOk) with
  | none => exact List.mem_of_find?_eq_some (by simpa [first] using found)
  | some firstEnvelope =>
      have eq : firstEnvelope = e := by simpa [first] using found
      exact eq ▸ List.mem_of_find?_eq_some first

private theorem selectPacket_ok {before : ReplayState} {source target : NodeID}
    {packet : Packet} {e : Envelope}
    (success : Replay.selectPacket before source target packet = .ok e)
    : e.source = source
      /\ e.target = target
      /\ (packet == Packet.ofMessage e.payload) = true := by
  unfold Replay.selectPacket at success
  dsimp only at success
  split at success
  · rename_i envelope selected
    obtain ⟨⟨⟩, checked, rest⟩ := bind_ok success
    split at rest
    · have eq : e = envelope := (Except.ok.inj rest).symm
      subst e
      have listed : envelope ∈ Replay.pendingBetween before source target := by
        cases found
              : Replay.closest packet (Replay.pendingBetween before source target) with
        | none => exact List.mem_of_head? (by simpa [found] using selected)
        | some first =>
            have eq : first = envelope := by simpa [found] using selected
            exact eq ▸ closest_mem found
      have endpoints : envelope.source = source /\ envelope.target = target := by
        have filtered := List.mem_filter.mp
          (show envelope ∈ (before.state.network.filter
            fun x => x.source == source && x.target == target) from listed)
        simpa using filtered.2
      exact ⟨endpoints.1, endpoints.2, checkPacket_ok checked⟩
    · cases rest
  · cases success

private theorem initSource_ok {before : ReplayState} {index view : Nat}
    {state : NodeState} (success : Replay.initSource before index view = .ok state)
    : (exists source, (source, state) ∈ before.state.nodes)
      /\ index <= state.commitIndex
      /\ (index = 0 \/ isSignatureAt state.log index = true)
      /\ termAt state.log index = view := by
  unfold Replay.initSource at success
  split at success
  · rename_i source witness found
    have eq : witness = state := Except.ok.inj success
    subst eq
    refine ⟨⟨source, List.mem_of_find?_eq_some found⟩, ?_⟩
    simpa [and_assoc] using List.find?_some found
  · cases success

private theorem sendsLoop_sound {header : Header}
    (body : NativeSend -> List Envelope -> Except String (ForInStep (List Envelope)))
    (bodySound
      : forall send queued result,
          body send queued = .ok result
          -> exists e,
              e ∈ queued
              /\ SendMatches header send e
              /\ result = .yield (removeOne e queued))
    {sends : List NativeSend} {queued : List Envelope}
    (success : forIn sends queued body = .ok [])
    : SendsMatch header sends queued := by
  induction sends generalizing queued with
  | nil =>
      change Except.ok queued = .ok [] at success
      have eq := Except.ok.inj success
      subst queued
      exact ⟨[], .nil, rfl, by simp⟩
  | cons send sends ih =>
      rw [List.forIn_cons] at success
      obtain ⟨result, ran, tail⟩ := bind_ok success
      obtain ⟨e, member, matched, rfl⟩ := bodySound send queued result ran
      obtain ⟨ordered, perm, length, all⟩ := ih tail
      have take := List.perm_cons_erase member
      rw [← removeOne_eq_erase] at take
      refine ⟨e :: ordered, take.trans (perm.cons e), by simp [length], ?_⟩
      intro pair present
      simp only [List.zip_cons_cons, List.mem_cons] at present
      rcases present with rfl | present
      · exact matched
      · exact all _ present

private theorem instruction_sound {header : Header} {before after : ReplayState}
    {instruction : Instruction}
    (success : Replay.runInstruction header before instruction = .ok after)
    : ∃ actions, ValidInstruction header before instruction actions after := by
  cases instruction with
  | observeNodeState node expected origin =>
      rw [Replay.runInstruction] at success
      obtain ⟨⟨⟩, observed, unchanged⟩ := bind_ok success
      cases Except.ok.inj unchanged
      exact ⟨[], .node observed⟩
  | observeSends sends origin =>
      rw [Replay.runInstruction] at success
      obtain ⟨queued, ran, checked⟩ := bind_ok success
      cases queued with
      | cons => cases checked
      | nil =>
          cases Except.ok.inj checked
          refine ⟨[], .sends (sendsLoop_sound _ ?_ ran)⟩
          intro send pending result step
          dsimp only at step
          obtain ⟨target, named, rest⟩ := bind_ok step
          obtain ⟨e, found⟩ := Option.isSome_iff_exists.mp (show
            (Replay.closest send.packet (pending.filter (·.target == target))).isSome from by
              cases eq : Replay.closest send.packet (pending.filter (·.target == target))
              · simp [eq] at rest
                cases rest
              · simp)
          rw [found] at rest
          obtain ⟨⟨⟩, packet, next⟩ := bind_ok rest
          have listed := List.mem_filter.mp (closest_mem found)
          have eq : e.target = target := by simpa using listed.2
          exact ⟨
            e,
            listed.1,
            ⟨eq.symm ▸ mapError_ok named, checkPacket_ok (mapError_ok packet)⟩,
            (Except.ok.inj next).symm
          ⟩
  | action step origin =>
      cases step with
      | «local» node input =>
          rw [Replay.runInstruction] at success
          obtain ⟨self, named, ran⟩ := bind_ok success
          have stepped : before.run header (.local self input) (Step.local node input).name =
              .ok after := by
            cases input <;> dsimp only at ran
            case append =>
              obtain ⟨⟨⟩, _, stepped⟩ := bind_ok ran
              exact stepped
            case sendEntries =>
              split at ran
              · exact ran
              · cases ran
            all_goals exact ran
          exact ⟨_, action_sound (.local named) stepped⟩
      | receive source destination packet =>
          rw [Replay.runInstruction] at success
          obtain ⟨src, sourceName, ran⟩ := bind_ok success
          obtain ⟨dst, destinationName, ran⟩ := bind_ok ran
          obtain ⟨e, selected, stepped⟩ := bind_ok ran
          obtain ⟨rfl, rfl, packetMatch⟩ := selectPacket_ok selected
          exact ⟨_, action_sound (.receive sourceName destinationName packetMatch) stepped⟩
      | initAsBackup node index view =>
          rw [Replay.runInstruction] at success
          obtain ⟨self, named, ran⟩ := bind_ok success
          obtain ⟨source, selected, stepped⟩ := bind_ok ran
          obtain ⟨⟨_, member⟩, committed, signature, term⟩ := initSource_ok selected
          exact ⟨_, action_sound (.initAsBackup named member committed signature term) stepped⟩

private theorem ValidInstructions.append {header : Header}
    {before middle after : ReplayState} {first second : List Instruction}
    {actions rest : List Model.Action}
    (left : ValidInstructions header before first actions middle)
    (right : ValidInstructions header middle second rest after)
    : ValidInstructions header before (first ++ second) (actions ++ rest) after := by
  induction left with
  | nil => exact right
  | cons step _ ih =>
      simpa only [List.cons_append, List.append_assoc]
        using ValidInstructions.cons step (ih right)

private theorem group_sound {header : Header} {before after : ReplayState} {group : Group}
    (success : Replay.runGroup header before group = .ok after)
    : exists actions,
        ValidInstructions header before group.instructions.toList actions after := by
  rw [Replay.runGroup, ← Array.foldlM_toList] at success
  generalize group.instructions.toList = instructions at success ⊢
  induction instructions generalizing before with
  | nil =>
      cases Except.ok.inj success
      exact ⟨[], .nil _⟩
  | cons instruction instructions ih =>
      rw [List.foldlM_cons] at success
      obtain ⟨middle, ran, tail⟩ := bind_ok success
      obtain ⟨actions, first⟩ := instruction_sound (mapError_ok ran)
      obtain ⟨rest, later⟩ := ih tail
      exact ⟨actions ++ rest, .cons first later⟩

private theorem groups_sound {header : Header} {before after : ReplayState}
    {groups : List Group}
    (success : groups.foldlM (Replay.runGroup header) before = .ok after)
    : exists actions,
        ValidInstructions header before
          (groups.flatMap fun group => group.instructions.toList) actions after := by
  induction groups generalizing before with
  | nil =>
      cases Except.ok.inj success
      exact ⟨[], .nil _⟩
  | cons group groups ih =>
      rw [List.foldlM_cons] at success
      obtain ⟨middle, ran, tail⟩ := bind_ok success
      obtain ⟨actions, first⟩ := group_sound ran
      obtain ⟨rest, later⟩ := ih tail
      exact ⟨actions ++ rest, ValidInstructions.append first later⟩

/-- Successful certification witnesses an enabled sequence of model actions from the
supplied cut, and justifies every observation in group and instruction order. -/
public theorem replayFrom_sound (header : Header) (s0 : Model.State)
    (groups : Array Group) (final : ReplayState)
    (success : Replay.replayFrom header { state := s0 } groups = .ok final)
    : exists actions,
        ValidInstructions header { state := s0 }
          (groups.toList.flatMap fun group => group.instructions.toList) actions final
        /\ CCF.Execution.Run (Model.transitionSystem header.bootstrap []) s0 actions
            final.state := by
  rw [Replay.replayFrom, ← Array.foldlM_toList] at success
  obtain ⟨actions, execution⟩ := groups_sound success
  exact ⟨actions, execution, ValidInstructions.run execution⟩

open CCF (Finset)
open Proofs.Safety

private theorem sorted_zip {log : List Entry}
    (sorted : log.Pairwise fun a b => a.term <= b.term)
    : (log.zip log.tail).all (fun (a, b) => a.term <= b.term) = true := by
  induction log with
  | nil => rfl
  | cons a rest ih =>
      cases rest with
      | nil => rfl
      | cons b rest =>
          have parts := List.pairwise_cons.mp sorted
          simp only [List.tail_cons, List.zip_cons_cons, List.all_cons, Bool.and_eq_true,
            decide_eq_true_eq]
          exact ⟨parts.1 _ List.mem_cons_self, ih parts.2⟩

private theorem checkNode_ok [Proofs.Config.InitialConfiguration]
    {accepted : Finset NodeID} {history : History} {node : NodeID} {state : NodeState}
    (bootstrap : accepted = Proofs.Config.INITIAL_CONFIGURATION \/ accepted = ∅)
    (inv : Inv history) (present : Now history node state)
    (frontier : Proofs.Direct.CommitFrontier state)
    (selfVote : state.role = .candidate -> node ∈ state.votesGranted)
    (known : state.role = .primary -> state.primaryKnown = true)
    : InitInvariant.checkNode accepted node state = .ok () := by
  have commit : state.commitIndex = 0 \/ isSignatureAt state.log state.commitIndex = true :=
    Decidable.em (state.commitIndex = 0) |>.imp (fun z => z) (fun nz =>
      frontier.2 (Nat.pos_of_ne_zero nz))
  have terms := List.all_eq_true.mpr (fun entry listed => decide_eq_true
    (inv.terms node state present entry listed))
  have sorted := sorted_zip (inv.sorted node state present)
  have active : Engaged state -> Model.BOOTSTRAP_TERM <= state.currentTerm :=
    inv.active node state present
  have candidate : (state.role == .candidate) = true ->
      (3 <= state.currentTerm
        && state.votedFor == some node
        && decide (node ∈ state.votesGranted)
        && state.log.all (·.term < state.currentTerm)) = true := by
    intro role
    replace role := beq_iff_eq.mp role
    obtain ⟨term, voted, _, _, entries⟩ := inv.candidate node state present role
    simp [term, voted, selfVote role, List.all_eq_true]
    exact entries
  have leader : (state.role == .primary) = true ->
      (!state.log.isEmpty && state.primaryKnown) = true := by
    intro role
    replace role := beq_iff_eq.mp role
    simp [inv.leader_logs node state present role, known role]
  have rooted := inv.rooted node state present
  have activeTest :
      (state.role != .none && !(state.role == .follower && state.currentTerm == 0
        && state.log.isEmpty)) = true -> decide (Model.BOOTSTRAP_TERM <= state.currentTerm) = true := by
    intro test
    apply decide_eq_true
    apply active
    simp [Engaged] at test ⊢
    grind
  have commitTest : (state.commitIndex <= state.log.length
      && (state.commitIndex == 0 || isSignatureAt state.log state.commitIndex)) = true := by
    simp [frontier.1, commit]
  unfold InitInvariant.checkNode
  dsimp only
  simp (config := { contextual := true }) only [InitInvariant.ensure, commitTest, terms,
    sorted, activeTest, candidate, leader, ite_true, pure_bind, ite_self]
  all_goals
    cases logEq : state.log with
    | nil => rfl
    | cons root tail =>
        have eq : root = Proofs.Config.GENESIS := by
          simpa [Rooted, logEq] using rooted
        subst root
        rcases bootstrap with rfl | rfl
        · simp
          rfl
        · have empty : Not (∅ : Finset NodeID).Nonempty := by
            rintro ⟨node, member⟩
            simp at member
          simp [empty]
          rfl

private theorem forM_ok {α : Type} (f : α -> Except String Unit) {items : List α}
    (ok : forall item, item ∈ items -> f item = .ok ())
    : items.forM f = .ok () := by
  induction items with
  | nil => rfl
  | cons item rest ih =>
      change (do f item; rest.forM f) = .ok ()
      rw [ok item List.mem_cons_self, ih (fun x hx => ok x (List.mem_cons_of_mem _ hx))]
      rfl

private theorem forIn_ok {α : Type} {items : List α}
    {body : α -> PUnit -> Except String (ForInStep PUnit)}
    (ok : forall item, item ∈ items -> body item ⟨⟩ = .ok (.yield ⟨⟩))
    : forIn items PUnit.unit body = .ok ⟨⟩ := by
  induction items with
  | nil => rfl
  | cons item rest ih =>
      rw [List.forIn_cons, ok item List.mem_cons_self]
      exact ih (fun x hx => ok x (List.mem_cons_of_mem _ hx))

private theorem then_ok {α β : Type} {a : Except String α} {b : Except String β}
    {value : α} {result : β} (first : a = .ok value) (next : b = .ok result)
    : (do
        let _ ← a; b)
      = .ok result := by
  rw [first]
  exact next

private theorem take_eq_of_committed_comparable {a b : NodeState}
    (aBound : a.commitIndex <= a.log.length) (bBound : b.commitIndex <= b.log.length)
    (comparable : a.committedLog <+: b.committedLog \/ b.committedLog <+: a.committedLog)
    : a.log.take (min a.commitIndex b.commitIndex)
      = b.log.take (min a.commitIndex b.commitIndex) := by
  have prefixEq (left right : NodeState) (bound : left.commitIndex <= left.log.length)
      (prefixed : left.committedLog <+: right.committedLog) :
      left.log.take (min left.commitIndex right.commitIndex) =
        right.log.take (min left.commitIndex right.commitIndex) := by
    have eq := List.prefix_iff_eq_take.mp prefixed
    have length : left.committedLog.length = left.commitIndex := by
      simp [NodeState.committedLog, List.length_take, Nat.min_eq_left bound]
    rw [length] at eq
    have ordered : left.commitIndex <= right.commitIndex := by
      have lengthLe := prefixed.length_le
      rw [length] at lengthLe
      exact Nat.le_trans lengthLe (by
        simp only [NodeState.committedLog, List.length_take]
        exact Nat.min_le_left _ _)
    simpa [NodeState.committedLog, List.take_take, Nat.min_eq_left ordered] using eq
  rcases comparable with prefixed | prefixed
  · exact prefixEq a b aBound prefixed
  · simpa [Nat.min_comm] using (prefixEq b a bBound prefixed).symm

private theorem check_ok [Proofs.Config.InitialConfiguration]
    {nodes : List NodeID} {state : Model.State} {accepted : Finset NodeID}
    (bootstrap : accepted = Proofs.Config.INITIAL_CONFIGURATION \/ accepted = ∅)
    (reachable
      : (Model.transitionSystem Proofs.Config.INITIAL_CONFIGURATION nodes).Reachable
          state)
    (selfVote
      : forall node localState,
          (node, localState) ∈ state.nodes
          -> localState.role = .candidate
          -> node ∈ localState.votesGranted)
    (known
      : forall node localState,
          (node, localState) ∈ state.nodes
          -> localState.role = .primary
          -> localState.primaryKnown = true)
    (messages
      : forall e, e ∈ state.network -> InitInvariant.checkMessage state e = .ok ())
    : InitInvariant.check accepted state = .ok () := by
  obtain ⟨_, exec, inv⟩ := inv_of_reachable reachable
  have frontier := Proofs.Direct.NodeInvariant.reachable Proofs.Direct.commitFrontier_invariant reachable
  unfold InitInvariant.check
  refine then_ok (forIn_ok ?_) (forM_ok _ messages)
  rintro ⟨i, a⟩ left
  dsimp only
  rw [checkNode_ok bootstrap inv left (frontier i a left) (selfVote i a left) (known i a left)]
  simp only [show Except.ok () = (pure () : Except String Unit) from rfl, pure_bind]
  apply then_ok (forIn_ok ?_) rfl
  rintro ⟨j, b⟩ right
  dsimp only
  split
  · rename_i lt
    have different : i ≠ j := Nat.ne_of_lt lt
    have safe : (!(a.role == .primary && b.role == .primary
        && a.currentTerm == b.currentTerm)) = true := by
      have distinct := Proofs.Election.primary_eq_of_reachable reachable left right
      cases eq : (a.role == .primary && b.role == .primary && a.currentTerm == b.currentTerm)
      · rfl
      · simp at eq
        exact (different (distinct eq.1.1 eq.1.2 eq.2)).elim
    have same := take_eq_of_committed_comparable (frontier i a left).1
      (frontier j b right).1 (committed_logs_comparable exec left right)
    simp only [InitInvariant.ensure, safe, ite_true, pure_bind, beq_iff_eq.mpr same]
    rfl
  · rfl

open Proofs.Direct (Keeps)

private def Bookkeeping (self : NodeID) (state : NodeState) : Prop :=
  (state.role = .candidate -> self ∈ state.votesGranted)
  /\ (state.role = .primary -> state.primaryKnown = true)

private theorem Bookkeeping.commit {self : NodeID} {state : NodeState}
    (held : Bookkeeping self state) (index : Nat)
    : Bookkeeping self (state.recordCommit self index) := by
  unfold NodeState.recordCommit
  dsimp only
  split
  · simp [Bookkeeping]
  · exact held

private theorem Bookkeeping.advance {self : NodeID} {state : NodeState}
    (held : Bookkeeping self state)
    : Keeps (Bookkeeping self)
        (advanceCommit (CCF.Capabilities.record self) state self) := by
  unfold advanceCommit
  dsimp only
  refine Keeps.ite' (fun _ => Keeps.pure' held) fun _ => ?_
  have committed := held.commit (highestCommittableIndex state self)
  refine Keeps.ite' (fun _ => ?_) (fun _ => Keeps.pure' committed)
  exact Keeps.ite' (fun _ => Keeps.seq' fun _ => Keeps.pure' committed)
    (fun _ => Keeps.pure' committed)

private theorem Bookkeeping.elect {self : NodeID} {state : NodeState}
    (held : Bookkeeping self state)
    : Keeps (Bookkeeping self)
        (electIfQuorum (CCF.Capabilities.record self) self state) := by
  unfold electIfQuorum
  refine Keeps.ite' (fun _ => ?_) (fun _ => Keeps.pure' held)
  unfold becomePrimary
  exact Keeps.bind'
    ((show Bookkeeping self (primaryState state) by
      simp [Bookkeeping, primaryState]).advance)
    fun _ h =>
      Keeps.seq' fun _ => Keeps.pure' h

private theorem Bookkeeping.campaign (self : NodeID) (state : NodeState)
    : Keeps (Bookkeeping self)
        (becomeCandidate (CCF.Capabilities.record self) state self) := by
  unfold becomeCandidate
  exact Keeps.bind'
    ((show Bookkeeping self (freshCandidate self state) by
      simp [Bookkeeping, freshCandidate]).elect)
    fun _ h =>
      Keeps.seq' fun _ => Keeps.pure' h

private theorem Bookkeeping.observe {self : NodeID} {state : NodeState}
    (held : Bookkeeping self state) (message : Message)
    : Bookkeeping self (observeTerm state message) := by
  cases message <;> simp only [observeTerm]
  all_goals
    first
    | exact held
    | unfold updateTerm
      repeat' split
      all_goals first | exact held | simp [Bookkeeping, becomeAwareOfNewTerm]

private theorem Bookkeeping.fromLeader {self : NodeID} {state : NodeState}
    (held : Bookkeeping self state) (r : AppendEntriesRequest)
    : Bookkeeping self (handleAppendEntiresFromPrimary self state r).1 := by
  unfold handleAppendEntiresFromPrimary
  dsimp only
  apply Bookkeeping.commit
  generalize (r.entries.drop (state.log.length - r.prevLogIndex)) = entries
  induction entries generalizing state with
  | nil => exact held
  | cons head tail ih =>
      rw [List.foldl_cons]
      apply ih
      split
      · exact Bookkeeping.commit (show Bookkeeping self { state with log := state.log ++ [head] } from held) _
      · exact held

private theorem Bookkeeping.accept {self source : NodeID} {state : NodeState}
    (held : Bookkeeping self state) (r : AppendEntriesRequest)
    : Keeps (Bookkeeping self)
        (handleAppendEntriesRequest (CCF.Capabilities.record self) self source state
          r) := by
  unfold handleAppendEntriesRequest
  dsimp only
  have observed : Bookkeeping self (if r.term = state.currentTerm
      /\ (state.role = .candidate \/ state.role = .preVoteCandidate) then
      becomeAwareOfNewTerm state r.term else state) := by
    split
    · simp [Bookkeeping, becomeAwareOfNewTerm]
    · exact held
  generalize (if r.term = state.currentTerm
    /\ (state.role = .candidate \/ state.role = .preVoteCandidate) then
    becomeAwareOfNewTerm state r.term else state) = current at observed ⊢
  refine Keeps.ite' (fun _ => ?_) fun _ => ?_
  · exact Keeps.ite' (fun _ => Keeps.seq' fun _ => Keeps.pure' observed)
      (fun _ => Keeps.seq' fun _ => Keeps.pure' observed)
  have known : Bookkeeping self { current with primaryKnown := true } :=
    ⟨observed.1, fun _ => rfl⟩
  refine Keeps.ite' (fun _ => Keeps.pure' known) fun _ => ?_
  apply Keeps.seq'
  intro _
  apply Keeps.pure'
  apply Bookkeeping.fromLeader
  split <;> exact known

private theorem Bookkeeping.append {self : NodeID} {state : NodeState}
    (held : Bookkeeping self state) (entry : EntryContent)
    : Keeps (Bookkeeping self)
        (appendEntry (CCF.Capabilities.record self) self state entry) := by
  unfold appendEntry
  simp only [pure_bind]
  repeat'
    first
    | refine Keeps.ite' (fun _ => ?_) fun _ => ?_
    | refine Keeps.seq' fun _ => ?_
  all_goals
    split
    · exact Keeps.pure' held
    · exact Keeps.seq' fun _ => Keeps.seq' fun _ => Keeps.pure' held

private theorem Bookkeeping.send {self : NodeID} {state : NodeState}
    (held : Bookkeeping self state) (destination endIndex : Nat)
    : Keeps (Bookkeeping self)
        (sendEntries (CCF.Capabilities.record self) self state destination endIndex) := by
  unfold sendEntries
  exact Keeps.seq' fun _ => Keeps.seq' fun _ => Keeps.pure' held

private theorem bookkeeping_invariant [Proofs.Config.InitialConfiguration]
    : Proofs.Direct.NodeInvariant Bookkeeping := by
  refine ⟨?_, ?_⟩
  · intro node
    simp only [Model.initialNodeState]
    split <;> rename_i isLeader
    · simp [Bookkeeping, isLeader]
    · split <;> simp [Bookkeeping]
  intro self state event after outputs held
  suffices keeps : Keeps (Bookkeeping self) (Model.Node.step
      (CCF.Capabilities.record self) self state event) by
    exact keeps {} after outputs
  cases event with
  | internal input =>
      cases input with
      | append entries =>
          unfold Model.Node.step Model.Node.act appendBatch
          exact Keeps.seq' fun _ => Keeps.bind' (Keeps.foldlM' (fun _ entry h =>
            Keeps.bind' (h.append entry.content) fun mid h =>
              Keeps.foldlM' (fun _ (peer, idx) h => h.send peer idx) entry.flushes mid h)
            entries state held) fun _ h => h.advance
      | sendEntries peer idx => exact held.send peer idx
      | timeout kind =>
          cases kind with
          | election =>
              unfold Model.Node.step Model.Node.act startElection becomePreVoteCandidate
              refine Keeps.seq'
                fun _ =>
                  Keeps.ite' (fun _ => Bookkeeping.campaign self _)
                    fun _ =>
                      Keeps.seq' fun _ => Keeps.pure' (by simp [Bookkeeping])
          | checkQuorum =>
              unfold Model.Node.step Model.Node.act checkQuorum
              exact Keeps.seq' fun _ => Keeps.pure' (by simp [Bookkeeping])
      | nominateSuccessor =>
          exact (Keeps.nominateSuccessor _ self state).mono fun _ eq => eq ▸ held
      | initAsBackup entries =>
          unfold Model.Node.step Model.Node.act initAsBackup
          exact Keeps.seq'
            fun _ => Keeps.pure' (by simp [Bookkeeping, becomeAwareOfNewTerm])
  | receive source message =>
      have obs := held.observe message
      unfold Model.Node.step Model.Node.receive
      refine Keeps.ite' (fun _ => Keeps.pure' held) fun _ => ?_
      dsimp only
      generalize observeTerm state message = current at obs ⊢
      cases message with
      | appendEntriesRequest r => exact obs.accept r
      | appendEntriesResponse r =>
          unfold handleAppendEntriesResponse
          refine Keeps.ite' (fun _ => Keeps.pure' obs) fun _ => ?_
          refine Keeps.ite' (fun _ => ?_) (fun _ => Keeps.pure' obs)
          let index := max (current.matchIndex source) r.lastLogIndex
          let updated := { current with matchIndex := CCF.Function.update current.matchIndex source index }
          exact Keeps.ite' (fun _ => Bookkeeping.advance (state := updated) obs) (fun _ => Keeps.pure' obs)
      | requestVoteRequest r =>
          unfold handleRequestVoteRequest
          exact Keeps.seq' fun _ => Keeps.pure' (by split <;> exact obs)
      | requestVoteResponse r =>
          unfold handleRequestVoteResponse
          refine Keeps.ite' (fun _ => ?_) (fun _ => Keeps.pure' obs)
          exact Bookkeeping.elect ⟨fun role => CCF.Finset.mem_insert.mpr
            (Or.inr (obs.1 role)), obs.2⟩
      | requestPreVoteRequest r =>
          unfold handleRequestPreVoteRequest
          exact Keeps.seq' fun _ => Keeps.pure' obs
      | requestPreVoteResponse r =>
          unfold handleRequestPreVoteResponse
          refine Keeps.ite' (fun _ => ?_) (fun _ => Keeps.pure' obs)
          exact Keeps.ite' (fun _ => Bookkeeping.campaign self _) (fun _ => Keeps.pure' obs)
      | proposeRequestVoteRequest term =>
          unfold handleProposeRequestVoteRequest
          exact Keeps.ite' (fun _ => Bookkeeping.campaign self _) (fun _ => Keeps.pure' obs)

open CCF (Capabilities)

private def Uniform (entries : List Entry) : Prop :=
  forall e, e ∈ entries -> entries.head?.all (·.term == e.term) = true

private theorem uniform_of_batch {entries : List Entry} {term : Nat}
    (same : entries.all (·.term == term) = true)
    : Uniform entries := by
  intro entry member
  cases entries with
  | nil => simp at member
  | cons head tail =>
      have eq (e : Entry) (mem : e ∈ head :: tail) : e.term = term :=
        beq_iff_eq.mp (List.all_eq_true.mp same e mem)
      simp [eq head List.mem_cons_self, eq entry member]

-- Facts about the emitted packet that do not follow from the historical safety summary.
private def PacketExtras (self : NodeID) (term : Nat) (e : Model.Envelope) : Prop :=
  e.target ≠ self
  /\ match e.payload with
      | .appendEntriesRequest r => Uniform r.entries
      | .appendEntriesResponse r => r.term <= term
      | .requestVoteRequest r => 3 <= r.term /\ r.lastCommittableTerm < r.term
      | .requestPreVoteRequest r => r.lastCommittableTerm <= r.term
      | .proposeRequestVoteRequest t => 2 <= t
      | _ => True

private theorem sends_one {α : Type} {self peer : NodeID} {payload : Message}
    {ok : α -> Model.Envelope -> Prop} (result : α)
    (valid : ok result { source := self, target := peer, payload })
    : Sends (fun a sent => ∀ e, e ∈ sent -> ok a e)
        (do
          (Capabilities.record self).send payload peer; pure result
          : NodeEffect α) := by
  refine Sends.bind' (Sends.send _ _ _) fun _ _ eq => Sends.pure' ?_
  simp [eq, valid]

private theorem sends_append {α β : Type} {ok : Model.Envelope -> Prop}
    {m : NodeEffect α} {f : α -> NodeEffect β}
    (first : Sends (fun _ sent => ∀ e, e ∈ sent -> ok e) m)
    (rest : ∀ a, Sends (fun _ sent => ∀ e, e ∈ sent -> ok e) (f a))
    : Sends (fun _ sent => ∀ e, e ∈ sent -> ok e) (m >>= f) := by
  refine Sends.bind' first fun a _ old => (rest a).mono fun _ _ new e member => ?_
  exact (List.mem_append.mp member).elim (old e) (new e)

private theorem successor_ne_self {self peer : NodeID} {state : NodeState}
    {excluded : Finset NodeID} (found : findSuccessor state self excluded = some peer)
    : peer ≠ self := by
  unfold findSuccessor at found
  dsimp only at found
  let peers := (eligiblePeers state self \ excluded).sort
  change List.foldl _ none peers = some peer at found
  have all : forall p, p ∈ peers -> p ≠ self := by
    intro p member
    exact (CCF.Finset.mem_erase.mp (CCF.Finset.mem_sdiff.mp (CCF.Finset.mem_sort.mp member)).1).1
  generalize peers = ps at found all
  have fold := List.foldlRecOn (motive := fun r : Option NodeID =>
    ∀ p, r = some p -> p ≠ self) ps
      (fun best candidate => match best with
        | none => some candidate
        | some selected =>
            if rankBelow
                (state.matchIndex selected, latestMembershipIndex state.activeConfigurations selected, selected)
                (state.matchIndex candidate, latestMembershipIndex state.activeConfigurations candidate, candidate)
              then some candidate else best)
      (b := none) (by simp)
  apply fold _ peer found
  intro best saved candidate member
  cases best with
  | none => simpa using all candidate member
  | some best =>
      dsimp only
      split
      · simpa using all candidate member
      · exact saved

private theorem nominate_extras {self : NodeID} {state : NodeState}
    (active : state.role = .primary -> 2 <= state.currentTerm) (excluded : Finset NodeID)
    (bound : Nat)
    : Sends (fun _ sent => ∀ e, e ∈ sent -> PacketExtras self bound e)
        (nominateSuccessor (Capabilities.record self) state self excluded) := by
  unfold nominateSuccessor
  refine Sends.guard_bind fun leader => ?_
  split
  · rename_i peer found
    exact sends_one _ ⟨successor_ne_self found, active leader⟩
  · exact Sends.pure' (by simp)

private theorem advance_extras {self : NodeID} {state : NodeState}
    (active : state.role = .primary -> 2 <= state.currentTerm) (bound : Nat)
    : Sends
        (fun after sent =>
          after.currentTerm = state.currentTerm
          /\ ∀ e, e ∈ sent -> PacketExtras self bound e)
        (advanceCommit (Capabilities.record self) state self) := by
  unfold advanceCommit
  dsimp only
  have term (index : Nat) : (state.recordCommit self index).currentTerm = state.currentTerm := by
    unfold NodeState.recordCommit
    dsimp only
    split <;> rfl
  refine Sends.ite' (fun _ => Sends.pure' ⟨rfl, by simp⟩) fun _ => ?_
  refine Sends.ite' (fun _ => ?_) fun _ => Sends.pure' ⟨term _, by simp⟩
  refine Sends.ite' (fun _ => ?_) fun _ => Sends.pure' ⟨term _, by simp⟩
  refine Sends.bind' (nominate_extras active _ bound) fun _ _ all => Sends.pure' ?_
  exact ⟨term _, by simpa using all⟩

private theorem sendEntries_extras (self : NodeID) (state : NodeState)
    (peer endIndex bound : Nat)
    : Sends
        (fun after sent =>
          after.currentTerm = state.currentTerm
          /\ after.role = state.role
          /\ ∀ e, e ∈ sent -> PacketExtras self bound e)
        (sendEntries (Capabilities.record self) self state peer endIndex) := by
  unfold sendEntries
  refine Sends.guard_bind fun ⟨_, eligible, _, _, uniform, _⟩ => ?_
  refine Sends.bind' (Sends.send _ _ _) fun _ _ eq => Sends.pure' ⟨rfl, rfl, ?_⟩
  intro e member
  simp [eq] at member
  subst e
  exact ⟨(CCF.Finset.mem_erase.mp eligible).1, uniform_of_batch uniform⟩

private theorem appendEntry_extras (self : NodeID) (state : NodeState)
    (content : EntryContent) (bound : Nat)
    : Sends
        (fun after sent =>
          after.currentTerm = state.currentTerm
          /\ after.role = state.role
          /\ ∀ e, e ∈ sent -> PacketExtras self bound e)
        (appendEntry (Capabilities.record self) self state content) := by
  unfold appendEntry
  simp only [pure_bind]
  repeat'
    first
    | refine Sends.ite' (fun _ => ?_) fun _ => ?_
    | refine Sends.guard_bind fun _ => ?_
  all_goals
    split
    · exact Sends.pure' ⟨rfl, rfl, by simp⟩
    · refine Sends.guard_bind fun _ => ?_
      refine Sends.bind' (Sends.forIn' (R := PacketExtras self bound) fun peer _ member => ?_)
        fun _ _ all => Sends.pure' ⟨rfl, rfl, by simpa using all⟩
      have mem := CCF.Finset.mem_sort.mp member
      refine sends_one _ ⟨(CCF.Finset.mem_erase.mp mem).1, ?_⟩
      simp [makeAppendEntriesRequest, messageEntries, mem, Uniform]

private theorem appendBatch_extras {self : NodeID} {state : NodeState}
    (active : state.role = .primary -> 2 <= state.currentTerm)
    (entries : List AppendEntryInput) (bound : Nat)
    : Sends (fun _ sent => ∀ e, e ∈ sent -> PacketExtras self bound e)
        (appendBatch (Capabilities.record self) self state entries) := by
  let I (next : NodeState) (sent : List Model.Envelope) :=
    next.currentTerm = state.currentTerm /\ next.role = .primary
    /\ ∀ e, e ∈ sent -> PacketExtras self bound e
  have join {x y : List Model.Envelope}
      (old : ∀ e, e ∈ x -> PacketExtras self bound e)
      (new : ∀ e, e ∈ y -> PacketExtras self bound e) :
      ∀ e, e ∈ x ++ y -> PacketExtras self bound e :=
    fun e member => (List.mem_append.mp member).elim (old e) (new e)
  unfold appendBatch
  refine Sends.guard_bind fun enabled => ?_
  refine Sends.bind'
    (Sends.foldlM' (I := I) ?_ entries state [] ⟨rfl, enabled.1, by simp⟩)
    fun current sent prior => ?_
  · intro current sent entry h
    refine Sends.bind' (appendEntry_extras self current entry.content bound)
      fun next later ⟨term, leader, fresh⟩ => ?_
    have h' : I next (sent ++ later) := ⟨term.trans h.1, leader.trans h.2.1, join h.2.2 fresh⟩
    refine (Sends.foldlM' (I := I) (fun mid queued (peer, idx) h => ?_) entry.flushes next
      (sent ++ later) h').mono fun _ _ result => by simpa [List.append_assoc] using result
    refine (sendEntries_extras self mid peer idx bound).mono fun _ later ⟨eq, role, fresh⟩ => ?_
    exact ⟨eq.trans h.1, role.trans h.2.1, join h.2.2 fresh⟩
  · refine (advance_extras (state := current) (self := self)
      (fun _ => prior.1.symm ▸ active enabled.1) bound).mono fun _ _ ⟨_, new⟩ => ?_
    exact join prior.2.2 new

private theorem sends_both {α : Type} {p q : α -> List Model.Envelope -> Prop}
    {m : NodeEffect α} (left : Sends p m) (right : Sends q m)
    : Sends (fun a sent => p a sent /\ q a sent) m := by
  intro before res after ran
  obtain ⟨xs, xeq, px⟩ := left before res after ran
  obtain ⟨ys, yeq, qy⟩ := right before res after ran
  have eq : xs = ys := List.append_cancel_left (xeq.symm.trans yeq)
  exact ⟨xs, xeq, px, eq ▸ qy⟩

private theorem primary_extras (self : NodeID) (candidate : NodeState) (bound : Nat)
    (active : 2 <= candidate.currentTerm)
    : Sends (fun _ sent => ∀ e, e ∈ sent -> PacketExtras self bound e)
        (becomePrimary (Capabilities.record self) self candidate) := by
  unfold becomePrimary
  refine Sends.bind' (sends_both (advanceCommit_sends self _)
    (advance_extras (state := primaryState candidate) (fun _ => active) bound))
    fun leader sent ⟨⟨advanced, _⟩, _, old⟩ => ?_
  refine Sends.bind' (Sends.forIn' (R := PacketExtras self bound) fun peer _ member => ?_)
    fun _ _ new => Sends.pure' ?_
  · have other : peer ≠ self := (CCF.Finset.mem_erase.mp (CCF.Finset.mem_sort.mp member)).1
    have start : leader.sentIndex peer = leader.log.length := by
      rw [advanced.sentIndex, advanced.log]
      rfl
    refine sends_one _ ⟨other, ?_⟩
    simp [makeAppendEntriesRequest, start, messageEntries, Uniform]
  · intro e member
    simp only [List.append_nil] at member
    exact (List.mem_append.mp member).elim (old e) (new e)

private theorem election_extras (self : NodeID) (candidate : NodeState) (bound : Nat)
    (active : candidate.role = .candidate -> 2 <= candidate.currentTerm)
    : Sends (fun _ sent => ∀ e, e ∈ sent -> PacketExtras self bound e)
        (electIfQuorum (Capabilities.record self) self candidate) := by
  unfold electIfQuorum
  exact Sends.ite' (fun won => primary_extras self candidate bound (active won.1))
    (fun _ => Sends.pure' (by simp))

private theorem term_bounded {log : List Entry} {term : Nat}
    (terms : ∀ e, e ∈ log -> e.term <= term) (index : Nat)
    : termAt log index <= term := by
  unfold termAt
  cases found : entryAt? log index with
  | none => exact Nat.zero_le _
  | some e => exact terms e (Proofs.Ledger.entryAt_mem found)

private theorem campaign_extras (self : NodeID) (pre : NodeState) (bound : Nat)
    (active : 2 <= pre.currentTerm)
    (terms : ∀ entry, entry ∈ pre.log -> entry.term <= pre.currentTerm)
    : Sends (fun _ sent => ∀ e, e ∈ sent -> PacketExtras self bound e)
        (becomeCandidate (Capabilities.record self) pre self) := by
  unfold becomeCandidate
  refine sends_append (election_extras self (freshCandidate self pre) bound (fun _ => by
    change 2 <= pre.currentTerm + 1
    omega)) fun _ => ?_
  refine Sends.bind' (broadcast_sends self _ _) fun _ _ all => Sends.pure' ?_
  intro e member
  obtain ⟨_, other, packet⟩ := all e (by simpa using member)
  refine ⟨other, ?_⟩
  rw [packet]
  have ht := term_bounded terms (lastCommittableIndex pre)
  change 3 <= pre.currentTerm + 1 /\ lastCommittableTerm pre < pre.currentTerm + 1
  unfold lastCommittableTerm
  omega

private theorem start_extras (self : NodeID) (pre : NodeState) (bound : Nat)
    (active : Engaged pre -> 2 <= pre.currentTerm)
    (terms : ∀ entry, entry ∈ pre.log -> entry.term <= pre.currentTerm)
    : Sends (fun _ sent => ∀ e, e ∈ sent -> PacketExtras self bound e)
        (startElection (Capabilities.record self) pre self) := by
  unfold startElection
  refine Sends.guard_bind fun can => ?_
  have active := active (canStartElection_engaged can)
  unfold becomePreVoteCandidate
  dsimp only
  refine Sends.ite' (fun _ => campaign_extras self _ bound active terms) fun _ => ?_
  refine Sends.bind' (broadcast_sends self _ _) fun _ _ all => Sends.pure' ?_
  intro e member
  obtain ⟨_, other, packet⟩ := all e (by simpa using member)
  refine ⟨other, ?_⟩
  rw [packet]
  exact term_bounded terms _

private theorem aeReply_extras (self source : NodeID) (pre : NodeState)
    (r : AppendEntriesRequest) (other : source ≠ self)
    (terms : ∀ entry, entry ∈ pre.log -> entry.term <= pre.currentTerm)
    : Sends (fun after sent => ∀ e, e ∈ sent -> PacketExtras self after.currentTerm e)
        (handleAppendEntriesRequest (Capabilities.record self) self source pre r) := by
  unfold handleAppendEntriesRequest
  dsimp only
  have hterm : (if r.term = pre.currentTerm
      /\ (pre.role = .candidate \/ pre.role = .preVoteCandidate) then
      becomeAwareOfNewTerm pre r.term else pre).currentTerm = pre.currentTerm := by
    split
    · rename_i same
      exact same.1
    · rfl
  have hlog : (if r.term = pre.currentTerm
      /\ (pre.role = .candidate \/ pre.role = .preVoteCandidate) then
      becomeAwareOfNewTerm pre r.term else pre).log = pre.log := by
    split <;> rfl
  generalize (if r.term = pre.currentTerm
      /\ (pre.role = .candidate \/ pre.role = .preVoteCandidate) then
      becomeAwareOfNewTerm pre r.term else pre) = st at hterm hlog ⊢
  refine Sends.ite' (fun _ => ?_) fun _ => ?_
  · refine Sends.ite' (fun _ => sends_one _ ⟨other, Nat.le_refl _⟩) fun _ => ?_
    exact sends_one _ ⟨other, by rw [hterm, hlog]; exact term_bounded terms _⟩
  · refine Sends.ite' (fun _ => Sends.pure' (by simp)) fun _ => ?_
    have reply (current : NodeState) :
        Sends (fun after sent => ∀ e, e ∈ sent -> PacketExtras self after.currentTerm e)
          (do
            let (next, response) := handleAppendEntiresFromPrimary self current r
            (Capabilities.record self).send (.appendEntriesResponse response) source
            pure next : NodeEffect NodeState) := by
      have spec := fromLeader_spec self current r
      cases eq : handleAppendEntiresFromPrimary self current r with
      | mk new response =>
          rw [eq] at spec
          dsimp only at spec
          refine sends_one _ ⟨other, ?_⟩
          change response.term <= new.currentTerm
          rw [spec.1, spec.2.2.2.2.2.2.2]
          exact Nat.le_refl _
    exact reply _

private theorem weaken_bound {α : Type} {self : NodeID} {m : NodeEffect α}
    (getTerm : α -> Nat)
    (all : ∀ term, Sends (fun _ sent => ∀ e, e ∈ sent -> PacketExtras self term e) m)
    : Sends (fun a sent => ∀ e, e ∈ sent -> PacketExtras self (getTerm a) e) m :=
  fun outputs result after ran => all (getTerm result) outputs result after ran

set_option maxHeartbeats 750000 in
private theorem receive_extras (self source : NodeID) (pre : NodeState)
    (message : Message) (other : source ≠ self)
    (active : Engaged pre -> 2 <= pre.currentTerm)
    (terms : ∀ e, e ∈ pre.log -> e.term <= pre.currentTerm)
    : Sends (fun after sent => ∀ e, e ∈ sent -> PacketExtras self after.currentTerm e)
        (receive (Capabilities.record self) self source pre message) := by
  unfold receive
  refine Sends.ite' (fun _ => Sends.pure' (by simp)) fun _ => ?_
  dsimp only
  cases message with
  | appendEntriesRequest r =>
      rcases observe_bumping pre (message := .appendEntriesRequest r) trivial
        with ⟨bump, eq⟩ | ⟨_, eq⟩
      · rw [eq]
        exact aeReply_extras self source _ r other fun e mem => Nat.le_of_lt (Nat.lt_of_le_of_lt
          (terms e mem) bump)
      · rw [eq]
        exact aeReply_extras self source _ r other terms
  | appendEntriesResponse r =>
      rcases observe_response pre r with ⟨_, _, eq⟩ | ⟨_, eq⟩ <;> rw [eq]
      · simp [handleAppendEntriesResponse, bumpedState]
        exact Sends.pure' (by simp)
      · unfold handleAppendEntriesResponse
        refine Sends.ite' (fun _ => Sends.pure' (by simp)) fun leader => ?_
        have primary : pre.role = .primary := by simpa using leader
        have two := active (by simp [Engaged, primary])
        refine Sends.ite' (fun _ => ?_) fun _ => Sends.pure' (by simp)
        refine Sends.ite' (fun _ => ?_) fun _ => Sends.pure' (by simp)
        apply weaken_bound NodeState.currentTerm
        intro term
        let index := max (pre.matchIndex source) r.lastLogIndex
        let updated := { pre with matchIndex := CCF.Function.update pre.matchIndex source index }
        exact (advance_extras (self := self) (state := updated) (fun _ => two) term).mono
          fun _ _ h => h.2
  | requestVoteRequest r =>
      unfold handleRequestVoteRequest
      exact sends_one _ ⟨other, trivial⟩
  | requestPreVoteRequest r =>
      unfold handleRequestPreVoteRequest
      exact sends_one _ ⟨other, trivial⟩
  | requestVoteResponse r =>
      rcases observe_bumping pre (message := .requestVoteResponse r) trivial
        with ⟨_, eq⟩ | ⟨_, eq⟩ <;> rw [eq]
      · simp [handleRequestVoteResponse, bumpedState]
        exact Sends.pure' (by simp)
      · unfold handleRequestVoteResponse
        refine Sends.ite' (fun won => ?_) fun _ => Sends.pure' (by simp)
        exact weaken_bound NodeState.currentTerm fun term => election_extras self _ term
          (fun _ => active (by simp [Engaged, won.1]))
  | requestPreVoteResponse r =>
      rcases observe_bumping pre (message := .requestPreVoteResponse r) trivial
        with ⟨_, eq⟩ | ⟨_, eq⟩ <;> rw [eq]
      · simp [handleRequestPreVoteResponse, bumpedState]
        exact Sends.pure' (by simp)
      · unfold handleRequestPreVoteResponse
        refine Sends.ite' (fun won => ?_) fun _ => Sends.pure' (by simp)
        refine Sends.ite' (fun _ => ?_) fun _ => Sends.pure' (by simp)
        exact weaken_bound NodeState.currentTerm fun term => campaign_extras self _ term
          (active (by simp [Engaged, won.1])) terms
  | proposeRequestVoteRequest t =>
      unfold observeTerm handleProposeRequestVoteRequest
      refine Sends.ite' (fun can => ?_) fun _ => Sends.pure' (by simp)
      exact weaken_bound NodeState.currentTerm fun term =>
        campaign_extras self _ term (active (canStartElection_engaged can.2)) terms

private theorem local_extras (self : NodeID) (pre : NodeState) (event : Event)
    (other : ∀ source payload, event = .receive source payload -> source ≠ self)
    (active : Engaged pre -> 2 <= pre.currentTerm)
    (terms : ∀ e, e ∈ pre.log -> e.term <= pre.currentTerm)
    : Sends (fun after sent => ∀ e, e ∈ sent -> PacketExtras self after.currentTerm e)
        (Model.Node.step (Capabilities.record self) self pre event) := by
  have primary (leader : pre.role = .primary) : 2 <= pre.currentTerm :=
    active (by simp [Engaged, leader])
  cases event with
  | receive source payload =>
      exact receive_extras self source pre payload (other source payload rfl) active terms
  | internal input =>
      apply weaken_bound NodeState.currentTerm
      intro term
      cases input with
      | append entries => exact appendBatch_extras primary entries term
      | sendEntries peer idx =>
          exact (sendEntries_extras self pre peer idx term).mono fun _ _ h => h.2.2
      | nominateSuccessor => exact nominate_extras primary ∅ term
      | initAsBackup entries =>
          unfold Model.Node.step Model.Node.act initAsBackup
          exact Sends.guard_bind fun _ => Sends.pure' (by simp)
      | timeout timeout =>
          cases timeout with
          | election => exact start_extras self pre term active terms
          | checkQuorum =>
              unfold Model.Node.step Model.Node.act checkQuorum
              exact Sends.guard_bind fun _ => Sends.pure' (by simp)

private def PacketOK (state : Model.State) (e : Model.Envelope) : Prop :=
  e.source ≠ e.target
  /\ (exists sender,
        (e.source, sender) ∈ state.nodes /\ e.payload.term <= sender.currentTerm)
  /\ match e.payload with
      | .appendEntriesRequest r =>
          2 <= r.term
          /\ r.prevLogTerm <= r.term
          /\ (r.prevLogIndex = 0 -> r.prevLogTerm = 0)
          /\ Uniform r.entries
          /\ forall entry,
              entry ∈ r.entries -> r.prevLogTerm <= entry.term /\ entry.term <= r.term
      | .appendEntriesResponse r => r.success = true -> 2 <= r.term
      | .requestVoteRequest r => 3 <= r.term /\ r.lastCommittableTerm < r.term
      | .requestPreVoteRequest r => 2 <= r.term /\ r.lastCommittableTerm <= r.term
      | .requestVoteResponse r =>
          r.voteGranted = true
          -> 3 <= r.term
              /\ exists candidate,
                  (e.target, candidate) ∈ state.nodes /\ r.term <= candidate.currentTerm
      | .requestPreVoteResponse _ => True
      | .proposeRequestVoteRequest t => 2 <= t

private theorem packet_preserved {before after : Model.State} {e : Model.Envelope}
    (transport
      : forall node localState,
          (node, localState) ∈ before.nodes
          -> exists later,
              (node, later) ∈ after.nodes /\ localState.currentTerm <= later.currentTerm)
    (ok : PacketOK before e)
    : PacketOK after e := by
  obtain ⟨other, ⟨sender, found, bound⟩, fields⟩ := ok
  obtain ⟨later, present, le⟩ := transport _ _ found
  refine ⟨other, ⟨later, present, Nat.le_trans bound le⟩, ?_⟩
  cases eq : e.payload <;> simp only [eq] at fields ⊢
  all_goals try exact fields
  intro yes
  obtain ⟨term, candidate, inTable, bound⟩ := fields yes
  obtain ⟨new, present, le⟩ := transport _ _ inTable
  exact ⟨term, new, present, Nat.le_trans bound le⟩

private theorem ae_bounds [Proofs.Config.InitialConfiguration]
    {source target : NodeID} {sender : NodeState} {r : AppendEntriesRequest}
    (ae : AEOk source target sender r)
    (bounded : ∀ e, e ∈ sender.log -> e.term <= sender.currentTerm)
    (sorted : sender.log.Pairwise fun a b => a.term <= b.term)
    : r.prevLogTerm <= r.term
      /\ (r.prevLogIndex = 0 -> r.prevLogTerm = 0)
      /\ ∀ e, e ∈ r.entries -> r.prevLogTerm <= e.term /\ e.term <= r.term := by
  obtain ⟨_, term, _, prev, entries, _⟩ := ae
  refine ⟨by rw [prev, term]; exact term_bounded bounded _, ?_, ?_⟩
  · intro idx
    rw [prev, idx, termAt_zero]
  · intro e member
    have inDrop := entries.sublist.subset member
    have inLog := (List.drop_sublist _ _).subset inDrop
    refine ⟨?_, term ▸ bounded e inLog⟩
    obtain ⟨index, indexBound, found⟩ := List.mem_iff_getElem.mp inDrop
    simp only [List.length_drop] at indexBound
    have within : r.prevLogIndex + index + 1 <= sender.log.length := by omega
    have entryTerm : termAt sender.log (r.prevLogIndex + index + 1) = e.term := by
      rw [List.getElem_drop] at found
      simpa [termAt_eq (by omega) within] using congrArg Entry.term found
    rw [prev, ← entryTerm]
    exact termAt_mono sorted (by omega) within

set_option maxHeartbeats 750000 in
private theorem packets_of_exec [Proofs.Config.InitialConfiguration]
    {nodes : List NodeID} {state : Model.State} {history : History}
    (exec : Exec nodes (state :: history))
    : ∀ e, e ∈ state.network -> PacketOK state e := by
  have all : ∀ {hist : History}, Exec nodes hist ->
      ∀ {current past}, hist = current :: past -> ∀ e, e ∈ current.network -> PacketOK current e := by
    intro hist executed
    induction executed with
    | initial initialized =>
        intro current past eq e member
        have currentEq := (List.cons.inj eq).1
        subst current
        simp only [initialized.2.2.2.1, List.not_mem_nil] at member
    | @step before after past action prior stepped ih =>
        intro current tail eq e member
        have currentEq := (List.cons.inj eq).1
        subst current
        obtain ⟨tr⟩ := LocalTransition.ofStep stepped
        have priorInv := good_of_exec prior _ (List.suffix_refl _) (List.cons_ne_nil _ _)
        have postExec := Exec.step prior stepped
        have inv := good_of_exec postExec _ (List.suffix_refl _) (List.cons_ne_nil _ _)
        have transport (node : NodeID) (previous : NodeState)
            (inTable : (node, previous) ∈ before.nodes) :
            exists later, (node, later) ∈ after.nodes /\ previous.currentTerm <= later.currentTerm := by
          have seen : Seen (after :: before :: past) node previous :=
            ⟨before, by simp, inTable⟩
          by_cases same : node = tr.actor
          · subst node
            exact ⟨tr.post, tr.post_mem, inv.term_mono _ _ _ tr.post_mem seen⟩
          · have stays : (node, previous) ∈ after.nodes := by
              rw [tr.nodesEq]
              exact List.mem_map.mpr ⟨_, inTable, by simp [same]⟩
            exact ⟨previous, stays, Nat.le_refl _⟩
        rcases tr.mem_network member with old | new
        · exact packet_preserved transport (ih rfl e old)
        have caused (source : NodeID) (payload : Message) (receive : tr.event = .receive source payload) :
            ∃ incoming, incoming ∈ before.network /\ incoming.source = source
              /\ incoming.target = tr.actor /\ incoming.payload = payload := by
          rcases tr.source with ⟨_, internal, _⟩ | ⟨incoming, queued, target, action, _⟩
          · rw [receive] at internal
            cases internal
          · rw [receive] at action
            have parts := Event.receive.inj action
            exact ⟨incoming, queued, parts.1.symm, target, parts.2.symm⟩
        have other (source : NodeID) (payload : Message) (receive : tr.event = .receive source payload) :
            source ≠ tr.actor := by
          obtain ⟨incoming, queued, sourceEq, target, _⟩ := caused source payload receive
          simpa [sourceEq, target] using (ih rfl incoming queued).1
        obtain ⟨sent, sentEq, shape⟩ :=
          local_extras tr.actor tr.pre tr.event other (priorInv.active _ _ tr.pre_mem)
            (priorInv.terms _ _ tr.pre_mem) {} _ _ tr.ran
        have sentEq : tr.outputs.outgoing = sent := by simpa using sentEq
        obtain ⟨different, extras⟩ := shape e (sentEq ▸ new)
        obtain ⟨src, classified⟩ := Summary.sends tr.summary e new
        have sender : (e.source, tr.post) ∈ after.nodes := src ▸ tr.post_mem
        have two (bump : Bumping e.payload) : 2 <= e.payload.term :=
          inv.message_terms e member bump
        refine ⟨fun eq => different (eq.symm.trans src), ?_⟩
        cases payload : e.payload
        all_goals simp only [payload] at extras classified sender two ⊢
        case appendEntriesRequest r =>
          obtain ⟨ae, _, _⟩ := classified
          obtain ⟨prev, zero, bounds⟩ := ae_bounds ae
            (inv.terms _ _ tr.post_mem) (inv.sorted _ _ tr.post_mem)
          exact ⟨⟨tr.post, sender, Nat.le_of_eq ae.2.1⟩, two trivial, prev, zero, extras, bounds⟩
        case appendEntriesResponse r =>
          refine ⟨⟨tr.post, sender, extras⟩, fun success => ?_⟩
          obtain ⟨source, request, receive, accepted, term, _⟩ := classified success
          obtain ⟨incoming, queued, _, _, requestEq⟩ := caused source _ receive
          have fields := (ih rfl incoming queued).2.2
          simp only [requestEq] at fields
          rw [term, ← accepted.1]
          exact fields.1
        case requestVoteRequest r =>
          exact ⟨⟨tr.post, sender, Nat.le_of_eq classified.1⟩, extras⟩
        case requestPreVoteRequest r =>
          exact ⟨⟨tr.post, sender, Nat.le_of_eq classified⟩, two trivial, extras⟩
        case requestVoteResponse r =>
          refine ⟨⟨tr.post, sender, Nat.le_of_eq classified.1⟩, fun granted => ?_⟩
          obtain ⟨request, receive, requestTerm, _, _⟩ := classified.2 granted
          obtain ⟨incoming, queued, named, _, requestEq⟩ := caused e.target _ receive
          obtain ⟨_, ⟨candidate, present, termBound⟩, fields⟩ := ih rfl incoming queued
          simp only [requestEq, named, Message.term] at present termBound fields
          obtain ⟨later, listed, le⟩ := transport _ _ present
          have same := requestTerm.trans classified.1.symm
          exact ⟨same ▸ fields.1, later, listed, same ▸ Nat.le_trans termBound le⟩
        case requestPreVoteResponse r =>
          exact ⟨⟨tr.post, sender, Nat.le_of_eq classified⟩, trivial⟩
        case proposeRequestVoteRequest term =>
          exact ⟨⟨tr.post, sender, Nat.le_of_eq classified⟩, extras⟩
  exact all exec rfl

private theorem lookup_eq_nodeState (state : Model.State) (node : NodeID)
    : state.nodes.lookup node = CCF.MultiNodeTransitionSystem.nodeState state node := by
  unfold CCF.MultiNodeTransitionSystem.nodeState
  induction state.nodes with
  | nil => rfl
  | cons entry entries ih =>
      obtain ⟨key, localState⟩ := entry
      by_cases same : node = key
      · subst key
        simp
      · have ne : key ≠ node := Ne.symm same
        rw [List.lookup_cons, beq_eq_false_iff_ne.mpr same]
        simp [ne, ih]

private theorem checkMessage_ok [Proofs.Config.InitialConfiguration]
    {state : Model.State} {e : Model.Envelope}
    (distinct : (state.nodes.map Prod.fst).Nodup) (ok : PacketOK state e)
    : InitInvariant.checkMessage state e = .ok () := by
  obtain ⟨other, ⟨sender, present, bound⟩, fields⟩ := ok
  have lookup (node : NodeID) (localState : NodeState) (present : (node, localState) ∈ state.nodes) :
      state.nodes.lookup node = some localState := by
    rw [lookup_eq_nodeState]
    exact Proofs.Direct.nodeState_of_mem distinct present
  have checked : (e.source != e.target && e.payload.term <= sender.currentTerm) = true := by
    simp [other, bound]
  unfold InitInvariant.checkMessage
  rw [lookup _ _ present]
  simp only [InitInvariant.ensure, checked, ite_true, pure_bind]
  cases payload : e.payload
  all_goals simp only [payload] at fields ⊢
  case appendEntriesRequest r =>
    obtain ⟨two, prev, zero, uniform, entries⟩ := fields
    have atZero : (r.prevLogIndex != 0 || r.prevLogTerm == 0) = true := by
      by_cases index : r.prevLogIndex = 0
      · simp [index, zero index]
      · simp [index]
    have all : (r.entries.all fun x =>
        r.prevLogTerm <= x.term && x.term <= r.term && r.entries.head?.all (·.term == x.term))
        = true := by
      apply List.all_eq_true.mpr
      intro entry member
      obtain ⟨lo, hi⟩ := entries entry member
      simp [lo, hi, uniform _ member]
    simp only [two, prev, atZero, all, decide_true, Bool.and_true, ite_true]
    rfl
  case appendEntriesResponse r =>
    have valid : (!r.success || 2 <= r.term) = true := by
      cases yes : r.success <;> simp [yes, fields]
    simp only [valid, ite_true]
    rfl
  case requestVoteRequest r =>
    simp [fields.1, fields.2]
    rfl
  case requestPreVoteRequest r =>
    simp [fields.1, fields.2]
    rfl
  case requestVoteResponse r =>
    split
    · rename_i yes
      obtain ⟨three, candidate, present, term⟩ := fields yes
      simp [lookup _ _ present, three, term]
      rfl
    · rfl
  case requestPreVoteResponse => rfl
  case proposeRequestVoteRequest =>
    simp [fields]
    rfl

/-- The concrete cut checker accepts every reachable state, whether supplied the original
bootstrap configuration or no bootstrap information. Reachability supplies the initial
membership and node-table conditions; no conditions on the cut are assumed. -/
public theorem reachable_implies_initInvariant (bootstrap : Finset NodeID)
    (nodes : List NodeID) (s0 : Model.State)
    (reachable : (Model.transitionSystem bootstrap nodes).Reachable s0)
    : InitInvariant.check bootstrap s0 = .ok () /\ InitInvariant.check ∅ s0 = .ok () := by
  let _ : Proofs.Config.InitialConfiguration := ⟨bootstrap⟩
  have book := Proofs.Direct.NodeInvariant.reachable bookkeeping_invariant reachable
  have distinct := Proofs.Direct.keys_nodup reachable
  obtain ⟨_, exec⟩ := exec_of_reachable reachable
  have packets (e : Model.Envelope) (member : e ∈ s0.network) :=
    checkMessage_ok distinct (packets_of_exec exec e member)
  have accepted (cutConfig : Finset NodeID) (eq : cutConfig = bootstrap \/ cutConfig = ∅) :=
    check_ok eq reachable (fun i a member => (book i a member).1)
      (fun i a member => (book i a member).2) packets
  exact ⟨accepted bootstrap (Or.inl rfl), accepted ∅ (Or.inr rfl)⟩

end Consensus.MidTrace.Proofs.Certificate
