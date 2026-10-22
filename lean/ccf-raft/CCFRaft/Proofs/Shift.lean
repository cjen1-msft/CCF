module

public import CCFRaft.Proofs.Liveness
public import CCFRaft.Proofs.Replication.Horizon

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# Suffixes of executions

The suffix of an execution is an execution observed from an intermediate state,
and keeps the untimed obligations and fair loss. Packets sent before the suffix starts
become envelopes in flight; only finitely many of them are ever delivered.
-/

open CCF CCF.MultiNodeTransitionSystem
open CCFRaft.Model.Node
open CCFRaft.Liveness

namespace CCFRaft.Proofs.Shift

variable {trace : Trace} {start : Nat}

theorem action_shift (event : Liveness.Event)
    : (event.shift start).action = event.action := by
  cases event <;> simp only [Event.shift] <;> (try split) <;> rfl

theorem actor_shift (event : Liveness.Event)
    : (event.shift start).actor = event.actor := by
  cases event <;> simp only [Event.shift] <;> (try split) <;> rfl

theorem crash_shift (event : Liveness.Event) (node : NodeID)
    : event.shift start = .crash node <-> event = .crash node := by
  cases event <;> simp only [Event.shift] <;> (try split) <;> simp

theorem sent_shift {packet : Packet}
    : (trace.shift start).Sent packet
      <-> trace.Sent { packet with sent := start + packet.sent } := by
  simp [Trace.Sent, Trace.shift, action_shift]

/-- What a resolution of the suffix resolves in the execution. -/
theorem resolution_shift {index : Nat} {packet : Packet}
    (resolved : ((trace.shift start).event index).resolution = some packet)
    : exists original,
        (trace.event (start + index)).resolution = some original
        /\ start <= original.sent
        /\ packet = { original with sent := original.sent - start } := by
  simp only [Trace.shift] at resolved
  cases event : trace.event (start + index) with
  | deliver original =>
      rw [event] at resolved
      simp only [Event.shift] at resolved
      split at resolved
      · simp [Event.resolution] at resolved
      · simp only [Event.resolution, Option.some.injEq] at resolved
        exact ⟨original, rfl, by omega, resolved.symm⟩
  | drop original =>
      rw [event] at resolved
      simp only [Event.shift] at resolved
      split at resolved
      · simp [Event.resolution] at resolved
      · simp only [Event.resolution, Option.some.injEq] at resolved
        exact ⟨original, rfl, by omega, resolved.symm⟩
  | _ =>
      rw [event] at resolved
      simp [Event.shift, Event.resolution] at resolved

variable {config : Finset NodeID} {nodes : List NodeID}

theorem valid_shift (valid : trace.ValidFrom config nodes) (start : Nat)
    : (trace.shift start).ValidFrom config nodes := by
  refine {
    initial := CCFRaft.Proofs.Liveness.reachable valid start
    step := fun index action selected => ?_
    stutter := fun index none => ?_
    running := fun index node actor => ?_
    failures := fun index => ?_
    resolution := fun index packet resolved => ?_
    inFlight := ?_
  }
  · simp only [Trace.shift, action_shift] at selected ⊢
    rw [show start + (index + 1) = start + index + 1 by omega]
    exact valid.step (start + index) action selected
  · simp only [Trace.shift, action_shift] at none ⊢
    rw [show start + (index + 1) = start + index + 1 by omega]
    exact valid.stutter (start + index) none
  · simp only [Trace.shift, actor_shift] at actor ⊢
    exact valid.running (start + index) node actor
  · have failed := valid.failures (start + index)
    simp only [Trace.shift]
    rw [show start + (index + 1) = start + index + 1 by omega]
    cases event : trace.event (start + index) with
    | crash node =>
        rw [event] at failed
        simpa [Event.shift] using failed
    | deliver packet =>
        rw [event] at failed
        by_cases early : packet.sent < start <;> simpa [Event.shift, early] using failed
    | drop packet =>
        rw [event] at failed
        by_cases early : packet.sent < start <;> simpa [Event.shift, early] using failed
    | _ =>
        rw [event] at failed
        simpa [Event.shift] using failed
  · obtain ⟨original, resolvedOriginal, later, rfl⟩ := resolution_shift resolved
    obtain ⟨sent, before, unique⟩ := valid.resolution (start + index) original resolvedOriginal
    refine ⟨
      sent_shift.mpr
        (by
          simpa [show start + (original.sent - start) = original.sent by omega]
            using sent),
      by simp only; omega,
      fun earlier lt same => ?_
    ⟩
    cases earlierResolved : ((trace.shift start).event earlier).resolution with
    | none => rw [earlierResolved] at same; cases same
    | some other =>
        obtain ⟨otherOriginal, otherResolved, otherLater, rfl⟩ := resolution_shift earlierResolved
        rw [earlierResolved] at same
        simp only [Option.map_some, Option.some.injEq, Prod.mk.injEq] at same
        apply unique (start + earlier) (by omega)
        rw [otherResolved]
        simp only [Option.map_some, Option.some.injEq, Prod.mk.injEq]
        exact ⟨by omega, same.2⟩
  · have injective : Function.Injective (fun index : Nat => start + index) :=
      fun _ _ eq => Nat.add_left_cancel eq
    refine ((valid.inFlight.union
              (Replication.old_resolutions_finite valid start)).preimage
              injective.injOn).subset
      ?_
    rintro index ⟨envelope, delivered⟩
    simp only [Trace.shift] at delivered
    simp only [Set.mem_preimage, Set.mem_union, Set.mem_ofPred_eq]
    cases event : trace.event (start + index) with
    | deliverInFlight original =>
        exact Or.inl ⟨original, rfl⟩
    | deliver packet =>
        rw [event] at delivered
        simp only [Event.shift] at delivered
        split at delivered
        · exact Or.inr ⟨packet, rfl, by assumption⟩
        · cases delivered
    | drop packet =>
        rw [event] at delivered
        simp only [Event.shift] at delivered
        split at delivered <;> cases delivered
    | _ =>
        rw [event] at delivered
        simp [Event.shift] at delivered

/-- A local event of the suffix is the same local event of the execution. -/
theorem local_shift {index : Nat} {node : NodeID} {input : Input}
    : (trace.shift start).event index = .local node input
      <-> trace.event (start + index) = .local node input := by
  simp only [Trace.shift]
  cases trace.event (start + index) <;> simp only [Event.shift] <;> (try split) <;> simp

theorem fair_shift {model : LivenessModel} (fair : model.FairFrom trace) (start : Nat)
    : model.FairFrom (trace.shift start) := by
  refine
    {
      execution := valid_shift fair.execution start
      heartbeats := fun index leader peer due => ?_
      signatures := fun index leader due => ?_
      confirmations := fun index leader due => ?_
    }
  · obtain ⟨later, le, holds⟩ := fair.heartbeats (start + index) leader peer due
    refine ⟨later - start, by omega, ?_⟩
    have same : start + (later - start) = later := by omega
    rcases holds with stopped | ⟨state, frontier, found, event, backlog⟩
    · left
      intro due'
      apply stopped
      simpa only [Trace.PeerDue, Trace.shift, same] using due'
    · right
      refine ⟨state, frontier, ?_, ?_, backlog⟩
      · simpa only [Trace.shift, same] using found
      · rw [local_shift, same]
        exact event
  · obtain ⟨later, le, holds⟩ := fair.signatures (start + index) leader due
    refine ⟨later - start, by omega, ?_⟩
    have same : start + (later - start) = later := by omega
    rcases holds with stopped | ⟨entries, event, member⟩
    · left
      intro due'
      apply stopped
      simpa only [Trace.SignatureDue, Trace.shift, same] using due'
    · right
      refine ⟨entries, ?_, member⟩
      rw [local_shift, same]
      exact event
  · obtain ⟨later, le, holds⟩ := fair.confirmations (start + index) leader due
    refine ⟨later - start, by omega, ?_⟩
    have same : start + (later - start) = later := by omega
    rcases holds with stopped | ⟨entries, event, member⟩
    · left
      intro due'
      apply stopped
      simpa only [Trace.ConfirmationDue, Trace.shift, same] using due'
    · right
      refine ⟨entries, ?_, member⟩
      rw [local_shift, same]
      exact event

theorem fair_loss_shift (valid : trace.ValidFrom config nodes) {participants : Finset NodeID}
    (fair : FairLoss trace participants) (start : Nat)
    : FairLoss (trace.shift start) participants := by
  intro source target traffic sourceIn targetIn attempts cutoff
  have original : InfinitelySent trace source target traffic := by
    intro cutoff'
    obtain ⟨packet, sent, after, packetSource, packetTarget, matching⟩ := attempts cutoff'
    exact ⟨{ packet with sent := start + packet.sent }, sent_shift.mp sent, by simp only; omega,
      packetSource, packetTarget, matching⟩
  obtain ⟨old, oldBound⟩ := Set.Finite.bddAbove (Replication.old_resolutions_finite valid start)
  obtain ⟨index, packet, after, event, packetSource, packetTarget, matching⟩ :=
    fair source target traffic sourceIn targetIn original (max (start + cutoff) (old + 1))
  have late : start <= packet.sent := by
    by_contra early
    have := oldBound ⟨packet, by rw [event]; rfl, Nat.lt_of_not_le early⟩
    omega
  refine ⟨
    index - start,
    { packet with sent := packet.sent - start },
    by omega,
    ?_,
    packetSource,
    packetTarget,
    matching
  ⟩
  have notEarly : Not (packet.sent < start) := by omega
  simp only [Trace.shift, show start + (index - start) = index by omega, event, Event.shift,
    notEarly, ite_false]

end CCFRaft.Proofs.Shift
