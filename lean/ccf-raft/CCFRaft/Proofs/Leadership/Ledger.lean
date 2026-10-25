module

public import CCFRaft.Proofs.Liveness.Network

@[expose] public section

/-!
# The packet ledger in send order

Outstanding packets are listed by increasing sequence number, so a consumed
packet splits the ledger into older packets and the rest, and a delivered
packet is the first outstanding packet of its channel.
-/

namespace CCFRaft.Proofs.Liveness.Admissible

open CCFRaft.Liveness
open HasProtocol (proto)
open HasTime (time)
open HasNetwork (pending issued)

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  {system : CCF.TransitionSystem Model.State Model.Action}
  {trace : Trace W Liveness.Event}
  (admissible : Admissible system trace)

include admissible

/-- Outstanding packets are listed in send order. -/
theorem ids_sorted {index : Nat} {point : W} (found : trace.stateAt index = some point)
    : (pending point).Pairwise fun first second => first.id < second.id :=
  admissible.coherent.induction
    (start := 0)
    (motive :=
      fun _ point => (pending point).Pairwise fun first second => first.id < second.id)
    (fun point found => by
      rw [Trace.stateAt_zero, Option.some.injEq] at found
      subst found
      rw [admissible.delivery.init.1]
      exact List.Pairwise.nil)
    (fun _ step _ stepped held => by
      obtain ⟨_, _, emitted, _, _, ledger⟩ := admissible.delivery.next stepped
      have batchIds
          : (Packet.batch emitted (issued step.before) (time step.before)).map Packet.id
            = List.range' (issued step.before) emitted.length := by
        unfold Packet.batch
        rw [List.map_map, ← List.zipIdx_map_snd]
        rfl
      have batchSorted
          : (Packet.batch emitted (issued step.before) (time step.before)).Pairwise
              fun first second => first.id < second.id := by
        rw [← List.pairwise_map (f := Packet.id), batchIds]
        exact List.pairwise_lt_range'
      rw [ledger, List.pairwise_append]
      refine ⟨held.sublist (Event.remaining_sublist _ _), batchSorted,
        fun old oldMember new newMember => ?_⟩
      have := admissible.id_lt (admissible.before stepped) (Event.mem_remaining oldMember)
      have := (Packet.id_mem_batch newMember).1
      omega)
    index point
    (Nat.zero_le _)
    found

/-- A consumed packet splits the ledger: the packets before it are older, and the
step keeps all the others. -/
theorem consumed_split {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) {packet : Packet}
    (consumed : step.action.consumedPacket = some packet)
    : exists front back,
        pending step.before = front ++ packet :: back
        /\ step.action.remaining (pending step.before) = front ++ back
        /\ forall other, other ∈ front -> other.id < packet.id := by
  have member := admissible.consumed_pending stepped consumed
  have recorded := admissible.before stepped
  obtain ⟨found, front, back, notSame, same, split, erased⟩ :=
    List.exists_of_eraseP member (p := packet.sameIdentity) (by simp [Packet.sameIdentity])
  simp only [Packet.sameIdentity, beq_iff_eq] at same
  have foundMember : found ∈ pending step.before := by
    rw [split]
    exact List.mem_append_right _ List.mem_cons_self
  have foundEq : found = packet :=
    List.inj_on_of_nodup_map (admissible.ids_nodup recorded) foundMember member same.symm
  subst foundEq
  have sorted := admissible.ids_sorted recorded
  rw [split, List.pairwise_append] at sorted
  refine ⟨front, back, split, ?_, fun other otherIn =>
    sorted.2.2 other otherIn found List.mem_cons_self⟩
  unfold Event.remaining
  rw [consumed]
  exact erased

/-- A delivered packet is the first outstanding packet of its channel. -/
theorem delivered_split {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) {packet : Packet}
    (delivered : step.action = .deliver packet)
    : exists front back,
        pending step.before = front ++ packet :: back
        /\ step.action.remaining (pending step.before) = front ++ back
        /\ forall other,
            other ∈ front
            -> other.envelope.source = packet.envelope.source
            -> Not (other.envelope.target = packet.envelope.target) := by
  obtain ⟨front, back, split, remaining, older⟩ :=
    admissible.consumed_split stepped (packet := packet) (by rw [delivered]; rfl)
  refine ⟨front, back, split, remaining, fun other otherIn source target => ?_⟩
  have inOrder := (admissible.delivery.next stepped).2.1
  rw [delivered] at inOrder
  have := inOrder other (by rw [split]; exact List.mem_append_left _ otherIn) source target
  have := older other otherIn
  omega

end CCFRaft.Proofs.Liveness.Admissible
