module

public import CCFRaft.Proofs.Liveness.Network
public import CCFRaft.Proofs.Concrete
public import Mathlib.Data.List.Perm.Subperm

import all Init.Control.State

@[expose] public section

/-!
The packet ledger contains at most the copies of each envelope in the protocol network.
Drops remove only ledger entries; deliveries remove one occurrence from both lists.
-/

namespace CCFRaft.Proofs.Liveness.Admissible

open CCFRaft.Liveness
open CCF.MultiNodeTransitionSystem
open Model.Node
open HasProtocol (proto)
open HasTime (time)
open HasNetwork (pending issued)

private theorem batch_envelopes (emitted : List Model.Envelope) (first : Nat)
    (sentAt : Real)
    : (Packet.batch emitted first sentAt).map Packet.envelope = emitted := by
  unfold Packet.batch
  rw [List.map_map]
  exact List.zipIdx_map_fst first emitted

private theorem remaining_perm {packets : List Packet} {packet : Packet}
    (unique : (packets.map Packet.id).Nodup) (member : packet ∈ packets)
    : (packet :: packets.eraseP packet.sameIdentity).Perm packets := by
  obtain ⟨other, front, back, _, same, split, erased⟩ :=
    List.exists_of_eraseP (p := packet.sameIdentity) member
      (by simp [Packet.sameIdentity])
  have otherMember : other ∈ packets := by rw [split]; simp
  have equal : packet = other :=
    List.inj_on_of_nodup_map unique member otherMember
      (by simpa [Packet.sameIdentity] using same)
  subst other
  rw [erased, split]
  exact List.perm_middle.symm

private theorem removeOne_eq_erase {α : Type} [BEq α] (value : α) (items : List α)
    : removeOne value items = items.erase value := by
  induction items with
  | nil => rfl
  | cons head tail ih =>
      simp only [removeOne, List.erase_cons, ih]

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  [Config.InitialConfiguration] {nodes : List NodeID}
  {trace : Trace W Liveness.Event}
  (admissible : Admissible Config.INITIAL_CONFIGURATION nodes trace)

include admissible

/-- Outstanding packet envelopes form a sub-multiset of the protocol network. -/
theorem pending_subperm {index : Nat} {point : W}
    (found : trace.stateAt index = some point)
    : ((pending point).map Packet.envelope).Subperm (proto point).network := by
  apply admissible.coherent.induction
    (start := 0)
    (motive :=
      fun _ point =>
        ((pending point).map Packet.envelope).Subperm (proto point).network)
    (fun point found => by
      rw [Trace.stateAt_zero, Option.some.injEq] at found
      subst point
      rw [admissible.delivery.init.1]
      exact List.nil_subperm)
    (fun _ step _ stepped held => by
      obtain ⟨_, _, emitted, produced, _, ledger⟩ := admissible.delivery.next stepped
      rw [ledger, List.map_append, batch_envelopes]
      cases event : step.action with
      | «local» node input =>
          have selected : step.action.action = some (.local node input) := by
            simp [event, Event.action]
          have enabled := admissible.step stepped selected
          obtain ⟨pre, post, outputs, nodeFound, ran, after⟩ :=
            Concrete.step_local enabled
          have out : outgoing (proto step.before) (.local node input) =
              some outputs.outgoing := by
            simp [outgoing, nodeFound, Model.Node.step, ran]
          simp only [selected, out, Option.bind_eq_bind, Option.bind_eq_some_iff,
            Option.some.injEq] at produced
          obtain ⟨_, _, produced⟩ := produced
          rw [← produced, after]
          simpa [event, Event.remaining, Event.consumedPacket]
            using held.append (List.Subperm.refl outputs.outgoing)
      | deliver packet =>
          have selected : step.action.action = some (.deliver packet.envelope) := by
            simp [event, Event.action]
          have enabled := admissible.step stepped selected
          obtain ⟨_, pre, post, outputs, nodeFound, ran, after⟩ :=
            Concrete.step_deliver enabled
          have out : outgoing (proto step.before) (.deliver packet.envelope) =
              some outputs.outgoing := by
            simp [outgoing, nodeFound, Model.Node.step, ran]
          simp only [selected, out, Option.bind_eq_bind, Option.bind_eq_some_iff,
            Option.some.injEq] at produced
          obtain ⟨_, _, produced⟩ := produced
          have member : packet ∈ pending step.before :=
            admissible.consumed_pending stepped (by simp [event, Event.consumedPacket])
          have perm := (remaining_perm
            (admissible.ids_nodup (admissible.before stepped)) member).map Packet.envelope
          have erased := (perm.subperm.trans held).erase packet.envelope
          simp only [List.map_cons, List.erase_cons_head] at erased
          rw [← produced, after]
          simpa [event, Event.remaining, Event.consumedPacket, removeOne_eq_erase]
            using erased.append (List.Subperm.refl outputs.outgoing)
      | drop packet | crash node | idle =>
          have selected : step.action.action = none := by simp [event, Event.action]
          simp only [selected, Option.some.injEq] at produced
          rw [← produced, List.append_nil, admissible.stutter stepped selected]
          exact ((Event.remaining_sublist _ _).map Packet.envelope).subperm.trans held)
    index point
    (Nat.zero_le _)
    found

/-- Every outstanding packet's envelope is present in the protocol network. -/
theorem pending_mem_network {index : Nat} {point : W}
    (found : trace.stateAt index = some point) {packet : Packet}
    (member : packet ∈ pending point)
    : packet.envelope ∈ (proto point).network :=
  (admissible.pending_subperm found).subset (List.mem_map_of_mem member)

end CCFRaft.Proofs.Liveness.Admissible
