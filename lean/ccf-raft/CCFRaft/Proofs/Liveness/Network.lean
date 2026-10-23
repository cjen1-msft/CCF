module

public import CCFRaft.Proofs.Liveness.Admissible

@[expose] public section

/-!
# The packet ledger

Where the packets of an admissible execution come from, and when the network
stops consuming packets sent before a given index.
-/

namespace CCFRaft.Liveness

theorem Event.remaining_sublist (event : Event) (pending : List Packet)
    : List.Sublist (event.remaining pending) pending := by
  unfold Event.remaining
  split
  · exact List.eraseP_sublist
  · exact List.Sublist.refl _

theorem Event.mem_remaining {event : Event} {pending : List Packet} {packet : Packet}
    (member : packet ∈ event.remaining pending)
    : packet ∈ pending :=
  (event.remaining_sublist pending).subset member

/-- The packets of a batch are its envelopes, numbered in order from `first`. -/
theorem Packet.mem_batch {packet : Packet} {emitted : List Model.Envelope} {first : Nat}
    {sentAt : Real}
    : packet ∈ Packet.batch emitted first sentAt
      <-> exists ordinal,
            emitted[ordinal]? = some packet.envelope
            /\ packet.id = first + ordinal
            /\ packet.sentAt = sentAt := by
  unfold Packet.batch
  rw [List.mem_map]
  constructor
  · rintro ⟨⟨envelope, id⟩, member, rfl⟩
    obtain ⟨le, found⟩ := List.mem_zipIdx_iff_le_and_getElem?_sub.mp member
    exact ⟨id - first, found, by simp only; omega, rfl⟩
  · rintro ⟨ordinal, found, idEq, sentAtEq⟩
    refine ⟨(packet.envelope, first + ordinal), ?_, ?_⟩
    · rw [List.mem_zipIdx_iff_le_and_getElem?_sub]
      simpa using found
    · cases packet
      simp_all

theorem Packet.id_mem_batch {packet : Packet} {emitted : List Model.Envelope}
    {first : Nat} {sentAt : Real} (member : packet ∈ Packet.batch emitted first sentAt)
    : first <= packet.id /\ packet.id < first + emitted.length := by
  obtain ⟨ordinal, found, idEq, _⟩ := Packet.mem_batch.mp member
  have := (List.getElem?_eq_some_iff.mp found).1
  omega

end CCFRaft.Liveness

namespace CCFRaft.Proofs.Liveness.Admissible

open CCFRaft.Liveness
open Model.Node
open HasProtocol (proto)
open HasTime (time)
open HasNetwork (pending issued)

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  {system : CCF.TransitionSystem Model.State Model.Action}
  {trace : Trace W Liveness.Event}
  (admissible : Admissible system trace)

include admissible

/-- A consumed packet was outstanding. -/
theorem consumed_pending {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) {packet : Packet}
    (consumed : step.action.consumedPacket = some packet)
    : packet ∈ pending step.before := by
  have outstanding := (admissible.delivery.next stepped).1
  simp only [consumed] at outstanding
  exact outstanding

theorem issued_step {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step)
    : issued step.before <= issued step.after := by
  obtain ⟨_, emitted, _, count, _⟩ := admissible.delivery.next stepped
  omega

theorem issued_mono {earlier later : Nat} (le : earlier <= later) {first last : W}
    (firstFound : trace.stateAt earlier = some first)
    (lastFound : trace.stateAt later = some last)
    : issued first <= issued last :=
  admissible.coherent.chain (relation := fun first last => issued first <= issued last)
    (fun _ => Nat.le_refl _) (fun _ _ _ => Nat.le_trans)
    (fun _ _ stepped => admissible.issued_step stepped) le firstFound lastFound

/-- Outstanding packets have already been issued. -/
theorem id_lt {index : Nat} {point : W} (found : trace.stateAt index = some point)
    {packet : Packet} (member : packet ∈ pending point)
    : packet.id < issued point :=
  admissible.delivery.invariant admissible.coherent
    (invariant :=
      fun point => forall packet, packet ∈ pending point -> packet.id < issued point)
    (fun point init packet member => by
      rw [init.1] at member
      cases member)
    (fun step next held packet member => by
      obtain ⟨_, emitted, _, count, ledger⟩ := next
      rw [ledger, List.mem_append] at member
      rw [count]
      rcases member with kept | new
      · have := held packet (Event.mem_remaining kept)
        omega
      · exact (Packet.id_mem_batch new).2)
    found packet member

/-- Every outstanding packet was sent at an earlier step. -/
theorem pending_sent {index : Nat} {point : W} (found : trace.stateAt index = some point)
    {packet : Packet} (member : packet ∈ pending point)
    : exists sent, sent < index /\ trace.SentAt sent packet := by
  induction index generalizing point with
  | zero =>
      rw [Trace.stateAt_zero, Option.some.injEq] at found
      subst found
      rw [admissible.delivery.init.1] at member
      cases member
  | succ index ih =>
      obtain ⟨step, stepped, rfl⟩ := Trace.stateAt_succ_eq_some.mp found
      by_cases old : packet ∈ pending step.before
      · obtain ⟨sent, lt, sentAt⟩ := ih (admissible.before stepped) old
        exact ⟨sent, Nat.lt_succ_of_lt lt, sentAt⟩
      · exact ⟨index, Nat.lt_succ_self _, step, stepped, member, old⟩

/-- Every consumed packet was sent at an earlier step. -/
theorem consumed_sent {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) {packet : Packet}
    (consumed : step.action.consumedPacket = some packet)
    : exists sent, sent < index /\ trace.SentAt sent packet :=
  admissible.pending_sent (admissible.before stepped)
    (admissible.consumed_pending stepped consumed)

/-- A packet is sent by a protocol action, as one of the envelopes the action emits,
with the next sequence numbers and the time of its sending step. -/
theorem sentAt_emitted {index : Nat} {packet : Packet} (sent : trace.SentAt index packet)
    : exists step action emitted,
        trace.stepAt index = some step
        /\ step.action.action = some action
        /\ outgoing (proto step.before) action = some emitted
        /\ packet.envelope ∈ emitted
        /\ issued step.before <= packet.id
        /\ packet.id < issued step.after
        /\ packet.sentAt = time step.before := by
  obtain ⟨step, stepped, member, fresh⟩ := sent
  obtain ⟨_, emitted, produced, count, ledger⟩ := admissible.delivery.next stepped
  rw [ledger, List.mem_append] at member
  rcases member with kept | new
  · exact absurd (Event.mem_remaining kept) fresh
  · obtain ⟨ordinal, found, _, sentAtEq⟩ := Packet.mem_batch.mp new
    have emits := List.mem_of_getElem? found
    have ids := Packet.id_mem_batch new
    cases selected : step.action.action with
    | none =>
        simp only [selected, Option.some.injEq] at produced
        subst produced
        cases emits
    | some action =>
        simp only [selected, Option.bind_eq_bind, Option.bind_eq_some_iff] at produced
        obtain ⟨_, _, out⟩ := produced
        exact ⟨
          step,
          action,
          emitted,
          stepped,
          selected,
          out,
          emits,
          ids.1,
          by omega,
          sentAtEq
        ⟩

/-- Each envelope a recorded protocol action emits is sent as a packet. -/
theorem sentAt_of_emitted {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) {action : Model.Action}
    (selected : step.action.action = some action) {emitted : List Model.Envelope}
    (out : outgoing (proto step.before) action = some emitted) {envelope : Model.Envelope}
    (member : envelope ∈ emitted)
    : exists packet,
        trace.SentAt index packet
        /\ packet.envelope = envelope
        /\ packet.sentAt = time step.before := by
  obtain ⟨_, emitted', produced, _, ledger⟩ := admissible.delivery.next stepped
  have enabled := admissible.step stepped selected
  simp only [selected, enabled, out, Option.bind_eq_bind, Option.bind_some,
    Option.some.injEq] at produced
  subst produced
  obtain ⟨ordinal, found⟩ := List.mem_iff_getElem?.mp member
  refine ⟨⟨issued step.before + ordinal, envelope, time step.before⟩,
    ⟨step, stepped, ?_, fun old => ?_⟩, rfl, rfl⟩
  · rw [ledger, List.mem_append]
    exact Or.inr (Packet.mem_batch.mpr ⟨ordinal, found, rfl, rfl⟩)
  · have := admissible.id_lt (admissible.before stepped) old
    simp at this

/-- A step does not add outstanding packets numbered below `bound` once `bound`
packets have been issued. -/
private theorem countP_after {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) {bound : Nat}
    (issuedLe : bound <= issued step.before)
    : (pending step.after).countP (fun packet : Packet => packet.id < bound)
      = (step.action.remaining (pending step.before)).countP
          (fun packet : Packet => packet.id < bound) := by
  obtain ⟨_, emitted, _, _, ledger⟩ := admissible.delivery.next stepped
  rw [ledger, List.countP_append, Nat.add_eq_left, List.countP_eq_zero]
  intro packet new
  have := (Packet.id_mem_batch new).1
  simp only [decide_eq_true_eq, not_lt]
  omega

/-- Before `stop`, the network consumes every packet sent before `cutoff` that it
ever consumes: from `stop` on, each consumed packet was sent at or after `cutoff`. -/
theorem horizon (cutoff : Nat)
    : exists stop,
        cutoff <= stop
        /\ forall index step packet,
            stop <= index
            -> trace.stepAt index = some step
            -> step.action.consumedPacket = some packet
            -> exists sent,
                cutoff <= sent /\ sent < index /\ trace.SentAt sent packet := by
  cases cutoffFound : trace.stateAt cutoff with
  | none =>
      refine ⟨cutoff, Nat.le_refl _, fun index step packet le stepped _ => ?_⟩
      obtain ⟨_, found⟩ := Trace.stateAt_of_stepAt stepped
      obtain ⟨_, found'⟩ := Trace.stateAt_of_le le found
      rw [cutoffFound] at found'
      cases found'
  | some first =>
      let old (point : W) : Nat := (pending point).countP fun packet => packet.id < issued first
      have stepLe {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
          (le : cutoff <= index) (stepped : trace.stepAt index = some step)
          : old step.after <= old step.before := by
        simp only [old,
          admissible.countP_after stepped
            (admissible.issued_mono le cutoffFound (admissible.before stepped))]
        exact (Event.remaining_sublist _ _).countP_le
      obtain ⟨stop, stopPoint, le, stopFound, settled⟩ :=
        Trace.settles_of_antitone cutoffFound (measure := fun _ point => old point)
          fun index later point point' le after found found' =>
            admissible.coherent.induction (start := index)
              (motive := fun _ point' => old point' <= old point)
              (fun point' found' => by
                rw [found, Option.some.injEq] at found'
                exact found' ▸ Nat.le_refl _)
              (fun _ _ after' stepped held =>
                Nat.le_trans (stepLe (Nat.le_trans le after') stepped) held)
              later point' after found'
      refine ⟨stop, le, fun index step packet after stepped consumed => ?_⟩
      obtain ⟨sent, lt, sentAt⟩ := admissible.consumed_sent stepped consumed
      refine ⟨sent, ?_, lt, sentAt⟩
      by_contra early
      obtain ⟨sentStep, sentStepped, sentMember, _⟩ := sentAt
      have below : packet.id < issued first :=
        Nat.lt_of_lt_of_le (admissible.id_lt (Trace.stateAt_succ_of_stepAt sentStepped) sentMember)
          (admissible.issued_mono (by omega) (Trace.stateAt_succ_of_stepAt sentStepped)
            cutoffFound)
      have strict : old step.after < old step.before := by
        simp only [old,
          admissible.countP_after stepped
            (admissible.issued_mono (Nat.le_trans le after) cutoffFound
              (admissible.before stepped)),
          Event.remaining, consumed]
        obtain ⟨erased, front, back, _, same, split, erasedEq⟩ :=
          List.exists_of_eraseP (admissible.consumed_pending stepped consumed)
            (p := packet.sameIdentity) (by simp [Packet.sameIdentity])
        simp only [Packet.sameIdentity, beq_iff_eq] at same
        rw [erasedEq, split, List.countP_append, List.countP_append, List.countP_cons]
        simp only [← same, below, decide_true, ↓reduceIte]
        omega
      have atIndex := settled index step.before after (admissible.before stepped)
      have atNext := settled (index + 1) step.after (Nat.le_succ_of_le after)
        (Trace.stateAt_succ_of_stepAt stepped)
      omega

end CCFRaft.Proofs.Liveness.Admissible
