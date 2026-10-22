module

public import CCFRaft.Liveness.Assumptions
public import Mathlib.Data.Set.Finite.Lattice

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# Old traffic eventually stops arriving

Each step sends finitely many packets and each packet resolves at most once, so
for any cutoff only finitely many events resolve a packet sent before it. The
initial network is finite and each of its copies is delivered at most once, so
in-flight deliveries also stop.
-/

open CCFRaft CCFRaft.Model.Node CCFRaft.Liveness

namespace CCFRaft.Proofs.Replication

variable {trace : Trace} {config : Finset NodeID} {nodes : List NodeID}
  (execution : trace.ValidFrom config nodes)

include execution

/-- The packets sent before `start` have bounded ordinals. -/
theorem ordinal_bound (start : Nat)
    : exists bound,
        forall packet,
          trace.Sent packet -> packet.sent < start -> packet.ordinal < bound := by
  refine ⟨
    (Finset.range start).sup
      fun index =>
        (((trace.event index).action.bind (outgoing (trace.state index))).map
          List.length).getD
          0,
    fun packet sent early => ?_
  ⟩
  unfold Trace.Sent at sent
  cases sends
        : (trace.event packet.sent).action.bind (outgoing (trace.state packet.sent)) with
  | none => simp [sends] at sent
  | some messages =>
      simp only [sends, Option.bind_some] at sent
      have lt := (List.getElem?_eq_some_iff.mp sent).1
      have le := Finset.le_sup (f := fun index =>
        (((trace.event index).action.bind (outgoing (trace.state index))).map
          List.length).getD 0) (Finset.mem_range.mpr early)
      simp only [sends, Option.map_some, Option.getD_some] at le
      omega

/-- Only finitely many events resolve packets sent before `start`. -/
theorem old_resolutions_finite (start : Nat)
    : {index |
        exists packet, (trace.event index).resolution = some packet /\ packet.sent < start
      }.Finite := by
  classical
  obtain ⟨bound, ordinals⟩ := ordinal_bound execution start
  let key : Nat -> Nat × Nat := fun index =>
    ((trace.event index).resolution.map fun packet => (packet.sent, packet.ordinal)).getD (0, 0)
  let pairs : Finset (Nat × Nat) := Finset.range start ×ˢ Finset.range bound
  refine Set.Finite.of_finite_image (f := key) ((pairs.finite_toSet).subset ?_) ?_
  · rintro _ ⟨index, ⟨packet, resolved, early⟩, rfl⟩
    have sent := (execution.resolution index packet resolved).1
    simp only [key, resolved, Option.map_some, Option.getD_some, pairs, Finset.coe_product,
      Set.mem_prod, Finset.coe_range, Set.mem_Iio]
    exact ⟨early, ordinals packet sent early⟩
  · rintro first ⟨packet, resolved, _⟩ second ⟨packet', resolved', _⟩ same
    simp only [key, resolved, resolved', Option.map_some, Option.getD_some] at same
    by_contra different
    rcases Nat.lt_or_gt_of_ne different with lt | lt
    · exact (execution.resolution second packet' resolved').2.2 first lt
        (by simp [resolved, same])
    · exact (execution.resolution first packet resolved).2.2 second lt
        (by simp [resolved', same])

/-- Only finitely many events deliver from the initial network. -/
theorem inFlights_finite
    : {index |
        exists envelope, trace.event index = .deliverInFlight envelope
      }.Finite :=
  execution.inFlight

/-- From some index on, every delivery is of a packet sent at or after `start`. -/
theorem horizon (start : Nat)
    : exists stop,
        forall index envelope,
          stop <= index
          -> (trace.event index).delivered = some envelope
          -> exists packet,
              trace.event index = .deliver packet
              /\ packet.envelope = envelope
              /\ trace.Sent packet
              /\ start <= packet.sent
              /\ packet.sent < index := by
  obtain ⟨old, oldBound⟩ := Set.Finite.bddAbove (old_resolutions_finite execution start)
  obtain ⟨flight, flightBound⟩ := Set.Finite.bddAbove (inFlights_finite execution)
  refine ⟨max old flight + 1, fun index envelope later delivered => ?_⟩
  cases event : trace.event index with
  | deliver packet =>
      rw [event] at delivered
      simp only [Event.delivered, Option.some.injEq] at delivered
      have resolved : (trace.event index).resolution = some packet := by
        rw [event]
        rfl
      obtain ⟨sent, before, _⟩ := execution.resolution index packet resolved
      refine ⟨packet, rfl, delivered, sent, ?_, before⟩
      by_contra early
      have := oldBound ⟨packet, resolved, Nat.lt_of_not_le early⟩
      omega
  | deliverInFlight envelope' =>
      have := flightBound ⟨envelope', event⟩
      omega
  | _ => rw [event] at delivered; cases delivered

end CCFRaft.Proofs.Replication
