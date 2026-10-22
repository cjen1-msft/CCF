module

public import CCFRaft.Liveness.Assumptions
public import Mathlib.Tactic.Linarith

@[expose] public section

/-!
# Timers that keep being reset

A timer that is reset within `gap` of every point of an execution has been reset
less than `window > gap` before any point at least `window` after the start.
This turns the heartbeat and delivery bounds into the timer condition that
`LivenessModel.Valid.electionTimers` excludes.
-/

namespace CCFRaft.Proofs.Leadership

open CCFRaft.Liveness

/-- If every index more than `gap` before `index` is followed, strictly later and
within `gap` in time, by a `reset`, and `index` is at least `window` after the
start, then a reset happens strictly before `index` and less than `window` before
it. -/
theorem recent_reset {trace : Trace} (monotone : Monotone trace.time)
    {reset : Nat -> Prop} {gap window : Real} (lt : gap < window) {index : Nat}
    (late : trace.time 0 + window <= trace.time index)
    (follows
      : forall earlier,
          earlier <= index
          -> trace.time earlier + gap < trace.time index
          -> exists later,
              earlier < later
              /\ trace.time later <= trace.time earlier + gap
              /\ reset later)
    : exists later,
        later < index /\ trace.time index - window < trace.time later /\ reset later := by
  classical
  set anchor := Nat.findGreatest (fun j => trace.time j <= trace.time index - window) index
    with anchorDef
  have anchorSpec : trace.time anchor <= trace.time index - window :=
    Nat.findGreatest_spec (P := fun j => trace.time j <= trace.time index - window)
      (Nat.zero_le index) (by linarith)
  have anchorLe : anchor <= index :=
    Nat.findGreatest_le (P := fun j => trace.time j <= trace.time index - window) index
  obtain ⟨later, after, within, holds⟩ := follows anchor anchorLe (by linarith)
  have before : later < index := by
    by_contra notBefore
    have := monotone (Nat.le_of_not_lt notBefore)
    linarith
  refine ⟨later, before, ?_, holds⟩
  have next : Not (trace.time (anchor + 1) <= trace.time index - window) :=
    Nat.findGreatest_is_greatest (P := fun j => trace.time j <= trace.time index - window)
      (Nat.lt_succ_self anchor) (by omega)
  have mono := monotone (show anchor + 1 <= later by omega)
  simp only [not_le] at next
  linarith

end CCFRaft.Proofs.Leadership
