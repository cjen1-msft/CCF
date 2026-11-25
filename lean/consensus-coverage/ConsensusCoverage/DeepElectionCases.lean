module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.SolvedWitnesses
import all ConsensusCoverage.ReachPath
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.DeepElectionCases

open Consensus Consensus.Proofs Consensus.Model Safety SolvedWitnesses

set_option maxRecDepth 8192

variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)

-- The elected tuple entering led_cur also enters led_after. Its appearance
-- in the advanced ghost is witnessed by this transition, not an older term.
private theorem newElection (h : step_led_cur_led_after_inr f t c) :
    ∃ k l i, (reach% SolvedWitnesses.step_led_after_led_inr[0]) f t c c.actor k ∧
      Elected (f.advance t) c.actor k l i ∧ ElectStep f t c.actor k l i ∧
      Led (f.advance t) c.actor k := by
  obtain ⟨k, root, now, led, _, ⟨l, i, step⟩, _⟩ := h
  refine ⟨k, l, i, .inl ⟨root, now, led, now, now, led, rfl⟩, ?_, step, led⟩
  exact Or.inr ⟨f.current, rfl, step⟩

theorem electedLed (h : step_led_cur_led_after_inr f t c) :
    step_led_after_led_inr f t c := by
  obtain ⟨k, l, i, root, e, _, led⟩ := newElection c h
  exact .inl ⟨c.actor, k, root, ⟨l, i, e⟩, l, ⟨i, e⟩, i, e, led⟩

theorem electedNew (h : step_led_cur_led_after_inr f t c) :
    step_led_after_elected_after_inr f t c := by
  obtain ⟨k, l, i, root, e, step, led⟩ := newElection c h
  exact .inl ⟨c.actor, k, root, ⟨l, i, e⟩, l, ⟨i, e⟩, i, e, step, led⟩

end ConsensusCoverage.DeepElectionCases
