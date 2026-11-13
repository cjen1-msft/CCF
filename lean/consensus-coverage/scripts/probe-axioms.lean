module

import all Consensus.Proofs.SafetyInvariant

/-! Axioms behind the major premises of the evaluated splits (does reducing the proof term
to read off the taken case stand a chance?). -/

open Consensus.Proofs.Safety in
#print axioms Ctx.now_after
open Consensus.Proofs.Safety in
#print axioms Ctx.led_after
open Consensus.Proofs.Safety in
#print axioms LocalTransition.summary
open Consensus.Proofs.Safety in
#print axioms good_of_exec
