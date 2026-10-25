module

public import CCFRaft.Proofs.Leadership.Settles
public import CCFRaft.Proofs.Leadership.Timers
public import CCFRaft.Proofs.Replication.Run

@[expose] public section

/-!
# A stable window while participants catch up

`stable_window_catchup` replaces `InSync` in `stable_window_inSync` by a bound on
how far participants' logs diverge from the primary's at the start. A lagging
participant rejects AppendEntries, and a rejection does not reset its election
timer, so the window premise `WindowMatching` fails. Timer resets come instead
from acknowledgements: a participant sends a successful AppendEntries response
only from a step that accepts a request, and accepting passes the log check,
which resets its timer (`reset_of_ack`). The primary's repair of a participant
lagging by at most `backlog` entries ends in such an acknowledgement within
`repair maxDelay heartbeatInterval backlog`, so every participant's timer is
reset within `repair + heartbeatInterval + maxDelay` of every point of the
window (`reset_within`), and `recent_reset` rules out timeouts while the
freshness exceeds that gap.
-/

namespace CCFRaft.Proofs.Leadership

open CCF CCF.MultiNodeTransitionSystem
open Model.Node
open CCFRaft.Liveness
open CCFRaft.Proofs.Safety
open CCFRaft.Proofs.Replication
open CCFRaft.Proofs.StablePrimary
open CCFRaft.Proofs.Liveness (Admissible)
open HasProtocol (proto)
open HasTime (time)
open HasLive (live)
open HasNetwork (pending)

/-- The time within which a participant acknowledges at least the primary's log
at a given point, if its log lagged by at most `backlog` entries at the start of
the window: a few delays and heartbeat intervals for stale traffic to drain, and
two rounds of rejection and retry per lagging entry. -/
def repair (delay interval : Real) (backlog : Nat) : Real :=
  6 * delay + 4 * interval + 2 * ((backlog : Real) + 1) * (2 * delay + interval)

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]

section Recorded

variable [Config.InitialConfiguration] {nodes : List NodeID}
  {trace : Trace W Liveness.Event}
  (admissible
    : Admissible (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes) trace)

include admissible

/-- The step that sends a successful AppendEntries response resets its sender's
election timer: it accepts a request, which passes the log check. -/
theorem reset_of_ack {index : Nat} {packet : Packet} (sent : trace.SentAt index packet)
    {response : AppendEntriesResponse}
    (payload : packet.envelope.payload = .appendEntriesResponse response)
    (success : response.success = true)
    : exists step, trace.stepAt index = some step /\ ElectionReset step packet.envelope.source := by
  obtain ⟨step, action, actor, event, state, next, outputs, stepped, selected, acts, found, ran,
      _, member, source⟩ := sent_step admissible sent
  obtain ⟨_, eq, holds⟩ := CCFRaft.Proofs.Safety.summary actor state event {} _ _ ran
  have facts : Summary actor state event next outputs.outgoing := by simpa [eq] using holds
  have ok := (Summary.sends facts _ member).2
  rw [payload] at ok
  obtain ⟨requester, request, eventEq, accepted, _, _⟩ := ok.2 success
  obtain ⟨_, termLe, _, _, check, _⟩ := accepted
  refine ⟨step, stepped, ?_⟩
  cases action with
  | «local» node input =>
      obtain ⟨_, internal⟩ := acts
      rw [internal] at eventEq
      cases eventEq
  | deliver envelope =>
      obtain ⟨actorEq, received⟩ := acts
      rw [received] at eventEq
      obtain ⟨_, payloadEq⟩ := Model.Node.Event.receive.inj eventEq
      cases delivered : step.action with
      | deliver delivered' =>
          rw [delivered] at selected
          simp only [Liveness.Event.action, Option.some.injEq] at selected
          injection selected with selected
          rw [ElectionReset, delivered]
          refine ⟨by rw [selected, ← actorEq, source], ?_⟩
          rw [show nodeState (proto step.before) packet.envelope.source = some state by
            rw [source]; exact found]
          refine Or.inr ?_
          rw [selected, payloadEq]
          rcases Nat.lt_or_ge state.currentTerm request.term with lt | ge
          · exact Or.inl lt
          · exact Or.inr ⟨by omega, Or.inr (Or.inr check)⟩
      | _ => simp [delivered, Liveness.Event.action] at selected

end Recorded

end CCFRaft.Proofs.Leadership
