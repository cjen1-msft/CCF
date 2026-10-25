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

omit [HasProtocol W Model.State] [HasTime W] [HasLive W] in
/-- If the peer acknowledges within `bound` of every point, then within
`delay + interval + bound` after every point it sends a successful acknowledgement.
The primary passes within `interval` of a delay after the point, and the
acknowledgement delivered after that pass was sent after the point, because
delivery takes at most `delay`. The trace and its clock are abstract so that this
applies to a cut of a recording. -/
theorem ack_sent_within {trace : Trace W Liveness.Event} {clock : Nat -> Real}
    {start last : Nat} {stop delay interval bound : Real} {peer : NodeID}
    (mono : forall index later, index <= later -> later <= last -> clock index <= clock later)
    (ends : forall index step, trace.stepAt index = some step -> index < last)
    (prompt
      : forall index step packet sent,
          trace.stepAt index = some step
          -> step.action = .deliver packet
          -> trace.SentAt sent packet
          -> clock index <= clock sent + delay)
    (sentOf
      : forall index step packet,
          trace.stepAt index = some step
          -> step.action = .deliver packet
          -> exists sent, sent < index /\ trace.SentAt sent packet)
    (passes
      : forall moment : Real,
          clock start <= moment
          -> moment + interval <= stop
          -> exists index step,
              start <= index
              /\ moment < clock index
              /\ clock index <= moment + interval
              /\ trace.stepAt index = some step)
    (acks
      : forall base,
          start <= base
          -> base <= last
          -> clock base + bound <= stop
          -> exists later step reply response,
              base < later
              /\ clock later <= clock base + bound
              /\ trace.stepAt later = some step
              /\ step.action = .deliver reply
              /\ reply.envelope.source = peer
              /\ reply.envelope.payload = .appendEntriesResponse response
              /\ response.success = true)
    (delayNonneg : 0 <= delay) (boundNonneg : 0 <= bound) {index : Nat}
    (startLe : start <= index) (indexLe : index <= last)
    (timely : clock index + (delay + interval + bound) <= stop)
    : exists sent reply response,
        index < sent
        /\ clock sent <= clock index + (delay + interval + bound)
        /\ trace.SentAt sent reply
        /\ reply.envelope.source = peer
        /\ reply.envelope.payload = .appendEntriesResponse response
        /\ response.success = true := by
  have startClock := mono start index startLe indexLe
  obtain ⟨base, baseStep, baseStart, baseAfter, baseBefore, baseStepped⟩ :=
    passes (clock index + delay) (by linarith) (by linarith)
  have baseLt := ends base baseStep baseStepped
  obtain ⟨later, step, reply, response, after, laterClock, stepped, delivers, source, payload,
      success⟩ := acks base baseStart baseLt.le (by linarith)
  have laterLt := ends later step stepped
  obtain ⟨sent, sentLt, sentAt⟩ := sentOf later step reply stepped delivers
  have arrival := prompt later step reply sent stepped delivers sentAt
  have baseLe := mono base later after.le laterLt.le
  have sentLe := mono sent later sentLt.le laterLt.le
  have indexLt : index < sent := by
    by_contra early
    have := mono sent index (by omega) indexLe
    linarith
  exact ⟨sent, reply, response, indexLt, by linarith, sentAt, source, payload, success⟩

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

/-- A node that sends a successful acknowledgement within `gap` after every early
enough point of the window does not time out at least `fresh` after the start,
where `fresh` exceeds `gap` and is at most half an election timeout. -/
theorem no_timeout_of_acks {bounds : Bounds}
    (elections : trace.ElectionScheduling (some (bounds.electionTimeout / 2)))
    {gap fresh : Real} (ratio : gap < fresh) (freshLe : fresh <= bounds.electionTimeout / 2)
    {start index : Nat} {step : CCF.Execution.Step W Liveness.Event} {node : NodeID}
    (afterStart : start <= index) (stepped : trace.stepAt index = some step)
    (event : step.action = .local node (.timeout .election))
    {first : W} (firstFound : trace.stateAt start = some first)
    (late : time first + fresh <= time step.before)
    (acks
      : forall earlier point,
          start <= earlier
          -> earlier <= index
          -> trace.stateAt earlier = some point
          -> time point + gap < time step.before
          -> exists sent sender reply response,
              earlier < sent
              /\ trace.stepAt sent = some sender
              /\ time sender.before <= time point + gap
              /\ trace.SentAt sent reply
              /\ reply.envelope.source = node
              /\ reply.envelope.payload = .appendEntriesResponse response
              /\ response.success = true)
    : False := by
  obtain ⟨reset, resetPoint, _, before, resetFound, recent, resetStep, resetStepped, isReset⟩ :=
    recent_reset
      (fun _ _ _ _ le firstFound lastFound => admissible.time_le le firstFound lastFound)
      ratio afterStart firstFound (admissible.before stepped) late
      (reset := fun later =>
        exists reset, trace.stepAt later = some reset /\ ElectionReset reset node)
      (fun earlier point after le recorded early => by
        obtain ⟨sent, sender, reply, response, after, senderStepped, inTime, sentAt, source,
            payload, success⟩ := acks earlier point after le recorded early
        obtain ⟨reset, resetStepped, isReset⟩ := reset_of_ack admissible sentAt payload success
        rw [senderStepped, Option.some.injEq] at resetStepped
        subst reset
        exact ⟨sent, sender.before, after, admissible.before senderStepped, inTime,
          sender, senderStepped, source ▸ isReset⟩)
  have := elections reset index resetStep step node before resetStepped stepped event isReset
  rw [admissible.before resetStepped, Option.some.injEq] at resetFound
  rw [← resetFound] at recent
  linarith

end Recorded

end CCFRaft.Proofs.Leadership
