module

public import CCFRaft.Proofs.Replication.Link
public import CCFRaft.Proofs.Replication.Retry

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# A quiet peer settles

Fix a live, eligible peer of a stable primary that eventually stops acknowledging a given log position.
Its term reaches the primary's term, its log eventually stops changing, and its agreement with the primary's growing log settles.
Each log change acknowledges the end of the accepted batch and strictly increases a bounded potential while that end stays below the bound.
All measures read recorded points; persistent heartbeat obligations supply any later states the argument needs.
-/

open CCF CCF.MultiNodeTransitionSystem
open CCFRaft
open CCFRaft.Model.Node
open CCFRaft.Liveness
open CCFRaft.Proofs.Config
open CCFRaft.Proofs.Safety
open CCFRaft.Proofs.StablePrimary
open CCFRaft.Proofs.Liveness (Admissible)
open CCFRaft.Proofs.CommitLiveness (stable_log_prefix)
open HasProtocol (proto)

namespace CCFRaft.Proofs.Replication

variable {W : Type} [HasProtocol W Model.State]

/-- A node's log at a world, or the empty log if the node is absent.
Measures use this projection only at recorded points, with presence proved separately. -/
noncomputable def nodeLog (point : W) (node : NodeID) : List Entry :=
  ((nodeState (proto point) node).map NodeState.log).getD []

theorem nodeLog_eq {point : W} {node : NodeID} {state : NodeState}
    (found : nodeState (proto point) node = some state)
    : nodeLog point node = state.log := by
  simp [nodeLog, found]

/-- A primary's send frontier at a world, or zero if it is absent.
Presence lemmas remove the fallback when this is used as a recorded-point measure. -/
noncomputable def sentFrontier (point : W) (leader peer : NodeID) : Nat :=
  ((nodeState (proto point) leader).map fun state => state.sentIndex peer).getD 0

theorem sentFrontier_eq {point : W} {leader : NodeID} (peer : NodeID) {state : NodeState}
    (found : nodeState (proto point) leader = some state)
    : sentFrontier point leader peer = state.sentIndex peer := by
  simp [sentFrontier, found]

/-- One more than the length of a short peer log that is a prefix of the primary's,
and zero otherwise. This is a measure of a recorded world, not a total trace index. -/
noncomputable def potential (point : W) (leader peer : NodeID) (bound : Nat) : Nat := by
  classical
  exact if nodeLog point peer <+: nodeLog point leader /\ (nodeLog point peer).length < bound
    then (nodeLog point peer).length + 1 else 0

theorem potential_le (point : W) (leader peer : NodeID) (bound : Nat)
    : potential point leader peer bound <= bound := by
  unfold potential
  split
  · rename_i holds
    omega
  · exact Nat.zero_le _

theorem zip_prefix_eq {α : Type}
    : forall {left right common : List α},
        left <+: common
        -> right <+: common
        -> forall pair, pair ∈ left.zip right -> pair.1 = pair.2
  | [], _, _, _, _, _, member => by simp at member
  | _ :: _, [], _, _, _, _, member => by simp at member
  | _ :: _, _ :: _, [], left, _, _, _ => by simp at left
  | _ :: _, _ :: _, _ :: _, left, right, pair, member => by
      rw [List.cons_prefix_cons] at left right
      rcases List.mem_cons.mp member with rfl | member
      · simp [left.1, right.1]
      · exact zip_prefix_eq left.2 right.2 pair member

/-- No conflict when the follower's suffix and the batch are both prefixes of one list. -/
theorem conflictIndex_eq_none {log common : List Entry} {request : AppendEntriesRequest}
    (left : log.drop request.prevLogIndex <+: common) (right : request.entries <+: common)
    : conflictIndex log request = none := by
  unfold conflictIndex
  rw [Option.map_eq_none_iff, List.find?_eq_none]
  rintro ⟨⟨existing, incoming⟩, position⟩ member
  have same : existing = incoming :=
    zip_prefix_eq left right _ (List.fst_mem_of_mem_zipIdx member)
  simp [same]

/-- From a recorded `origin` during stable leadership, the peer has a fixed log
and term, and a fixed agreement with the primary at every recorded state. -/
structure Regime [HasLive W] [HasNetwork W] {trace : Trace W Liveness.Event} {start : Nat}
    {leader : NodeID} {term : Nat} (stable : StableLeader trace start leader term)
    (peer : NodeID) (log : List Entry) (agreed origin : Nat)
    : Prop where
  afterStart : start <= origin
  recorded : exists point, trace.stateAt origin = some point
  state
    : forall index point,
        origin <= index
        -> trace.stateAt index = some point
        -> exists state,
            nodeState (proto point) peer = some state
            /\ state.currentTerm = term
            /\ state.log = log
  agreement
    : forall index state,
        origin <= index
        -> trace.nodeAt index leader = some state
        -> agree log state.log = agreed
  fresh
    : forall index step packet,
        origin <= index
        -> trace.stepAt index = some step
        -> step.action = .deliver packet
        -> exists sent, start <= sent /\ sent < index /\ trace.SentAt sent packet

/-- The previous index of a delivered AppendEntries request, and zero otherwise. -/
def prevOf : Liveness.Event -> Nat
  | .deliver packet =>
      match packet.envelope.payload with
      | .appendEntriesRequest request => request.prevLogIndex
      | _ => 0
  | _ => 0

theorem prevOf_eq {event : Liveness.Event} {packet : Packet}
    (delivered : event = .deliver packet) {request : AppendEntriesRequest}
    (payload : packet.envelope.payload = .appendEntriesRequest request)
    : prevOf event = request.prevLogIndex := by
  subst delivered
  simp [prevOf, payload]

theorem nackResponse_failure (w : NodeState) (r : AppendEntriesRequest)
    : (nackResponse w r).success = false := by
  unfold nackResponse
  split <;> rfl

theorem nackResponse_congr {w w' : NodeState} {r r' : AppendEntriesRequest}
    (term : w.currentTerm = w'.currentTerm) (log : w.log = w'.log)
    (requestTerm : r.term = r'.term) (prev : r.prevLogIndex = r'.prevLogIndex)
    (prevTerm : r.prevLogTerm = r'.prevLogTerm)
    : nackResponse w r = nackResponse w' r' := by
  simp only [nackResponse, term, log, requestTerm, prev, prevTerm]

theorem nackResponse_short {w : NodeState} {r : AppendEntriesRequest}
    (beyond : w.log.length < r.prevLogIndex)
    : nackResponse w r
      = { term := w.currentTerm, success := false, lastLogIndex := w.log.length } := by
  simp [nackResponse, termAt_of_length_lt beyond]

/-- Repeated low and high recorded values force repeated recorded crossing steps. -/
private theorem recorded_crossing {A : Type} {trace : Trace W A}
    (coherent : trace.Coherent) {measure : W -> Nat} {threshold : Nat}
    (low
      : Often
          fun index =>
            exists point, trace.stateAt index = some point /\ measure point < threshold)
    (high
      : Often
          fun index =>
            exists point, trace.stateAt index = some point /\ threshold <= measure point)
    : Often
        fun index =>
          exists step,
            trace.stepAt index = some step
            /\ measure step.before < threshold
            /\ threshold <= measure step.after := by
  intro cutoff
  obtain ⟨first, afterCutoff, firstPoint, firstFound, below⟩ := low cutoff
  obtain ⟨last, afterFirst, lastPoint, lastFound, above⟩ := high first
  have scan
      : forall index point, first <= index -> trace.stateAt index = some point
        -> threshold <= measure point
        -> exists index step, first <= index /\ trace.stepAt index = some step
          /\ measure step.before < threshold /\ threshold <= measure step.after := by
    intro index point le
    induction index, le using Nat.le_induction generalizing point with
    | base =>
        intro found reached
        rw [firstFound, Option.some.injEq] at found
        subst found
        omega
    | succ index le ih =>
        intro found reached
        obtain ⟨step, stepped, rfl⟩ := Trace.stateAt_succ_eq_some.mp found
        by_cases below : measure step.before < threshold
        · exact ⟨index, step, le, stepped, below, reached⟩
        · exact ih step.before (coherent.before stepped) (by omega)
  obtain ⟨index, step, le, stepped, crossed⟩ :=
    scan last lastPoint afterFirst lastFound above
  exact ⟨index, afterCutoff.trans le, step, stepped, crossed⟩

variable [Config.InitialConfiguration] [HasTime W] [HasLive W] [HasNetwork W]

section Peer

variable {nodes : List NodeID} {trace : Trace W Liveness.Event}
  (admissible
    : Admissible (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes) trace)
  {start : Nat} {leader : NodeID} {term : Nat}
  (stable : StableLeader trace start leader term)
  {peer : NodeID}

include admissible stable

/-- A live, eligible peer keeps a heartbeat obligation due. -/
theorem peer_due
    (live
      : forall index point,
          start <= index -> trace.stateAt index = some point -> peer ∈ HasLive.live point)
    (eligible
      : forall index state,
          start <= index
          -> trace.nodeAt index leader = some state
          -> peer ∈ eligiblePeers state leader)
    {index : Nat} {point : W} (le : start <= index)
    (found : trace.stateAt index = some point)
    : PeerDue point leader peer := by
  obtain ⟨leaderLive, state, nodeFound, primary, _, notRetired⟩ := stable.leads le found
  exact ⟨
    leaderLive,
    live index point le found,
    state,
    nodeFound,
    primary,
    notRetired,
    eligible index state le (by rw [Trace.nodeAt_of_stateAt found, nodeFound])
  ⟩

/-- Persistent heartbeat obligations produce arbitrarily late recorded productive sends. -/
theorem sends_often {bound : Option Real} (heartbeats : trace.HeartbeatScheduling bound)
    (live
      : forall index point,
          start <= index -> trace.stateAt index = some point -> peer ∈ HasLive.live point)
    (eligible
      : forall index state,
          start <= index
          -> trace.nodeAt index leader = some state
          -> peer ∈ eligiblePeers state leader)
    : Often
        fun index =>
          exists step,
            trace.stepAt index = some step /\ ProductiveSend step leader peer := by
  obtain ⟨first, found⟩ := stable.1
  intro cutoff
  obtain ⟨index, step, le, stepped, productive⟩ :=
    (heartbeats leader peer).often found (fun _ _ le found =>
      peer_due admissible stable live eligible le found) cutoff
  exact ⟨index, le, step, stepped, productive⟩

/-- Heartbeats to a perpetually live, eligible peer prevent a finite recording from ending. -/
theorem peer_recorded {bound : Option Real} (heartbeats : trace.HeartbeatScheduling bound)
    (live
      : forall index point,
          start <= index -> trace.stateAt index = some point -> peer ∈ HasLive.live point)
    (eligible
      : forall index state,
          start <= index
          -> trace.nodeAt index leader = some state
          -> peer ∈ eligiblePeers state leader)
    (index : Nat)
    : exists point, trace.stateAt index = some point := by
  obtain ⟨first, found⟩ := stable.1
  obtain ⟨point, pointFound⟩ :=
    (heartbeats leader peer).recorded found (fun _ _ le found =>
      peer_due admissible stable live eligible le found) (Nat.le_max_left start index)
  exact Trace.stateAt_of_le (Nat.le_max_right start index) pointFound

/-- The peer reaches the primary's term and stays there at every later recorded state. -/
theorem peer_current {bound : Option Real} (heartbeats : trace.HeartbeatScheduling bound)
    (live
      : forall index point,
          start <= index -> trace.stateAt index = some point -> peer ∈ HasLive.live point)
    (eligible
      : forall index state,
          start <= index
          -> trace.nodeAt index leader = some state
          -> peer ∈ eligiblePeers state leader)
    {participants : Finset NodeID} (fair : FairLoss trace participants)
    (leaderIn : leader ∈ participants) (peerIn : peer ∈ participants)
    : exists joined point,
        start <= joined
        /\ trace.stateAt joined = some point
        /\ forall index point,
            joined <= index
            -> trace.stateAt index = some point
            -> exists state,
                nodeState (proto point) peer = some state
                /\ state.currentTerm = term := by
  obtain ⟨index, step, packet, after, stepped, event, _, target, matched⟩ :=
    fair leader peer _ leaderIn peerIn
      (heartbeats_sent admissible heartbeats stable live eligible) start
  cases payload : packet.envelope.payload with
  | appendEntriesRequest request =>
      rw [payload] at matched
      refine ⟨
        index + 1,
        step.after,
        by omega,
        Trace.stateAt_succ_of_stepAt stepped,
        fun later point le found => ?_
      ⟩
      obtain ⟨state, nodeFound, ge⟩ :=
        term_after_request admissible stepped (by rw [event]; rfl) payload matched
          (Nat.lt_of_succ_le le) found
      rw [target] at nodeFound
      have upper := peer_term_le admissible heartbeats stable fair leaderIn peerIn live eligible
        later state (by omega) nodeFound
      exact ⟨
        state,
        by rwa [Trace.nodeAt_of_stateAt found] at nodeFound,
        le_antisymm upper ge
      ⟩
  | _ =>
      rw [payload] at matched
      exact matched.elim

/-- A fixed log's agreement with the primary's growing log attains a greatest value
at a recorded state and keeps it at every later recorded state. -/
theorem agree_settles (log : List Entry) {index : Nat} (le : start <= index) {first : W}
    (found : trace.stateAt index = some first)
    : exists stop state,
        index <= stop
        /\ trace.nodeAt stop leader = some state
        /\ forall later after,
            stop <= later
            -> trace.nodeAt later leader = some after
            -> agree log after.log = agree log state.log := by
  obtain ⟨stop, point, afterIndex, stopFound, constant⟩ :=
    Trace.settles_of_monotone found (measure := fun _ point => agree log (nodeLog point leader))
      (fun earlier later before after afterStart laterLe beforeFound afterFound => by
        obtain ⟨_, old, oldFound, _⟩ := stable.leads (le.trans afterStart) beforeFound
        obtain ⟨_, new, newFound, _⟩ := stable.leads (by omega) afterFound
        rw [nodeLog_eq oldFound, nodeLog_eq newFound]
        exact agree_mono (stable_log_prefix admissible stable (le.trans afterStart) laterLe
          (by rw [Trace.nodeAt_of_stateAt beforeFound, oldFound])
          (by rw [Trace.nodeAt_of_stateAt afterFound, newFound])))
      (fun _ _ _ _ => agree_le_left _ _)
  obtain ⟨_, state, stateFound, _⟩ := stable.leads (le.trans afterIndex) stopFound
  refine ⟨
    stop,
    state,
    afterIndex,
    by rw [Trace.nodeAt_of_stateAt stopFound, stateFound],
    fun later after laterLe afterFound => ?_
  ⟩
  obtain ⟨last, lastFound, lastNode⟩ := Trace.nodeAt_eq_some.mp afterFound
  have same := constant later last laterLe lastFound
  rwa [nodeLog_eq stateFound, nodeLog_eq lastNode] at same

variable (different : Not (peer = leader))

include different

section Regime

variable {log : List Entry} {agreed origin : Nat}

/-- A request from the primary is rejected beyond the agreement, ignored below it,
or accepted up to it. Responses to other senders go back to those senders. -/
theorem request_outcome (regime : Regime stable peer log agreed origin) {index : Nat}
    {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) {packet : Packet}
    (event : step.action = .deliver packet) (began : origin <= index)
    (target : packet.envelope.target = peer) {request : AppendEntriesRequest}
    (payload : packet.envelope.payload = .appendEntriesRequest request)
    {primary : NodeState}
    (leaderFound : nodeState (proto step.before) leader = some primary)
    : exists w sends,
        w.currentTerm = term
        /\ w.log = log
        /\ outgoing (proto step.before) (.deliver packet.envelope) = some sends
        /\ (forall x, x ∈ sends -> x.target = packet.envelope.source)
        /\ (packet.envelope.source = leader
            -> request.term = term
                /\ request.prevLogIndex <= primary.log.length
                /\ request.prevLogTerm = termAt primary.log request.prevLogIndex
                /\ ((agreed < request.prevLogIndex
                      /\ Not
                          (termAt log request.prevLogIndex
                            = termAt primary.log request.prevLogIndex)
                      /\ sends
                          = [{
                              source := peer
                              target := leader
                              payload := .appendEntriesResponse (nackResponse w request)
                            }])
                    \/ (request.prevLogIndex < agreed /\ sends = [])
                    \/ (request.prevLogIndex + request.entries.length <= agreed
                        /\ sends
                            = [{
                                source := peer
                                target := leader
                                payload :=
                                  .appendEntriesResponse
                                    {
                                      term
                                      success := true
                                      lastLogIndex :=
                                        request.prevLogIndex + request.entries.length
                                    }
                              }]))) := by
  have delivered : step.action.delivered = some packet.envelope := by rw [event]; rfl
  obtain ⟨z, found, zTerm, zLog⟩ := regime.state index step.before began (admissible.before stepped)
  obtain ⟨z', found', zTerm', zLog'⟩ :=
    regime.state (index + 1) step.after (Nat.le_succ_of_le began)
      (Trace.stateAt_succ_of_stepAt stepped)
  have foundAt : nodeState (proto step.before) packet.envelope.target = some z := by
    rw [target]; exact found
  have foundAt' : nodeState (proto step.after) packet.envelope.target = some z' := by
    rw [target]; exact found'
  have le : request.term <= z.currentTerm := by
    have := request_term_le admissible stepped delivered payload foundAt'
    omega
  obtain ⟨after, sends, foundAfter, received, out⟩ :=
    receive_step admissible stepped delivered payload foundAt le
  have afterLog : after.log = log := by
    rw [foundAt', Option.some.injEq] at foundAfter
    rw [← foundAfter, zLog']
  have wTerm : (awareState z request).currentTerm = term :=
    (awareState_term z request).trans zTerm
  have wLog : (awareState z request).log = log := (awareState_log z request).trans zLog
  refine ⟨awareState z request, sends, wTerm, wLog, out, ?_, fun source => ?_⟩
  · rcases received with ⟨_, _, rfl⟩ | ⟨_, _, _, _, rfl⟩
        | ⟨_, _, _, _, _, _, _, _, _, _, rfl⟩ <;> simp
  obtain ⟨sent, sentLate, _, sentAt⟩ := regime.fresh index step packet began stepped event
  have rTerm := stable_requests admissible stable sentLate sentAt source payload
  obtain ⟨_, _, prevLe, prevTerm, entries⟩ :=
    request_at admissible stable (regime.afterStart.trans began) stepped delivered payload
      rTerm leaderFound
  have leaderNode : trace.nodeAt index leader = some primary := by
    rw [admissible.nodeAt_before stepped, leaderFound]
  have view := view_at admissible stable different (regime.afterStart.trans began) leaderNode
    (by rw [admissible.nodeAt_before stepped, found]) zTerm
  have agreement := regime.agreement index primary began leaderNode
  refine ⟨rTerm, prevLe, prevTerm, ?_⟩
  rw [target, source] at received
  rcases received with ⟨reject, _, sendsEq⟩ | ⟨_, _, ignore, _, sendsEq⟩
      | ⟨_, matched, _, _, _, _, acceptEq, _, _, _, sendsEq⟩
  · have mismatch
        : Not (termAt log request.prevLogIndex = termAt primary.log request.prevLogIndex) := by
      intro same
      rcases reject with stale | notMatched
      · omega
      by_cases short : request.prevLogIndex <= log.length
      · exact notMatched ⟨by rw [wLog]; exact short, by rw [wLog, same, prevTerm]⟩
      · have positive := view.leaderPositive _ (by omega) prevLe
        rw [termAt_of_length_lt (by omega)] at same
        omega
    refine Or.inl ⟨?_, mismatch, sendsEq⟩
    by_contra low
    exact mismatch (termAt_agree (by omega))
  · refine Or.inr (Or.inl ⟨?_, sendsEq⟩)
    have commit := view.commit
    rw [zLog, agreement] at commit
    rcases ignore with low | ⟨conflict, settledFlag⟩
    · have : (awareState z request).commitIndex = z.commitIndex := by
        unfold awareState
        split <;> rfl
      omega
    · exfalso
      obtain ⟨same, campaigning⟩ := awareState_settled settledFlag
      obtain ⟨notCandidate, notPre⟩ := campaigning (rTerm.trans zTerm.symm)
      have sub := view.settled ⟨notCandidate, notPre, by rw [← same]; exact settledFlag⟩
      rw [zLog] at sub
      rw [wLog, conflictIndex_eq_none (sub.drop request.prevLogIndex) entries] at conflict
      simp at conflict
  · refine Or.inr (Or.inr ⟨?_, by rw [sendsEq, wTerm]⟩)
    rw [afterLog, wLog] at acceptEq
    obtain ⟨prevBound, prevMatch⟩ := matched
    rw [wLog] at prevBound prevMatch
    have aligned
        : forall j, 0 < j -> j <= log.length -> j <= primary.log.length
          -> termAt log j = termAt primary.log j -> log.take j = primary.log.take j := by
      intro j positive bound leaderBound same
      have := view.matching j positive (by rw [zLog]; exact bound) leaderBound
        (by rw [zLog]; exact same)
      rwa [zLog] at this
    have prevAgree : log.take request.prevLogIndex = primary.log.take request.prevLogIndex := by
      by_cases zero : request.prevLogIndex = 0
      · simp [zero]
      · exact aligned _ (by omega) prevBound prevLe (by rw [prevMatch, prevTerm])
    have shape := acceptLog_eq prevBound prevLe prevAgree entries aligned
    rw [← acceptEq] at shape
    have batch := entries.length_le
    rw [List.length_drop] at batch
    have lengthLe : request.prevLogIndex + request.entries.length <= log.length := by
      rw [shape, List.length_append, List.length_take]
      omega
    have takeEq : log.take (request.prevLogIndex + request.entries.length)
        = primary.log.take (request.prevLogIndex + request.entries.length) := by
      rw [shape]
      exact List.take_left' (by rw [List.length_take]; omega)
    have := le_agree _ _ _ lengthLe (by omega) takeEq
    omega

/-- A rejection sent in the regime answers a current-term request beyond the
agreement, at a position mismatching the peer's fixed log. -/
theorem nack_origin (regime : Regime stable peer log agreed origin) {index : Nat}
    {packet : Packet} (sent : trace.SentAt index packet) (began : origin <= index)
    (source : packet.envelope.source = peer) (target : packet.envelope.target = leader)
    {response : AppendEntriesResponse}
    (payload : packet.envelope.payload = .appendEntriesResponse response)
    (failure : response.success = false) {primary : NodeState}
    (leaderFound : trace.nodeAt index leader = some primary)
    : exists w request,
        w.currentTerm = term
        /\ w.log = log
        /\ response = nackResponse w request
        /\ request.term = term
        /\ agreed < request.prevLogIndex
        /\ request.prevLogIndex <= primary.log.length
        /\ request.prevLogTerm = termAt primary.log request.prevLogIndex
        /\ Not
            (termAt log request.prevLogIndex
              = termAt primary.log request.prevLogIndex) := by
  obtain ⟨step, envelope, request, _, stepped, delivered, envelopeTarget, requestPayload, _⟩ :=
    response_origin admissible sent payload
  obtain ⟨delivery, event, rfl⟩ := packet_of_delivered delivered
  rw [admissible.nodeAt_before stepped] at leaderFound
  obtain ⟨w, sends, wTerm, wLog, out, aimed, detail⟩ :=
    request_outcome admissible stable different regime stepped event began
      (envelopeTarget.trans source) requestPayload leaderFound
  obtain ⟨sentStep, action, emitted, sentStepped, selected, out', member, -⟩ :=
    admissible.sentAt_emitted sent
  rw [stepped, Option.some.injEq] at sentStepped
  subst sentStep
  have selected' : step.action.action = some (.deliver delivery.envelope) := by rw [event]; rfl
  rw [selected', Option.some.injEq] at selected
  subst action
  rw [out, Option.some.injEq] at out'
  subst emitted
  have fromLeader : delivery.envelope.source = leader := by rw [← aimed _ member, target]
  obtain ⟨rTerm, prevLe, prevTerm, outcome⟩ := detail fromLeader
  rcases outcome with ⟨above, mismatch, sendsEq⟩ | ⟨_, sendsEq⟩ | ⟨_, sendsEq⟩
  · rw [sendsEq, List.mem_singleton] at member
    rw [member] at payload
    injection payload with responseEq
    exact ⟨w, request, wTerm, wLog, responseEq.symm, rTerm, above, prevLe, prevTerm, mismatch⟩
  · rw [sendsEq] at member
    simp at member
  · rw [sendsEq, List.mem_singleton] at member
    rw [member] at payload
    injection payload with responseEq
    rw [← responseEq] at failure
    simp at failure

/-- Read against the primary's later log, a rejection retries at or above the
agreement and below the rejected position. -/
theorem retry_bounds (regime : Regime stable peer log agreed origin) {w : NodeState}
    {request : AppendEntriesRequest} (wTerm : w.currentTerm = term) (wLog : w.log = log)
    (rTerm : request.term = term) {sent later : Nat} (began : origin <= sent)
    (le : sent <= later) {before after : NodeState}
    (found : trace.nodeAt sent leader = some before)
    (found' : trace.nodeAt later leader = some after)
    (prevLe : request.prevLogIndex <= before.log.length)
    (prevTerm : request.prevLogTerm = termAt before.log request.prevLogIndex)
    (mismatch
      : Not (termAt log request.prevLogIndex = termAt before.log request.prevLogIndex))
    : agreed <= retry after.log w request
      /\ retry after.log w request < min request.prevLogIndex (log.length + 1) := by
  obtain ⟨point, pointFound, _⟩ := Trace.nodeAt_eq_some.mp found'
  obtain ⟨z, zFound, zTerm, zLog⟩ := regime.state later point (began.trans le) pointFound
  have view := view_at admissible stable different (by have := regime.afterStart; omega) found'
    (by rw [Trace.nodeAt_of_stateAt pointFound, zFound]) zTerm
  have grows := stable_log_prefix admissible stable (regime.afterStart.trans began) le found found'
  have transfer : termAt after.log request.prevLogIndex = termAt before.log request.prevLogIndex :=
    termAt_of_prefix grows prevLe
  rw [← transfer] at prevTerm mismatch
  have sorted := view.sorted
  have positive := view.positive
  rw [zLog] at sorted positive
  have agreement := regime.agreement later after (began.trans le) found'
  constructor
  · have := agree_le_retry (w := w) (by rw [wLog]; exact sorted) view.leaderSorted
      (fun index => by rw [wTerm]; exact view.leaderTerms index) (prevLe.trans grows.length_le)
      prevTerm (by rw [wLog]; exact mismatch)
    rwa [wLog, agreement] at this
  · have := retry_lt (w := w) (log := after.log) (by rw [wLog]; exact positive)
      (by omega) prevTerm (by rw [wLog]; exact mismatch)
    rwa [wLog] at this

/-- The primary's match frontier cannot exceed its agreement with a fixed peer log. -/
theorem match_le_agreed (regime : Regime stable peer log agreed origin) {index : Nat}
    (began : origin <= index) {primary : NodeState}
    (leaderFound : trace.nodeAt index leader = some primary)
    : primary.matchIndex peer <= agreed := by
  obtain ⟨point, pointFound, _⟩ := Trace.nodeAt_eq_some.mp leaderFound
  obtain ⟨z, found, zTerm, zLog⟩ := regime.state index point began pointFound
  have := (view_at admissible stable different (regime.afterStart.trans began) leaderFound
    (by rw [Trace.nodeAt_of_stateAt pointFound, found]) zTerm).matchLe
  rwa [zLog, regime.agreement index primary began leaderFound] at this

/-- Once in-flight rejections come from the regime, the retry floor never drops. -/
theorem floor_step (regime : Regime stable peer log agreed origin)
    (eligible
      : forall index state,
          origin <= index
          -> trace.nodeAt index leader = some state
          -> peer ∈ eligiblePeers state leader)
    {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) (began : origin <= index)
    (late
      : forall packet,
          step.action = .deliver packet
          -> exists sent, origin <= sent /\ sent < index /\ trace.SentAt sent packet)
    {before after : NodeState}
    (found : nodeState (proto step.before) leader = some before)
    (found' : nodeState (proto step.after) leader = some after)
    : min (before.sentIndex peer) agreed <= min (after.sentIndex peer) agreed := by
  have beforeNode : trace.nodeAt index leader = some before := by
    rw [admissible.nodeAt_before stepped, found]
  rcases (leader_move admissible stable peer (regime.afterStart.trans began) stepped found found').2
      with same | ⟨endIndex, _, le, _, value, _⟩
      | ⟨envelope, response, delivered, source, target, payload, failure, value⟩
      | ⟨_, _, _, _, _, aimed⟩
  · rw [same]
  · rw [value]
    omega
  · obtain ⟨packet, event, rfl⟩ := packet_of_delivered delivered
    obtain ⟨sent, sentLate, sentBefore, sentAt⟩ := late packet event
    obtain ⟨point, pointFound⟩ := Trace.stateAt_of_le sentBefore.le (admissible.before stepped)
    obtain ⟨sender, senderFound⟩ := stable.found (regime.afterStart.trans sentLate) pointFound
    obtain ⟨w, request, wTerm, wLog, responseEq, rTerm, _, prevLe, prevTerm, mismatch⟩ :=
      nack_origin admissible stable different regime sentAt sentLate source target payload failure
        senderFound
    obtain ⟨floor, _⟩ :=
      retry_bounds admissible stable different regime wTerm wLog rTerm sentLate sentBefore.le
        senderFound beforeNode prevLe prevTerm mismatch
    have retryEq : retry before.log w request
        = findHighestPossibleMatch before.log response.lastLogIndex response.term := by
      rw [responseEq]
      rfl
    rw [value]
    omega
  · exact absurd (eligible index before began beforeNode) aimed

theorem request_matches {index endIndex threshold : Nat} (le : start <= index)
    {state : NodeState} (found : trace.nodeAt index leader = some state)
    (low : state.sentIndex peer < threshold) (high : threshold <= endIndex)
    (bound : endIndex <= state.log.length)
    : Traffic.Matches (.replication term threshold)
        (.appendEntriesRequest (makeAppendEntriesRequest state peer endIndex)) := by
  show term <= _ /\ _ < threshold /\ threshold <= _ + _
  simp only [makeAppendEntriesRequest, messageEntries_length bound, stable.current le found]
  omega

/-- A primary request sent above the retry floor is rejected beyond the agreement
or acknowledged exactly at it. Both outcomes record the actual emitted packet. -/
theorem answer (regime : Regime stable peer log agreed origin)
    (eligible
      : forall index state,
          origin <= index
          -> trace.nodeAt index leader = some state
          -> peer ∈ eligiblePeers state leader)
    {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) {packet : Packet}
    (event : step.action = .deliver packet) {sent : Nat}
    (sentAt : trace.SentAt sent packet) (sentLate : origin <= sent)
    (sentBefore : sent < index) (source : packet.envelope.source = leader)
    (target : packet.envelope.target = peer) {request : AppendEntriesRequest}
    (payload : packet.envelope.payload = .appendEntriesRequest request)
    {before primary : NodeState} (found : trace.nodeAt sent leader = some before)
    (leaderFound : nodeState (proto step.before) leader = some primary)
    (floor : agreed <= before.sentIndex peer)
    : request.term = term
      /\ request.prevLogIndex = before.sentIndex peer
      /\ request.prevLogIndex + request.entries.length <= before.log.length
      /\ ((agreed < request.prevLogIndex
            /\ exists w,
                w.currentTerm = term
                /\ w.log = log
                /\ request.prevLogIndex <= primary.log.length
                /\ request.prevLogTerm = termAt primary.log request.prevLogIndex
                /\ Not
                    (termAt log request.prevLogIndex
                      = termAt primary.log request.prevLogIndex)
                /\ exists reply,
                    trace.SentAt index reply
                    /\ reply.envelope
                        = {
                          source := peer
                          target := leader
                          payload := .appendEntriesResponse (nackResponse w request)
                        })
          \/ (request.prevLogIndex + request.entries.length = agreed
              /\ exists reply,
                  trace.SentAt index reply
                  /\ reply.envelope
                      = {
                        source := peer
                        target := leader
                        payload :=
                          .appendEntriesResponse
                            { term, success := true, lastLogIndex := agreed }
                      })) := by
  obtain ⟨sending, _, _, sendStepped, -⟩ := admissible.sentAt_emitted sentAt
  obtain ⟨_, after, afterFound, _⟩ :=
    stable.leads (Nat.le_succ_of_le (regime.afterStart.trans sentLate))
      (Trace.stateAt_succ_of_stepAt sendStepped)
  have foundBefore : nodeState (proto sending.before) leader = some before := by
    rwa [admissible.nodeAt_before sendStepped] at found
  obtain ⟨rTerm, prevEq, _, endLe⟩ :=
    leader_request_shape admissible stable (regime.afterStart.trans sentLate) sendStepped
      foundBefore afterFound (by rw [target]; exact eligible sent before sentLate found)
      sentAt source payload
  rw [target] at prevEq
  obtain ⟨w, sends, wTerm, wLog, out, _, detail⟩ :=
    request_outcome admissible stable different regime stepped event (by omega) target payload leaderFound
  obtain ⟨_, prevLe, prevTerm, outcome⟩ := detail source
  have selected : step.action.action = some (.deliver packet.envelope) := by rw [event]; rfl
  refine ⟨rTerm, prevEq, endLe, ?_⟩
  rcases outcome with ⟨above, mismatch, sendsEq⟩ | ⟨_, _⟩ | ⟨_, sendsEq⟩
  · rw [sendsEq] at out
    obtain ⟨reply, replySent, replyEnvelope, -⟩ :=
      admissible.sentAt_of_emitted stepped selected out (List.mem_singleton_self _)
    exact Or.inl ⟨above, w, wTerm, wLog, prevLe, prevTerm, mismatch, reply, replySent, replyEnvelope⟩
  · omega
  · have reached : request.prevLogIndex + request.entries.length = agreed := by omega
    rw [sendsEq, reached] at out
    obtain ⟨reply, replySent, replyEnvelope, -⟩ :=
      admissible.sentAt_of_emitted stepped selected out (List.mem_singleton_self _)
    exact Or.inr ⟨reached, reply, replySent, replyEnvelope⟩

/-- Productive heartbeats eventually raise the retry frontier to the agreement,
after all subsequently delivered rejections were sent in the regime. -/
theorem floor_reached (regime : Regime stable peer log agreed origin)
    {heartbeatBound : Option Real} (heartbeats : trace.HeartbeatScheduling heartbeatBound)
    (live
      : forall index point,
          start <= index -> trace.stateAt index = some point -> peer ∈ HasLive.live point)
    (eligible
      : forall index state,
          start <= index
          -> trace.nodeAt index leader = some state
          -> peer ∈ eligiblePeers state leader)
    {stop : Nat} (began : origin <= stop) {first : W}
    (stopFound : trace.stateAt stop = some first)
    (late
      : forall index step packet,
          stop <= index
          -> trace.stepAt index = some step
          -> step.action = .deliver packet
          -> exists sent, origin <= sent /\ sent < index /\ trace.SentAt sent packet)
    : exists reached point,
        stop <= reached
        /\ trace.stateAt reached = some point
        /\ forall index state,
            reached <= index
            -> trace.nodeAt index leader = some state
            -> agreed <= state.sentIndex peer := by
  have stepLe
      : forall index step, stop <= index -> trace.stepAt index = some step
        -> min (sentFrontier step.before leader peer) agreed
          <= min (sentFrontier step.after leader peer) agreed := by
    intro index step le stepped
    obtain ⟨_, before, beforeFound, _⟩ :=
      stable.leads (by have := regime.afterStart; omega) (admissible.before stepped)
    obtain ⟨_, after, afterFound, _⟩ :=
      stable.leads (by have := regime.afterStart; omega) (Trace.stateAt_succ_of_stepAt stepped)
    rw [sentFrontier_eq peer beforeFound, sentFrontier_eq peer afterFound]
    exact floor_step admissible stable different regime
      (fun i s after found => eligible i s (regime.afterStart.trans after) found)
      stepped (began.trans le) (fun packet event => late index step packet le stepped event)
      beforeFound afterFound
  obtain ⟨reached, point, le, reachedFound, constant⟩ :=
    Trace.settles_of_monotone stopFound
      (measure := fun _ point => min (sentFrontier point leader peer) agreed)
      (fun _ _ _ _ le after found found' =>
        admissible.coherent.measure_mono
          (measure := fun _ point => min (sentFrontier point leader peer) agreed)
          stepLe le after found found')
      (fun _ _ _ _ => Nat.min_le_right _ _)
  refine ⟨reached, point, le, reachedFound, fun index state after found => ?_⟩
  by_contra low
  obtain ⟨last, lastFound, nodeFound⟩ := Trace.nodeAt_eq_some.mp found
  obtain ⟨d, afterD, step, stepped, before, endIndex, beforeFound, event, grows⟩ :=
    sends_often admissible stable heartbeats live eligible reached
  obtain ⟨_, next, nextFound, _⟩ :=
    stable.leads (by have := regime.afterStart; omega) (Trace.stateAt_succ_of_stepAt stepped)
  obtain ⟨_, _, frontier, _⟩ := send_step admissible stepped event beforeFound nextFound
  have atIndex := constant index last after lastFound
  have atD := constant d step.before afterD (admissible.before stepped)
  have atNext := constant (d + 1) step.after (Nat.le_succ_of_le afterD)
    (Trace.stateAt_succ_of_stepAt stepped)
  rw [sentFrontier_eq peer nodeFound] at atIndex
  rw [sentFrontier_eq peer beforeFound] at atD
  rw [sentFrontier_eq peer nextFound] at atNext
  have agreement := regime.agreement d before (by omega)
    (by rw [admissible.nodeAt_before stepped, beforeFound])
  have := agree_le_right log before.log
  have grown := grows (by omega)
  omega

/-- The primary cannot keep sending batches across a fixed agreement. -/
theorem extend_absurd (regime : Regime stable peer log agreed origin)
    (eligible
      : forall index state,
          origin <= index
          -> trace.nodeAt index leader = some state
          -> peer ∈ eligiblePeers state leader)
    {participants : Finset NodeID} (fair : FairLoss trace participants)
    (leaderIn : leader ∈ participants) (peerIn : peer ∈ participants) {floorStart : Nat}
    (originLe : origin <= floorStart)
    (floor
      : forall index state,
          floorStart <= index
          -> trace.nodeAt index leader = some state
          -> agreed <= state.sentIndex peer)
    (sends : InfinitelySent trace leader peer (.replication term (agreed + 1)))
    : False := by
  obtain ⟨stop, _, late⟩ := admissible.horizon floorStart
  obtain ⟨index, step, packet, le, stepped, event, source, target, matched⟩ :=
    fair leader peer _ leaderIn peerIn sends stop
  cases payload : packet.envelope.payload with
  | appendEntriesRequest request =>
      rw [payload] at matched
      obtain ⟨sent, sentLate, sentBefore, sentAt⟩ :=
        late index step packet le stepped (by rw [event]; rfl)
      obtain ⟨point, pointFound⟩ := Trace.stateAt_of_le sentBefore.le (admissible.before stepped)
      obtain ⟨before, beforeFound⟩ :=
        stable.found (by have := regime.afterStart; omega) pointFound
      obtain ⟨_, primary, leaderFound, _⟩ :=
        stable.leads (by have := regime.afterStart; omega) (admissible.before stepped)
      obtain ⟨_, _, _, outcome⟩ :=
        answer admissible stable different regime eligible stepped event sentAt (by omega)
          sentBefore source target payload beforeFound leaderFound (floor sent before sentLate beforeFound)
      obtain ⟨_, lt, reach⟩ := matched
      rcases outcome with ⟨above, _⟩ | ⟨reached, _⟩ <;> omega
  | _ =>
      rw [payload] at matched
      exact matched.elim

/-- Without recurrent batches across the agreement, a longer primary log forces
the retry frontier to stay strictly above the agreement. -/
theorem floor_strict (regime : Regime stable peer log agreed origin)
    {heartbeatBound : Option Real} (heartbeats : trace.HeartbeatScheduling heartbeatBound)
    (live
      : forall index point,
          start <= index -> trace.stateAt index = some point -> peer ∈ HasLive.live point)
    (eligible
      : forall index state,
          start <= index
          -> trace.nodeAt index leader = some state
          -> peer ∈ eligiblePeers state leader)
    {floorStart : Nat} (originLe : origin <= floorStart)
    (floor
      : forall index state,
          floorStart <= index
          -> trace.nodeAt index leader = some state
          -> agreed <= state.sentIndex peer)
    {grown : Nat}
    (long
      : forall index state,
          grown <= index
          -> trace.nodeAt index leader = some state
          -> agreed < state.log.length)
    (rare : Not (InfinitelySent trace leader peer (.replication term (agreed + 1))))
    : exists strict point,
        floorStart <= strict
        /\ trace.stateAt strict = some point
        /\ forall index state,
            strict <= index
            -> trace.nodeAt index leader = some state
            -> agreed < state.sentIndex peer := by
  simp only [InfinitelySent, not_forall, not_exists, not_and] at rare
  obtain ⟨cutoff, rare⟩ := rare
  obtain ⟨point, pointFound⟩ :=
    peer_recorded admissible stable heartbeats live eligible (max cutoff (max grown floorStart))
  refine ⟨
    max cutoff (max grown floorStart),
    point,
    by omega,
    pointFound,
    fun index state le found => ?_
  ⟩
  by_contra low
  obtain ⟨first, firstFound, firstNode⟩ := Trace.nodeAt_eq_some.mp found
  have stays : forall d point, index <= d -> trace.stateAt d = some point
      -> forall state, nodeState (proto point) leader = some state -> state.sentIndex peer = agreed :=
    admissible.coherent.induction (start := index)
      (motive := fun _ point => forall state, nodeState (proto point) leader = some state
        -> state.sentIndex peer = agreed)
      (fun point pointFound current currentFound => by
        rw [firstFound, Option.some.injEq] at pointFound
        subst pointFound
        rw [firstNode, Option.some.injEq] at currentFound
        subst current
        have := floor index state (by omega) found
        omega)
      (fun d step after stepped ih next nextFound => by
        obtain ⟨_, before, beforeFound, _⟩ :=
          stable.leads (by have := regime.afterStart; omega) (admissible.before stepped)
        have beforeNode : trace.nodeAt d leader = some before := by
          rw [admissible.nodeAt_before stepped, beforeFound]
        have atD := ih before beforeFound
        have atNext := floor (d + 1) next (by omega) (by rw [Trace.nodeAt_succ stepped, nextFound])
        rcases (leader_move admissible stable peer (by have := regime.afterStart; omega)
            stepped beforeFound nextFound).2 with same | ⟨endIndex, _, _, bound, value,
            packet, sent, envelope⟩ | ⟨_, _, _, _, _, _, _, value⟩ | ⟨_, _, _, _, _, aimed⟩
        · rw [same, atD]
        · by_contra moved
          apply rare d packet sent (by omega)
          · rw [envelope]
          · rw [envelope]
          · rw [envelope]
            exact request_matches admissible stable different (by have := regime.afterStart; omega)
              beforeNode (by omega) (by omega) bound
        · have := match_le_agreed admissible stable different regime (by omega) beforeNode
          rw [value]
          omega
        · exact absurd (eligible d before (by have := regime.afterStart; omega) beforeNode) aimed)
  obtain ⟨d, after, step, stepped, before, endIndex, beforeFound, event, grows⟩ :=
    sends_often admissible stable heartbeats live eligible index
  obtain ⟨_, next, nextFound, _⟩ :=
    stable.leads (by have := regime.afterStart; omega) (Trace.stateAt_succ_of_stepAt stepped)
  obtain ⟨_, bound, frontier, packet, sent, envelope⟩ :=
    send_step admissible stepped event beforeFound nextFound
  have atD := stays d step.before after (admissible.before stepped) before beforeFound
  have atNext := stays (d + 1) step.after (by omega) (Trace.stateAt_succ_of_stepAt stepped) next nextFound
  have beforeNode : trace.nodeAt d leader = some before := by
    rw [admissible.nodeAt_before stepped, beforeFound]
  have := long d before (by omega) beforeNode
  have grown' := grows (by omega)
  apply rare d packet sent (by omega)
  · rw [envelope]
  · rw [envelope]
  · rw [envelope]
    exact request_matches admissible stable different (by have := regime.afterStart; omega)
      beforeNode (by omega) (by omega) bound

/-- Above the agreement every request is rejected.
The least recurrent rejected position produces one recurrent rejection, which
forces recurrent batches across that position and hence a smaller recurrent position. -/
theorem bucket_absurd (regime : Regime stable peer log agreed origin)
    {heartbeatBound : Option Real} (heartbeats : trace.HeartbeatScheduling heartbeatBound)
    (live
      : forall index point,
          start <= index -> trace.stateAt index = some point -> peer ∈ HasLive.live point)
    (eligible
      : forall index state,
          start <= index
          -> trace.nodeAt index leader = some state
          -> peer ∈ eligiblePeers state leader)
    {participants : Finset NodeID} (fair : FairLoss trace participants)
    (leaderIn : leader ∈ participants) (peerIn : peer ∈ participants)
    {strict : Nat} (originLe : origin <= strict)
    (above
      : forall index state,
          strict <= index
          -> trace.nodeAt index leader = some state
          -> agreed < state.sentIndex peer)
    : False := by
  obtain ⟨stop, stopLe, late⟩ := admissible.horizon strict
  have rejected
      : forall index step packet request primary,
          stop <= index -> trace.stepAt index = some step -> step.action = .deliver packet
          -> packet.envelope.source = leader -> packet.envelope.target = peer
          -> packet.envelope.payload = .appendEntriesRequest request
          -> nodeState (proto step.before) leader = some primary
          -> request.term = term /\ agreed < request.prevLogIndex
            /\ exists w,
                w.currentTerm = term /\ w.log = log
                /\ request.prevLogIndex <= primary.log.length
                /\ request.prevLogTerm = termAt primary.log request.prevLogIndex
                /\ Not (termAt log request.prevLogIndex = termAt primary.log request.prevLogIndex)
                /\ exists reply, trace.SentAt index reply
                    /\ reply.envelope = {
                      source := peer
                      target := leader
                      payload := .appendEntriesResponse (nackResponse w request)
                    } := by
    intro index step packet request primary le stepped event source target payload leaderFound
    obtain ⟨sent, sentLate, sentBefore, sentAt⟩ :=
      late index step packet le stepped (by rw [event]; rfl)
    obtain ⟨point, pointFound⟩ := Trace.stateAt_of_le sentBefore.le (admissible.before stepped)
    obtain ⟨before, beforeFound⟩ :=
      stable.found (by have := regime.afterStart; omega) pointFound
    have gt := above sent before sentLate beforeFound
    obtain ⟨rTerm, prevEq, _, outcome⟩ :=
      answer admissible stable different regime
        (fun i s after found => eligible i s (regime.afterStart.trans after) found)
        stepped event sentAt (by omega) sentBefore source target payload beforeFound leaderFound gt.le
    rcases outcome with ⟨gt, rest⟩ | ⟨reached, _⟩
    · exact ⟨rTerm, gt, rest⟩
    · omega
  let P : Nat -> Prop := fun index =>
    stop <= index /\ exists step packet request,
      trace.stepAt index = some step /\ step.action = .deliver packet
      /\ packet.envelope.source = leader /\ packet.envelope.target = peer
      /\ packet.envelope.payload = .appendEntriesRequest request
  -- Only recorded deliveries satisfying P use this label; its fallback is irrelevant.
  let label : Nat -> Nat := fun index =>
    min (((trace.actionAt index).map prevOf).getD 0) (log.length + 1)
  have labelEq : forall {index step packet request},
      trace.stepAt index = some step -> step.action = .deliver packet
      -> packet.envelope.payload = .appendEntriesRequest request
      -> label index = min request.prevLogIndex (log.length + 1) := by
    intro index step packet request stepped event payload
    simp only [label, Trace.actionAt, stepped, Option.map_some, Option.getD_some,
      prevOf_eq event payload]
  have often : Often P := by
    intro cutoff
    obtain ⟨index, step, packet, le, stepped, event, source, target, matched⟩ :=
      fair leader peer _ leaderIn peerIn
        (heartbeats_sent admissible heartbeats stable live eligible) (max cutoff stop)
    cases payload : packet.envelope.payload with
    | appendEntriesRequest request =>
        exact ⟨
          index,
          by omega,
          by omega,
          step,
          packet,
          request,
          stepped,
          event,
          source,
          target,
          payload
        ⟩
    | _ =>
        rw [payload] at matched
        exact matched.elim
  obtain ⟨least, repeats, minimal⟩ :=
    often.least_bucket (label := label) (bound := log.length + 1)
      (fun _ _ => Nat.min_le_right _ _)
  obtain ⟨first, _, ⟨firstLe, step0, packet0, request0, stepped0, event0, source0, target0, payload0⟩,
      label0⟩ := repeats 0
  obtain ⟨_, primary0, leaderFound0, _⟩ :=
    stable.leads (by have := regime.afterStart; omega) (admissible.before stepped0)
  have leaderNode0 : trace.nodeAt first leader = some primary0 := by
    rw [admissible.nodeAt_before stepped0, leaderFound0]
  obtain ⟨rTerm0, gt0, w0, wTerm0, wLog0, prevLe0, prevTerm0, mismatch0, _⟩ :=
    rejected first step0 packet0 request0 primary0 firstLe stepped0 event0 source0 target0 payload0
      leaderFound0
  have leastEq : least = min request0.prevLogIndex (log.length + 1) := by
    rw [← label0, labelEq stepped0 event0 payload0]
  have agreedLe : agreed <= log.length := by
    rw [← regime.agreement first primary0 (by omega) leaderNode0]
    exact agree_le_left _ _
  have agreedLt : agreed < least := by omega
  let nack := nackResponse w0 request0
  have sameNack : forall {index step packet request w primary},
      first <= index -> trace.stepAt index = some step -> step.action = .deliver packet
      -> packet.envelope.payload = .appendEntriesRequest request -> label index = least
      -> w.currentTerm = term -> w.log = log -> request.term = term
      -> request.prevLogIndex <= primary.log.length
      -> request.prevLogTerm = termAt primary.log request.prevLogIndex
      -> nodeState (proto step.before) leader = some primary
      -> nackResponse w request = nack := by
    intro index step packet request w primary le stepped event payload labelIs wTerm wLog rTerm
      prevLe prevTerm leaderFound
    rw [labelEq stepped event payload] at labelIs
    dsimp only [nack]
    by_cases short : request0.prevLogIndex <= log.length
    · have prevEq : request.prevLogIndex = request0.prevLogIndex := by omega
      have transfer : termAt primary.log request0.prevLogIndex
          = termAt primary0.log request0.prevLogIndex :=
        termAt_of_prefix
          (stable_log_prefix admissible stable (by have := regime.afterStart; omega) le leaderNode0
            (by rw [admissible.nodeAt_before stepped, leaderFound])) prevLe0
      refine nackResponse_congr (wTerm.trans wTerm0.symm) (wLog.trans wLog0.symm)
        (rTerm.trans rTerm0.symm) prevEq ?_
      rw [prevTerm, prevTerm0, prevEq, transfer]
    · rw [nackResponse_short (by rw [wLog]; omega), nackResponse_short (by rw [wLog0]; omega),
        wTerm, wTerm0, wLog, wLog0]
  have nacksSent : InfinitelySent trace peer leader (.exact (.appendEntriesResponse nack)) := by
    intro cutoff
    obtain ⟨index, le, ⟨afterStop, step, packet, request, stepped, event, source, target, payload⟩,
        labelIs⟩ := repeats (max cutoff first)
    obtain ⟨_, primary, leaderFound, _⟩ :=
      stable.leads (by have := regime.afterStart; omega) (admissible.before stepped)
    obtain ⟨rTerm, _, w, wTerm, wLog, prevLe, prevTerm, _, reply, sent, envelope⟩ :=
      rejected index step packet request primary afterStop stepped event source target payload leaderFound
    refine ⟨index, reply, sent, by omega, ?_, ?_, ?_⟩ <;> rw [envelope]
    show Message.appendEntriesResponse (nackResponse w request) = .appendEntriesResponse nack
    rw [sameNack (by omega) stepped event payload labelIs wTerm wLog rTerm prevLe prevTerm leaderFound]
  have low : Often fun index =>
      exists point, trace.stateAt index = some point /\ sentFrontier point leader peer < least := by
    intro cutoff
    obtain ⟨index, step, packet, le, stepped, event, source, target, matched⟩ :=
      fair peer leader _ peerIn leaderIn nacksSent (max cutoff first)
    have matched : packet.envelope.payload = .appendEntriesResponse nack := matched
    obtain ⟨_, before, beforeFound, _⟩ :=
      stable.leads (by have := regime.afterStart; omega) (admissible.before stepped)
    obtain ⟨_, after, afterFound, _⟩ :=
      stable.leads (by have := regime.afterStart; omega) (Trace.stateAt_succ_of_stepAt stepped)
    have beforeNode : trace.nodeAt index leader = some before := by
      rw [admissible.nodeAt_before stepped, beforeFound]
    have value := nack_exact admissible stable (by have := regime.afterStart; omega) stepped
      (show step.action.delivered = some packet.envelope by rw [event]; rfl) target matched
      (nackResponse_failure w0 request0) beforeFound afterFound
      (by rw [source]; exact eligible index before (by have := regime.afterStart; omega) beforeNode)
    rw [source] at value
    obtain ⟨_, retryLt⟩ :=
      retry_bounds admissible stable different regime wTerm0 wLog0 rTerm0 (by omega) (by omega)
        leaderNode0 beforeNode prevLe0 prevTerm0 mismatch0
    have retryEq : retry before.log w0 request0
        = findHighestPossibleMatch before.log nack.lastLogIndex nack.term := rfl
    have := match_le_agreed admissible stable different regime (by omega) beforeNode
    refine ⟨index + 1, by omega, step.after, Trace.stateAt_succ_of_stepAt stepped, ?_⟩
    rw [sentFrontier_eq peer afterFound, value]
    omega
  have high : Often fun index =>
      exists point, trace.stateAt index = some point /\ least <= sentFrontier point leader peer := by
    intro cutoff
    obtain ⟨stop', _, late'⟩ := admissible.horizon (max cutoff strict)
    obtain ⟨index, le, ⟨_, step, packet, request, stepped, event, source, target, payload⟩,
        labelIs⟩ := repeats stop'
    obtain ⟨sent, sentLate, _, sentAt⟩ :=
      late' index step packet le stepped (by rw [event]; rfl)
    obtain ⟨sending, _, _, sendStepped, -⟩ := admissible.sentAt_emitted sentAt
    obtain ⟨_, before, beforeFound, _⟩ :=
      stable.leads (by have := regime.afterStart; omega) (admissible.before sendStepped)
    have beforeNode : trace.nodeAt sent leader = some before := by
      rw [admissible.nodeAt_before sendStepped, beforeFound]
    obtain ⟨endIndex, _, requestEq⟩ :=
      leader_request admissible stable (by have := regime.afterStart; omega) sendStepped beforeFound
        (by rw [target]; exact eligible sent before (by have := regime.afterStart; omega) beforeNode)
        sentAt source payload
    have prevEq : request.prevLogIndex = before.sentIndex peer := by
      rw [requestEq, target]
      rfl
    rw [labelEq stepped event payload] at labelIs
    refine ⟨sent, by omega, sending.before, admissible.before sendStepped, ?_⟩
    rw [sentFrontier_eq peer beforeFound]
    omega
  have batches : InfinitelySent trace leader peer (.replication term least) := by
    intro cutoff
    obtain ⟨d, le, step, stepped, below, reach⟩ :=
      recorded_crossing admissible.coherent low high (max cutoff strict)
    obtain ⟨_, before, beforeFound, _⟩ :=
      stable.leads (by have := regime.afterStart; omega) (admissible.before stepped)
    obtain ⟨_, after, afterFound, _⟩ :=
      stable.leads (by have := regime.afterStart; omega) (Trace.stateAt_succ_of_stepAt stepped)
    have beforeNode : trace.nodeAt d leader = some before := by
      rw [admissible.nodeAt_before stepped, beforeFound]
    rw [sentFrontier_eq peer beforeFound] at below
    rw [sentFrontier_eq peer afterFound] at reach
    rcases (leader_move admissible stable peer (by have := regime.afterStart; omega)
        stepped beforeFound afterFound).2 with same | ⟨endIndex, _, _, bound, value, packet, sent,
        envelope⟩ | ⟨_, _, _, _, _, _, _, value⟩ | ⟨_, _, _, _, _, aimed⟩
    · omega
    · refine ⟨d, packet, sent, by omega, ?_, ?_, ?_⟩ <;> rw [envelope]
      exact request_matches admissible stable different (by have := regime.afterStart; omega)
        beforeNode below (by omega) bound
    · have := match_le_agreed admissible stable different regime (by omega) beforeNode
      omega
    · exact absurd (eligible d before (by have := regime.afterStart; omega) beforeNode) aimed
  have smaller : Often fun index => P index /\ label index < least := by
    intro cutoff
    obtain ⟨index, step, packet, le, stepped, event, source, target, matched⟩ :=
      fair leader peer _ leaderIn peerIn batches (max cutoff stop)
    cases payload : packet.envelope.payload with
    | appendEntriesRequest request =>
        rw [payload] at matched
        obtain ⟨_, lt, _⟩ := matched
        have := labelEq stepped event payload
        exact ⟨
          index,
          by omega,
          ⟨by omega, step, packet, request, stepped, event, source, target, payload⟩,
          by omega
        ⟩
    | _ =>
        rw [payload] at matched
        exact matched.elim
  obtain ⟨k, _, repeatsK⟩ :=
    smaller.bucket (label := label) (bound := least - 1) (fun _ holds => by omega)
  exact minimal k (by omega) (repeatsK.mono fun _ ⟨⟨holds, _⟩, eq⟩ => ⟨holds, eq⟩)

end Regime

section Quiet

variable {bound quietFrom : Nat}
  (quiet
    : forall index packet,
        trace.SentAt index packet
        -> quietFrom <= index
        -> packet.envelope.source = peer
        -> packet.envelope.target = leader
        -> Not (Traffic.Matches (.response term true bound) packet.envelope.payload))

include quiet

/-- Every log change of a current-term quiet peer strictly increases its bounded
point-valued potential; unchanged logs cannot decrease it. -/
theorem potential_step {index : Nat} (afterStart : start <= index)
    (began : quietFrom <= index) {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) {before after : NodeState}
    (found : nodeState (proto step.before) peer = some before)
    (found' : nodeState (proto step.after) peer = some after)
    (beforeTerm : before.currentTerm = term) (afterTerm : after.currentTerm = term)
    : (after.log = before.log
        -> potential step.before leader peer bound
            <= potential step.after leader peer bound)
      /\ (Not (after.log = before.log)
          -> potential step.before leader peer bound
              < potential step.after leader peer bound) := by
  obtain ⟨_, primary, primaryFound, _⟩ := stable.leads afterStart (admissible.before stepped)
  obtain ⟨_, next, nextFound, _⟩ :=
    stable.leads (Nat.le_succ_of_le afterStart) (Trace.stateAt_succ_of_stepAt stepped)
  have grows := stable_log_prefix admissible stable afterStart (Nat.le_succ index)
    (by rw [admissible.nodeAt_before stepped, primaryFound])
    (by rw [Trace.nodeAt_succ stepped, nextFound])
  unfold potential
  rw [nodeLog_eq found, nodeLog_eq found', nodeLog_eq primaryFound, nodeLog_eq nextFound]
  refine ⟨fun same => ?_, fun changed => ?_⟩
  · rw [same]
    split
    · rename_i holds
      have holds' : before.log <+: next.log /\ before.log.length < bound :=
        ⟨holds.1.trans grows, holds.2⟩
      rw [ite_eq_left_of_eq_true _ _ (eq_true holds')]
    · exact Nat.zero_le _
  obtain ⟨envelope, request, leaderState, _, _, _, _, _, leaderFound, within, postLog, differ,
      packet, sent, packetEnvelope⟩ :=
    follower_step admissible stable afterStart stepped different found found' beforeTerm afterTerm changed
  rw [primaryFound, Option.some.injEq] at leaderFound
  subst leaderState
  have short : request.prevLogIndex + request.entries.length < bound := by
    have noAck := quiet index packet sent began (by rw [packetEnvelope]) (by rw [packetEnvelope])
    rw [packetEnvelope] at noAck
    simp only [Traffic.Matches, le_refl, true_and] at noAck
    omega
  have length : after.log.length = request.prevLogIndex + request.entries.length := by
    rw [postLog, List.length_take]
    omega
  have prefix_ : after.log <+: next.log := by
    rw [postLog]
    exact (List.take_prefix _ _).trans grows
  have holds' : after.log <+: next.log /\ after.log.length < bound := ⟨prefix_, by omega⟩
  rw [ite_eq_left_of_eq_true _ _ (eq_true holds'), length]
  split
  · rename_i holds
    have : before.log.length < request.prevLogIndex + request.entries.length := by
      by_contra long
      exact differ (take_eq_of_prefix holds.1 (Nat.le_of_not_lt long)).symm
    omega
  · omega

/-- A quiet current-term peer's log becomes constant at a recorded state. -/
theorem log_settles (afterStart : start <= quietFrom) {first : W}
    (firstFound : trace.stateAt quietFrom = some first)
    (current
      : forall index point,
          quietFrom <= index
          -> trace.stateAt index = some point
          -> exists state,
              nodeState (proto point) peer = some state /\ state.currentTerm = term)
    : exists settled point,
        quietFrom <= settled
        /\ trace.stateAt settled = some point
        /\ forall index later,
            settled <= index
            -> trace.stateAt index = some later
            -> nodeLog later peer = nodeLog point peer := by
  have stepFacts : forall index step, quietFrom <= index -> trace.stepAt index = some step
      -> (nodeLog step.after peer = nodeLog step.before peer
          \/ potential step.before leader peer bound < potential step.after leader peer bound)
        /\ potential step.before leader peer bound <= potential step.after leader peer bound := by
    intro index step began stepped
    obtain ⟨before, found, beforeTerm⟩ := current index step.before began (admissible.before stepped)
    obtain ⟨after, found', afterTerm⟩ :=
      current (index + 1) step.after (Nat.le_succ_of_le began) (Trace.stateAt_succ_of_stepAt stepped)
    have facts := potential_step admissible stable different quiet (afterStart.trans began) began
      stepped found found' beforeTerm afterTerm
    rw [nodeLog_eq found, nodeLog_eq found']
    by_cases same : after.log = before.log
    · exact ⟨Or.inl same, facts.1 same⟩
    · exact ⟨Or.inr (facts.2 same), (facts.2 same).le⟩
  obtain ⟨stop, point, began, stopFound, constant⟩ :=
    Trace.settles_of_monotone firstFound
      (measure := fun _ point => potential point leader peer bound)
      (fun _ _ _ _ le after found found' =>
        admissible.coherent.measure_mono
          (measure := fun _ point => potential point leader peer bound)
          (fun index step le stepped => (stepFacts index step le stepped).2) le after found found')
      (fun _ point _ _ => potential_le point leader peer bound)
  refine ⟨stop, point, began, stopFound, ?_⟩
  exact admissible.coherent.induction (start := stop)
    (motive := fun _ later => nodeLog later peer = nodeLog point peer)
    (fun later found => by rw [stopFound, Option.some.injEq] at found; rw [← found])
    (fun index step le stepped ih => by
      rcases (stepFacts index step (began.trans le) stepped).1 with same | lt
      · exact same.trans ih
      · have := constant index step.before le (admissible.before stepped)
        have := constant (index + 1) step.after (Nat.le_succ_of_le le)
          (Trace.stateAt_succ_of_stepAt stepped)
        omega)

/-- A quiet live, eligible peer settles into a regime after old deliveries have drained. -/
theorem settles {heartbeatBound : Option Real}
    (heartbeats : trace.HeartbeatScheduling heartbeatBound)
    (live
      : forall index point,
          start <= index -> trace.stateAt index = some point -> peer ∈ HasLive.live point)
    (eligible
      : forall index state,
          start <= index
          -> trace.nodeAt index leader = some state
          -> peer ∈ eligiblePeers state leader)
    {participants : Finset NodeID} (fair : FairLoss trace participants)
    (leaderIn : leader ∈ participants) (peerIn : peer ∈ participants)
    : exists log agreed origin,
        quietFrom <= origin /\ Regime stable peer log agreed origin := by
  obtain ⟨joined, _, joinedLe, _, current⟩ :=
    peer_current admissible stable heartbeats live eligible fair leaderIn peerIn
  obtain ⟨first, firstFound⟩ :=
    peer_recorded admissible stable heartbeats live eligible (max quietFrom joined)
  obtain ⟨settled, settledPoint, settledLe, settledFound, logConst⟩ :=
    log_settles admissible stable different (quietFrom := max quietFrom joined)
      (fun index packet sent le => quiet index packet sent (by omega))
      (by omega) firstFound (fun index point le found => current index point (by omega) found)
  obtain ⟨stop, primary, stopLe, stopFound, agreeConst⟩ :=
    agree_settles admissible stable (nodeLog settledPoint peer) (by omega) settledFound
  obtain ⟨fresh, _, freshHolds⟩ := admissible.horizon start
  obtain ⟨point, pointFound⟩ := peer_recorded admissible stable heartbeats live eligible (max stop fresh)
  refine ⟨
    nodeLog settledPoint peer,
    agree (nodeLog settledPoint peer) primary.log,
    max stop fresh,
    by omega,
    ⟨by omega, ⟨point, pointFound⟩, ?_, ?_, ?_⟩
  ⟩
  · intro index point le found
    obtain ⟨z, zFound, zTerm⟩ := current index point (by omega) found
    refine ⟨z, zFound, zTerm, ?_⟩
    rw [← nodeLog_eq zFound]
    exact logConst index point (by omega) found
  · intro index state le found
    exact agreeConst index state (by omega) found
  · intro index step packet le stepped event
    exact freshHolds index step packet (by omega) stepped (by rw [event]; rfl)

/-- A primary log that never extends past the agreement gets that agreement
acknowledged, contradicting quietness once it covers the requested bound. -/
theorem flat_absurd {log : List Entry} {agreed origin : Nat}
    (regime : Regime stable peer log agreed origin) (began : quietFrom <= origin)
    {heartbeatBound : Option Real} (heartbeats : trace.HeartbeatScheduling heartbeatBound)
    (live
      : forall index point,
          start <= index -> trace.stateAt index = some point -> peer ∈ HasLive.live point)
    (eligible
      : forall index state,
          start <= index
          -> trace.nodeAt index leader = some state
          -> peer ∈ eligiblePeers state leader)
    {participants : Finset NodeID} (fair : FairLoss trace participants)
    (leaderIn : leader ∈ participants) (peerIn : peer ∈ participants) {floorStart : Nat}
    (originLe : origin <= floorStart)
    (floor
      : forall index state,
          floorStart <= index
          -> trace.nodeAt index leader = some state
          -> agreed <= state.sentIndex peer)
    {reach : Nat} (reachLe : start <= reach) {state : NodeState}
    (reachFound : trace.nodeAt reach leader = some state)
    (reachBound : bound <= state.log.length)
    (flat
      : forall index state,
          floorStart <= index
          -> trace.nodeAt index leader = some state
          -> state.log.length <= agreed)
    : False := by
  obtain ⟨stop, _, late⟩ := admissible.horizon floorStart
  obtain ⟨index, step, packet, le, stepped, event, source, target, matched⟩ :=
    fair leader peer _ leaderIn peerIn
      (heartbeats_sent admissible heartbeats stable live eligible) (max stop reach)
  cases payload : packet.envelope.payload with
  | appendEntriesRequest request =>
      obtain ⟨sent, sentLate, sentBefore, sentAt⟩ :=
        late index step packet (by omega) stepped (by rw [event]; rfl)
      obtain ⟨point, pointFound⟩ := Trace.stateAt_of_le sentBefore.le (admissible.before stepped)
      obtain ⟨before, beforeFound⟩ :=
        stable.found (by have := regime.afterStart; omega) pointFound
      obtain ⟨_, primary, leaderFound, _⟩ :=
        stable.leads (by have := regime.afterStart; omega) (admissible.before stepped)
      have leaderNode : trace.nodeAt index leader = some primary := by
        rw [admissible.nodeAt_before stepped, leaderFound]
      obtain ⟨_, _, endLe, outcome⟩ :=
        answer admissible stable different regime
          (fun i s after found => eligible i s (regime.afterStart.trans after) found)
          stepped event sentAt (by omega) sentBefore source target payload beforeFound leaderFound
          (floor sent before sentLate beforeFound)
      have := flat sent before sentLate beforeFound
      rcases outcome with ⟨above, _⟩ | ⟨_, reply, replySent, replyEnvelope⟩
      · omega
      · have grows := (stable_log_prefix admissible stable reachLe (by omega) reachFound leaderNode).length_le
        have := flat index primary (by omega) leaderNode
        apply quiet index reply replySent (by omega)
        · rw [replyEnvelope]
        · rw [replyEnvelope]
        · rw [replyEnvelope]
          exact ⟨le_rfl, rfl, (show bound <= agreed by omega)⟩
  | _ =>
      rw [payload] at matched
      exact matched.elim

end Quiet

/-- A live, eligible peer keeps acknowledging every position of the stable primary's log. -/
theorem acks_sent {heartbeatBound : Option Real}
    (heartbeats : trace.HeartbeatScheduling heartbeatBound)
    (live
      : forall index point,
          start <= index -> trace.stateAt index = some point -> peer ∈ HasLive.live point)
    (eligible
      : forall index state,
          start <= index
          -> trace.nodeAt index leader = some state
          -> peer ∈ eligiblePeers state leader)
    {participants : Finset NodeID} (fair : FairLoss trace participants)
    (leaderIn : leader ∈ participants) (peerIn : peer ∈ participants) {bound reach : Nat}
    (reachLe : start <= reach) {state : NodeState}
    (reachFound : trace.nodeAt reach leader = some state)
    (reachBound : bound <= state.log.length)
    : InfinitelySent trace peer leader (.response term true bound) := by
  intro cutoff
  by_contra none
  simp only [not_exists, not_and] at none
  have quiet : forall index packet,
      trace.SentAt index packet -> max cutoff start <= index
      -> packet.envelope.source = peer -> packet.envelope.target = leader
      -> Not (Traffic.Matches (.response term true bound) packet.envelope.payload) :=
    fun index packet sent le => none index packet sent (by omega)
  obtain ⟨log, agreed, origin, began, regime⟩ :=
    settles admissible stable different quiet heartbeats live eligible fair leaderIn peerIn
  have eligibleRegime : forall index state,
      origin <= index -> trace.nodeAt index leader = some state -> peer ∈ eligiblePeers state leader :=
    fun index state le found => eligible index state (regime.afterStart.trans le) found
  obtain ⟨stop, stopLe, late⟩ := admissible.horizon origin
  obtain ⟨point, pointFound⟩ := peer_recorded admissible stable heartbeats live eligible stop
  obtain ⟨floorStart, _, floorLe, _, floor⟩ :=
    floor_reached admissible stable different regime heartbeats live eligible stopLe pointFound
      (fun index step packet le stepped event => late index step packet le stepped (by rw [event]; rfl))
  by_cases grows : exists grown point, trace.stateAt grown = some point
      /\ forall index state, grown <= index -> trace.nodeAt index leader = some state
        -> agreed < state.log.length
  · obtain ⟨grown, _, _, long⟩ := grows
    by_cases sends : InfinitelySent trace leader peer (.replication term (agreed + 1))
    · exact extend_absurd admissible stable different regime eligibleRegime fair leaderIn peerIn
        (by omega) floor sends
    · obtain ⟨strict, _, strictLe, _, above⟩ :=
        floor_strict admissible stable different regime heartbeats live eligible (by omega) floor long sends
      exact bucket_absurd admissible stable different regime heartbeats live eligible fair leaderIn peerIn
        (by omega) above
  · refine flat_absurd admissible stable different quiet regime began heartbeats live eligible fair
      leaderIn peerIn (by omega) floor reachLe reachFound reachBound fun index state le found => ?_
    by_contra long
    obtain ⟨point, pointFound, _⟩ := Trace.nodeAt_eq_some.mp found
    refine grows ⟨index, point, pointFound, fun later after laterLe afterFound => ?_⟩
    have := (stable_log_prefix admissible stable (by have := regime.afterStart; omega)
      laterLe found afterFound).length_le
    omega

omit different in
/-- The stable primary's match index never drops between recorded states. -/
theorem match_mono {index later : Nat} (afterStart : start <= index) (le : index <= later)
    {before after : NodeState} (found : trace.nodeAt index leader = some before)
    (found' : trace.nodeAt later leader = some after)
    : before.matchIndex peer <= after.matchIndex peer := by
  obtain ⟨first, firstFound, firstNode⟩ := Trace.nodeAt_eq_some.mp found
  obtain ⟨last, lastFound, lastNode⟩ := Trace.nodeAt_eq_some.mp found'
  have grows : forall i point, index <= i -> trace.stateAt i = some point
      -> forall state, nodeState (proto point) leader = some state
        -> before.matchIndex peer <= state.matchIndex peer :=
    admissible.coherent.induction (start := index)
      (motive := fun _ point => forall state, nodeState (proto point) leader = some state
        -> before.matchIndex peer <= state.matchIndex peer)
      (fun point pointFound state nodeFound => by
        rw [firstFound, Option.some.injEq] at pointFound
        subst pointFound
        rw [firstNode, Option.some.injEq] at nodeFound
        subst state
        exact le_rfl)
      (fun i step le stepped ih next nextFound => by
        obtain ⟨_, current, currentFound, _⟩ :=
          stable.leads (afterStart.trans le) (admissible.before stepped)
        have beforeLe := ih current currentFound
        rcases (leader_move admissible stable peer (afterStart.trans le) stepped currentFound nextFound).1
            with same | ⟨_, _, _, _, _, _, _, _, value⟩ <;> omega)
  exact grows later last le lastFound after lastNode

/-- The stable primary's match index for a live, eligible peer eventually covers
every position of its log, and keeps doing so at all later recorded states. -/
theorem match_reaches {heartbeatBound : Option Real}
    (heartbeats : trace.HeartbeatScheduling heartbeatBound)
    (live
      : forall index point,
          start <= index -> trace.stateAt index = some point -> peer ∈ HasLive.live point)
    (eligible
      : forall index state,
          start <= index
          -> trace.nodeAt index leader = some state
          -> peer ∈ eligiblePeers state leader)
    {participants : Finset NodeID} (fair : FairLoss trace participants)
    (leaderIn : leader ∈ participants) (peerIn : peer ∈ participants) {bound reach : Nat}
    (reachLe : start <= reach) {state : NodeState}
    (reachFound : trace.nodeAt reach leader = some state)
    (reachBound : bound <= state.log.length)
    : exists stop point,
        start <= stop
        /\ trace.stateAt stop = some point
        /\ forall index state,
            stop <= index
            -> trace.nodeAt index leader = some state
            -> bound <= state.matchIndex peer := by
  obtain ⟨index, step, packet, afterStart, stepped, event, source, target, matched⟩ :=
    fair peer leader _ peerIn leaderIn
      (acks_sent admissible stable different heartbeats live eligible fair leaderIn peerIn
        reachLe reachFound reachBound) start
  cases payload : packet.envelope.payload with
  | appendEntriesResponse response =>
      rw [payload] at matched
      obtain ⟨newer, success, covers⟩ := matched
      obtain ⟨_, before, beforeFound, _⟩ := stable.leads afterStart (admissible.before stepped)
      obtain ⟨_, after, afterFound, _⟩ :=
        stable.leads (Nat.le_succ_of_le afterStart) (Trace.stateAt_succ_of_stepAt stepped)
      have beforeNode : trace.nodeAt index leader = some before := by
        rw [admissible.nodeAt_before stepped, beforeFound]
      have afterNode : trace.nodeAt (index + 1) leader = some after := by
        rw [Trace.nodeAt_succ stepped, afterFound]
      have value := ack_exact admissible stable afterStart stepped
        (show step.action.delivered = some packet.envelope by rw [event]; rfl) target payload success newer
        beforeFound afterFound (by rw [source]; exact eligible index before afterStart beforeNode)
      rw [source] at value
      refine ⟨
        index + 1,
        step.after,
        by omega,
        Trace.stateAt_succ_of_stepAt stepped,
        fun later next le found => ?_
      ⟩
      have := match_mono admissible stable (peer := peer) (Nat.le_succ_of_le afterStart) le afterNode found
      omega
  | _ =>
      rw [payload] at matched
      exact matched.elim

end Peer

end CCFRaft.Proofs.Replication
