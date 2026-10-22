module

public import CCFRaft.Proofs.Replication.Link
public import CCFRaft.Proofs.Replication.Horizon
public import CCFRaft.Proofs.Replication.Retry

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# A quiet peer settles

Fix a peer of the stable primary that, from some index on, never acknowledges a
given log position. Its term reaches the primary's term, its log eventually stops
changing, and the prefix it shares with the primary's growing log eventually stops
growing.

Each log change acknowledges the end of the accepted batch, and the new log is the
primary's log up to that end. While that end stays below the bound, the change
strictly increases a bounded potential, so changes stop.
-/

open CCF CCF.MultiNodeTransitionSystem
open CCFRaft
open CCFRaft.Model.Node
open CCFRaft.Liveness
open CCFRaft.Proofs.Config
open CCFRaft.Proofs.Safety
open CCFRaft.Proofs.StablePrimary

namespace CCFRaft.Proofs.Replication

/-- A node's log, or the empty log when it has no state. -/
noncomputable def peerLog (trace : Trace) (peer : NodeID) (index : Nat) : List Entry :=
  ((nodeState (trace.state index) peer).map NodeState.log).getD []

theorem peerLog_eq {trace : Trace} {peer : NodeID} {index : Nat} {state : NodeState}
    (found : nodeState (trace.state index) peer = some state)
    : peerLog trace peer index = state.log := by
  simp [peerLog, found]

/-- One more than the length of a short peer log that is a prefix of the
primary's, and zero otherwise. -/
noncomputable def potential {trace : Trace} {leader : NodeID} {term : Nat}
    (stable : LeadsThroughout trace leader term) (peer : NodeID) (bound index : Nat)
    : Nat := by
  classical
  exact
    if peerLog trace peer index <+: (stable.state index).log
        /\ (peerLog trace peer index).length < bound then
      (peerLog trace peer index).length + 1
    else
      0

theorem potential_le {trace : Trace} {leader : NodeID} {term : Nat}
    (stable : LeadsThroughout trace leader term) (peer : NodeID) (bound index : Nat)
    : potential stable peer bound index <= bound := by
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

/-- No conflict when the follower's suffix and the batch are both prefixes of one
list. -/
theorem conflictIndex_eq_none {log common : List Entry} {request : AppendEntriesRequest}
    (left : log.drop request.prevLogIndex <+: common) (right : request.entries <+: common)
    : conflictIndex log request = none := by
  unfold conflictIndex
  rw [Option.map_eq_none_iff, List.find?_eq_none]
  rintro ⟨⟨existing, incoming⟩, position⟩ member
  have same : existing = incoming :=
    zip_prefix_eq left right _ (List.fst_mem_of_mem_zipIdx member)
  simp [same]

/-- From `origin` on, `peer` is at the stable primary's term with log `log`, which
agrees with the primary's log on exactly `agreed` positions, and every delivery is
of a packet sent during the execution. -/
structure Regime {trace : Trace} {leader : NodeID} {term : Nat}
    (stable : LeadsThroughout trace leader term) (peer : NodeID) (log : List Entry)
    (agreed origin : Nat)
    : Prop where
  state
    : forall index,
        origin <= index
        -> exists z,
            nodeState (trace.state index) peer = some z
            /\ z.currentTerm = term
            /\ z.log = log
  agreement : forall index, origin <= index -> agree log (stable.state index).log = agreed
  fresh
    : forall index envelope,
        origin <= index
        -> (trace.event index).delivered = some envelope
        -> exists packet,
            trace.event index = .deliver packet /\ packet.envelope = envelope

theorem Regime.later {trace : Trace} {leader : NodeID} {term : Nat}
    {stable : LeadsThroughout trace leader term} {peer : NodeID} {log : List Entry}
    {agreed origin : Nat} (regime : Regime stable peer log agreed origin) {later : Nat}
    (le : origin <= later)
    : Regime stable peer log agreed later where
  state index after := regime.state index (le.trans after)
  agreement index after := regime.agreement index (le.trans after)
  fresh index envelope after := regime.fresh index envelope (le.trans after)

/-- A packet delivered past a horizon was sent from the horizon's start on. -/
theorem late_sent {trace : Trace} {start stop : Nat}
    (late
      : forall index envelope,
          stop <= index
          -> (trace.event index).delivered = some envelope
          -> exists packet,
              trace.event index = .deliver packet
              /\ packet.envelope = envelope
              /\ trace.Sent packet
              /\ start <= packet.sent
              /\ packet.sent < index)
    {index : Nat} {packet : Packet} (le : stop <= index)
    (event : trace.event index = .deliver packet)
    : start <= packet.sent /\ packet.sent < index := by
  obtain ⟨other, event', _, _, sentLate, before⟩ :=
    late index packet.envelope le (by rw [event]; rfl)
  rw [event, Liveness.Event.deliver.injEq] at event'
  rw [event']
  exact ⟨sentLate, before⟩

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

variable [Config.InitialConfiguration]

section Peer

variable {trace : Trace} {nodes : List NodeID}
  (execution : trace.ValidFrom Config.INITIAL_CONFIGURATION nodes)
  {leader : NodeID} {term : Nat} (stable : LeadsThroughout trace leader term)
  {peer : NodeID}

include execution stable

theorem sends_often (productive : Often (trace.ProductiveSend leader peer))
    : Often
        fun index =>
          exists endIndex,
            trace.event index = .local leader (.sendEntries peer endIndex)
            /\ ((stable.state index).sentIndex peer < (stable.state index).log.length
                -> (stable.state index).sentIndex peer < endIndex) :=
  productive.mono
    fun _ ⟨_, frontier, found, event, grows⟩ => by
      rw [stable.state_eq found] at grows
      exact ⟨frontier, event, grows⟩

theorem requests_sent (productive : Often (trace.ProductiveSend leader peer))
    : InfinitelySent trace leader peer (.appendRequest term) := by
  intro cutoff
  obtain ⟨index, le, endIndex, event, _⟩ := sends_often execution stable productive cutoff
  obtain ⟨_, _, _, sent⟩ := send_step execution stable event
  refine ⟨_, sent, le, rfl, rfl, ?_⟩
  show term <= (makeAppendEntriesRequest (stable.state index) peer endIndex).term
  simp [makeAppendEntriesRequest, stable.current]

/-- The peer reaches the primary's term and stays there. -/
theorem peer_current {participants : Finset NodeID} (fair : FairLoss trace participants)
    (leaderIn : leader ∈ participants) (peerIn : peer ∈ participants)
    (productive : Often (trace.ProductiveSend leader peer))
    {joined : Nat}
    (termLe
      : forall index state,
          joined <= index
          -> nodeState (trace.state index) peer = some state
          -> state.currentTerm <= term)
    : exists start,
        forall index,
          start <= index
          -> exists state,
              nodeState (trace.state index) peer = some state
              /\ state.currentTerm = term := by
  obtain ⟨index, packet, joinedLe, event, _, target, matched⟩ :=
    fair leader peer _ leaderIn peerIn (requests_sent execution stable productive) joined
  cases payload : packet.envelope.payload with
  | appendEntriesRequest request =>
      rw [payload] at matched
      refine ⟨index + 1, fun later le => ?_⟩
      obtain ⟨state, found, ge⟩ :=
        term_after_request execution stable (by rw [event]; rfl) payload matched
          (Nat.lt_of_succ_le le)
      rw [target] at found
      exact ⟨state, found, le_antisymm (termLe _ _ (by omega) found) ge⟩
  | _ =>
      rw [payload] at matched
      exact matched.elim

/-- The prefix a fixed log shares with the primary's growing log eventually stops
growing. -/
theorem agree_settles (log : List Entry) (start : Nat)
    : exists stop,
        start <= stop
        /\ forall index,
            stop <= index
            -> agree log (stable.state index).log = agree log (stable.state stop).log :=
  eventually_const
    (fun index _ => agree_mono (stable_prefix execution stable (Nat.le_succ index)))
    (fun _ _ => agree_le_left log _)

variable (different : Not (peer = leader))

include different

section Regime

variable {log : List Entry} {agreed origin : Nat}

/-- How the peer handles a delivered request in the regime: requests of other
senders are answered to them, and the primary's requests are rejected beyond the
agreement, ignored below it, or accepted up to it. -/
theorem request_outcome (regime : Regime stable peer log agreed origin) {index : Nat}
    {packet : Packet} (event : trace.event index = .deliver packet)
    (began : origin <= index) (target : packet.envelope.target = peer)
    {request : AppendEntriesRequest}
    (payload : packet.envelope.payload = .appendEntriesRequest request)
    : exists w sends,
        w.currentTerm = term
        /\ w.log = log
        /\ outgoing (trace.state index) (.deliver packet.envelope) = some sends
        /\ (forall x, x ∈ sends -> x.target = packet.envelope.source)
        /\ (packet.envelope.source = leader
            -> request.term = term
                /\ request.prevLogIndex <= (stable.state index).log.length
                /\ request.prevLogTerm
                    = termAt (stable.state index).log request.prevLogIndex
                /\ ((agreed < request.prevLogIndex
                      /\ Not
                          (termAt log request.prevLogIndex
                            = termAt (stable.state index).log request.prevLogIndex)
                      /\ sends
                          = [{
                              source := peer,
                              target := leader,
                              payload := .appendEntriesResponse (nackResponse w request)
                            }])
                    \/ (request.prevLogIndex < agreed /\ sends = [])
                    \/ (request.prevLogIndex + request.entries.length <= agreed
                        /\ sends
                            = [{
                                source := peer,
                                target := leader,
                                payload :=
                                  .appendEntriesResponse
                                    {
                                      term,
                                      success := true,
                                      lastLogIndex :=
                                        request.prevLogIndex + request.entries.length
                                    }
                              }]))) := by
  have delivered : (trace.event index).delivered = some packet.envelope := by rw [event]; rfl
  obtain ⟨z, found, zTerm, zLog⟩ := regime.state index began
  obtain ⟨z', found', zTerm', zLog'⟩ := regime.state (index + 1) (Nat.le_succ_of_le began)
  have foundAt : nodeState (trace.state index) packet.envelope.target = some z := by
    rw [target]; exact found
  have foundAt' : nodeState (trace.state (index + 1)) packet.envelope.target = some z' := by
    rw [target]; exact found'
  have le : request.term <= z.currentTerm := by
    have := request_term_le execution stable delivered payload foundAt'
    omega
  obtain ⟨after, sends, foundAfter, step, out⟩ :=
    receive_step execution delivered payload foundAt le
  have afterLog : after.log = log := by
    rw [foundAt', Option.some.injEq] at foundAfter
    rw [← foundAfter, zLog']
  have wTerm : (awareState z request).currentTerm = term :=
    (awareState_term z request).trans zTerm
  have wLog : (awareState z request).log = log := (awareState_log z request).trans zLog
  refine ⟨awareState z request, sends, wTerm, wLog, out, ?_, fun source => ?_⟩
  · rcases step with ⟨_, _, rfl⟩ | ⟨_, _, _, _, rfl⟩ | ⟨_, _, _, _, _, _, _, _, _, _, rfl⟩ <;>
      simp
  have sent : trace.Sent packet := (execution.resolution index packet (by rw [event]; rfl)).1
  have rTerm := stable_requests execution stable sent source payload
  obtain ⟨_, _, prevLe, prevTerm, entries⟩ := request_at execution stable delivered payload rTerm
  have view := view_at execution stable different found zTerm
  have agreement := regime.agreement index began
  refine ⟨rTerm, prevLe, prevTerm, ?_⟩
  rw [target, source] at step
  rcases step with ⟨reject, _, sendsEq⟩ | ⟨_, _, ignore, _, sendsEq⟩
      | ⟨_, matched, _, _, _, _, acceptEq, _, _, _, sendsEq⟩
  · have mismatch
        : Not (termAt log request.prevLogIndex
            = termAt (stable.state index).log request.prevLogIndex) := by
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
        : forall j,
            0 < j
            -> j <= log.length
            -> j <= (stable.state index).log.length
            -> termAt log j = termAt (stable.state index).log j
            -> log.take j = (stable.state index).log.take j := by
      intro j positive bound leaderBound same
      have := view.matching j positive (by rw [zLog]; exact bound) leaderBound
        (by rw [zLog]; exact same)
      rwa [zLog] at this
    have prevAgree
        : log.take request.prevLogIndex
          = (stable.state index).log.take request.prevLogIndex := by
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
    have takeEq
        : log.take (request.prevLogIndex + request.entries.length)
          = (stable.state index).log.take (request.prevLogIndex + request.entries.length) := by
      rw [shape]
      exact List.take_left' (by rw [List.length_take]; omega)
    have := le_agree _ _ _ lengthLe (by omega) takeEq
    omega

/-- A rejection the peer sends the primary in the regime answers a request of the
term beyond the agreement, whose previous position mismatches the peer's log. -/
theorem nack_origin (regime : Regime stable peer log agreed origin) {packet : Packet}
    (sent : trace.Sent packet) (began : origin <= packet.sent)
    (source : packet.envelope.source = peer) (target : packet.envelope.target = leader)
    {response : AppendEntriesResponse}
    (payload : packet.envelope.payload = .appendEntriesResponse response)
    (failure : response.success = false)
    : exists w request,
        w.currentTerm = term
        /\ w.log = log
        /\ response = nackResponse w request
        /\ request.term = term
        /\ agreed < request.prevLogIndex
        /\ request.prevLogIndex <= (stable.state packet.sent).log.length
        /\ request.prevLogTerm
            = termAt (stable.state packet.sent).log request.prevLogIndex
        /\ Not
            (termAt log request.prevLogIndex
              = termAt (stable.state packet.sent).log request.prevLogIndex) := by
  obtain ⟨envelope, request, _, delivered, envelopeTarget, requestPayload, _⟩ :=
    response_origin execution sent payload
  obtain ⟨delivery, event, rfl⟩ := regime.fresh _ _ began delivered
  obtain ⟨w, sends, wTerm, wLog, out, aimed, detail⟩ :=
    request_outcome execution stable different regime event began
      (envelopeTarget.trans source) requestPayload
  have member : sends[packet.ordinal]? = some packet.envelope := by
    have selected
        : (trace.event packet.sent).action = some (.deliver delivery.envelope) := by
      rw [event]; rfl
    unfold Trace.Sent at sent
    rw [selected] at sent
    simpa [out] using sent
  have mem := List.mem_of_getElem? member
  have fromLeader : delivery.envelope.source = leader := by
    rw [← aimed _ mem, target]
  obtain ⟨rTerm, prevLe, prevTerm, outcome⟩ := detail fromLeader
  rcases outcome with ⟨above, mismatch, sendsEq⟩ | ⟨_, sendsEq⟩ | ⟨_, sendsEq⟩
  · rw [sendsEq, List.mem_singleton] at mem
    rw [mem] at payload
    injection payload with responseEq
    exact ⟨w, request, wTerm, wLog, responseEq.symm, rTerm, above, prevLe, prevTerm, mismatch⟩
  · rw [sendsEq] at mem
    simp at mem
  · rw [sendsEq, List.mem_singleton] at mem
    rw [mem] at payload
    injection payload with responseEq
    rw [← responseEq] at failure
    simp at failure

/-- Read against the primary's later log, a rejection from the regime retries at
or above the agreement and below the rejected position. -/
theorem retry_bounds (regime : Regime stable peer log agreed origin) {w : NodeState}
    {request : AppendEntriesRequest} (wTerm : w.currentTerm = term) (wLog : w.log = log)
    (rTerm : request.term = term) {sent later : Nat} (began : origin <= sent)
    (le : sent <= later)
    (prevLe : request.prevLogIndex <= (stable.state sent).log.length)
    (prevTerm : request.prevLogTerm = termAt (stable.state sent).log request.prevLogIndex)
    (mismatch
      : Not
          (termAt log request.prevLogIndex
            = termAt (stable.state sent).log request.prevLogIndex))
    : agreed <= retry (stable.state later).log w request
      /\ retry (stable.state later).log w request
          < min request.prevLogIndex (log.length + 1) := by
  obtain ⟨z, found, zTerm, zLog⟩ := regime.state later (began.trans le)
  have view := view_at execution stable different found zTerm
  have grows := stable_prefix execution stable le
  have transfer
      : termAt (stable.state later).log request.prevLogIndex
        = termAt (stable.state sent).log request.prevLogIndex :=
    termAt_of_prefix grows prevLe
  rw [← transfer] at prevTerm mismatch
  have sorted := view.sorted
  have positive := view.positive
  rw [zLog] at sorted positive
  have agreement := regime.agreement later (began.trans le)
  constructor
  · have := agree_le_retry (w := w) (by rw [wLog]; exact sorted) view.leaderSorted
      (fun index => by rw [wTerm]; exact view.leaderTerms index) (prevLe.trans grows.length_le)
      prevTerm (by rw [wLog]; exact mismatch)
    rwa [wLog, agreement] at this
  · have := retry_lt (w := w) (log := (stable.state later).log) (by rw [wLog]; exact positive)
      (by omega) prevTerm (by rw [wLog]; exact mismatch)
    rwa [wLog] at this

/-- While the peer stays eligible, `min sentIndex agreed` never drops in the
regime once rejections in flight come from the regime. -/
theorem floor_step (regime : Regime stable peer log agreed origin)
    (eligible
      : forall index, origin <= index -> peer ∈ eligiblePeers (stable.state index) leader)
    {index : Nat} (began : origin <= index)
    (late : forall packet, trace.event index = .deliver packet -> origin <= packet.sent)
    : min ((stable.state index).sentIndex peer) agreed
      <= min ((stable.state (index + 1)).sentIndex peer) agreed := by
  rcases (leader_move execution stable peer index (stable.found index)
      (stable.found (index + 1))).2 with same | ⟨endIndex, _, le, _, value, _⟩
      | ⟨envelope, response, delivered, source, target, payload, failure, value⟩
      | ⟨_, _, _, _, _, aimed⟩
  · rw [same]
  · rw [value]
    omega
  · obtain ⟨packet, event, rfl⟩ := regime.fresh index envelope began delivered
    have resolved := execution.resolution index packet (by rw [event]; rfl)
    obtain ⟨w, request, wTerm, wLog, responseEq, rTerm, _, prevLe, prevTerm, mismatch⟩ :=
      nack_origin execution stable different regime resolved.1 (late packet event) source target
        payload failure
    obtain ⟨floor, _⟩ :=
      retry_bounds execution stable different regime wTerm wLog rTerm (late packet event)
        resolved.2.1.le prevLe prevTerm mismatch
    have retryEq
        : retry (stable.state index).log w request
          = findHighestPossibleMatch (stable.state index).log response.lastLogIndex
              response.term := by
      rw [responseEq]
      rfl
    rw [value]
    omega
  · exact absurd (eligible index began) aimed

/-- The primary's retry index for the peer eventually stays at or above the
agreement. -/
theorem floor_reached (regime : Regime stable peer log agreed origin)
    (eligible
      : forall index, origin <= index -> peer ∈ eligiblePeers (stable.state index) leader)
    (productive : Often (trace.ProductiveSend leader peer)) {stop : Nat}
    (began : origin <= stop)
    (late
      : forall index packet,
          stop <= index -> trace.event index = .deliver packet -> origin <= packet.sent)
    : exists reached,
        stop <= reached
        /\ forall index,
            reached <= index -> agreed <= (stable.state index).sentIndex peer := by
  obtain ⟨reached, le, constant⟩ :=
    eventually_const (f := fun index => min ((stable.state index).sentIndex peer) agreed)
      (start := stop) (bound := agreed)
      (fun index after =>
        floor_step execution stable different regime eligible (began.trans after)
          (late index · after))
      (fun _ _ => Nat.min_le_right _ _)
  refine ⟨reached, le, fun index later => ?_⟩
  by_contra low
  obtain ⟨d, after, endIndex, event, grows⟩ := sends_often execution stable productive reached
  obtain ⟨_, _, frontier, _⟩ := send_step execution stable event
  have atIndex
      : min ((stable.state index).sentIndex peer) agreed
        = min ((stable.state reached).sentIndex peer) agreed :=
    constant index later
  have atD
      : min ((stable.state d).sentIndex peer) agreed
        = min ((stable.state reached).sentIndex peer) agreed :=
    constant d after
  have atNext
      : min ((stable.state (d + 1)).sentIndex peer) agreed
        = min ((stable.state reached).sentIndex peer) agreed :=
    constant (d + 1) (Nat.le_succ_of_le after)
  have agreement := regime.agreement d (by omega)
  have := agree_le_right log (stable.state d).log
  have grown := grows (by omega)
  omega

theorem match_le_agreed (regime : Regime stable peer log agreed origin) {index : Nat}
    (began : origin <= index)
    : (stable.state index).matchIndex peer <= agreed := by
  obtain ⟨z, found, zTerm, zLog⟩ := regime.state index began
  have := (view_at execution stable different found zTerm).matchLe
  rwa [zLog, regime.agreement index began] at this

theorem request_matches {index endIndex threshold : Nat}
    (low : (stable.state index).sentIndex peer < threshold) (high : threshold <= endIndex)
    (bound : endIndex <= (stable.state index).log.length)
    : Traffic.Matches (.replication term threshold)
        (.appendEntriesRequest
          (makeAppendEntriesRequest (stable.state index) peer endIndex)) := by
  show term <= _ /\ _ < threshold /\ threshold <= _ + _
  simp only [makeAppendEntriesRequest, messageEntries_length bound, stable.current]
  omega

/-- A request of the primary delivered in the regime, sent while the retry index
was at or above the agreement, is rejected beyond the agreement or accepted
exactly at it. -/
theorem answer (regime : Regime stable peer log agreed origin)
    (eligible
      : forall index, origin <= index -> peer ∈ eligiblePeers (stable.state index) leader)
    {index : Nat} {packet : Packet} (event : trace.event index = .deliver packet)
    (sentLate : origin <= packet.sent)
    (source : packet.envelope.source = leader) (target : packet.envelope.target = peer)
    {request : AppendEntriesRequest}
    (payload : packet.envelope.payload = .appendEntriesRequest request)
    (floor : agreed <= (stable.state packet.sent).sentIndex peer)
    : request.term = term
      /\ request.prevLogIndex = (stable.state packet.sent).sentIndex peer
      /\ request.prevLogIndex + request.entries.length
          = (stable.state (packet.sent + 1)).sentIndex peer
      /\ request.prevLogIndex + request.entries.length
          <= (stable.state packet.sent).log.length
      /\ ((agreed < request.prevLogIndex
            /\ exists w,
                w.currentTerm = term
                /\ w.log = log
                /\ request.prevLogIndex <= (stable.state index).log.length
                /\ request.prevLogTerm
                    = termAt (stable.state index).log request.prevLogIndex
                /\ Not
                    (termAt log request.prevLogIndex
                      = termAt (stable.state index).log request.prevLogIndex)
                /\ trace.Sent
                    ⟨
                      index,
                      0,
                      {
                        source := peer
                        target := leader
                        payload := .appendEntriesResponse (nackResponse w request)
                      }
                    ⟩)
          \/ (request.prevLogIndex + request.entries.length = agreed
              /\ trace.Sent
                  ⟨
                    index,
                    0,
                    {
                      source := peer
                      target := leader
                      payload :=
                        .appendEntriesResponse
                          { term, success := true, lastLogIndex := agreed }
                    }
                  ⟩)) := by
  have resolved := execution.resolution index packet (by rw [event]; rfl)
  have sent := resolved.1
  have began : origin <= index := by
    have := resolved.2.1
    omega
  obtain ⟨rTerm, prevEq, endEq, endLe⟩ :=
    leader_request_shape execution stable (by rw [target]; exact eligible _ sentLate) sent
      source payload
  rw [target] at prevEq endEq
  obtain ⟨w, sends, wTerm, wLog, out, _, detail⟩ :=
    request_outcome execution stable different regime event began target payload
  obtain ⟨_, prevLe, prevTerm, outcome⟩ := detail source
  have selected : (trace.event index).action = some (.deliver packet.envelope) := by
    rw [event]
    rfl
  refine ⟨rTerm, prevEq, endEq, endLe, ?_⟩
  rcases outcome with ⟨above, mismatch, sendsEq⟩ | ⟨_, _⟩ | ⟨_, sendsEq⟩
  · exact Or.inl ⟨above, w, wTerm, wLog, prevLe, prevTerm, mismatch,
      sent_of_outgoing execution selected out (by rw [sendsEq]; rfl)⟩
  · omega
  · have reached : request.prevLogIndex + request.entries.length = agreed := by omega
    refine Or.inr ⟨reached, sent_of_outgoing execution selected out ?_⟩
    rw [sendsEq, reached]
    rfl

/-- The primary never sends a batch across the agreement infinitely often. -/
theorem extend_absurd (regime : Regime stable peer log agreed origin)
    (eligible
      : forall index, origin <= index -> peer ∈ eligiblePeers (stable.state index) leader)
    {participants : Finset NodeID} (fair : FairLoss trace participants)
    (leaderIn : leader ∈ participants) (peerIn : peer ∈ participants) {floorStart : Nat}
    (originLe : origin <= floorStart)
    (floor
      : forall index,
          floorStart <= index -> agreed <= (stable.state index).sentIndex peer)
    (sends : InfinitelySent trace leader peer (.replication term (agreed + 1)))
    : False := by
  obtain ⟨stop, late⟩ := horizon execution floorStart
  obtain ⟨index, packet, le, event, source, target, matched⟩ :=
    fair leader peer _ leaderIn peerIn sends stop
  cases payload : packet.envelope.payload with
  | appendEntriesRequest request =>
      rw [payload] at matched
      obtain ⟨sentLate, before⟩ := late_sent late le event
      obtain ⟨_, _, _, _, outcome⟩ :=
        answer execution stable different regime eligible event (by omega) source target payload
          (floor _ sentLate)
      obtain ⟨_, lt, reach⟩ := matched
      rcases outcome with ⟨above, _⟩ | ⟨reached, _⟩ <;> omega
  | _ =>
      rw [payload] at matched
      exact matched.elim

/-- Without batches across the agreement, a primary whose log extends past it keeps
its retry index strictly above it. -/
theorem floor_strict (regime : Regime stable peer log agreed origin)
    (eligible
      : forall index, origin <= index -> peer ∈ eligiblePeers (stable.state index) leader)
    (productive : Often (trace.ProductiveSend leader peer)) {floorStart : Nat}
    (originLe : origin <= floorStart)
    (floor
      : forall index,
          floorStart <= index -> agreed <= (stable.state index).sentIndex peer)
    {grown : Nat}
    (long : forall index, grown <= index -> agreed < (stable.state index).log.length)
    (rare : Not (InfinitelySent trace leader peer (.replication term (agreed + 1))))
    : exists strict,
        floorStart <= strict
        /\ forall index,
            strict <= index -> agreed < (stable.state index).sentIndex peer := by
  simp only [InfinitelySent, not_forall, not_exists, not_and] at rare
  obtain ⟨cutoff, rare⟩ := rare
  refine ⟨max cutoff (max grown floorStart), by omega, fun index le => ?_⟩
  by_contra low
  have stays : forall d, index <= d -> (stable.state d).sentIndex peer = agreed := by
    intro d after
    induction d, after using Nat.le_induction with
    | base =>
        have := floor index (by omega)
        omega
    | succ d after ih =>
        have := floor (d + 1) (by omega)
        rcases (leader_move execution stable peer d (stable.found d)
            (stable.found (d + 1))).2 with same | ⟨endIndex, _, _, bound, value, sent⟩
            | ⟨_, _, _, _, _, _, _, value⟩ | ⟨_, _, _, _, _, aimed⟩
        · rw [same, ih]
        · by_contra moved
          exact rare _ sent (show cutoff <= d by omega) rfl rfl
            (request_matches execution stable different (by omega) (by omega) bound)
        · have := match_le_agreed execution stable different regime (show origin <= d by omega)
          rw [value]
          omega
        · exact absurd (eligible d (by omega)) aimed
  obtain ⟨d, after, endIndex, event, grows⟩ := sends_often execution stable productive index
  obtain ⟨_, bound, frontier, sent⟩ := send_step execution stable event
  have atD := stays d after
  have atNext := stays (d + 1) (by omega)
  have := long d (by omega)
  have grown' := grows (by omega)
  exact rare _ sent (show cutoff <= d by omega) rfl rfl
    (request_matches execution stable different (by omega) (by omega) bound)

/-- With the retry index strictly above the agreement, every request is rejected.
The least rejected position that recurs is answered by one fixed rejection, which
keeps pulling the retry index below it, so batches keep crossing it from below and
some smaller position recurs. -/
theorem bucket_absurd (regime : Regime stable peer log agreed origin)
    (eligible
      : forall index, origin <= index -> peer ∈ eligiblePeers (stable.state index) leader)
    {participants : Finset NodeID} (fair : FairLoss trace participants)
    (leaderIn : leader ∈ participants) (peerIn : peer ∈ participants)
    (productive : Often (trace.ProductiveSend leader peer)) {strict : Nat}
    (originLe : origin <= strict)
    (above
      : forall index, strict <= index -> agreed < (stable.state index).sentIndex peer)
    : False := by
  obtain ⟨stop, late⟩ := horizon execution strict
  have rejected
      : forall index packet request,
          stop <= index
          -> trace.event index = .deliver packet
          -> packet.envelope.source = leader
          -> packet.envelope.target = peer
          -> packet.envelope.payload = .appendEntriesRequest request
          -> request.term = term
            /\ request.prevLogIndex = (stable.state packet.sent).sentIndex peer
            /\ strict <= packet.sent
            /\ packet.sent < index
            /\ agreed < request.prevLogIndex
            /\ exists w,
                w.currentTerm = term
                /\ w.log = log
                /\ request.prevLogIndex <= (stable.state index).log.length
                /\ request.prevLogTerm
                  = termAt (stable.state index).log request.prevLogIndex
                /\ Not (termAt log request.prevLogIndex
                    = termAt (stable.state index).log request.prevLogIndex)
                /\ trace.Sent ⟨index, 0, {
                      source := peer
                      target := leader
                      payload := .appendEntriesResponse (nackResponse w request)
                    }⟩ := by
    intro index packet request le event source target payload
    obtain ⟨sentLate, before⟩ := late_sent late le event
    obtain ⟨rTerm, prevEq, _, _, outcome⟩ :=
      answer execution stable different regime eligible event (by omega) source target payload
        (above _ sentLate).le
    rcases outcome with ⟨gt, rest⟩ | ⟨reached, _⟩
    · exact ⟨rTerm, prevEq, sentLate, before, gt, rest⟩
    · have := above _ sentLate
      omega
  let P : Nat -> Prop := fun index =>
    stop <= index
    /\ exists packet request,
        trace.event index = .deliver packet
        /\ packet.envelope.source = leader
        /\ packet.envelope.target = peer
        /\ packet.envelope.payload = .appendEntriesRequest request
  let label : Nat -> Nat := fun index => min (prevOf (trace.event index)) (log.length + 1)
  have labelEq
      : forall {index packet request},
          trace.event index = .deliver packet
          -> packet.envelope.payload = .appendEntriesRequest request
          -> label index = min request.prevLogIndex (log.length + 1) := by
    intro index packet request event payload
    show min (prevOf _) _ = _
    rw [prevOf_eq event payload]
  have often : Often P := by
    intro cutoff
    obtain ⟨index, packet, le, event, source, target, matched⟩ :=
      fair leader peer _ leaderIn peerIn (requests_sent execution stable productive)
        (max cutoff stop)
    cases payload : packet.envelope.payload with
    | appendEntriesRequest request =>
        exact ⟨index, by omega, by omega, packet, request, event, source, target, payload⟩
    | _ =>
        rw [payload] at matched
        exact matched.elim
  obtain ⟨least, repeats, minimal⟩ :=
    often.least_bucket (label := label) (bound := log.length + 1)
      (fun _ _ => Nat.min_le_right _ _)
  obtain ⟨first, _, ⟨firstLe, packet₀, request₀, event₀, source₀, target₀, payload₀⟩,
      label₀⟩ := repeats 0
  obtain ⟨rTerm₀, _, sentLate₀, before₀, gt₀, w₀, wTerm₀, wLog₀, prevLe₀, prevTerm₀,
      mismatch₀, _⟩ :=
    rejected first packet₀ request₀ firstLe event₀ source₀ target₀ payload₀
  have leastEq : least = min request₀.prevLogIndex (log.length + 1) := by
    rw [← label₀, labelEq event₀ payload₀]
  have agreedLe : agreed <= log.length := by
    rw [← regime.agreement first (by omega)]
    exact agree_le_left _ _
  have agreedLt : agreed < least := by omega
  obtain ⟨nack, nackEq⟩ : exists nack, nack = nackResponse w₀ request₀ := ⟨_, rfl⟩
  have sameNack
      : forall {index packet request w},
          first <= index
          -> trace.event index = .deliver packet
          -> packet.envelope.payload = .appendEntriesRequest request
          -> label index = least
          -> w.currentTerm = term
          -> w.log = log
          -> request.term = term
          -> request.prevLogIndex <= (stable.state index).log.length
          -> request.prevLogTerm = termAt (stable.state index).log request.prevLogIndex
          -> nackResponse w request = nack := by
    intro index packet request w le event payload labelIs wTerm wLog rTerm prevLe prevTerm
    rw [labelEq event payload] at labelIs
    rw [nackEq]
    by_cases short : request₀.prevLogIndex <= log.length
    · have prevEq : request.prevLogIndex = request₀.prevLogIndex := by omega
      have transfer
          : termAt (stable.state index).log request₀.prevLogIndex
            = termAt (stable.state first).log request₀.prevLogIndex :=
        termAt_of_prefix (stable_prefix execution stable le) prevLe₀
      refine nackResponse_congr (wTerm.trans wTerm₀.symm) (wLog.trans wLog₀.symm)
        (rTerm.trans rTerm₀.symm) prevEq ?_
      rw [prevTerm, prevTerm₀, prevEq, transfer]
    · rw [nackResponse_short (by rw [wLog]; omega), nackResponse_short (by rw [wLog₀]; omega),
        wTerm, wTerm₀, wLog, wLog₀]
  have nacksSent : InfinitelySent trace peer leader (.exact (.appendEntriesResponse nack)) := by
    intro cutoff
    obtain ⟨index, le, ⟨stopLe, packet, request, event, source, target, payload⟩, labelIs⟩ :=
      repeats (max cutoff first)
    obtain ⟨rTerm, _, _, _, _, w, wTerm, wLog, prevLe, prevTerm, _, sent⟩ :=
      rejected index packet request stopLe event source target payload
    refine ⟨_, sent, show cutoff <= index by omega, rfl, rfl, ?_⟩
    show Message.appendEntriesResponse (nackResponse w request) = .appendEntriesResponse nack
    rw [sameNack (by omega) event payload labelIs wTerm wLog rTerm prevLe prevTerm]
  have low : Often fun index => (stable.state index).sentIndex peer < least := by
    intro cutoff
    obtain ⟨index, packet, le, event, source, target, matched⟩ :=
      fair peer leader _ peerIn leaderIn nacksSent (max cutoff first)
    have matched : packet.envelope.payload = .appendEntriesResponse nack := matched
    have delivered : (trace.event index).delivered = some packet.envelope := by
      rw [event]
      rfl
    have value :=
      nack_exact execution stable delivered target matched
        (by rw [nackEq]; exact nackResponse_failure w₀ request₀) (stable.found index)
        (stable.found (index + 1)) (by rw [source]; exact eligible index (by omega))
    rw [source] at value
    obtain ⟨_, retryLt⟩ :=
      retry_bounds execution stable different regime wTerm₀ wLog₀ rTerm₀
        (show origin <= first by omega) (show first <= index by omega) prevLe₀ prevTerm₀
        mismatch₀
    have retryEq
        : retry (stable.state index).log w₀ request₀
          = findHighestPossibleMatch (stable.state index).log nack.lastLogIndex nack.term := by
      rw [nackEq]
      rfl
    have := match_le_agreed execution stable different regime (show origin <= index by omega)
    refine ⟨index + 1, by omega, ?_⟩
    show (stable.state (index + 1)).sentIndex peer < least
    rw [value]
    omega
  have high : Often fun index => least <= (stable.state index).sentIndex peer := by
    intro cutoff
    obtain ⟨stop', late'⟩ := horizon execution cutoff
    obtain ⟨index, le, ⟨stopLe, packet, request, event, source, target, payload⟩, labelIs⟩ :=
      repeats (max stop' stop)
    obtain ⟨_, prevEq, _, _, _, _⟩ :=
      rejected index packet request stopLe event source target payload
    obtain ⟨sentLate, _⟩ := late_sent late' (show stop' <= index by omega) event
    rw [labelEq event payload] at labelIs
    exact ⟨packet.sent, sentLate, by omega⟩
  have batches : InfinitelySent trace leader peer (.replication term least) := by
    intro cutoff
    obtain ⟨d, le, below, reach⟩ := Often.crossing low high (max cutoff strict)
    rcases (leader_move execution stable peer d (stable.found d) (stable.found (d + 1))).2
        with same | ⟨endIndex, _, _, bound, value, sent⟩ | ⟨_, _, _, _, _, _, _, value⟩
        | ⟨_, _, _, _, _, aimed⟩
    · omega
    · exact ⟨_, sent, show cutoff <= d by omega, rfl, rfl,
        request_matches execution stable different below (by omega) bound⟩
    · have := match_le_agreed execution stable different regime (show origin <= d by omega)
      omega
    · exact absurd (eligible d (by omega)) aimed
  have smaller : Often fun index => P index /\ label index < least := by
    intro cutoff
    obtain ⟨index, packet, le, event, source, target, matched⟩ :=
      fair leader peer _ leaderIn peerIn batches (max cutoff stop)
    cases payload : packet.envelope.payload with
    | appendEntriesRequest request =>
        rw [payload] at matched
        obtain ⟨_, lt, _⟩ := matched
        have := labelEq event payload
        exact ⟨
          index,
          by omega,
          ⟨by omega, packet, request, event, source, target, payload⟩,
          by omega
        ⟩
    | _ =>
        rw [payload] at matched
        exact matched.elim
  obtain ⟨k, kLe, repeatsK⟩ :=
    smaller.bucket (label := label) (bound := least - 1) (fun _ holds => by omega)
  exact minimal k (by omega) (repeatsK.mono fun _ ⟨⟨holds, _⟩, eq⟩ => ⟨holds, eq⟩)

end Regime

section Quiet

variable {bound start : Nat}
  (quiet
    : forall packet,
        trace.Sent packet
        -> start <= packet.sent
        -> packet.envelope.source = peer
        -> packet.envelope.target = leader
        -> Not (Traffic.Matches (.response term true bound) packet.envelope.payload))

include quiet

/-- While the peer stays at the term and never acknowledges `bound`, a log change
strictly increases the potential, and otherwise the potential does not drop. -/
theorem potential_step {index : Nat} (began : start <= index) {before after : NodeState}
    (found : nodeState (trace.state index) peer = some before)
    (found' : nodeState (trace.state (index + 1)) peer = some after)
    (beforeTerm : before.currentTerm = term) (afterTerm : after.currentTerm = term)
    : (after.log = before.log
        -> potential stable peer bound index <= potential stable peer bound (index + 1))
      /\ (Not (after.log = before.log)
          -> potential stable peer bound index
              < potential stable peer bound (index + 1)) := by
  have grows := stable_prefix execution stable (Nat.le_succ index)
  unfold potential
  rw [peerLog_eq found, peerLog_eq found']
  refine ⟨fun same => ?_, fun changed => ?_⟩
  · rw [same]
    split
    · rename_i holds
      have holds' : before.log <+: (stable.state (index + 1)).log /\ before.log.length < bound :=
        ⟨holds.1.trans grows, holds.2⟩
      rw [ite_eq_left_of_eq_true _ _ (eq_true holds')]
    · exact Nat.zero_le _
  obtain ⟨envelope, request, leaderState, _, _, _, _, _, leaderFound, within, postLog, differ,
      sent⟩ :=
    follower_step execution stable different found found' beforeTerm afterTerm changed
  rw [stable.state_eq leaderFound] at within postLog differ
  have short : request.prevLogIndex + request.entries.length < bound := by
    have := quiet _ sent began rfl rfl
    simp only [Traffic.Matches, le_refl, true_and] at this
    omega
  have length : after.log.length = request.prevLogIndex + request.entries.length := by
    rw [postLog, List.length_take]
    omega
  have prefix_ : after.log <+: (stable.state (index + 1)).log := by
    rw [postLog]
    exact (List.take_prefix _ _).trans grows
  have holds' : after.log <+: (stable.state (index + 1)).log /\ after.log.length < bound :=
    ⟨prefix_, by omega⟩
  rw [ite_eq_left_of_eq_true _ _ (eq_true holds'), length]
  split
  · rename_i holds
    have : before.log.length < request.prevLogIndex + request.entries.length := by
      by_contra long
      exact differ (take_eq_of_prefix holds.1 (Nat.le_of_not_lt long)).symm
    omega
  · omega

/-- The peer's log eventually stops changing. -/
theorem log_settles
    (current
      : forall index,
          start <= index
          -> exists state,
              nodeState (trace.state index) peer = some state /\ state.currentTerm = term)
    : exists settled,
        start <= settled
        /\ forall index,
            settled <= index
            -> peerLog trace peer index = peerLog trace peer settled := by
  have step : forall index, start <= index -> peerLog trace peer (index + 1) = peerLog trace peer index
      \/ potential stable peer bound index < potential stable peer bound (index + 1) := by
    intro index began
    obtain ⟨before, found, beforeTerm⟩ := current index began
    obtain ⟨after, found', afterTerm⟩ := current (index + 1) (Nat.le_succ_of_le began)
    rw [peerLog_eq found, peerLog_eq found']
    by_cases same : after.log = before.log
    · exact Or.inl same
    · exact Or.inr ((potential_step execution stable different quiet began found found'
        beforeTerm afterTerm).2 same)
  obtain ⟨stop, began, constant⟩ := eventually_const (f := potential stable peer bound)
    (start := start) (bound := bound)
    (fun index began => by
      rcases step index began with same | lt
      · obtain ⟨before, found, beforeTerm⟩ := current index began
        obtain ⟨after, found', afterTerm⟩ := current (index + 1) (Nat.le_succ_of_le began)
        rw [peerLog_eq found, peerLog_eq found'] at same
        exact (potential_step execution stable different quiet began found found' beforeTerm
          afterTerm).1 same
      · exact lt.le)
    (fun index _ => potential_le stable peer bound index)
  refine ⟨stop, began, fun index le => ?_⟩
  induction index, le using Nat.le_induction with
  | base => rfl
  | succ index le ih =>
      rcases step index (began.trans le) with same | lt
      · rw [same, ih]
      · have := constant index le
        have := constant (index + 1) (Nat.le_succ_of_le le)
        omega

/-- A quiet peer settles into a regime. -/
theorem settles {participants : Finset NodeID} (fair : FairLoss trace participants)
    (leaderIn : leader ∈ participants) (peerIn : peer ∈ participants)
    (productive : Often (trace.ProductiveSend leader peer))
    {joined : Nat}
    (termLe
      : forall index state,
          joined <= index
          -> nodeState (trace.state index) peer = some state
          -> state.currentTerm <= term)
    : exists log agreed origin,
        start <= origin /\ Regime stable peer log agreed origin := by
  obtain ⟨current, holds⟩ := peer_current execution stable fair leaderIn peerIn productive termLe
  obtain ⟨settled, settledLe, logConst⟩ :=
    log_settles execution stable different (start := max start current)
      (fun packet sent le => quiet packet sent (le_trans (le_max_left _ _) le))
      (fun index le => holds index (le_trans (le_max_right _ _) le))
  obtain ⟨stop, stopLe, agreeConst⟩ :=
    agree_settles execution stable (peerLog trace peer settled) settled
  obtain ⟨fresh, freshHolds⟩ := horizon execution 0
  refine ⟨
    peerLog trace peer settled,
    agree (peerLog trace peer settled) (stable.state stop).log,
    max stop fresh,
    by omega,
    ⟨
      fun index le => ?_,
      fun index le => agreeConst index (by omega),
      fun index envelope le delivered => ?_
    ⟩
  ⟩
  · obtain ⟨z, found, zTerm⟩ := holds index (by omega)
    refine ⟨z, found, zTerm, ?_⟩
    rw [← peerLog_eq found]
    exact logConst index (by omega)
  · obtain ⟨packet, event, eq, _⟩ := freshHolds index envelope (by omega) delivered
    exact ⟨packet, event, eq⟩

/-- A primary log that stops growing past the agreement gets the agreement
acknowledged, so a quiet peer cannot have reached it. -/
theorem flat_absurd {log : List Entry} {agreed origin : Nat}
    (regime : Regime stable peer log agreed origin) (began : start <= origin)
    (eligible
      : forall index, origin <= index -> peer ∈ eligiblePeers (stable.state index) leader)
    {participants : Finset NodeID}
    (fair : FairLoss trace participants) (leaderIn : leader ∈ participants)
    (peerIn : peer ∈ participants) (productive : Often (trace.ProductiveSend leader peer))
    {floorStart : Nat} (originLe : origin <= floorStart)
    (floor
      : forall index,
          floorStart <= index -> agreed <= (stable.state index).sentIndex peer)
    {reach : Nat} (reachBound : bound <= (stable.state reach).log.length)
    (flat
      : forall index, floorStart <= index -> (stable.state index).log.length <= agreed)
    : False := by
  obtain ⟨stop, late⟩ := horizon execution floorStart
  obtain ⟨index, packet, le, event, source, target, matched⟩ :=
    fair leader peer _ leaderIn peerIn (requests_sent execution stable productive)
      (max stop reach)
  cases payload : packet.envelope.payload with
  | appendEntriesRequest request =>
      obtain ⟨sentLate, before⟩ := late_sent late (show stop <= index by omega) event
      obtain ⟨_, _, _, endLe, outcome⟩ :=
        answer execution stable different regime eligible event (by omega) source target payload
          (floor _ sentLate)
      have := flat packet.sent sentLate
      rcases outcome with ⟨above, _⟩ | ⟨_, sent⟩
      · omega
      · have grows := (stable_prefix execution stable (show reach <= index by omega)).length_le
        have := flat index (by omega)
        exact quiet _ sent (show start <= index by omega) rfl rfl
          (show term <= term /\ true = true /\ bound <= agreed from ⟨le_rfl, rfl, by omega⟩)
  | _ =>
      rw [payload] at matched
      exact matched.elim

end Quiet

/-- A peer of the stable primary keeps acknowledging every position of the
primary's log. -/
theorem acks_sent {joined : Nat}
    (eligible
      : forall index, joined <= index -> peer ∈ eligiblePeers (stable.state index) leader)
    {participants : Finset NodeID} (fair : FairLoss trace participants)
    (leaderIn : leader ∈ participants) (peerIn : peer ∈ participants)
    (productive : Often (trace.ProductiveSend leader peer))
    (termLe
      : forall index state,
          joined <= index
          -> nodeState (trace.state index) peer = some state
          -> state.currentTerm <= term)
    {bound reach : Nat} (reachBound : bound <= (stable.state reach).log.length)
    : InfinitelySent trace peer leader (.response term true bound) := by
  intro cutoff
  by_contra none
  simp only [not_exists, not_and] at none
  have quiet :=
    fun (packet : Packet) (sent : trace.Sent packet) (le : max cutoff joined <= packet.sent) =>
      none packet sent (le_trans (le_max_left _ _) le)
  obtain ⟨log, agreed, origin, began, regime⟩ :=
    settles execution stable different quiet fair leaderIn peerIn productive termLe
  have eligible
      : forall index, origin <= index -> peer ∈ eligiblePeers (stable.state index) leader :=
    fun index le => eligible index (by omega)
  obtain ⟨stop, late⟩ := horizon execution origin
  obtain ⟨floorStart, floorLe, floor⟩ :=
    floor_reached execution stable different regime eligible productive (stop := max stop origin)
      (by omega) (fun _ _ le event => (late_sent late (by omega) event).1)
  by_cases grows : exists grown, forall index, grown <= index
      -> agreed < (stable.state index).log.length
  · obtain ⟨grown, long⟩ := grows
    by_cases sends : InfinitelySent trace leader peer (.replication term (agreed + 1))
    · exact extend_absurd execution stable different regime eligible fair leaderIn peerIn
        (by omega) floor sends
    · obtain ⟨strict, strictLe, above⟩ :=
        floor_strict execution stable different regime eligible productive (by omega) floor
          long
          sends
      exact bucket_absurd execution stable different regime eligible fair leaderIn peerIn
        productive (by omega) above
  · refine flat_absurd execution stable different quiet regime began eligible fair leaderIn peerIn
      productive (by omega) floor reachBound fun index le => ?_
    by_contra long
    refine grows ⟨index, fun later after => ?_⟩
    have := (stable_prefix execution stable after).length_le
    omega

/-- The stable primary's match index for a peer never drops. -/
theorem match_mono {index later : Nat} (le : index <= later)
    : (stable.state index).matchIndex peer <= (stable.state later).matchIndex peer :=
  mono_of_step (f := fun index => (stable.state index).matchIndex peer) (start := 0)
    (fun d _ => by
      rcases (leader_move execution stable peer d (stable.found d) (stable.found (d + 1))).1
          with same | ⟨_, _, _, _, _, _, _, _, value⟩
      · exact same.ge
      · show _ <= (stable.state (d + 1)).matchIndex peer
        rw [value]
        exact le_max_left _ _)
    (Nat.zero_le _) le

/-- The stable primary's match index for a peer eventually covers every position of
its log. -/
theorem match_reaches {joined : Nat}
    (eligible
      : forall index, joined <= index -> peer ∈ eligiblePeers (stable.state index) leader)
    {participants : Finset NodeID} (fair : FairLoss trace participants)
    (leaderIn : leader ∈ participants) (peerIn : peer ∈ participants)
    (productive : Often (trace.ProductiveSend leader peer))
    (termLe
      : forall index state,
          joined <= index
          -> nodeState (trace.state index) peer = some state
          -> state.currentTerm <= term)
    {bound reach : Nat} (reachBound : bound <= (stable.state reach).log.length)
    : exists stop,
        forall index, stop <= index -> bound <= (stable.state index).matchIndex peer := by
  obtain ⟨index, packet, joinedLe, event, source, target, matched⟩ :=
    fair peer leader _ peerIn leaderIn
      (acks_sent execution stable different eligible fair leaderIn peerIn productive termLe
        reachBound) joined
  cases payload : packet.envelope.payload with
  | appendEntriesResponse response =>
      rw [payload] at matched
      obtain ⟨newer, success, covers⟩ := matched
      have value :=
        ack_exact execution stable (show (trace.event index).delivered = some packet.envelope by
            rw [event]; rfl) target payload success newer (stable.found index)
          (stable.found (index + 1)) (by rw [source]; exact eligible index joinedLe)
      rw [source] at value
      refine ⟨index + 1, fun later le => ?_⟩
      have := match_mono execution stable different le
      omega
  | _ =>
      rw [payload] at matched
      exact matched.elim

end Peer

end CCFRaft.Proofs.Replication
