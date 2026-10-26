module

public import CCFRaft.Model
public import CCFRaft.Liveness.Assumptions
public import CCFRaft.Liveness.Model.Policy
public import CCFRaft.Liveness.Seq
public import CCF.Execution

import CCFRaft.Proofs.CommittedLogs
import CCFRaft.Proofs.Direct.CommitFrontier
import CCFRaft.Proofs.Duel.Initial
import CCFRaft.Proofs.Duel.Witness
import CCFRaft.Proofs.Election
import CCFRaft.Proofs.Leadership.AnchorSync
import CCFRaft.Proofs.Leadership.CatchUp
import CCFRaft.Proofs.Leadership.CatchUpWitness
import CCFRaft.Proofs.Leadership.InSync
import CCFRaft.Proofs.Leadership.InitIncumbent
import CCFRaft.Proofs.Leadership.SettlesWitness
import CCFRaft.Proofs.Leadership.Stable
import CCFRaft.Proofs.LivenessWitness
import CCFRaft.Proofs.Replication.Commit
import CCFRaft.Proofs.Timed.Commit
import CCFRaft.Proofs.Witnesses

@[expose] public section

/-!
Safety and liveness theorems about the Raft model, each paired with a witness
lemma exhibiting a nontrivial execution relevant to that property.
-/

namespace CCFRaft.Properties

abbrev GlobalTrace := CCF.Execution.Trace Model.State Model.Action

open Model.Node

/-- Any two committed logs in a valid trace are prefix-comparable: those of
any two nodes, in any two states of the trace. -/
theorem committed_logs_prefix
    : forall (config : Finset NodeID),
      forall (nodes : List NodeID) (trace : GlobalTrace),
      forall (stateA stateB : Model.State),
      forall (left right : NodeID) (leftState rightState : NodeState),
        (trace.Valid (Model.transitionSystem config nodes)
          /\ stateA ∈ trace.states (Model.transitionSystem config nodes)
          /\ stateB ∈ trace.states (Model.transitionSystem config nodes)
          /\ (left, leftState) ∈ stateA.nodes
          /\ (right, rightState) ∈ stateB.nodes)
        -> leftState.committedLog <+: rightState.committedLog
            \/ rightState.committedLog <+: leftState.committedLog := by
  exact Proofs.CommittedLogs.committed_logs_prefix

/-- Witness: a valid trace has two states in which two distinct nodes have
nonempty committed logs. -/
lemma committed_logs_prefix_witness
    : exists (config : Finset NodeID),
    exists (nodes : List NodeID) (trace : GlobalTrace),
    exists (stateA stateB : Model.State),
    exists (left right : NodeID) (leftState rightState : NodeState),
      trace.Valid (Model.transitionSystem config nodes)
      /\ stateA ∈ trace.states (Model.transitionSystem config nodes)
      /\ stateB ∈ trace.states (Model.transitionSystem config nodes)
      /\ (left, leftState) ∈ stateA.nodes
      /\ (right, rightState) ∈ stateB.nodes
      /\ left ≠ right
      /\ leftState.committedLog ≠ []
      /\ rightState.committedLog ≠ [] := by
  exact Proofs.Witnesses.committed_logs_prefix_witness

/-- A successful network step from a state with unique node IDs preserves each
node's committed prefix. -/
theorem single_node_committed_log_monotonic
    : forall (config : Finset NodeID) (nodes : List NodeID),
      forall (pre post : Model.State),
      forall (nodeId : NodeID) (nodePre nodePost : NodeState),
      forall (action : Model.Action),
        ((pre.nodes.map Prod.fst).Nodup
          /\ (Model.transitionSystem config nodes).step pre action = some post
          /\ (nodeId, nodePre) ∈ pre.nodes
          /\ (nodeId, nodePost) ∈ post.nodes)
        -> nodePre.committedLog <+: nodePost.committedLog := by
  exact Proofs.Direct.single_node_committed_log_monotonic

/-- Witness: a successful step from a state with unique node IDs strictly extends
one node's nonempty committed log. -/
lemma single_node_committed_log_monotonic_witness
    : exists (config : Finset NodeID) (nodes : List NodeID),
    exists (pre post : Model.State),
    exists (nodeId : NodeID) (nodePre nodePost : NodeState),
    exists (action : Model.Action),
      (pre.nodes.map Prod.fst).Nodup
      /\ (Model.transitionSystem config nodes).step pre action = some post
      /\ (nodeId, nodePre) ∈ pre.nodes
      /\ (nodeId, nodePost) ∈ post.nodes
      /\ nodePre.committedLog ≠ []
      /\ nodePre.committedLog.length < nodePost.committedLog.length := by
  exact Proofs.Witnesses.single_node_committed_log_monotonic_witness

/-- No two distinct nodes are primary in the same term. -/
theorem election_safety
    : forall (config : Finset NodeID),
      forall (nodes : List NodeID) (trace : GlobalTrace) (state : Model.State),
      forall (left right : NodeID) (leftState rightState : NodeState),
        (trace.Valid (Model.transitionSystem config nodes)
          /\ state ∈ trace.states (Model.transitionSystem config nodes)
          /\ (left, leftState) ∈ state.nodes
          /\ (right, rightState) ∈ state.nodes
          /\ leftState.role = .primary
          /\ rightState.role = .primary
          /\ leftState.currentTerm = rightState.currentTerm)
        -> left = right := by
  exact Proofs.Election.election_safety

/-- Witness: a valid trace has a state in which two nodes are primaries. -/
lemma election_safety_witness
    : exists (config : Finset NodeID),
    exists
    (nodes : List NodeID) (trace : GlobalTrace) (state : Model.State),
    exists (left right : NodeID) (leftState rightState : NodeState),
      trace.Valid (Model.transitionSystem config nodes)
      /\ state ∈ trace.states (Model.transitionSystem config nodes)
      /\ (left, leftState) ∈ state.nodes
      /\ (right, rightState) ∈ state.nodes
      /\ leftState.role = .primary
      /\ rightState.role = .primary
      /\ left ≠ right := by
  exact Proofs.Witnesses.election_safety_witness

/-- Every positive commit index points to a signature entry. -/
theorem committed_frontier_is_signature
    : forall (config : Finset NodeID),
      forall (nodes : List NodeID) (trace : GlobalTrace) (state : Model.State),
      forall (node : NodeID) (nodeState : NodeState),
        (trace.Valid (Model.transitionSystem config nodes)
          /\ state ∈ trace.states (Model.transitionSystem config nodes)
          /\ (node, nodeState) ∈ state.nodes
          /\ 0 < nodeState.commitIndex)
        -> isSignatureAt nodeState.log nodeState.commitIndex = true := by
  exact Proofs.Direct.committed_frontier_is_signature

/-- Witness: a valid trace has a state with a positive commit index. -/
lemma committed_frontier_is_signature_witness
    : exists (config : Finset NodeID),
    exists
    (nodes : List NodeID) (trace : GlobalTrace) (state : Model.State),
    exists (node : NodeID) (nodeState : NodeState),
      trace.Valid (Model.transitionSystem config nodes)
      /\ state ∈ trace.states (Model.transitionSystem config nodes)
      /\ (node, nodeState) ∈ state.nodes
      /\ 0 < nodeState.commitIndex := by
  exact Proofs.Witnesses.committed_frontier_is_signature_witness

/-- Commit liveness, timed. For any timing bounds, maximum delay and backlog there
is a nonnegative window length `duration`, independent of the trace, with the
following property. Take one coherent recorded relational trace. Assume
coherence and validity of the protocol, timing, crash, delivery (in order on each
channel) and bounded-delay models for `system := Model.transitionSystem config
nodes`, and an unbounded
clock: every packet is then delivered or dropped within `maxDelay`, unless its
target crashes first. Assume that a primary sends due heartbeats
within `bounds.heartbeatInterval` and due signatures within
`bounds.signatureInterval`. Take a stable window from index `start` for
`duration`: `leader` is the uncontested primary of `term`, stays live and
unretired, every configuration active at it keeps a live majority among
`participants`, and no packet between it and a participant is dropped.
Additionally, reconfiguration is settled at the leader throughout the
window: one active configuration and all completed removals confirmed in its
committed ledger. Followers need not have learned this completion. This
excludes waiting for retirement cleanup, which has no scheduling deadline.
If at `start` every participant has adopted `term`, the primary's log beyond its
common prefix with each participant spans at most `backlog` distinct terms, and
the primary holds or appends `request`, then `request` is in the primary's committed prefix within
the window. `commit_liveness_witness` meets the premises for every nonnegative
window length, so they are satisfiable whatever `duration` is.
`signature_settles` and `signature_settles_catchup` yield the stable window;
settled reconfiguration remains a separate premise. -/
theorem commit_liveness
    : forall (config : Finset NodeID) (nodes : List NodeID),
        let system := Model.transitionSystem config nodes
        forall (bounds : Liveness.Bounds) (maxDelay : Real) (backlog : Nat),
          exists duration : Real,
            0 <= duration
            /\ forall (W : Type) [Liveness.HasProtocol W Model.State] [Liveness.HasTime W]
                      [Liveness.HasLive W] [Liveness.HasNetwork W],
                forall (trace : Liveness.Trace W Liveness.Event) (start : Nat),
                forall (leader : NodeID) (term : Nat) (participants : Finset NodeID)
                        (request : ReqID),
                  (trace.Coherent
                    /\ trace.Valid (Liveness.protocolModel system)
                    /\ trace.Valid Liveness.timingModel
                    /\ trace.Valid Liveness.crashModel
                    /\ trace.Valid (Liveness.deliveryModel system)
                    /\ trace.Valid (Liveness.boundedDelayModel maxDelay)
                    /\ Liveness.TimeDiverges trace
                    /\ 0 <= maxDelay
                    /\ trace.HeartbeatScheduling (some bounds.heartbeatInterval)
                    /\ trace.SignatureScheduling (some bounds.signatureInterval)
                    /\ Liveness.StableWindow trace start duration leader term participants
                    /\ Liveness.Window.ReconfigurationSettled trace start duration leader
                    /\ Liveness.BacklogTerms trace start leader participants backlog
                    /\ Liveness.InTermAt trace start term participants
                    /\ Liveness.SubmittedAt trace start leader request)
                  -> exists index,
                      Liveness.Within trace start duration index
                      /\ Liveness.RequestCommitted trace leader request index := by
  exact Proofs.Timed.commit_liveness_timed

/-- Witness: for every nonnegative window length, a one-node execution with
positive heartbeat and signature bounds meets every premise of `commit_liveness`
and commits its request within the window. -/
lemma commit_liveness_witness
    : let system := Model.transitionSystem {0} [0]
      let bounds : Liveness.Bounds :=
        { heartbeatInterval := 1 / 4, electionTimeout := 4, signatureInterval := 1 / 4 }
      forall duration : Real,
        0 <= duration
        -> exists trace : Liveness.Trace (Liveness.World Model.State) Liveness.Event,
            (trace.Coherent
              /\ trace.Valid (Liveness.protocolModel system)
              /\ trace.Valid Liveness.timingModel
              /\ trace.Valid Liveness.crashModel
              /\ trace.Valid (Liveness.deliveryModel system)
              /\ trace.Valid (Liveness.boundedDelayModel 0)
              /\ Liveness.TimeDiverges trace
              /\ 0 <= (0 : Real)
              /\ trace.HeartbeatScheduling (some bounds.heartbeatInterval)
              /\ trace.SignatureScheduling (some bounds.signatureInterval)
              /\ Liveness.StableWindow trace 0 duration 0 Model.BOOTSTRAP_TERM {0}
              /\ Liveness.Window.ReconfigurationSettled trace 0 duration 0
              /\ Liveness.BacklogTerms trace 0 0 {0} 0
              /\ Liveness.InTermAt trace 0 Model.BOOTSTRAP_TERM {0}
              /\ Liveness.SubmittedAt trace 0 0 10)
            /\ exists index,
                Liveness.Within trace 0 duration index
                /\ Liveness.RequestCommitted trace 0 10 index := by
  exact Proofs.LivenessWitness.timed_commit_window_witness

/-- Duelling leaders resolve: from a good period, the probability that no primary
anchors its term in time decays geometrically in the number of rounds.

The randomness is the election-timeout draw. `Liveness.run participants policy
sample` is the execution a scheduler `policy` produces against `sample`, a stream
of offsets: each election-timer reset of a participant takes the next offset and
sets the node's deadline that far after the reset. The scheduler chooses
everything else, including deliveries, drops, crashes, requests and the timers of
non-participants. It sees past deadlines but not future offsets, and its steps
depend measurably on the sample (`Liveness.Borel`). The offsets are independent
draws from `law`, a probability law on `[E / 2, E]`, `E = bounds.electionTimeout`,
that puts at most `rho` on any interval of radius `4 * maxDelay`
(`Liveness.Law`). CCF's discrete draw meets it with
`rho = (8 * maxDelay + 1) / (E / 2 + 1)`.

Assume, for every sample in the support, that the run is coherent, that the
protocol, timing, crash, delivery, bounded-delay and timer models hold, that time
diverges, and that a primary sends due heartbeats within
`bounds.heartbeatInterval`. A participant whose deadline has passed times out
before time advances, and in the window the clock passes a participant's pending
deadline at no more than `overshoots` steps, each time by at most `jump`. Take a
good period from `start` for `duration` among `participants`, in which the logs
match where AppendEntries are delivered between participants and no
participant's retirement commits. At `start` the participants count votes only
in configurations with nodes `members`, each has a committed configuration, and
each has a role (`Liveness.HasRole`). Then the probability that no primary
anchors its term among `participants` by `start + duration`
(`Liveness.HandoffBy`), with `fresh` left on every anchor timer, is at most
`(overshoots + 1) * (2 n (n - 1) rho) ^ rounds`, `n` the number of participants.
Within `initial` of `start` a primary anchors its term or a round starts, and a
round of `E + 4 * maxDelay` ends the duel unless the draws of its competitors fall
within `4 * maxDelay` of each other. `signature_settles` then keeps the primary for
the rest of the good period when `bounds.heartbeatInterval + maxDelay < fresh`.
Each premise is needed; `LIVENESS.md` gives the counterexamples. -/
theorem duelling_leaders_resolve
    : forall (config : Finset NodeID) (nodes : List NodeID),
        let system := Model.transitionSystem config nodes
        forall (policy : Liveness.Policy) (law : MeasureTheory.Measure Real),
        forall (bounds : Liveness.Bounds) (maxDelay jump rho fresh : Real),
        forall (overshoots rounds start : Nat) (participants members : Finset NodeID),
          let electionTimeout := bounds.electionTimeout
          let heartbeat := bounds.heartbeatInterval
          let handover := 2 * (heartbeat + maxDelay) + maxDelay
          let initial := 3 * electionTimeout + 3 * jump + 5 * maxDelay + handover
          let duration :=
            initial
            + (overshoots + 1) * rounds * (electionTimeout + 4 * maxDelay)
            + (overshoots + 1) * jump
            + 4 * maxDelay
          (Liveness.Law electionTimeout (4 * maxDelay) rho law
            /\ Liveness.Borel participants policy
            /\ 0 <= maxDelay
            /\ 0 <= jump
            /\ 0 <= heartbeat
            /\ 4 * maxDelay < electionTimeout / 2
            /\ handover < electionTimeout / 2
            /\ fresh <= electionTimeout / 2 - 4 * maxDelay
            /\ fresh <= electionTimeout / 2 - handover
            /\ participants ⊆ members
            /\ participants.Nonempty
            /\ (forall node, node ∈ participants -> node ∈ nodes)
            /\ forall sample : Liveness.Sample,
                (forall j, sample j ∈ Set.Icc (electionTimeout / 2) electionTimeout)
                -> let trace := Liveness.run participants policy sample
                  trace.Coherent
                  /\ trace.Valid (Liveness.protocolModel system)
                  /\ trace.Valid Liveness.timingModel
                  /\ trace.Valid Liveness.crashModel
                  /\ trace.Valid (Liveness.deliveryModel system)
                  /\ trace.Valid (Liveness.boundedDelayModel maxDelay)
                  /\ trace.Valid (Liveness.timerModel electionTimeout)
                  /\ Liveness.TimeDiverges trace
                  /\ trace.HeartbeatScheduling (some heartbeat)
                  /\ (forall node,
                      node ∈ participants
                      -> Liveness.Scheduled trace (some 0)
                          (fun point => Liveness.TimeoutDue point node)
                          (fun step => step.action = .local node (.timeout .election)))
                  /\ (exists bad : Finset Nat,
                      bad.card <= overshoots
                      /\ forall index step node,
                          node ∈ participants
                          -> Liveness.Within trace start duration index
                          -> trace.stepAt index = some step
                          -> Liveness.NoOvershoot (some (if index ∈ bad then jump else 0))
                              step node)
                  /\ Liveness.GoodPeriod trace start duration participants
                  /\ Liveness.Window.Matching trace start duration participants
                  /\ Liveness.Window.AnchorActive trace start duration participants
                  /\ forall point,
                      trace.stateAt start = some point
                      -> Liveness.Membership participants members
                          (Liveness.HasProtocol.proto point)
                        /\ Liveness.ConfigurationCommitted participants
                          (Liveness.HasProtocol.proto point)
                        /\ Liveness.HasRole participants (Liveness.HasProtocol.proto point))
          -> MeasureTheory.Measure.infinitePi (fun _ => law)
              {sample |
                Not
                  (Liveness.HandoffBy (Liveness.run participants policy sample) participants
                    start duration fresh)
              }
            <= ENNReal.ofReal
                ((overshoots + 1)
                  * Liveness.roundFailure rho (participants.card - 1)
                      (2 * participants.card) ^ rounds) := by
  intro config nodes system policy law bounds maxDelay jump rho fresh overshoots rounds start
    participants members electionTimeout heartbeat handover initial duration
    ⟨isLaw, borel, nonnegative, jumpNonnegative, heartbeatNonnegative, ratio, handoverRatio,
      freshLe, freshHandover, subset, nonempty, present, runs⟩
  let _ : Proofs.Config.InitialConfiguration := ⟨config⟩
  exact Proofs.Duel.Resolve.duelling_leaders_resolve (nodes := nodes) (initial := initial)
    (overshoots := overshoots) isLaw borel freshLe fun sample support => by
      obtain ⟨coherent, protocol, timing, crash, delivery, delay, timers, diverges, heartbeats,
        firing, overshoot, period, matching, active, atStart⟩ := runs sample support
      have admissible : Proofs.Liveness.Admissible system (Liveness.run participants policy sample) :=
        ⟨coherent, protocol, timing, crash, delivery⟩
      have membership := fun point found => (atStart point found).1
      have configured := fun point found => (atStart point found).2.1
      have roled
          : forall first node state,
              (Liveness.run participants policy sample).stateAt start = some first
              -> node ∈ participants
              -> CCF.MultiNodeTransitionSystem.nodeState (Liveness.HasProtocol.proto first) node
                  = some state
              -> Not (state.role = .none) :=
        fun first node state found member located =>
          (atStart first found).2.2 node state (Proofs.Witnesses.mem_of_nodeState located) member
      have long := Proofs.Duel.Resolve.initial_le_window (initial := initial)
        (overshoots := overshoots) (rounds := rounds) nonnegative jumpNonnegative ratio
      exact Proofs.Duel.Resolve.setup_of_init admissible delay timers diverges firing overshoot
        nonnegative jumpNonnegative ratio long (by positivity) period matching active
        membership subset configured roled nonempty present
        (Proofs.Leadership.init_incumbent admissible delay timers diverges heartbeats
          nonnegative heartbeatNonnegative handoverRatio freshHandover long period active
          matching membership subset roled)

open Proofs.Duel.Witness in
/-- Witness: for any number of rounds, a one-node service whose node is primary
throughout meets every premise of `duelling_leaders_resolve` from index one, with
election timeout 4, heartbeat interval 1/2, no delay, jump or overshoots, the
uniform law on `[2, 4]` and freshness 1, and every run hands off. The run resets
no timer, so it exercises the premises, not the rounds. -/
lemma duelling_leaders_resolve_witness
    : let system := Model.transitionSystem {0} [0]
      let bounds : Liveness.Bounds :=
        { heartbeatInterval := 1 / 2, electionTimeout := 4, signatureInterval := 1 }
      forall rounds : Nat,
        let electionTimeout := bounds.electionTimeout
        let heartbeat := bounds.heartbeatInterval
        let handover := 2 * (heartbeat + 0) + 0
        let initial := 3 * electionTimeout + 3 * 0 + 5 * 0 + handover
        let duration :=
          initial + (0 + 1) * rounds * (electionTimeout + 4 * 0) + (0 + 1) * 0 + 4 * 0
        exists (policy : Liveness.Policy) (law : MeasureTheory.Measure Real),
          (Liveness.Law electionTimeout (4 * 0) 0 law
            /\ Liveness.Borel {0} policy
            /\ 0 <= (0 : Real)
            /\ 0 <= (0 : Real)
            /\ 0 <= heartbeat
            /\ 4 * 0 < electionTimeout / 2
            /\ handover < electionTimeout / 2
            /\ 1 <= electionTimeout / 2 - 4 * 0
            /\ 1 <= electionTimeout / 2 - handover
            /\ ({0} : Finset NodeID) ⊆ {0}
            /\ ({0} : Finset NodeID).Nonempty
            /\ (forall node, node ∈ ({0} : Finset NodeID) -> node ∈ [0])
            /\ forall sample : Liveness.Sample,
                (forall j, sample j ∈ Set.Icc (electionTimeout / 2) electionTimeout)
                -> let trace := Liveness.run {0} policy sample
                  trace.Coherent
                  /\ trace.Valid (Liveness.protocolModel system)
                  /\ trace.Valid Liveness.timingModel
                  /\ trace.Valid Liveness.crashModel
                  /\ trace.Valid (Liveness.deliveryModel system)
                  /\ trace.Valid (Liveness.boundedDelayModel 0)
                  /\ trace.Valid (Liveness.timerModel electionTimeout)
                  /\ Liveness.TimeDiverges trace
                  /\ trace.HeartbeatScheduling (some heartbeat)
                  /\ (forall node,
                      node ∈ ({0} : Finset NodeID)
                      -> Liveness.Scheduled trace (some 0)
                          (fun point => Liveness.TimeoutDue point node)
                          (fun step => step.action = .local node (.timeout .election)))
                  /\ (exists bad : Finset Nat,
                      bad.card <= 0
                      /\ forall index step node,
                          node ∈ ({0} : Finset NodeID)
                          -> Liveness.Within trace 1 duration index
                          -> trace.stepAt index = some step
                          -> Liveness.NoOvershoot (some (if index ∈ bad then 0 else 0))
                              step node)
                  /\ Liveness.GoodPeriod trace 1 duration {0}
                  /\ Liveness.Window.Matching trace 1 duration {0}
                  /\ Liveness.Window.AnchorActive trace 1 duration {0}
                  /\ forall point,
                      trace.stateAt 1 = some point
                      -> Liveness.Membership {0} {0} (Liveness.HasProtocol.proto point)
                        /\ Liveness.ConfigurationCommitted {0} (Liveness.HasProtocol.proto point)
                        /\ Liveness.HasRole {0} (Liveness.HasProtocol.proto point))
          /\ forall sample : Liveness.Sample,
              Liveness.HandoffBy (Liveness.run {0} policy sample) {0} 1 duration 1 := by
  intro system bounds rounds electionTimeout heartbeat handover initial duration
  have durationNonnegative : 0 <= duration := by
    simp only [duration, initial, handover, heartbeat, electionTimeout, bounds]
    positivity
  refine ⟨policy, law, ⟨law_valid, borel, le_rfl, le_rfl, by norm_num [heartbeat, bounds],
    by norm_num [electionTimeout, bounds], by norm_num [handover, heartbeat, electionTimeout, bounds],
    by norm_num [electionTimeout, bounds], by norm_num [handover, heartbeat, electionTimeout, bounds],
    subset_refl _, Finset.singleton_nonempty 0, by simp, fun sample _ => ?_⟩,
    fun sample => handoff_one sample 1 duration durationNonnegative⟩
  intro trace
  obtain ⟨coherent, protocol, timing, crash, delivery⟩ := admissible_unfolded sample
  exact ⟨coherent, protocol, timing, crash, delivery, bounded_delay sample, timers sample,
    diverges sample, heartbeats sample heartbeat, firing sample,
    overshoot sample 1 duration 0 0, good_period sample 1 duration, matching sample 1 duration,
    anchor_active sample 1 duration,
    fun point found => ⟨membership_one sample point found, configured_one sample point found,
      has_role sample 1 point found⟩⟩

/-- A fresh primary stays uncontested while the good period lasts, when a quorum
of participants, the anchor, knows it and is in sync with it: the bridge from
`duelling_leaders_resolve` to the window `commit_liveness` consumes, in the common
case. At `start` the term is quiet among `participants`, and `anchor` anchors it
(`Liveness.AnchoredStart`): a quorum of the primary's configurations, containing
the primary, whose nodes are at the term, know the primary and are its
replication peers, with none of their pre-votes of the term in flight or counted.
Every majority of every configuration participants can count votes in meets the
anchor, and no anchor node of the term times out for `fresh`. Every anchor node
is in sync with the primary: its log is a prefix of the primary's, no rejection
from it is in flight, and the primary's requests in flight to it chain from the
end of its log. No anchor node's retirement commits in the window. Then every
heartbeat passes every anchor node's log check, so each anchor node's election
timer is reset within `heartbeatInterval + maxDelay`, before `fresh` runs out,
and none times out in the window. A node that knows the primary grants no
pre-vote, so no participant, lagging or not, gathers a pre-vote quorum and moves
past the term. The result is a stable window over the anchor, which
`commit_liveness` takes with the anchor as its participants, with the term quiet
among all participants. Each premise is needed; `LIVENESS.md` gives the
counterexamples. `signature_settles_catchup` drops the sync premise for a larger
`fresh`. -/
theorem signature_settles
    : forall (config : Finset NodeID) (nodes : List NodeID),
        let system := Model.transitionSystem config nodes
        forall (W : Type) [Liveness.HasProtocol W Model.State] [Liveness.HasTime W]
                [Liveness.HasLive W] [Liveness.HasNetwork W] [Liveness.HasTimers W],
        forall (trace : Liveness.Trace W Liveness.Event) (bounds : Liveness.Bounds),
        forall (maxDelay fresh duration : Real) (start : Nat),
        forall (leader : NodeID) (term : Nat) (participants anchor : Finset NodeID),
          (trace.Coherent
            /\ trace.Valid (Liveness.protocolModel system)
            /\ trace.Valid Liveness.timingModel
            /\ trace.Valid Liveness.crashModel
            /\ trace.Valid (Liveness.deliveryModel system)
            /\ trace.Valid (Liveness.boundedDelayModel maxDelay)
            /\ trace.Valid (Liveness.timerModel bounds.electionTimeout)
            /\ 0 <= maxDelay
            /\ trace.HeartbeatScheduling (some bounds.heartbeatInterval)
            /\ bounds.heartbeatInterval + maxDelay < fresh
            /\ fresh <= bounds.electionTimeout / 2
            /\ Liveness.AnchoredStart trace start leader term participants anchor fresh
            /\ Liveness.InSync trace start leader term anchor
            /\ Liveness.GoodPeriod trace start duration participants
            /\ Liveness.Window.AnchorActive trace start duration anchor)
          -> Liveness.StableWindow trace start duration leader term anchor
              /\ Liveness.Window.StableTerm trace start duration leader term
                  participants := by
  intro config nodes system W _ _ _ _ _ trace bounds maxDelay fresh duration start leader term
    participants anchor ⟨coherent, protocol, timing, crash, delivery, bounded, timers, nonneg,
      heartbeats, ratio, freshLe, initial, sync, good, active⟩
  let _ : Proofs.Config.InitialConfiguration := ⟨config⟩
  exact Proofs.Leadership.stable_window_anchored (nodes := nodes)
    ⟨coherent, protocol, timing, crash, delivery⟩ timers bounded nonneg heartbeats ratio
    freshLe initial good active sync

/-- Witness: for every nonnegative window length, a one-node execution with
heartbeat interval 1, election timeout 4 and freshness 2, whose node is both the
participants and the anchor, meets every premise of `signature_settles` and has
its conclusion. It resets no timer and times out no node, so every election
deadline stays at 0. -/
lemma signature_settles_witness
    : let system := Model.transitionSystem {0} [0]
      let bounds : Liveness.Bounds :=
        { heartbeatInterval := 1, electionTimeout := 4, signatureInterval := 1 }
      letI : Liveness.HasTimers (Liveness.World Model.State) := ⟨fun _ _ => 0⟩
      forall duration : Real,
        0 <= duration
        -> exists trace : Liveness.Trace (Liveness.World Model.State) Liveness.Event,
            (trace.Coherent
              /\ trace.Valid (Liveness.protocolModel system)
              /\ trace.Valid Liveness.timingModel
              /\ trace.Valid Liveness.crashModel
              /\ trace.Valid (Liveness.deliveryModel system)
              /\ trace.Valid (Liveness.boundedDelayModel 0)
              /\ trace.Valid (Liveness.timerModel bounds.electionTimeout)
              /\ 0 <= (0 : Real)
              /\ trace.HeartbeatScheduling (some bounds.heartbeatInterval)
              /\ bounds.heartbeatInterval + 0 < 2
              /\ 2 <= bounds.electionTimeout / 2
              /\ Liveness.AnchoredStart trace 0 0 Model.BOOTSTRAP_TERM {0} {0} 2
              /\ Liveness.InSync trace 0 0 Model.BOOTSTRAP_TERM {0}
              /\ Liveness.GoodPeriod trace 0 duration {0}
              /\ Liveness.Window.AnchorActive trace 0 duration {0})
            /\ Liveness.StableWindow trace 0 duration 0 Model.BOOTSTRAP_TERM {0}
            /\ Liveness.Window.StableTerm trace 0 duration 0 Model.BOOTSTRAP_TERM
                {0} := by
  intro system bounds duration nonneg
  obtain ⟨trace, ⟨admissible, timers, bounded, delay, heartbeats, ratio, freshLe, anchored,
      good, active, sync⟩, stable, quiet⟩ :=
    Proofs.Leadership.stable_window_anchored_witness duration nonneg
  exact ⟨trace, ⟨admissible.coherent, admissible.protocol, admissible.timing,
    admissible.crash, admissible.delivery, bounded, timers, delay, heartbeats, ratio, freshLe,
    anchored, sync, good, active⟩, stable, quiet⟩

/-- `signature_settles` while the anchor catches up: at `start` the anchor anchors
the term as in `signature_settles`, and the primary's log beyond its common prefix
with each anchor node spans at most `backlog` distinct terms, with no premise on
the messages in flight. An anchor node's election timer is reset only by an
AppendEntries that passes its log check, so a lagging anchor node is reset only
once the primary has repaired its log. From any point, the primary's next
heartbeat goes out within `interval`, the heartbeat interval if positive, and
reaches every anchor node within `maxDelay`; the repair it starts is acknowledged
within `6 maxDelay + 4 interval + 2 (backlog + 1) (2 maxDelay + interval)`, the
round bound of `commit_liveness`. So with `fresh` above their sum no anchor node
times out in the window, and, as in `signature_settles`, no participant moves past
the term. Each premise is needed; `LIVENESS.md` gives the counterexamples,
including one with `fresh` at `2 interval + 3 maxDelay`.

Reading the ratio: `fresh` is how long after `start` no anchor node times out, at
most half an election timeout. In that time the primary must repair every lagging
anchor node and get an acknowledgement back, or the node times out and starts an
election. Each rejection moves the primary's probe back past a whole term of its
log (the retry hint), so a node whose unagreed suffix spans `backlog` terms is
repaired within two round trips per term, plus two for the primary's own new
entries. Each round trip costs at most `2 maxDelay + interval`. A fixed overhead
of `7 maxDelay + 5 interval`, for stale traffic to drain and the next heartbeat to
go out and arrive, gives the left-hand side, so the premise just says repair time
< `fresh`. The in-sync bridge `signature_settles` needs only one heartbeat round:
`interval + maxDelay < fresh`. The constants are worst-case sums along the proof,
not tight. -/
theorem signature_settles_catchup
    : forall (config : Finset NodeID) (nodes : List NodeID),
        let system := Model.transitionSystem config nodes
        forall (W : Type) [Liveness.HasProtocol W Model.State] [Liveness.HasTime W]
                [Liveness.HasLive W] [Liveness.HasNetwork W] [Liveness.HasTimers W],
        forall (trace : Liveness.Trace W Liveness.Event) (bounds : Liveness.Bounds),
        forall (maxDelay fresh duration : Real) (backlog start : Nat),
        forall (leader : NodeID) (term : Nat) (participants anchor : Finset NodeID),
          let interval := max bounds.heartbeatInterval 0
          (trace.Coherent
            /\ trace.Valid (Liveness.protocolModel system)
            /\ trace.Valid Liveness.timingModel
            /\ trace.Valid Liveness.crashModel
            /\ trace.Valid (Liveness.deliveryModel system)
            /\ trace.Valid (Liveness.boundedDelayModel maxDelay)
            /\ trace.Valid (Liveness.timerModel bounds.electionTimeout)
            /\ Liveness.TimeDiverges trace
            /\ 0 <= maxDelay
            /\ trace.HeartbeatScheduling (some bounds.heartbeatInterval)
            /\ 6 * maxDelay
                  + 4 * interval
                  + 2 * ((backlog : Real) + 1) * (2 * maxDelay + interval)
                  + interval
                  + maxDelay
                < fresh
            /\ fresh <= bounds.electionTimeout / 2
            /\ Liveness.AnchoredStart trace start leader term participants anchor fresh
            /\ Liveness.BacklogTerms trace start leader anchor backlog
            /\ Liveness.GoodPeriod trace start duration participants
            /\ Liveness.Window.AnchorActive trace start duration anchor)
          -> Liveness.StableWindow trace start duration leader term anchor
              /\ Liveness.Window.StableTerm trace start duration leader term
                  participants := by
  intro config nodes system W _ _ _ _ _ trace bounds maxDelay fresh duration backlog start leader
    term participants anchor interval ⟨coherent, protocol, timing, crash, delivery, bounded,
      timers, diverges, nonneg, heartbeats, ratio, freshLe, initial, behind, good, active⟩
  let _ : Proofs.Config.InitialConfiguration := ⟨config⟩
  exact Proofs.Leadership.stable_window_catchup_anchored (nodes := nodes)
    ⟨coherent, protocol, timing, crash, delivery⟩ timers bounded diverges nonneg heartbeats
    ratio freshLe initial good active behind

/-- Witness: for every nonnegative window length, a one-node execution with
heartbeat interval `1 / 10`, election timeout 4, freshness 2 and backlog 0, whose
node is both the participants and the anchor, meets every premise of
`signature_settles_catchup` and has its conclusion. It resets no timer and times
out no node, so every election deadline stays at 0. -/
lemma signature_settles_catchup_witness
    : let system := Model.transitionSystem {0} [0]
      let bounds : Liveness.Bounds :=
        { heartbeatInterval := 1 / 10, electionTimeout := 4, signatureInterval := 1 }
      let interval := max bounds.heartbeatInterval 0
      letI : Liveness.HasTimers (Liveness.World Model.State) := ⟨fun _ _ => 0⟩
      forall duration : Real,
        0 <= duration
        -> exists trace : Liveness.Trace (Liveness.World Model.State) Liveness.Event,
            (trace.Coherent
              /\ trace.Valid (Liveness.protocolModel system)
              /\ trace.Valid Liveness.timingModel
              /\ trace.Valid Liveness.crashModel
              /\ trace.Valid (Liveness.deliveryModel system)
              /\ trace.Valid (Liveness.boundedDelayModel 0)
              /\ trace.Valid (Liveness.timerModel bounds.electionTimeout)
              /\ Liveness.TimeDiverges trace
              /\ 0 <= (0 : Real)
              /\ trace.HeartbeatScheduling (some bounds.heartbeatInterval)
              /\ 6 * 0
                    + 4 * interval
                    + 2 * (((0 : Nat) : Real) + 1) * (2 * 0 + interval)
                    + interval
                    + 0
                  < 2
              /\ 2 <= bounds.electionTimeout / 2
              /\ Liveness.AnchoredStart trace 0 0 Model.BOOTSTRAP_TERM {0} {0} 2
              /\ Liveness.BacklogTerms trace 0 0 {0} 0
              /\ Liveness.GoodPeriod trace 0 duration {0}
              /\ Liveness.Window.AnchorActive trace 0 duration {0})
            /\ Liveness.StableWindow trace 0 duration 0 Model.BOOTSTRAP_TERM {0}
            /\ Liveness.Window.StableTerm trace 0 duration 0 Model.BOOTSTRAP_TERM
                {0} := by
  intro system bounds interval duration nonneg
  obtain ⟨trace, ⟨admissible, timers, bounded, diverges, delay, heartbeats, ratio, freshLe,
      anchored, good, active, behind⟩, stable, quiet⟩ :=
    Proofs.Leadership.CatchUpWitness.stable_window_catchup_anchored_witness duration nonneg
  exact ⟨trace, ⟨admissible.coherent, admissible.protocol, admissible.timing,
    admissible.crash, admissible.delivery, bounded, timers, diverges, delay, heartbeats, ratio,
    freshLe, anchored, behind, good, active⟩, stable, quiet⟩

end CCFRaft.Properties
