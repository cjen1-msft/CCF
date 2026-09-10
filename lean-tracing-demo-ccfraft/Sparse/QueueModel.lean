import Sparse.Queue

set_option autoImplicit false

/-!
Actual Model congruence for all 17 action constructors.

Related retains the complete NodeStore and every other non-network State field.
Only cross-source queue interleaving is forgotten. There are no entry-state,
destination-consistency, distinct-endpoint, capacity, or active-node assumptions.

The receive proof branches on actual handlers and their generated responses.
It includes nonconsuming stepdown, unallocated response sources, malformed
destinations, and exact-packet deduplication after dequeue. updateTerm uses
newerMessage? without adding the receive destination guard.

This is a semantic proof, not a sparse runtime representation or SMT encoder.
-/

namespace CCFRaft.Sparse.QueueModel

open Sparse.Queue

variable {N T : Type} [DecidableEq N]

def frame (state : State N T) : State N T :=
  { state with network := fun _ => [] }

def observe (state : State N T) : Prod (State N T) (Sparse N T) :=
  (frame state, abstractNetwork state.network)

def Related (left right : State N T) : Prop :=
  observe left = observe right

theorem related_network {left right : State N T} (h : Related left right) :
    abstractNetwork left.network = abstractNetwork right.network :=
  congrArg Prod.snd h

theorem related_frame {left right : State N T} (h : Related left right) :
    frame left = frame right :=
  congrArg Prod.fst h

theorem related_reconstruct {left right : State N T} (h : Related left right) :
    right = { left with network := right.network } := by
  have hf := congrArg (fun state : State N T => { state with network := right.network })
    (related_frame h)
  exact hf.symm

theorem related_nodes {left right : State N T} (h : Related left right) :
    left.nodes = right.nodes := by
  have hn := congrArg (fun state : State N T => state.nodes) (related_frame h)
  exact hn

theorem related_allocated {left right : State N T} (h : Related left right) (node : N) :
    left.allocated node <-> right.allocated node := by
  simp only [State.allocated, related_nodes h]

theorem take_coupled (left right : Network N T) (source destination : N)
    (h : abstractNetwork left = abstractNetwork right)
    (m : Message N T) (rest : List (Message N T))
    (selected : takeFirstFrom source (left destination) = some (m, rest)) :
    exists rest', takeFirstFrom source (right destination) = some (m, rest') /\
      abstractNetwork (updateQueue left destination rest) =
        abstractNetwork (updateQueue right destination rest') := by
  have hp : partition source (right destination) = m :: partition source rest :=
    (congrFun (congrFun h destination) source).symm.trans
      (take_some_spec source (left destination) m rest selected).2.1
  cases take_enabled source (right destination) m (partition source rest) hp with
  | intro rest' hr =>
    refine Exists.intro rest' (And.intro hr.1 ?_)
    rw [dequeue_correct left destination source m rest selected,
      dequeue_correct right destination source m rest' hr.1, h, hr.2.1]

theorem take_none_coupled (left right : Network N T) (source destination : N)
    (h : abstractNetwork left = abstractNetwork right)
    (selected : takeFirstFrom source (left destination) = none) :
    takeFirstFrom source (right destination) = none := by
  apply (take_none_iff source (right destination)).mpr
  exact (congrFun (congrFun h destination) source).symm.trans
    ((take_none_iff source (left destination)).mp selected)

theorem newerMessage_replace (state : State N T) (network : Network N T)
    (h : abstractNetwork state.network = abstractNetwork network)
    (source destination : N) :
    newerMessage? state source destination =
      newerMessage? { state with network := network } source destination := by
  cases ht : takeFirstFrom source (state.network destination) with
  | none =>
    have ht' := take_none_coupled state.network network source destination h ht
    simp [newerMessage?, ht, ht']
  | some pair =>
    cases pair with
    | mk m rest =>
      cases take_coupled state.network network source destination h m rest ht with
      | intro rest' hr =>
        simp only [newerMessage?, ht, hr.1]
        rfl

variable [DecidableEq T] [Bootstrap N]

theorem receive_replace (state : State N T) (network : Network N T)
    (h : abstractNetwork state.network = abstractNetwork network)
    (source destination : N) :
    (handleReceive? state source destination).map observe =
      (handleReceive? { state with network := network } source destination).map observe := by
  cases ht : takeFirstFrom source (state.network destination) with
  | none =>
    have ht' := take_none_coupled state.network network source destination h ht
    simp [handleReceive?, ht, ht']
  | some pair =>
    cases pair with
    | mk m rest =>
      cases take_coupled state.network network source destination h m rest ht with
      | intro rest' hr =>
        have propose (request : ProposeVoteRequest N) :
            handleProposeVoteRequest? { state with network := network } destination request =
              handleProposeVoteRequest? state destination request := by
          rfl
        simp only [handleReceive?, ht, hr.1]
        split
        next => rfl
        next =>
          cases m <;> simp only [State.allocated, propose]
          all_goals
            repeat' (split <;> simp_all [observe, frame, reply, enqueue_correct])

theorem receive_congr {left right : State N T} (h : Related left right)
    (source destination : N) :
    (handleReceive? left source destination).map observe =
      (handleReceive? right source destination).map observe := by
  have hr := receive_replace left right.network (related_network h) source destination
  rw [<- related_reconstruct h] at hr
  exact hr

omit [DecidableEq T] [Bootstrap N] in
theorem newerMessage_congr {left right : State N T} (h : Related left right)
    (source destination : N) :
    newerMessage? left source destination = newerMessage? right source destination := by
  have hr := newerMessage_replace left right.network (related_network h) source destination
  rw [<- related_reconstruct h] at hr
  exact hr

theorem enabled_replace (state : State N T) (network : Network N T)
    (h : abstractNetwork state.network = abstractNetwork network)
    (action : Action N T) :
    Enabled state action <-> Enabled { state with network := network } action := by
  cases action <;> try rfl
  case receive source destination =>
    have hs := congrArg Option.isSome (receive_replace state network h source destination)
    simp only [Option.isSome_map] at hs
    simp only [Enabled, hs]
    rfl
  case updateTerm source destination =>
    simp only [Enabled, newerMessage_replace state network h source destination]
    rfl

theorem enabled_congr {left right : State N T} (h : Related left right)
    (action : Action N T) :
    Enabled left action <-> Enabled right action := by
  have hr := enabled_replace left right.network (related_network h) action
  rw [<- related_reconstruct h] at hr
  exact hr

theorem next_receive_replace (state : State N T) (network : Network N T)
    (h : abstractNetwork state.network = abstractNetwork network)
    (source destination : N) :
    Related (CCFRaft.next state (.receive source destination))
      (CCFRaft.next { state with network := network } (.receive source destination)) := by
  have hr := receive_replace state network h source destination
  change observe ((handleReceive? state source destination).getD state) =
    observe ((handleReceive? { state with network := network } source destination).getD
      { state with network := network })
  cases hl : handleReceive? state source destination <;>
    cases hn : handleReceive? { state with network := network } source destination <;>
    simp_all [observe, frame]

theorem next_updateTerm_replace (state : State N T) (network : Network N T)
    (h : abstractNetwork state.network = abstractNetwork network)
    (source destination : N) :
    Related (CCFRaft.next state (.updateTerm source destination))
      (CCFRaft.next { state with network := network } (.updateTerm source destination)) := by
  simp only [Related, CCFRaft.next, <- newerMessage_replace state network h source destination]
  split <;> simp [observe, frame, h]

theorem advanceCommit_replace (state : State N T) (network : Network N T) (node : N) :
    advanceCommitState { state with network := network } node =
      { advanceCommitState state node with network := network } := by
  rfl

omit [DecidableEq T] [Bootstrap N] in
theorem demote_replace (state : State N T) (network : Network N T) (node : N) :
    demoteRetiredCommitted { state with network := network } node =
      { demoteRetiredCommitted state node with network := network } := by
  simp only [demoteRetiredCommitted]
  split <;> simp_all [stepDownState]

omit [DecidableEq T] [Bootstrap N] in
theorem demote_network (state : State N T) (node : N) :
    (demoteRetiredCommitted state node).network = state.network := by
  simp only [demoteRetiredCommitted]
  split <;> rfl

theorem next_replace (state : State N T) (network : Network N T)
    (h : abstractNetwork state.network = abstractNetwork network)
    (action : Action N T) :
    Related (CCFRaft.next state action)
      (CCFRaft.next { state with network := network } action) := by
  cases action
  case receive source destination =>
    exact next_receive_replace state network h source destination
  case updateTerm source destination =>
    exact next_updateTerm_replace state network h source destination
  case advanceCommitIndex node =>
    simp only [Related, CCFRaft.next, advanceCommit_replace, demote_replace, observe, frame]
    apply Prod.ext
    next => rfl
    next => simpa only [demote_network, advanceCommitState] using h
  case advanceCommitIndexAndProposeVote source destination =>
    simp only [Related, CCFRaft.next, advanceCommit_replace, demote_replace, observe, frame]
    apply Prod.ext
    next => rfl
    next =>
      simp only [enqueue_correct, demote_network, advanceCommitState]
      rw [h]
      rfl
  all_goals
    apply Prod.ext
    next => rfl
    next =>
      first
      | exact h
      | simp only [observe, CCFRaft.next, enqueue_correct]
        rw [h]
        rfl

theorem next_congr {left right : State N T} (h : Related left right)
    (action : Action N T) :
    Related (CCFRaft.next left action) (CCFRaft.next right action) := by
  have hr := next_replace left right.network (related_network h) action
  rw [<- related_reconstruct h] at hr
  exact hr

theorem actual_action_bisimulation {left right : State N T} (h : Related left right)
    (action : Action N T) :
    (Enabled left action <-> Enabled right action) /\
      Related (CCFRaft.next left action) (CCFRaft.next right action) :=
  And.intro (enabled_congr h action) (next_congr h action)

theorem runActions_congr (actions : List (Action N T))
    {left right : State N T} (h : Related left right) :
    (runActions left actions).map observe = (runActions right actions).map observe := by
  induction actions generalizing left right with
  | nil => exact congrArg some h
  | cons action actions ih =>
    by_cases enabled : Enabled left action
    next =>
      have enabled' := (enabled_congr h action).mp enabled
      simp only [runActions, system, ExecutableTransitionSystem.applyAction,
        enabled, enabled', if_true]
      exact ih (next_congr h action)
    next =>
      have disabled' : Not (Enabled right action) :=
        fun enabled' => enabled ((enabled_congr h action).mpr enabled')
      simp only [runActions, system, ExecutableTransitionSystem.applyAction,
        enabled, disabled', if_false]

-- The right-hand witness is fixed before executing the actual ordered actions.
theorem runActions_lift (actions : List (Action N T))
    {left right final : State N T} (h : Related left right)
    (executed : runActions left actions = some final) :
    exists final', runActions right actions = some final' /\ Related final final' := by
  have hc := runActions_congr actions h
  rw [executed] at hc
  cases hr : runActions right actions with
  | none => simp [hr] at hc
  | some final' =>
    simp only [hr, Option.map_some] at hc
    exact Exists.intro final' (And.intro rfl (Option.some.inj hc))

theorem nonconsuming_stepdown (state : State N T) (source destination : N)
    (request : AppendEntriesRequest N T) (rest : List (Message N T))
    (node : NodeState N T)
    (selected : takeFirstFrom source (state.network destination) =
      some (.appendEntriesRequest request, rest))
    (addressed : request.destination = destination)
    (stepdown : returnToFollowerState? (state.nodes destination) request = some node) :
    (CCFRaft.next state (.receive source destination)).network = state.network := by
  simp [CCFRaft.next, handleReceive?, selected, Message.destination, addressed, stepdown]

theorem malformed_updateTerm_difference (state : State N T) (source destination : N)
    (message : Message N T) (rest : List (Message N T))
    (allocated : state.allocated destination)
    (selected : takeFirstFrom source (state.network destination) = some (message, rest))
    (malformed : Not (message.destination = destination))
    (allowed : messageSourceAllowed state message)
    (newer : (state.nodes destination).currentTerm < message.term) :
    Enabled state (.updateTerm source destination) /\
      Not (Enabled state (.receive source destination)) /\
      (CCFRaft.next state (.updateTerm source destination)).network = state.network := by
  have hn : newerMessage? state source destination = some message := by
    simp [newerMessage?, selected, allowed, newer]
  have rejected := malformed_receive_rejected state source destination message rest
    selected malformed
  refine And.intro ?_ (And.intro ?_ ?_)
  next => simp [Enabled, allocated, hn]
  next => simp [Enabled, rejected]
  next => simp [CCFRaft.next, hn]


end CCFRaft.Sparse.QueueModel
