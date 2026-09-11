import Sparse.ConfigurationSnapshot

set_option autoImplicit false

namespace CCFRaft.Sparse.ConfigurationPublication

local notation:50 x:51 " IN " xs:51 => Membership.mem xs x

variable {N T : Type} [DecidableEq N] [DecidableEq T] [Bootstrap N]

structure Write (N : Type) where
  source : N
  peer : N
  index : Nat
  term : Nat
  configuration : Finset N
  deriving DecidableEq

def Write.entry (write : Write N) : Entry N T :=
  { term := write.term, content := .reconfiguration write.configuration }

def changed (state : State N T) (write : Write N) : State N T :=
  CCFRaft.next state (.changeConfiguration write.source write.configuration)

-- Only finite operation data, never a predecessor state, closure, or cache.
structure Frame (N : Type) where
  write : Write N
  published : Nat
  commit : Nat
  deriving DecidableEq

def frame (state : State N T) (write : Write N) : Frame N :=
  { write, published := (state.nodes write.source).log.length
    commit := (state.nodes write.source).commitIndex }

structure CanBegin (state : State N T) (write : Write N) : Prop where
  model_enabled : CCFRaft.Enabled state (.changeConfiguration write.source write.configuration)
  index : write.index = (state.nodes write.source).log.length + 1
  term : write.term = (state.nodes write.source).currentTerm
  added : write.configuration \ (latestConfiguration (state.nodes write.source)).nodes = {write.peer}
  different : Not (write.peer = write.source)
  fresh : Not (state.allocated write.peer)
  active_before : (state.nodes write.source).membershipState = .active
  active_after : ((changed state write).nodes write.source).membershipState = .active
  committed : (state.nodes write.source).commitIndex <= (state.nodes write.source).log.length

structure Pending (state : State N T) (token : Frame N) : Prop where
  index : token.write.index = token.published + 1
  length : (state.nodes token.write.source).log.length = token.write.index
  entry : entryAt? (state.nodes token.write.source).log token.write.index = some token.write.entry
  term : (state.nodes token.write.source).currentTerm = token.write.term
  commit : (state.nodes token.write.source).commitIndex = token.commit
  committed : token.commit <= token.published
  role : (state.nodes token.write.source).role = .leader
  active : (state.nodes token.write.source).membershipState = .active
  source_allocated : state.allocated token.write.source
  peer_allocated : state.allocated token.write.peer
  different : Not (token.write.peer = token.write.source)
  peer_active : token.write.peer IN activeNodeUnion (state.nodes token.write.source)
  cursor : (state.nodes token.write.source).sentIndex token.write.peer = token.published

inductive Phase (N : Type) where
  | idle
  | callback (token : Frame N)
  | publication (token : Frame N)
  deriving DecidableEq

structure Machine (N T : Type) where
  core : State N T
  phase : Phase N

def idle (state : State N T) : Machine N T := { core := state, phase := .idle }

inductive Event (N T : Type) where
  | model (action : CCFRaft.Action N T)
  | begin (write : Write N)
  | callback (sendSucceeded : Bool)
  | close

-- Success is a premise supplied by the implementation relation, not by a raw
-- send-attempt record. No other event can interleave with an open frame.
def Enabled (machine : Machine N T) : Event N T -> Prop
  | .model action => machine.phase = .idle /\ CCFRaft.Enabled machine.core action
  | .begin write => machine.phase = .idle /\ CanBegin machine.core write
  | .callback success =>
    match machine.phase with
    | .callback token => success = true /\ Pending machine.core token
    | _ => False
  | .close =>
    match machine.phase with
    | .publication token => Pending machine.core token
    | _ => False

def callbackCore (state : State N T) (token : Frame N) : State N T :=
  CCFRaft.next state (.appendEntries token.write.source token.write.peer token.published)

-- Like Model.next, this is total. Only Step validates an execution.
def next (machine : Machine N T) : Event N T -> Machine N T
  | .model action => idle (CCFRaft.next machine.core action)
  | .begin write =>
    { core := changed machine.core write, phase := .callback (frame machine.core write) }
  | .callback _ =>
    match machine.phase with
    | .callback token =>
      { core := callbackCore machine.core token, phase := .publication token }
    | _ => machine
  | .close =>
    match machine.phase with
    | .publication _ => idle machine.core
    | _ => machine

def Step (before : Machine N T) (event : Event N T) (after : Machine N T) : Prop :=
  Enabled before event /\ after = next before event

theorem old_action_inclusion (state : State N T) (action : CCFRaft.Action N T) :
    Step (idle state) (.model action) (idle (CCFRaft.next state action)) <->
      CCFRaft.Enabled state action := by
  simp [Step, Enabled, idle, next]

theorem no_model_interleaving (state : State N T) (token : Frame N)
    (action : CCFRaft.Action N T) :
    Not (Enabled { core := state, phase := .callback token } (.model action)) /\
    Not (Enabled { core := state, phase := .publication token } (.model action)) := by
  simp [Enabled]

theorem failed_attempt_not_enabled (state : State N T) (token : Frame N) :
    Not (Enabled { core := state, phase := .callback token } (.callback false)) := by
  simp [Enabled]

theorem begin_frame (state : State N T) (write : Write N) :
    (next (idle state) (.begin write)).phase = .callback (frame state write) := rfl

theorem begin_frame_unique (state : State N T) (write : Write N) (token : Frame N)
    (produced : (next (idle state) (.begin write)).phase = .callback token) :
    token = frame state write :=
  (Phase.callback.inj produced).symm

theorem only_begin_opens_frame (before after : Machine N T) (event : Event N T) (token : Frame N)
    (step : Step before event after) (opened : after.phase = .callback token) :
    exists write, event = .begin write /\ before.phase = .idle /\ CanBegin before.core write /\
      after.core = changed before.core write /\ token = frame before.core write := by
  have enabled := step.1
  have same := step.2
  subst after
  cases event with
  | model action => simp [next, idle] at opened
  | begin write =>
    exact Exists.intro write (And.intro rfl (And.intro enabled.1
      (And.intro enabled.2 (And.intro rfl (Phase.callback.inj opened).symm))))
  | callback success =>
    cases phase : before.phase with
    | idle => simp [Enabled, phase] at enabled
    | callback old => simp [next, phase] at opened
    | publication old => simp [Enabled, phase] at enabled
  | close =>
    cases phase : before.phase with
    | idle => simp [Enabled, phase] at enabled
    | callback old => simp [Enabled, phase] at enabled
    | publication old => simp [next, phase, idle] at opened

theorem changed_log (state : State N T) (write : Write N) (allowed : CanBegin state write) :
    ((changed state write).nodes write.source).log =
      (state.nodes write.source).log ++ [write.entry] := by
  simp [changed, CCFRaft.next, Write.entry, allowed.term]

theorem begin_prefix (state : State N T) (write : Write N) (allowed : CanBegin state write) :
    (((changed state write).nodes write.source).log).take (frame state write).published =
      (state.nodes write.source).log := by
  rw [changed_log state write allowed]
  simp [frame]

omit [DecidableEq T] in
theorem active_snoc (node : NodeState N T) (configuration : Finset N) (term : Nat)
    (committed : node.commitIndex <= node.log.length) :
    activeConfigurations { node with log := node.log ++ [{ term, content := .reconfiguration configuration }] } =
      activeConfigurations node ++ [{ index := node.log.length + 1, nodes := configuration }] := by
  have cutoff := (Configuration.current_predecessor node.log node.commitIndex).1
  have current :
      currentConfigurationAt (node.log ++ [{ term, content := .reconfiguration configuration }]) node.commitIndex =
        currentConfigurationAt node.log node.commitIndex := by
    rw [Configuration.current_snoc]
    simp only [show Not (node.log.length + 1 <= node.commitIndex) from by omega, if_false]
  have physical :
      configurationsInLog (node.log ++ [{ term, content := .reconfiguration configuration }]) =
        configurationsInLog node.log ++ [{ index := node.log.length + 1, nodes := configuration }] := by
    simp [configurationsInLog, Configuration.configurations_append,
      configurationsInLogFrom, Nat.add_comm]
  have within : (currentConfigurationAt node.log node.commitIndex).index <= node.log.length + 1 := by omega
  simp only [activeConfigurations, currentConfiguration, current, allConfigurations, physical]
  change ((implicitConfiguration :: configurationsInLog node.log) ++
    [({ index := node.log.length + 1, nodes := configuration } : Configuration N)]).filter _ = _
  rw [List.filter_append]
  simp [within]

theorem changed_active (state : State N T) (write : Write N) (allowed : CanBegin state write) :
    activeConfigurations ((changed state write).nodes write.source) =
      activeConfigurations (state.nodes write.source) ++
        [{ index := write.index, nodes := write.configuration }] := by
  have result := active_snoc (state.nodes write.source) write.configuration
    (state.nodes write.source).currentTerm allowed.committed
  simpa [changed, CCFRaft.next, activeConfigurations, currentConfiguration, allowed.index] using result

theorem begin_peer_fresh (state : State N T) (write : Write N) (allowed : CanBegin state write) :
    (changed state write).nodes.node? write.peer = some freshNodeState := by
  have added : write.peer IN write.configuration \ (latestConfiguration (state.nodes write.source)).nodes := by
    rw [allowed.added]
    simp
  have fresh : Not (state.nodes.allocated write.peer) := allowed.fresh
  have allocated := NodeStore.node?_allocate_of_not_allocated_of_mem state.nodes
    (write.configuration \ (latestConfiguration (state.nodes write.source)).nodes)
    write.peer fresh added
  simpa [changed, CCFRaft.next, updateNode, allowed.different] using allocated

theorem begin_join_history (state : State N T) (write : Write N) (allowed : CanBegin state write) :
    Not (write.peer IN state.hasJoined) /\
      (changed state write).hasJoined = Union.union state.hasJoined {write.peer} := by
  have added : write.peer IN write.configuration \ (latestConfiguration (state.nodes write.source)).nodes := by
    rw [allowed.added]
    simp
  exact And.intro (allowed.model_enabled.2.2.2.2.2.1 write.peer added)
    (by simp [changed, CCFRaft.next, allowed.added])

theorem begin_pending (state : State N T) (write : Write N) (allowed : CanBegin state write) :
    Pending (changed state write) (frame state write) := by
  have added : write.peer IN write.configuration \ (latestConfiguration (state.nodes write.source)).nodes := by
    rw [allowed.added]
    simp
  have peer_member := (Finset.mem_sdiff.mp added).1
  constructor
  next => exact allowed.index
  next =>
    change ((changed state write).nodes write.source).log.length = write.index
    rw [changed_log state write allowed]
    simp [allowed.index]
  next =>
    change entryAt? ((changed state write).nodes write.source).log write.index = some write.entry
    rw [changed_log state write allowed, allowed.index]
    simp [entryAt?]
  next => simpa [changed, CCFRaft.next, frame] using allowed.term.symm
  next => simp [changed, CCFRaft.next, frame]
  next => exact allowed.committed
  next => simpa [changed, CCFRaft.next, frame] using allowed.model_enabled.2.1
  next => exact allowed.active_after
  next => simp [changed, CCFRaft.next, frame, State.allocated, NodeStore.allocated, updateNode]
  next =>
    change ((changed state write).nodes.node? write.peer).isSome
    rw [begin_peer_fresh state write allowed]
    rfl
  next => exact allowed.different
  next =>
    change write.peer IN activeNodeUnion ((changed state write).nodes write.source)
    rw [activeNodeUnion, changed_active state write allowed, List.foldl_append]
    simp [peer_member]
  next =>
    change ((changed state write).nodes write.source).sentIndex write.peer = (state.nodes write.source).log.length
    have not_old := (Finset.mem_sdiff.mp added).2
    simp [changed, CCFRaft.next, peer_member, not_old]

omit [DecidableEq N] [DecidableEq T] [Bootstrap N] in
theorem termAt_take_frontier (log : List (Entry N T)) (published : Nat) :
    termAt (log.take published) published = termAt log published := by
  by_cases zero : published = 0
  next => simp [termAt, entryAt?, zero]
  next =>
    have within : published - 1 < published := by omega
    simp [termAt, entryAt?, zero, within]

def packet (state : State N T) (token : Frame N) : AppendEntriesRequest N T :=
  { term := token.write.term
    prevLogIndex := token.published
    prevLogTerm := termAt ((state.nodes token.write.source).log.take token.published) token.published
    entries := []
    leaderCommit := token.commit
    source := token.write.source
    destination := token.write.peer }

omit [DecidableEq T] in
theorem callback_packet (state : State N T) (token : Frame N) (pending : Pending state token) :
    makeAppendEntriesRequest state token.write.source token.write.peer token.published =
      packet state token := by
  simp [makeAppendEntriesRequest, packet, pending.cursor, pending.term, pending.commit,
    messageEntries, termAt_take_frontier]

theorem callback_not_model_enabled (state : State N T) (token : Frame N)
    (pending : Pending state token) :
    Not (CCFRaft.Enabled state
      (.appendEntries token.write.source token.write.peer token.published)) := by
  intro enabled
  have end_index := enabled.2.2.2.2.2.1
  rw [pending.cursor, pending.length, pending.index, Nat.min_self] at end_index
  omega

theorem callback_core_effect (state : State N T) (token : Frame N) (pending : Pending state token) :
    callbackCore state token =
      { state with network := enqueueNoDup state.network (.appendEntriesRequest (packet state token)) } := by
  have cursor : updateIndex (state.nodes token.write.source).sentIndex token.write.peer token.published =
      (state.nodes token.write.source).sentIndex := by
    rw [updateIndex, <- pending.cursor]
    exact Function.update_eq_self _ _
  have found : state.nodes.node? token.write.source = some (state.nodes token.write.source) := by
    have present := pending.source_allocated
    cases lookup : state.nodes.node? token.write.source with
    | none => simp [State.allocated, NodeStore.allocated, lookup] at present
    | some value => simp [NodeStore.get, lookup]
  have same : updateNode state.nodes token.write.source (state.nodes token.write.source) = state.nodes := by
    apply congrArg NodeStore.mk
    apply Finmap.ext_lookup
    intro node
    by_cases equal : node = token.write.source
    next =>
      subst node
      exact (NodeStore.node?_set_same state.nodes _ _).trans found.symm
    next => exact NodeStore.node?_set_of_ne state.nodes _ node _ equal
  simp only [callbackCore, CCFRaft.next, cursor, callback_packet state token pending]
  simpa only using congrArg
    (fun nodes => { state with
      nodes := nodes
      network := enqueueNoDup state.network (.appendEntriesRequest (packet state token)) }) same

theorem callback_pending (state : State N T) (token : Frame N) (pending : Pending state token) :
    Pending (callbackCore state token) token := by
  rw [callback_core_effect state token pending]
  cases pending
  constructor <;> assumption

theorem begin_step (state : State N T) (write : Write N) (allowed : CanBegin state write) :
    Step (idle state) (.begin write)
      { core := changed state write, phase := .callback (frame state write) } :=
  And.intro (And.intro rfl allowed) rfl

theorem callback_step (state : State N T) (token : Frame N) (pending : Pending state token)
    (sendSucceeded : Bool) (success : sendSucceeded = true) :
    Step { core := state, phase := .callback token } (.callback sendSucceeded)
      { core := callbackCore state token, phase := .publication token } :=
  And.intro (And.intro success pending) rfl

theorem close_step (state : State N T) (token : Frame N) (pending : Pending state token) :
    Step { core := state, phase := .publication token } .close (idle state) :=
  And.intro pending rfl

theorem cannot_close_before_callback (state : State N T) (token : Frame N) :
    Not (Enabled { core := state, phase := .callback token } .close) := by
  simp [Enabled]

theorem cannot_repeat_callback (state : State N T) (token : Frame N) (success : Bool) :
    Not (Enabled { core := state, phase := .publication token } (.callback success)) := by
  simp [Enabled]

def publishedLength (machine : Machine N T) (source : N) : Nat :=
  match machine.phase with
  | .idle => (machine.core.nodes source).log.length
  | .callback token | .publication token =>
    if source = token.write.source then token.published else (machine.core.nodes source).log.length

def observedSentIndex (machine : Machine N T) (source peer : N) : Nat :=
  match machine.phase with
  | .callback token =>
    if source = token.write.source /\ peer = token.write.peer then token.write.index
    else (machine.core.nodes source).sentIndex peer
  | _ => (machine.core.nodes source).sentIndex peer

def openingSnapshot (state : State N T) (token : Frame N) : List (Configuration N) :=
  ConfigurationSnapshot.positiveActive
    ((state.nodes token.write.source).log.take token.published) token.commit

def closingSnapshot (state : State N T) (token : Frame N) : List (Configuration N) :=
  ConfigurationSnapshot.positiveActive (state.nodes token.write.source).log token.commit

theorem begin_snapshot (state : State N T) (write : Write N) (allowed : CanBegin state write) :
    openingSnapshot (changed state write) (frame state write) =
      (activeConfigurations (state.nodes write.source)).filter (fun c => 0 < c.index) := by
  change ConfigurationSnapshot.positiveActive
    (((changed state write).nodes write.source).log.take (frame state write).published)
    (state.nodes write.source).commitIndex = _
  rw [begin_prefix state write allowed]
  exact ConfigurationSnapshot.positiveActive_model _

omit [DecidableEq T] in
theorem closing_snapshot_model (state : State N T) (token : Frame N) (pending : Pending state token) :
    closingSnapshot state token =
      (activeConfigurations (state.nodes token.write.source)).filter (fun c => 0 < c.index) := by
  rw [closingSnapshot, <- pending.commit]
  exact ConfigurationSnapshot.positiveActive_model _

theorem changed_snapshot (state : State N T) (write : Write N) (allowed : CanBegin state write) :
    closingSnapshot (changed state write) (frame state write) =
      (activeConfigurations (state.nodes write.source)).filter (fun c => 0 < c.index) ++
        [{ index := write.index, nodes := write.configuration }] := by
  rw [closing_snapshot_model _ _ (begin_pending state write allowed)]
  simp only [frame]
  rw [changed_active state write allowed, List.filter_append]
  have positive : 0 < write.index := by rw [allowed.index]; omega
  simp [positive]

theorem callback_snapshots (state : State N T) (token : Frame N) (pending : Pending state token) :
    openingSnapshot (callbackCore state token) token = openingSnapshot state token /\
    closingSnapshot (callbackCore state token) token = closingSnapshot state token := by
  rw [callback_core_effect state token pending]
  exact And.intro rfl rfl

omit [DecidableEq T] in
theorem published_and_pending (state : State N T) (token : Frame N) (pending : Pending state token) :
    publishedLength { core := state, phase := .callback token } token.write.source = token.published /\
    (state.nodes token.write.source).log.length = token.published + 1 /\
    entryAt? (state.nodes token.write.source).log (token.published + 1) = some token.write.entry := by
  refine And.intro (by simp [publishedLength]) (And.intro ?_ ?_)
  next => exact pending.length.trans pending.index
  next => rw [<- pending.index]; exact pending.entry

omit [DecidableEq T] in
theorem provisional_cursor (state : State N T) (token : Frame N) (pending : Pending state token) :
    observedSentIndex { core := state, phase := .callback token } token.write.source token.write.peer =
        (state.nodes token.write.source).sentIndex token.write.peer + 1 /\
    (packet state token).prevLogIndex + 1 = token.write.index := by
  simp [observedSentIndex, pending.cursor, pending.index, packet]

theorem publication_close (state : State N T) (token : Frame N) (pending : Pending state token) :
    (next { core := state, phase := .publication token } .close).core = state /\
    publishedLength { core := state, phase := .publication token } token.write.source = token.published /\
    publishedLength (next { core := state, phase := .publication token } .close) token.write.source =
      token.write.index := by
  simp [next, idle, publishedLength, pending.length]

-- The frame and both intermediate states are constructed, not existential inputs.
theorem one_operation (state : State N T) (write : Write N) (allowed : CanBegin state write)
    (sendSucceeded : Bool) (success : sendSucceeded = true) :
    let token := frame state write
    let afterBegin := changed state write
    let afterCallback := callbackCore afterBegin token
    Step (idle state) (.begin write) { core := afterBegin, phase := .callback token } /\
    Step { core := afterBegin, phase := .callback token } (.callback sendSucceeded)
      { core := afterCallback, phase := .publication token } /\
    Step { core := afterCallback, phase := .publication token } .close (idle afterCallback) := by
  have pending := begin_pending state write allowed
  exact And.intro (begin_step state write allowed)
    (And.intro (callback_step _ _ pending sendSucceeded success)
      (close_step _ _ (callback_pending _ _ pending)))

theorem same_frame_observations (state : State N T) (write : Write N) (allowed : CanBegin state write)
    (snapshot : List (Configuration N))
    (observed : (activeConfigurations (state.nodes write.source)).filter (fun c => 0 < c.index) = snapshot) :
    let token := frame state write
    let afterBegin := changed state write
    let afterCallback := callbackCore afterBegin token
    openingSnapshot afterBegin token = snapshot /\
    openingSnapshot afterCallback token = snapshot /\
    closingSnapshot afterCallback token =
      snapshot ++ [{ index := write.index, nodes := write.configuration }] := by
  have pending := begin_pending state write allowed
  have preserved := callback_snapshots _ _ pending
  have opening := (begin_snapshot state write allowed).trans observed
  refine And.intro opening (And.intro (preserved.1.trans opening) ?_)
  rw [preserved.2, changed_snapshot state write allowed, observed]

namespace Regression

local instance : NeZero NODE_COUNT := { out := by decide }

def initial : State Node Nat :=
  { nodes := NodeStore.ofFinset {0} (fun _ =>
      { (freshNodeState : NodeState Node Nat) with
        role := .leader
        currentTerm := 2
        log := [{ term := 2, content := .reconfiguration {0} },
                { term := 2, content := .signature }]
        commitIndex := 2 })
    network := fun _ => []
    submittedTxIds := {}
    hasJoined := {0} }

def write : Write Node :=
  { source := 0, peer := 1, index := 3, term := 2, configuration := {0, 1} }

theorem allowed : CanBegin initial write := by
  constructor <;> decide +kernel

def started : Machine Node Nat := next (idle initial) (.begin write)
def sent : Machine Node Nat := next started (.callback true)
def closed : Machine Node Nat := next sent .close

theorem kernel_chain :
    Step (idle initial) (.begin write) started /\
    Step started (.callback true) sent /\
    Step sent .close closed :=
  one_operation initial write allowed true rfl

theorem kernel_frontiers :
    publishedLength started 0 = 2 /\
    (started.core.nodes 0).log.length = 3 /\
    observedSentIndex started 0 1 = 3 /\
    (started.core.nodes 0).sentIndex 1 = 2 /\
    publishedLength sent 0 = 2 /\
    observedSentIndex sent 0 1 = 2 /\
    publishedLength closed 0 = 3 /\
    entryAt? (closed.core.nodes 0).log 3 =
      some { term := 2, content := .reconfiguration {0, 1} } := by
  decide +kernel

theorem kernel_packet :
    sent.core.network 1 =
      [.appendEntriesRequest
        { term := 2, prevLogIndex := 2, prevLogTerm := 2, entries := [],
          leaderCommit := 2, source := 0, destination := 1 }] := by
  decide +kernel

theorem kernel_same_frame :
    started.phase = .callback (frame initial write) /\
    sent.phase = .publication (frame initial write) /\
    closed.phase = .idle := by
  decide +kernel

theorem kernel_snapshots :
    openingSnapshot started.core (frame initial write) = [{ index := 1, nodes := {0} }] /\
    openingSnapshot sent.core (frame initial write) = [{ index := 1, nodes := {0} }] /\
    closingSnapshot sent.core (frame initial write) =
      [{ index := 1, nodes := {0} }, { index := 3, nodes := {0, 1} }] :=
  same_frame_observations initial write allowed _ (by decide +kernel)

theorem kernel_not_old_send :
    Not (CCFRaft.Enabled started.core (.appendEntries 0 1 2)) /\
    CCFRaft.Enabled started.core (.appendEntries 0 1 3) := by
  decide +kernel

theorem kernel_wrong_write_index : Not (CanBegin initial { write with index := 2 }) := by
  intro invalid
  have bad := invalid.index
  have expected : (initial.nodes write.source).log.length + 1 = 3 := by decide +kernel
  change 2 = (initial.nodes write.source).log.length + 1 at bad
  omega

theorem kernel_wrong_write_term : Not (CanBegin initial { write with term := 3 }) := by
  intro invalid
  have bad := invalid.term
  have expected : (initial.nodes write.source).currentTerm = 2 := by decide +kernel
  change 3 = (initial.nodes write.source).currentTerm at bad
  omega

end Regression

end CCFRaft.Sparse.ConfigurationPublication

run_cmd do
  let mut checked := 0
  for (name, info) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.Sparse.ConfigurationPublication).isPrefixOf name then
      match info with
      | .axiomInfo _ => throwError "explicit publication axiom: {name}"
      | _ =>
        checked := checked + 1
        for axiomName in (<- Lean.collectAxioms name) do
          unless axiomName == ``propext || axiomName == ``Classical.choice ||
              axiomName == ``Quot.sound do
            throwError "unexpected axiom in {name}: {axiomName}"
  if checked = 0 then
    throwError "no publication declarations audited"
  Lean.logInfo m!"ConfigurationPublication: {checked} declarations passed the allowed-axiom gate."
