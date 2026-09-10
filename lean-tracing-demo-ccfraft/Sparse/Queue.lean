import Model

set_option autoImplicit false

namespace CCFRaft.Sparse.Queue

variable {N T : Type} [DecidableEq N]

def partition (source : N) (queue : List (Message N T)) : List (Message N T) :=
  queue.filter fun message => decide (message.source = source)

theorem partition_mem (source : N) (queue : List (Message N T)) (m : Message N T) :
    Membership.mem (partition source queue) m <->
      Membership.mem queue m /\ m.source = source := by
  simp [partition]

theorem own_partition_mem (queue : List (Message N T)) (m : Message N T) :
    Membership.mem (partition m.source queue) m <-> Membership.mem queue m := by
  simp [partition_mem]

theorem take_spec (source : N) (queue : List (Message N T)) :
    match takeFirstFrom source queue with
    | none => partition source queue = []
    | some (m, rest) =>
        m.source = source /\
        partition source queue = m :: partition source rest /\
        forall other, Not (other = source) -> partition other rest = partition other queue := by
  induction queue with
  | nil => simp [takeFirstFrom, partition]
  | cons m tail ih =>
    by_cases h : m.source = source
    next =>
      simp only [takeFirstFrom, h, if_true]
      refine And.intro True.intro (And.intro ?_ ?_)
      next => simp [partition, h]
      next =>
        intro other ne
        have hm : Not (m.source = other) := by
          intro he
          exact ne (he.symm.trans h)
        simp [partition, hm]
    next =>
      simp only [takeFirstFrom, h, if_false]
      cases ht : takeFirstFrom source tail with
      | none =>
        simp only [ht] at ih
        simpa [partition, h] using ih
      | some pair =>
        cases pair with
        | mk m' rest =>
          simp only [ht] at ih
          refine And.intro ih.1 (And.intro ?_ ?_)
          next => simpa [partition, h] using ih.2.1
          next =>
            intro other ne
            simp only [partition, List.filter_cons]
            exact congrArg (fun xs => if decide (m.source = other) then m :: xs else xs)
              (ih.2.2 other ne)

theorem take_none_iff (source : N) (queue : List (Message N T)) :
    takeFirstFrom source queue = none <-> partition source queue = [] := by
  have spec := take_spec source queue
  cases h : takeFirstFrom source queue with
  | none => simpa [h] using spec
  | some pair =>
    cases pair with
    | mk m rest =>
      simp only [h] at spec
      simp [spec.2.1]

theorem take_some_spec (source : N) (queue : List (Message N T))
    (m : Message N T) (rest : List (Message N T))
    (h : takeFirstFrom source queue = some (m, rest)) :
    m.source = source /\
    partition source queue = m :: partition source rest /\
    forall other, Not (other = source) -> partition other rest = partition other queue := by
  simpa [h] using take_spec source queue

theorem take_enabled (source : N) (queue : List (Message N T))
    (m : Message N T) (tail : List (Message N T))
    (h : partition source queue = m :: tail) :
    exists rest, takeFirstFrom source queue = some (m, rest) /\
      partition source rest = tail /\
      forall other, Not (other = source) -> partition other rest = partition other queue := by
  cases ht : takeFirstFrom source queue with
  | none =>
    have := (take_none_iff source queue).mp ht
    simp [h] at this
  | some pair =>
    cases pair with
    | mk selected rest =>
      have spec := take_some_spec source queue selected rest ht
      have eqs := List.cons.inj (h.symm.trans spec.2.1)
      cases eqs.1
      exact Exists.intro rest (And.intro rfl (And.intro eqs.2.symm spec.2.2))

theorem first_correct (source : N) (queue : List (Message N T)) :
    (takeFirstFrom source queue).map Prod.fst = (partition source queue).head? := by
  cases ht : takeFirstFrom source queue with
  | none =>
    simp [(take_none_iff source queue).mp ht]
  | some pair =>
    cases pair with
    | mk m rest =>
      simp [(take_some_spec source queue m rest ht).2.1]

theorem first_observation_correct (source : N) (queue : List (Message N T))
    (m : Message N T) :
    (exists rest, takeFirstFrom source queue = some (m, rest)) <->
      (partition source queue).head? = some m := by
  rw [<- first_correct]
  cases takeFirstFrom source queue with
  | none => simp
  | some pair =>
    cases pair with
    | mk selected rest => simp

abbrev Network (N T : Type) := N -> List (Message N T)
abbrev Sparse (N T : Type) := N -> N -> List (Message N T)

def abstractNetwork (network : Network N T) : Sparse N T :=
  fun destination source => partition source (network destination)

def replaceSource (queues : Sparse N T) (destination source : N)
    (tail : List (Message N T)) : Sparse N T :=
  Function.update queues destination (Function.update (queues destination) source tail)

theorem dequeue_correct (network : Network N T) (destination source : N)
    (m : Message N T) (rest : List (Message N T))
    (h : takeFirstFrom source (network destination) = some (m, rest)) :
    abstractNetwork (updateQueue network destination rest) =
      replaceSource (abstractNetwork network) destination source (partition source rest) := by
  have spec := take_some_spec source (network destination) m rest h
  funext d s
  by_cases hd : d = destination
  next =>
    subst d
    by_cases hs : s = source
    next =>
      subst s
      simp [abstractNetwork, updateQueue, replaceSource]
    next => simpa [abstractNetwork, updateQueue, replaceSource, hs] using spec.2.2 s hs
  next => simp [abstractNetwork, updateQueue, replaceSource, hd]

theorem cross_source_swap (a b : Message N T)
    (different : Not (a.source = b.source)) :
    (fun source => partition source [a, b]) =
      (fun source => partition source [b, a]) := by
  funext source
  by_cases ha : a.source = source
  next =>
    have hb : Not (b.source = source) := by
      intro hb
      exact different (ha.trans hb.symm)
    simp [partition, ha, hb]
  next =>
    by_cases hb : b.source = source <;> simp [partition, ha, hb]

section Dedup

variable [DecidableEq T]

def sparseEnqueue (queues : Sparse N T) (m : Message N T) : Sparse N T :=
  let queue := queues m.destination m.source
  if Membership.mem queue m then queues
  else replaceSource queues m.destination m.source (queue ++ [m])

theorem enqueue_correct (network : Network N T) (m : Message N T) :
    abstractNetwork (enqueueNoDup network m) =
      sparseEnqueue (abstractNetwork network) m := by
  have hm := own_partition_mem (network m.destination) m
  simp only [enqueueNoDup, sparseEnqueue, abstractNetwork, hm]
  split
  next => rfl
  next =>
    funext d s
    by_cases hd : d = m.destination
    next =>
      subst d
      by_cases hs : s = m.source
      next =>
        subst s
        simp [abstractNetwork, replaceSource, updateQueue, partition]
      next =>
        have hs' : Not (m.source = s) := Ne.symm hs
        simp [abstractNetwork, replaceSource, updateQueue, partition, hs, hs']
    next => simp [abstractNetwork, replaceSource, updateQueue, hd]

end Dedup

def WellFormed (queues : N -> List (Message N T)) : Prop :=
  forall source m, Membership.mem (queues source) m -> m.source = source

theorem partition_wellFormed (queue : List (Message N T)) :
    WellFormed (fun source => partition source queue) := by
  intro source m h
  exact ((partition_mem source queue m).mp h).2

theorem partition_of_wellFormed (queues : N -> List (Message N T))
    (wf : WellFormed queues) (source other : N) :
    partition source (queues other) = if other = source then queues other else [] := by
  by_cases h : other = source
  next =>
    subst other
    simp only [if_true]
    apply List.filter_eq_self.mpr
    intro m hm
    simpa using wf source m hm
  next =>
    simp only [h, if_false]
    apply List.filter_eq_nil_iff.mpr
    intro m hm
    have hs := wf other m hm
    simp [hs, h]

def realize (sources : List N) (queues : N -> List (Message N T)) :
    List (Message N T) :=
  sources.flatMap queues

theorem partition_realize (sources : List N) (queues : N -> List (Message N T))
    (wf : WellFormed queues) (source : N) (unique : sources.Nodup) :
    partition source (realize sources queues) =
      if Membership.mem sources source then queues source else [] := by
  induction sources with
  | nil => simp [realize, partition]
  | cons other sources ih =>
    have hn := List.nodup_cons.mp unique
    have hp := partition_of_wellFormed queues wf source other
    change partition source (queues other ++ realize sources queues) = _
    simp only [partition] at hp
    simp only [partition, List.filter_append]
    rw [hp, show List.filter (fun m : Message N T => decide (m.source = source))
      (realize sources queues) = _ from ih hn.2]
    by_cases hs : other = source
    next =>
      subst other
      simp [hn.1]
    next =>
      simp [hs, Ne.symm hs]

theorem realizability [Fintype N] (queues : N -> List (Message N T))
    (wf : WellFormed queues) :
    forall source, partition source (realize Finset.univ.toList queues) = queues source := by
  intro source
  simpa using partition_realize Finset.univ.toList queues wf source
    (Finset.nodup_toList Finset.univ)

theorem sum_partition_length [Fintype N] (queue : List (Message N T)) :
    Finset.univ.sum (fun source : N => (partition source queue).length) = queue.length := by
  induction queue with
  | nil => simp [partition]
  | cons m tail ih =>
    have hp (source : N) :
        (partition source (m :: tail)).length =
          (partition source tail).length + if m.source = source then 1 else 0 := by
      by_cases h : m.source = source <;> simp [partition, h]
    simp_rw [hp]
    simp [Finset.sum_add_distrib, ih]

noncomputable def realizeNetwork [Fintype N] (queues : Sparse N T) : Network N T :=
  fun destination => realize Finset.univ.toList (queues destination)

theorem network_realizability [Fintype N] (queues : Sparse N T)
    (wf : forall destination, WellFormed (queues destination)) :
    abstractNetwork (realizeNetwork queues) = queues := by
  funext destination source
  exact realizability (queues destination) (wf destination) source

theorem empty_network :
    abstractNetwork (fun _ : N => ([] : List (Message N T))) = fun _ _ => [] := by
  rfl

variable [DecidableEq T]

-- No inequality between destination, source, or response endpoints is required.
theorem reply_correct (network : Network N T) (destination source : N)
    (m : Message N T) (rest : List (Message N T))
    (response : AppendEntriesResponse N)
    (h : takeFirstFrom source (network destination) = some (m, rest)) :
    abstractNetwork (reply network destination rest response) =
      sparseEnqueue
        (replaceSource (abstractNetwork network) destination source (partition source rest))
        (.appendEntriesResponse response) := by
  unfold reply
  rw [enqueue_correct, dequeue_correct network destination source m rest h]

theorem malformed_receive_rejected [Bootstrap N] (state : State N T)
    (source destination : N) (m : Message N T) (rest : List (Message N T))
    (selected : takeFirstFrom source (state.network destination) = some (m, rest))
    (malformed : Not (m.destination = destination)) :
    handleReceive? state source destination = none := by
  simp [handleReceive?, selected, malformed]

-- A receive label records the exact selected packet, retaining destination guards.
-- The optional emitted packet models dequeue followed by a deduplicated reply.
inductive Command (N T : Type) where
  | send (message : Message N T)
  | receive (source destination : N) (selected : Message N T)
      (emitted : Option (Message N T))

def emitConcrete (network : Network N T) (emitted : Option (Message N T)) : Network N T :=
  match emitted with
  | none => network
  | some m => enqueueNoDup network m

def emitSparse (queues : Sparse N T) (emitted : Option (Message N T)) : Sparse N T :=
  match emitted with
  | none => queues
  | some m => sparseEnqueue queues m

theorem emit_correct (network : Network N T) (emitted : Option (Message N T)) :
    abstractNetwork (emitConcrete network emitted) =
      emitSparse (abstractNetwork network) emitted := by
  cases emitted with
  | none => rfl
  | some m => exact enqueue_correct network m

def concreteStep (command : Command N T) (network : Network N T) :
    Option (Network N T) :=
  match command with
  | .send m => some (enqueueNoDup network m)
  | .receive source destination selected emitted =>
    match takeFirstFrom source (network destination) with
    | none => none
    | some (m, rest) =>
      if m = selected /\ m.destination = destination then
        some (emitConcrete (updateQueue network destination rest) emitted)
      else none

def sparseStep (command : Command N T) (queues : Sparse N T) :
    Option (Sparse N T) :=
  match command with
  | .send m => some (sparseEnqueue queues m)
  | .receive source destination selected emitted =>
    match queues destination source with
    | [] => none
    | m :: tail =>
      if m = selected /\ m.destination = destination then
        some (emitSparse (replaceSource queues destination source tail) emitted)
      else none

theorem step_correct (command : Command N T) (network : Network N T) :
    (concreteStep command network).map abstractNetwork =
      sparseStep command (abstractNetwork network) := by
  cases command with
  | send m => simp [concreteStep, sparseStep, enqueue_correct]
  | receive source destination selected emitted =>
    cases ht : takeFirstFrom source (network destination) with
    | none =>
      have empty := (take_none_iff source (network destination)).mp ht
      simp [concreteStep, sparseStep, ht, abstractNetwork, empty]
    | some pair =>
      cases pair with
      | mk m rest =>
        have spec := take_some_spec source (network destination) m rest ht
        have head : abstractNetwork network destination source =
            m :: partition source rest := spec.2.1
        simp only [concreteStep, ht, sparseStep, head]
        split
        next =>
          simp only [Option.map_some, emit_correct, dequeue_correct network destination source m rest ht]
        next => rfl

theorem step_lift (command : Command N T) (network : Network N T)
    (next : Sparse N T)
    (h : sparseStep command (abstractNetwork network) = some next) :
    exists nextNetwork, concreteStep command network = some nextNetwork /\
      abstractNetwork nextNetwork = next := by
  have commute := (step_correct command network).trans h
  cases hc : concreteStep command network with
  | none => simp [hc] at commute
  | some nextNetwork =>
    simp only [hc, Option.map_some] at commute
    exact Exists.intro nextNetwork (And.intro rfl (Option.some.inj commute))

def runConcrete : List (Command N T) -> Network N T -> Option (Network N T)
  | [], network => some network
  | command :: commands, network =>
      (concreteStep command network).bind (runConcrete commands)

def runSparse : List (Command N T) -> Sparse N T -> Option (Sparse N T)
  | [], queues => some queues
  | command :: commands, queues =>
      (sparseStep command queues).bind (runSparse commands)

theorem run_correct (commands : List (Command N T)) (network : Network N T) :
    (runConcrete commands network).map abstractNetwork =
      runSparse commands (abstractNetwork network) := by
  induction commands generalizing network with
  | nil => rfl
  | cons command commands ih =>
    have step := step_correct command network
    cases hc : concreteStep command network with
    | none =>
      simp only [hc, Option.map_none] at step
      simp [runConcrete, runSparse, hc, step.symm]
    | some nextNetwork =>
      simp only [hc, Option.map_some] at step
      simp only [runConcrete, runSparse, hc, step.symm, Option.bind_some]
      exact ih nextNetwork

-- This starts from the given witness and executes every concrete step in order.
theorem global_witness (commands : List (Command N T)) (network : Network N T)
    (final : Sparse N T)
    (h : runSparse commands (abstractNetwork network) = some final) :
    exists finalNetwork, runConcrete commands network = some finalNetwork /\
      abstractNetwork finalNetwork = final := by
  have commute := (run_correct commands network).trans h
  cases hc : runConcrete commands network with
  | none => simp [hc] at commute
  | some finalNetwork =>
    simp only [hc, Option.map_some] at commute
    exact Exists.intro finalNetwork (And.intro rfl (Option.some.inj commute))

theorem arbitrary_initial_witness [Fintype N] (commands : List (Command N T))
    (initial final : Sparse N T)
    (wf : forall destination, WellFormed (initial destination))
    (h : runSparse commands initial = some final) :
    exists finalNetwork, runConcrete commands (realizeNetwork initial) = some finalNetwork /\
      abstractNetwork finalNetwork = final := by
  apply global_witness commands (realizeNetwork initial) final
  simpa [network_realizability initial wf] using h

-- Specialization keeps all 15 source partitions, not just active trace nodes.
example (queue : List (Message CCFRaft.Node Nat)) :
    Finset.univ.sum (fun source : CCFRaft.Node => (partition source queue).length) =
      queue.length :=
  sum_partition_length queue

private def node0 : CCFRaft.Node := Fin.mk 0 (by decide)
private def node1 : CCFRaft.Node := Fin.mk 1 (by decide)

private def selfResponse : AppendEntriesResponse CCFRaft.Node :=
  { term := 1, success := true, lastLogIndex := 0, source := node0, destination := node0 }

private def selfRequest : Message CCFRaft.Node Nat :=
  .appendEntriesRequest
    { term := 1, prevLogIndex := 0, prevLogTerm := 0, entries := [],
      leaderCommit := 0, source := node0, destination := node0 }

private def otherPacket : Message CCFRaft.Node Nat :=
  .appendEntriesResponse
    { term := 1, success := true, lastLogIndex := 0, source := node1, destination := node0 }

example :
    takeFirstFrom node0 [otherPacket, selfRequest, .appendEntriesResponse selfResponse] =
      some (selfRequest, [otherPacket, .appendEntriesResponse selfResponse]) := by
  decide

-- A self-reply checks the queue after removal and retains an existing duplicate.
example :
    (reply (fun _ => [otherPacket, selfRequest, .appendEntriesResponse selfResponse])
      node0 [otherPacket, .appendEntriesResponse selfResponse] selfResponse) node0 =
        [otherPacket, .appendEntriesResponse selfResponse] := by
  decide

-- With no duplicate, the reply appends behind the untouched other-source packet.
example :
    (reply (fun _ => [selfRequest, otherPacket]) node0 [otherPacket] selfResponse) node0 =
      [otherPacket, .appendEntriesResponse selfResponse] := by
  decide


end CCFRaft.Sparse.Queue
