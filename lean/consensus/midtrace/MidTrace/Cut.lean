module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.Replay.Groups
public import Std.Data.HashMap

@[expose] public section

namespace Consensus.MidTrace

deriving instance
  Hashable
for
  Replay.Packet.AppendEntries, Replay.Packet.AppendEntriesResponse, Replay.Packet.RequestVote, Replay.Packet.RequestVoteResponse, Replay.Packet.ProposeRequestVote, Replay.Packet

/-- The groups of a successful strict schedule, in the order it ran them. -/
def scheduleGroups (header : Replay.Header) (queues : Array (Array Replay.Group))
    : Except String (Array Replay.Group) := do
  let (result, groups) := ((Replay.schedule header queues false).run).run #[]
  discard result
  return groups

/-- Split the successful strict schedule, replaying exactly its removed prefix. -/
def cutGroups (header : Replay.Header) (queues : Array (Array Replay.Group)) (cut : Nat)
    : Except String (Model.State × Array Replay.Group × Array Replay.Group) := do
  let groups ← scheduleGroups header queues
  let before := groups.extract 0 cut
  let atCut ← Replay.replayFrom header { state := header.initial } before
  return (atCut.state, before, groups.extract cut groups.size)

/-- A packet on a channel: source, destination and packet. -/
private abbrev Wire := String × String × Replay.Packet

/-- The receive a group starts with, which decides whether it waits. -/
private def firstReceive (g : Replay.Group) : Option Wire :=
  match g.instructions.find? (· matches .action ..) with
  | some (.action (.receive src dst pkt) _) => some (src, dst, pkt)
  | _ => none

/-- The packets a group natively sends. -/
private def sends (g : Replay.Group) : Array Wire :=
  g.instructions.flatMap
    fun
    | .observeSends sends _ => sends.toArray.map fun s => (g.node, s.target, s.packet)
    | _ => #[]

private def bump (counts : Std.HashMap Wire Nat) (w : Wire) (delta : Int)
    : Std.HashMap Wire Nat :=
  counts.insert w (counts.getD w 0 + delta).toNat

/--
Merge queue heads without replay or bootstrap. A backwards clock cannot reorder a queue.
Clocks of different processes may disagree, so a receive waits while no scheduled group
has sent its packet and its sender still sends it later; the packet may otherwise come
from the network at the cut. The earliest ready head runs, then by queue; if every head
waits, as in a cycle, the earliest head runs anyway.
-/
@[no_expose]
def orderGroups (queues : Array (Array Replay.Group)) : Array Replay.Group :=
  Id.run do
    -- Sends of unscheduled groups, and sends of scheduled groups not yet received.
    let mut pending : Std.HashMap Wire Nat := {}
    for q in queues do
      for g in q do
        for w in sends g do
          pending := bump pending w 1
    let mut sent : Std.HashMap Wire Nat := {}
    let mut next := Array.replicate queues.size 0
    let mut ordered := #[]
    for _ in [:queues.foldl (· + ·.size) 0] do
      let mut ready : Option (Nat × Nat × Replay.Group) := none
      let mut any : Option (Nat × Nat × Replay.Group) := none
      for h : i in [:queues.size] do
        if let some g := queues[i][next[i]!]? then
          let time := g.ts.getD g.m_ts
          if any.all (time < ·.1) then any := some (time, i, g)
          let waits :=
            match firstReceive g with
            | some w => sent.getD w 0 == 0 && pending.getD w 0 > 0
            | none => false
          if !waits && ready.all (time < ·.1) then ready := some (time, i, g)
      if let some (_, i, g) := ready.orElse fun _ => any then
        if let some w := firstReceive g then
          if sent.getD w 0 > 0 then sent := bump sent w (-1)
        for w in sends g do
          sent := bump sent w 1
          pending := bump pending w (-1)
        ordered := ordered.push g
        next := next.modify i (· + 1)
    return ordered

/-- Functions that start a group, in a node's events. -/
def groupHeads : List String :=
  [
    "replicate",
    "recv_append_entries",
    "recv_append_entries_response",
    "recv_request_vote",
    "recv_request_vote_response",
    "recv_propose_request_vote",
    "tick",
    "nomination",
    "drop_pending_to",
    "init_as_backup"
  ]

/-- Whether `events` from `start` begins a real bootstrap group (`ruleBootstrap`). -/
def startsBootstrap (events : Array Replay.Event) (start : Nat) : Bool :=
  if events[start]?.map (·.function) != some "become_leader" then
    false
  else
    let i :=
      Id.run do
        let mut i := start + 1
        while h : i < events.size do
          let fn := events[i].function
          if fn == "tick" || fn == "nomination" then i := i + 1 else break
        return i
    events[i]?.map (·.function) == some "replicate"
    && events[i + 1]?.map (·.function) == some "replicate_entry"
    && events[i + 2]?.map (·.function) == some "add_configuration"

/--
Skip a window's leading events that continue a group whose head the window misses; also
the number skipped.
-/
def trimLeadingToGroupHead (events : Array Replay.Event) : Array Replay.Event × Nat :=
  let start :=
    Id.run do
      for h : i in [:events.size] do
        if groupHeads.contains events[i].function || startsBootstrap events i then
          return i
      return events.size
  (events.extract start events.size, start)

end Consensus.MidTrace
