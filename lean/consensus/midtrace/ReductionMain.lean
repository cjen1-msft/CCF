module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.Replay.Groups
public import MidTrace.Cut
public import MidTrace.GroupJson
public import MidTrace.StateJson

@[expose] public section

open Consensus Consensus.MidTrace

private def usage :=
  "usage:
  consensus-reduction --trace TRACE.msgpack [--from-cut [--lenient]]
  consensus-reduction true-state TRACE.msgpack N
--trace writes the trace's groups to standard output, one JSON object per line, in strict
schedule order from bootstrap or, with --from-cut, in causal order without bootstrap.
--lenient also drops each node's events before its first group head or after its last group.
true-state writes the model state after the first N groups of the strict schedule.
EXIT CODES: 0 success  2 usage or input error"

private structure Options where
  fromCut : Bool := false
  lenient : Bool := false
  path : Option String := none

private def parse : List String → Options → Except String Options
  | [], o => do
      if o.lenient && !o.fromCut then throw "--lenient requires --from-cut"
      if o.path.isNone then throw usage
      return o
  | "--trace" :: path :: rest, o => do
      if o.path.isSome then throw usage
      parse rest { o with path := some path }
  | "--from-cut" :: rest, o => parse rest { o with fromCut := true }
  | "--lenient" :: rest, o => parse rest { o with lenient := true }
  | arg :: _, _ =>
      if arg.startsWith "--" then throw s!"unknown option {arg}" else throw usage

/-- The declared nodes must be nonempty, named, distinct and sorted. -/
private def validateHeader (header : Replay.Header) : Except String Unit := do
  let declared := header.declared
  if declared.isEmpty then throw "empty capture: no declared nodes"
  unless declared.all (!·.isEmpty) do
    throw "blank node name in capture"
  unless declared.eraseDups == declared do
    throw "declared nodes must be distinct"
  unless declared == declared.mergeSort do
    throw "declared nodes must be sorted lexically"

/--
Read and reduce a trace. With `fromCut` there need be no bootstrap; with `lenient` too,
each node's leading events before its first group head and any events from its first
ungrouped one, such as a group the capture truncates, are dropped and reported.
-/
private def trace (path : String) (fromCut := false) (lenient := false)
    : IO Replay.Reduced := do
  let records ← IO.ofExcept (← Replay.readLog path)
  let (streams, names) ←
    IO.ofExcept (Replay.prepareEvents records (includePacketPeers := fromCut))
  let r ←
    if fromCut && lenient then
      let trimmed := streams.map trimLeadingToGroupHead
      let r ←
        IO.ofExcept
          (Replay.reduce (trimmed.map (·.1)) names (lenient := true)
            (requireBootstrap := false))
      for ((stream, events, leading), (total, consumed))
          in (streams.zip trimmed).zip r.events do
        let some first := stream[0]? | continue
        if leading > 0 then
          IO.eprintln s!"lenient: node '{first.node}': dropped {leading} leading events"
        if consumed < total then
          let location := events[consumed]!.record.location
          IO.eprintln
            s!"lenient: node '{first.node}': dropped {total - consumed} trailing events from {location}"
      pure r
    else
      IO.ofExcept (Replay.reduce streams names (requireBootstrap := !fromCut))
  IO.ofExcept (validateHeader r.header)
  return r

@[no_expose]
def main (args : List String) : IO UInt32 := do
  try
    match args with
    | ["true-state", path, k] =>
        let r ← trace path
        let some cut := k.toNat? | throw
                                    (IO.userError
                                      s!"expected a natural number, got '{k}'")
        let groups ← IO.ofExcept (scheduleGroups r.header r.queues)
        if cut > groups.size then
          throw (IO.userError s!"cut {cut} exceeds {groups.size} groups")
        let atCut ←
          IO.ofExcept
            (Replay.replayFrom r.header { state := r.header.initial }
              (groups.extract 0 cut))
        IO.println (encodeState r.header atCut.state).compress
        return 0
    | _ =>
        let o ← IO.ofExcept (parse args {})
        let some path := o.path | throw (IO.userError usage)
        let r ← trace path o.fromCut o.lenient
        let groups ←
          if o.fromCut then
            pure (orderGroups r.queues)
          else
            IO.ofExcept (scheduleGroups r.header r.queues)
        let out ← IO.getStdout
        try
          for group in groups do
            out.putStrLn (encodeGroup r.header group).compress
          out.flush
        catch
          | .resourceVanished .. => return 0
          | e => throw e
        return 0
  catch e =>
    IO.eprintln (toString e); return 2
