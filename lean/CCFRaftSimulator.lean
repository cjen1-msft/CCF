-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Simulation
import CCFRaft.Slice25Simulation
import CCFRaft.Slice3Simulation

open CCFRaft.Simulation

/-- Command-line usage text for simulation and deterministic replay. -/
def usage : String :=
  "usage:\n  ccf-raft-simulator simulate [duration-ms] [seed] [max-depth]\n  ccf-raft-simulator replay <trace-file>\n  ccf-raft-simulator simulate25 [duration-ms] [seed] [max-depth]\n  ccf-raft-simulator replay25 <trace-file>\n  ccf-raft-simulator simulate3 [duration-ms] [seed] [max-depth]\n  ccf-raft-simulator replay3 <trace-file>"

/-- Parse an optional natural-number argument, using a default on failure. -/
def parseNatOr (raw : Option String) (fallback : Nat) : Nat :=
  raw.bind String.toNat? |>.getD fallback

/-- Dispatch the compiled simulator's `simulate` and `replay` subcommands. -/
def main (args : List String) : IO UInt32 := do
  match args with
  | "simulate" :: rest =>
      let durationMs := parseNatOr rest[0]? 5000
      let seed := parseNatOr rest[1]? 1
      let maxDepth := parseNatOr rest[2]? 1000
      simulate durationMs seed maxDepth
  | ["replay", path] =>
      replayFile path
  | "simulate25" :: rest =>
      let durationMs := parseNatOr rest[0]? 5000
      let seed := parseNatOr rest[1]? 1
      let maxDepth := parseNatOr rest[2]? 1000
      CCFRaft.Slice25.Simulation.simulate durationMs seed maxDepth
  | ["replay25", path] =>
      CCFRaft.Slice25.Simulation.replayFile path
  | "simulate3" :: rest =>
      let durationMs := parseNatOr rest[0]? 5000
      let seed := parseNatOr rest[1]? 1
      let maxDepth := parseNatOr rest[2]? 1000
      CCFRaft.Slice3.Simulation.simulate durationMs seed maxDepth
  | ["replay3", path] =>
      CCFRaft.Slice3.Simulation.replayFile path
  | _ =>
      IO.eprintln usage
      return 2
