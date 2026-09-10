import Sparse.IntervalDemandPlan
import Lean.Data.Json

namespace CCFRaft.Sparse.IntervalDemandFixtures

open VersionedIntervals
open IntervalReadback (Demand)
open IntervalDemandPlan

private def repeatedChild : (depth : Nat) -> Graph 1 Nat (depth + 1)
  | 0 => .push .empty (.root 0)
  | depth + 1 =>
    .push (repeatedChild depth) (.splice 0 1 (Fin.last depth) (Fin.last depth))

private def twoRoots (lower upper : Nat) : Graph 3 Nat 3 :=
  .push (.push (.push .empty (.root 0)) (.root 1)) (.splice lower upper 0 1)

private def runCase {roots size : Nat} (label : String) (graph : Graph roots Nat size)
    (requests : List (Demand roots size)) (expected : Nat) (benchmark : Bool) : IO Unit := do
  let start <- if benchmark then IO.monoNanosNow else pure 0
  let forced <- IO.mkRef (plan graph requests).length
  let finish <- if benchmark then IO.monoNanosNow else pure 0
  let count <- forced.get
  if count != expected then
    throw (IO.userError s!"{label}: expected {expected} demands, got {count}")
  let fields := [
    ("case", Lean.toJson label),
    ("versions", Lean.toJson size),
    ("distinct_demands", Lean.toJson count)]
  let fields := if benchmark then fields ++ [("elapsed_ns", Lean.toJson (finish - start))]
    else fields
  IO.println (Lean.Json.mkObj fields).compress
  ( <- IO.getStdout).flush

def run (benchmark : Bool) : IO Unit := do
  for depth in [4, 6, 8, 10, 12, 16, 64, 128, 399] do
    runCase s!"repeated-child-{depth}" (repeatedChild depth)
      [(.version (Fin.last depth), 0)] (depth + 2) benchmark
  runCase "duplicate-and-aliased-positions" (repeatedChild 12)
    [(.version (Fin.last 12), 0), (.version (Fin.last 12), 0),
      (.version (Fin.last 12), 7)] 28 benchmark
  runCase "empty-interval-both-children" (twoRoots 5 5) [(.version 2, 0)] 5 benchmark
  runCase "reversed-interval-both-children" (twoRoots 100 2)
    [(.version 2, 1000000)] 5 benchmark
  runCase "constant-no-roots" (.push (.empty : Graph 3 Nat 0) (.constant 9))
    [(.version 0, 7)] 1 benchmark
  runCase "empty-requests" (repeatedChild 399) [] 0 benchmark
  runCase "unreferenced-root-domain"
    (.push (.empty : Graph 1000000 Nat 0) (.root 500000))
    [(.version 0, 1000000)] 2 benchmark

end CCFRaft.Sparse.IntervalDemandFixtures

def main (args : List String) : IO UInt32 := do
  let benchmark := match args with
    | [] => some false
    | ["--benchmark"] => some true
    | _ => none
  let some benchmark := benchmark |
    ( <- IO.getStderr).putStrLn "usage: IntervalDemandFixtureMain.lean [--benchmark]"
    return 1
  CCFRaft.Sparse.IntervalDemandFixtures.run benchmark
  return 0
