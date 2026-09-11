import Sparse.JointIntervalCompletion
import Lean.Data.Json

namespace CCFRaft.Sparse.JointIntervalFixtures

open VersionedIntervals IntervalReadback JointIntervalCompletion

private def fixture {roots size : Nat} {A : Type} (name : String)
    (graph : Graph roots A size) (queries : List (IntervalQueries.LocalQuery size A))
    (points : List (Demand roots size)) : Lean.Json :=
  Lean.Json.mkObj [
    ("case", Lean.toJson name), ("roots", Lean.toJson roots),
    ("cuts", Lean.toJson (cutList graph queries points).length),
    ("requests", Lean.toJson (requests graph queries points).length),
    ("planned", Lean.toJson (planned graph queries points).length)]

private def firstRoot : Graph 1 Nat 1 := .push .empty (.root 0)

private def twoRoots : Graph 2 Nat 2 :=
  .push (.push .empty (.root 0)) (.root 1)

private def secondQuery : IntervalQueries.LocalQuery 2 Nat where
  lower := 0
  upper := 1
  accepts values := values 1 = 0
  references := [1]
  locality left right agree := by rw [agree 1 (by simp)]

def fixtures : List Lean.Json := [
  fixture "empty" (.empty : Graph 0 Nat 0) [] [],
  fixture "root-version-alias" firstRoot []
    [(.root 0, 17), (.version 0, 17)],
  fixture "repeated-points" firstRoot []
    (List.replicate 400 (.version 0, 1000000)),
  fixture "point-only-many-cuts" firstRoot []
    ((List.range 400).map fun index => (.version 0, 1000000 + index)),
  fixture "query-plus-point-only-reference" twoRoots [secondQuery]
    ((List.range 400).map fun index => (.version 0, 1000000 + index)),
  fixture "million-root-domain" (.empty : Graph 1000000 Nat 0) []
    ((List.range 400).map fun index => (.root 500000, 1000000 + index)),
  fixture "non-equality-cell-type"
    (.push (.empty : Graph 0 (Nat -> Nat) 0) (.constant fun n => n)) []
    [(.version 0, 1)],
  fixture "query-only" twoRoots [secondQuery] []
]

end CCFRaft.Sparse.JointIntervalFixtures

def main : IO Unit := do
  IO.println (Lean.toJson CCFRaft.Sparse.JointIntervalFixtures.fixtures).compress
