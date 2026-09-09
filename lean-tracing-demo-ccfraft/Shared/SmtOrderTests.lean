-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Shared.SmtOrder

set_option autoImplicit false

namespace TraceSmt.NatTermOrderTests

abbrev Term := NatTerm 3

def u0 : Term := .unknown ⟨0, by decide⟩
def u1 : Term := .unknown ⟨1, by decide⟩

def nested : Term :=
  .add
    (.add (.literal 8) u1)
    (.named 2 4 "nested" (.add u0 (.literal 13)))

def representative : Finset Term := {
  .literal 2,
  .literal 1,
  u1,
  u0,
  .named 1 7 "b" (.literal 0),
  .named 1 7 "a" (.literal 1),
  .named 1 7 "a" (.literal 0),
  .add u0 (.literal 3),
  nested
}

def sortedRepresentative : List Term :=
  representative.sort (fun left right => left <= right)

#guard sortedRepresentative.length == representative.card
#guard sortedRepresentative.Pairwise (fun left right => left <= right)
#guard sortedRepresentative == [
  .literal 1,
  .literal 2,
  u0,
  u1,
  .add u0 (.literal 3),
  nested,
  .named 1 7 "a" (.literal 0),
  .named 1 7 "a" (.literal 1),
  .named 1 7 "b" (.literal 0)
]
#guard (.named 1 7 "a" (.literal 0) : Term) ∈ sortedRepresentative
#guard (.named 1 7 "a" (.literal 1) : Term) ∈ sortedRepresentative
#guard (.named 1 7 "b" (.literal 0) : Term) ∈ sortedRepresentative
#guard nested ∈ sortedRepresentative

example (term : Term) :
    term ∈ representative.sort (fun left right => left <= right) <->
      term ∈ representative := by
  exact Finset.mem_sort (fun left right : Term => left <= right)

end TraceSmt.NatTermOrderTests
