# Shared trace infrastructure

This directory contains code that does not depend on CCFRaft reduction rules.
It parses captured events, represents reduced traces and formulas, invokes
cvc5, and records solver artifacts.

Model-specific preprocessing and reduction rules stay in `reduction.py`.

`Smt.lean` defines the shared symbolic expressions, their meaning, and the
trusted SMT-LIB serializer used by the checked trace encoder.
`SmtOrder.lean` provides a computable structural ordering for symbolic terms,
so finite sets can be enumerated without an unexecutable choice operation.
`Equality.lean` lifts an exact symbolic equality into equality of finite lists.
`Guarded.lean` represents symbolic choices and proves evaluation, composition,
and equality-sensitive queue operations. Branch-specific named values require
distinct binding slots.
`smt.py` contains generic solver-query and core-reduction utilities.
The legacy, CCF-specific projected encoding lives in `../ccfraft_projection.py`.
