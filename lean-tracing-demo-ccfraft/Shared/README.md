# Shared trace infrastructure

This directory contains code that does not depend on CCFRaft reduction rules.
It parses captured events, represents reduced traces and formulas, invokes
cvc5, and records solver artifacts.

Model-specific preprocessing and reduction rules stay in `Reduction.lean` and
`reduction.py`.
