# Machine-checked proof machinery

An agent may overwrite this directory.

Lean checks the theorem bodies in this directory. Manual review focuses on the
definitions and theorem statements in the parent directory instead.

The directory name is historical: files need not be produced by a generator.
Compiling an implementation is not enough to establish its correctness.
The checked trace encoder must inhabit the reviewed
`BoundedTrace.VerifiedEncoder` type. Its proof field connects the
executable encoder to the model contract for every supported entry, trace,
bound, and assignment.

Runtime utilities in this directory do not acquire that guarantee merely
because they compile. The reviewed `EncodeTrace.lean` entry point
enforces the encoder type and rejects unapproved proof axioms.
