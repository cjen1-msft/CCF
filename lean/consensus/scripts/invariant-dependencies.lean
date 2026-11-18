import Consensus.Properties

/-!
Check that each joint safety theorem uses frame initialization and preservation,
not the old execution invariant. Then print the safety declarations used by all
the public properties. Run from the package directory:

    lake env lean scripts/invariant-dependencies.lean

The output identifies proof declarations needed by the public claims. Source
tactics can also refer to a declaration that disappears during elaboration, so
rebuild after removing declarations absent from this report.
-/

open Lean

private def closure (env : Environment) (roots : Array Name) : NameSet := Id.run do
  let mut pending := roots
  let mut seen : NameSet := {}
  while !pending.isEmpty do
    let name := pending.back!
    pending := pending.pop
    if seen.contains name then continue
    seen := seen.insert name
    let some info := env.find? name | continue
    let expressions :=
      match info with
      | .defnInfo value => #[value.type, value.value]
      | .thmInfo value => #[value.type, value.value]
      | .opaqueInfo value => #[value.type, value.value]
      | _ => #[info.type]
    if let .inductInfo value := info then
      pending := pending ++ value.ctors.toArray
    for expression in expressions do
      pending := pending ++ expression.getUsedConstants
  return seen

run_cmd do
  let env ← getEnv
  for root in #[``Consensus.Properties.election_safety, ``Consensus.Properties.committed_logs_prefix] do
    let names := (closure env #[root]).toArray.map fun n => (privateToUserName? n).getD n
    for required in #[`Consensus.Proofs.Safety.inv_of_reachable, `Consensus.Proofs.Safety.inv_initial,
        `Consensus.Proofs.Safety.Ctx.inv_step] do
      unless names.contains required do throwError "{root}: missing {required}"
    for forbidden in #[`Consensus.Proofs.Safety.Exec, `Consensus.Proofs.Safety.inv_of_exec,
        `Consensus.Proofs.Safety.Historical, `ConsensusCoverage.Historical] do
      if names.any forbidden.isPrefixOf then throwError "{root}: depends on {forbidden}"
    let axioms ← collectAxioms root
    for a in axioms do
      unless #[``propext, ``Quot.sound, ``Classical.choice].contains a do
        throwError "{root}: unexpected axiom {a}"
    liftM <| IO.println s!"{root}: stepwise; axioms {axioms}"
  let roots := env.constants.fold (init := #[]) fun names name info =>
    if name.getPrefix == `Consensus.Properties && info.isTheorem then names.push name else names
  let seen := closure env roots
  for name in seen.toArray.qsort Name.lt do
    if (name.toString.splitOn "Consensus.Proofs.Safety.").length > 1 then
      liftM <| IO.println name
