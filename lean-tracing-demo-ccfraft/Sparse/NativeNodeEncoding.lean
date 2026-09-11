-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeQuorumEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem stored_read_correct {sort : Ty} (assignment : Assignment)
    (before after node peer : Nat) (default value : Expr sort)
    (present : (allocated node : Expr .bool).eval assignment Locals.empty = true)
    (binding : (Term.equal (.free (.array .int sort) after)
      (.store (.free (.array .int sort) before) (.integer node) value)).eval
        assignment Locals.empty = true) :
    (read after peer default).eval assignment Locals.empty =
      if peer = node then value.eval assignment Locals.empty
      else (read before peer default).eval assignment Locals.empty := by
  simp only [Term.eval, decide_eq_true_eq] at binding
  simp only [allocated, Term.eval] at present
  by_cases same : peer = node
  · subst peer
    simp [read, allocated, Term.eval, binding, present]
  · have different : (peer : Int) ≠ (node : Int) := by exact_mod_cast same
    simp [read, allocated, Term.eval, binding, same, different]

theorem get_step {width : PNat} (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat)
    (node peer : Fin width) :
    NativeArrayCheckQuorum.get (NativeArrayCheckQuorum.step arrays node) peer =
      if peer = node then
        { NativeArrayCheckQuorum.get arrays node with role := .follower, isNewFollower := true }
      else NativeArrayCheckQuorum.get arrays peer := by
  by_cases same : peer = node
  · subst peer
    simp [NativeArrayCheckQuorum.get, NativeArrayCheckQuorum.step]
  · simp [NativeArrayCheckQuorum.get, NativeArrayCheckQuorum.step, same]

structure NodeColumnsRep {width : PNat} (assignment : Assignment) (columns : NodeColumns)
    (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat) : Prop where
  allocated : forall (node : Fin width), (NativeEncode.allocated node.val : Expr .bool).eval assignment Locals.empty =
    (arrays node).isSome
  role : forall (node : Fin width), (read columns.role node.val (.integer 0)).eval assignment Locals.empty =
    roleCode (NativeArrayCheckQuorum.get arrays node).role
  newFollower : forall (node : Fin width), (read columns.newFollower node.val (.boolean true)).eval assignment Locals.empty =
    (NativeArrayCheckQuorum.get arrays node).isNewFollower
  currentTerm : forall (node : Fin width), (read 5 node.val (.integer 0)).eval assignment Locals.empty =
    ((NativeArrayCheckQuorum.get arrays node).currentTerm : Int)
  commit : forall (node : Fin width), (NativeEncode.commit node.val : Expr .int).eval assignment Locals.empty =
    ((NativeArrayCheckQuorum.get arrays node).commit : Int)
  length : forall (node : Fin width), (NativeEncode.length node.val : Expr .int).eval assignment Locals.empty =
    ((NativeArrayCheckQuorum.get arrays node).log.length : Int)
  entries : forall (node : Fin width) (index : Nat), index < (NativeArrayCheckQuorum.get arrays node).log.length ->
    modelEntry ((entryAt width node.val (.integer index) : Expr (entryTy width)).eval assignment Locals.empty) =
      (NativeArrayCheckQuorum.get arrays node).log.entries index

theorem NodeColumnsRep.configuration_log {width : PNat} {assignment : Assignment}
    {columns : NodeColumns} {arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat}
    (rep : NodeColumnsRep assignment columns arrays) (node : Fin width) :
    ConfigurationLogRep assignment node.val (NativeArrayCheckQuorum.get arrays node).log
      (NativeArrayCheckQuorum.get arrays node).commit := by
  refine ⟨rep.length node, rep.commit node, ?_⟩
  intro index within
  have entry := congrArg Entry.content (rep.entries node index within)
  simpa [modelEntry, entryAt, Term.eval] using entry

theorem NodeColumnsRep.set_integer {width : PNat} {assignment : Assignment}
    {columns : NodeColumns} {arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat}
    (rep : NodeColumnsRep assignment columns arrays) (id : Nat) (value : Int) :
    NodeColumnsRep (assignment.set .int id value) columns arrays := by
  constructor
  · intro node
    simpa [NativeEncode.allocated, Term.eval, Assignment.set] using rep.allocated node
  · intro node
    simpa [read, NativeEncode.allocated, Term.eval, Assignment.set] using rep.role node
  · intro node
    simpa [read, NativeEncode.allocated, Term.eval, Assignment.set] using rep.newFollower node
  · intro node
    simpa [read, NativeEncode.allocated, Term.eval, Assignment.set] using rep.currentTerm node
  · intro node
    simpa [NativeEncode.commit, read, NativeEncode.allocated, Term.eval, Assignment.set] using rep.commit node
  · intro node
    simpa [NativeEncode.length, read, NativeEncode.allocated, Term.eval, Assignment.set] using rep.length node
  · intro node index within
    simpa [entryAt, Term.eval, Assignment.set] using rep.entries node index within

theorem node_columns_enabled {width : PNat} [Bootstrap (Fin width)]
    (assignment : Assignment) (bootstrap : BitVec width) (columns : NodeColumns)
    (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat) (node : Fin width)
    (currentId witnessId : Nat) (different : currentId ≠ witnessId)
    (rep : NodeColumnsRep assignment columns arrays)
    (sameBootstrap : decodeBits bootstrap = INITIAL_CONFIGURATION) :
    (exists (currentValue : Int) (witnessValue : Int),
      Holds (leadingGuards columns.role node.val ++
        configurationGuards width bootstrap node.val currentId witnessId)
        ((assignment.set .int currentId currentValue).set .int witnessId witnessValue)) <->
      NativeArrayCheckQuorum.enabled arrays node := by
  simp only [Holds, leadingGuards, configurationGuards, List.mem_append, List.mem_cons,
    List.not_mem_nil, or_false, or_imp, forall_and, forall_eq, and_assoc]
  constructor
  · rintro ⟨currentValue, witnessValue, allocatedNode, leader, candidate, latest, other⟩
    have extended := (rep.set_integer currentId currentValue).set_integer witnessId witnessValue
    have allocatedModel : (arrays node).isSome = true := (extended.allocated node).symm.trans allocatedNode
    have leaderModel : (NativeArrayCheckQuorum.get arrays node).role = .leader := by
      apply (role_code_leader _).mp
      simpa only [leaderGuard, Term.eval, decide_eq_true_eq, extended.role] using leader
    refine ⟨allocatedModel, leaderModel, ?_⟩
    exact (configuration_guards_exists_correct assignment bootstrap node currentId witnessId different
      (NativeArrayCheckQuorum.get arrays node).log (NativeArrayCheckQuorum.get arrays node).commit
      (rep.configuration_log node) sameBootstrap).mp ⟨currentValue, witnessValue, candidate, latest, other⟩
  · rintro ⟨allocatedModel, leaderModel, configuration⟩
    obtain ⟨currentValue, witnessValue, candidate, latest, other⟩ :=
      (configuration_guards_exists_correct assignment bootstrap node currentId witnessId different
        (NativeArrayCheckQuorum.get arrays node).log (NativeArrayCheckQuorum.get arrays node).commit
        (rep.configuration_log node) sameBootstrap).mpr configuration
    have extended := (rep.set_integer currentId currentValue).set_integer witnessId witnessValue
    refine ⟨currentValue, witnessValue, (extended.allocated node).trans allocatedModel, ?_,
      candidate, latest, other⟩
    simp only [leaderGuard, Term.eval, decide_eq_true_eq, extended.role, leaderModel, roleCode]

theorem node_columns_model_enabled {width : PNat} [Bootstrap (Fin width)]
    (assignment : Assignment) (bootstrap : BitVec width) (columns : NodeColumns)
    (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat) (model : State (Fin width) Nat)
    (node : Fin width) (currentId witnessId : Nat) (different : currentId ≠ witnessId)
    (rep : NodeColumnsRep assignment columns arrays)
    (modelRep : NativeArrayCheckQuorum.Rep arrays model)
    (sameBootstrap : decodeBits bootstrap = INITIAL_CONFIGURATION) :
    (exists (currentValue : Int) (witnessValue : Int),
      Holds (leadingGuards columns.role node.val ++
        configurationGuards width bootstrap node.val currentId witnessId)
        ((assignment.set .int currentId currentValue).set .int witnessId witnessValue)) <->
      CCFRaft.Enabled model (.checkQuorum node) :=
  (node_columns_enabled assignment bootstrap columns arrays node currentId witnessId
    different rep sameBootstrap).trans (NativeArrayCheckQuorum.enabled_correct arrays model modelRep node)

theorem node_columns_step {width : PNat} (assignment : Assignment)
    (before : NodeColumns) (afterRole afterFollower : Nat)
    (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat) (node : Fin width)
    (rep : NodeColumnsRep assignment before arrays)
    (present : (arrays node).isSome = true)
    (roleBinding : (Term.equal (.free (.array .int .int) afterRole)
      (stepDownRole before.role node.val)).eval
        assignment Locals.empty = true)
    (followerBinding : (Term.equal (.free (.array .int .bool) afterFollower)
      (stepDownFollower before.newFollower node.val)).eval
        assignment Locals.empty = true) :
    NodeColumnsRep assignment { before with role := afterRole, newFollower := afterFollower }
      (NativeArrayCheckQuorum.step arrays node) := by
  simp only [stepDownRole] at roleBinding
  simp only [stepDownFollower] at followerBinding
  have allocatedNode : (allocated node.val : Expr .bool).eval assignment Locals.empty = true :=
    (rep.allocated node).trans present
  constructor
  · intro peer
    by_cases same : peer = node
    · subst peer
      simpa [NativeArrayCheckQuorum.step] using allocatedNode
    · simpa [NativeArrayCheckQuorum.step, same] using rep.allocated peer
  · intro peer
    rw [stored_read_correct assignment before.role afterRole node.val peer.val
      (.integer 0) (.integer 1) allocatedNode roleBinding, get_step]
    by_cases same : peer = node
    · subst peer
      simp [Term.eval, roleCode]
    · have different : peer.val ≠ node.val := fun equal => same (Fin.ext equal)
      simpa [same, different] using rep.role peer
  · intro peer
    rw [stored_read_correct assignment before.newFollower afterFollower node.val peer.val
      (.boolean true) (.boolean true) allocatedNode followerBinding, get_step]
    by_cases same : peer = node
    · subst peer
      simp [Term.eval]
    · have different : peer.val ≠ node.val := fun equal => same (Fin.ext equal)
      simpa [same, different] using rep.newFollower peer
  · intro peer
    have previous := rep.currentTerm peer
    rw [get_step]
    by_cases same : peer = node <;> simp_all
  · intro peer
    have previous := rep.commit peer
    rw [get_step]
    by_cases same : peer = node <;> simp_all
  · intro peer
    have previous := rep.length peer
    rw [get_step]
    by_cases same : peer = node <;> simp_all
  · intro peer index within
    rw [get_step] at within ⊢
    by_cases same : peer = node
    · subst peer
      simpa using rep.entries node index (by simpa using within)
    · simpa [same] using rep.entries peer index (by simpa [same] using within)

theorem node_columns_model_step {width : PNat} [Bootstrap (Fin width)]
    (assignment : Assignment) (before : NodeColumns) (afterRole afterFollower : Nat)
    (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat) (model : State (Fin width) Nat)
    (node : Fin width) (rep : NodeColumnsRep assignment before arrays)
    (modelRep : NativeArrayCheckQuorum.Rep arrays model) (present : (arrays node).isSome = true)
    (roleBinding : (Term.equal (.free (.array .int .int) afterRole)
      (stepDownRole before.role node.val)).eval assignment Locals.empty = true)
    (followerBinding : (Term.equal (.free (.array .int .bool) afterFollower)
      (stepDownFollower before.newFollower node.val)).eval assignment Locals.empty = true) :
    NodeColumnsRep assignment { before with role := afterRole, newFollower := afterFollower }
      (NativeArrayCheckQuorum.step arrays node) /\
      NativeArrayCheckQuorum.Rep (NativeArrayCheckQuorum.step arrays node)
        (CCFRaft.next model (.checkQuorum node)) :=
  ⟨node_columns_step assignment before afterRole afterFollower arrays node rep present
      roleBinding followerBinding,
    NativeArrayCheckQuorum.step_correct arrays model modelRep node⟩

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
