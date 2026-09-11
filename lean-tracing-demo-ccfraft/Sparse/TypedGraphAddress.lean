import Sparse.TypedIntervalEncoding

set_option autoImplicit false

namespace CCFRaft.Sparse.TypedGraphAddress

open Smt (Assignment Term Symbol)
open TypedIntervalEncoding (SymbolicGraph interpret)
open IntervalReadback (Address lookup actual)
open VersionedIntervals (Version RootArrays evaluate)

abbrev Graph (roots size : Nat) := SymbolicGraph roots .entry size

variable {roots size prior : Nat}

def rootTag (node : Version roots (Term .entry) prior) : Option (Fin roots) :=
  match node with
  | .root root => some root
  | .constant _ | .splice _ _ _ _ => none

theorem rootTag_eq (node : Version roots (Term .entry) prior) (root : Fin roots) :
    rootTag node = some root <-> node = .root root := by
  cases node <;> simp [rootTag]

-- Scan newest first. The result is an existing syntactic root node, not a value alias.
def findRoot : {size : Nat} -> Graph roots size -> Fin roots -> Option (Fin size)
  | _, .empty, _ => none
  | _, .push previous node, root =>
    if rootTag node = some root then some (Fin.last _)
    else (findRoot previous root).map Fin.castSucc

theorem findRoot_sound (graph : Graph roots size) (root : Fin roots) :
    forall version, findRoot graph root = some version -> lookup graph version = .root root := by
  induction graph with
  | empty => intro version; exact Fin.elim0 version
  | push previous node ih =>
    intro version found
    by_cases hit : rootTag node = some root
    next =>
      have same := (rootTag_eq node root).mp hit
      simp only [findRoot, if_pos hit, Option.some.injEq] at found
      subst version
      simpa only [lookup, Fin.lastCases_last] using same
    next =>
      cases earlier : findRoot previous root with
      | none => simp [findRoot, hit, earlier] at found
      | some old =>
        simp only [findRoot, if_neg hit, earlier, Option.map_some, Option.some.injEq] at found
        subst version
        simpa only [lookup, Fin.lastCases_castSucc] using ih old earlier

theorem findRoot_none_iff (graph : Graph roots size) (root : Fin roots) :
    findRoot graph root = none <-> forall version, Not (lookup graph version = .root root) := by
  induction graph with
  | empty => simp [findRoot]
  | @push prior previous node ih =>
    by_cases hit : rootTag node = some root
    next =>
      have same := (rootTag_eq node root).mp hit
      constructor
      next => intro absent; simp [findRoot, hit] at absent
      next =>
        intro absent
        exact False.elim (absent (Fin.last prior) (by simpa only [lookup, Fin.lastCases_last] using same))
    next =>
      constructor
      next =>
        intro absent version
        have old_none : findRoot previous root = none := by
          simpa only [findRoot, if_neg hit, Option.map_eq_none_iff] using absent
        refine Fin.lastCases ?_ (fun old => ?_) version
        next => simpa only [lookup, Fin.lastCases_last, <- rootTag_eq] using hit
        next => simpa only [lookup, Fin.lastCases_castSucc] using (ih.mp old_none) old
      next =>
        intro absent
        have old_none := ih.mpr (fun old => by
          simpa only [lookup, Fin.lastCases_castSucc] using absent old.castSucc)
        simp [findRoot, hit, old_none]

structure Resolution (roots oldSize : Nat) where
  newSize : Nat
  graph : Graph roots newSize
  oldSize_le : oldSize <= newSize
  version : Fin newSize

def resolve (graph : Graph roots size) : Address roots size -> Resolution roots size
  | .version version => { newSize := size, graph, oldSize_le := Nat.le_refl _, version }
  | .root root =>
    match findRoot graph root with
    | some version => { newSize := size, graph, oldSize_le := Nat.le_refl _, version }
    | none =>
      { newSize := size + 1
        graph := .push graph (.root root)
        oldSize_le := Nat.le_succ _
        version := Fin.last size }

theorem resolve_version (graph : Graph roots size) (version : Fin size) :
    resolve graph (.version version) =
      { newSize := size, graph, oldSize_le := Nat.le_refl _, version } := rfl

theorem resolve_root_found (graph : Graph roots size) (root : Fin roots) (version : Fin size)
    (found : findRoot graph root = some version) :
    resolve graph (.root root) =
      { newSize := size, graph, oldSize_le := Nat.le_refl _, version } := by
  simp [resolve, found]

theorem resolve_root_missing (graph : Graph roots size) (root : Fin roots)
    (missing : findRoot graph root = none) :
    resolve graph (.root root) =
      { newSize := size + 1
        graph := .push graph (.root root)
        oldSize_le := Nat.le_succ _
        version := Fin.last size } := by
  simp [resolve, missing]

theorem size_bound (graph : Graph roots size) (address : Address roots size) :
    (resolve graph address).newSize <= size + 1 := by
  cases address with
  | version version => exact Nat.le_succ _
  | root root => cases found : findRoot graph root <;> simp [resolve, found]

theorem old_lookup (graph : Graph roots size) (address : Address roots size) (version : Fin size) :
    lookup (resolve graph address).graph (Fin.castLE (resolve graph address).oldSize_le version) =
      lookup graph version := by
  cases address with
  | version selected => rfl
  | root root =>
    cases found : findRoot graph root with
    | some selected => rw [resolve_root_found graph root selected found]; rfl
    | none =>
      rw [resolve_root_missing graph root found]
      change lookup (.push graph (.root root)) version.castSucc = lookup graph version
      simp only [lookup, Fin.lastCases_castSucc]

theorem old_values (assignment : Assignment) (graph : Graph roots size) (address : Address roots size)
    (arrays : RootArrays roots EntryValue.Entry) (position : Nat) (version : Fin size) :
    evaluate (interpret assignment (resolve graph address).graph) arrays position
        (Fin.castLE (resolve graph address).oldSize_le version) =
      evaluate (interpret assignment graph) arrays position version := by
  cases address with
  | version selected => rfl
  | root root =>
    cases found : findRoot graph root with
    | some selected => rw [resolve_root_found graph root selected found]; rfl
    | none =>
      rw [resolve_root_missing graph root found]
      change evaluate (interpret assignment (.push graph (.root root))) arrays position version.castSucc = _
      simp only [interpret, evaluate, VersionedIntervals.Graph.values, Fin.snoc_castSucc]

theorem resolved_value (assignment : Assignment) (graph : Graph roots size) (address : Address roots size)
    (arrays : RootArrays roots EntryValue.Entry) (position : Nat) :
    evaluate (interpret assignment (resolve graph address).graph) arrays position
        (resolve graph address).version =
      actual (interpret assignment graph) arrays address position := by
  cases address with
  | version version => rfl
  | root root =>
    cases found : findRoot graph root with
    | some version =>
      rw [resolve_root_found graph root version found]
      change evaluate (interpret assignment graph) arrays position version = arrays root position
      unfold evaluate
      rw [IntervalReadback.values_lookup, TypedIntervalEncoding.lookup_interpret,
        findRoot_sound graph root version found]
      rfl
    | none =>
      rw [resolve_root_missing graph root found]
      change evaluate (interpret assignment (.push graph (.root root))) arrays position (Fin.last size) = _
      simp only [interpret, evaluate, VersionedIntervals.Graph.values, Fin.snoc_last,
        TypedIntervalEncoding.interpretNode, Version.value, actual]

def nodeSymbols : Version roots (Term .entry) prior -> List Symbol
  | .root _ => []
  | .constant term => SmtScript.termSymbols term
  | .splice lower upper _ _ => [.constant .int lower, .constant .int upper]

def sourceSymbols : {size : Nat} -> Graph roots size -> List Symbol
  | _, .empty => []
  | _, .push previous node => sourceSymbols previous ++ nodeSymbols node

theorem nodeMax_eq_symbols (node : Version roots (Term .entry) prior) :
    TypedIntervalEncoding.nodeMax node = (nodeSymbols node).toFinset.sup SymbolBounds.symbolId := by
  cases node <;>
    simp [TypedIntervalEncoding.nodeMax, nodeSymbols, SymbolBounds.termMax_correct,
      SymbolBounds.symbolId]

theorem graphMax_eq_sourceSymbols (graph : Graph roots size) :
    TypedIntervalEncoding.graphMax graph = (sourceSymbols graph).toFinset.sup SymbolBounds.symbolId := by
  induction graph with
  | empty => simp [TypedIntervalEncoding.graphMax, sourceSymbols]
  | push previous node ih =>
    simp only [TypedIntervalEncoding.graphMax, sourceSymbols, List.toFinset_append,
      Finset.sup_union, ih, nodeMax_eq_symbols]

theorem endpoints_preserved (graph : Graph roots size) (address : Address roots size) :
    (resolve graph address).graph.endpoints = graph.endpoints := by
  cases address with
  | version version => rfl
  | root root =>
    cases found : findRoot graph root with
    | some version => rw [resolve_root_found graph root version found]
    | none =>
      rw [resolve_root_missing graph root found]
      simp [VersionedIntervals.Graph.endpoints, Version.endpoints]

theorem sourceSymbols_preserved (graph : Graph roots size) (address : Address roots size) :
    sourceSymbols (resolve graph address).graph = sourceSymbols graph := by
  cases address with
  | version version => rfl
  | root root =>
    cases found : findRoot graph root with
    | some version => rw [resolve_root_found graph root version found]
    | none =>
      rw [resolve_root_missing graph root found]
      simp [sourceSymbols, nodeSymbols]

theorem graphMax_preserved (graph : Graph roots size) (address : Address roots size) :
    TypedIntervalEncoding.graphMax (resolve graph address).graph =
      TypedIntervalEncoding.graphMax graph := by
  rw [graphMax_eq_sourceSymbols, sourceSymbols_preserved, <- graphMax_eq_sourceSymbols]

namespace Regression

theorem empty_canonical :
    let result := resolve (.empty : Graph 1 0) (.root 0)
    result.newSize = 1 /\ result.version.val = 0 /\
      rootTag (lookup result.graph result.version) = some 0 := by
  decide +kernel

theorem nonzero_root_from_empty :
    let result := resolve (.empty : Graph 22 0) (.root 7)
    result.newSize = 1 /\ result.version.val = 0 /\
      rootTag (lookup result.graph result.version) = some 7 := by
  decide +kernel

def priorRoots : Graph 22 3 :=
  .push (.push (.push .empty (.root 4)) (.root 7)) (.root 4)

theorem prior_roots_and_newest_alias :
    findRoot priorRoots 4 = some 2 /\ findRoot priorRoots 7 = some 1 /\
      findRoot priorRoots 21 = none /\
      (resolve priorRoots (.root 4)).newSize = 3 /\
      (resolve priorRoots (.root 4)).version.val = 2 /\
      (resolve priorRoots (.root 7)).version.val = 1 := by
  decide +kernel

theorem missing_root_appended_once :
    let first := resolve priorRoots (.root 21)
    let again := resolve first.graph (.root 21)
    first.newSize = 4 /\ first.version.val = 3 /\
      rootTag (lookup first.graph first.version) = some 21 /\
      again.newSize = 4 /\ again.version.val = 3 := by
  decide +kernel

theorem version_retains_graph_and_id :
    resolve priorRoots (.version 0) =
      { newSize := 3, graph := priorRoots, oldSize_le := Nat.le_refl _, version := 0 } := rfl

theorem unrelated_old_version (assignment : Assignment)
    (arrays : RootArrays 22 EntryValue.Entry) (position : Nat) :
    evaluate (interpret assignment (resolve priorRoots (.root 21)).graph) arrays position
        (Fin.castLE (resolve priorRoots (.root 21)).oldSize_le (1 : Fin 3)) =
      arrays 7 position := by
  rw [old_values]
  rfl

def metadataGraph : Graph 22 3 :=
  .push (.push (.push .empty (.root 7))
    (.constant (.app .nodes .entry 9001
      (.configurationNodes (.app .int .content 8001 (.unknown .int 7001))))))
    (.splice 6001 6002 0 1)

theorem unused_high_metadata :
    sourceSymbols metadataGraph =
      [.unary .nodes .entry 9001, .unary .int .content 8001, .constant .int 7001,
        .constant .int 6001, .constant .int 6002] /\
      metadataGraph.endpoints = [6001, 6002] /\
      TypedIntervalEncoding.graphMax metadataGraph = 9001 /\
      sourceSymbols (resolve metadataGraph (.root 21)).graph = sourceSymbols metadataGraph /\
      (resolve metadataGraph (.root 21)).graph.endpoints = [6001, 6002] /\
      TypedIntervalEncoding.graphMax (resolve metadataGraph (.root 21)).graph = 9001 := by
  decide +kernel

theorem reused_root_keeps_unused_metadata :
    (resolve metadataGraph (.root 7)).newSize = 3 /\
      (resolve metadataGraph (.root 7)).version.val = 0 /\
      TypedIntervalEncoding.graphMax (resolve metadataGraph (.root 7)).graph = 9001 := by
  decide +kernel

theorem version_retains_nonroot_id :
    resolve metadataGraph (.version 2) =
      { newSize := 3, graph := metadataGraph, oldSize_le := Nat.le_refl _, version := 2 } := rfl

theorem unused_metadata_requires_no_domains (assignment : Assignment)
    (arrays : RootArrays 22 EntryValue.Entry) (position : Nat) :
    evaluate (interpret assignment (resolve metadataGraph (.root 21)).graph) arrays position
        (resolve metadataGraph (.root 21)).version =
      arrays 21 position := by
  exact resolved_value assignment metadataGraph (.root 21) arrays position

theorem unrelated_constant_preserved (assignment : Assignment)
    (arrays : RootArrays 22 EntryValue.Entry) (position : Nat) :
    evaluate (interpret assignment (resolve metadataGraph (.root 21)).graph) arrays position
        (Fin.castLE (resolve metadataGraph (.root 21)).oldSize_le (1 : Fin 3)) =
      assignment.unary .nodes .entry 9001
        ((Term.configurationNodes (.app .int .content 8001 (.unknown .int 7001))).eval assignment) := by
  rw [old_values]
  rfl

theorem nonroot_nodes_are_not_root_tags :
    rootTag (.constant (.unknown .entry 7) : Version 22 (Term .entry) 3) = none /\
      rootTag (.splice 0 0 0 0 : Version 22 (Term .entry) 3) = none := by
  decide +kernel

end Regression

end CCFRaft.Sparse.TypedGraphAddress

run_cmd do
  let mut checked := 0
  for (name, info) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.Sparse.TypedGraphAddress).isPrefixOf name then
      if let .axiomInfo _ := info then
        throwError "explicit axiom declaration: {name}"
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
      checked := checked + 1
  Lean.logInfo m!"Sparse.TypedGraphAddress: allowed-axiom gate passed for {checked} declarations."

#print axioms CCFRaft.Sparse.TypedGraphAddress.findRoot_none_iff
#print axioms CCFRaft.Sparse.TypedGraphAddress.old_values
#print axioms CCFRaft.Sparse.TypedGraphAddress.resolved_value
#print axioms CCFRaft.Sparse.TypedGraphAddress.sourceSymbols_preserved
