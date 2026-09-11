import Sparse.NativeNodeOperations

set_option autoImplicit false

namespace CCFRaft.Sparse.NativeNodeSets

open Smt SmtScript NodeSetCodec NativeNodeOperations

def union (left right : Term .nodes) : Term .nodes := .nodesOr left right
def intersection (left right : Term .nodes) : Term .nodes := .nodesAnd left right
def difference (left right : Term .nodes) : Term .nodes := .nodesAnd left (.nodesNot right)
def insert (node : Node) (value : Term .nodes) : Term .nodes :=
  union (.nodes (encodeNodes {node})) value
def erase (node : Node) (value : Term .nodes) : Term .nodes :=
  difference value (.nodes (encodeNodes {node}))
def nonempty (value : Term .nodes) : Term .bool := .not (.equal value (.nodes 0))
def subset (left right : Term .nodes) : Term .bool := .equal (intersection left right) left

def sumTerms : List (Term .int) -> Term .int
  | [] => .integer 0
  | value :: rest => .add value (sumTerms rest)

def unionTerms : List (Term .nodes) -> Term .nodes
  | [] => .nodes 0
  | value :: rest => union value (unionTerms rest)

def cardinality (value : Term .nodes) : Term .int :=
  sumTerms (List.ofFn fun node : Node => .ite (member node value) (.integer 1) (.integer 0))

def majority (support configuration : Term .nodes) : Term .bool :=
  let hits := cardinality (intersection support configuration)
  .not (.le (.add hits hits) (cardinality configuration))

def filter (value : Term .nodes) (predicate : Node -> Term .bool) : Term .nodes :=
  intersection value (unionTerms (List.ofFn fun node : Node =>
    .ite (predicate node) (.nodes (encodeNodes {node})) (.nodes 0)))

theorem union_eval (assignment : Assignment) (left right : Term .nodes) :
    decodeNodes ((union left right).eval assignment) =
      Union.union (decodeNodes (left.eval assignment)) (decodeNodes (right.eval assignment)) :=
  decode_or _ _

theorem intersection_eval (assignment : Assignment) (left right : Term .nodes) :
    decodeNodes ((intersection left right).eval assignment) =
      Inter.inter (decodeNodes (left.eval assignment)) (decodeNodes (right.eval assignment)) :=
  decode_and _ _

theorem difference_eval (assignment : Assignment) (left right : Term .nodes) :
    decodeNodes ((difference left right).eval assignment) =
      SDiff.sdiff (decodeNodes (left.eval assignment)) (decodeNodes (right.eval assignment)) :=
  decode_difference _ _

theorem insert_eval (assignment : Assignment) (node : Node) (value : Term .nodes) :
    decodeNodes ((insert node value).eval assignment) =
      Insert.insert node (decodeNodes (value.eval assignment)) :=
  decode_insert _ _

theorem erase_eval (assignment : Assignment) (node : Node) (value : Term .nodes) :
    decodeNodes ((erase node value).eval assignment) =
      (decodeNodes (value.eval assignment)).erase node := by
  simp [erase, difference_eval, Term.eval, Finset.sdiff_singleton_eq_erase]

theorem nonempty_eval (assignment : Assignment) (value : Term .nodes) :
    (nonempty value).eval assignment =
      decide (decodeNodes (value.eval assignment)).Nonempty := by
  simp only [nonempty, Term.eval, <- decide_not, <- bits_eq_iff, decode_zero,
    Finset.nonempty_iff_ne_empty]

theorem subset_eval (assignment : Assignment) (left right : Term .nodes) :
    (subset left right).eval assignment =
      decide (HasSubset.Subset (decodeNodes (left.eval assignment)) (decodeNodes (right.eval assignment))) := by
  simp only [subset, intersection, Term.eval, <- bits_eq_iff, decode_and, Finset.inter_eq_left]

theorem sumTerms_eval (assignment : Assignment) (terms : List (Term .int)) :
    (sumTerms terms).eval assignment = (terms.map (Term.eval assignment)).sum := by
  induction terms with
  | nil => rfl
  | cons value rest ih => simp [sumTerms, Term.eval, ih]

theorem cardinality_eval (assignment : Assignment) (value : Term .nodes) :
    (cardinality value).eval assignment =
      Int.ofNat (decodeNodes (value.eval assignment)).card := by
  unfold cardinality
  rw [sumTerms_eval, List.map_ofFn, List.sum_ofFn]
  simp only [Function.comp_def, Term.eval, member_eval, decide_eq_true_eq]
  rw [Finset.sum_boole]
  simp only [Finset.filter_mem_eq_inter, Finset.univ_inter]
  rfl

theorem cardinality_bounds (assignment : Assignment) (value : Term .nodes) :
    0 <= (cardinality value).eval assignment /\
      (cardinality value).eval assignment <= 15 := by
  simp only [cardinality_eval]
  have bound := Finset.card_le_univ (decodeNodes (value.eval assignment))
  have domain : Fintype.card Node = 15 := rfl
  rw [domain] at bound
  constructor
  next => exact Int.natCast_nonneg _
  next =>
    change ((decodeNodes (value.eval assignment)).card : Int) <= (15 : Int)
    exact_mod_cast bound

theorem majority_eval (assignment : Assignment) (support configuration : Term .nodes)
    (index : Nat) :
    (majority support configuration).eval assignment =
      decide (hasConfigurationMajority (decodeNodes (support.eval assignment))
        { index := index, nodes := decodeNodes (configuration.eval assignment) }) := by
  change Bool.not (decide ((cardinality (intersection support configuration)).eval assignment +
    (cardinality (intersection support configuration)).eval assignment <=
    (cardinality configuration).eval assignment)) = _
  have arithmetic (hits total : Nat) :
      Not (Int.ofNat hits + Int.ofNat hits <= Int.ofNat total) <-> hits * 2 > total := by
    change Not ((hits : Int) + (hits : Int) <= (total : Int)) <-> hits * 2 > total
    omega
  simp only [cardinality_eval, intersection_eval, <- decide_not, hasConfigurationMajority,
    arithmetic]

theorem majority_model (assignment : Assignment) (support : Finset Node)
    (configuration : Configuration Node) :
    (majority (.nodes (encodeNodes support)) (.nodes (encodeNodes configuration.nodes))).eval
        assignment = decide (hasConfigurationMajority support configuration) := by
  rw [majority_eval assignment _ _ configuration.index]
  simp only [Term.eval, decode_encode_nodes]

theorem unionTerms_member (assignment : Assignment) (terms : List (Term .nodes)) (node : Node) :
    Membership.mem (decodeNodes ((unionTerms terms).eval assignment)) node <->
      exists term, Membership.mem terms term /\
        Membership.mem (decodeNodes (term.eval assignment)) node := by
  induction terms with
  | nil => simp [unionTerms, Term.eval]
  | cons value rest ih => simp [unionTerms, union_eval, ih]

theorem filter_eval (assignment : Assignment) (value : Term .nodes)
    (predicate : Node -> Term .bool) :
    decodeNodes ((filter value predicate).eval assignment) =
      (decodeNodes (value.eval assignment)).filter
        (fun node => (predicate node).eval assignment = true) := by
  ext node
  simp only [filter, intersection_eval, Finset.mem_inter, unionTerms_member,
    List.mem_ofFn, Finset.mem_filter]
  simp only [exists_exists_eq_and, Term.eval, apply_ite decodeNodes,
    decode_encode_nodes, decode_zero]
  simp only [apply_ite (fun nodes : Finset Node => Membership.mem nodes node)]
  simp

theorem mask_text (assignment : Assignment) (term : Term .nodes) (nodes : Finset Node)
    (meaning : decodeNodes (term.eval assignment) = nodes) :
    SmtExpressionText.eval assignment term.render = some (.nodes (encodeNodes nodes)) := by
  rw [SmtExpressionText.typed_render_eval, <- meaning]
  simp only [embed, encode_decode_bits]

theorem union_text (assignment : Assignment) (left right : Term .nodes) :
    SmtExpressionText.eval assignment (union left right).render =
      some (.nodes (encodeNodes
        (Union.union (decodeNodes (left.eval assignment)) (decodeNodes (right.eval assignment))))) :=
  mask_text _ _ _ (union_eval _ _ _)

theorem intersection_text (assignment : Assignment) (left right : Term .nodes) :
    SmtExpressionText.eval assignment (intersection left right).render =
      some (.nodes (encodeNodes
        (Inter.inter (decodeNodes (left.eval assignment)) (decodeNodes (right.eval assignment))))) :=
  mask_text _ _ _ (intersection_eval _ _ _)

theorem difference_text (assignment : Assignment) (left right : Term .nodes) :
    SmtExpressionText.eval assignment (difference left right).render =
      some (.nodes (encodeNodes
        (SDiff.sdiff (decodeNodes (left.eval assignment)) (decodeNodes (right.eval assignment))))) :=
  mask_text _ _ _ (difference_eval _ _ _)

theorem insert_text (assignment : Assignment) (node : Node) (value : Term .nodes) :
    SmtExpressionText.eval assignment (insert node value).render =
      some (.nodes (encodeNodes (Insert.insert node (decodeNodes (value.eval assignment))))) :=
  mask_text _ _ _ (insert_eval _ _ _)

theorem erase_text (assignment : Assignment) (node : Node) (value : Term .nodes) :
    SmtExpressionText.eval assignment (erase node value).render =
      some (.nodes (encodeNodes ((decodeNodes (value.eval assignment)).erase node))) :=
  mask_text _ _ _ (erase_eval _ _ _)

theorem filter_text (assignment : Assignment) (value : Term .nodes)
    (predicate : Node -> Term .bool) :
    SmtExpressionText.eval assignment (filter value predicate).render =
      some (.nodes (encodeNodes ((decodeNodes (value.eval assignment)).filter
        (fun node => (predicate node).eval assignment = true)))) :=
  mask_text _ _ _ (filter_eval _ _ _)

theorem cardinality_text (assignment : Assignment) (value : Term .nodes) :
    SmtExpressionText.eval assignment (cardinality value).render =
      some (.integer (Int.ofNat (decodeNodes (value.eval assignment)).card)) := by
  rw [SmtExpressionText.typed_render_eval, cardinality_eval]
  rfl

theorem nonempty_text (assignment : Assignment) (value : Term .nodes) :
    SmtScriptText.runText assignment (render [nonempty value]) =
      some (decide (decodeNodes (value.eval assignment)).Nonempty) := by
  rw [SmtScriptText.runText_render, compile_eval]
  simp only [List.all_cons, List.all_nil, nonempty_eval, Bool.and_true]

theorem subset_text (assignment : Assignment) (left right : Term .nodes) :
    SmtScriptText.runText assignment (render [subset left right]) =
      some (decide (HasSubset.Subset
        (decodeNodes (left.eval assignment)) (decodeNodes (right.eval assignment)))) := by
  rw [SmtScriptText.runText_render, compile_eval]
  simp only [List.all_cons, List.all_nil, subset_eval, Bool.and_true]

theorem majority_text (assignment : Assignment) (support configuration : Term .nodes)
    (index : Nat) :
    SmtScriptText.runText assignment (render [majority support configuration]) =
      some (decide (hasConfigurationMajority (decodeNodes (support.eval assignment))
        { index := index, nodes := decodeNodes (configuration.eval assignment) })) := by
  rw [SmtScriptText.runText_render, compile_eval]
  simp only [List.all_cons, List.all_nil, majority_eval assignment _ _ index, Bool.and_true]

theorem majority_model_text (assignment : Assignment) (support : Finset Node)
    (configuration : Configuration Node) :
    SmtScriptText.runText assignment
        (render [majority (.nodes (encodeNodes support)) (.nodes (encodeNodes configuration.nodes))]) =
      some (decide (hasConfigurationMajority support configuration)) := by
  rw [SmtScriptText.runText_render, compile_eval]
  simp only [List.all_cons, List.all_nil, majority_model, Bool.and_true]

theorem basic_maxima (left right : Term .nodes) (node : Node) :
    SymbolBounds.termMax (union left right) = max (SymbolBounds.termMax left) (SymbolBounds.termMax right) /\
    SymbolBounds.termMax (intersection left right) = max (SymbolBounds.termMax left) (SymbolBounds.termMax right) /\
    SymbolBounds.termMax (difference left right) = max (SymbolBounds.termMax left) (SymbolBounds.termMax right) /\
    SymbolBounds.termMax (insert node left) = SymbolBounds.termMax left /\
    SymbolBounds.termMax (erase node left) = SymbolBounds.termMax left /\
    SymbolBounds.termMax (nonempty left) = SymbolBounds.termMax left /\
    SymbolBounds.termMax (subset left right) = max (SymbolBounds.termMax left) (SymbolBounds.termMax right) := by
  simp [union, intersection, difference, insert, erase, nonempty, subset, SymbolBounds.termMax]

theorem sumTerms_max (terms : List (Term .int)) :
    SymbolBounds.termMax (sumTerms terms) =
      (terms.map SymbolBounds.termMax).foldr max 0 := by
  induction terms with
  | nil => rfl
  | cons value rest ih => simp [sumTerms, SymbolBounds.termMax, ih]

theorem unionTerms_max (terms : List (Term .nodes)) :
    SymbolBounds.termMax (unionTerms terms) =
      (terms.map SymbolBounds.termMax).foldr max 0 := by
  induction terms with
  | nil => rfl
  | cons value rest ih => simp [unionTerms, union, SymbolBounds.termMax, ih]

theorem cardinality_max (value : Term .nodes) :
    SymbolBounds.termMax (cardinality value) = SymbolBounds.termMax value := by
  unfold cardinality
  rw [sumTerms_max, List.map_ofFn]
  simp only [Function.comp_def, SymbolBounds.termMax, member_maximum, Nat.max_self, Nat.max_zero]
  simp [NODE_COUNT]

theorem majority_max (support configuration : Term .nodes) :
    SymbolBounds.termMax (majority support configuration) =
      max (SymbolBounds.termMax support) (SymbolBounds.termMax configuration) := by
  change max (max (SymbolBounds.termMax (cardinality (intersection support configuration)))
    (SymbolBounds.termMax (cardinality (intersection support configuration))))
      (SymbolBounds.termMax (cardinality configuration)) = _
  simp only [cardinality_max, intersection, SymbolBounds.termMax, Nat.max_self, Nat.max_assoc]

theorem filter_max (value : Term .nodes) (predicate : Node -> Term .bool) :
    SymbolBounds.termMax (filter value predicate) =
      max (SymbolBounds.termMax value)
        ((List.ofFn fun node : Node => SymbolBounds.termMax (predicate node)).foldr max 0) := by
  change max (SymbolBounds.termMax value) (SymbolBounds.termMax (unionTerms _)) = _
  rw [unionTerms_max, List.map_ofFn]
  simp only [Function.comp_def, SymbolBounds.termMax, Nat.max_self, Nat.max_zero]

theorem unrolling_width :
    (List.ofFn fun node : Node => node).length = 15 := List.length_ofFn

theorem cardinality_congr (left right : Assignment) (a b : Term .nodes)
    (same : a.eval left = b.eval right) :
    (cardinality a).eval left = (cardinality b).eval right := by
  simp only [cardinality_eval, same]

theorem filter_congr (left right : Assignment) (a b : Term .nodes)
    (p q : Node -> Term .bool) (same : a.eval left = b.eval right)
    (samePredicates : forall node, (p node).eval left = (q node).eval right) :
    (filter a p).eval left = (filter b q).eval right := by
  rw [<- bits_eq_iff, filter_eval, filter_eval, same]
  simp only [samePredicates]

theorem singleton_count (assignment : Assignment) (node : Node) :
    (cardinality (.nodes (encodeNodes {node}))).eval assignment = 1 := by
  rw [cardinality_eval]
  simp [Term.eval]

theorem decode_full : decodeNodes (32767 : BitVec NODE_COUNT) = Finset.univ := by
  have full : (32767 : BitVec NODE_COUNT) = ~~~(0 : BitVec NODE_COUNT) := by decide +kernel
  rw [full, decode_not, decode_zero]
  simp

theorem boundary_counts (assignment : Assignment) :
    (cardinality (.nodes 0)).eval assignment = 0 /\
    (cardinality (.nodes 32767)).eval assignment = 15 := by
  simp only [cardinality_eval, Term.eval, decode_zero, decode_full, Finset.card_empty,
    Finset.card_univ]
  exact And.intro rfl rfl

theorem empty_configuration (assignment : Assignment) (support : Term .nodes) :
    (majority support (.nodes 0)).eval assignment = false := by
  rw [majority_eval assignment _ _ 0]
  simp only [Term.eval, hasConfigurationMajority, decode_zero, Finset.inter_empty,
    Finset.card_empty, Nat.zero_mul, Nat.lt_irrefl, decide_false]

theorem tied_configuration (assignment : Assignment) (support configuration : Term .nodes)
    (tie : (Inter.inter (decodeNodes (support.eval assignment))
      (decodeNodes (configuration.eval assignment))).card * 2 =
        (decodeNodes (configuration.eval assignment)).card) :
    (majority support configuration).eval assignment = false := by
  rw [majority_eval assignment _ _ 0]
  simp only [hasConfigurationMajority, tie, Nat.lt_irrefl, decide_false]

theorem outsiders_ignored (assignment : Assignment) (support configuration : Term .nodes) :
    (majority support configuration).eval assignment =
      (majority (intersection support configuration) configuration).eval assignment := by
  simp only [majority_eval assignment _ _ 0, hasConfigurationMajority, intersection_eval,
    Finset.inter_assoc, Finset.inter_self]

theorem disjoint_support (assignment : Assignment) (support configuration : Term .nodes)
    (disjoint : Inter.inter (decodeNodes (support.eval assignment))
      (decodeNodes (configuration.eval assignment)) = {}) :
    (majority support configuration).eval assignment = false := by
  rw [majority_eval assignment _ _ 0]
  simp only [hasConfigurationMajority, disjoint, Finset.card_empty, Nat.zero_mul,
    Nat.not_lt_zero, decide_false]

theorem full_threshold (assignment : Assignment) (support : Term .nodes) :
    (majority support (.nodes 32767)).eval assignment =
      decide (8 <= (decodeNodes (support.eval assignment)).card) := by
  rw [majority_eval assignment _ _ 0]
  simp only [hasConfigurationMajority, Term.eval, decode_full, Finset.inter_univ,
    Finset.card_univ, node_card]
  have threshold (count : Nat) : count * 2 > NODE_COUNT <-> 8 <= count := by
    unfold NODE_COUNT
    omega
  simp only [threshold]

theorem filter_constants (assignment : Assignment) (value : Term .nodes) :
    (filter value (fun _ => .boolean true)).eval assignment = value.eval assignment /\
    (filter value (fun _ => .boolean false)).eval assignment = 0 := by
  constructor <;> rw [<- bits_eq_iff, filter_eval] <;> simp only [Term.eval, decode_zero] <;> simp

theorem filter_one_position (assignment : Assignment) (value : Term .nodes) (node : Node) :
    (filter value (fun other => .boolean (decide (other = node)))).eval assignment =
      (intersection value (.nodes (encodeNodes {node}))).eval assignment := by
  rw [<- bits_eq_iff, filter_eval, intersection_eval]
  ext other
  simp [Term.eval]

theorem native_uf_alias (assignment : Assignment) (id : Nat) (left right : Term .int)
    (same : left.eval assignment = right.eval assignment) (predicate : Node -> Term .bool) :
    (cardinality (.app .int .nodes id left)).eval assignment =
      (cardinality (.app .int .nodes id right)).eval assignment /\
    (filter (.app .int .nodes id left) predicate).eval assignment =
      (filter (.app .int .nodes id right) predicate).eval assignment := by
  have values : (Term.app .int .nodes id left).eval assignment =
      (Term.app .int .nodes id right).eval assignment := by simp only [Term.eval, same]
  exact And.intro (cardinality_congr _ _ _ _ values)
    (filter_congr _ _ _ _ _ _ values (fun _ => rfl))

theorem wrong_selector_count (assignment : Assignment) :
    (cardinality (.configurationNodes .signature)).eval assignment =
      Int.ofNat (decodeNodes (assignment.selectors.cfgWrong .signature)).card := by
  rw [cardinality_eval]
  rfl

theorem guarded_nonconfiguration_not_majority (assignment : Assignment) (support : Term .nodes) :
    (majority support (NativeSelectors.cfgOr .signature (.nodes 0))).eval assignment = false := by
  rw [majority_eval assignment _ _ 0]
  have zero : (NativeSelectors.cfgOr .signature (.nodes 0)).eval assignment = 0 := rfl
  simp only [zero, hasConfigurationMajority, decode_zero, Finset.inter_empty,
    Finset.card_empty, Nat.zero_mul, Nat.lt_irrefl, decide_false]

theorem model_controls :
    Not (hasConfigurationMajority (decodeNodes 1) { index := 0, nodes := decodeNodes 16385 }) /\
    hasConfigurationMajority (decodeNodes 16385) { index := 0, nodes := decodeNodes 16385 } /\
    hasConfigurationMajority (decodeNodes 3) { index := 0, nodes := decodeNodes 16387 } /\
    Not (hasConfigurationMajority (decodeNodes 16384) { index := 0, nodes := decodeNodes 3 }) /\
    Not (hasConfigurationMajority (decodeNodes 127) { index := 0, nodes := decodeNodes 32767 }) /\
    hasConfigurationMajority (decodeNodes 255) { index := 0, nodes := decodeNodes 32767 } := by
  decide +kernel

end CCFRaft.Sparse.NativeNodeSets

run_cmd do
  let mut checked := 0
  for (name, info) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.Sparse.NativeNodeSets).isPrefixOf name then
      match info with
      | .axiomInfo _ => throwError "explicit derived node-set axiom: {name}"
      | _ =>
        checked := checked + 1
        for axiomName in (<- Lean.collectAxioms name) do
          unless axiomName == ``propext || axiomName == ``Classical.choice ||
              axiomName == ``Quot.sound do
            throwError "unexpected axiom in {name}: {axiomName}"
  Lean.logInfo m!"NativeNodeSets: {checked} declarations passed the allowed-axiom gate."
