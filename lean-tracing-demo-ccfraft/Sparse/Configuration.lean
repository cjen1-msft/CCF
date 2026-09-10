import Model
import Mathlib.Data.List.OfFn

-- One arbitrary log, finite exact entryAt? and currentConfigurationAt observations.
-- No reachability, term ordering, observed-node universe, or log-length cap.
-- No active-configuration, signature-scan, quorum, retirement, version, or SMT claim.
-- Run from lean-tracing-demo-ccfraft: nice -n10 lake env lean <this-file>

set_option autoImplicit false

namespace CCFRaft.Sparse.Configuration

local notation:50 x:51 " IN " xs:51 => Membership.mem xs x

variable {N T : Type} [DecidableEq N] [Bootstrap N]

def Reconfig (log : List (Entry N T)) (i : Nat) (nodes : Finset N) : Prop :=
  exists e, entryAt? log i = some e /\ e.content = .reconfiguration nodes

omit [DecidableEq N] [Bootstrap N] in
theorem entry_bounds {log : List (Entry N T)} {i : Nat} {e : Entry N T}
    (h : entryAt? log i = some e) : 0 < i /\ i <= log.length := by
  by_cases hi : i = 0
  next => simp [entryAt?, hi] at h
  next =>
    have hn : i - 1 < log.length := List.getElem?_eq_some_iff.mp
      (by simpa [entryAt?, hi] using h) |>.1
    omega

omit [DecidableEq N] [Bootstrap N] in
theorem reconfig_bounds {log : List (Entry N T)} {i : Nat} {nodes : Finset N}
    (h : Reconfig log i nodes) : 0 < i /\ i <= log.length := by
  cases h with
  | intro e he => exact entry_bounds he.1

omit [DecidableEq N] [Bootstrap N] in
theorem configurations_append (a b : List (Entry N T)) (start : Nat) :
    configurationsInLogFrom start (a ++ b) =
      configurationsInLogFrom start a ++
        configurationsInLogFrom (start + a.length) b := by
  induction a generalizing start with
  | nil => simp [configurationsInLogFrom]
  | cons e es ih =>
    cases hc : e.content <;>
      simp [configurationsInLogFrom, hc, ih, Nat.add_comm, Nat.add_left_comm]

theorem current_snoc (log : List (Entry N T)) (e : Entry N T) (f : Nat) :
    currentConfigurationAt (log ++ [e]) f =
      match e.content with
      | .reconfiguration nodes =>
          if log.length + 1 <= f then { index := log.length + 1, nodes }
          else currentConfigurationAt log f
      | _ => currentConfigurationAt log f := by
  cases hc : e.content <;>
    simp [currentConfigurationAt, configurationsInLog, configurations_append,
      configurationsInLogFrom, hc, List.foldl_append, Nat.add_comm]

omit [DecidableEq N] [Bootstrap N] in
theorem reconfig_snoc (log : List (Entry N T)) (e : Entry N T)
    (i : Nat) (nodes : Finset N) :
    Reconfig (log ++ [e]) i nodes <->
      Reconfig log i nodes \/
        (i = log.length + 1 /\ e.content = .reconfiguration nodes) := by
  by_cases hi : i = 0
  next =>
    subst i
    simp [Reconfig, entryAt?]
  by_cases old : i <= log.length
  next =>
    have hlt : i - 1 < log.length := by omega
    have hne : Not (i = log.length + 1) := by omega
    simp [Reconfig, entryAt?, hi, List.getElem?_append, hlt, hne]
  next =>
    have hold : Not (Reconfig log i nodes) := fun h => old (reconfig_bounds h).2
    simp only [hold, false_or]
    by_cases last : i = log.length + 1
    next =>
      subst i
      simp [Reconfig, entryAt?]
    next =>
      have hout : (log ++ [e]).length <= i - 1 := by simp; omega
      simp [Reconfig, entryAt?, hi, List.getElem?_eq_none hout, last]

-- The exclusion is semantic here; finiteConditions below eliminates its range scan.
def Predecessor (log : List (Entry N T)) (f : Nat) (c : Configuration N) : Prop :=
  c.index <= min f log.length /\
  ((c.index = 0 /\ c.nodes = INITIAL_CONFIGURATION) \/
    Reconfig log c.index c.nodes) /\
  (forall i nodes, Reconfig log i nodes -> i <= min f log.length -> i <= c.index)

theorem current_predecessor (log : List (Entry N T)) (f : Nat) :
    Predecessor log f (currentConfigurationAt log f) := by
  induction log using List.reverseRecOn with
  | nil =>
    simp only [currentConfigurationAt, configurationsInLog, configurationsInLogFrom,
      List.foldl_nil]
    refine And.intro (by simp [implicitConfiguration])
      (And.intro (Or.inl (And.intro rfl rfl)) ?_)
    intro i nodes h
    have := reconfig_bounds h
    simp at this
    omega
  | append_singleton log e ih =>
    have step :
        (currentConfigurationAt log f).index <= min f (log ++ [e]).length /\
        (((currentConfigurationAt log f).index = 0 /\
          (currentConfigurationAt log f).nodes = INITIAL_CONFIGURATION) \/
          Reconfig (log ++ [e]) (currentConfigurationAt log f).index
            (currentConfigurationAt log f).nodes) := by
      constructor
      next =>
        have := ih.1
        simp only [List.length_append, List.length_singleton]
        omega
      next =>
        rcases ih.2.1 with h | h
        next => exact Or.inl h
        next => exact Or.inr ((reconfig_snoc log e _ _).mpr (Or.inl h))
    rw [current_snoc]
    cases hc : e.content with
    | transaction tx =>
      refine And.intro step.1 (And.intro step.2 ?_)
      intro i nodes h hif
      rcases (reconfig_snoc log e i nodes).mp h with h | h
      next => exact ih.2.2 i nodes h (by have := (reconfig_bounds h).2; omega)
      next => simp [hc] at h
    | signature =>
      refine And.intro step.1 (And.intro step.2 ?_)
      intro i nodes h hif
      rcases (reconfig_snoc log e i nodes).mp h with h | h
      next => exact ih.2.2 i nodes h (by have := (reconfig_bounds h).2; omega)
      next => simp [hc] at h
    | retiredCommitted ns =>
      refine And.intro step.1 (And.intro step.2 ?_)
      intro i nodes h hif
      rcases (reconfig_snoc log e i nodes).mp h with h | h
      next => exact ih.2.2 i nodes h (by have := (reconfig_bounds h).2; omega)
      next => simp [hc] at h
    | reconfiguration ns =>
      simp only
      by_cases hf : log.length + 1 <= f
      next =>
        rw [if_pos hf]
        refine And.intro (by simp; omega) (And.intro (Or.inr ?_) ?_)
        next => exact (reconfig_snoc log e _ _).mpr (Or.inr (And.intro rfl hc))
        next =>
          intro i nodes h _
          have := (reconfig_bounds h).2
          simpa using this
      next =>
        rw [if_neg hf]
        refine And.intro step.1 (And.intro step.2 ?_)
        intro i nodes h hif
        rcases (reconfig_snoc log e i nodes).mp h with h | h
        next => exact ih.2.2 i nodes h (by have := (reconfig_bounds h).2; omega)
        next =>
          simp only [List.length_append, List.length_singleton] at hif
          omega

theorem predecessor_unique {log : List (Entry N T)} {f : Nat}
    {a b : Configuration N} (ha : Predecessor log f a)
    (hb : Predecessor log f b) : a = b := by
  have le : forall x y : Configuration N,
      Predecessor log f x -> Predecessor log f y -> x.index <= y.index := by
    intro x y hx hy
    rcases hx.2.1 with hz | hr
    next => omega
    next => exact hy.2.2 x.index x.nodes hr hx.1
  have hi : a.index = b.index := Nat.le_antisymm (le a b ha hb) (le b a hb ha)
  have hn : a.nodes = b.nodes := by
    rcases ha.2.1 with ha | ha <;> rcases hb.2.1 with hb | hb
    next => exact ha.2.trans hb.2.symm
    next =>
      have := (reconfig_bounds hb).1
      omega
    next =>
      have := (reconfig_bounds ha).1
      omega
    next =>
      cases ha with
      | intro ea hea =>
        cases hb with
        | intro eb heb =>
          have same := hea.1
          rw [hi, heb.1] at same
          cases Option.some.inj same
          exact EntryContent.reconfiguration.inj (hea.2.symm.trans heb.2)
  cases a
  cases b
  simp_all

theorem currentConfigurationAt_iff (log : List (Entry N T)) (f : Nat)
    (c : Configuration N) :
    currentConfigurationAt log f = c <-> Predecessor log f c := by
  constructor
  next =>
    intro h
    rw [<- h]
    exact current_predecessor log f
  next => exact predecessor_unique (current_predecessor log f)

theorem currentConfigurationAt_exclusion_iff (log : List (Entry N T)) (f : Nat)
    (c : Configuration N) :
    currentConfigurationAt log f = c <->
      c.index <= min f log.length /\
      ((c.index = 0 /\ c.nodes = INITIAL_CONFIGURATION) \/
        Reconfig log c.index c.nodes) /\
      (forall i nodes, c.index < i -> i <= min f log.length ->
        Not (Reconfig log i nodes)) := by
  rw [currentConfigurationAt_iff]
  constructor
  next =>
    intro h
    refine And.intro h.1 (And.intro h.2.1 ?_)
    intro i nodes lower upper hr
    have := h.2.2 i nodes hr upper
    omega
  next =>
    intro h
    refine And.intro h.1 (And.intro h.2.1 ?_)
    intro i nodes hr upper
    by_contra hn
    exact h.2.2 i nodes (by omega) upper hr

abbrev Point (N T : Type) := Prod Nat (Option (Entry N T))
abbrev Query (N : Type) := Prod Nat (Configuration N)

-- All quantifiers below range over supplied records, not the physical log.
structure FiniteConditions (n : Nat) (points : List (Point N T))
    (queries : List (Query N)) : Prop where
  point_none : forall p, p IN points -> (p.2 = none <-> p.1 = 0 \/ n < p.1)
  point_agree : forall p, p IN points -> forall r, r IN points ->
    p.1 = r.1 -> p.2 = r.2
  query_bound : forall q, q IN queries -> q.2.index <= min q.1 n
  query_zero : forall q, q IN queries ->
    q.2.index = 0 -> q.2.nodes = INITIAL_CONFIGURATION
  anchor_agree : forall q, q IN queries -> forall r, r IN queries ->
    0 < q.2.index -> q.2.index = r.2.index -> q.2.nodes = r.2.nodes
  anchor_point : forall q, q IN queries -> forall p, p IN points ->
    0 < q.2.index -> p.1 = q.2.index ->
      exists e, p.2 = some e /\ e.content = .reconfiguration q.2.nodes
  -- A mandatory reconfiguration cannot lie in (q.index, min q.frontier n].
  exclude_point : forall q, q IN queries -> forall p, p IN points ->
    forall e nodes, p.2 = some e -> e.content = .reconfiguration nodes ->
      p.1 <= min q.1 n -> p.1 <= q.2.index
  exclude_anchor : forall q, q IN queries -> forall r, r IN queries ->
    0 < r.2.index -> r.2.index <= min q.1 n -> r.2.index <= q.2.index

def Realizes (log : List (Entry N T)) (n : Nat) (points : List (Point N T))
    (queries : List (Query N)) : Prop :=
  log.length = n /\
  (forall p, p IN points -> entryAt? log p.1 = p.2) /\
  (forall q, q IN queries -> currentConfigurationAt log q.1 = q.2)

omit [DecidableEq N] [Bootstrap N] in
theorem entry_none (log : List (Entry N T)) (i : Nat) :
    entryAt? log i = none <-> i = 0 \/ log.length < i := by
  by_cases hi : i = 0
  next => simp [entryAt?, hi]
  next =>
    simp only [entryAt?, if_neg hi, List.getElem?_eq_none_iff]
    omega

theorem realizes_conditions {log : List (Entry N T)} {n : Nat}
    {points : List (Point N T)} {queries : List (Query N)}
    (h : Realizes log n points queries) : FiniteConditions n points queries := by
  have pred : forall q, q IN queries -> Predecessor log q.1 q.2 :=
    fun q hq => (currentConfigurationAt_iff log q.1 q.2).mp (h.2.2 q hq)
  have anchor : forall q, q IN queries -> 0 < q.2.index ->
      Reconfig log q.2.index q.2.nodes := by
    intro q hq hp
    rcases (pred q hq).2.1 with hz | hr
    next => omega
    next => exact hr
  constructor
  next =>
    intro p hp
    rw [<- h.2.1 p hp, entry_none, h.1]
  next =>
    intro p hp r hr hi
    rw [<- h.2.1 p hp, <- h.2.1 r hr, hi]
  next =>
    intro q hq
    simpa [h.1] using (pred q hq).1
  next =>
    intro q hq hz
    rcases (pred q hq).2.1 with hzero | hr
    next => exact hzero.2
    next => have := (reconfig_bounds hr).1; omega
  next =>
    intro q hq r hr hpos hi
    cases anchor q hq hpos with
    | intro e he =>
      cases anchor r hr (by omega) with
      | intro e' he' =>
        have same := he.1
        rw [hi, he'.1] at same
        cases Option.some.inj same
        exact EntryContent.reconfiguration.inj (he.2.symm.trans he'.2)
  next =>
    intro q hq p hp hpos hi
    cases anchor q hq hpos with
    | intro e he =>
      exact Exists.intro e (And.intro (by rw [<- h.2.1 p hp, hi]; exact he.1) he.2)
  next =>
    intro q hq p hp e nodes he hc bound
    exact (pred q hq).2.2 p.1 nodes
      (Exists.intro e (And.intro ((h.2.1 p hp).trans he) hc))
      (by simpa [h.1] using bound)
  next =>
    intro q hq r hr hpos bound
    exact (pred q hq).2.2 r.2.index r.2.nodes (anchor r hr hpos)
      (by simpa [h.1] using bound)

def PointAt (points : List (Point N T)) (i : Nat) : Prop :=
  exists e, (i, some e) IN points

def AnchorAt (queries : List (Query N)) (i : Nat) : Prop :=
  exists q, q IN queries /\ 0 < q.2.index /\ q.2.index = i

-- A proof witness for this fragment only. It does not preserve signature scans,
-- hidden entries of a fixed array, log versions, or any other omitted reader.
noncomputable def completeCell (points : List (Point N T))
    (queries : List (Query N)) (i : Nat) : Entry N T := by
  classical
  exact if hp : PointAt points i then Classical.choose hp
    else if hq : AnchorAt queries i then
      { term := 0, content := .reconfiguration (Classical.choose hq).2.nodes }
    else { term := 0, content := .signature }

theorem completeCell_point {n : Nat} {points : List (Point N T)}
    {queries : List (Query N)} (h : FiniteConditions n points queries)
    {i : Nat} {e : Entry N T} (hp : (i, some e) IN points) :
    completeCell points queries i = e := by
  classical
  have hex : PointAt points i := Exists.intro e hp
  simp only [completeCell, dif_pos hex]
  exact Option.some.inj
    (h.point_agree (i, some (Classical.choose hex)) (Classical.choose_spec hex)
      (i, some e) hp rfl)

theorem completeCell_anchor {n : Nat} {points : List (Point N T)}
    {queries : List (Query N)} (h : FiniteConditions n points queries)
    {q : Query N} (hq : q IN queries) (pos : 0 < q.2.index) :
    (completeCell points queries q.2.index).content = .reconfiguration q.2.nodes := by
  classical
  by_cases hp : PointAt points q.2.index
  next =>
    have hm := Classical.choose_spec hp
    rw [completeCell_point h hm]
    cases h.anchor_point q hq (q.2.index, some (Classical.choose hp)) hm pos rfl with
    | intro e he =>
      cases Option.some.inj he.1
      exact he.2
  next =>
    have hex : AnchorAt queries q.2.index :=
      Exists.intro q (And.intro hq (And.intro pos rfl))
    simp only [completeCell, dif_neg hp, dif_pos hex]
    have hm := Classical.choose_spec hex
    exact congrArg EntryContent.reconfiguration
      (h.anchor_agree (Classical.choose hex) hm.1 q hq hm.2.1 hm.2.2)

omit [DecidableEq N] [Bootstrap N] in
theorem completeCell_origin (points : List (Point N T)) (queries : List (Query N))
    (i : Nat) (nodes : Finset N)
    (hc : (completeCell points queries i).content = .reconfiguration nodes) :
    (exists e, (i, some e) IN points /\ e.content = .reconfiguration nodes) \/
      AnchorAt queries i := by
  classical
  by_cases hp : PointAt points i
  next =>
    simp only [completeCell, dif_pos hp] at hc
    exact Or.inl (Exists.intro (Classical.choose hp)
      (And.intro (Classical.choose_spec hp) hc))
  next =>
    by_cases hq : AnchorAt queries i
    next => exact Or.inr hq
    next => simp [completeCell, hp, hq] at hc

-- List.ofFn is mathematical completion, never an encoder operation.
noncomputable def completeLog (n : Nat) (points : List (Point N T))
    (queries : List (Query N)) : List (Entry N T) :=
  List.ofFn (fun i : Fin n => completeCell points queries (i.val + 1))

omit [DecidableEq N] [Bootstrap N] in
theorem completeLog_length (n : Nat) (points : List (Point N T))
    (queries : List (Query N)) : (completeLog n points queries).length = n := by
  simp [completeLog]

omit [DecidableEq N] [Bootstrap N] in
theorem completeLog_read (n : Nat) (points : List (Point N T))
    (queries : List (Query N)) (i : Nat) (pos : 0 < i) (bound : i <= n) :
    entryAt? (completeLog n points queries) i = some (completeCell points queries i) := by
  have hzero : Not (i = 0) := by omega
  have hlt : i - 1 < n := by omega
  have hi : i - 1 + 1 = i := by omega
  simp [entryAt?, hzero, completeLog, hlt, hi]

theorem completion_realizes {n : Nat} {points : List (Point N T)}
    {queries : List (Query N)} (h : FiniteConditions n points queries) :
    Realizes (completeLog n points queries) n points queries := by
  refine And.intro (completeLog_length n points queries) (And.intro ?_ ?_)
  next =>
    intro p hp
    cases he : p.2 with
    | none =>
      apply (entry_none _ p.1).mpr
      simpa [completeLog_length] using (h.point_none p hp).mp he
    | some e =>
      have live : Not (p.1 = 0 \/ n < p.1) := by
        intro bad
        have := (h.point_none p hp).mpr bad
        simp [he] at this
      rw [completeLog_read n points queries p.1 (by omega) (by omega)]
      have hm : (p.1, some e) IN points := by simpa [<- he] using hp
      rw [completeCell_point h hm]
  next =>
    intro q hq
    apply (currentConfigurationAt_iff _ q.1 q.2).mpr
    refine And.intro ?_ (And.intro ?_ ?_)
    next => simpa [completeLog_length] using h.query_bound q hq
    next =>
      by_cases hz : q.2.index = 0
      next => exact Or.inl (And.intro hz (h.query_zero q hq hz))
      next =>
        have pos : 0 < q.2.index := by omega
        have bound : q.2.index <= n := le_trans (h.query_bound q hq) (min_le_right _ _)
        exact Or.inr (Exists.intro (completeCell points queries q.2.index)
          (And.intro (completeLog_read n points queries q.2.index pos bound)
            (completeCell_anchor h hq pos)))
    next =>
      intro i nodes hr bound
      have bounds := reconfig_bounds hr
      rw [completeLog_length] at bounds bound
      cases hr with
      | intro e he =>
        rw [completeLog_read n points queries i bounds.1 bounds.2] at he
        have hc := he.2
        rw [<- Option.some.inj he.1] at hc
        rcases completeCell_origin points queries i nodes hc with hp | ha
        next =>
          cases hp with
          | intro e' he' =>
            exact h.exclude_point q hq (i, some e') he'.1 e' nodes rfl he'.2 bound
        next =>
          cases ha with
          | intro r hr =>
            rw [<- hr.2.2]
            exact h.exclude_anchor q hq r hr.1 hr.2.1 (by simpa [hr.2.2] using bound)

theorem finite_completion_iff (n : Nat) (points : List (Point N T))
    (queries : List (Query N)) :
    FiniteConditions n points queries <->
      exists log : List (Entry N T), Realizes log n points queries := by
  constructor
  next =>
    intro h
    exact Exists.intro (completeLog n points queries) (completion_realizes h)
  next =>
    intro witness
    cases witness with
    | intro log h => exact realizes_conditions h

-- Regression instances use only the finite conditions, never evaluate completeLog.
theorem million_sparse_example :
    exists log : List (Entry N T), Realizes log 1000000
      [(0, none), (1000001, none),
       (10, some { term := 73, content := .reconfiguration ({} : Finset N) }),
       (10, some { term := 73, content := .reconfiguration ({} : Finset N) })]
      [(0, implicitConfiguration),
       (10, { index := 10, nodes := {} }),
       (2000000, { index := 10, nodes := {} }),
       (2000000, { index := 10, nodes := {} })] := by
  apply (finite_completion_iff _ _ _).mp
  constructor <;> simp [List.mem_cons, implicitConfiguration]

theorem empty_log_example (f : Nat) :
    exists log : List (Entry N T), Realizes log 0
      [(0, none), (1, none)] [(f, implicitConfiguration)] := by
  apply (finite_completion_iff _ _ _).mp
  constructor <;> simp [List.mem_cons, implicitConfiguration]

theorem interval_conflict_rejected :
    Not (exists log : List (Entry N T), Realizes log 1000000 []
      [(100, { index := 10, nodes := ({} : Finset N) }),
       (20, { index := 20, nodes := ({} : Finset N) })]) := by
  intro witness
  have h := (finite_completion_iff _ _ _).mpr witness
  have bad := h.exclude_anchor
    (100, { index := 10, nodes := {} }) (by simp)
    (20, { index := 20, nodes := {} }) (by simp) (by norm_num) (by norm_num)
  norm_num at bad

theorem signature_anchor_conflict_rejected :
    Not (exists log : List (Entry N T), Realizes log 1
      [(1, some { term := 0, content := .signature })]
      [(1, { index := 1, nodes := ({} : Finset N) })]) := by
  intro witness
  have h := (finite_completion_iff _ _ _).mpr witness
  have bad := h.anchor_point (1, { index := 1, nodes := {} }) (by simp)
    (1, some { term := 0, content := .signature }) (by simp) (by norm_num) rfl
  simp at bad

theorem live_none_rejected :
    Not (exists log : List (Entry N T), Realizes log 1 [(1, none)] []) := by
  intro witness
  have h := (finite_completion_iff _ _ _).mpr witness
  have bad := (h.point_none (1, none) (by simp)).mp rfl
  norm_num at bad

theorem coincident_payload_conflict_rejected (a b : Finset N) (different : Not (a = b)) :
    Not (exists log : List (Entry N T), Realizes log 1 []
      [(1, { index := 1, nodes := a }), (2, { index := 1, nodes := b })]) := by
  intro witness
  have h := (finite_completion_iff _ _ _).mpr witness
  exact different (h.anchor_agree
    (1, { index := 1, nodes := a }) (by simp)
    (2, { index := 1, nodes := b }) (by simp) (by norm_num) rfl)

theorem point_interval_conflict_rejected :
    Not (exists log : List (Entry N T), Realizes log 100
      [(20, some { term := 7, content := .reconfiguration ({} : Finset N) })]
      [(100, { index := 10, nodes := ({} : Finset N) })]) := by
  intro witness
  have h := (finite_completion_iff _ _ _).mpr witness
  have bad := h.exclude_point (100, { index := 10, nodes := {} }) (by simp)
    (20, some { term := 7, content := .reconfiguration {} }) (by simp)
    { term := 7, content := .reconfiguration {} } {} rfl rfl (by norm_num)
  norm_num at bad

theorem duplicate_point_conflict_rejected (a b : Entry N T) (different : Not (a = b)) :
    Not (exists log : List (Entry N T), Realizes log 1
      [(1, some a), (1, some b)] []) := by
  intro witness
  have h := (finite_completion_iff _ _ _).mpr witness
  exact different (Option.some.inj
    (h.point_agree (1, some a) (by simp) (1, some b) (by simp) rfl))

theorem zero_point_some_rejected (e : Entry N T) :
    Not (exists log : List (Entry N T), Realizes log 0 [(0, some e)] []) := by
  intro witness
  have h := (finite_completion_iff _ _ _).mpr witness
  have bad := (h.point_none (0, some e) (by simp)).mpr (Or.inl rfl)
  simp at bad

theorem bootstrap_payload_conflict_rejected (nodes : Finset N)
    (different : Not (nodes = INITIAL_CONFIGURATION)) :
    Not (exists log : List (Entry N T), Realizes log 0 []
      [(100, { index := 0, nodes })]) := by
  intro witness
  have h := (finite_completion_iff _ _ _).mpr witness
  exact different (h.query_zero (100, { index := 0, nodes }) (by simp) rfl)

end CCFRaft.Sparse.Configuration

run_cmd do
  let env <- Lean.getEnv
  let mut checked := 0
  for (name, info) in env.constants.toList do
    if `CCFRaft.Sparse.Configuration |>.isPrefixOf name then
      match info with
      | .axiomInfo _ => throwError "explicit prototype axiom: {name}"
      | _ =>
        checked := checked + 1
        for axiomName in (<- Lean.collectAxioms name) do
          unless axiomName == ``propext || axiomName == ``Classical.choice ||
              axiomName == ``Quot.sound do
            throwError "unexpected transitive axiom in {name}: {axiomName}"
  if checked = 0 then
    throwError "no prototype declarations audited"
  Lean.logInfo m!"Full namespace axiom gate passed: {checked} declarations; no new axioms."
  for theoremName in [
      ``CCFRaft.Sparse.Configuration.currentConfigurationAt_iff,
      ``CCFRaft.Sparse.Configuration.currentConfigurationAt_exclusion_iff,
      ``CCFRaft.Sparse.Configuration.finite_completion_iff,
      ``CCFRaft.Sparse.Configuration.million_sparse_example,
      ``CCFRaft.Sparse.Configuration.empty_log_example,
      ``CCFRaft.Sparse.Configuration.interval_conflict_rejected,
      ``CCFRaft.Sparse.Configuration.signature_anchor_conflict_rejected,
      ``CCFRaft.Sparse.Configuration.live_none_rejected,
      ``CCFRaft.Sparse.Configuration.coincident_payload_conflict_rejected,
      ``CCFRaft.Sparse.Configuration.point_interval_conflict_rejected,
      ``CCFRaft.Sparse.Configuration.duplicate_point_conflict_rejected,
      ``CCFRaft.Sparse.Configuration.zero_point_some_rejected,
      ``CCFRaft.Sparse.Configuration.bootstrap_payload_conflict_rejected] do
    let axioms <- Lean.collectAxioms theoremName
    for name in axioms do
      unless name == ``propext || name == ``Classical.choice || name == ``Quot.sound do
        throwError "unexpected axiom in {theoremName}: {name}"
    Lean.logInfo m!"axiom gate passed: {theoremName}: {axioms}"
