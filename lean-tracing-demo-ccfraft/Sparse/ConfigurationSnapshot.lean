import Sparse.Configuration
import MachineGenerated.HandlerProofs
import Mathlib.Data.List.Sort

set_option autoImplicit false

namespace CCFRaft.Sparse.ConfigurationSnapshot

local notation:50 x:51 " IN " xs:51 => Membership.mem xs x

variable {N T : Type} [DecidableEq N] [Bootstrap N]

-- Derived physical snapshot only, not a C++ callback-state relation.
def positiveActive (log : List (Entry N T)) (commit : Nat) : List (Configuration N) :=
  (configurationsInLog log).filter fun configuration =>
    (currentConfigurationAt log commit).index <= configuration.index

theorem positiveActive_model (state : NodeState N T) :
    positiveActive state.log state.commitIndex =
      (activeConfigurations state).filter (fun configuration => 0 < configuration.index) := by
  classical
  rw [positiveActive, activeConfigurations, currentConfiguration, List.filter_filter]
  simp only [allConfigurations, List.filter_cons, implicitConfiguration]
  apply List.filter_congr
  intro configuration member
  have positive := (configurationsInLog_index_bounds state.log member).1
  simp [positive]

theorem mem_positiveActive (log : List (Entry N T)) (commit : Nat)
    (configuration : Configuration N) :
    configuration IN positiveActive log commit <->
      configuration IN configurationsInLog log /\
        (currentConfigurationAt log commit).index <= configuration.index := by
  simp [positiveActive]

omit [DecidableEq N] [Bootstrap N] in
theorem mem_configurations_iff (log : List (Entry N T)) (configuration : Configuration N) :
    configuration IN configurationsInLog log <->
      Configuration.Reconfig log configuration.index configuration.nodes := by
  induction log using List.reverseRecOn with
  | nil =>
    simp [configurationsInLog, configurationsInLogFrom, Configuration.Reconfig, entryAt?]
  | append_singleton log entry ih =>
    have step : configurationsInLog (log ++ [entry]) =
        configurationsInLog log ++ configurationsInLogFrom (log.length + 1) [entry] := by
      simp [configurationsInLog, Configuration.configurations_append, Nat.add_comm]
    rw [step, List.mem_append, ih, Configuration.reconfig_snoc]
    cases configuration
    cases content : entry.content <;>
      simp [configurationsInLogFrom, content, eq_comm, and_comm]

theorem current_self_iff (log : List (Entry N T)) (configuration : Configuration N)
    (positive : 0 < configuration.index) :
    currentConfigurationAt log configuration.index = configuration <->
      configuration IN configurationsInLog log := by
  classical
  rw [Configuration.currentConfigurationAt_iff]
  constructor
  next =>
    intro predecessor
    apply (mem_configurations_iff log configuration).mpr
    cases predecessor.2.1 with
    | inl zero => omega
    | inr physical => exact physical
  next =>
    intro member
    have bounds := configurationsInLog_index_bounds log member
    refine And.intro (by omega)
      (And.intro (Or.inr ((mem_configurations_iff log configuration).mp member)) ?_)
    intro index nodes _ below
    omega

def tailQueries (length : Nat) : List (Configuration N) -> List (Configuration.Query N)
  | [] => []
  | [configuration] => [(length, configuration)]
  | earlier :: later :: rest =>
      (later.index - 1, earlier) :: tailQueries length (later :: rest)

def headQuery (length commit : Nat) : List (Configuration N) -> Configuration.Query N
  | [] => (length, implicitConfiguration)
  | first :: _ =>
      if first.index <= commit then (commit, first)
      else (first.index - 1, implicitConfiguration)

def queries (length commit : Nat) (snapshot : List (Configuration N)) :
    List (Configuration.Query N) :=
  snapshot.map (fun configuration => (configuration.index, configuration)) ++
    (tailQueries length snapshot ++ [headQuery length commit snapshot])

structure Shape (length : Nat) (snapshot : List (Configuration N)) : Prop where
  ordered : snapshot.Pairwise (fun left right => left.index < right.index)
  bounds : forall configuration, configuration IN snapshot ->
    0 < configuration.index /\ configuration.index <= length

def Answers (log : List (Entry N T)) (observations : List (Configuration.Query N)) : Prop :=
  forall query, query IN observations -> currentConfigurationAt log query.1 = query.2

theorem queries_length (length commit : Nat) (snapshot : List (Configuration N)) :
    (queries length commit snapshot).length = 2 * snapshot.length + 1 := by
  have tails : forall values : List (Configuration N),
      (tailQueries length values).length = values.length := by
    intro values
    induction values with
    | nil => rfl
    | cons first rest ih =>
      cases rest with
      | nil => rfl
      | cons next rest =>
        simp only [List.length_cons] at ih
        simp only [tailQueries, List.length_cons]
        omega
  simp [queries, tails]
  omega

omit [DecidableEq N] [Bootstrap N] in
theorem head_index_le (first : Configuration N) (rest : List (Configuration N))
    (ordered : (first :: rest).Pairwise (fun left right => left.index < right.index))
    (configuration : Configuration N) (member : configuration IN first :: rest) :
    first.index <= configuration.index := by
  cases List.mem_cons.mp member with
  | inl same => subst configuration; exact Nat.le_refl _
  | inr tail => exact Nat.le_of_lt ((List.pairwise_cons.mp ordered).1 configuration tail)

theorem answers_queries_iff (log : List (Entry N T)) (length commit : Nat)
    (snapshot : List (Configuration N)) :
    Answers log (queries length commit snapshot) <->
      (forall configuration, configuration IN snapshot ->
        currentConfigurationAt log configuration.index = configuration) /\
      Answers log (tailQueries length snapshot) /\
      currentConfigurationAt log (headQuery length commit snapshot).1 =
        (headQuery length commit snapshot).2 := by
  constructor
  next =>
    intro answers
    refine And.intro ?_ (And.intro ?_ ?_)
    next =>
      intro configuration member
      exact answers (configuration.index, configuration) (by simp [queries, member])
    next =>
      intro query member
      exact answers query (by simp [queries, member])
    next => exact answers (headQuery length commit snapshot) (by simp [queries])
  next =>
    intro answers query member
    simp only [queries, List.mem_append] at member
    cases member with
    | inl member =>
      cases List.mem_map.mp member with
      | intro configuration evidence =>
        rw [<- evidence.2]
        exact answers.1 configuration evidence.1
    | inr member =>
      cases member with
      | inl member => exact answers.2.1 query member
      | inr member =>
        have same : query = headQuery length commit snapshot := by simpa using member
        simpa [same] using answers.2.2

theorem tail_complete (log : List (Entry N T)) (first : Configuration N)
    (rest : List (Configuration N))
    (known : forall configuration, configuration IN first :: rest ->
      configuration IN configurationsInLog log)
    (answers : Answers log (tailQueries log.length (first :: rest))) :
    forall configuration, configuration IN configurationsInLog log ->
      first.index <= configuration.index -> configuration IN first :: rest := by
  classical
  induction rest generalizing first with
  | nil =>
    intro configuration physical lower
    have last := answers (log.length, first) (by simp [tailQueries])
    have predecessor := (Configuration.currentConfigurationAt_iff log log.length first).mp last
    have bounds := configurationsInLog_index_bounds log physical
    have upper := predecessor.2.2 configuration.index configuration.nodes
      ((mem_configurations_iff log configuration).mp physical) (by omega)
    have same := configurationsInLog_index_unique log physical (known first (by simp))
      (Nat.le_antisymm upper lower)
    simp [same]
  | cons next rest ih =>
    intro configuration physical lower
    by_cases before : configuration.index < next.index
    next =>
      have gap := answers (next.index - 1, first) (by simp [tailQueries])
      have predecessor := (Configuration.currentConfigurationAt_iff log (next.index - 1) first).mp gap
      have bounds := configurationsInLog_index_bounds log physical
      have upper := predecessor.2.2 configuration.index configuration.nodes
        ((mem_configurations_iff log configuration).mp physical) (by omega)
      have same := configurationsInLog_index_unique log physical (known first (by simp))
        (Nat.le_antisymm upper lower)
      simp [same]
    next =>
      apply List.mem_cons_of_mem
      apply ih next
      next =>
        intro candidate member
        exact known candidate (List.mem_cons_of_mem first member)
      next =>
        intro query member
        exact answers query (by simp only [tailQueries, List.mem_cons]; exact Or.inr member)
      next => exact physical
      next => omega

theorem tail_answers (log : List (Entry N T)) (first : Configuration N)
    (rest : List (Configuration N))
    (known : forall configuration, configuration IN first :: rest ->
      configuration IN configurationsInLog log)
    (ordered : (first :: rest).Pairwise (fun left right => left.index < right.index))
    (complete : forall configuration, configuration IN configurationsInLog log ->
      first.index <= configuration.index -> configuration IN first :: rest) :
    Answers log (tailQueries log.length (first :: rest)) := by
  classical
  induction rest generalizing first with
  | nil =>
    have first_known := known first (by simp)
    have bounds := configurationsInLog_index_bounds log first_known
    have last : currentConfigurationAt log log.length = first := by
      apply (Configuration.currentConfigurationAt_iff log log.length first).mpr
      refine And.intro (by omega)
        (And.intro (Or.inr ((mem_configurations_iff log first).mp first_known)) ?_)
      intro index nodes reconfig within
      by_cases below : index <= first.index
      next => exact below
      next =>
        have physical := (mem_configurations_iff log { index, nodes }).mpr reconfig
        have member := complete { index, nodes } physical (by change first.index <= index; omega)
        have same : ({ index, nodes } : CCFRaft.Configuration N) = first := by simpa using member
        have same_index := congrArg CCFRaft.Configuration.index same
        change index = first.index at same_index
        omega
    intro query member
    have same : query = (log.length, first) := by simpa [tailQueries] using member
    simpa [same] using last
  | cons next rest ih =>
    have first_known := known first (by simp)
    have bounds := configurationsInLog_index_bounds log first_known
    have ordered_parts := List.pairwise_cons.mp ordered
    have increasing := ordered_parts.1 next (by simp)
    have gap : currentConfigurationAt log (next.index - 1) = first := by
      apply (Configuration.currentConfigurationAt_iff log (next.index - 1) first).mpr
      refine And.intro (by omega)
        (And.intro (Or.inr ((mem_configurations_iff log first).mp first_known)) ?_)
      intro index nodes reconfig within
      by_cases below : index <= first.index
      next => exact below
      next =>
        have physical := (mem_configurations_iff log { index, nodes }).mpr reconfig
        have member := complete { index, nodes } physical (by change first.index <= index; omega)
        cases List.mem_cons.mp member with
        | inl same =>
          have same_index := congrArg CCFRaft.Configuration.index same
          change index = first.index at same_index
          omega
        | inr member =>
          have lower := head_index_le next rest ordered_parts.2 { index, nodes } member
          change next.index <= index at lower
          omega
    have later : Answers log (tailQueries log.length (next :: rest)) := by
      apply ih next
      next =>
        intro configuration member
        exact known configuration (List.mem_cons_of_mem first member)
      next => exact ordered_parts.2
      next =>
        intro configuration physical lower
        have member := complete configuration physical (by omega)
        cases List.mem_cons.mp member with
        | inl same => subst configuration; omega
        | inr member => exact member
    intro query member
    cases List.mem_cons.mp (show query IN
        (next.index - 1, first) :: tailQueries log.length (next :: rest) from member) with
    | inl same => simpa [same] using gap
    | inr member => exact later query member

theorem positiveActive_empty_iff (log : List (Entry N T)) (commit : Nat) :
    positiveActive log commit = [] <->
      currentConfigurationAt log log.length = implicitConfiguration := by
  classical
  constructor
  next =>
    intro empty
    have current := Configuration.current_predecessor log commit
    cases current.2.1 with
    | inl zero =>
      have physical_empty : configurationsInLog log = [] := by
        simpa [positiveActive, zero.1] using empty
      simp [currentConfigurationAt, physical_empty]
    | inr physical =>
      have known := (mem_configurations_iff log (currentConfigurationAt log commit)).mpr physical
      have active := (mem_positiveActive log commit _).mpr (And.intro known (Nat.le_refl _))
      simp [empty] at active
  next =>
    intro implicit
    apply List.eq_nil_iff_forall_not_mem.mpr
    intro configuration member
    have known := ((mem_positiveActive log commit configuration).mp member).1
    have bounds := configurationsInLog_index_bounds log known
    have predecessor := Configuration.current_predecessor log log.length
    rw [implicit] at predecessor
    have impossible := predecessor.2.2 configuration.index configuration.nodes
      ((mem_configurations_iff log configuration).mp known) (by omega)
    simp only [implicitConfiguration] at impossible
    omega

theorem snapshot_iff (log : List (Entry N T)) (commit : Nat)
    (snapshot : List (Configuration N)) :
    positiveActive log commit = snapshot <->
      Shape log.length snapshot /\ Answers log (queries log.length commit snapshot) := by
  classical
  cases snapshot with
  | nil =>
    constructor
    next =>
      intro empty
      refine And.intro { ordered := by simp, bounds := by simp } ?_
      intro query member
      have same : query = (log.length, implicitConfiguration) := by
        simpa [queries, tailQueries, headQuery] using member
      simpa [same] using (positiveActive_empty_iff log commit).mp empty
    next =>
      intro valid
      apply (positiveActive_empty_iff log commit).mpr
      exact valid.2 (log.length, implicitConfiguration) (by simp [queries, headQuery])
  | cons first rest =>
    constructor
    next =>
      intro same
      have ordered : (first :: rest).Pairwise (fun left right => left.index < right.index) := by
        rw [<- same]
        exact (configurationsInLog_pairwise_index_lt log).filter _
      have known : forall configuration, configuration IN first :: rest ->
          configuration IN configurationsInLog log := by
        intro configuration member
        rw [<- same] at member
        exact ((mem_positiveActive log commit configuration).mp member).1
      have bounds : forall configuration, configuration IN first :: rest ->
          0 < configuration.index /\ configuration.index <= log.length := by
        intro configuration member
        exact configurationsInLog_index_bounds log (known configuration member)
      have first_active : first IN positiveActive log commit := by simp [same]
      have first_cutoff := ((mem_positiveActive log commit first).mp first_active).2
      have complete : forall configuration, configuration IN configurationsInLog log ->
          first.index <= configuration.index -> configuration IN first :: rest := by
        intro configuration physical lower
        rw [<- same]
        exact (mem_positiveActive log commit configuration).mpr
          (And.intro physical (Nat.le_trans first_cutoff lower))
      refine And.intro { ordered, bounds } ?_
      apply (answers_queries_iff log log.length commit (first :: rest)).mpr
      refine And.intro ?_ (And.intro (tail_answers log first rest known ordered complete) ?_)
      next =>
        intro configuration member
        exact (current_self_iff log configuration (bounds configuration member).1).mpr
          (known configuration member)
      next =>
        have current := Configuration.current_predecessor log commit
        have first_known := known first (by simp)
        have first_bounds := bounds first (by simp)
        by_cases committed : first.index <= commit
        next =>
          simp only [headQuery, if_pos committed]
          apply (Configuration.currentConfigurationAt_iff log commit first).mpr
          refine And.intro (by omega)
            (And.intro (Or.inr ((mem_configurations_iff log first).mp first_known)) ?_)
          intro index nodes physical below
          have upper := current.2.2 index nodes physical below
          omega
        next =>
          simp only [headQuery, if_neg committed]
          have current_zero : (currentConfigurationAt log commit).index = 0 := by
            cases current.2.1 with
            | inl zero => exact zero.1
            | inr physical =>
              have current_known := (mem_configurations_iff log _).mpr physical
              have active := (mem_positiveActive log commit _).mpr
                (And.intro current_known (Nat.le_refl _))
              rw [same] at active
              have lower := head_index_le first rest ordered _ active
              have upper := current.1
              omega
          apply (Configuration.currentConfigurationAt_iff log (first.index - 1) _).mpr
          refine And.intro (by simp [implicitConfiguration])
            (And.intro (Or.inl (And.intro rfl rfl)) ?_)
          intro index nodes physical below
          have member := (mem_positiveActive log commit { index, nodes }).mpr
            (And.intro ((mem_configurations_iff log _).mpr physical) (by simp [current_zero]))
          rw [same] at member
          have lower := head_index_le first rest ordered { index, nodes } member
          change first.index <= index at lower
          change index <= (implicitConfiguration (Node := N)).index
          simp only [implicitConfiguration]
          omega
    next =>
      intro valid
      have answers := (answers_queries_iff log log.length commit (first :: rest)).mp valid.2
      have known : forall configuration, configuration IN first :: rest ->
          configuration IN configurationsInLog log := by
        intro configuration member
        exact (current_self_iff log configuration (valid.1.bounds configuration member).1).mp
          (answers.1 configuration member)
      have complete := tail_complete log first rest known answers.2.1
      have threshold : forall configuration, configuration IN configurationsInLog log ->
          ((currentConfigurationAt log commit).index <= configuration.index <->
            first.index <= configuration.index) := by
        by_cases committed : first.index <= commit
        next =>
          have current : currentConfigurationAt log commit = first := by
            simpa [headQuery, committed] using answers.2.2
          intro configuration _
          rw [current]
        next =>
          have implicit : currentConfigurationAt log (first.index - 1) = implicitConfiguration := by
            simpa [headQuery, committed] using answers.2.2
          have excluded := (Configuration.currentConfigurationAt_iff log (first.index - 1) _).mp implicit
          have current := Configuration.current_predecessor log commit
          have current_zero : (currentConfigurationAt log commit).index = 0 := by
            cases current.2.1 with
            | inl zero => exact zero.1
            | inr physical =>
              have upper := current.1
              have zero := excluded.2.2 _ _ physical (by omega)
              simp only [implicitConfiguration] at zero
              omega
          intro configuration physical
          have first_lower : first.index <= configuration.index := by
            by_contra below
            have bounds := configurationsInLog_index_bounds log physical
            have zero := excluded.2.2 configuration.index configuration.nodes
              ((mem_configurations_iff log configuration).mp physical) (by omega)
            simp only [implicitConfiguration] at zero
            omega
          simp [current_zero, first_lower]
      letI : Std.Antisymm (fun left right : Configuration N => left.index < right.index) :=
        { antisymm := fun _ _ forward backward => False.elim (Nat.lt_asymm forward backward) }
      letI : Std.Irrefl (fun left right : Configuration N => left.index < right.index) :=
        { irrefl := fun configuration => Nat.lt_irrefl configuration.index }
      apply ((configurationsInLog_pairwise_index_lt log).filter
        (fun configuration => decide ((currentConfigurationAt log commit).index <= configuration.index))).eq_of_mem_iff
        valid.1.ordered
      intro configuration
      change configuration IN positiveActive log commit <-> configuration IN first :: rest
      rw [mem_positiveActive]
      constructor
      next =>
        intro active
        exact complete configuration active.1 ((threshold configuration active.1).mp active.2)
      next =>
        intro member
        have physical := known configuration member
        exact And.intro physical ((threshold configuration physical).mpr
          (head_index_le first rest valid.1.ordered configuration member))

theorem model_snapshot_iff (state : NodeState N T) (snapshot : List (Configuration N)) :
    (activeConfigurations state).filter (fun configuration => 0 < configuration.index) = snapshot <->
      Shape state.log.length snapshot /\
        Answers state.log (queries state.log.length state.commitIndex snapshot) := by
  rw [<- positiveActive_model]
  exact snapshot_iff state.log state.commitIndex snapshot

-- All checks range over snapshot records, query records, and optional exact points.
def FiniteConditions (length commit : Nat) (points : List (Configuration.Point N T))
    (snapshot : List (Configuration N)) : Prop :=
  Shape length snapshot /\ Configuration.FiniteConditions length points (queries length commit snapshot)

theorem finite_completion_iff (length commit : Nat) (points : List (Configuration.Point N T))
    (snapshot : List (Configuration N)) :
    FiniteConditions length commit points snapshot <->
      exists log : List (Entry N T),
        log.length = length /\
        (forall point, point IN points -> entryAt? log point.1 = point.2) /\
        positiveActive log commit = snapshot := by
  constructor
  next =>
    intro valid
    have witness := (Configuration.finite_completion_iff length points
      (queries length commit snapshot)).mp valid.2
    cases witness with
    | intro log observations =>
      refine Exists.intro log (And.intro observations.1 (And.intro observations.2.1 ?_))
      apply (snapshot_iff log commit snapshot).mpr
      simpa only [observations.1] using And.intro valid.1 observations.2.2
  next =>
    intro witness
    cases witness with
    | intro log observed =>
      have exact_snapshot := (snapshot_iff log commit snapshot).mp observed.2.2
      refine And.intro (by simpa only [observed.1] using exact_snapshot.1) ?_
      apply Configuration.realizes_conditions (log := log)
      refine And.intro observed.1 (And.intro observed.2.1 ?_)
      simpa only [observed.1] using exact_snapshot.2

theorem empty_log_snapshot (commit : Nat) :
    FiniteConditions (N := N) (T := T) 0 commit [] [] := by
  apply (finite_completion_iff 0 commit [] []).mpr
  refine Exists.intro [] (And.intro rfl (And.intro (by simp) ?_))
  simp [positiveActive, configurationsInLog, configurationsInLogFrom]

theorem empty_snapshot_nonempty_log (commit : Nat) :
    FiniteConditions (N := N) (T := T) 1 commit
      [(0, none), (1, some { term := 9, content := .signature }), (2, none)] [] := by
  apply (finite_completion_iff 1 commit _ []).mpr
  refine Exists.intro [{ term := 9, content := .signature }]
    (And.intro rfl (And.intro ?_ ?_))
  next => simp [entryAt?]
  next => simp [positiveActive, configurationsInLog, configurationsInLogFrom]

theorem empty_node_set_allowed :
    FiniteConditions (N := N) (T := T) 1 0 [] [{ index := 1, nodes := Finset.empty }] := by
  apply (finite_completion_iff 1 0 [] _).mpr
  refine Exists.intro [{ term := 7, content := .reconfiguration Finset.empty }]
    (And.intro rfl (And.intro (by simp) ?_))
  simp [positiveActive, currentConfigurationAt, configurationsInLog,
    configurationsInLogFrom, implicitConfiguration]

theorem two_configuration_phases (older newer : Finset N) :
    let log : List (Entry N T) :=
      [{ term := 9, content := .reconfiguration older },
       { term := 0, content := .signature },
       { term := 1, content := .reconfiguration newer }]
    positiveActive log 0 = [{ index := 1, nodes := older }, { index := 3, nodes := newer }] /\
    positiveActive log 2 = [{ index := 1, nodes := older }, { index := 3, nodes := newer }] /\
    positiveActive log 100 = [{ index := 3, nodes := newer }] := by
  simp [positiveActive, currentConfigurationAt, configurationsInLog,
    configurationsInLogFrom, implicitConfiguration]

theorem hidden_pending_point_rejected (older newer : Finset N) :
    Not (FiniteConditions (T := T) 3 2
      [(3, some { term := 4, content := .reconfiguration newer })]
      [{ index := 1, nodes := older }]) := by
  intro valid
  have excluded := valid.2.exclude_point (3, { index := 1, nodes := older })
    (by simp [queries, tailQueries])
    (3, some { term := 4, content := .reconfiguration newer }) (by simp)
    { term := 4, content := .reconfiguration newer } newer rfl rfl (by simp)
  change 3 <= 1 at excluded
  omega

theorem nonincreasing_indices_rejected (length commit leftIndex rightIndex : Nat)
    (left right : Finset N) (nonincreasing : rightIndex <= leftIndex) :
    Not (FiniteConditions (T := T) length commit []
      [{ index := leftIndex, nodes := left }, { index := rightIndex, nodes := right }]) := by
  intro valid
  have impossible := (List.pairwise_cons.mp valid.1.ordered).1
    { index := rightIndex, nodes := right } (by simp)
  change leftIndex < rightIndex at impossible
  omega

theorem zero_index_rejected (length commit : Nat) (nodes : Finset N) :
    Not (FiniteConditions (T := T) length commit [] [{ index := 0, nodes }]) := by
  intro valid
  have impossible := (valid.1.bounds { index := 0, nodes } (by simp)).1
  change 0 < 0 at impossible
  omega

end CCFRaft.Sparse.ConfigurationSnapshot

run_cmd do
  let namespaceName := `CCFRaft.Sparse.ConfigurationSnapshot
  let environment <- Lean.getEnv
  let mut count := 0
  for (name, _) in environment.constants.toList do
    if namespaceName.isPrefixOf name then
      count := count + 1
      let axioms <- Lean.collectAxioms name
      for axiomName in axioms do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
  Lean.logInfo m!"ConfigurationSnapshot: audited {count} declarations; only propext, Classical.choice, Quot.sound"
