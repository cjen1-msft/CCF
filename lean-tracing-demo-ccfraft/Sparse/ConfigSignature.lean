import Sparse.Configuration
import MachineGenerated.HandlerProofs

-- One arbitrary log; exact points, configuration frontiers, and signature maxima.
-- A supplied fallback transaction is used only to prove joint existence.
-- No runtime unknown-log default, reachability, term ordering, or node-universe cap.
-- No active-list, quorum, retirement, range-equality, version, or SMT claim.

set_option autoImplicit false

namespace CCFRaft.Sparse.ConfigSignature

open Sparse.Configuration

local notation:50 x:51 " IN " xs:51 => Membership.mem xs x

variable {N T : Type} [DecidableEq N] [DecidableEq T] [Bootstrap N]

def SignatureAt (log : List (Entry N T)) (i : Nat) : Prop :=
  exists e, entryAt? log i = some e /\ e.content = .signature

omit [DecidableEq N] [DecidableEq T] [Bootstrap N] in
theorem signature_bounds {log : List (Entry N T)} {i : Nat}
    (h : SignatureAt log i) : 0 < i /\ i <= log.length := by
  cases h with
  | intro e he => exact entry_bounds he.1

omit [Bootstrap N] in
theorem signature_test_iff (log : List (Entry N T)) (i : Nat) :
    isSignatureAt log i = true <-> SignatureAt log i := by
  constructor
  next => exact isSignatureAtTrue
  next =>
    intro h
    cases h with
    | intro e he => simp [isSignatureAt, he.1, he.2]

-- This is the actual reader: maxCommittableIndex (log.take frontier).
omit [Bootstrap N] in
theorem signature_maximum_exclusion_iff (log : List (Entry N T)) (f j : Nat) :
    maxCommittableIndexUpTo log f = j <->
      j <= min f log.length /\
      (j = 0 \/ SignatureAt log j) /\
      (forall i, j < i -> i <= min f log.length -> Not (SignatureAt log i)) := by
  have bounds : maxCommittableIndexUpTo log f <= min f log.length :=
    le_min (maxCommittableIndexUpTo_le_frontier log f)
      (maxCommittableIndexUpTo_le_length log f)
  have positive : 0 < maxCommittableIndexUpTo log f ->
      SignatureAt log (maxCommittableIndexUpTo log f) :=
    fun hp => (signature_test_iff _ _).mp (maxCommittableIndexUpToPositiveIsSignature hp)
  have lower : forall i, SignatureAt log i -> i <= f ->
      i <= maxCommittableIndexUpTo log f := by
    intro i hi hf
    exact signatureIndex_le_maxCommittableIndex
      (isSignatureAt_take_of_le hf ((signature_test_iff _ _).mpr hi))
  constructor
  next =>
    intro hj
    rw [hj] at bounds positive lower
    refine And.intro bounds (And.intro ?_ ?_)
    next =>
      by_cases hz : j = 0
      next => exact Or.inl hz
      next => exact Or.inr (positive (by omega))
    next =>
      intro i after within hi
      have := lower i hi (le_trans within (min_le_left _ _))
      omega
  next =>
    intro h
    apply Nat.le_antisymm
    next =>
      by_contra hn
      have hp : 0 < maxCommittableIndexUpTo log f := by omega
      exact h.2.2 _ (by omega) bounds (positive hp)
    next =>
      rcases h.2.1 with hz | hi
      next => omega
      next => exact lower j hi (le_trans h.1 (min_le_left _ _))

abbrev SignatureQuery := Prod Nat Nat

-- Only supplied records are compared; no conditions enumerate indices through n.
structure JointConditions (n : Nat) (points : List (Point N T))
    (configs : List (Query N)) (signatures : List SignatureQuery) : Prop where
  configuration : FiniteConditions n points configs
  signature_bound : forall q, q IN signatures -> q.2 <= min q.1 n
  signature_point : forall q, q IN signatures -> forall p, p IN points ->
    0 < q.2 -> p.1 = q.2 ->
      exists e, p.2 = some e /\ e.content = .signature
  signature_exclude_point : forall q, q IN signatures -> forall p, p IN points ->
    forall e, p.2 = some e -> e.content = .signature ->
      p.1 <= min q.1 n -> p.1 <= q.2
  signature_exclude_anchor : forall q, q IN signatures -> forall r, r IN signatures ->
    0 < r.2 -> r.2 <= min q.1 n -> r.2 <= q.2
  anchors_disjoint : forall q, q IN signatures -> forall r, r IN configs ->
    0 < q.2 -> 0 < r.2.index -> Not (q.2 = r.2.index)

def JointRealizes (log : List (Entry N T)) (n : Nat) (points : List (Point N T))
    (configs : List (Query N)) (signatures : List SignatureQuery) : Prop :=
  Realizes log n points configs /\
    (forall q, q IN signatures -> maxCommittableIndexUpTo log q.1 = q.2)

theorem realizes_joint_conditions {log : List (Entry N T)} {n : Nat}
    {points : List (Point N T)} {configs : List (Query N)}
    {signatures : List SignatureQuery}
    (h : JointRealizes log n points configs signatures) :
    JointConditions n points configs signatures := by
  have spec := fun q hq => (signature_maximum_exclusion_iff log q.1 q.2).mp (h.2 q hq)
  have anchor : forall q, q IN signatures -> 0 < q.2 -> SignatureAt log q.2 := by
    intro q hq hp
    rcases (spec q hq).2.1 with hz | ha
    next => omega
    next => exact ha
  constructor
  next => exact realizes_conditions h.1
  next =>
    intro q hq
    simpa [h.1.1] using (spec q hq).1
  next =>
    intro q hq p hp pos same
    cases anchor q hq pos with
    | intro e he =>
      exact Exists.intro e
        (And.intro (by rw [<- h.1.2.1 p hp, same]; exact he.1) he.2)
  next =>
    intro q hq p hp e he hc within
    by_contra hn
    exact (spec q hq).2.2 p.1 (by omega) (by simpa [h.1.1] using within)
      (Exists.intro e (And.intro ((h.1.2.1 p hp).trans he) hc))
  next =>
    intro q hq r hr pos within
    by_contra hn
    exact (spec q hq).2.2 r.2 (by omega) (by simpa [h.1.1] using within)
      (anchor r hr pos)
  next =>
    intro q hq r hr pos rpos same
    have cr := (currentConfigurationAt_exclusion_iff log r.1 r.2).mp (h.1.2.2 r hr)
    rcases cr.2.1 with hz | hc
    next => omega
    next =>
      cases hc with
      | intro ce hce =>
        cases anchor q hq pos with
        | intro se hse =>
          have reads := hse.1
          rw [same, hce.1] at reads
          have entries := Option.some.inj reads
          have clash := hse.2
          rw [<- entries, hce.2] at clash
          cases clash

def SignatureAnchorAt (signatures : List SignatureQuery) (i : Nat) : Prop :=
  exists q, q IN signatures /\ 0 < q.2 /\ q.2 = i

-- Reuse the frozen cell completion only at demanded points/configuration anchors.
-- Its signature default is never used for an undemanded cell.
noncomputable def jointCell (fallbackTx : T) (points : List (Point N T))
    (configs : List (Query N)) (signatures : List SignatureQuery) (i : Nat) : Entry N T := by
  classical
  exact if PointAt points i \/ AnchorAt configs i then completeCell points configs i
    else if SignatureAnchorAt signatures i then { term := 0, content := .signature }
    else { term := 0, content := .transaction fallbackTx }

omit [DecidableEq T] in
theorem jointCell_point (fallbackTx : T) {n : Nat} {points : List (Point N T)}
    {configs : List (Query N)} {signatures : List SignatureQuery}
    (h : JointConditions n points configs signatures) {i : Nat} {e : Entry N T}
    (hp : (i, some e) IN points) :
    jointCell fallbackTx points configs signatures i = e := by
  classical
  have demanded : PointAt points i \/ AnchorAt configs i :=
    Or.inl (Exists.intro e hp)
  rw [jointCell, if_pos demanded]
  exact completeCell_point h.configuration hp

omit [DecidableEq T] in
theorem jointCell_configuration (fallbackTx : T) {n : Nat} {points : List (Point N T)}
    {configs : List (Query N)} {signatures : List SignatureQuery}
    (h : JointConditions n points configs signatures)
    {q : Query N} (hq : q IN configs) (pos : 0 < q.2.index) :
    (jointCell fallbackTx points configs signatures q.2.index).content =
      .reconfiguration q.2.nodes := by
  classical
  have demanded : PointAt points q.2.index \/ AnchorAt configs q.2.index :=
    Or.inr (Exists.intro q (And.intro hq (And.intro pos rfl)))
  rw [jointCell, if_pos demanded]
  exact completeCell_anchor h.configuration hq pos

omit [DecidableEq T] in
theorem jointCell_signature (fallbackTx : T) {n : Nat} {points : List (Point N T)}
    {configs : List (Query N)} {signatures : List SignatureQuery}
    (h : JointConditions n points configs signatures)
    {q : SignatureQuery} (hq : q IN signatures) (pos : 0 < q.2) :
    (jointCell fallbackTx points configs signatures q.2).content = .signature := by
  classical
  by_cases hp : PointAt points q.2
  next =>
    have hm := Classical.choose_spec hp
    rw [jointCell_point fallbackTx h hm]
    cases h.signature_point q hq (q.2, some (Classical.choose hp)) hm pos rfl with
    | intro e he =>
      cases Option.some.inj he.1
      exact he.2
  next =>
    have noConfig : Not (AnchorAt configs q.2) := by
      intro ha
      cases ha with
      | intro r hr => exact h.anchors_disjoint q hq r hr.1 pos hr.2.1 hr.2.2.symm
    have hs : SignatureAnchorAt signatures q.2 :=
      Exists.intro q (And.intro hq (And.intro pos rfl))
    simp [jointCell, hp, noConfig, hs]

omit [DecidableEq N] [DecidableEq T] [Bootstrap N] in
theorem jointCell_configuration_origin (fallbackTx : T) (points : List (Point N T))
    (configs : List (Query N)) (signatures : List SignatureQuery)
    (i : Nat) (nodes : Finset N)
    (hc : (jointCell fallbackTx points configs signatures i).content = .reconfiguration nodes) :
    (exists e, (i, some e) IN points /\ e.content = .reconfiguration nodes) \/
      AnchorAt configs i := by
  classical
  by_cases demanded : PointAt points i \/ AnchorAt configs i
  next =>
    rw [jointCell, if_pos demanded] at hc
    exact completeCell_origin points configs i nodes hc
  next =>
    by_cases hs : SignatureAnchorAt signatures i <;> simp [jointCell, demanded, hs] at hc

omit [DecidableEq T] in
theorem jointCell_signature_origin (fallbackTx : T) {n : Nat} {points : List (Point N T)}
    {configs : List (Query N)} {signatures : List SignatureQuery}
    (h : JointConditions n points configs signatures) (i : Nat)
    (hc : (jointCell fallbackTx points configs signatures i).content = .signature) :
    (exists e, (i, some e) IN points /\ e.content = .signature) \/
      SignatureAnchorAt signatures i := by
  classical
  by_cases hp : PointAt points i
  next =>
    have hm := Classical.choose_spec hp
    rw [jointCell_point fallbackTx h hm] at hc
    exact Or.inl (Exists.intro (Classical.choose hp) (And.intro hm hc))
  next =>
    by_cases ha : AnchorAt configs i
    next =>
      cases ha with
      | intro q hq =>
        have content := jointCell_configuration fallbackTx h hq.1 hq.2.1
        rw [hq.2.2, hc] at content
        cases content
    next =>
      by_cases hs : SignatureAnchorAt signatures i
      next => exact Or.inr hs
      next => simp [jointCell, hp, ha, hs] at hc

-- Mathematical witness only. No symbolic list or range-sized formula is emitted.
noncomputable def jointLog (fallbackTx : T) (n : Nat) (points : List (Point N T))
    (configs : List (Query N)) (signatures : List SignatureQuery) : List (Entry N T) :=
  List.ofFn (fun i : Fin n => jointCell fallbackTx points configs signatures (i.val + 1))

omit [DecidableEq N] [DecidableEq T] [Bootstrap N] in
theorem jointLog_length (fallbackTx : T) (n : Nat) (points : List (Point N T))
    (configs : List (Query N)) (signatures : List SignatureQuery) :
    (jointLog fallbackTx n points configs signatures).length = n := by
  simp [jointLog]

omit [DecidableEq N] [DecidableEq T] [Bootstrap N] in
theorem jointLog_read (fallbackTx : T) (n : Nat) (points : List (Point N T))
    (configs : List (Query N)) (signatures : List SignatureQuery)
    (i : Nat) (pos : 0 < i) (bound : i <= n) :
    entryAt? (jointLog fallbackTx n points configs signatures) i =
      some (jointCell fallbackTx points configs signatures i) := by
  have hz : Not (i = 0) := by omega
  have hlt : i - 1 < n := by omega
  have hi : i - 1 + 1 = i := by omega
  simp [entryAt?, hz, jointLog, hlt, hi]

theorem joint_completion_realizes (fallbackTx : T) {n : Nat} {points : List (Point N T)}
    {configs : List (Query N)} {signatures : List SignatureQuery}
    (h : JointConditions n points configs signatures) :
    JointRealizes (jointLog fallbackTx n points configs signatures)
      n points configs signatures := by
  have read := jointLog_read fallbackTx n points configs signatures
  have length := jointLog_length fallbackTx n points configs signatures
  constructor
  next =>
    refine And.intro length (And.intro ?_ ?_)
    next =>
      intro p hp
      cases he : p.2 with
      | none =>
        apply (entry_none _ p.1).mpr
        simpa [length] using (h.configuration.point_none p hp).mp he
      | some e =>
        have live : Not (p.1 = 0 \/ n < p.1) := by
          intro bad
          have := (h.configuration.point_none p hp).mpr bad
          simp [he] at this
        rw [read p.1 (by omega) (by omega)]
        have hm : (p.1, some e) IN points := by simpa [<- he] using hp
        rw [jointCell_point fallbackTx h hm]
    next =>
      intro q hq
      apply (currentConfigurationAt_exclusion_iff _ q.1 q.2).mpr
      refine And.intro (by simpa [length] using h.configuration.query_bound q hq)
        (And.intro ?_ ?_)
      next =>
        by_cases hz : q.2.index = 0
        next => exact Or.inl (And.intro hz (h.configuration.query_zero q hq hz))
        next =>
          have pos : 0 < q.2.index := by omega
          have bound := le_trans (h.configuration.query_bound q hq) (min_le_right _ _)
          exact Or.inr (Exists.intro (jointCell fallbackTx points configs signatures q.2.index)
            (And.intro (read q.2.index pos bound) (jointCell_configuration fallbackTx h hq pos)))
      next =>
        intro i nodes after within hr
        have bounds := reconfig_bounds hr
        rw [length] at bounds within
        cases hr with
        | intro e he =>
          rw [read i bounds.1 bounds.2] at he
          have hc := he.2
          rw [<- Option.some.inj he.1] at hc
          rcases jointCell_configuration_origin fallbackTx points configs signatures i nodes hc
            with hp | ha
          next =>
            cases hp with
            | intro e' he' =>
              have := h.configuration.exclude_point q hq (i, some e') he'.1
                e' nodes rfl he'.2 within
              omega
          next =>
            cases ha with
            | intro r hr =>
              have := h.configuration.exclude_anchor q hq r hr.1 hr.2.1
                (by simpa [hr.2.2] using within)
              omega
  next =>
    intro q hq
    apply (signature_maximum_exclusion_iff _ q.1 q.2).mpr
    refine And.intro (by simpa [length] using h.signature_bound q hq)
      (And.intro ?_ ?_)
    next =>
      by_cases hz : q.2 = 0
      next => exact Or.inl hz
      next =>
        have pos : 0 < q.2 := by omega
        have bound := le_trans (h.signature_bound q hq) (min_le_right _ _)
        exact Or.inr (Exists.intro (jointCell fallbackTx points configs signatures q.2)
          (And.intro (read q.2 pos bound) (jointCell_signature fallbackTx h hq pos)))
    next =>
      intro i after within hs
      have bounds := signature_bounds hs
      rw [length] at bounds within
      cases hs with
      | intro e he =>
        rw [read i bounds.1 bounds.2] at he
        have hc := he.2
        rw [<- Option.some.inj he.1] at hc
        rcases jointCell_signature_origin fallbackTx h i hc with hp | ha
        next =>
          cases hp with
          | intro e' he' =>
            have := h.signature_exclude_point q hq (i, some e') he'.1 e' rfl he'.2 within
            omega
        next =>
          cases ha with
          | intro r hr =>
            have := h.signature_exclude_anchor q hq r hr.1 hr.2.1
              (by simpa [hr.2.2] using within)
            omega

theorem joint_finite_completion_iff (fallbackTx : T) (n : Nat) (points : List (Point N T))
    (configs : List (Query N)) (signatures : List SignatureQuery) :
    JointConditions n points configs signatures <->
      exists log : List (Entry N T), JointRealizes log n points configs signatures := by
  constructor
  next =>
    intro h
    exact Exists.intro (jointLog fallbackTx n points configs signatures)
      (joint_completion_realizes fallbackTx h)
  next =>
    intro witness
    cases witness with
    | intro log h => exact realizes_joint_conditions h

-- These regressions simplify finite records, never evaluate the witness log.
theorem million_joint_example (fallbackTx : T) :
    exists log : List (Entry N T), JointRealizes log 1000000
      [(0, none), (1000001, none),
       (10, some { term := 73, content := .reconfiguration ({} : Finset N) }),
       (20, some { term := 9, content := .signature }),
       (30, some { term := 1, content := .transaction fallbackTx })]
      [(0, implicitConfiguration),
       (10, { index := 10, nodes := {} }),
       (2000000, { index := 10, nodes := {} })]
      [(0, 0), (19, 0), (20, 20), (2000000, 20), (2000000, 20)] := by
  apply (joint_finite_completion_iff fallbackTx _ _ _ _).mp
  constructor
  next =>
    constructor <;> simp [List.mem_cons, implicitConfiguration]
    aesop
  all_goals simp [List.mem_cons, implicitConfiguration]

theorem empty_joint_example (fallbackTx : T) (f : Nat) :
    exists log : List (Entry N T), JointRealizes log 0
      [(0, none), (1, none)] [(f, implicitConfiguration)] [(0, 0), (f, 0)] := by
  apply (joint_finite_completion_iff fallbackTx _ _ _ _).mp
  constructor
  next => constructor <;> simp [List.mem_cons, implicitConfiguration]
  all_goals simp [List.mem_cons, implicitConfiguration]

theorem overlapping_anchors_rejected :
    Not (exists log : List (Entry N T), JointRealizes log 100 []
      [(50, { index := 10, nodes := ({} : Finset N) })] [(50, 10)]) := by
  intro witness
  cases witness with
  | intro log realizes =>
    have h := realizes_joint_conditions realizes
    exact h.anchors_disjoint (50, 10) (by simp)
      (50, { index := 10, nodes := {} }) (by simp) (by norm_num) (by norm_num) rfl

theorem signature_anchor_exclusion_rejected :
    Not (exists log : List (Entry N T), JointRealizes log 100 [] []
      [(100, 10), (20, 20)]) := by
  intro witness
  cases witness with
  | intro log realizes =>
    have h := realizes_joint_conditions realizes
    have bad := h.signature_exclude_anchor (100, 10) (by simp) (20, 20) (by simp)
      (by norm_num) (by norm_num)
    norm_num at bad

theorem zero_signature_point_exclusion_rejected :
    Not (exists log : List (Entry N T), JointRealizes log 100
      [(20, some { term := 1, content := .signature })] [] [(100, 0)]) := by
  intro witness
  cases witness with
  | intro log realizes =>
    have h := realizes_joint_conditions realizes
    have bad := h.signature_exclude_point (100, 0) (by simp)
      (20, some { term := 1, content := .signature }) (by simp)
      { term := 1, content := .signature } rfl rfl (by norm_num)
    norm_num at bad

theorem configuration_exclusion_rejected :
    Not (exists log : List (Entry N T), JointRealizes log 100 []
      [(100, { index := 10, nodes := ({} : Finset N) }),
       (20, { index := 20, nodes := ({} : Finset N) })] [(100, 30)]) := by
  intro witness
  cases witness with
  | intro log realizes =>
    have h := realizes_joint_conditions realizes
    have bad := h.configuration.exclude_anchor
      (100, { index := 10, nodes := {} }) (by simp)
      (20, { index := 20, nodes := {} }) (by simp) (by norm_num) (by norm_num)
    norm_num at bad

theorem explicit_point_signature_anchor_rejected :
    Not (exists log : List (Entry N T), JointRealizes log 100
      [(10, some { term := 1, content := .reconfiguration ({} : Finset N) })]
      [] [(100, 10)]) := by
  intro witness
  cases witness with
  | intro log realizes =>
    have h := realizes_joint_conditions realizes
    have bad := h.signature_point (100, 10) (by simp)
      (10, some { term := 1, content := .reconfiguration {} }) (by simp) (by norm_num) rfl
    simp at bad

theorem out_of_range_signature_rejected :
    Not (exists log : List (Entry N T), JointRealizes log 100 [] [] [(200, 101)]) := by
  intro witness
  cases witness with
  | intro log realizes =>
    have bad := (realizes_joint_conditions realizes).signature_bound (200, 101) (by simp)
    norm_num at bad

end CCFRaft.Sparse.ConfigSignature

run_cmd do
  let env <- Lean.getEnv
  let mut checked := 0
  for (name, info) in env.constants.toList do
    if `CCFRaft.Sparse.ConfigSignature |>.isPrefixOf name then
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
      ``CCFRaft.Sparse.ConfigSignature.signature_maximum_exclusion_iff,
      ``CCFRaft.Sparse.ConfigSignature.joint_finite_completion_iff,
      ``CCFRaft.Sparse.ConfigSignature.million_joint_example,
      ``CCFRaft.Sparse.ConfigSignature.empty_joint_example,
      ``CCFRaft.Sparse.ConfigSignature.overlapping_anchors_rejected,
      ``CCFRaft.Sparse.ConfigSignature.signature_anchor_exclusion_rejected,
      ``CCFRaft.Sparse.ConfigSignature.zero_signature_point_exclusion_rejected,
      ``CCFRaft.Sparse.ConfigSignature.configuration_exclusion_rejected,
      ``CCFRaft.Sparse.ConfigSignature.explicit_point_signature_anchor_rejected,
      ``CCFRaft.Sparse.ConfigSignature.out_of_range_signature_rejected] do
    let axioms <- Lean.collectAxioms theoremName
    for name in axioms do
      unless name == ``propext || name == ``Classical.choice || name == ``Quot.sound do
        throwError "unexpected axiom in {theoremName}: {name}"
    Lean.logInfo m!"axiom gate passed: {theoremName}: {axioms}"
