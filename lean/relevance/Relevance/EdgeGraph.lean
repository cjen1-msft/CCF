module

public import CCF.Execution

@[expose] public section

/-!
# Edge graphs: a finite model of the steps of a transition system

Generic over `CCF.TransitionSystem`; nothing here mentions a particular model. A finite model is
given by an abstraction `α` from states to contexts, a step classifier `cls`, and an edge relation
`edge` on (context, class, context).

* `Complete`: every reachable step `s -a-> t` is an instance of an edge
  `(α s, cls s a t, α t)`.
* `complete_of_inductive`: completeness follows from one inductive set `J` that contains the
  initial states and is closed under steps, every step from `J` being an instance of an edge.
  There is no search and no bound.
* `exact_of_witnessed`: if moreover every edge is realised by a reachable step (for example by a
  replayed run), the edge relation is exactly the set of realised edges.
* `covered`: if a set of tested steps hits every edge of a complete edge relation, every reachable
  step has the observation `(α s, cls s a t, α t)` of some tested step.
-/

namespace Relevance.EdgeGraph

variable {sys : CCF.TransitionSystem} {Q C : Type}

/-- Every reachable step is an instance of an edge. -/
def Complete (α : sys.State → Q) (cls : sys.State → sys.Action → sys.State → C)
    (edge : Q → C → Q → Prop) : Prop :=
  ∀ s a t, sys.Reachable s → sys.step s a = some t → edge (α s) (cls s a t) (α t)

/-- The edge `(q, c, q')` is realised by a reachable step. -/
def Realised (α : sys.State → Q) (cls : sys.State → sys.Action → sys.State → C)
    (q : Q) (c : C) (q' : Q) : Prop :=
  ∃ s a t, sys.Reachable s ∧ sys.step s a = some t ∧ α s = q ∧ cls s a t = c ∧ α t = q'

theorem reachable_of_inductive {J : sys.State → Prop} (init : ∀ s, sys.init s → J s)
    (closed : ∀ s a t, J s → sys.step s a = some t → J t) {s : sys.State}
    (reachable : sys.Reachable s) : J s := by
  induction reachable with
  | initial initialized => exact init _ initialized
  | step _ transition ih => exact closed _ _ _ ih transition

/-- **Completeness from one inductive set.** If `J` contains the initial states, is closed under
steps, and every step from `J` is an instance of an edge, then every reachable step is. -/
theorem complete_of_inductive (α : sys.State → Q) (cls : sys.State → sys.Action → sys.State → C)
    (edge : Q → C → Q → Prop) (J : sys.State → Prop) (init : ∀ s, sys.init s → J s)
    (closed : ∀ s a t, J s → sys.step s a = some t → J t ∧ edge (α s) (cls s a t) (α t)) :
    Complete α cls edge :=
  fun s a t reachable transition =>
    (closed s a t (reachable_of_inductive init (fun s a t j st => (closed s a t j st).1)
      reachable) transition).2

/-- **Exactness.** A complete edge relation all of whose edges are realised is exactly the set of
realised edges. -/
theorem exact_of_witnessed {α : sys.State → Q} {cls : sys.State → sys.Action → sys.State → C}
    {edge : Q → C → Q → Prop} (complete : Complete α cls edge)
    (witnessed : ∀ q c q', edge q c q' → Realised α cls q c q') (q : Q) (c : C) (q' : Q) :
    edge q c q' ↔ Realised α cls q c q' := by
  constructor
  · exact witnessed q c q'
  · rintro ⟨s, a, t, reachable, transition, rfl, rfl, rfl⟩
    exact complete s a t reachable transition

/-- The end of a run from an initial state is reachable. -/
theorem Run.reachable {s t : sys.State} {acts : List sys.Action}
    (run : CCF.Execution.Run sys s acts t) (reachable : sys.Reachable s) : sys.Reachable t := by
  induction run with
  | nil => exact reachable
  | cons transition _ ih => exact ih (.step reachable transition)

/-- **Coverage.** If a complete edge relation has, for each edge, a tested step with that edge,
then every reachable step has the observation of some tested step. -/
theorem covered {α : sys.State → Q} {cls : sys.State → sys.Action → sys.State → C}
    {edge : Q → C → Q → Prop} (complete : Complete α cls edge)
    (T : sys.State → sys.Action → sys.State → Prop)
    (hits : ∀ q c q', edge q c q' → ∃ s a t, T s a t ∧ α s = q ∧ cls s a t = c ∧ α t = q')
    {s : sys.State} {a : sys.Action} {t : sys.State} (reachable : sys.Reachable s)
    (h : sys.step s a = some t) :
    ∃ s' a' t', T s' a' t' ∧ α s' = α s ∧ cls s' a' t' = cls s a t ∧ α t' = α t :=
  hits _ _ _ (complete s a t reachable h)

end Relevance.EdgeGraph
