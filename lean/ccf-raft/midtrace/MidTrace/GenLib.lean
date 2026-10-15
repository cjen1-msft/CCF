module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import MidTrace.GenIr

@[expose] public section

/-!
# Symbolic lists, sets, options and effects

Model-independent counterparts, over `GenIr`, of the `List`, `Finset`,
`Option` and effect-monad operations a model uses. Each operation denotes its
Lean counterpart exactly under the representation below, so a model is
encoded by replacing each operation with its counterpart.

* `SSet`: a finite set over a fixed universe of `n` elements, one bit each.
* `SOpt`: an option as a presence bit and a value.
* `SList`: a list of records stored struct-of-arrays: element `i` is cell
  `off + i` of every field array, for `i < len`. `take`, `drop` and pushing
  one element never copy.
* `MList`: the list of `elem p` for the positions `p` in `[0, hi]` where
  `mask p` holds, in position order. This is the result of `filter`,
  `filterMap` or `flatMap` producing at most one element per position, so
  those never materialize a list.
* `Eff`: a step of the effect monad as a path condition, an enabledness
  condition (`guard`) and the sends made under each path condition.
-/

namespace CCFRaft.MidTrace.Gen

open CCFRaft.MidTrace.Smt (Tm INF)

/-! ## Merging branches -/

class Merge (α : Type) where
  merge : Tm → α → α → GM α

instance : Merge Tm := ⟨iteT⟩

instance : Merge Unit := ⟨fun _ _ _ => pure ()⟩

instance {α : Type} [Merge α] : Merge (Array α) :=
  ⟨fun c a b => (a.zip b).mapM fun (x, y) => Merge.merge c x y⟩

instance {α β : Type} [Merge α] [Merge β] : Merge (α × β) :=
  ⟨fun c a b => do return (← Merge.merge c a.1 b.1, ← Merge.merge c a.2 b.2)⟩

/-! ## Naturals and comparisons -/

/-- Truncated subtraction, as on `Nat`. -/
def natSub (a b : Tm) : GM Tm := do
  maxT (← subT a b) (.int 0)

def gtT (a b : Tm) : GM Tm := lt b a

def geT (a b : Tm) : GM Tm := le b a

def neT (a b : Tm) : GM Tm := do
  notT (← eqT a b)

def boolInt (c : Tm) : GM Tm := iteT c (.int 1) (.int 0)

/-- `values[x]` for a symbolic `x` in `[0, values.size)`. -/
def pick (values : Array Tm) (x : Tm) : GM Tm := do
  let some last := values.back? | return .int 0
  let mut acc := last
  for i in (List.range (values.size - 1)).reverse do
    acc ← iteT (← eqK x i) values[i]! acc
  return acc

/-! ## Finite sets -/

/-- A subset of a fixed universe of `size` elements, one bit per element. -/
abbrev SSet := Array Tm

namespace SSet

def empty (size : Nat) : SSet := Array.replicate size (.bool false)

def ofBools (bits : Array Bool) : SSet := bits.map .bool

def single (size i : Nat) : SSet := (empty size).set! i (.bool true)

def mem (s : SSet) (i : Nat) : Tm := s[i]!

/-- Membership of a symbolic element in `[0, s.size)`. -/
def memAt (s : SSet) (x : Tm) : GM Tm := pick s x

def union (a b : SSet) : GM SSet := (a.zip b).mapM fun (x, y) => orL [x, y]

def inter (a b : SSet) : GM SSet := (a.zip b).mapM fun (x, y) => andL [x, y]

def diff (a b : SSet) : GM SSet := (a.zip b).mapM fun (x, y) => do andL [x, ← notT y]

def erase (s : SSet) (i : Nat) : SSet := s.set! i (.bool false)

def insert (s : SSet) (i : Nat) : SSet := s.set! i (.bool true)

def card (s : SSet) : GM Tm := countT s

def nonempty (s : SSet) : GM Tm := orL s.toList

def subset (a b : SSet) : GM Tm := do
  andL (← (a.zip b).mapM fun (x, y) => impliesT x y).toList

def eqS (a b : SSet) : GM Tm := do
  andL (← (a.zip b).mapM fun (x, y) => eqT x y).toList

def filter (s : SSet) (p : Nat → GM Tm) : GM SSet := do
  let mut out := #[]
  for h : i in [0:s.size] do
    out := out.push (← andL [s[i], ← p i])
  return out

end SSet

/-! ## Options -/

structure SOpt (α : Type) where
  isSome : Tm
  val : α

instance {α : Type} [Merge α] : Merge (SOpt α) :=
  ⟨fun c a b => do return ⟨← iteT c a.isSome b.isSome, ← Merge.merge c a.val b.val⟩⟩

namespace SOpt

def getD (o : SOpt Tm) (d : Tm) : GM Tm := iteT o.isSome o.val d

/-- An optional natural number as one integer, `-1` meaning `none`. -/
def code (o : SOpt Tm) : GM Tm := o.getD (.int (-1))

def ofCode (t : Tm) : GM (SOpt Tm) := do
  return ⟨← le (.int 0) t, t⟩

end SOpt

/-! ## Offset lists -/

/-- Element `i < len` is cell `off + i` of each array in `arrs`. -/
structure SList where
  arrs : Array Tm
  off : Tm
  len : Tm
deriving Inhabited

instance : Merge SList :=
  ⟨fun c a b => do
    return {
      arrs := ← Merge.merge c a.arrs b.arrs
      off := ← iteT c a.off b.off
      len := ← iteT c a.len b.len
    }⟩

namespace SList

/-- `l[i]`, for `i < l.length`. -/
def get (l : SList) (i : Tm) : GM (Array Tm) := do
  let k ← addT l.off i
  l.arrs.mapM fun a => select a k

/-- Field `f` of `l[i]`, for `i < l.length`. -/
def getF (l : SList) (i : Tm) (f : Nat) : GM Tm := do
  select l.arrs[f]! (← addT l.off i)

/-- `l.take n` -/
def take (l : SList) (n : Tm) : GM SList := do
  return { l with len := ← minT n l.len }

/-- `l.drop n` -/
def drop (l : SList) (n : Tm) : GM SList := do
  let m ← minT n l.len
  return { l with off := ← addT l.off m, len := ← subT l.len m }

/-- `if c then l ++ [r] else l`: the cell after the end is not part of `l`. -/
def pushIf (l : SList) (c : Tm) (r : Array Tm) : GM SList := do
  let k ← addT l.off l.len
  let arrs ← (l.arrs.zip r).mapM fun (a, v) => store a k v
  return { l with arrs, len := ← addT l.len (← boolInt c) }

/-- `l ++ [r]` -/
def push (l : SList) (r : Array Tm) : GM SList := l.pushIf (.bool true) r

/-- `a ++ b` -/
def append (a b : SList) : GM SList := do
  let aEnd ← addT a.off a.len
  let arrs ←
    (a.arrs.zip b.arrs).mapM
      fun (x, y) => do
        let elem := (← srtOf x).elem
        lam elem
          fun k => do
            iteT (← lt k aEnd) (← select x k) (← select y (← addT (← subT k aEnd) b.off))
  return { arrs, off := a.off, len := ← addT a.len b.len }

def isEmpty (l : SList) : GM Tm := eqK l.len 0

/-- `l.getLast?` -/
def getLast? (l : SList) : GM (SOpt (Array Tm)) := do
  return ⟨← lt (.int 0) l.len, ← l.get (← addK l.len (-1))⟩

/-- `l.any p` -/
def any (l : SList) (p : Array Tm → GM Tm) : GM Tm := do
  foldAny (.int 0) (← addK l.len (-1)) fun i => do p (← l.get i)

/-- `l.all p` -/
def all (l : SList) (p : Array Tm → GM Tm) : GM Tm := do
  foldAll (.int 0) (← addK l.len (-1)) fun i => do p (← l.get i)

/-- `((l.zipIdx base).find? fun (x, i) => p x i).map Prod.snd` -/
def findIdx? (l : SList) (base : Int) (p : Array Tm → Tm → GM Tm) : GM (SOpt Tm) := do
  let cond (i : Tm) : GM Tm := do
    p (← l.get i) (← addK i base)
  let hi ← addK l.len (-1)
  let found ← foldAny (.int 0) hi cond
  let index ← foldFirst (.int 0) hi cond (fun i => addK i base) (.int 0)
  return ⟨found, index⟩

/-- `(a.zip b).any p` -/
def zipAny (a b : SList) (p : Array Tm → Array Tm → GM Tm) : GM Tm := do
  let hi ← addK (← minT a.len b.len) (-1)
  foldAny (.int 0) hi fun i => do p (← a.get i) (← b.get i)

end SList

/-! ## Masked lists -/

/-- The list of `elem p` for positions `p` in `[0, hi]` satisfying `mask`. -/
structure MList where
  hi : Tm
  mask : Tm → GM Tm
  elem : Tm → GM (Array Tm)
  /-- A record of the element sorts, used as the default. -/
  dflt : Array Tm

namespace MList

def maskedElem (l : MList) (p : Tm) (q : Array Tm → GM Tm) : GM Tm := do
  andL [← l.mask p, ← q (← l.elem p)]

/-- `l.filter q` -/
def filter (l : MList) (q : Array Tm → GM Tm) : MList :=
  { l with mask := fun p => l.maskedElem p q }

/-- `l.length` -/
def length (l : MList) : GM Tm :=
  foldSum (.int 0) l.hi l.mask fun _ => pure (.int 1)

/-- Cell `p` is the number of elements at positions before `p`. -/
def ranks (l : MList) : GM Tm :=
  scan .int (.int 0)
    fun k acc => do
      addT acc (← boolInt (← l.mask (← addK k (-1))))

def rankAt (l : MList) (p : Tm) : GM Tm := do
  select (← l.ranks) p

/-- `l.drop n` -/
def drop (l : MList) (n : Tm) : MList :=
  { l with mask := fun p => do andL [← l.mask p, ← le n (← l.rankAt p)] }

/-- `l.any q` -/
def any (l : MList) (q : Array Tm → GM Tm) : GM Tm :=
  foldAny (.int 0) l.hi fun p => l.maskedElem p q

/-- `l.all q` -/
def all (l : MList) (q : Array Tm → GM Tm) : GM Tm :=
  foldAll (.int 0) l.hi fun p => do impliesT (← l.mask p) (← q (← l.elem p))

/-- `l.find? q` -/
def find? (l : MList) (q : Array Tm → GM Tm) : GM (SOpt (Array Tm)) := do
  let found ← l.any q
  let mut val := #[]
  for h : f in [0:l.dflt.size] do
    val :=
      val.push
        (← foldFirst (.int 0) l.hi (fun p => l.maskedElem p q)
            (fun p => do return (← l.elem p)[f]!) l.dflt[f])
  return ⟨found, val⟩

/-- `(l.find? q).map (·[f])` -/
def findF? (l : MList) (q : Array Tm → GM Tm) (f : Nat) : GM (SOpt Tm) := do
  let val ←
    foldFirst (.int 0) l.hi (fun p => l.maskedElem p q)
      (fun p => do return (← l.elem p)[f]!) l.dflt[f]!
  return ⟨← l.any q, val⟩

/-- `l.foldl (fun _ x => x) d` -/
def lastD (l : MList) (d : Array Tm) : GM (Array Tm) := do
  let mut val := #[]
  for h : f in [0:d.size] do
    val :=
      val.push
        (← foldLast (.int 0) l.hi l.mask (fun p => do return (← l.elem p)[f]!) d[f])
  return val

/-- `l.foldl (fun m x => if q x then max m (v x) else m) d` -/
def maxD (l : MList) (q : Array Tm → GM Tm) (v : Array Tm → GM Tm) (d : Tm) : GM Tm :=
  foldMax (.int 0) l.hi (fun p => l.maskedElem p q) (fun p => do v (← l.elem p)) d

/-- The union of the sets in fields `[start, start + size)`. -/
def unionAt (l : MList) (start size : Nat) : GM SSet := do
  let mut bits := #[]
  for i in [0:size] do
    bits := bits.push (← l.any fun x => pure x[start + i]!)
  return bits

/-- `l.zip l.tail`: every element but the first, after the one before it. -/
def zipTail (l : MList) : GM MList := do
  let mut prevs := #[]
  for h : f in [0:l.dflt.size] do
    let d := l.dflt[f]
    prevs :=
      prevs.push
        (← scan (← srtOf d) d
            fun k acc => do
              let p ← addK k (-1)
              iteT (← l.mask p) (← l.elem p)[f]! acc)
  return {
    hi := l.hi
    mask := fun p => do andL [← l.mask p, ← le (.int 1) (← l.rankAt p)]
    elem := fun p => do return (← prevs.mapM fun prev => select prev p) ++ (← l.elem p)
    dflt := l.dflt ++ l.dflt
  }

/-- `l[i]`, for `i < l.length`. -/
def nth (l : MList) (i : Tm) : GM (Array Tm) := do
  let mut val := #[]
  for h : f in [0:l.dflt.size] do
    val :=
      val.push
        (← foldFirst (.int 0) l.hi
            (fun p => do andL [← l.mask p, ← eqT (← l.rankAt p) i])
            (fun p => do return (← l.elem p)[f]!) l.dflt[f])
  return val

end MList

/-! ## Effects -/

/-- The sends and enabledness of a step of an effect monad. -/
structure Eff where
  /-- The branch being executed. -/
  pc : Tm := .bool true
  /-- Every `guard` reached holds. -/
  ok : Tm := .bool true
  /-- Path condition, destination, message: in send order. -/
  sends : Array (Tm × Nat × Array Tm) := #[]

abbrev EM := StateT Eff GM

/-- `guard g` -/
def guardE (g : Tm) : EM Unit := do
  let eff ← get
  let ok ← andL [eff.ok, ← impliesT eff.pc g]
  set { eff with ok }

/-- `send message destination` -/
def sendE (message : Array Tm) (destination : Nat) : EM Unit := do
  modify fun eff => { eff with sends := eff.sends.push (eff.pc, destination, message) }

/-- `send message destination` for a symbolic destination in `[0, size)`. -/
def sendAtE (message : Array Tm) (destination : Tm) (size : Nat) : EM Unit := do
  for j in [0:size] do
    let eff ← get
    let pc ← andL [eff.pc, ← eqK destination j]
    if pc != .bool false then
      set { eff with sends := eff.sends.push (pc, j, message) }

/-- `if c then t else e` -/
def sif {α : Type} [Merge α] (c : Tm) (t e : EM α) : EM α := do
  match c with
  | .bool true => t
  | .bool false => e
  | _ =>
      let pc := (← get).pc
      let pcT ← andL [pc, c]
      modify fun eff => { eff with pc := pcT }
      let a ← t
      let pcE ← andL [pc, ← notT c]
      modify fun eff => { eff with pc := pcE }
      let b ← e
      modify fun eff => { eff with pc }
      Merge.merge c a b

/-- `if c then t` -/
def swhen (c : Tm) (t : EM Unit) : EM Unit := sif c t (pure ())

end CCFRaft.MidTrace.Gen
