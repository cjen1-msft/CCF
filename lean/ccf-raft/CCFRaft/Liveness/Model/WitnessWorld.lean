module

public import CCFRaft.Liveness.Model.World

@[expose] public section

namespace CCFRaft.Liveness

/-- One closed instantiation of the open world, for witnesses only.
Public statements quantify over any `W` with the required accessors. -/
structure World (S : Type) where
  proto : S
  time : Real
  live : Finset NodeID
  pending : List Packet
  issued : Nat

instance {S : Type} : HasProtocol (World S) S where
  proto := World.proto

instance {S : Type} : HasTime (World S) where
  time := World.time

instance {S : Type} : HasLive (World S) where
  live := World.live

instance {S : Type} : HasNetwork (World S) where
  pending := World.pending
  issued := World.issued

end CCFRaft.Liveness
