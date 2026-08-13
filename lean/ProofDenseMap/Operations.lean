import ProofDenseMap.Basic

namespace ProofDenseMap

/-- Insert a new ULID into the map, assigning it a new dense Index.
    This operation creates a new map where both forward and backward
    pointers are updated simultaneously, ensuring symmetry. -/
def insert (m : DenseEntityMap) (u : ULID) (new_idx : Index) : DenseEntityMap :=
  { forward := fun x => if x == u then some new_idx else m.forward x,
    backward := fun idx => if idx == new_idx then some u else m.backward idx }

end ProofDenseMap
