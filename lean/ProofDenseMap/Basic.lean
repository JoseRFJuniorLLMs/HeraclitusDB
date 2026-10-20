namespace ProofDenseMap

/-- ULID abstract representation -/
abbrev ULID := Nat

/-- Dense Index abstract representation (simulating u32) -/
abbrev Index := Nat

/-- The Dense Entity Map structure.
    In formal verification, instead of writing an array or hashmap, 
    we model the map as pure logical functions. -/
structure DenseEntityMap where
  forward : ULID → Option Index
  backward : Index → Option ULID

/-- Initial empty map where nothing is allocated. -/
def empty : DenseEntityMap :=
  { forward := fun _ => none,
    backward := fun _ => none }

end ProofDenseMap
