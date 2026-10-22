import ProofDenseMap.Basic
import ProofDenseMap.Operations

namespace ProofDenseMap

/-- The fundamental invariant that defines a structurally sound DenseEntityMap:
    For every pair of ULID and Index, pointing forward must imply pointing backward. -/
def IsValidMap (m : DenseEntityMap) : Prop :=
  ∀ u idx, m.forward u = some idx ↔ m.backward idx = some u

-- 1. Property: Initialization is safe.
theorem empty_is_valid : IsValidMap empty := by
  intro u idx
  simp [empty, IsValidMap]

-- 2. Property (is_injective): No collision.
-- If the map is valid, no two different ULIDs can point to the same Index.
theorem forward_injective (m : DenseEntityMap) :
  IsValidMap m →
  ∀ u1 u2 idx, m.forward u1 = some idx → m.forward u2 = some idx → u1 = u2
:= by
  intro h_valid u1 u2 idx h1 h2
  have h1_back := (h_valid u1 idx).mp h1
  have h2_back := (h_valid u2 idx).mp h2
  -- Since `backward` is a deterministic function, `m.backward idx` can only have one value.
  rw [h1_back] at h2_back
  injection h2_back

-- 3. Property (is_surjective_inverse): No loss.
-- If a ULID is mapped to an Index, doing a backward lookup will never yield `none`
-- and will never yield the wrong ULID.
theorem backward_surjective_inverse (m : DenseEntityMap) :
  IsValidMap m →
  ∀ u idx, m.forward u = some idx → m.backward idx = some u
:= by
  intro h_valid u idx h
  exact (h_valid u idx).mp h

-- 4. Property (bijection_integrity): The Master Theorem (No swaps).
-- Translating a ULID to an Index and back returns exactly the original ULID mathematically.
theorem bijection_integrity (m : DenseEntityMap) :
  IsValidMap m →
  ∀ u idx, m.forward u = some idx → m.backward (m.forward u).get! = some u
:= by
  intro valid u idx h
  rw [h]
  exact (valid u idx).mp h

-- 5. Property: Insert maintains integrity.
-- If we take a valid map and insert a non-existent ULID with a non-existent Index, it remains valid.
theorem insert_maintains_validity (m : DenseEntityMap) (u : ULID) (idx : Index) :
  IsValidMap m →
  m.forward u = none →
  m.backward idx = none →
  IsValidMap (insert m u idx)
:= by
  intro valid freshU freshI x j
  have noU (i : Index) : m.backward i ≠ some u := by
    intro h
    have := (valid u i).mpr h
    simp [freshU] at this
  have noI (a : ULID) : m.forward a ≠ some idx := by
    intro h
    have := (valid a idx).mp h
    simp [freshI] at this
  by_cases hx : x = u <;> by_cases hj : j = idx
  all_goals simp_all [insert]
  · exact Ne.symm hj
  · exact Ne.symm hx
  · exact valid x j

end ProofDenseMap
