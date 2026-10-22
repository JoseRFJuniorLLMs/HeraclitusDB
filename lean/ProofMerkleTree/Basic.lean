namespace ProofMerkleTree

/-- Abstract representation of Data in a Leaf -/
abbrev Data := Nat

/-- Symbolic unbounded digest with disjoint leaf and branch domains.
    This is not a finite hash and makes no claim about BLAKE3 collisions. -/
inductive Hash where
  | leafDigest : Nat → Hash
  | branchDigest : Hash → Hash → Hash
deriving Repr, DecidableEq, Inhabited

/-- Symbolic leaf digest. -/
def crypto_hash (d : Data) : Hash := .leafDigest d

/-- Constructor injectivity of symbolic leaves. -/
theorem crypto_hash_injective : ∀ x y, crypto_hash x = crypto_hash y → x = y := by
  intro x y h
  exact Hash.leafDigest.inj h

/-- Symbolic branch digest. -/
def combine_hash (h1 h2 : Hash) : Hash := .branchDigest h1 h2

/-- Constructor injectivity of symbolic branches. -/
theorem combine_hash_injective : ∀ h1 h2 h3 h4, combine_hash h1 h2 = combine_hash h3 h4 → h1 = h3 ∧ h2 = h4 := by
  intro a b c d h
  exact Hash.branchDigest.inj h

/-- The Merkle Tree inductive structure. -/
inductive MerkleTree where
  | leaf (h : Hash) (d : Data)
  | node (h : Hash) (left : MerkleTree) (right : MerkleTree)
deriving Repr

end ProofMerkleTree
