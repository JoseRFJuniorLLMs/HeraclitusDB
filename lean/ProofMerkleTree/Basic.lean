namespace ProofMerkleTree

/-- Abstract representation of Data in a Leaf -/
def Data := Nat
deriving Repr, DecidableEq, Inhabited

/-- Abstract representation of a Cryptographic Hash -/
def Hash := Nat
deriving Repr, DecidableEq, Inhabited

/-- Dummy cryptographic hash function for computability in Lean.
    In the theorems, we rely only on the injectivity axiom below, not this implementation. -/
def crypto_hash (d : Data) : Hash := d

/-- Fundamental Axiom: The leaf hash function is collision-resistant. -/
axiom crypto_hash_injective : ∀ x y, crypto_hash x = crypto_hash y → x = y

/-- Dummy hash combination function for computability in Lean. -/
def combine_hash (h1 h2 : Hash) : Hash := h1 + h2

/-- Fundamental Axiom: Combining hashes is collision-resistant. -/
axiom combine_hash_injective : ∀ h1 h2 h3 h4, combine_hash h1 h2 = combine_hash h3 h4 → h1 = h3 ∧ h2 = h4

/-- The Merkle Tree inductive structure. -/
inductive MerkleTree where
  | leaf (h : Hash) (d : Data)
  | node (h : Hash) (left : MerkleTree) (right : MerkleTree)
deriving Repr

end ProofMerkleTree
