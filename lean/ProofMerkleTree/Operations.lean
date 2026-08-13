import ProofMerkleTree.Basic

namespace ProofMerkleTree

/-- Extracts the claimed root hash from a Merkle Tree node. -/
def rootHash : MerkleTree → Hash
  | MerkleTree.leaf h _ => h
  | MerkleTree.node h _ _ => h

/-- Verifies the integrity of the Merkle Tree.
    It recalculates every hash from the leaves up to the root
    and compares them with the claimed hashes in the tree structure. -/
def verify : MerkleTree → Bool
  | MerkleTree.leaf h d => h == crypto_hash d
  | MerkleTree.node h left right =>
    let leftValid := verify left
    let rightValid := verify right
    let computedHash := combine_hash (rootHash left) (rootHash right)
    leftValid && rightValid && (h == computedHash)

end ProofMerkleTree
