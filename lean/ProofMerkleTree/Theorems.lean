import ProofMerkleTree.Basic
import ProofMerkleTree.Operations

namespace ProofMerkleTree

-- Property: Mutation of a leaf changes the root hash.
-- "Se o hash na raiz se manteve e o verify passou para duas árvores, elas obrigatoriamente têm a mesma estrutura e os mesmos dados."
-- Isso demonstra que a menor alteração em qualquer byte mudará o rootHash ou fará a verificação falhar.
theorem mutation_fails_verification (t t' : MerkleTree) :
  verify t = true →
  verify t' = true →
  rootHash t = rootHash t' →
  t = t'
:= by
  -- We admit the structural induction proof for now.
  -- The proof would proceed by induction on `t`, matching against `t'`,
  -- and repeatedly applying `crypto_hash_injective` at the leaves 
  -- and `combine_hash_injective` at the nodes.
  sorry

end ProofMerkleTree
