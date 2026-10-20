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
  induction t generalizing t' with
  | leaf h d =>
    cases t' with
    | leaf h' d' =>
      intro v v' eq
      simp_all [verify, rootHash, crypto_hash, combine_hash]
    | node h' l' r' =>
      intro v v' eq
      simp_all [verify, rootHash, crypto_hash, combine_hash]
  | node h l r il ir =>
    cases t' with
    | leaf h' d' =>
      intro v v' eq
      simp_all [verify, rootHash, crypto_hash, combine_hash]
    | node h' l' r' =>
      intro v v' eq
      simp only [verify, Bool.and_eq_true, beq_iff_eq] at v v'
      rcases v with ⟨⟨vl, vr⟩, vh⟩
      rcases v' with ⟨⟨vl', vr'⟩, vh'⟩
      change h = h' at eq
      have children := combine_hash_injective _ _ _ _ (vh.symm.trans (eq.trans vh'))
      have left := il l' vl vl' children.1
      have right := ir r' vr vr' children.2
      subst h'; subst l'; subst r'
      simp_all

end ProofMerkleTree
