/- Reference model: an approval identifier is recorded at most once. -/
namespace ProofApprovalIdempotence
def approve (id : Nat) (ledger : List Nat) : List Nat :=
  if id ∈ ledger then ledger else id :: ledger
theorem approval_idempotent (id : Nat) (ledger : List Nat) :
    approve id (approve id ledger) = approve id ledger := by
  by_cases h : id ∈ ledger <;> simp [approve, h]
end ProofApprovalIdempotence
