/- Reference model: a call updates only its (tenant, agent) scope. -/
namespace ProofToolCallIsolation
abbrev Scope := Nat × Nat
abbrev State := Scope → List Nat
def call (scope : Scope) (tool : Nat) (state : State) : State :=
  fun target => if target = scope then tool :: state target else state target
theorem foreign_scope_unchanged (state : State) (scope other : Scope) (tool : Nat)
    (distinct : other ≠ scope) : call scope tool state other = state other := by
  simp [call, distinct]
theorem own_scope_records_call (state : State) (scope : Scope) (tool : Nat) :
    call scope tool state scope = tool :: state scope := by
  simp [call]
end ProofToolCallIsolation
