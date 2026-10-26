/- Additive reference model. Parallel equivalence here does not establish
   equivalence for arbitrary stateful Rust VM transitions. -/
namespace ProofDeterministicReplay

/-- Abstract state of the database. -/
abbrev State := Nat

/-- Abstract event in the log. -/
abbrev Event := Nat

/-- A pure transition function modeling the execution of an event in the H-VM. -/
def apply_event (s : State) (e : Event) : State := s + e

/-- When running in parallel, states are chunked and then merged. 
    This models the state reduction. -/
def merge_states (a b : State) : State := a + b

/-- For parallel execution to be deterministic and equivalent to sequential,
    the merge operation must be associative. -/
theorem merge_associative : ∀ a b c, merge_states (merge_states a b) c = merge_states a (merge_states b c) := Nat.add_assoc

/-- And merging an event sequentially must be mathematically equivalent 
    to merging the resulting state of that event. -/
theorem apply_is_merge : ∀ s e, apply_event s e = merge_states s (apply_event 0 e) := by
  intros; simp [apply_event, merge_states]

/-- Initial empty state of the DB. -/
def empty_state : State := 0

end ProofDeterministicReplay
