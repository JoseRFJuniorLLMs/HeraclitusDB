namespace ProofDeterministicReplay

/-- Abstract state of the database. -/
def State := Nat
deriving Repr, DecidableEq, Inhabited

/-- Abstract event in the log. -/
def Event := Nat
deriving Repr, DecidableEq, Inhabited

/-- A pure transition function modeling the execution of an event in the H-VM. -/
axiom apply_event : State → Event → State

/-- When running in parallel, states are chunked and then merged. 
    This models the state reduction. -/
axiom merge_states : State → State → State

/-- For parallel execution to be deterministic and equivalent to sequential,
    the merge operation must be associative. -/
axiom merge_associative : ∀ a b c, merge_states (merge_states a b) c = merge_states a (merge_states b c)

/-- And merging an event sequentially must be mathematically equivalent 
    to merging the resulting state of that event. -/
axiom apply_is_merge : ∀ s e, apply_event s e = merge_states s (apply_event 0 e)

/-- Initial empty state of the DB. -/
def empty_state : State := 0

end ProofDeterministicReplay
