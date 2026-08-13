namespace ProofAppendOnly

/-- LSN (Log Sequence Number) represented as a Natural number for simplicity in proofs. -/
def LSN := Nat
deriving Repr, DecidableEq, Inhabited

/-- An event in the Append-Only Log. -/
structure Event where
  lsn : LSN
  hash : Nat -- Abstract representation of the event's content/hash
deriving Repr, DecidableEq, Inhabited

/-- The Append-Only Log, modeled as a List of Events.
    The head of the list is the most recent event (reverse chronological order). -/
structure Log where
  events : List Event
deriving Repr, DecidableEq

/-- The state of the database after replaying a log.
    For simplicity, we model the state as the sum of all hashes,
    representing a deterministic deterministic reduction over the log. -/
def State := Nat

end ProofAppendOnly
