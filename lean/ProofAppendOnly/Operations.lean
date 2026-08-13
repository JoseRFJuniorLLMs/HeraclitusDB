import ProofAppendOnly.Basic

namespace ProofAppendOnly

/-- Appends a new event to the log. 
    Returns `some Log` if successful, or `none` if the LSN is not strictly greater than the last LSN. -/
def append (log : Log) (evt : Event) : Option Log :=
  match log.events with
  | [] => some { events := [evt] }
  | last_evt :: rest =>
    if evt.lsn > last_evt.lsn then
      some { events := evt :: last_evt :: rest }
    else
      none

/-- Replays the log from left to right (chronological order) to reconstruct the state. -/
def replay (log : Log) : State :=
  -- events is stored in reverse order (newest first). 
  -- So we fold from the right (oldest first).
  log.events.foldr (init := 0) fun evt state => state + evt.hash

/-- Truncates the log, removing all events with LSN >= limit.
    This simulates rolling back to a previous valid state. -/
def truncate (log : Log) (limit : LSN) : Log :=
  { events := log.events.dropWhile (fun evt => evt.lsn >= limit) }

/-- Verifies the integrity of the log.
    In a real system, this checks cryptographic hashes.
    Here, we just verify that LSNs are strictly monotonically increasing. -/
def verify (log : Log) : Bool :=
  let rec check : List Event → Bool
    | [] => true
    | [_] => true
    | e1 :: e2 :: rest =>
      if e1.lsn > e2.lsn then check (e2 :: rest) else false
  check log.events

end ProofAppendOnly
