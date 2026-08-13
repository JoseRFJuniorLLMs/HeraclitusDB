import ProofDeterministicReplay.Basic

namespace ProofDeterministicReplay

/-- The Log is a chronological sequence of events. -/
def Log := List Event

/-- Sequential Replay: folds over the log applying events strictly one by one.
    This simulates a single-threaded CPU processing events in exact physical order. -/
def replay_sequential (initial_state : State) (log : Log) : State :=
  log.foldl apply_event initial_state

/-- Parallel Replay: processes two halves of the log independently and merges them.
    This simulates GPU/SIMD/Threading out-of-order parallel execution over chunks. -/
def replay_parallel (initial_state : State) (log_left : Log) (log_right : Log) : State :=
  let state_left := replay_sequential initial_state log_left
  let state_right := replay_sequential empty_state log_right
  merge_states state_left state_right

end ProofDeterministicReplay
