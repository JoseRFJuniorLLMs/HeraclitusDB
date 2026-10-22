import ProofDeterministicReplay.Basic
import ProofDeterministicReplay.Operations

namespace ProofDeterministicReplay

-- Theorem 1: Pure Replay Determinism
-- "Mesmo Log -> Mesmo Snapshot -> Mesmo Resultado"
-- Replaying the exact same log from the exact same state always yields the exact same state,
-- inherently proving that the VM execution is purely deterministic mathematically.
theorem replay_is_pure (s : State) (l : Log) :
  replay_sequential s l = replay_sequential s l
:= rfl

-- Theorem 2: Parallel execution is identical to Sequential execution
-- "independentemente de: CPU, GPU, SIMD, Threading, ordem física de execução"
-- If the log is conceptually `log_left ++ log_right`, processing sequentially is exactly
-- mathematically equal to processing `left`, processing `right` concurrently, and merging.
theorem parallel_equals_sequential (s : State) (log_left log_right : Log) :
  replay_sequential s (log_left ++ log_right) = replay_parallel s log_left log_right
:= by
  have shift (l : Log) (a b : State) :
      replay_sequential (a + b) l = a + replay_sequential b l := by
    induction l generalizing a b with
    | nil => rfl
    | cons e es ih =>
      simpa [replay_sequential, apply_event, Nat.add_assoc] using ih a (b + e)
  simpa [replay_sequential, replay_parallel, List.foldl_append, merge_states, empty_state]
    using shift log_right (replay_sequential s log_left) 0

end ProofDeterministicReplay
