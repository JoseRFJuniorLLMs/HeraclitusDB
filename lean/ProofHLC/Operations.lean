import ProofHLC.Basic

namespace ProofHLC

/-- Utility function to get the maximum of two natural numbers. -/
def max (a b : Nat) : Nat :=
  if a > b then a else b

/-- Generates a new HLC timestamp from the node's local physical time `physical_now`
    and the node's previous HLC timestamp `prev`. -/
def now (physical_now : Nat) (prev : HLCTime) : HLCTime :=
  let new_l := max physical_now prev.l
  let new_c := if new_l == prev.l then prev.c + 1 else 0
  { l := new_l, c := new_c }

/-- Updates the node's HLC timestamp when a message with a remote HLC timestamp `msg`
    is received, using the node's local physical time `physical_now` and previous HLC timestamp `prev`. -/
def receive (physical_now : Nat) (prev : HLCTime) (msg : HLCTime) : HLCTime :=
  let new_l := max (max physical_now prev.l) msg.l
  let new_c := 
    if new_l == prev.l && new_l == msg.l then
      max prev.c msg.c + 1
    else if new_l == prev.l then
      prev.c + 1
    else if new_l == msg.l then
      msg.c + 1
    else
      0
  { l := new_l, c := new_c }

end ProofHLC
