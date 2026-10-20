import ProofHLC.Basic
import ProofHLC.Operations
import Std.Tactic

namespace ProofHLC

-- 1. Property: HLC Monotonicity for Local Events (hlc_monotonicity)
-- Prova que gerar um novo timestamp a partir do anterior resulta em um timestamp estritamente maior.
theorem hlc_monotonicity (pt : Nat) (prev : HLCTime) :
  prev < now pt prev
:= by
  unfold LT.lt instLTHLCTime hlc_lt now max
  dsimp
  by_cases h : pt > prev.l
  · -- Caso pt > prev.l
    have h_max : (if pt > prev.l then pt else prev.l) = pt := if_pos h
    rw [h_max]
    simp [h]
  · -- Caso pt <= prev.l
    have h_max : (if pt > prev.l then pt else prev.l) = prev.l := if_neg h
    rw [h_max]
    simp

-- 2. Property: No Physical Time Regression (hlc_no_physical_regression)
-- Mesmo que a máquina tenha drift de relógio para trás (pt < prev.l), o relógio lógico HLC impede regressão.
theorem hlc_no_physical_regression (pt : Nat) (prev : HLCTime) :
  pt < prev.l → prev < now pt prev
:= by
  intro _
  exact hlc_monotonicity pt prev

-- 3. Property: Causal Order Preservation on Message Receive (hlc_causality_preservation)
-- Quando um nó B recebe uma mensagem enviada por A no tempo `msg`, o novo tempo de B (`receive`)
-- é estritamente posterior a `msg`. Isso garante causalidade distribuída estável.
theorem hlc_causality_preservation (pt : Nat) (prev : HLCTime) (msg : HLCTime) :
  msg < receive pt prev msg
:= by
  have ge_right (a b : Nat) : b ≤ max a b := by
    unfold max
    split <;> omega
  have bound := ge_right (max pt prev.l) msg.l
  change hlc_lt msg (receive pt prev msg) = true
  by_cases eq : max (max pt prev.l) msg.l = msg.l
  · by_cases same : msg.l = prev.l
    · have counter : msg.c < max prev.c msg.c + 1 := by
        have := ge_right prev.c msg.c
        omega
      rw [same] at eq
      simp [hlc_lt, receive, same, eq, counter]
    · simp [hlc_lt, receive, eq, same]
  · have lt : msg.l < max (max pt prev.l) msg.l := by omega
    simp [hlc_lt, receive, lt]

end ProofHLC
