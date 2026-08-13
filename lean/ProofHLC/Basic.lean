namespace ProofHLC

/-- The Hybrid Logical Clock Timestamp structure. -/
structure HLCTime where
  l : Nat -- Physical time component (highest physical time observed)
  c : Nat -- Logical counter component for event ordering within the same physical tick
deriving Repr, DecidableEq, Inhabited

/-- Strict ordering relation (<) on HLCTime (lexicographical order). -/
def hlc_lt (t1 t2 : HLCTime) : Bool :=
  t1.l < t2.l || (t1.l == t2.l && t1.c < t2.c)

instance : LT HLCTime where
  lt t1 t2 := hlc_lt t1 t2 = true

/-- Non-strict ordering relation (<=) on HLCTime. -/
def hlc_le (t1 t2 : HLCTime) : Bool :=
  t1.l < t2.l || (t1.l == t2.l && t1.c <= t2.c)

instance : LE HLCTime where
  le t1 t2 := hlc_le t1 t2 = true

end ProofHLC
