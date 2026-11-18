import Mathlib.Data.ZMod.Basic
import Mathlib.Tactic.NormNum.Prime

namespace GoyaFormal

def q : ℕ := 8380417

theorem q_pos : 0 < q := by decide

instance : NeZero q := ⟨by decide⟩

instance : Fact (Nat.Prime q) := ⟨by norm_num [q]⟩

abbrev Zq := ZMod q

theorem zq_card : Fintype.card Zq = q := ZMod.card q

end GoyaFormal
