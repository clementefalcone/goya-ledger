import Mathlib.Tactic

/-!
# ML-DSA-65 rejection sampling parameters

Arithmetic facts about the ML-DSA-65 parameters γ₁, β and η that the
rejection sampling argument relies on: shifting an accepted response by
at most β keeps it inside the masking range, and the shift is injective.
Distributions and statistical distance are not modelled.
-/

namespace GoyaFormal

def mldsaGamma1 : ℕ := 524288
def mldsaBeta : ℕ := 196
def mldsaEta : ℕ := 4

theorem gamma1_exceeds_beta_plus_eta : mldsaGamma1 > mldsaBeta + mldsaEta := by
  unfold mldsaGamma1 mldsaBeta mldsaEta; omega

theorem abort_bound_positive : 0 < mldsaGamma1 - mldsaBeta := by
  unfold mldsaGamma1 mldsaBeta; omega

theorem single_coefficient_rejection_ratio_lt_two :
    mldsaGamma1 / (mldsaGamma1 - mldsaBeta - mldsaEta) < 2 := by
  unfold mldsaGamma1 mldsaBeta mldsaEta; omega

theorem shift_maps_into_range (inner outer shift : ℕ)
    (h_fit : inner + shift ≤ outer)
    (x : ℕ) (hx : x < inner) :
    x + shift < outer := by omega

theorem shift_injective (shift : ℕ) (x₁ x₂ : ℕ)
    (h : x₁ + shift = x₂ + shift) :
    x₁ = x₂ := by omega

def acceptedRange : ℕ := 2 * (mldsaGamma1 - mldsaBeta) - 1
def maskingRange : ℕ := 2 * mldsaGamma1 - 1
def maxShift : ℕ := mldsaBeta

theorem mldsa_shift_fits : acceptedRange + maxShift ≤ maskingRange := by
  unfold acceptedRange maskingRange maxShift mldsaGamma1 mldsaBeta; omega

theorem mldsa_accepted_in_masking :
    ∀ x : ℕ, x < acceptedRange → ∀ s : ℕ, s ≤ maxShift →
      x + s < maskingRange := by
  intros x hx s hs
  have := mldsa_shift_fits
  omega

theorem mldsa_shift_injective :
    ∀ s x₁ x₂ : ℕ, x₁ + s = x₂ + s → x₁ = x₂ := by
  intros; omega

end GoyaFormal
