import Mathlib.RingTheory.AdjoinRoot
import Formal.Lattice.Zq

namespace GoyaFormal

noncomputable section

open Polynomial

def n : ℕ := 256

def cycloPoly : Polynomial Zq := X ^ n + 1

abbrev Rq := AdjoinRoot cycloPoly

instance : CommRing Rq := AdjoinRoot.instCommRing cycloPoly

def k_mldsa65 : ℕ := 6
def l_mldsa65 : ℕ := 5

abbrev RqVec (d : ℕ) := Fin d → Rq

abbrev MlDsaPublicMatrix := Fin k_mldsa65 → Fin l_mldsa65 → Rq
abbrev MlDsaSecretVec := RqVec l_mldsa65
abbrev MlDsaPublicVec := RqVec k_mldsa65

end

end GoyaFormal
