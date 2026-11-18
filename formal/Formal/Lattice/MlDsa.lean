import Formal.Lattice.ModuleLWE

/-!
# ML-DSA-65 Scheme Definition (FIPS 204)

KeyGen, Sign, Verify as pure functions over R_q.
Parameters: k=6, l=5, n=256, q=8380417, η=4.
-/

namespace GoyaFormal

noncomputable section

open Polynomial

def eta : ℕ := 4

structure MlDsaPublicKey where
  seedRho : ByteArray
  vecT : MlDsaPublicVec

structure MlDsaSecretKey where
  seedRho : ByteArray
  seedK : ByteArray
  tr : ByteArray
  vecS1 : MlDsaSecretVec
  vecS2 : MlDsaPublicVec
  vecT : MlDsaPublicVec

structure MlDsaKeyPair where
  pk : MlDsaPublicKey
  sk : MlDsaSecretKey

structure MlDsaSignature where
  hint : Fin k_mldsa65 → Rq
  response : MlDsaSecretVec
  challenge : Rq

opaque expandA : ByteArray → MlDsaPublicMatrix

opaque sampleSecret : ByteArray → Nat → MlDsaSecretVec

opaque sampleNoise : ByteArray → Nat → MlDsaPublicVec

def keyGen (seed : ByteArray) (rho rhoPrime seedK : ByteArray) : MlDsaKeyPair :=
  let matA := expandA rho
  let s1 := sampleSecret rhoPrime 0
  let s2 := sampleNoise rhoPrime 1
  let t := fun i => matVecMul matA s1 i + s2 i
  let pk : MlDsaPublicKey := { seedRho := rho, vecT := t }
  let sk : MlDsaSecretKey := {
    seedRho := rho, seedK := seedK, tr := seed,
    vecS1 := s1, vecS2 := s2, vecT := t
  }
  { pk := pk, sk := sk }

theorem keygen_public_key_is_mlwe (seed rho rhoPrime seedK : ByteArray) :
    let kp := keyGen seed rho rhoPrime seedK
    let matA := expandA rho
    let s1 := sampleSecret rhoPrime 0
    let noise := sampleNoise rhoPrime 1
    isModuleLweSample
      { matA := matA, vecT := kp.pk.vecT }
      { vecS := s1 }
      noise := by
  simp [keyGen, isModuleLweSample, matVecMul]

-- ════════════════════════════════════════════════════════════════
-- Sign
-- ════════════════════════════════════════════════════════════════

opaque hashToChallenge : ByteArray → MlDsaPublicVec → ByteArray → Rq

opaque sampleMaskingVec : ByteArray → Nat → MlDsaSecretVec

def scalarVecMul (c : Rq) (v : RqVec d) : RqVec d :=
  fun i => c * v i

def vecAdd (a b : RqVec d) : RqVec d :=
  fun i => a i + b i

def sign (sk : MlDsaSecretKey) (message : ByteArray) (nonce : Nat) : MlDsaSignature :=
  let matA := expandA sk.seedRho
  let y := sampleMaskingVec sk.seedK nonce
  let w := fun i => matVecMul matA y i
  let c := hashToChallenge sk.tr w message
  let z := vecAdd y (scalarVecMul c sk.vecS1)
  { hint := fun _ => 0, response := z, challenge := c }

theorem sign_response_structure (sk : MlDsaSecretKey) (msg : ByteArray) (nonce : Nat) :
    let sig := sign sk msg nonce
    let y := sampleMaskingVec sk.seedK nonce
    let c := sig.challenge
    sig.response = vecAdd y (scalarVecMul c sk.vecS1) := by
  simp [sign]

-- ════════════════════════════════════════════════════════════════
-- Verify
-- ════════════════════════════════════════════════════════════════

def vecSub (a b : RqVec d) : RqVec d :=
  fun i => a i - b i

def verify (pk : MlDsaPublicKey) (message : ByteArray) (sig : MlDsaSignature) (tr : ByteArray) : Prop :=
  let matA := expandA pk.seedRho
  let az := fun i => matVecMul matA sig.response i
  let ct := scalarVecMul sig.challenge pk.vecT
  let wPrime := vecSub az ct
  let cPrime := hashToChallenge tr wPrime message
  cPrime = sig.challenge

theorem matVecMul_add (A : MlDsaPublicMatrix) (u v : MlDsaSecretVec) (i : Fin k_mldsa65) :
    matVecMul A (vecAdd u v) i = matVecMul A u i + matVecMul A v i := by
  simp only [matVecMul, vecAdd]
  rw [← Finset.sum_add_distrib]
  congr 1; ext j; ring

theorem matVecMul_scalarMul (A : MlDsaPublicMatrix) (c : Rq) (v : MlDsaSecretVec) (i : Fin k_mldsa65) :
    matVecMul A (scalarVecMul c v) i = c * matVecMul A v i := by
  simp only [matVecMul, scalarVecMul]
  rw [Finset.mul_sum]
  congr 1; ext j; ring

theorem verify_correctness (matA : MlDsaPublicMatrix) (y s1 : MlDsaSecretVec)
    (s2 : MlDsaPublicVec) (c : Rq) (i : Fin k_mldsa65) :
    let z := vecAdd y (scalarVecMul c s1)
    let t := fun j => matVecMul matA s1 j + s2 j
    matVecMul matA z i - c * t i =
      matVecMul matA y i - c * s2 i := by
  simp only []
  rw [matVecMul_add, matVecMul_scalarMul]
  ring

end

end GoyaFormal
