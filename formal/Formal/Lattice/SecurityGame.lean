import Formal.Lattice.MlDsa

/-!
# EUF-CMA Security Game for a simplified ML-DSA-65

Deterministic skeleton of the EUF-CMA → SelfTargetMSIS step from
Barbosa et al. (CRYPTO 2023). It has no norm bounds, no probabilities
and no quantum adversary, so a valid forgery maps to a SelfTargetMSIS
solution by definition. It is not a security proof.
-/

namespace GoyaFormal

noncomputable section

-- ════════════════════════════════════════════════════════════════
-- Security games
-- ════════════════════════════════════════════════════════════════

structure Forgery where
  message : ByteArray
  signature : MlDsaSignature

structure EufCmaResult where
  forgery : Forgery
  queriedMessages : List ByteArray

def eufCmaWins (pk : MlDsaPublicKey) (tr : ByteArray) (result : EufCmaResult) : Prop :=
  verify pk result.forgery.message result.forgery.signature tr
  ∧ result.forgery.message ∉ result.queriedMessages

-- ════════════════════════════════════════════════════════════════
-- SelfTargetMSIS
-- ════════════════════════════════════════════════════════════════

structure SelfTargetMsisInstance where
  matA : MlDsaPublicMatrix
  vecT : MlDsaPublicVec

structure SelfTargetMsisSolution where
  message : ByteArray
  response : MlDsaSecretVec
  challenge : Rq

def selfTargetMsisValid (inst : SelfTargetMsisInstance) (sol : SelfTargetMsisSolution)
    (tr : ByteArray) : Prop :=
  let w := fun i => matVecMul inst.matA sol.response i - sol.challenge * inst.vecT i
  hashToChallenge tr w sol.message = sol.challenge

theorem forgery_yields_stmsis_solution
    (pk : MlDsaPublicKey) (tr : ByteArray)
    (forgery : Forgery)
    (h_valid : verify pk forgery.message forgery.signature tr) :
    selfTargetMsisValid
      { matA := expandA pk.seedRho, vecT := pk.vecT }
      { message := forgery.message,
        response := forgery.signature.response,
        challenge := forgery.signature.challenge }
      tr := by
  simp only [selfTargetMsisValid, verify] at *
  exact h_valid

-- ════════════════════════════════════════════════════════════════
-- CMA-to-NMA Simulator
-- ════════════════════════════════════════════════════════════════

structure SimulatedSignature where
  z : MlDsaSecretVec
  c : Rq
  w : MlDsaPublicVec

def simulateSignature (pk : MlDsaPublicKey) (z : MlDsaSecretVec) (c : Rq) : SimulatedSignature :=
  let matA := expandA pk.seedRho
  let w := fun i => matVecMul matA z i - c * pk.vecT i
  { z := z, c := c, w := w }

theorem simulated_signature_verifies
    (pk : MlDsaPublicKey) (z : MlDsaSecretVec) (c : Rq) (tr : ByteArray) (msg : ByteArray)
    (h_oracle : hashToChallenge tr (simulateSignature pk z c).w msg = c) :
    verify pk msg { hint := fun _ => 0, response := z, challenge := c } tr := by
  simp only [verify, simulateSignature] at *
  exact h_oracle

-- ════════════════════════════════════════════════════════════════
-- Main theorems
-- ════════════════════════════════════════════════════════════════

theorem eufcma_implies_stmsis
    (pk : MlDsaPublicKey) (tr : ByteArray)
    (result : EufCmaResult)
    (h_win : eufCmaWins pk tr result) :
    selfTargetMsisValid
      { matA := expandA pk.seedRho, vecT := pk.vecT }
      { message := result.forgery.message,
        response := result.forgery.signature.response,
        challenge := result.forgery.signature.challenge }
      tr := by
  exact forgery_yields_stmsis_solution pk tr result.forgery h_win.1

end

end GoyaFormal
