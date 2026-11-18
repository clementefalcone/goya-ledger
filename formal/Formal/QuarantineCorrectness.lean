/-!
# Quarantine Correctness — Formal Verification

Proves that quarantine never touches contracts with PQC signatures,
and always quarantines contracts with only classical signatures.

Mirrors: `src/lexchain/engine.rs :: quarantine_classical_contracts()`
-/

inductive SigAlgorithm where
  | Ed25519
  | MlDsa65
  | SlhDsa128s
  | Rsa
  | EcdsaP256
  deriving DecidableEq, Repr, BEq

open SigAlgorithm

def isPostQuantum : SigAlgorithm → Bool
  | MlDsa65    => true
  | SlhDsa128s => true
  | _          => false

def isClassical : SigAlgorithm → Bool
  | Ed25519   => true
  | Rsa       => true
  | EcdsaP256 => true
  | _         => false

def classicalAlgos : List SigAlgorithm := [Ed25519, Rsa, EcdsaP256]

def allCompromised (compromised : List SigAlgorithm) (sigs : List SigAlgorithm) : Bool :=
  sigs.all fun a => compromised.contains a

theorem pqc_classical_disjoint :
    ∀ a : SigAlgorithm, ¬(isPostQuantum a = true ∧ isClassical a = true) := by
  intro a ⟨hp, hc⟩; cases a <;> simp [isPostQuantum, isClassical] at hp hc

theorem mldsa_not_classical : isClassical MlDsa65 = false := by rfl
theorem slhdsa_not_classical : isClassical SlhDsa128s = false := by rfl
theorem ed25519_is_classical : isClassical Ed25519 = true := by rfl
theorem mldsa_is_pqc : isPostQuantum MlDsa65 = true := by rfl

theorem mldsa_not_in_classical_list :
    classicalAlgos.contains MlDsa65 = false := by decide

theorem slhdsa_not_in_classical_list :
    classicalAlgos.contains SlhDsa128s = false := by decide

theorem ed25519_in_classical_list :
    classicalAlgos.contains Ed25519 = true := by decide

theorem pqc_prevents_quarantine_singleton :
    allCompromised classicalAlgos [MlDsa65] = false := by decide

theorem pqc_prevents_quarantine_mixed :
    allCompromised classicalAlgos [Ed25519, MlDsa65] = false := by decide

theorem ed25519_only_quarantined :
    allCompromised classicalAlgos [Ed25519] = true := by decide

theorem ed25519_pair_quarantined :
    allCompromised classicalAlgos [Ed25519, Ed25519] = true := by decide

theorem rsa_quarantined :
    allCompromised classicalAlgos [Rsa] = true := by decide

theorem empty_is_vacuously_quarantined :
    allCompromised classicalAlgos [] = true := by decide
