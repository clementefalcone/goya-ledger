import Formal.Lattice.Rq

/-!
# Module-LWE — sample structure for ML-DSA-65

Defines what a Module-LWE sample is. The hardness of Module-LWE is not
stated or assumed anywhere in this development.
-/

namespace GoyaFormal

structure ModuleLweInstance where
  matA : MlDsaPublicMatrix
  vecT : MlDsaPublicVec

structure ModuleLweWitness where
  vecS : MlDsaSecretVec

noncomputable section

def matVecMul (A : MlDsaPublicMatrix) (s : MlDsaSecretVec) : MlDsaPublicVec :=
  fun i => Finset.univ.sum fun j => A i j * s j

def isModuleLweSample (inst : ModuleLweInstance) (wit : ModuleLweWitness) (noise : MlDsaPublicVec) : Prop :=
  inst.vecT = fun i => matVecMul inst.matA wit.vecS i + noise i

end

end GoyaFormal
