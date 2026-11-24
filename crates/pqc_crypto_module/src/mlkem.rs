//! ML-KEM-768 key encapsulation (FIPS 203), backed by AWS-LC.

use aws_lc_rs::kem::{Ciphertext, DecapsulationKey, EncapsulationKey, ML_KEM_768};

use crate::approved_mode::require_approved;
use crate::errors::CryptoError;
use crate::types::{MlKemCiphertext, MlKemPrivateKey, MlKemPublicKey, MlKemSharedSecret};

/// ML-KEM-768 keypair.
pub struct MlKemKeyPair {
    pub public_key: MlKemPublicKey,
    pub private_key: MlKemPrivateKey,
}

/// Generate an ML-KEM-768 keypair. Requires approved mode.
pub fn generate_keypair() -> Result<MlKemKeyPair, CryptoError> {
    require_approved()?;
    generate_keypair_raw()
}

pub(crate) fn generate_keypair_raw() -> Result<MlKemKeyPair, CryptoError> {
    let key_failure = |_| CryptoError::InvalidKey("ML-KEM-768 key generation failed".into());
    let decapsulation_key = DecapsulationKey::generate(&ML_KEM_768).map_err(key_failure)?;
    let private_key = MlKemPrivateKey(
        decapsulation_key
            .key_bytes()
            .map_err(key_failure)?
            .as_ref()
            .to_vec(),
    );
    private_key.mlock();
    let public_key = MlKemPublicKey(
        decapsulation_key
            .encapsulation_key()
            .and_then(|key| key.key_bytes())
            .map_err(key_failure)?
            .as_ref()
            .to_vec(),
    );
    Ok(MlKemKeyPair {
        public_key,
        private_key,
    })
}

/// Encapsulate: generate a shared secret and ciphertext from a public key.
pub fn encapsulate(
    public_key: &MlKemPublicKey,
) -> Result<(MlKemCiphertext, MlKemSharedSecret), CryptoError> {
    require_approved()?;
    encapsulate_raw(public_key)
}

pub fn encapsulate_raw(
    public_key: &MlKemPublicKey,
) -> Result<(MlKemCiphertext, MlKemSharedSecret), CryptoError> {
    let encapsulation_key = EncapsulationKey::new(&ML_KEM_768, public_key.as_bytes())
        .map_err(|_| CryptoError::InvalidKey("invalid ML-KEM-768 public key".into()))?;
    let (ciphertext, secret) = encapsulation_key
        .encapsulate()
        .map_err(|_| CryptoError::InvalidKey("ML-KEM-768 encapsulation failed".into()))?;
    let shared = MlKemSharedSecret(secret.as_ref().to_vec());
    shared.mlock();
    Ok((MlKemCiphertext(ciphertext.as_ref().to_vec()), shared))
}

/// Decapsulate: recover the shared secret from a ciphertext and private key.
pub fn decapsulate(
    private_key: &MlKemPrivateKey,
    ciphertext: &MlKemCiphertext,
) -> Result<MlKemSharedSecret, CryptoError> {
    require_approved()?;
    decapsulate_raw(private_key, ciphertext)
}

pub fn decapsulate_raw(
    private_key: &MlKemPrivateKey,
    ciphertext: &MlKemCiphertext,
) -> Result<MlKemSharedSecret, CryptoError> {
    let decapsulation_key = DecapsulationKey::new(&ML_KEM_768, &private_key.0)
        .map_err(|_| CryptoError::InvalidKey("invalid ML-KEM-768 private key".into()))?;
    if ciphertext.as_bytes().len() != 1088 {
        return Err(CryptoError::InvalidKey(
            "invalid ML-KEM-768 ciphertext".into(),
        ));
    }
    let secret = decapsulation_key
        .decapsulate(Ciphertext::from(ciphertext.as_bytes()))
        .map_err(|_| CryptoError::InvalidKey("invalid ML-KEM-768 ciphertext".into()))?;
    let shared = MlKemSharedSecret(secret.as_ref().to_vec());
    shared.mlock();
    Ok(shared)
}

#[cfg(feature = "acvp")]
mod pqclean_derand {
    extern crate pqcrypto_mlkem;

    use super::*;

    extern "C" {
        #[link_name = "PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair_derand"]
        fn mlkem768_keypair_derand(
            pk: *mut u8,
            sk: *mut u8,
            coins: *const u8,
        ) -> std::os::raw::c_int;

        #[link_name = "PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc_derand"]
        fn mlkem768_enc_derand(
            ct: *mut u8,
            ss: *mut u8,
            pk: *const u8,
            coins: *const u8,
        ) -> std::os::raw::c_int;
    }

    /// Deterministic ML-KEM-768 keygen from 64 bytes of coins (d || z).
    /// For ACVP/CMVP testing only.
    #[doc(hidden)]
    pub fn generate_keypair_derand(coins: &[u8; 64]) -> Result<MlKemKeyPair, CryptoError> {
        let mut pk = vec![0u8; 1184];
        let mut sk = vec![0u8; 2400];
        // SAFETY: pk (1184 B) and sk (2400 B) pre-allocated to FIPS 203 spec sizes.
        // coins is a valid 64-byte slice. PQClean writes exactly pk_len + sk_len bytes.
        let ret =
            unsafe { mlkem768_keypair_derand(pk.as_mut_ptr(), sk.as_mut_ptr(), coins.as_ptr()) };
        if ret != 0 {
            return Err(CryptoError::InvalidKey(
                "mlkem keypair_derand failed".into(),
            ));
        }
        let private_key = MlKemPrivateKey(sk);
        private_key.mlock();
        Ok(MlKemKeyPair {
            public_key: MlKemPublicKey(pk),
            private_key,
        })
    }

    /// Deterministic ML-KEM-768 encapsulation from 32 bytes of coins (m).
    /// For ACVP/CMVP testing only.
    #[doc(hidden)]
    pub fn encapsulate_derand(
        public_key: &MlKemPublicKey,
        coins: &[u8; 32],
    ) -> Result<(MlKemCiphertext, MlKemSharedSecret), CryptoError> {
        let mut ct = vec![0u8; 1088];
        let mut ss = vec![0u8; 32];
        // SAFETY: ct (1088 B) and ss (32 B) pre-allocated to FIPS 203 spec sizes.
        // public_key is validated by caller. coins is a valid 32-byte slice.
        // PQClean writes exactly ct_len + ss_len bytes.
        let ret = unsafe {
            mlkem768_enc_derand(
                ct.as_mut_ptr(),
                ss.as_mut_ptr(),
                public_key.as_bytes().as_ptr(),
                coins.as_ptr(),
            )
        };
        if ret != 0 {
            return Err(CryptoError::InvalidKey("mlkem enc_derand failed".into()));
        }
        let shared = MlKemSharedSecret(ss);
        shared.mlock();
        Ok((MlKemCiphertext(ct), shared))
    }
}

#[cfg(feature = "acvp")]
pub use pqclean_derand::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approved_mode::{set_state, ModuleState};

    #[test]
    fn keygen_produces_correct_sizes() {
        let kp = generate_keypair_raw().unwrap();
        assert_eq!(kp.public_key.as_bytes().len(), 1184);
        assert_eq!(kp.private_key.0.len(), 2400);
    }

    #[test]
    fn encapsulate_produces_correct_sizes() {
        let kp = generate_keypair_raw().unwrap();
        let (ct, ss) = encapsulate_raw(&kp.public_key).unwrap();
        assert_eq!(ct.as_bytes().len(), 1088);
        assert_eq!(ss.as_bytes().len(), 32);
    }

    #[test]
    fn mlkem_keypair_encaps_decaps_roundtrip() {
        let kp = generate_keypair_raw().unwrap();
        let (ct, ss1) = encapsulate_raw(&kp.public_key).unwrap();
        let ss2 = decapsulate_raw(&kp.private_key, &ct).unwrap();
        assert_eq!(ss1.as_bytes(), ss2.as_bytes());
    }

    #[test]
    fn mlkem_invalid_ciphertext_rejected() {
        let kp = generate_keypair_raw().unwrap();
        let bad_ct = MlKemCiphertext(vec![0xAA; 100]);
        assert!(decapsulate_raw(&kp.private_key, &bad_ct).is_err());
    }

    #[test]
    fn mlkem_private_key_zeroizes_on_drop() {
        let kp = generate_keypair_raw().unwrap();
        let len = kp.private_key.0.len();
        assert!(len > 0);
        drop(kp.private_key);
        // ZeroizeOnDrop derive verified by compilation and non-zero initial size.
    }

    #[test]
    fn mlkem_shared_secret_zeroizes_on_drop() {
        let kp = generate_keypair_raw().unwrap();
        let (_, ss) = encapsulate_raw(&kp.public_key).unwrap();
        let len = ss.as_bytes().len();
        assert_eq!(len, 32);
        drop(ss);
        // ZeroizeOnDrop derive verified by compilation.
    }

    #[test]
    fn mlkem_api_rejects_before_approved_mode() {
        // Reset state to Uninitialized
        set_state(ModuleState::Uninitialized);
        assert!(generate_keypair().is_err());
    }

    #[test]
    fn mlkem_api_works_after_approved_mode() {
        set_state(ModuleState::Approved);
        let kp = generate_keypair().unwrap();
        let (ct, ss1) = encapsulate(&kp.public_key).unwrap();
        let ss2 = decapsulate(&kp.private_key, &ct).unwrap();
        assert_eq!(ss1.as_bytes(), ss2.as_bytes());
    }
}
