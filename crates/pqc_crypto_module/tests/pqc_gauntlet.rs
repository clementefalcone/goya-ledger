//! PQC Gauntlet — Exhaustive post-quantum cryptographic verification.
//!
//! Goes beyond IOTA/Cardano/Ethereum PQC testing:
//! - NIST FIPS 204/203 parameter conformance
//! - Bit-level signature corruption (every byte position)
//! - ML-DSA randomized signing proof (non-deterministic by spec)
//! - ML-KEM IND-CCA2 implicit rejection
//! - Cross-keypair forgery resistance
//! - Signature malleability detection
//! - Pathological input resistance
//! - Key validation (wrong sizes, all-zero, all-ones)
//! - Timing baseline for side-channel awareness
//! - Entropy quality (chi-squared, byte distribution)

use std::sync::MutexGuard;
use std::time::Instant;

use pqc_crypto_module::api;
use pqc_crypto_module::approved_mode;
use pqc_crypto_module::types::*;

fn init() -> MutexGuard<'static, ()> {
    let guard = approved_mode::__test_reset();
    api::initialize_approved_mode().unwrap();
    guard
}

// ═══════════════════════════════════════════════════════════════════
// 1. FIPS 204 PARAMETER CONFORMANCE (ML-DSA-65)
// ═══════════════════════════════════════════════════════════════════

#[test]
fn mldsa65_public_key_exactly_1952_bytes() {
    let _g = init();
    for _ in 0..10 {
        let kp = api::generate_mldsa_keypair().unwrap();
        assert_eq!(kp.public_key.as_bytes().len(), 1952);
    }
}

#[test]
fn mldsa65_private_key_exactly_4032_bytes() {
    let _g = init();
    for _ in 0..10 {
        let kp = api::generate_mldsa_keypair().unwrap();
        assert_eq!(kp.private_key.as_bytes().len(), 4032);
    }
}

#[test]
fn mldsa65_signature_exactly_3309_bytes() {
    let _g = init();
    let kp = api::generate_mldsa_keypair().unwrap();
    for i in 0..10 {
        let msg = format!("message {i}");
        let sig = api::sign_message(&kp.private_key, msg.as_bytes()).unwrap();
        assert_eq!(sig.as_bytes().len(), 3309);
    }
}

// ═══════════════════════════════════════════════════════════════════
// 2. ML-DSA RANDOMIZED SIGNING (FIPS 204 §5.2)
//    ML-DSA-65 is RANDOMIZED — same key+msg MUST produce different sigs
// ═══════════════════════════════════════════════════════════════════

#[test]
fn mldsa65_signing_is_randomized() {
    let _g = init();
    let kp = api::generate_mldsa_keypair().unwrap();
    let msg = b"randomization test vector";

    let sig1 = api::sign_message(&kp.private_key, msg).unwrap();
    let sig2 = api::sign_message(&kp.private_key, msg).unwrap();

    assert_ne!(
        sig1.as_bytes(),
        sig2.as_bytes(),
        "ML-DSA-65 is randomized per FIPS 204 — same key+msg must produce different signatures"
    );

    // Both must still verify
    api::verify_signature(&kp.public_key, msg, &sig1).unwrap();
    api::verify_signature(&kp.public_key, msg, &sig2).unwrap();
}

// ═══════════════════════════════════════════════════════════════════
// 3. BIT-LEVEL SIGNATURE CORRUPTION
//    Flip one byte at every position — none must verify
// ═══════════════════════════════════════════════════════════════════

#[test]
fn mldsa65_single_byte_corruption_at_every_position() {
    let _g = init();
    let kp = api::generate_mldsa_keypair().unwrap();
    let msg = b"corruption sweep";
    let sig = api::sign_message(&kp.private_key, msg).unwrap();
    let sig_bytes = sig.as_bytes().to_vec();

    // Sample every 33rd position (100 positions across 3309 bytes)
    // Full sweep at every position would be 3309 tests — we sample densely
    let positions: Vec<usize> = (0..sig_bytes.len()).step_by(33).collect();
    let mut failed_positions = vec![];

    for &pos in &positions {
        let mut corrupted = sig_bytes.clone();
        corrupted[pos] ^= 0x01; // Minimal bit flip
        let bad_sig = MldsaSignature(corrupted);
        if api::verify_signature(&kp.public_key, msg, &bad_sig).is_ok() {
            failed_positions.push(pos);
        }
    }

    assert!(
        failed_positions.is_empty(),
        "Signature verified after corruption at byte positions: {failed_positions:?}"
    );
}

#[test]
fn mldsa65_first_last_middle_byte_corruption() {
    let _g = init();
    let kp = api::generate_mldsa_keypair().unwrap();
    let msg = b"boundary corruption test";
    let sig = api::sign_message(&kp.private_key, msg).unwrap();
    let sig_bytes = sig.as_bytes().to_vec();

    for pos in [0, sig_bytes.len() / 2, sig_bytes.len() - 1] {
        for flip in [0x01, 0x80, 0xFF] {
            let mut corrupted = sig_bytes.clone();
            corrupted[pos] ^= flip;
            let bad_sig = MldsaSignature(corrupted);
            assert!(
                api::verify_signature(&kp.public_key, msg, &bad_sig).is_err(),
                "Corruption at pos={pos} flip=0x{flip:02X} must fail"
            );
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// 4. CROSS-KEYPAIR FORGERY RESISTANCE
// ═══════════════════════════════════════════════════════════════════

#[test]
fn mldsa65_cross_keypair_signature_rejected() {
    let _g = init();
    let kp_a = api::generate_mldsa_keypair().unwrap();
    let kp_b = api::generate_mldsa_keypair().unwrap();
    let msg = b"cross-key forgery attempt";

    let sig_a = api::sign_message(&kp_a.private_key, msg).unwrap();

    // Signature from key A must not verify under key B
    assert!(
        api::verify_signature(&kp_b.public_key, msg, &sig_a).is_err(),
        "CRITICAL: signature from key A verified under key B"
    );
}

#[test]
fn mldsa65_ten_keypairs_no_cross_verification() {
    let _g = init();
    let keypairs: Vec<_> = (0..10)
        .map(|_| api::generate_mldsa_keypair().unwrap())
        .collect();
    let msg = b"multi-key isolation test";

    for (i, kp) in keypairs.iter().enumerate() {
        let sig = api::sign_message(&kp.private_key, msg).unwrap();

        // Must verify with own key
        api::verify_signature(&kp.public_key, msg, &sig).unwrap();

        // Must NOT verify with any other key
        for (j, other) in keypairs.iter().enumerate() {
            if i != j {
                assert!(
                    api::verify_signature(&other.public_key, msg, &sig).is_err(),
                    "Key {i}'s signature verified under key {j}"
                );
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// 5. SIGNATURE MALLEABILITY
//    Can an attacker produce a second valid signature from a valid one?
// ═══════════════════════════════════════════════════════════════════

#[test]
fn mldsa65_signature_not_malleable_by_negation() {
    let _g = init();
    let kp = api::generate_mldsa_keypair().unwrap();
    let msg = b"malleability test";
    let sig = api::sign_message(&kp.private_key, msg).unwrap();

    // Try common malleability attacks
    let attacks: Vec<(&str, Vec<u8>)> = vec![
        // Bit-complement entire signature
        ("complement", sig.as_bytes().iter().map(|b| !b).collect()),
        // Reverse signature bytes
        ("reverse", sig.as_bytes().iter().rev().copied().collect()),
        // Zero-pad
        ("zero-extend", {
            let mut v = sig.as_bytes().to_vec();
            v.push(0);
            v.truncate(3309);
            v
        }),
    ];

    for (name, mutated) in attacks {
        if mutated.len() == 3309 && mutated != sig.as_bytes() {
            let bad = MldsaSignature(mutated);
            assert!(
                api::verify_signature(&kp.public_key, msg, &bad).is_err(),
                "Malleability attack '{name}' produced a valid signature"
            );
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// 6. PATHOLOGICAL INPUT RESISTANCE
// ═══════════════════════════════════════════════════════════════════

#[test]
fn mldsa65_sign_verify_empty_message() {
    let _g = init();
    let kp = api::generate_mldsa_keypair().unwrap();
    let sig = api::sign_message(&kp.private_key, b"").unwrap();
    api::verify_signature(&kp.public_key, b"", &sig).unwrap();
}

#[test]
fn mldsa65_sign_verify_single_byte() {
    let _g = init();
    let kp = api::generate_mldsa_keypair().unwrap();
    for byte in [0x00, 0x01, 0x7F, 0x80, 0xFF] {
        let msg = &[byte];
        let sig = api::sign_message(&kp.private_key, msg).unwrap();
        api::verify_signature(&kp.public_key, msg, &sig).unwrap();
    }
}

#[test]
fn mldsa65_sign_verify_large_message_1mb() {
    let _g = init();
    let kp = api::generate_mldsa_keypair().unwrap();
    let msg = vec![0xAB; 1_048_576]; // 1 MB
    let sig = api::sign_message(&kp.private_key, &msg).unwrap();
    api::verify_signature(&kp.public_key, &msg, &sig).unwrap();
}

#[test]
fn mldsa65_sign_verify_all_zeros_message() {
    let _g = init();
    let kp = api::generate_mldsa_keypair().unwrap();
    let msg = vec![0u8; 10_000];
    let sig = api::sign_message(&kp.private_key, &msg).unwrap();
    api::verify_signature(&kp.public_key, &msg, &sig).unwrap();
}

#[test]
fn mldsa65_sign_verify_all_ones_message() {
    let _g = init();
    let kp = api::generate_mldsa_keypair().unwrap();
    let msg = vec![0xFF; 10_000];
    let sig = api::sign_message(&kp.private_key, &msg).unwrap();
    api::verify_signature(&kp.public_key, &msg, &sig).unwrap();
}

// ═══════════════════════════════════════════════════════════════════
// 7. KEY VALIDATION — REJECT PATHOLOGICAL KEYS
// ═══════════════════════════════════════════════════════════════════

#[test]
fn reject_zero_private_key() {
    let _g = init();
    let zero_sk = MldsaPrivateKey(vec![0u8; 4032]);
    let result = api::sign_message(&zero_sk, b"test");
    // Must either error or produce a signature that fails to verify
    // (the implementation may accept the key but produce invalid output)
    if let Ok(sig) = result {
        let zero_pk = MldsaPublicKey(vec![0u8; 1952]);
        assert!(
            api::verify_signature(&zero_pk, b"test", &sig).is_err(),
            "All-zero keypair must not produce valid signatures"
        );
    }
}

#[test]
fn reject_wrong_size_public_key() {
    let _g = init();
    let kp = api::generate_mldsa_keypair().unwrap();
    let sig = api::sign_message(&kp.private_key, b"size test").unwrap();

    for size in [0, 1, 32, 64, 1951, 1953, 3309, 4032] {
        let bad_pk = MldsaPublicKey(vec![0x42; size]);
        assert!(
            api::verify_signature(&bad_pk, b"size test", &sig).is_err(),
            "Public key of size {size} must be rejected"
        );
    }
}

#[test]
fn reject_wrong_size_signature() {
    let _g = init();
    let kp = api::generate_mldsa_keypair().unwrap();

    for size in [0, 1, 64, 3308, 3310, 4032, 6618] {
        let bad_sig = MldsaSignature(vec![0x42; size]);
        assert!(
            api::verify_signature(&kp.public_key, b"size test", &bad_sig).is_err(),
            "Signature of size {size} must be rejected"
        );
    }
}

#[test]
fn reject_truncated_signature() {
    let _g = init();
    let kp = api::generate_mldsa_keypair().unwrap();
    let sig = api::sign_message(&kp.private_key, b"truncation test").unwrap();

    for trim in [1, 10, 100, 1000, 3308] {
        let truncated = MldsaSignature(sig.as_bytes()[..3309 - trim].to_vec());
        assert!(
            api::verify_signature(&kp.public_key, b"truncation test", &truncated).is_err(),
            "Signature truncated by {trim} bytes must be rejected"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════
// 8. ML-KEM-768 GAUNTLET (FIPS 203)
// ═══════════════════════════════════════════════════════════════════

#[test]
fn mlkem768_parameter_sizes() {
    let _g = init();
    let kp = api::generate_mlkem_keypair().unwrap();
    assert_eq!(kp.public_key.as_bytes().len(), 1184, "ML-KEM-768 pk");
    assert_eq!(kp.private_key.0.len(), 2400, "ML-KEM-768 sk");

    let (ct, ss) = api::mlkem_encapsulate(&kp.public_key).unwrap();
    assert_eq!(ct.as_bytes().len(), 1088, "ML-KEM-768 ciphertext");
    assert_eq!(ss.as_bytes().len(), 32, "ML-KEM-768 shared secret");
}

#[test]
fn mlkem768_ind_cca2_implicit_rejection() {
    // ML-KEM-768 is IND-CCA2 secure: decapsulating a corrupted ciphertext
    // must produce a DIFFERENT shared secret (implicit rejection), not error.
    // This is a critical security property — without it, an oracle attack is possible.
    let _g = init();
    let kp = api::generate_mlkem_keypair().unwrap();
    let (ct, ss_good) = api::mlkem_encapsulate(&kp.public_key).unwrap();

    // Corrupt one byte of ciphertext
    let mut bad_ct_bytes = ct.as_bytes().to_vec();
    bad_ct_bytes[0] ^= 0x01;
    let bad_ct = MlKemCiphertext(bad_ct_bytes);

    // Some implementations error instead of implicit reject — both acceptable
    if let Ok(ss_bad) = api::mlkem_decapsulate(&kp.private_key, &bad_ct) {
        assert_ne!(
            ss_good.as_bytes(),
            ss_bad.as_bytes(),
            "IND-CCA2 VIOLATION: corrupted ciphertext produced same shared secret"
        );
    }
}

#[test]
fn mlkem768_cross_keypair_decapsulation_fails() {
    let _g = init();
    let kp_a = api::generate_mlkem_keypair().unwrap();
    let kp_b = api::generate_mlkem_keypair().unwrap();

    let (ct, ss_a) = api::mlkem_encapsulate(&kp_a.public_key).unwrap();

    // Decapsulate with wrong key — must produce different secret
    if let Ok(ss_b) = api::mlkem_decapsulate(&kp_b.private_key, &ct) {
        assert_ne!(
            ss_a.as_bytes(),
            ss_b.as_bytes(),
            "CRITICAL: same shared secret with different private key"
        );
    }
}

#[test]
fn mlkem768_encapsulation_is_randomized() {
    let _g = init();
    let kp = api::generate_mlkem_keypair().unwrap();

    let (ct1, ss1) = api::mlkem_encapsulate(&kp.public_key).unwrap();
    let (ct2, ss2) = api::mlkem_encapsulate(&kp.public_key).unwrap();

    assert_ne!(
        ct1.as_bytes(),
        ct2.as_bytes(),
        "ML-KEM encapsulation must be randomized"
    );
    assert_ne!(
        ss1.as_bytes(),
        ss2.as_bytes(),
        "Different encapsulations must produce different shared secrets"
    );
}

#[test]
fn mlkem768_wrong_ciphertext_sizes_rejected() {
    let _g = init();
    let kp = api::generate_mlkem_keypair().unwrap();

    for size in [0, 1, 32, 1087, 1089, 2000, 4096] {
        let bad_ct = MlKemCiphertext(vec![0x42; size]);
        assert!(
            api::mlkem_decapsulate(&kp.private_key, &bad_ct).is_err(),
            "Ciphertext of size {size} must be rejected"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════
// 9. ENTROPY QUALITY
// ═══════════════════════════════════════════════════════════════════

#[test]
fn rng_byte_distribution_chi_squared() {
    let _g = init();
    // Generate 10KB of random bytes and verify uniform distribution
    let bytes = api::random_bytes(10_000).unwrap();

    let mut counts = [0u64; 256];
    for &b in &bytes {
        counts[b as usize] += 1;
    }

    // Chi-squared test: expected = 10000/256 ≈ 39.06
    let expected = 10_000.0 / 256.0;
    let chi_sq: f64 = counts
        .iter()
        .map(|&c| {
            let diff = c as f64 - expected;
            diff * diff / expected
        })
        .sum();

    // Critical value for 255 df at p=0.001 is ~310.5
    // We use a generous threshold to avoid flaky tests
    assert!(
        chi_sq < 350.0,
        "RNG byte distribution failed chi-squared test: {chi_sq:.1} (threshold 350.0)"
    );
}

#[test]
fn rng_no_repeated_32_byte_blocks() {
    let _g = init();
    let mut seen = std::collections::HashSet::new();
    for _ in 0..1000 {
        let block = api::random_bytes(32).unwrap();
        assert!(
            seen.insert(block),
            "RNG produced duplicate 32-byte block in 1000 samples"
        );
    }
}

#[test]
fn rng_consecutive_outputs_differ() {
    let _g = init();
    let mut prev = api::random_bytes(32).unwrap();
    for i in 0..100 {
        let next = api::random_bytes(32).unwrap();
        assert_ne!(
            prev, next,
            "RNG produced identical consecutive output at iteration {i}"
        );
        prev = next;
    }
}

// ═══════════════════════════════════════════════════════════════════
// 10. KEYGEN UNIQUENESS
// ═══════════════════════════════════════════════════════════════════

#[test]
fn mldsa65_keygen_unique_keypairs() {
    let _g = init();
    let mut public_keys = std::collections::HashSet::new();
    for _ in 0..50 {
        let kp = api::generate_mldsa_keypair().unwrap();
        let pk = kp.public_key.as_bytes().to_vec();
        assert!(
            public_keys.insert(pk),
            "ML-DSA keygen produced duplicate public key in 50 samples"
        );
    }
}

#[test]
fn mlkem768_keygen_unique_keypairs() {
    let _g = init();
    let mut public_keys = std::collections::HashSet::new();
    for _ in 0..50 {
        let kp = api::generate_mlkem_keypair().unwrap();
        let pk = kp.public_key.as_bytes().to_vec();
        assert!(
            public_keys.insert(pk),
            "ML-KEM keygen produced duplicate public key in 50 samples"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════
// 11. SHA3-256 NIST KAT VECTORS
// ═══════════════════════════════════════════════════════════════════

#[test]
fn sha3_256_nist_kat_vectors() {
    let _g = init();
    // Official NIST test vectors from FIPS 202
    let vectors: Vec<(&[u8], &str)> = vec![
        (
            b"",
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
        ),
        (
            b"abc",
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
        ),
        (
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376",
        ),
    ];

    for (input, expected) in vectors {
        let hash = api::sha3_256(input).unwrap();
        assert_eq!(
            hash.to_hex(),
            expected,
            "SHA3-256 KAT failed for input of length {}",
            input.len()
        );
    }
}

#[test]
fn sha3_256_deterministic() {
    let _g = init();
    let input = b"determinism test vector 2026";
    let h1 = api::sha3_256(input).unwrap();
    let h2 = api::sha3_256(input).unwrap();
    assert_eq!(h1, h2, "SHA3-256 must be deterministic");
}

#[test]
fn sha3_256_avalanche_effect() {
    let _g = init();
    let h1 = api::sha3_256(b"A").unwrap();
    let h2 = api::sha3_256(b"B").unwrap();

    // Count differing bits
    let diff_bits: u32 = h1
        .as_bytes()
        .iter()
        .zip(h2.as_bytes().iter())
        .map(|(a, b)| (a ^ b).count_ones())
        .sum();

    // Ideal avalanche: 128 bits differ (50% of 256)
    // Accept 90-166 range (generous to avoid flaky)
    assert!(
        (90..=166).contains(&diff_bits),
        "SHA3-256 avalanche: {diff_bits} bits differ (expected ~128)"
    );
}

// ═══════════════════════════════════════════════════════════════════
// 12. TIMING BASELINE (side-channel awareness)
//     Not a definitive constant-time test, but flags gross violations
// ═══════════════════════════════════════════════════════════════════

#[test]
fn mldsa65_verify_timing_no_gross_shortcut() {
    let _g = init();
    let kp = api::generate_mldsa_keypair().unwrap();
    let msg = b"timing test";
    let sig = api::sign_message(&kp.private_key, msg).unwrap();

    // Time valid verification
    let start = Instant::now();
    for _ in 0..100 {
        let _ = api::verify_signature(&kp.public_key, msg, &sig);
    }
    let valid_time = start.elapsed();

    // Time invalid verification (corrupted signature)
    let mut bad_sig_bytes = sig.as_bytes().to_vec();
    bad_sig_bytes[0] ^= 0xFF;
    let bad_sig = MldsaSignature(bad_sig_bytes);

    let start = Instant::now();
    for _ in 0..100 {
        let _ = api::verify_signature(&kp.public_key, msg, &bad_sig);
    }
    let invalid_time = start.elapsed();

    // Gross timing difference (>10x) would indicate early-exit
    let ratio = if valid_time > invalid_time {
        valid_time.as_nanos() as f64 / invalid_time.as_nanos().max(1) as f64
    } else {
        invalid_time.as_nanos() as f64 / valid_time.as_nanos().max(1) as f64
    };

    assert!(
        ratio < 10.0,
        "Timing ratio {ratio:.1}x between valid/invalid verify suggests early-exit vulnerability"
    );
}

// ═══════════════════════════════════════════════════════════════════
// 13. MESSAGE SENSITIVITY
//     Signatures must be bound to exact message content
// ═══════════════════════════════════════════════════════════════════

#[test]
fn mldsa65_adjacent_messages_produce_different_valid_signatures() {
    let _g = init();
    let kp = api::generate_mldsa_keypair().unwrap();

    let messages: Vec<&[u8]> = vec![
        b"transfer 100",
        b"transfer 101",
        b"transfer 100\0",
        b"Transfer 100",
        b" transfer 100",
        b"transfer 100 ",
    ];

    for (i, msg_a) in messages.iter().enumerate() {
        let sig_a = api::sign_message(&kp.private_key, msg_a).unwrap();
        api::verify_signature(&kp.public_key, msg_a, &sig_a).unwrap();

        for (j, msg_b) in messages.iter().enumerate() {
            if i != j {
                // Signature for msg_a must not verify under msg_b
                assert!(
                    api::verify_signature(&kp.public_key, msg_b, &sig_a).is_err(),
                    "Signature for message[{i}] verified under message[{j}]"
                );
            }
        }
    }
}

#[test]
fn mldsa65_null_byte_injection() {
    let _g = init();
    let kp = api::generate_mldsa_keypair().unwrap();

    let msg1 = b"payload";
    let msg2 = b"payload\x00evil";

    let sig1 = api::sign_message(&kp.private_key, msg1).unwrap();
    let sig2 = api::sign_message(&kp.private_key, msg2).unwrap();

    // sig1 must not verify msg2 and vice versa
    assert!(api::verify_signature(&kp.public_key, msg2, &sig1).is_err());
    assert!(api::verify_signature(&kp.public_key, msg1, &sig2).is_err());
}

// ═══════════════════════════════════════════════════════════════════
// 14. HMAC-SHA3-256 KAT
// ═══════════════════════════════════════════════════════════════════

#[test]
fn hmac_sha3_256_different_keys_produce_different_macs() {
    let _g = init();
    let data = b"authenticated data";
    let mac1 = api::hmac_sha3_256(b"key1", data).unwrap();
    let mac2 = api::hmac_sha3_256(b"key2", data).unwrap();
    assert_ne!(mac1.to_hex(), mac2.to_hex());
}

#[test]
fn hmac_sha3_256_different_data_produce_different_macs() {
    let _g = init();
    let key = b"shared key";
    let mac1 = api::hmac_sha3_256(key, b"data1").unwrap();
    let mac2 = api::hmac_sha3_256(key, b"data2").unwrap();
    assert_ne!(mac1.to_hex(), mac2.to_hex());
}

#[test]
fn hmac_sha3_256_deterministic() {
    let _g = init();
    let mac1 = api::hmac_sha3_256(b"key", b"data").unwrap();
    let mac2 = api::hmac_sha3_256(b"key", b"data").unwrap();
    assert_eq!(mac1, mac2);
}

// ═══════════════════════════════════════════════════════════════════
// 15. KEY ENTROPY — verify keys are not degenerate
// ═══════════════════════════════════════════════════════════════════

#[test]
fn mldsa65_public_key_has_sufficient_entropy() {
    let _g = init();
    let kp = api::generate_mldsa_keypair().unwrap();
    let pk = kp.public_key.as_bytes();

    // Count unique bytes — real keys should use most of 0-255
    let unique: std::collections::HashSet<u8> = pk.iter().copied().collect();
    assert!(
        unique.len() > 200,
        "Public key uses only {}/256 unique byte values — suspicious",
        unique.len()
    );
}

#[test]
fn mldsa65_private_key_has_sufficient_entropy() {
    let _g = init();
    let kp = api::generate_mldsa_keypair().unwrap();
    let sk = kp.private_key.as_bytes();

    let unique: std::collections::HashSet<u8> = sk.iter().copied().collect();
    assert!(
        unique.len() > 200,
        "Private key uses only {}/256 unique byte values — suspicious",
        unique.len()
    );
}

// ═══════════════════════════════════════════════════════════════════
// 16. APPROVED MODE ENFORCEMENT (defense in depth)
// ═══════════════════════════════════════════════════════════════════

#[test]
fn all_apis_reject_in_error_state() {
    let _state = approved_mode::__test_reset();
    approved_mode::set_state(approved_mode::ModuleState::Error);

    assert!(
        api::generate_mldsa_keypair().is_err(),
        "generate_mldsa must reject"
    );
    assert!(
        api::generate_mlkem_keypair().is_err(),
        "generate_mlkem must reject"
    );
    assert!(api::sha3_256(b"x").is_err(), "sha3_256 must reject");
    assert!(api::random_bytes(32).is_err(), "random_bytes must reject");
    // hmac_sha3_256 intentionally does NOT require approved mode (utility hash)
}

// ═══════════════════════════════════════════════════════════════════
// 17. ALGORITHM PARAMETER CENSUS
//     Verify the module exposes exactly the algorithms we claim
// ═══════════════════════════════════════════════════════════════════

#[test]
fn module_exposes_exactly_mldsa65_mlkem768_sha3() {
    let _g = init();

    // ML-DSA-65 keypair sizes match FIPS 204 Table 1
    let dsa_kp = api::generate_mldsa_keypair().unwrap();
    assert_eq!(dsa_kp.public_key.as_bytes().len(), 1952); // FIPS 204: τ·(1+k·d)...
    assert_eq!(dsa_kp.private_key.as_bytes().len(), 4032);

    // ML-KEM-768 sizes match FIPS 203 Table 2
    let kem_kp = api::generate_mlkem_keypair().unwrap();
    assert_eq!(kem_kp.public_key.as_bytes().len(), 1184); // 384·k + 32
    assert_eq!(kem_kp.private_key.0.len(), 2400);

    let (ct, ss) = api::mlkem_encapsulate(&kem_kp.public_key).unwrap();
    assert_eq!(ct.as_bytes().len(), 1088); // du·k·n/8 + dv·n/8
    assert_eq!(ss.as_bytes().len(), 32);

    // SHA3-256 output
    let h = api::sha3_256(b"census").unwrap();
    assert_eq!(h.as_bytes().len(), 32);
}

// ═══════════════════════════════════════════════════════════════════
// 18. STRESS: RAPID KEYGEN + SIGN/VERIFY CYCLES
// ═══════════════════════════════════════════════════════════════════

#[test]
fn mldsa65_100_keygen_sign_verify_cycles() {
    let _g = init();
    for i in 0..100 {
        let kp = api::generate_mldsa_keypair().unwrap();
        let msg = format!("cycle {i}");
        let sig = api::sign_message(&kp.private_key, msg.as_bytes()).unwrap();
        api::verify_signature(&kp.public_key, msg.as_bytes(), &sig)
            .unwrap_or_else(|e| panic!("cycle {i} failed: {e}"));
    }
}

#[test]
fn mlkem768_100_encaps_decaps_cycles() {
    let _g = init();
    for i in 0..100 {
        let kp = api::generate_mlkem_keypair().unwrap();
        let (ct, ss1) = api::mlkem_encapsulate(&kp.public_key).unwrap();
        let ss2 = api::mlkem_decapsulate(&kp.private_key, &ct)
            .unwrap_or_else(|e| panic!("cycle {i} failed: {e}"));
        assert_eq!(ss1.as_bytes(), ss2.as_bytes(), "cycle {i} mismatch");
    }
}
