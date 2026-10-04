//! CLI helper for LexChain signing operations.
//!
//! Usage:
//!   goya-sign keygen ed25519
//!   goya-sign keygen ml-dsa-65
//!   goya-sign sign ed25519 <private_key_hex> <payload>
//!   goya-sign sign ml-dsa-65 <private_key_hex> <payload>

use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: goya-sign <keygen|sign> <algorithm> [args...]");
        std::process::exit(1);
    }

    let cmd = &args[1];
    let algo = &args[2];

    match cmd.as_str() {
        "keygen" => keygen(algo),
        "sign" => {
            if args.len() < 5 {
                eprintln!("Usage: goya-sign sign <algorithm> <private_key_hex> <payload>");
                std::process::exit(1);
            }
            sign(algo, &args[3], &args[4]);
        }
        _ => {
            eprintln!("Unknown command: {cmd}");
            std::process::exit(1);
        }
    }
}

fn keygen(algo: &str) {
    match algo {
        "ed25519" => {
            use pqc_crypto_module::legacy::rng::OsRng;
            let sk = pqc_crypto_module::legacy::ed25519::SigningKey::generate(&mut OsRng);
            let pk = sk.verifying_key();
            println!(
                "{}",
                serde_json::json!({
                    "algorithm": "Ed25519",
                    "did": rust_bc::identity::did::did_from_pubkey_hex(&hex::encode(pk.to_bytes())),
                    "public_key": hex::encode(pk.to_bytes()),
                    "private_key": hex::encode(sk.to_bytes()),
                })
            );
        }
        "ml-dsa-65" | "mldsa65" => {
            let kp = pqc_crypto_module::mldsa::generate_keypair_raw();
            println!(
                "{}",
                serde_json::json!({
                    "algorithm": "ML-DSA-65",
                    "did": rust_bc::identity::did::did_from_pubkey_hex(&hex::encode(kp.public_key.as_bytes())),
                    "public_key": hex::encode(kp.public_key.as_bytes()),
                    "private_key": hex::encode(kp.private_key.as_bytes()),
                })
            );
        }
        _ => {
            eprintln!("Unknown algorithm: {algo} (use ed25519 or ml-dsa-65)");
            std::process::exit(1);
        }
    }
}

fn sign(algo: &str, sk_hex: &str, payload: &str) {
    let sk_bytes = hex::decode(sk_hex).expect("invalid hex for private key");

    match algo {
        "ed25519" => {
            use pqc_crypto_module::legacy::ed25519::Signer;
            let sk_arr: [u8; 32] = sk_bytes.try_into().expect("Ed25519 sk must be 32 bytes");
            let sk = pqc_crypto_module::legacy::ed25519::SigningKey::from_bytes(&sk_arr);
            let sig = sk.sign(payload.as_bytes());
            println!(
                "{}",
                serde_json::json!({
                    "signature": hex::encode(sig.to_bytes()),
                })
            );
        }
        "ml-dsa-65" | "mldsa65" => {
            let sk = pqc_crypto_module::types::MldsaPrivateKey::from_bytes(&sk_bytes)
                .expect("invalid ML-DSA-65 private key");
            let sig = pqc_crypto_module::mldsa::sign_message_raw(&sk, payload.as_bytes())
                .expect("signing failed");
            println!(
                "{}",
                serde_json::json!({
                    "signature": hex::encode(sig.as_bytes()),
                })
            );
        }
        _ => {
            eprintln!("Unknown algorithm: {algo}");
            std::process::exit(1);
        }
    }
}
