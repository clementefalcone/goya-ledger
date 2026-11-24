#![no_main]
use libfuzzer_sys::fuzz_target;
use rust_bc::identity::signing::{MlDsaSigningProvider, SigningProvider};

static PROVIDER: std::sync::LazyLock<MlDsaSigningProvider> =
    std::sync::LazyLock::new(MlDsaSigningProvider::generate);

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }

    let split = 1 + data[0] as usize % (data.len() - 1);
    let message = &data[1..split];
    let fuzzed_sig = &data[split..];

    let _ = PROVIDER.verify(message, fuzzed_sig);

    if data.len() >= 3309 {
        let _ = PROVIDER.verify(b"fixed message", &data[..3309]);
    }

    if !data.is_empty() {
        let valid_sig = PROVIDER.sign(b"test").unwrap_or_default();
        if !valid_sig.is_empty() {
            let mut corrupted = valid_sig.clone();
            let flip_pos = data[0] as usize % corrupted.len();
            corrupted[flip_pos] ^= data.last().copied().unwrap_or(0xFF).max(1);
            let result = PROVIDER.verify(b"test", &corrupted);
            match result {
                Ok(valid) => assert!(!valid, "bitflipped signature must not verify"),
                Err(_) => {}
            }
        }
    }
});
