use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=csrc/");
    println!("cargo:rerun-if-changed=build.rs");
    if env::var_os("CARGO_FEATURE_ACVP").is_none() {
        return;
    }

    let internals_include =
        env::var("DEP_PQCRYPTO_INTERNALS_INCLUDEPATH").expect("pqcrypto-internals include path");

    let mldsa_src = find_pkg_src("pqcrypto-mldsa-");
    let mldsa_clean = mldsa_src.join("pqclean/crypto_sign/ml-dsa-65/clean");
    let mldsa_common = mldsa_src.join("pqclean/common");

    cc::Build::new()
        .file("csrc/acvp_derand.c")
        .include(&internals_include)
        .include(&mldsa_common)
        .include(&mldsa_clean)
        .compile("goya_acvp");
}

fn find_pkg_src(prefix: &str) -> PathBuf {
    let home = env::var("CARGO_HOME")
        .or_else(|_| env::var("HOME").map(|h| format!("{h}/.cargo")))
        .expect("CARGO_HOME or HOME");

    let registry_src = PathBuf::from(&home).join("registry/src");
    for entry in std::fs::read_dir(&registry_src).expect("read registry/src") {
        let index_dir = entry.expect("entry").path();
        if index_dir.is_dir() {
            for pkg in std::fs::read_dir(&index_dir).expect("read index") {
                let pkg_dir = pkg.expect("pkg").path();
                if let Some(name) = pkg_dir.file_name().and_then(|n| n.to_str()) {
                    if name.starts_with(prefix) {
                        return pkg_dir;
                    }
                }
            }
        }
    }
    panic!("{prefix} not found in cargo registry");
}
