#![no_main]
use libfuzzer_sys::fuzz_target;
use rust_bc::network::Message;
use rust_bc::storage::traits::Block;

fuzz_target!(|data: &[u8]| {
    if let Ok(Message::BftProposal { block_data, justify_qc, .. }) = serde_json::from_slice::<Message>(data) {
        let _ = serde_json::from_slice::<Block>(&block_data);
        let _ = serde_json::from_slice::<rust_bc::consensus::bft::types::QuorumCertificate>(&justify_qc);
    }
});
