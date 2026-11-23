//! PDF → DocumentFingerprint decomposition.
//!
//! Extracts text, structure, and metadata from a PDF binary
//! and produces a dimensional fingerprint for on-chain notarization.

use crate::crypto::hasher::{hash_with, HashAlgorithm};
use crate::document::fingerprint::DocumentFingerprint;
use lopdf::Object;

/// Extract a DocumentFingerprint from raw PDF bytes.
pub fn fingerprint_pdf(bytes: &[u8]) -> Result<DocumentFingerprint, String> {
    let doc = lopdf::Document::load_mem(bytes).map_err(|e| format!("invalid PDF: {e}"))?;

    let content = extract_text(&doc);
    let structure = extract_structure(&doc);
    let metadata = extract_metadata(&doc);

    let alg = HashAlgorithm::Sha256;
    let content_hash = hex::encode(hash_with(alg, content.as_bytes()));
    let structure_hash = hex::encode(hash_with(alg, structure.as_bytes()));
    let metadata_hash = if metadata.is_empty() {
        None
    } else {
        Some(hex::encode(hash_with(alg, metadata.as_bytes())))
    };

    let canonical_hash = DocumentFingerprint::compute_canonical_hash(
        &content_hash,
        &structure_hash,
        None,
        None,
        metadata_hash.as_deref(),
        alg,
    );

    Ok(DocumentFingerprint {
        content_hash,
        structure_hash,
        tables_hash: None,
        images_hash: None,
        metadata_hash,
        canonical_hash,
    })
}

fn extract_text(doc: &lopdf::Document) -> String {
    let mut text = String::new();
    let pages = doc.get_pages();
    let mut page_nums: Vec<u32> = pages.keys().copied().collect();
    page_nums.sort();
    for page_num in page_nums {
        if let Ok(content) = doc.extract_text(&[page_num]) {
            text.push_str(&content);
            text.push('\n');
        }
    }
    normalize_text(&text)
}

fn extract_structure(doc: &lopdf::Document) -> String {
    let pages = doc.get_pages();
    let page_count = pages.len();
    let mut structure = format!("pages:{page_count}");
    let mut page_nums: Vec<u32> = pages.keys().copied().collect();
    page_nums.sort();
    for (i, page_num) in page_nums.iter().enumerate() {
        if let Some(obj_id) = pages.get(page_num) {
            if let Ok(page) = doc.get_object(*obj_id) {
                if let Ok(dict) = page.as_dict() {
                    let has_annots = dict.has(b"Annots");
                    let has_media_box = dict.has(b"MediaBox");
                    structure.push_str(&format!(
                        ";p{i}:annots={has_annots},mediabox={has_media_box}"
                    ));
                }
            }
        }
    }
    structure
}

fn extract_metadata(doc: &lopdf::Document) -> String {
    let mut meta = String::new();
    if let Ok(info_id) = doc.trailer.get(b"Info") {
        if let Ok(info_ref) = info_id.as_reference() {
            if let Ok(info) = doc.get_object(info_ref) {
                if let Ok(dict) = info.as_dict() {
                    let keys: &[&[u8]] =
                        &[b"Title", b"Author", b"Subject", b"Creator", b"Producer"];
                    for key in keys {
                        if let Ok(val) = dict.get(key) {
                            let val_str = object_to_string(val);
                            if !val_str.is_empty() {
                                meta.push_str(&format!(
                                    "{}:{val_str};",
                                    String::from_utf8_lossy(key),
                                ));
                            }
                        }
                    }
                }
            }
        }
    }
    meta
}

fn object_to_string(obj: &Object) -> String {
    match obj {
        Object::String(bytes, _) => String::from_utf8_lossy(bytes).to_string(),
        Object::Name(bytes) => String::from_utf8_lossy(bytes).to_string(),
        _ => String::new(),
    }
}

fn normalize_text(text: &str) -> String {
    text.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_pdf_rejects_invalid() {
        let err = fingerprint_pdf(b"not a pdf").unwrap_err();
        assert!(err.contains("invalid PDF"));
    }

    #[test]
    fn deeply_nested_pdf_does_not_abort_the_process() {
        let depth = 100_000;
        let nested = format!("{}{}", "[".repeat(depth), "]".repeat(depth));
        let header = "%PDF-1.7\n";
        let object = format!("1 0 obj\n<< /Type /Catalog /Nested {nested} >>\nendobj\n");
        let xref_offset = header.len() + object.len();
        let pdf = format!(
            "{header}{object}xref\n0 2\n0000000000 65535 f \n{:010} 00000 n \ntrailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n",
            header.len()
        );
        let _ = fingerprint_pdf(pdf.as_bytes());
    }

    #[test]
    fn normalize_text_collapses_whitespace() {
        assert_eq!(normalize_text("  Hello   World  "), "hello world");
    }

    #[test]
    fn normalize_text_lowercases() {
        assert_eq!(normalize_text("ABC DEF"), "abc def");
    }
}
