use rust_bc::identity::pairwise::{parse_secret, subject_for, Audience, Disclosure};
use std::io::BufRead;

fn fail(message: String) -> ! {
    eprintln!("{message}");
    std::process::exit(1);
}

fn main() {
    let audience_name = std::env::args().nth(1).unwrap_or_else(|| {
        fail("Usage: PAIRWISE_SECRET=<hex> pairwise-subjects <audience> < dids".into())
    });
    let audience = Audience::parse(&audience_name)
        .filter(|app| app.disclosure() == Disclosure::Subject)
        .unwrap_or_else(|| {
            fail(format!(
                "{audience_name} is not an app that sees pairwise subjects"
            ))
        });
    let secret = std::env::var("PAIRWISE_SECRET")
        .map_err(|e| format!("PAIRWISE_SECRET is not set: {e}"))
        .and_then(|text| parse_secret(&text))
        .unwrap_or_else(|e| fail(e));
    for line in std::io::stdin().lock().lines() {
        let did = line.unwrap_or_else(|e| fail(format!("stdin not readable: {e}")));
        let did = did.trim();
        if did.is_empty() {
            continue;
        }
        let subject = subject_for(&secret, audience, did).unwrap_or_else(|e| fail(e));
        println!("{did} {subject}");
    }
}
