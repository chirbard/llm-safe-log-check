use regex::Regex;

pub struct Redaction {
    pub original: String, // exact substring found (may include "EE" prefix)
    pub label: String,    // EE_ID_A, EE_ID_B, ...
}

pub fn find_redactions(text: &str) -> Vec<Redaction> {
    let re = Regex::new(r"(?:EE)?[1-8][0-9]{10}").unwrap();
    let bytes = text.as_bytes();

    // (11-digit code) -> label, for deduplication across EE-prefixed and bare forms
    let mut code_labels: Vec<(String, String)> = Vec::new();
    let mut result: Vec<Redaction> = Vec::new();

    for m in re.find_iter(text) {
        // Reject if embedded in a longer alphanumeric token
        if m.start() > 0 && bytes[m.start() - 1].is_ascii_alphanumeric() {
            continue;
        }
        if m.end() < bytes.len() && bytes[m.end()].is_ascii_alphanumeric() {
            continue;
        }

        let full = m.as_str();
        let code = if full.starts_with("EE") { &full[2..] } else { full };

        let digits: Vec<u8> = code.bytes().map(|b| b - b'0').collect();
        if !valid_checksum(&digits) {
            continue;
        }

        let label = match code_labels.iter().find(|(c, _)| c == code) {
            Some((_, l)) => l.clone(),
            None => {
                let l = label(code_labels.len());
                code_labels.push((code.to_string(), l.clone()));
                l
            }
        };

        if !result.iter().any(|r| r.original == full) {
            result.push(Redaction { original: full.to_string(), label });
        }
    }

    result
}

fn valid_checksum(d: &[u8]) -> bool {
    if d.len() != 11 {
        return false;
    }

    let w1: [u32; 10] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 1];
    let rem1 = d[..10].iter().zip(w1.iter()).map(|(&x, &w)| x as u32 * w).sum::<u32>() % 11;
    if rem1 < 10 {
        return rem1 as u8 == d[10];
    }

    let w2: [u32; 10] = [3, 4, 5, 6, 7, 8, 9, 1, 2, 3];
    let rem2 = d[..10].iter().zip(w2.iter()).map(|(&x, &w)| x as u32 * w).sum::<u32>() % 11;
    if rem2 < 10 {
        return rem2 as u8 == d[10];
    }

    d[10] == 0
}

fn label(i: usize) -> String {
    if i < 26 {
        format!("REDACTED_EE_ID_{}", char::from(b'A' + i as u8))
    } else {
        format!("REDACTED_EE_ID_{}", i + 1)
    }
}
