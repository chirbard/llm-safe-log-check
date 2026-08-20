use regex::Regex;

// Not sensitive — skip these
const SKIP: &[&str] = &["127.0.0.1", "0.0.0.0", "255.255.255.255"];

pub struct IpRedaction {
    pub original: String,
    pub label: String,
}

pub fn find_redactions(text: &str) -> Vec<IpRedaction> {
    let re = Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap();

    let mut seen: Vec<String> = Vec::new();

    for m in re.find_iter(text) {
        let ip = m.as_str();
        if SKIP.contains(&ip) {
            continue;
        }
        if !is_valid_ipv4(ip) {
            continue;
        }
        if seen.iter().any(|s| s == ip) {
            continue;
        }
        seen.push(ip.to_string());
    }

    seen.into_iter()
        .enumerate()
        .map(|(i, original)| IpRedaction {
            label: label(i),
            original,
        })
        .collect()
}

fn is_valid_ipv4(s: &str) -> bool {
    s.split('.').count() == 4 && s.split('.').all(|p| p.parse::<u8>().is_ok())
}

fn label(i: usize) -> String {
    if i < 26 {
        format!("REDACTED_IP_{}", char::from(b'A' + i as u8))
    } else {
        format!("REDACTED_IP_{}", i + 1)
    }
}
