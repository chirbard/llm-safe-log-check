mod estonian_id;
mod ip;
mod scanner;

use anyhow::{Context, Result};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.is_empty() {
        run_stdin().await
    } else {
        run_file(Path::new(&args[0])).await
    }
}

async fn run_stdin() -> Result<()> {
    eprintln!("Paste your log message, then press Ctrl+D when done:");
    eprintln!();

    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;

    if input.trim().is_empty() {
        eprintln!("No input provided.");
        return Ok(());
    }

    let redacted = scan_and_report(&input).await?;
    println!("{redacted}");
    Ok(())
}

async fn run_file(path: &Path) -> Result<()> {
    let input = std::fs::read_to_string(path)
        .with_context(|| format!("Could not read {}", path.display()))?;

    let out_path = redacted_path(path);

    eprintln!("Scanning {}...", path.display());

    let redacted = scan_and_report(&input).await?;

    std::fs::write(&out_path, &redacted)
        .with_context(|| format!("Could not write {}", out_path.display()))?;

    eprintln!("Written to {}", out_path.display());
    Ok(())
}

async fn scan_and_report(input: &str) -> Result<String> {
    let llm_redactions = scanner::scan(input).await?;
    let ip_redactions = ip::find_redactions(input);
    let id_redactions = estonian_id::find_redactions(input);

    let total = llm_redactions.len() + ip_redactions.len() + id_redactions.len();
    if total == 0 {
        eprintln!("No sensitive content found.");
        return Ok(input.to_string());
    }

    eprintln!("\nFound {} item(s) to redact:", total);
    for r in &llm_redactions {
        eprintln!("  [{}] {}", r.category, r.description);
    }
    for r in &ip_redactions {
        eprintln!("  [ip_address] {} → {}", r.original, r.label);
    }
    for r in &id_redactions {
        eprintln!("  [estonian_id] {} → {}", r.original, r.label);
    }
    eprintln!();

    // Apply LLM redactions first, then deterministic regex passes
    let mut result = apply_llm_redactions(input, &llm_redactions);
    result = apply_labeled_redactions(&result, &ip_redactions, |r| (&r.original, &r.label));
    result = apply_labeled_redactions(&result, &id_redactions, |r| (&r.original, &r.label));
    Ok(result)
}

fn apply_llm_redactions(text: &str, redactions: &[scanner::Redaction]) -> String {
    let mut result = text.to_string();
    for r in redactions {
        let placeholder = format!("REDACTED_{}", r.category.to_uppercase());
        result = result.replace(&r.original, &placeholder);
    }
    result
}

fn apply_labeled_redactions<T, F>(text: &str, redactions: &[T], get: F) -> String
where
    F: Fn(&T) -> (&String, &String),
{
    let mut result = text.to_string();
    for r in redactions {
        let (original, label) = get(r);
        result = result.replace(original.as_str(), label.as_str());
    }
    result
}

fn redacted_path(path: &Path) -> PathBuf {
    let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("output");
    let ext = path.extension().and_then(|s| s.to_str());
    let new_name = match ext {
        Some(e) => format!("{stem}.redacted.{e}"),
        None => format!("{stem}.redacted"),
    };
    path.with_file_name(new_name)
}
