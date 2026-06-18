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
    let redactions = scanner::scan(input).await?;

    if redactions.is_empty() {
        eprintln!("No sensitive content found.");
        return Ok(input.to_string());
    }

    eprintln!("\nFound {} item(s) to redact:", redactions.len());
    for r in &redactions {
        eprintln!("  [{}] {}", r.category, r.description);
    }
    eprintln!();

    Ok(apply_redactions(input, &redactions))
}

fn apply_redactions(text: &str, redactions: &[scanner::Redaction]) -> String {
    let mut result = text.to_string();
    for r in redactions {
        let placeholder = format!("[REDACTED:{}]", r.category);
        result = result.replace(&r.original, &placeholder);
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
