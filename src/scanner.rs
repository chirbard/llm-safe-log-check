use anyhow::Result;
use serde_json::Value;

const DEFAULT_OLLAMA_URL: &str = "http://localhost:11434";
const DEFAULT_MODEL: &str = "qwen3.5:2b";

const SYSTEM_PROMPT: &str = "You are a security scanner. Respond with ONLY valid JSON, no thinking, no explanation, no markdown. Output nothing except the JSON object.";

const USER_PROMPT_TEMPLATE: &str = r#"Analyze the following log text for sensitive content that should be redacted.

Return ONLY this JSON structure, nothing else:
{"redactions":[]}

If sensitive content is found, return the exact substring to redact and its category:
{"redactions":[{"original":"actual-secret-value","category":"api_key","description":"brief description"}]}

Valid categories: api_key, password, pii, estonian_id, private_key, connection_string, other_secret

Rules:
- "original" MUST be the exact verbatim substring from the text — it will be used for string replacement
- Flag real secrets: API keys, passwords, tokens, private keys, SSNs, credit card numbers
- Flag Estonian personal identification codes: 11-digit codes starting with 1-8 (e.g. 38001085718) or prefixed with EE (e.g. EE38001085718) — use category "estonian_id". They may also appear embedded inside longer tokens (e.g. "ref38001085718") — still flag just the 11-digit portion as "original" and describe where it was found
- Flag PII only if clearly identifiable (e.g. name paired with SSN, medical, or financial data)
- Do NOT flag: placeholder values like "your-api-key-here", variable names, generic words
- Do NOT flag file paths or URLs unless they contain embedded credentials
- If the same secret appears multiple times, list it only once

Log text:
"#;

pub struct Redaction {
    pub original: String,
    pub category: String,
    pub description: String,
}

pub async fn scan(text: &str) -> Result<Vec<Redaction>> {
    let ollama_url = std::env::var("OLLAMA_URL").unwrap_or_else(|_| DEFAULT_OLLAMA_URL.to_string());
    let model = std::env::var("OLLAMA_MODEL").unwrap_or_else(|_| DEFAULT_MODEL.to_string());

    let user_content = format!("{USER_PROMPT_TEMPLATE}{text}");

    let body = serde_json::json!({
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_content}
        ],
        "stream": false,
        "format": "json",
        "think": false,
        "options": {
            "temperature": 0,
            "num_predict": 512
        }
    });

    let url = format!("{ollama_url}/api/chat");

    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .json(&body)
        .timeout(std::time::Duration::from_secs(60))
        .send()
        .await?;

    let resp_json: Value = resp.json().await?;

    let response_text = resp_json
        .get("message")
        .and_then(|m| m.get("content"))
        .and_then(|v| v.as_str())
        .unwrap_or("{}");

    parse_response(response_text)
}

fn parse_response(text: &str) -> Result<Vec<Redaction>> {
    let cleaned = text
        .trim()
        .trim_start_matches("```json")
        .trim_start_matches("```")
        .trim_end_matches("```")
        .trim();

    let Ok(parsed) = serde_json::from_str::<Value>(cleaned) else {
        eprintln!("Warning: could not parse Ollama response: {text}");
        return Ok(vec![]);
    };

    let Some(arr) = parsed.get("redactions").and_then(|v| v.as_array()) else {
        return Ok(vec![]);
    };

    let mut redactions = Vec::new();
    for item in arr {
        let original = item.get("original").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let category = item.get("category").and_then(|v| v.as_str()).unwrap_or("other_secret").to_string();
        let description = item.get("description").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if !original.is_empty() {
            redactions.push(Redaction { original, category, description });
        }
    }

    Ok(redactions)
}
