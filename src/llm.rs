use std::path::Path;

use anyhow::Context;
use futures::StreamExt;
use kalosm::language::*;
use serde::{Deserialize, Serialize};

use crate::{detector::Language, scanner::StaticHit};

const MAX_SOURCE_CHARS: usize = 8_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub line: Option<u32>,
    pub severity: String,
    pub category: String,
    pub pattern: String,
    pub explanation: String,
    pub suggestion: String,
}

pub struct AuditModel {
    llm: Llama,
}

impl AuditModel {
    pub async fn load() -> anyhow::Result<Self> {
        eprintln!("Loading model (first run downloads ~2.2 GB, cached afterward)...");
        let llm = Llama::phi_3()
            .await
            .context("Failed to load Phi-3 model — check network or disk space")?;
        Ok(Self { llm })
    }

    pub async fn analyze(
        &self,
        source: &str,
        language: Language,
        static_hits: &[StaticHit],
        file: &Path,
    ) -> anyhow::Result<Vec<Finding>> {
        let prompt = build_prompt(source, language, static_hits, file);

        let params = GenerationParameters::default().with_max_length(3000);
        let mut stream = self.llm.complete(&prompt).with_sampler(params);

        // Collect all tokens into a single string
        let mut response = String::new();
        while let Some(chunk) = stream.next().await {
            response.push_str(&chunk);
        }

        parse_findings(&response)
    }
}

fn build_prompt(
    source: &str,
    language: Language,
    static_hits: &[StaticHit],
    file: &Path,
) -> String {
    let filename = file
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown");

    let code_excerpt = if source.len() > MAX_SOURCE_CHARS {
        format!(
            "{}\n... [truncated at {} chars]",
            &source[..MAX_SOURCE_CHARS],
            MAX_SOURCE_CHARS
        )
    } else {
        source.to_string()
    };

    let static_section = if static_hits.is_empty() {
        "None detected.".to_string()
    } else {
        static_hits
            .iter()
            .map(|h| {
                format!(
                    "  - Line {}: [{}] `{}` matched `{}` — {}",
                    h.line, h.severity, h.pattern_name, h.matched_text, h.description
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };

    format!(
        r#"You are an expert security code auditor. Analyze the following {lang} source file for security vulnerabilities.
Return ONLY a valid JSON array of findings. No markdown. No prose. No code fences.

Static pre-scan results for {filename}:
{static_section}

File: {filename}
Language: {lang}

```
{code}
```

Each finding in the JSON array must have exactly these fields:
  "line"        : integer line number, or null if not applicable
  "severity"    : one of "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
  "category"    : short vulnerability category (e.g. "buffer-overflow", "sql-injection")
  "pattern"     : the specific code construct or API that is dangerous
  "explanation" : concise explanation of why this is a security risk
  "suggestion"  : concrete safe alternative or fix

If no vulnerabilities exist, return: []

JSON:"#,
        lang = language.name(),
        filename = filename,
        static_section = static_section,
        code = code_excerpt,
    )
}

fn parse_findings(response: &str) -> anyhow::Result<Vec<Finding>> {
    let json_str = extract_json_array(response).unwrap_or(response);

    match serde_json::from_str::<Vec<Finding>>(json_str) {
        Ok(findings) => Ok(findings),
        Err(_) => {
            // SLM produced non-parseable output — return it as a single INFO finding
            Ok(vec![Finding {
                line: None,
                severity: "INFO".to_string(),
                category: "parse-error".to_string(),
                pattern: String::new(),
                explanation: format!(
                    "Model response could not be parsed as JSON. Raw output: {}",
                    &response[..response.len().min(400)]
                ),
                suggestion: "Re-run or inspect the file manually.".to_string(),
            }])
        }
    }
}

fn extract_json_array(s: &str) -> Option<&str> {
    let start = s.find('[')?;
    let end = s.rfind(']')? + 1;
    if start < end {
        Some(&s[start..end])
    } else {
        None
    }
}
