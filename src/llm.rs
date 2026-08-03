use std::path::Path;

use anyhow::Context;
use futures::StreamExt;
use kalosm::language::*;
use serde::{Deserialize, Serialize};

use crate::{chunker, detector::Language, scanner::StaticHit};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Confidence {
    #[default]
    Low,
    Medium,
    High,
}

impl Confidence {
    pub fn sarif_rank(&self) -> f64 {
        match self {
            Confidence::Low => 25.0,
            Confidence::Medium => 60.0,
            Confidence::High => 90.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub line: Option<u32>,
    pub severity: String,
    pub category: String,
    pub pattern: String,
    pub explanation: String,
    pub suggestion: String,
    #[serde(default)]
    pub confidence: Confidence,
}

// ── Model configuration (models.toml) ──────────────────────────────────────

/// Deserialized representation of `models.toml`.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct ModelConfig {
    #[serde(default)]
    pub model: ModelSection,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ModelSection {
    /// One of: "phi3", "smollm2-135m", "smollm2-360m", "smollm2-1.7b",
    /// "llama3.2-1b", "llama3.2-3b", "qwen2.5-0.5b", "qwen2.5-1.5b",
    /// "qwen2.5-3b", or "custom".
    #[serde(default)]
    pub preset: Option<String>,

    /// Optional custom model definition. Used when `preset = "custom"`.
    #[serde(default)]
    pub custom: Option<CustomModel>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CustomModel {
    pub repo_id: String,
    pub filename: String,
}

impl Default for ModelSection {
    fn default() -> Self {
        Self {
            preset: Some("phi3".to_string()),
            custom: None,
        }
    }
}

/// Load `models.toml` from the project root (or CWD). Falls back to
/// the default preset if the file is missing or unreadable.
fn load_model_config() -> ModelConfig {
    let mut candidates: Vec<std::path::PathBuf> = vec![std::path::PathBuf::from("models.toml")];
    if let Ok(p) = std::env::var("SLM_AUDIT_CONFIG") {
        candidates.push(std::path::PathBuf::from(p));
    }
    for path in &candidates {
        if let Ok(text) = std::fs::read_to_string(path)
            && let Ok(cfg) = toml::from_str::<ModelConfig>(&text)
        {
            return cfg;
        }
    }
    ModelConfig::default()
}

/// Resolve the `LlamaSource` for the configured preset.
fn source_for_preset(preset: &str, custom: Option<&CustomModel>) -> anyhow::Result<LlamaSource> {
    match preset {
        "phi3" => Ok(LlamaSource::phi_3_mini_4k_instruct()),
        "smollm2-135m" => Ok(LlamaSource::new(FileSource::huggingface(
            "HuggingFaceTB/SmolLM2-135M-Instruct-GGUF",
            "main",
            "smollm2-135m-instruct-q4_k_m.gguf",
        ))),
        "smollm2-360m" => Ok(LlamaSource::new(FileSource::huggingface(
            "HuggingFaceTB/SmolLM2-360M-Instruct-GGUF",
            "main",
            "smollm2-360m-instruct-q4_k_m.gguf",
        ))),
        "smollm2-1.7b" => Ok(LlamaSource::new(FileSource::huggingface(
            "HuggingFaceTB/SmolLM2-1.7B-Instruct-GGUF",
            "main",
            "smollm2-1.7b-instruct-q4_k_m.gguf",
        ))),
        "llama3.2-1b" => Ok(LlamaSource::llama_3_2_1b_chat()),
        "llama3.2-3b" => Ok(LlamaSource::llama_3_2_3b_chat()),
        "qwen2.5-0.5b" => Ok(LlamaSource::qwen_2_5_0_5b_instruct()),
        "qwen2.5-1.5b" => Ok(LlamaSource::qwen_2_5_1_5b_instruct()),
        "qwen2.5-3b" => Ok(LlamaSource::qwen_2_5_3b_instruct()),
        "custom" => {
            let c = custom.ok_or_else(|| {
                anyhow::anyhow!(
                    "preset = \"custom\" requires a [model.custom] section \
                     with repo_id and filename in models.toml"
                )
            })?;
            Ok(LlamaSource::new(FileSource::huggingface(
                &c.repo_id,
                "main",
                &c.filename,
            )))
        }
        other => Err(anyhow::anyhow!(
            "Unknown model preset '{other}'. \
             Valid presets: phi3, smollm2-135m, smollm2-360m, smollm2-1.7b, \
             llama3.2-1b, llama3.2-3b, qwen2.5-0.5b, qwen2.5-1.5b, qwen2.5-3b, custom"
        )),
    }
}

pub struct AuditModel {
    llm: Llama,
}

impl AuditModel {
    pub async fn load() -> anyhow::Result<Self> {
        let cfg = load_model_config();
        let preset = cfg.model.preset.as_deref().unwrap_or("phi3");
        let source = source_for_preset(preset, cfg.model.custom.as_ref())?;

        let size_hint = match preset {
            "phi3" => "~2.2 GB",
            "smollm2-135m" => "~100 MB",
            "smollm2-360m" => "~250 MB",
            "smollm2-1.7b" => "~1.1 GB",
            "llama3.2-1b" => "~0.8 GB",
            "llama3.2-3b" => "~2.0 GB",
            "qwen2.5-0.5b" => "~0.5 GB",
            "qwen2.5-1.5b" => "~1.0 GB",
            "qwen2.5-3b" => "~1.8 GB",
            _ => "(size unknown)",
        };

        eprintln!("Loading model '{preset}' ({size_hint}, cached after first download)...");
        let llm = Llama::builder()
            .with_source(source)
            .build()
            .await
            .with_context(|| {
                format!("Failed to load model '{preset}' — check network or disk space")
            })?;
        Ok(Self { llm })
    }

    pub async fn analyze(
        &self,
        source: &str,
        language: Language,
        static_hits: &[StaticHit],
        file: &Path,
        timeout_secs: u64,
    ) -> anyhow::Result<Vec<Finding>> {
        let chunks = chunker::chunk_source(source, language);
        let mut all_findings: Vec<Finding> = Vec::new();

        for chunk in &chunks {
            let chunk_line_count = chunk.content.lines().count();
            let chunk_hits: Vec<&StaticHit> = static_hits
                .iter()
                .filter(|h| {
                    h.line >= chunk.start_line && h.line < chunk.start_line + chunk_line_count
                })
                .collect();

            let mut findings = self
                .analyze_chunk(&chunk.content, language, &chunk_hits, file, timeout_secs)
                .await?;

            // Adjust line numbers from chunk-relative to file-absolute
            let offset = (chunk.start_line as u32).saturating_sub(1);
            for f in findings.iter_mut() {
                if let Some(ln) = f.line {
                    f.line = Some(ln + offset);
                }
            }

            // Correlate confidence against static hits (file-absolute lines now)
            correlate_confidence(&mut findings, static_hits);
            all_findings.extend(findings);
        }

        Ok(all_findings)
    }

    async fn analyze_chunk(
        &self,
        code: &str,
        language: Language,
        static_hits: &[&StaticHit],
        file: &Path,
        timeout_secs: u64,
    ) -> anyhow::Result<Vec<Finding>> {
        let prompt = build_prompt(code, language, static_hits, file);
        let params = GenerationParameters::default().with_max_length(2048);

        let response =
            tokio::time::timeout(std::time::Duration::from_secs(timeout_secs), async move {
                let mut stream = self.llm.complete(&prompt).with_sampler(params);
                let mut buf = String::new();
                while let Some(token) = stream.next().await {
                    buf.push_str(&token);
                    // Early-stop once the top-level JSON array is balanced.
                    if is_complete_json_array(&buf) {
                        break;
                    }
                }
                buf
            })
            .await
            .context("LLM inference timed out — increase --timeout")?;

        parse_findings(&response)
    }
}

fn correlate_confidence(findings: &mut [Finding], static_hits: &[StaticHit]) {
    for f in findings.iter_mut() {
        if f.confidence == Confidence::High {
            continue;
        }
        let corroborated = f
            .line
            .map(|fl| {
                static_hits
                    .iter()
                    .any(|sh| (sh.line as u32).abs_diff(fl) <= 2)
            })
            .unwrap_or(false);
        f.confidence = if corroborated {
            Confidence::High
        } else {
            Confidence::Medium
        };
    }
}

fn build_prompt(
    code: &str,
    language: Language,
    static_hits: &[&StaticHit],
    _file: &Path,
) -> String {
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
        r#"<|im_start|>system
You are a security code analyzer. Output ONLY a JSON array of vulnerabilities. No explanation.<|im_end|>
<|im_start|>user
Find security vulnerabilities in this {lang} code.

Static scan found:
{static_section}

Code:
{code}

Rules:
- Output a JSON array, nothing else
- Each element: {{"line": <int>, "severity": "CRITICAL"|"HIGH"|"MEDIUM"|"LOW", "category": "<vuln-name>", "pattern": "<dangerous-code>", "explanation": "<why-dangerous>", "suggestion": "<how-to-fix>"}}
- If clean, output []

Example output:
[{{"line":1,"severity":"CRITICAL","category":"buffer-overflow","pattern":"gets(buf)","explanation":"gets() has no bounds checking","suggestion":"Use fgets() with size limit"}}]<|im_end|>
<|im_start|>assistant
"#,
        lang = language.name(),
        static_section = static_section,
        code = code,
    )
}

fn parse_findings(response: &str) -> anyhow::Result<Vec<Finding>> {
    let json_str = extract_json_array(response).unwrap_or(response);

    // First attempt: strict JSON parse (works when model output is clean)
    if let Ok(findings) = serde_json::from_str::<Vec<Finding>>(json_str) {
        return Ok(findings);
    }

    // Second attempt: regex-based field extraction.
    // SmolLM2-1.7B on CPU frequently produces near-valid JSON with
    // formatting errors (unquoted keys, unescaped inner quotes, missing
    // commas). Regex extraction is resilient to these variations.
    let findings = extract_findings_regex(json_str);
    if !findings.is_empty() {
        return Ok(findings);
    }

    // All attempts failed
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
        confidence: Confidence::Low,
    }])
}

/// Regex-based extraction of finding fields from raw model output.
/// Extracts each `{...}` block, then pulls fields by pattern-matching.
/// Tolerant of unquoted keys, missing commas, and formatting errors.
fn extract_findings_regex(s: &str) -> Vec<Finding> {
    let re_line = regex::Regex::new(r#"(?:line|Line)\s*[:=]?\s*(\d+)"#).unwrap();
    let mut findings = Vec::new();

    let objects = split_json_objects(s);
    for obj in &objects {
        let line = extract_json_field(obj, "line")
            .and_then(|v| v.trim().parse::<u32>().ok())
            .or_else(|| re_line.captures(obj).and_then(|c| c[1].parse::<u32>().ok()));

        let severity = extract_json_field(obj, "severity").unwrap_or_else(|| "MEDIUM".to_string());

        let category = extract_json_field(obj, "category")
            .or_else(|| extract_json_field(obj, "type"))
            .unwrap_or_else(|| "unknown".to_string());

        let pattern = extract_json_field(obj, "pattern").unwrap_or_default();

        let explanation = extract_json_field(obj, "explanation")
            .or_else(|| extract_json_field(obj, "risk"))
            .or_else(|| extract_json_field(obj, "description"))
            .unwrap_or_default();

        let suggestion = extract_json_field(obj, "suggestion")
            .or_else(|| extract_json_field(obj, "fix"))
            .unwrap_or_default();

        if category == "unknown" && pattern.is_empty() && explanation.is_empty() {
            continue;
        }

        findings.push(Finding {
            line,
            severity,
            category,
            pattern,
            explanation,
            suggestion,
            confidence: Confidence::Medium,
        });
    }

    findings
}

/// Split a JSON array string into individual object substrings.
/// Tolerant of braces inside string literals.
fn split_json_objects(s: &str) -> Vec<String> {
    let mut objects = Vec::new();
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        if chars[i] != '{' {
            i += 1;
            continue;
        }
        let start = i;
        let mut depth = 0i32;
        let mut in_string = false;
        let mut escape = false;

        while i < chars.len() {
            let c = chars[i];
            if escape {
                escape = false;
                i += 1;
                continue;
            }
            if c == '\\' {
                escape = true;
                i += 1;
                continue;
            }
            if c == '"' {
                in_string = !in_string;
                i += 1;
                continue;
            }
            if !in_string {
                if c == '{' {
                    depth += 1;
                } else if c == '}' {
                    depth -= 1;
                    if depth == 0 {
                        objects.push(chars[start..=i].iter().collect());
                        break;
                    }
                }
            }
            i += 1;
        }
        if depth != 0 {
            objects.push(chars[start..].iter().collect());
        }
        i += 1;
    }

    objects
}

/// Extract a quoted string value for a given field name from a JSON-like
/// object string. Handles: "key":"val", key:"val", key:"val", "key": "val"
fn extract_json_field(obj: &str, field: &str) -> Option<String> {
    let pattern = format!(r#""?{}"?\s*[:=]\s*"(?:\\"|[^"])*""#, regex::escape(field));
    let re = regex::Regex::new(&pattern).ok()?;
    let m = re.find(obj)?;
    let val = m.as_str();
    let start = val.find('"')? + 1;
    let end = val.rfind('"')?;
    if start >= end {
        return None;
    }
    Some(val[start..end].replace("\\\"", "\"").replace("\\\\", "\\"))
}

/// Check whether the buffer contains a complete top-level JSON array.
fn is_complete_json_array(buf: &str) -> bool {
    let mut depth: i32 = 0;
    let mut in_string = false;
    let mut escape = false;
    let mut found_open = false;

    for ch in buf.chars() {
        if escape {
            escape = false;
            continue;
        }
        if ch == '\\' {
            escape = true;
            continue;
        }
        if ch == '"' {
            in_string = !in_string;
            continue;
        }
        if in_string {
            continue;
        }
        if ch == '[' {
            depth += 1;
            found_open = true;
        } else if ch == ']' {
            depth -= 1;
            if found_open && depth == 0 {
                return true;
            }
        }
    }
    false
}

/// Extract the first JSON array span from the response string.
fn extract_json_array(s: &str) -> Option<&str> {
    let start = s.find('[')?;
    let mut depth: i32 = 0;
    let mut in_string = false;
    let mut escape = false;

    for (i, ch) in s.chars().enumerate().skip(start) {
        if escape {
            escape = false;
            continue;
        }
        if ch == '\\' {
            escape = true;
            continue;
        }
        if ch == '"' {
            in_string = !in_string;
            continue;
        }
        if in_string {
            continue;
        }
        if ch == '[' {
            depth += 1;
        } else if ch == ']' {
            depth -= 1;
            if depth == 0 {
                return Some(&s[start..=i]);
            }
        }
    }
    // Fallback: return everything from first [ to end
    Some(&s[start..])
}
