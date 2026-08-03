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
        let params = GenerationParameters::default().with_max_length(3000);

        let response =
            tokio::time::timeout(std::time::Duration::from_secs(timeout_secs), async move {
                let mut stream = self.llm.complete(&prompt).with_sampler(params);
                let mut buf = String::new();
                while let Some(token) = stream.next().await {
                    buf.push_str(&token);
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

fn build_prompt(code: &str, language: Language, static_hits: &[&StaticHit], file: &Path) -> String {
    let filename = file
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown");

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
        code = code,
    )
}

fn parse_findings(response: &str) -> anyhow::Result<Vec<Finding>> {
    let json_str = extract_json_array(response).unwrap_or(response);

    match serde_json::from_str::<Vec<Finding>>(json_str) {
        Ok(findings) => Ok(findings),
        Err(_) => Ok(vec![Finding {
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
        }]),
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
