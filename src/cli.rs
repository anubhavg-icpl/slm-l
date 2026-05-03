use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use walkdir::WalkDir;

use crate::{detector::Language, llm::{AuditModel, Confidence, Finding}, report, scanner};

#[derive(Parser)]
#[command(
    name = "slm-audit",
    about = "Local SLM-powered security auditor for C / C++ / C# / Rust",
    long_about = "Combines fast static pattern matching with local Phi-3 SLM inference.\nRuns 100% offline — no API keys, no data leaves your machine.",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a file or directory for security vulnerabilities
    Scan {
        /// File or directory to audit
        path: PathBuf,

        /// Override automatic language detection
        #[arg(long, value_enum)]
        lang: Option<LangArg>,

        /// Output format
        #[arg(long, default_value = "terminal", value_enum)]
        format: OutputFormat,

        /// LLM inference timeout in seconds
        #[arg(long, default_value_t = 60)]
        timeout: u64,

        /// Minimum confidence level to include in output
        #[arg(long, default_value = "low", value_enum)]
        min_confidence: ConfidenceArg,

        /// Run static pattern scan only — skip LLM inference (fast, no model download)
        #[arg(long)]
        static_only: bool,
    },
}

#[derive(Clone, ValueEnum)]
pub enum LangArg {
    C,
    Cpp,
    Cs,
    Rust,
}

#[derive(Clone, ValueEnum)]
enum OutputFormat {
    Terminal,
    Json,
    Sarif,
}

#[derive(Clone, ValueEnum)]
enum ConfidenceArg {
    Low,
    Medium,
    High,
}

impl From<&ConfidenceArg> for Confidence {
    fn from(arg: &ConfidenceArg) -> Self {
        match arg {
            ConfidenceArg::Low => Confidence::Low,
            ConfidenceArg::Medium => Confidence::Medium,
            ConfidenceArg::High => Confidence::High,
        }
    }
}

fn static_hits_to_findings(hits: &[scanner::StaticHit]) -> Vec<Finding> {
    hits.iter()
        .map(|h| Finding {
            line: Some(h.line as u32),
            severity: h.severity.to_string(),
            category: h.pattern_name.to_string(),
            pattern: h.matched_text.clone(),
            explanation: h.description.to_string(),
            suggestion: String::new(),
            confidence: Confidence::Low,
        })
        .collect()
}

fn lang_from_arg(arg: &LangArg) -> Language {
    match arg {
        LangArg::C => Language::C,
        LangArg::Cpp => Language::Cpp,
        LangArg::Cs => Language::DotNet,
        LangArg::Rust => Language::Rust,
    }
}

pub async fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            path,
            lang,
            format,
            timeout,
            min_confidence,
            static_only,
        } => {
            let files: Vec<PathBuf> = if path.is_file() {
                vec![path.clone()]
            } else {
                WalkDir::new(&path)
                    .follow_links(false)
                    .into_iter()
                    .filter_map(|e| e.ok())
                    .filter(|e| e.file_type().is_file())
                    .map(|e| e.path().to_path_buf())
                    .filter(|p| {
                        lang.as_ref()
                            .map(|_| true)
                            .unwrap_or_else(|| Language::from_path(p).is_some())
                    })
                    .collect()
            };

            if files.is_empty() {
                anyhow::bail!("No supported source files found at: {}", path.display());
            }

            let model = if static_only {
                None
            } else {
                Some(AuditModel::load().await?)
            };

            let min_conf = Confidence::from(&min_confidence);
            let mut results = Vec::new();

            for file in &files {
                let language = lang
                    .as_ref()
                    .map(lang_from_arg)
                    .or_else(|| Language::from_path(file));

                let Some(language) = language else {
                    continue;
                };

                let source = match std::fs::read_to_string(file) {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("Skipping {}: {e}", file.display());
                        continue;
                    }
                };

                eprintln!("Auditing {} [{}]...", file.display(), language.name());
                let static_hits = scanner::scan(&source, language);

                let mut findings = if let Some(ref m) = model {
                    m.analyze(&source, language, &static_hits, file, timeout).await?
                } else {
                    static_hits_to_findings(&static_hits)
                };

                findings.retain(|f| f.confidence >= min_conf);
                results.push((file.clone(), language, findings));
            }

            match format {
                OutputFormat::Terminal => report::print_terminal(&results),
                OutputFormat::Json => report::print_json(&results)?,
                OutputFormat::Sarif => report::print_sarif(&results)?,
            }
        }
    }

    Ok(())
}
