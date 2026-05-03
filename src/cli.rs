use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use walkdir::WalkDir;

use crate::{detector::Language, llm::AuditModel, report, scanner};

#[derive(Parser)]
#[command(
    name = "slm-audit",
    about = "Local SLM-powered security auditor for C / C++ / C# / Rust",
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
}

fn lang_arg_to_language(arg: &LangArg) -> Language {
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
        Commands::Scan { path, lang, format } => {
            // Collect all target files
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

            let model = AuditModel::load().await?;
            let mut results = Vec::new();

            for file in &files {
                let language = lang
                    .as_ref()
                    .map(lang_arg_to_language)
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
                let findings = model.analyze(&source, language, &static_hits, file).await?;
                results.push((file.clone(), language, findings));
            }

            match format {
                OutputFormat::Terminal => report::print_terminal(&results),
                OutputFormat::Json => report::print_json(&results)?,
            }
        }
    }

    Ok(())
}
