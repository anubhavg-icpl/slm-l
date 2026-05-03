use std::path::PathBuf;

use colored::Colorize;
use serde_json;

use crate::{detector::Language, llm::Finding};

pub fn print_terminal(results: &[(PathBuf, Language, Vec<Finding>)]) {
    let total_findings: usize = results.iter().map(|(_, _, f)| f.len()).sum();

    println!("{}", "━".repeat(70).dimmed());
    println!(
        "{} — {} file(s), {} finding(s)",
        "slm-audit".bold().cyan(),
        results.len(),
        if total_findings == 0 {
            total_findings.to_string().green().to_string()
        } else {
            total_findings.to_string().red().to_string()
        }
    );
    println!("{}", "━".repeat(70).dimmed());

    for (path, lang, findings) in results {
        let label = format!("[{}]", lang.name());
        println!(
            "\n{} {}",
            label.bold().blue(),
            path.display().to_string().underline()
        );

        if findings.is_empty() {
            println!("  {}", "✓ No findings".green());
            continue;
        }

        for f in findings {
            let sev_label = severity_colored(&f.severity);
            let line_str = f
                .line
                .map(|l| format!("line {l}"))
                .unwrap_or_else(|| "—".to_string());

            println!(
                "\n  {} {} {}",
                sev_label,
                f.category.bold(),
                line_str.dimmed()
            );
            if !f.pattern.is_empty() {
                println!("  Pattern   : {}", f.pattern.yellow());
            }
            println!("  Risk      : {}", f.explanation);
            println!("  Fix       : {}", f.suggestion.green());
        }
    }

    println!("\n{}", "━".repeat(70).dimmed());

    let crit = count_by_sev(results, "CRITICAL");
    let high = count_by_sev(results, "HIGH");
    let med = count_by_sev(results, "MEDIUM");
    let low = count_by_sev(results, "LOW");

    println!(
        "Summary  {}  {}  {}  {}",
        format!("CRITICAL:{crit}").red().bold(),
        format!("HIGH:{high}").red(),
        format!("MEDIUM:{med}").yellow(),
        format!("LOW:{low}").white().dimmed(),
    );
}

pub fn print_json(results: &[(PathBuf, Language, Vec<Finding>)]) -> anyhow::Result<()> {
    let output: Vec<serde_json::Value> = results
        .iter()
        .map(|(path, lang, findings)| {
            serde_json::json!({
                "file": path.display().to_string(),
                "language": lang.name(),
                "findings": findings,
            })
        })
        .collect();

    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

fn severity_colored(sev: &str) -> colored::ColoredString {
    match sev {
        "CRITICAL" => format!("[{sev}]").red().bold(),
        "HIGH" => format!("[{sev}]   ").red().normal(),
        "MEDIUM" => format!("[{sev}] ").yellow().normal(),
        "LOW" => format!("[{sev}]    ").white().dimmed(),
        _ => format!("[{sev}]   ").white().normal(),
    }
}

fn count_by_sev(results: &[(PathBuf, Language, Vec<Finding>)], sev: &str) -> usize {
    results
        .iter()
        .flat_map(|(_, _, f)| f)
        .filter(|f| f.severity == sev)
        .count()
}
