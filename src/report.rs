use std::path::PathBuf;

use colored::Colorize;
use crate::{detector::Language, llm::Finding};

pub fn print_terminal(results: &[(PathBuf, Language, Vec<Finding>)]) {
    let total: usize = results.iter().map(|(_, _, f)| f.len()).sum();

    println!("{}", "━".repeat(70).dimmed());
    println!(
        "{} — {} file(s), {} finding(s)",
        "slm-audit".bold().cyan(),
        results.len(),
        if total == 0 {
            total.to_string().green().to_string()
        } else {
            total.to_string().red().to_string()
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
            let conf = format!("[{:?}]", f.confidence).to_lowercase();

            println!(
                "\n  {} {} {} {}",
                sev_label,
                f.category.bold(),
                line_str.dimmed(),
                conf.dimmed()
            );
            if !f.pattern.is_empty() {
                println!("  Pattern   : {}", f.pattern.yellow());
            }
            println!("  Risk      : {}", f.explanation);
            println!("  Fix       : {}", f.suggestion.green());
        }
    }

    println!("\n{}", "━".repeat(70).dimmed());
    let crit = count_sev(results, "CRITICAL");
    let high = count_sev(results, "HIGH");
    let med = count_sev(results, "MEDIUM");
    let low = count_sev(results, "LOW");
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

pub fn print_sarif(results: &[(PathBuf, Language, Vec<Finding>)]) -> anyhow::Result<()> {
    // Collect unique rule IDs from all findings
    let mut rule_ids: Vec<String> = results
        .iter()
        .flat_map(|(_, _, findings)| findings.iter().map(|f| f.category.clone()))
        .collect();
    rule_ids.sort();
    rule_ids.dedup();

    let rules: Vec<serde_json::Value> = rule_ids
        .iter()
        .map(|id| {
            serde_json::json!({
                "id": id,
                "name": to_pascal_case(id),
                "shortDescription": {
                    "text": format!("Security vulnerability: {}", id.replace('-', " "))
                },
                "properties": {
                    "tags": ["security"],
                    "precision": "medium"
                }
            })
        })
        .collect();

    let sarif_results: Vec<serde_json::Value> = results
        .iter()
        .flat_map(|(path, _, findings)| {
            let uri = path.display().to_string();
            findings.iter().map(move |f| {
                let level = severity_to_sarif_level(&f.severity);
                let rank = f.confidence.sarif_rank();
                let mut result = serde_json::json!({
                    "ruleId": f.category,
                    "level": level,
                    "rank": rank,
                    "message": {
                        "text": format!("{} — {}", f.explanation, f.suggestion)
                    },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": uri,
                                "uriBaseId": "%SRCROOT%"
                            },
                            "region": {
                                "startLine": f.line.unwrap_or(1)
                            }
                        }
                    }]
                });

                if !f.suggestion.is_empty() {
                    result["fixes"] = serde_json::json!([{
                        "description": { "text": f.suggestion }
                    }]);
                }

                result
            })
        })
        .collect();

    let sarif = serde_json::json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "slm-audit",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/anubhavg-icpl/slm-l",
                    "rules": rules
                }
            },
            "results": sarif_results
        }]
    });

    println!("{}", serde_json::to_string_pretty(&sarif)?);
    Ok(())
}

fn severity_to_sarif_level(sev: &str) -> &'static str {
    match sev {
        "CRITICAL" | "HIGH" => "error",
        "MEDIUM" => "warning",
        _ => "note",
    }
}

fn to_pascal_case(s: &str) -> String {
    s.split('-')
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                None => String::new(),
                Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
            }
        })
        .collect()
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

fn count_sev(results: &[(PathBuf, Language, Vec<Finding>)], sev: &str) -> usize {
    results
        .iter()
        .flat_map(|(_, _, f)| f)
        .filter(|f| f.severity == sev)
        .count()
}
