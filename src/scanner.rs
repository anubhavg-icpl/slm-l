use regex::Regex;

use crate::{detector::Language, patterns};

#[derive(Debug, Clone)]
pub struct StaticHit {
    pub line: usize,
    pub pattern_name: &'static str,
    pub severity: &'static str,
    pub description: &'static str,
    pub matched_text: String,
}

pub fn scan(source: &str, lang: Language) -> Vec<StaticHit> {
    let patterns = patterns::for_language(lang);
    let mut hits: Vec<StaticHit> = Vec::new();

    for pattern in patterns {
        let Ok(re) = Regex::new(pattern.regex) else {
            continue;
        };

        for (line_idx, line) in source.lines().enumerate() {
            if let Some(m) = re.find(line) {
                hits.push(StaticHit {
                    line: line_idx + 1,
                    pattern_name: pattern.name,
                    severity: pattern.severity,
                    description: pattern.description,
                    matched_text: m.as_str().trim().to_string(),
                });
            }
        }
    }

    hits.sort_by_key(|h| h.line);
    hits
}
