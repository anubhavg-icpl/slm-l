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

#[cfg(test)]
mod tests {
    use super::*;

    fn has(hits: &[StaticHit], name: &str) -> bool {
        hits.iter().any(|h| h.pattern_name == name)
    }

    fn has_sev(hits: &[StaticHit], name: &str, sev: &str) -> bool {
        hits.iter().any(|h| h.pattern_name == name && h.severity == sev)
    }

    // ── C ──────────────────────────────────────────────────────────────────

    #[test]
    fn c_gets_is_critical() {
        let src = r#"void f() { char b[8]; gets(b); }"#;
        let hits = scan(src, Language::C);
        assert!(has_sev(&hits, "gets", "CRITICAL"), "gets must be CRITICAL");
    }

    #[test]
    fn c_strcpy_detected() {
        let src = r#"strcpy(dst, src);"#;
        assert!(has(&scan(src, Language::C), "strcpy"));
    }

    #[test]
    fn c_system_detected() {
        let src = r#"void run(char *c) { system(c); }"#;
        assert!(has_sev(&scan(src, Language::C), "system-call", "CRITICAL"));
    }

    #[test]
    fn c_printf_fmt_string_detected() {
        let src = r#"printf(user_input);"#;
        assert!(has(&scan(src, Language::C), "printf-format-string"));
    }

    #[test]
    fn c_safe_code_no_critical() {
        let src = r#"int main() { printf("%s\n", "hello"); return 0; }"#;
        let hits = scan(src, Language::C);
        assert!(hits.iter().all(|h| h.severity != "CRITICAL"), "safe C code should have no CRITICAL");
    }

    // ── C++ ────────────────────────────────────────────────────────────────

    #[test]
    fn cpp_reinterpret_cast_detected() {
        let src = r#"auto p = reinterpret_cast<char*>(ptr);"#;
        assert!(has(&scan(src, Language::Cpp), "reinterpret-cast"));
    }

    #[test]
    fn cpp_raw_new_array_detected() {
        let src = r#"int* arr = new int[size];"#;
        assert!(has(&scan(src, Language::Cpp), "raw-new-array"));
    }

    // ── C#/.NET ────────────────────────────────────────────────────────────

    #[test]
    fn dotnet_binaryformatter_is_critical() {
        let src = r#"var bf = new BinaryFormatter(); bf.Deserialize(s);"#;
        assert!(has_sev(&scan(src, Language::DotNet), "binary-formatter", "CRITICAL"));
    }

    #[test]
    fn dotnet_hardcoded_password_detected() {
        let src = r#"string password = "SuperSecret123";"#;
        assert!(has(&scan(src, Language::DotNet), "hardcoded-password"));
    }

    #[test]
    fn dotnet_md5_detected() {
        let src = r#"using var md5 = MD5.Create();"#;
        assert!(has(&scan(src, Language::DotNet), "md5-sha1"));
    }

    // ── Rust ───────────────────────────────────────────────────────────────

    #[test]
    fn rust_unsafe_detected() {
        let src = r#"unsafe { *ptr = 42; }"#;
        assert!(has(&scan(src, Language::Rust), "unsafe-block"));
    }

    #[test]
    fn rust_transmute_is_high() {
        let src = r#"let x: u64 = std::mem::transmute(f);"#;
        assert!(has_sev(&scan(src, Language::Rust), "transmute", "HIGH"));
    }

    #[test]
    fn rust_unwrap_detected() {
        let src = r#"let val = some_fn().unwrap();"#;
        assert!(has(&scan(src, Language::Rust), "unwrap-in-code"));
    }

    #[test]
    fn rust_unsafe_send_sync_detected() {
        let src = r#"unsafe impl Send for MyType {}"#;
        assert!(has(&scan(src, Language::Rust), "send-sync-impl"));
    }

    #[test]
    fn rust_safe_code_no_critical() {
        let src = r#"fn main() { println!("hello world"); }"#;
        let hits = scan(src, Language::Rust);
        assert!(hits.iter().all(|h| h.severity != "CRITICAL"), "safe Rust should have no CRITICAL");
    }
}
