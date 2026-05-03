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

    // ── C new patterns ─────────────────────────────────────────────────────

    #[test]
    fn c_exec_family_is_critical() {
        let src = r#"execvp(cmd, args);"#;
        assert!(has_sev(&scan(src, Language::C), "exec-family", "CRITICAL"));
    }

    #[test]
    fn c_tmpnam_detected() {
        let src = r#"char *name = tmpnam(NULL);"#;
        assert!(has(&scan(src, Language::C), "tmpnam-toctou"));
    }

    #[test]
    fn c_alloca_detected() {
        let src = r#"char *buf = alloca(n);"#;
        assert!(has(&scan(src, Language::C), "alloca-stack-overflow"));
    }

    #[test]
    fn c_vprintf_format_detected() {
        let src = r#"vprintf(fmt, args);"#;
        assert!(has(&scan(src, Language::C), "vprintf-format-string"));
    }

    #[test]
    fn c_dlopen_detected() {
        let src = r#"void *h = dlopen(user_path, RTLD_LAZY);"#;
        assert!(has(&scan(src, Language::C), "dlopen-user-path"));
    }

    #[test]
    fn c_mmap_exec_detected() {
        let src = r#"mmap(0, len, PROT_READ|PROT_EXEC, MAP_ANON, -1, 0);"#;
        assert!(has(&scan(src, Language::C), "mmap-exec"));
    }

    #[test]
    fn c_chroot_detected() {
        let src = r#"chroot("/sandbox");"#;
        assert!(has(&scan(src, Language::C), "chroot-no-chdir"));
    }

    #[test]
    fn c_getenv_detected() {
        let src = r#"char *p = getenv("PATH");"#;
        assert!(has(&scan(src, Language::C), "getenv-unchecked"));
    }

    // ── C++ new patterns ───────────────────────────────────────────────────

    #[test]
    fn cpp_dynamic_cast_unchecked_detected() {
        let src = r#"Derived* d = dynamic_cast<Derived*>(base);"#;
        assert!(has(&scan(src, Language::Cpp), "dynamic-cast-unchecked"));
    }

    #[test]
    fn cpp_catch_all_swallow_detected() {
        let src = r#"try { risky(); } catch (...) {}"#;
        assert!(has(&scan(src, Language::Cpp), "catch-all-swallow"));
    }

    #[test]
    fn cpp_integer_overflow_alloc_detected() {
        let src = r#"int* buf = new int[n * sizeof(int)];"#;
        assert!(has(&scan(src, Language::Cpp), "integer-overflow-alloc"));
    }

    // ── C# new patterns ────────────────────────────────────────────────────

    #[test]
    fn dotnet_ldap_injection_is_critical() {
        let src = r#"var ds = new DirectorySearcher("(uid=" + userInput + ")");"#;
        assert!(has_sev(&scan(src, Language::DotNet), "ldap-injection", "CRITICAL"));
    }

    #[test]
    fn dotnet_xpath_injection_is_critical() {
        let src = r#"var nodes = doc.SelectNodes("/users[@id='" + id + "']");"#;
        assert!(has_sev(&scan(src, Language::DotNet), "xpath-injection", "CRITICAL"));
    }

    #[test]
    fn dotnet_type_name_handling_is_critical() {
        let src = r#"var settings = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All };"#;
        assert!(has_sev(&scan(src, Language::DotNet), "type-name-handling", "CRITICAL"));
    }

    #[test]
    fn dotnet_soap_formatter_is_critical() {
        let src = r#"var sf = new SoapFormatter(); sf.Deserialize(stream);"#;
        assert!(has_sev(&scan(src, Language::DotNet), "soap-formatter", "CRITICAL"));
    }

    #[test]
    fn dotnet_weak_cipher_detected() {
        let src = r#"using var des = new DESCryptoServiceProvider();"#;
        assert!(has(&scan(src, Language::DotNet), "weak-cipher"));
    }

    #[test]
    fn dotnet_ecb_mode_detected() {
        let src = r#"aes.Mode = CipherMode.ECB;"#;
        assert!(has(&scan(src, Language::DotNet), "ecb-mode"));
    }

    #[test]
    fn dotnet_cert_bypass_detected() {
        let src = r#"ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };"#;
        assert!(has(&scan(src, Language::DotNet), "cert-validation-bypass"));
    }

    #[test]
    fn dotnet_hardcoded_connstring_detected() {
        let src = r#"string connectionString = "Server=prod;Password=S3cr3t!;";"#;
        assert!(has(&scan(src, Language::DotNet), "hardcoded-connstring"));
    }

    // ── Rust new patterns ──────────────────────────────────────────────────

    #[test]
    fn rust_box_from_raw_detected() {
        let src = r#"let b = Box::from_raw(raw_ptr);"#;
        assert!(has(&scan(src, Language::Rust), "box-from-raw"));
    }

    #[test]
    fn rust_maybe_uninit_assume_init_detected() {
        let src = r#"let val = MaybeUninit::<u64>::uninit().assume_init();"#;
        assert!(has(&scan(src, Language::Rust), "maybe-uninit-assume-init"));
    }

    #[test]
    fn rust_from_utf8_unchecked_detected() {
        let src = r#"let s = String::from_utf8_unchecked(bytes);"#;
        assert!(has(&scan(src, Language::Rust), "from-utf8-unchecked"));
    }

    #[test]
    fn rust_cstr_from_ptr_detected() {
        let src = r#"let s = CStr::from_ptr(ptr);"#;
        assert!(has(&scan(src, Language::Rust), "cstr-from-ptr"));
    }

    #[test]
    fn rust_ptr_read_write_detected() {
        let src = r#"ptr::write(dest, value);"#;
        assert!(has(&scan(src, Language::Rust), "ptr-read-write"));
    }

    #[test]
    fn rust_vec_set_len_detected() {
        let src = r#"v.set_len(new_len);"#;
        assert!(has(&scan(src, Language::Rust), "vec-set-len"));
    }

    #[test]
    fn rust_nonnull_unchecked_detected() {
        let src = r#"let nn = NonNull::new_unchecked(ptr);"#;
        assert!(has(&scan(src, Language::Rust), "nonnull-new-unchecked"));
    }

    #[test]
    fn rust_from_raw_parts_mut_detected() {
        let src = r#"let s = slice::from_raw_parts_mut(ptr, len);"#;
        assert!(has(&scan(src, Language::Rust), "from-raw-parts-mut"));
    }

    #[test]
    fn rust_hardcoded_secret_detected() {
        let src = r#"const API_KEY: &str = "sk-prod-abcdef1234567890";"#;
        assert!(has(&scan(src, Language::Rust), "hardcoded-secret"));
    }
}
