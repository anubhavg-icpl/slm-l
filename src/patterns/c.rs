use super::Pattern;

pub static PATTERNS: &[Pattern] = &[
    // ── Memory / buffer safety ──────────────────────────────────────────────
    Pattern {
        name: "gets",
        regex: r"\bgets\s*\(",
        severity: "CRITICAL",
        description: "gets() has no bounds checking — guaranteed buffer overflow. Use fgets() with explicit size.",
    },
    Pattern {
        name: "strcpy",
        regex: r"\bstrcpy\s*\(",
        severity: "HIGH",
        description: "strcpy() copies without length limit. Use strlcpy() or strncpy() with explicit bound.",
    },
    Pattern {
        name: "strcat",
        regex: r"\bstrcat\s*\(",
        severity: "HIGH",
        description: "strcat() appends without length checking. Use strncat() with remaining buffer size.",
    },
    Pattern {
        name: "sprintf",
        regex: r"\bsprintf\s*\(",
        severity: "HIGH",
        description: "sprintf() writes without bounds. Use snprintf() with explicit buffer size.",
    },
    Pattern {
        name: "scanf-no-width",
        regex: r#"\bscanf\s*\(\s*"[^"]*%s[^"]*""#,
        severity: "HIGH",
        description: "scanf %s without width specifier allows unbounded write. Use %Ns where N is buffer size - 1.",
    },
    Pattern {
        name: "memcpy-no-bounds",
        regex: r"\bmemcpy\s*\(",
        severity: "MEDIUM",
        description: "memcpy() with incorrect size argument causes buffer overflow. Verify size is bounded by destination.",
    },
    Pattern {
        name: "malloc-no-null-check",
        regex: r"\bmalloc\s*\(",
        severity: "MEDIUM",
        description: "malloc() return value must be checked for NULL before use.",
    },
    Pattern {
        name: "alloca-stack-overflow",
        regex: r"\balloca\s*\(",
        severity: "HIGH",
        description: "alloca() size is unchecked — stack overflow if size is attacker-controlled. Use malloc() or VLAs with validated sizes.",
    },
    // ── Format-string ───────────────────────────────────────────────────────
    Pattern {
        name: "printf-format-string",
        regex: r"\bprintf\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*[,)]",
        severity: "HIGH",
        description: "printf(user_input) is a format string vulnerability. Always use printf(\"%s\", input).",
    },
    Pattern {
        name: "vprintf-format-string",
        regex: r"\bv(?:printf|fprintf|sprintf|snprintf|dprintf)\s*\(",
        severity: "HIGH",
        description: "vprintf family with untrusted format string enables arbitrary read/write. Always pass a literal format string.",
    },
    // ── Command / code injection ─────────────────────────────────────────────
    Pattern {
        name: "system-call",
        regex: r"\bsystem\s*\(",
        severity: "CRITICAL",
        description: "system() passes input to shell — command injection risk. Use execve() with argv array.",
    },
    Pattern {
        name: "popen",
        regex: r"\bpopen\s*\(",
        severity: "HIGH",
        description: "popen() passes command to shell. Validate and sanitize input, prefer execve() family.",
    },
    Pattern {
        name: "exec-family",
        regex: r"\b(?:execl|execlp|execvp|execle|execve)\s*\(",
        severity: "CRITICAL",
        description: "exec family with user-controlled path/args enables command injection. Validate all inputs; prefer execve with absolute paths and explicit envp.",
    },
    Pattern {
        name: "dlopen-user-path",
        regex: r"\bdlopen\s*\(",
        severity: "HIGH",
        description: "dlopen() with user-controlled path enables DLL/SO hijacking. Hardcode library paths or verify path against an allowlist.",
    },
    // ── TOCTOU / temp-file races ─────────────────────────────────────────────
    Pattern {
        name: "tmpnam-toctou",
        regex: r"\b(?:tmpnam|tempnam)\s*\(",
        severity: "HIGH",
        description: "tmpnam/tempnam have a TOCTOU race between name generation and file creation. Use mkstemp() for atomic temp-file creation.",
    },
    // ── Privilege / filesystem ───────────────────────────────────────────────
    Pattern {
        name: "chroot-no-chdir",
        regex: r"\bchroot\s*\(",
        severity: "HIGH",
        description: "chroot() without chdir(\"/\") leaves cwd accessible outside the jail (CWE-243). Always call chdir(\"/\") immediately after chroot().",
    },
    Pattern {
        name: "getenv-unchecked",
        regex: r"\bgetenv\s*\(",
        severity: "MEDIUM",
        description: "getenv() returns attacker-controlled data. Validate and sanitize before use in paths, commands, or security decisions.",
    },
    // ── Executable memory ────────────────────────────────────────────────────
    Pattern {
        name: "mmap-exec",
        regex: r"\bmmap\s*\([^)]*PROT_EXEC",
        severity: "HIGH",
        description: "mmap with PROT_EXEC creates executable memory. Combined with PROT_WRITE this allows shellcode injection. Avoid RWX mappings.",
    },
    // ── Weak PRNG / crypto ───────────────────────────────────────────────────
    Pattern {
        name: "rand-for-security",
        regex: r"\brand\s*\(\s*\)",
        severity: "MEDIUM",
        description: "rand() is not cryptographically secure. Use /dev/urandom or a CSPRNG for security-sensitive values.",
    },
    // ── Input parsing ─────────────────────────────────────────────────────────
    Pattern {
        name: "atoi-no-validation",
        regex: r"\batoi\s*\(",
        severity: "LOW",
        description: "atoi() has no error detection. Use strtol() to detect invalid input and overflow.",
    },
];
