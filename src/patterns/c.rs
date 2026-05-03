use super::Pattern;

pub static PATTERNS: &[Pattern] = &[
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
        name: "printf-format-string",
        regex: r"\bprintf\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*[,)]",
        severity: "HIGH",
        description: "printf(user_input) is a format string vulnerability. Always use printf(\"%s\", input).",
    },
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
        name: "malloc-no-null-check",
        regex: r"\bmalloc\s*\(",
        severity: "MEDIUM",
        description: "malloc() return value must be checked for NULL before use.",
    },
    Pattern {
        name: "rand-for-security",
        regex: r"\brand\s*\(\s*\)",
        severity: "MEDIUM",
        description: "rand() is not cryptographically secure. Use /dev/urandom or a CSPRNG for security-sensitive values.",
    },
    Pattern {
        name: "memcpy-no-bounds",
        regex: r"\bmemcpy\s*\(",
        severity: "MEDIUM",
        description: "memcpy() with incorrect size argument causes buffer overflow. Verify size is bounded by destination.",
    },
    Pattern {
        name: "atoi-no-validation",
        regex: r"\batoi\s*\(",
        severity: "LOW",
        description: "atoi() has no error detection. Use strtol() to detect invalid input and overflow.",
    },
];
