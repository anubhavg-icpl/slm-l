use super::Pattern;

pub static PATTERNS: &[Pattern] = &[
    Pattern {
        name: "sql-injection-concat",
        regex: r#"(?i)(SqlCommand|ExecuteQuery|ExecuteReader|ExecuteNonQuery|ExecuteScalar)\s*\([^)]*\+"#,
        severity: "CRITICAL",
        description: "SQL query built with string concatenation — SQL injection. Use parameterized queries (SqlParameter).",
    },
    Pattern {
        name: "sql-string-format",
        regex: r#"(?i)string\.Format\s*\(\s*"[^"]*SELECT|string\.Format\s*\(\s*"[^"]*INSERT|string\.Format\s*\(\s*"[^"]*UPDATE|string\.Format\s*\(\s*"[^"]*DELETE"#,
        severity: "CRITICAL",
        description: "SQL built with string.Format is SQL injection. Use parameterized queries or an ORM.",
    },
    Pattern {
        name: "process-start-input",
        regex: r"(?i)Process\.Start\s*\([^)]*\+",
        severity: "CRITICAL",
        description: "Process.Start with concatenated input enables command injection. Validate/allowlist input strictly.",
    },
    Pattern {
        name: "binary-formatter",
        regex: r"(?i)\bBinaryFormatter\b",
        severity: "CRITICAL",
        description: "BinaryFormatter is insecure and deprecated. Deserializing untrusted data leads to RCE. Use System.Text.Json or Protobuf.",
    },
    Pattern {
        name: "losformatter",
        regex: r"(?i)\bLosFormatter\b|\bObjectStateFormatter\b",
        severity: "CRITICAL",
        description: "LosFormatter / ObjectStateFormatter are vulnerable to deserialization attacks. Replace with safe alternatives.",
    },
    Pattern {
        name: "path-traversal",
        regex: r"(?i)File\.(Open|ReadAll|WriteAll|ReadText|WriteText|Create|Delete)\s*\([^)]*Request\.",
        severity: "HIGH",
        description: "File path derived from request input enables path traversal. Use Path.GetFullPath and validate it stays under allowed root.",
    },
    Pattern {
        name: "hardcoded-password",
        regex: r#"(?i)(password|passwd|pwd|secret|apikey|api_key)\s*=\s*"[^"]{4,}""#,
        severity: "HIGH",
        description: "Hardcoded credential in source. Use environment variables, Azure Key Vault, or AWS Secrets Manager.",
    },
    Pattern {
        name: "md5-sha1",
        regex: r"(?i)\bMD5\.Create\b|\bSHA1\.Create\b|\bMD5CryptoServiceProvider\b|\bSHA1CryptoServiceProvider\b",
        severity: "HIGH",
        description: "MD5 / SHA1 are cryptographically broken. Use SHA-256+ (SHA256.Create) or Argon2/bcrypt for passwords.",
    },
    Pattern {
        name: "weak-prng",
        regex: r"\bnew\s+Random\s*\(",
        severity: "MEDIUM",
        description: "System.Random is not cryptographically secure. Use RandomNumberGenerator for security-sensitive values.",
    },
    Pattern {
        name: "unsafe-block",
        regex: r"\bunsafe\s*\{",
        severity: "MEDIUM",
        description: "unsafe block bypasses CLR memory safety. Audit pointer arithmetic and ensure pinned memory is released.",
    },
    Pattern {
        name: "xmldocument-dtd",
        regex: r"(?i)\bXmlDocument\b|\bXmlTextReader\b",
        severity: "MEDIUM",
        description: "XmlDocument and XmlTextReader enable XXE by default. Set XmlResolver = null and DtdProcessing = Prohibit.",
    },
    Pattern {
        name: "reflection-invoke",
        regex: r"(?i)\.Invoke\s*\([^)]*\)|Assembly\.Load\s*\(",
        severity: "MEDIUM",
        description: "Reflection Invoke / Assembly.Load with untrusted input enables code injection. Validate type and method names.",
    },
    Pattern {
        name: "regex-redos",
        regex: r"(?i)new\s+Regex\s*\([^)]*\+[^)]*\)",
        severity: "LOW",
        description: "Regex built from user input may enable ReDoS. Pre-compile patterns and apply input length limits.",
    },
];
