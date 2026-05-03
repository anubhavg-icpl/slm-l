use super::Pattern;

pub static PATTERNS: &[Pattern] = &[
    // ── SQL injection ────────────────────────────────────────────────────────
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
    // ── Command injection ────────────────────────────────────────────────────
    Pattern {
        name: "process-start-input",
        regex: r"(?i)Process\.Start\s*\([^)]*\+",
        severity: "CRITICAL",
        description: "Process.Start with concatenated input enables command injection. Validate/allowlist input strictly.",
    },
    // ── Insecure deserialization (RCE) ───────────────────────────────────────
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
        name: "soap-formatter",
        regex: r"(?i)\b(?:SoapFormatter|NetDataContractSerializer)\b",
        severity: "CRITICAL",
        description: "SoapFormatter / NetDataContractSerializer enable deserialization RCE with untrusted data. Use DataContractSerializer with a known-types allowlist.",
    },
    Pattern {
        name: "type-name-handling",
        regex: r"(?i)TypeNameHandling\s*\.\s*(?:All|Objects|Auto|Arrays)",
        severity: "CRITICAL",
        description: "Newtonsoft TypeNameHandling != None with untrusted JSON enables RCE (CWE-502). Set TypeNameHandling.None and bind to concrete types.",
    },
    // ── Injection — LDAP / XPath ─────────────────────────────────────────────
    Pattern {
        name: "ldap-injection",
        regex: r"(?i)(?:DirectorySearcher|DirectoryEntry)\s*\([^)]*\+",
        severity: "CRITICAL",
        description: "LDAP query with string concatenation enables LDAP injection (CWE-90). Encode all user inputs with SecurityElement.Escape.",
    },
    Pattern {
        name: "xpath-injection",
        regex: r#"(?i)\.(?:SelectNodes|SelectSingleNode|XPathSelectElement|XPathSelectElements)\s*\([^)]*\+"#,
        severity: "CRITICAL",
        description: "XPath expression built from user input enables XPath injection (CWE-643). Use parameterized XPath or input allowlisting.",
    },
    // ── XSS ──────────────────────────────────────────────────────────────────
    Pattern {
        name: "xss-response-write",
        regex: r"(?i)Response\.Write\s*\([^)]*(?:Request\b|\bInput\b|\bParam\b|\bQuery\b)",
        severity: "HIGH",
        description: "Response.Write with unencoded request data causes XSS (CWE-79). Use HtmlEncoder.Default.Encode or Razor's @variable syntax.",
    },
    // ── Path traversal ───────────────────────────────────────────────────────
    Pattern {
        name: "path-traversal",
        regex: r"(?i)File\.(Open|ReadAll|WriteAll|ReadText|WriteText|Create|Delete)\s*\([^)]*Request\.",
        severity: "HIGH",
        description: "File path derived from request input enables path traversal. Use Path.GetFullPath and validate it stays under allowed root.",
    },
    // ── Open redirect ────────────────────────────────────────────────────────
    Pattern {
        name: "open-redirect",
        regex: r"(?i)(?:Response\.Redirect|Redirect|LocalRedirect)\s*\([^)]*(?:Request\b|\burl\b|\bUri\b|\bredirect\b)",
        severity: "HIGH",
        description: "Redirect with unvalidated user input enables open redirect (CWE-601). Validate URL is relative or in a host allowlist.",
    },
    // ── Credential exposure ───────────────────────────────────────────────────
    Pattern {
        name: "hardcoded-password",
        regex: r#"(?i)(password|passwd|pwd|secret|apikey|api_key)\s*=\s*"[^"]{4,}""#,
        severity: "HIGH",
        description: "Hardcoded credential in source. Use environment variables, Azure Key Vault, or AWS Secrets Manager.",
    },
    Pattern {
        name: "hardcoded-connstring",
        regex: r#"(?i)connectionString\s*=\s*"[^"]{8,}""#,
        severity: "HIGH",
        description: "Hardcoded connection string exposes database credentials. Store in environment variables or a secrets manager.",
    },
    // ── Broken / weak cryptography ────────────────────────────────────────────
    Pattern {
        name: "md5-sha1",
        regex: r"(?i)\bMD5\.Create\b|\bSHA1\.Create\b|\bMD5CryptoServiceProvider\b|\bSHA1CryptoServiceProvider\b",
        severity: "HIGH",
        description: "MD5 / SHA1 are cryptographically broken. Use SHA-256+ (SHA256.Create) or Argon2/bcrypt for passwords.",
    },
    Pattern {
        name: "weak-cipher",
        regex: r"(?i)\b(?:DESCryptoServiceProvider|TripleDESCryptoServiceProvider|RC2CryptoServiceProvider)\b",
        severity: "HIGH",
        description: "DES / 3DES / RC2 are broken ciphers (CWE-327). Use AesGcm or AesCng with a 256-bit key.",
    },
    Pattern {
        name: "ecb-mode",
        regex: r"(?i)CipherMode\.ECB",
        severity: "HIGH",
        description: "ECB mode leaks plaintext patterns (CWE-327). Use AesGcm or CBC with HMAC-SHA256.",
    },
    // ── TLS / network ─────────────────────────────────────────────────────────
    Pattern {
        name: "cert-validation-bypass",
        regex: r"(?i)ServerCertificateValidationCallback\s*=",
        severity: "HIGH",
        description: "Custom ServerCertificateValidationCallback risks accepting invalid certificates. Returning true unconditionally disables TLS verification (CWE-295).",
    },
    Pattern {
        name: "ssrf-webclient",
        regex: r"(?i)(?:new\s+WebClient|HttpClient)[^;]*\.\s*(?:DownloadString|GetStringAsync|GetAsync|DownloadData)\s*\([^)]*(?:url|Uri|redirect|Request\.)",
        severity: "HIGH",
        description: "HTTP request with user-controlled URL enables SSRF (CWE-918). Validate URL against an allowlist of trusted hosts.",
    },
    // ── PRNG / randomness ─────────────────────────────────────────────────────
    Pattern {
        name: "weak-prng",
        regex: r"\bnew\s+Random\s*\(",
        severity: "MEDIUM",
        description: "System.Random is not cryptographically secure. Use RandomNumberGenerator for security-sensitive values.",
    },
    // ── Unsafe code ───────────────────────────────────────────────────────────
    Pattern {
        name: "unsafe-block",
        regex: r"\bunsafe\s*\{",
        severity: "MEDIUM",
        description: "unsafe block bypasses CLR memory safety. Audit pointer arithmetic and ensure pinned memory is released.",
    },
    // ── XML ───────────────────────────────────────────────────────────────────
    Pattern {
        name: "xmldocument-dtd",
        regex: r"(?i)\bXmlDocument\b|\bXmlTextReader\b",
        severity: "MEDIUM",
        description: "XmlDocument and XmlTextReader enable XXE by default. Set XmlResolver = null and DtdProcessing = Prohibit.",
    },
    // ── Reflection ───────────────────────────────────────────────────────────
    Pattern {
        name: "reflection-invoke",
        regex: r"(?i)\.Invoke\s*\([^)]*\)|Assembly\.Load\s*\(",
        severity: "MEDIUM",
        description: "Reflection Invoke / Assembly.Load with untrusted input enables code injection. Validate type and method names.",
    },
    // ── Cookie hygiene ────────────────────────────────────────────────────────
    Pattern {
        name: "cookie-missing-flags",
        regex: r"(?i)new\s+HttpCookie\s*\(",
        severity: "MEDIUM",
        description: "Verify HttpOnly=true and Secure=true on all cookies containing session or auth tokens (CWE-1004 / CWE-614).",
    },
    // ── ReDoS ─────────────────────────────────────────────────────────────────
    Pattern {
        name: "regex-redos",
        regex: r"(?i)new\s+Regex\s*\([^)]*\+[^)]*\)",
        severity: "LOW",
        description: "Regex built from user input may enable ReDoS. Pre-compile patterns and apply input length limits.",
    },
];
