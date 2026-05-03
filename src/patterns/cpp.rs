use super::Pattern;

pub static PATTERNS: &[Pattern] = &[
    // ── Inherited C-class issues ─────────────────────────────────────────────
    Pattern {
        name: "gets",
        regex: r"\bgets\s*\(",
        severity: "CRITICAL",
        description: "gets() has no bounds checking — guaranteed buffer overflow. Use fgets() or std::getline().",
    },
    Pattern {
        name: "strcpy",
        regex: r"\bstrcpy\s*\(",
        severity: "HIGH",
        description: "strcpy() copies without limit. Use std::string, strlcpy(), or strncpy() with explicit bound.",
    },
    Pattern {
        name: "sprintf",
        regex: r"\bsprintf\s*\(",
        severity: "HIGH",
        description: "sprintf() writes without bounds. Use snprintf() or std::ostringstream.",
    },
    Pattern {
        name: "system-call",
        regex: r"\bsystem\s*\(",
        severity: "CRITICAL",
        description: "system() passes input to shell — command injection. Use exec family or boost::process.",
    },
    Pattern {
        name: "printf-format-string",
        regex: r"\bprintf\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*[,)]",
        severity: "HIGH",
        description: "printf(user_var) is a format string vulnerability. Use printf(\"%s\", var) or std::cout.",
    },
    Pattern {
        name: "rand-for-security",
        regex: r"\bstd::rand\s*\(\s*\)|\brand\s*\(\s*\)",
        severity: "MEDIUM",
        description: "rand() / std::rand() is not cryptographically secure. Use std::random_device or OS CSPRNG.",
    },
    // ── Memory management ────────────────────────────────────────────────────
    Pattern {
        name: "raw-new-array",
        regex: r"\bnew\s+\w[\w:<>]*\s*\[",
        severity: "HIGH",
        description: "Raw new[] requires manual delete[]. Use std::vector or std::unique_ptr<T[]> instead.",
    },
    Pattern {
        name: "integer-overflow-alloc",
        regex: r"\bnew\s+\w[\w:<>]*\s*\[\s*\w+\s*\*",
        severity: "HIGH",
        description: "Integer overflow in new[] size expression (n*m) produces undersized allocation. Use checked arithmetic or std::vector.",
    },
    Pattern {
        name: "delete-without-bracket",
        regex: r"\bdelete\s+[^\[\s]",
        severity: "HIGH",
        description: "delete on an array allocated with new[] is undefined behaviour. Use delete[].",
    },
    // ── Type-system safety ───────────────────────────────────────────────────
    Pattern {
        name: "reinterpret-cast",
        regex: r"\breinterpret_cast\s*<",
        severity: "HIGH",
        description: "reinterpret_cast bypasses the type system. Violating strict aliasing is UB. Prefer safer casts.",
    },
    Pattern {
        name: "const-cast",
        regex: r"\bconst_cast\s*<",
        severity: "MEDIUM",
        description: "const_cast removes const contract. Writing through a const_cast result is UB if object was const.",
    },
    Pattern {
        name: "c-style-cast",
        regex: r"\(char\s*\*\)\s*\w|\(void\s*\*\)\s*\w|\(int\s*\)\s*\w",
        severity: "LOW",
        description: "C-style casts bypass C++ safety checks. Use static_cast, dynamic_cast, or bit_cast.",
    },
    Pattern {
        name: "dynamic-cast-unchecked",
        regex: r"\bdynamic_cast\s*<[^>]+\*>",
        severity: "MEDIUM",
        description: "dynamic_cast to pointer returns nullptr on type mismatch. Always null-check the result before dereferencing.",
    },
    // ── Exception safety ─────────────────────────────────────────────────────
    Pattern {
        name: "throw-in-destructor",
        regex: r"~\w+\s*\([^)]*\)[^{]*\{[^}]*throw\b",
        severity: "HIGH",
        description: "Throwing from a destructor during stack unwinding calls std::terminate(). Mark destructor noexcept.",
    },
    Pattern {
        name: "catch-all-swallow",
        regex: r"catch\s*\(\s*\.\.\.\s*\)\s*\{\s*\}",
        severity: "MEDIUM",
        description: "catch(...) {} silently swallows all exceptions including std::bad_alloc. Log or rethrow; never suppress silently.",
    },
    // ── Raw pointer / UB ─────────────────────────────────────────────────────
    Pattern {
        name: "raw-pointer-arithmetic",
        regex: r"\*\s*\(\s*\w+\s*\+",
        severity: "MEDIUM",
        description: "Raw pointer arithmetic is error-prone. Use std::span, iterators, or index-based access.",
    },
    Pattern {
        name: "memset-object",
        regex: r"\bmemset\s*\(\s*(?:this|&\w+)\s*,",
        severity: "MEDIUM",
        description: "memset on a C++ object with non-trivial members is undefined behaviour. Use constructors or std::fill.",
    },
    // ── Move semantics ───────────────────────────────────────────────────────
    Pattern {
        name: "use-after-move",
        regex: r"\bstd::move\s*\(\s*\w+\s*\)",
        severity: "LOW",
        description: "Moved-from objects are in a valid-but-unspecified state. Do not read or move them again without reassignment.",
    },
];
