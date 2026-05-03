use super::Pattern;

pub static PATTERNS: &[Pattern] = &[
    Pattern {
        name: "unsafe-block",
        regex: r"\bunsafe\s*\{",
        severity: "MEDIUM",
        description: "unsafe block opts out of Rust memory safety. Audit all invariants: pointer validity, aliasing, lifetimes.",
    },
    Pattern {
        name: "transmute",
        regex: r"\bstd::mem::transmute\b|\bmem::transmute\b",
        severity: "HIGH",
        description: "transmute reinterprets bytes between types — UB if layouts differ. Use safe alternatives: as, From/Into, bytemuck.",
    },
    Pattern {
        name: "from-raw-parts",
        regex: r"\bfrom_raw_parts\s*\(",
        severity: "HIGH",
        description: "from_raw_parts requires caller to guarantee pointer validity, alignment, and lifetime. Document invariants explicitly.",
    },
    Pattern {
        name: "raw-pointer-deref",
        regex: r"\*\s*(mut\s+)?\w+_ptr\b|\*\s*raw\b",
        severity: "HIGH",
        description: "Raw pointer dereference inside unsafe. Verify non-null, correctly aligned, and within valid allocation.",
    },
    Pattern {
        name: "forget",
        regex: r"\bstd::mem::forget\b|\bmem::forget\b",
        severity: "MEDIUM",
        description: "mem::forget leaks resources by skipping Drop. Prefer ManuallyDrop or ensure cleanup is handled elsewhere.",
    },
    Pattern {
        name: "unwrap-in-code",
        regex: r"\.unwrap\(\)",
        severity: "LOW",
        description: "unwrap() panics on None/Err. In production code use ?, expect() with context, or proper error handling.",
    },
    Pattern {
        name: "expect-in-code",
        regex: r#"\.expect\s*\(\s*""#,
        severity: "LOW",
        description: "expect() panics like unwrap() but with a message. Propagate errors with ? in fallible functions.",
    },
    Pattern {
        name: "integer-arithmetic",
        regex: r"(?:as\s+u(?:8|16|32|64|128|size)|as\s+i(?:8|16|32|64|128|size))",
        severity: "LOW",
        description: "as casts truncate silently in both debug and release. Use checked_as/try_into() or saturating/wrapping variants.",
    },
    Pattern {
        name: "send-sync-impl",
        regex: r"unsafe\s+impl\s+(?:Send|Sync)\s+for",
        severity: "HIGH",
        description: "Manual Send/Sync impl asserts thread safety to the compiler. Audit that shared/mutable access is actually safe.",
    },
    Pattern {
        name: "ffi-extern",
        regex: r#"\bextern\s+"C"\s*\{"#,
        severity: "MEDIUM",
        description: "FFI extern block: caller must ensure C function signatures match exactly and lifetimes are valid across boundary.",
    },
    Pattern {
        name: "env-vars-in-proc",
        regex: r"std::env::var\s*\(|std::env::args\s*\(",
        severity: "LOW",
        description: "Environment variables and args are attacker-controlled. Validate and sanitize before use in paths or commands.",
    },
];
