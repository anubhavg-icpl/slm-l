use super::Pattern;

pub static PATTERNS: &[Pattern] = &[
    // ── unsafe blocks ────────────────────────────────────────────────────────
    Pattern {
        name: "unsafe-block",
        regex: r"\bunsafe\s*\{",
        severity: "MEDIUM",
        description: "unsafe block opts out of Rust memory safety. Audit all invariants: pointer validity, aliasing, lifetimes.",
    },
    Pattern {
        name: "send-sync-impl",
        regex: r"unsafe\s+impl\s+(?:Send|Sync)\s+for",
        severity: "HIGH",
        description: "Manual Send/Sync impl asserts thread safety to the compiler. Audit that shared/mutable access is actually safe.",
    },
    // ── Type reinterpretation ────────────────────────────────────────────────
    Pattern {
        name: "transmute",
        regex: r"\bstd::mem::transmute\b|\bmem::transmute\b",
        severity: "HIGH",
        description: "transmute reinterprets bytes between types — UB if layouts differ. Use safe alternatives: as, From/Into, bytemuck.",
    },
    Pattern {
        name: "from-utf8-unchecked",
        regex: r"\bString::from_utf8_unchecked\s*\(|\bstr::from_utf8_unchecked\s*\(",
        severity: "HIGH",
        description: "from_utf8_unchecked with invalid UTF-8 is immediate UB. Use String::from_utf8() and handle the Err variant.",
    },
    // ── Raw pointer construction ──────────────────────────────────────────────
    Pattern {
        name: "from-raw-parts",
        regex: r"\bslice::from_raw_parts\s*\(",
        severity: "HIGH",
        description: "from_raw_parts requires pointer validity, alignment, initialization, and correct length. Document invariants explicitly.",
    },
    Pattern {
        name: "from-raw-parts-mut",
        regex: r"\bslice::from_raw_parts_mut\s*\(",
        severity: "HIGH",
        description: "from_raw_parts_mut requires exclusive access — any shared reference to overlapping memory is instant UB.",
    },
    Pattern {
        name: "box-from-raw",
        regex: r"\bBox::from_raw\s*\(",
        severity: "HIGH",
        description: "Box::from_raw transfers ownership from a raw pointer. Double-free or UAF if pointer is invalid or already owned.",
    },
    Pattern {
        name: "nonnull-new-unchecked",
        regex: r"\bNonNull::new_unchecked\s*\(",
        severity: "HIGH",
        description: "NonNull::new_unchecked with a null pointer is immediate UB. Use NonNull::new() and handle the None case.",
    },
    Pattern {
        name: "cstr-from-ptr",
        regex: r"\bCStr::from_ptr\s*\(",
        severity: "HIGH",
        description: "CStr::from_ptr requires a non-null, nul-terminated, valid-for-lifetime pointer. Verify provenance before calling.",
    },
    // ── Raw pointer read / write ──────────────────────────────────────────────
    Pattern {
        name: "raw-pointer-deref",
        regex: r"\*\s*(mut\s+)?\w+_ptr\b|\*\s*raw\b",
        severity: "HIGH",
        description: "Raw pointer dereference inside unsafe. Verify non-null, correctly aligned, and within valid allocation.",
    },
    Pattern {
        name: "ptr-read-write",
        regex: r"\bptr::(?:read|write|read_unaligned|write_unaligned|copy|copy_nonoverlapping)\s*\(",
        severity: "HIGH",
        description: "ptr::read/write bypass ownership and aliasing rules. Ensure target is valid, aligned, initialized, and not aliased.",
    },
    // ── Uninitialized memory ──────────────────────────────────────────────────
    Pattern {
        name: "maybe-uninit-assume-init",
        regex: r"\.assume_init\s*\(",
        severity: "HIGH",
        description: "MaybeUninit::assume_init on uninitialized memory is immediate UB. Ensure every field is initialized first.",
    },
    Pattern {
        name: "vec-set-len",
        regex: r"\.set_len\s*\(",
        severity: "HIGH",
        description: "Vec::set_len with len > capacity is UB; elements between old and new len must be initialized. Prefer Vec::resize or extend.",
    },
    // ── Resource leaks ────────────────────────────────────────────────────────
    Pattern {
        name: "forget",
        regex: r"\bstd::mem::forget\b|\bmem::forget\b",
        severity: "MEDIUM",
        description: "mem::forget leaks resources by skipping Drop. Prefer ManuallyDrop or ensure cleanup is handled elsewhere.",
    },
    // ── FFI boundary ─────────────────────────────────────────────────────────
    Pattern {
        name: "ffi-extern",
        regex: r#"\bextern\s+"C"\s*\{"#,
        severity: "MEDIUM",
        description: "FFI extern block: C function signatures must match exactly and lifetimes must be valid across the boundary.",
    },
    // ── Secrets / credentials ─────────────────────────────────────────────────
    Pattern {
        name: "hardcoded-secret",
        regex: r#"(?i)\bconst\s+\w*(?:PASSWORD|SECRET|KEY|TOKEN|APIKEY|API_KEY)\w*\s*(?::\s*\S+\s*)?=\s*""#,
        severity: "HIGH",
        description: "Hardcoded secret in const. Never store credentials in source. Use environment variables or a secrets manager.",
    },
    // ── Panic surface ─────────────────────────────────────────────────────────
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
    // ── Numeric safety ────────────────────────────────────────────────────────
    Pattern {
        name: "integer-arithmetic",
        regex: r"(?:as\s+u(?:8|16|32|64|128|size)|as\s+i(?:8|16|32|64|128|size))",
        severity: "LOW",
        description: "as casts truncate silently in debug and release. Use try_into() or checked/saturating/wrapping variants.",
    },
    // ── Attacker-controlled input ─────────────────────────────────────────────
    Pattern {
        name: "env-vars-in-proc",
        regex: r"std::env::var\s*\(|std::env::args\s*\(",
        severity: "LOW",
        description: "Environment variables and args are attacker-controlled. Validate and sanitize before use in paths or commands.",
    },
];
