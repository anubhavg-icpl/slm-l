<div align="center">

<img src="assets/banner.avif" alt="slm-audit — local SLM security code scanner" width="100%">

# slm-audit

**Why your SAST tool needs AI — and how to run it without the cloud.**

> Combines deterministic static analysis with on-device SmolLM2 inference.<br>
> 100% offline — no API keys, no telemetry, no code leaves your machine.

[![CI](https://img.shields.io/badge/build-passing-brightgreen?style=flat-square)](https://github.com/anubhavg-icpl/slm-l)
[![Tests](https://img.shields.io/badge/tests-45%20passing-brightgreen?style=flat-square)](https://github.com/anubhavg-icpl/slm-l)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-2024--edition-orange?style=flat-square)](https://www.rust-lang.org)
[![Model](https://img.shields.io/badge/model-SmolLM2--1.7B-purple?style=flat-square)](https://huggingface.co/HuggingFaceTB/SmolLM2-1.7B-Instruct)
[![Inference](https://img.shields.io/badge/inference-100%25_local-green?style=flat-square)](#model-configuration)
[![SARIF](https://img.shields.io/badge/output-SARIF_2.1.0-informational?style=flat-square)](#output-formats)

<br>

<img src="assets/demo.gif" alt="slm-audit demo" width="90%">

</div>

---

## Contents

- [Why SAST Needs AI](#why-sast-needs-ai) — the problem this solves
- [How It Works](#how-it-works) — the two-layer architecture
- [Quick Start](#quick-start) — get running in 60 seconds
- [Usage](#usage) — CLI reference and examples
- [Output Formats](#output-formats) — terminal, JSON, SARIF 2.1.0
- [Model Configuration](#model-configuration) — SmolLM2 presets and custom models
- [Supported Languages & Patterns](#supported-languages--patterns) — 84 patterns, 4 languages
- [CI / GitHub Code Scanning Integration](#ci--github-code-scanning-integration)
- [Production Deployment](#production-deployment) — air-gap, performance, requirements
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

---

## Why SAST Needs AI

Traditional static analysis (SAST) tools have a fundamental blind spot: **they understand syntax, not semantics.**

A regex can tell you that `strcpy` appears on line 42. It cannot tell you whether the source buffer is bounded, whether the destination is heap or stack, whether the length was validated three functions ago, or whether the input is even attacker-controlled. Every developer who has used SonarQube, Semgrep, or CodeQL knows the result: hundreds of findings, most of them false positives, buried under noise until the team learns to ignore the scanner entirely.

**slm-audit closes this gap with a small language model that reads the code the way a human reviewer would.**

### What regex sees vs. what the SLM sees

```c
// Regex flags this as: "strcpy → HIGH severity, CWE-120"
// SLM sees: destination is 64 bytes on stack, source is attacker-controlled
//           network input with no length check → CRITICAL, exploitable.
void handle_request(char *user_input) {
    char buf[64];
    strcpy(buf, user_input);
}
```

```c
// Regex flags this as: "strcpy → HIGH severity, CWE-120"
// SLM sees: destination is dynamically sized to source length + 1.
//           No overflow possible → LOW risk, not a real finding.
void safe_copy(const char *src) {
    char *buf = malloc(strlen(src) + 1);
    strcpy(buf, src);
}
```

Both fragments contain `strcpy`. Only the first is dangerous. A regex cannot tell them apart. The SLM can.

### Why not just use ChatGPT?

Because your source code is proprietary, regulated, classified, or covered by an NDA. Sending it to a third-party API is a data breach waiting to happen. `slm-audit` runs the model **on your machine** — your code never leaves the process. No API keys, no network calls, no telemetry, no data exfiltration risk.

| Approach | Accuracy | Privacy | Speed | Cost |
|----------|----------|---------|-------|------|
| Regex-only SAST (Semgrep, etc.) | Low (syntax only) | Local | Fast | Free |
| Cloud LLM SAST (ChatGPT, Claude) | High | **Code leaves your machine** | Network latency | Per-query |
| **slm-audit** (local SLM) | **High** (semantic) | **100% local** | 2–30 s/file | Free |

### Why SmolLM2?

SmolLM2-1.7B-Instruct (Hugging Face, Apache 2.0) was chosen after evaluating every model in the SmolLM family for CPU-based security analysis:

| | SmolLM2-135M | SmolLM2-360M | **SmolLM2-1.7B** | SmolLM3-3B |
|---|---|---|---|---|
| IFEval (instruction following) | 29.9 | 41.0 | **56.7** | 76.7 |
| ARC (reasoning) | 37.3 | 43.7 | **51.7** | 65.6 |
| Training tokens | 2T | 4T | **11T** | 11T |
| Size (Q4_K_M GGUF) | ~90 MB | ~250 MB | **~1.1 GB** | ~1.9 GB |
| CPU RAM | ~0.5 GB | ~1 GB | **~2.5 GB** | ~4 GB |
| kalosm compatible | Yes | Yes | **Yes** | Untested (custom arch) |

SmolLM2-1.7B is the sweet spot: trained on 11T tokens including The Stack (code), IFEval 56.7 for reliable structured JSON output, and small enough to run on any laptop. SmolLM3-3B is objectively better but uses a custom `smollm3` architecture that may not load in kalosm's Llama builder.

---

## How It Works

`slm-audit` uses a **two-layer detection pipeline**. The static layer is fast and deterministic. The SLM layer is slower but understands context. Findings confirmed by both layers get `HIGH` confidence.

```mermaid
flowchart TD
    A[Source File / Directory] --> B{Language\nDetection}
    B -->|.c .h| C[C]
    B -->|.cpp .cc .hpp| D[C++]
    B -->|.cs| E[C#/.NET]
    B -->|.rs| F[Rust]

    C & D & E & F --> G[Static Pre-Scanner\n84 regex patterns]
    G --> H{File size\n> 6 KB?}
    H -->|Yes| I[Function-level\nChunker]
    H -->|No| J[Single Chunk]
    I & J --> K[Prompt Builder\nstatic hits + code]

    K --> L[SmolLM2-1.7B\nLocal SLM Inference]
    L --> M[JSON Response\nParser]
    M --> N[Confidence\nCorrelation]
    G --> N
    N --> O{--min-confidence\nfilter}
    O --> P[terminal / JSON / SARIF]
```

### Layer 1: Static Pre-Scanner

84 handcrafted regex patterns cover the most dangerous APIs across C, C++, C#/.NET, and Rust. Each pattern is mapped to a CWE, severity level, and human-readable remediation guidance. Runs in under 100 ms per file.

### Layer 2: SLM Semantic Analysis

The static hits are fed into the prompt as context alongside the source code. The SmolLM2 model analyzes the code with awareness of data flow, control flow, and the specific vulnerability patterns already flagged. It returns structured JSON findings with explanations and fix suggestions.

### Confidence Scoring

| Confidence | Meaning | How to use |
|------------|---------|------------|
| **HIGH** | Both static scan and SLM agree on this finding | Act on these first |
| **MEDIUM** | SLM-only finding, or static hit in `--static-only` mode | Review manually |
| **LOW** | SLM could not parse output, or uncorrelated finding | Informational |

Use `--min-confidence high` for CI gates. Use `--min-confidence low` for thorough audits.

---

## Quick Start

### Prerequisites

| Requirement | Version |
|-------------|---------|
| Rust toolchain | 1.75+ |
| Free disk space | ~1.5 GB (model cache) |
| RAM | 4 GB minimum |
| Internet access | First run only (model download) |

### Build

```bash
git clone https://github.com/anubhavg-icpl/slm-l.git
cd slm-l
cargo build --release
```

### First Run

```bash
# Scan a C file — downloads SmolLM2-1.7B (~1.1 GB) on first run
./target/release/slm-audit scan ./myproject/main.c
```

The model is cached at `~/.cache/kalosm/` and reused automatically.

### Fast Triage (No Model Download)

```bash
# Static patterns only — no AI, no download, runs in milliseconds
./target/release/slm-audit scan ./src/ --static-only
```

---

## Usage

```
slm-audit scan <PATH> [OPTIONS]

Arguments:
  <PATH>                  File or directory to audit

Options:
  --lang <LANG>           Override language detection [c|cpp|cs|rust]
  --format <FORMAT>       Output format [terminal|json|sarif]  [default: terminal]
  --timeout <SECS>        LLM inference timeout per file       [default: 60]
  --min-confidence <LVL>  Minimum confidence to report         [default: low]
                          [possible values: low, medium, high]
  --static-only           Skip LLM inference (fast, no model download)
  -h, --help              Print help
  -V, --version           Print version
```

### Examples

```bash
# Audit a directory, all findings
slm-audit scan ./src/

# HIGH-confidence only (confirmed by both static scan and SLM)
slm-audit scan ./src/ --min-confidence high

# JSON output — pipe to jq for CRITICAL findings
slm-audit scan ./src/ --format json \
  | jq '.[] | .findings[] | select(.severity == "CRITICAL")'

# SARIF for GitHub Code Scanning
slm-audit scan ./src/ --format sarif > results.sarif

# Large C++ project with extended timeout
slm-audit scan ./engine/ --lang cpp --timeout 120

# Static-only fast scan (no model download needed)
slm-audit scan ./src/ --static-only --format json
```

---

## Output Formats

### Terminal

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
slm-audit — 3 file(s), 7 finding(s)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[C] src/parser.c

  [CRITICAL] buffer-overflow line 42 [high]
  Pattern   : gets(
  Risk      : gets() has no bounds checking — guaranteed buffer overflow.
  Fix       : Use fgets(buf, sizeof(buf), stdin) with explicit size.

  [HIGH]    format-string line 78 [medium]
  Pattern   : printf(user_input)
  Risk      : User-controlled format string enables arbitrary reads/writes.
  Fix       : Always use printf("%s", user_input).

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Summary  CRITICAL:1  HIGH:3  MEDIUM:2  LOW:1
```

### JSON

Structured output for SIEM, XDR, or custom dashboards:

```json
[
  {
    "file": "src/parser.c",
    "language": "C",
    "findings": [
      {
        "line": 42,
        "severity": "CRITICAL",
        "category": "buffer-overflow",
        "pattern": "gets(",
        "explanation": "gets() has no bounds checking — guaranteed buffer overflow.",
        "suggestion": "Use fgets(buf, sizeof(buf), stdin) with explicit size.",
        "confidence": "HIGH"
      }
    ]
  }
]
```

### SARIF 2.1.0

Standard format for GitHub Code Scanning, VS Code, and most IDE security plugins:

```bash
slm-audit scan ./src/ --format sarif > results.sarif
```

SARIF output includes rule definitions, severity-to-level mapping, confidence-to-rank mapping, and fix suggestions in `fixes[]` arrays.

---

## Model Configuration

Edit `models.toml` in the project root (or set `SLM_AUDIT_CONFIG` to a custom path):

```toml
[model]
# Available presets:
#   "smollm2-135m"  SmolLM2-135M-Instruct      ~100 MB  [fastest, CI triage]
#   "smollm2-360m"  SmolLM2-360M-Instruct      ~250 MB  [fast CI]
#   "smollm2-1.7b"  SmolLM2-1.7B-Instruct       ~1.1 GB  [default, best balance]
#   "phi3"          Phi-3-mini-4k-instruct    ~2.2 GB  [strong reasoning]
#   "llama3.2-1b"   Llama-3.2-1B-Instruct       ~0.8 GB
#   "llama3.2-3b"   Llama-3.2-3B-Instruct       ~2.0 GB
#   "qwen2.5-0.5b"  Qwen2.5-0.5B-Instruct       ~0.5 GB
#   "qwen2.5-1.5b"  Qwen2.5-1.5B-Instruct       ~1.0 GB
#   "qwen2.5-3b"    Qwen2.5-3B-Instruct         ~1.8 GB  [code-focused]
preset = "smollm2-1.7b"

# Custom GGUF model from any HuggingFace repo:
# [model.custom]
# repo_id  = "HuggingFaceTB/SmolLM2-1.7B-Instruct-GGUF"
# filename = "smollm2-1.7b-instruct-q4_k_m.gguf"
```

Models are cached at `~/.cache/kalosm/` on first download and reused automatically.

---

## Supported Languages & Patterns

84 handcrafted patterns across 4 languages, each mapped to a CWE:

### C — 20 patterns

| Pattern | Severity | Vulnerability |
|---------|----------|---------------|
| `gets` | CRITICAL | Buffer overflow — no bounds check (CWE-120) |
| `system()` | CRITICAL | Command injection via shell (CWE-78) |
| `execl` / `execlp` / `execvp` / `execve` | CRITICAL | Command injection — exec family (CWE-78) |
| `strcpy` / `strcat` | HIGH | Buffer overflow (CWE-120) |
| `sprintf` | HIGH | Buffer overflow (CWE-120) |
| `scanf %s` without width | HIGH | Unbounded stack write (CWE-120) |
| `printf(user_var)` | HIGH | Format string injection (CWE-134) |
| `vprintf` / `vsprintf` family | HIGH | Format string injection (CWE-134) |
| `alloca` | HIGH | Attacker-controlled stack allocation (CWE-121) |
| `tmpnam` / `tempnam` | HIGH | TOCTOU race on temp files (CWE-377) |
| `chroot` without `chdir` | HIGH | Jail escape (CWE-243) |
| `dlopen` | HIGH | Shared-library hijacking (CWE-426) |
| `mmap` with `PROT_EXEC` | HIGH | Executable memory / shellcode (CWE-114) |
| `popen` | HIGH | Shell command injection (CWE-78) |
| `malloc` unchecked | MEDIUM | Null pointer dereference (CWE-476) |
| `memcpy` unchecked | MEDIUM | Buffer overflow (CWE-120) |
| `rand()` for security | MEDIUM | Weak PRNG (CWE-338) |
| `getenv` unchecked | MEDIUM | Attacker-controlled environment (CWE-807) |
| `atoi` | LOW | No error detection / overflow (CWE-190) |

### C++ — 19 patterns

Inherits C patterns, plus:

| Pattern | Severity | Vulnerability |
|---------|----------|---------------|
| `new[]` without `delete[]` | HIGH | Memory leak / undefined behaviour (CWE-401) |
| Integer overflow in `new[]` size | HIGH | Undersized allocation (CWE-190) |
| `delete` on `new[]` pointer | HIGH | Undefined behaviour (CWE-762) |
| `reinterpret_cast` | HIGH | Strict aliasing violation / UB (CWE-704) |
| `throw` in destructor | HIGH | `std::terminate` during stack unwind (CWE-703) |
| `dynamic_cast` result unchecked | MEDIUM | Null pointer dereference (CWE-476) |
| `const_cast` | MEDIUM | Const contract violation (CWE-704) |
| `catch(...){}` swallow | MEDIUM | Silent exception suppression (CWE-390) |
| `memset` on C++ object | MEDIUM | Undefined behaviour on non-trivial type (CWE-119) |
| Raw pointer arithmetic | MEDIUM | Off-by-one / out-of-bounds (CWE-467) |
| `std::rand()` for security | MEDIUM | Weak PRNG (CWE-338) |
| C-style cast | LOW | Bypasses C++ type safety (CWE-704) |
| `std::move` on lvalue | LOW | Use-after-move state (CWE-416) |

### C#/.NET — 25 patterns

| Pattern | Severity | Vulnerability |
|---------|----------|---------------|
| `SqlCommand` + string concatenation | CRITICAL | SQL injection (CWE-89) |
| `string.Format` + SQL keywords | CRITICAL | SQL injection (CWE-89) |
| `Process.Start` + concatenation | CRITICAL | Command injection (CWE-78) |
| `BinaryFormatter` | CRITICAL | Insecure deserialization / RCE (CWE-502) |
| `LosFormatter` / `ObjectStateFormatter` | CRITICAL | Insecure deserialization (CWE-502) |
| `SoapFormatter` / `NetDataContractSerializer` | CRITICAL | Insecure deserialization / RCE (CWE-502) |
| `TypeNameHandling.All/Objects/Auto` | CRITICAL | Newtonsoft JSON RCE (CWE-502) |
| `DirectorySearcher` + concatenation | CRITICAL | LDAP injection (CWE-90) |
| `SelectNodes` / `SelectSingleNode` + concat | CRITICAL | XPath injection (CWE-643) |
| `Response.Write` with request data | HIGH | Cross-site scripting / XSS (CWE-79) |
| `File.Open(Request.*)` | HIGH | Path traversal (CWE-22) |
| `Response.Redirect(userUrl)` | HIGH | Open redirect (CWE-601) |
| Hardcoded passwords / API keys | HIGH | Credential exposure (CWE-798) |
| Hardcoded connection strings | HIGH | Database credential exposure (CWE-798) |
| `MD5.Create` / `SHA1.Create` | HIGH | Broken cryptography (CWE-327) |
| `DESCryptoServiceProvider` / `RC2` | HIGH | Broken cipher (CWE-327) |
| `CipherMode.ECB` | HIGH | ECB leaks plaintext patterns (CWE-327) |
| `ServerCertificateValidationCallback` | HIGH | TLS certificate bypass (CWE-295) |
| WebClient / HttpClient with user URL | HIGH | SSRF (CWE-918) |
| `new Random()` for security | MEDIUM | Weak PRNG (CWE-338) |
| `unsafe {}` block | MEDIUM | CLR memory safety bypass |
| `XmlDocument` / `XmlTextReader` | MEDIUM | XXE injection (CWE-611) |
| `Assembly.Load` / `.Invoke` | MEDIUM | Reflection code injection (CWE-470) |
| `new HttpCookie` | MEDIUM | Missing HttpOnly / Secure flags (CWE-1004) |
| `new Regex(user_input)` | LOW | ReDoS (CWE-1333) |

### Rust — 20 patterns

| Pattern | Severity | Vulnerability |
|---------|----------|---------------|
| `unsafe impl Send/Sync` | HIGH | False thread-safety assertion (CWE-362) |
| `std::mem::transmute` | HIGH | Type reinterpretation / UB (CWE-843) |
| `String::from_utf8_unchecked` | HIGH | Invalid UTF-8 is immediate UB |
| `slice::from_raw_parts` | HIGH | Unsafe slice — validity must be proven |
| `slice::from_raw_parts_mut` | HIGH | Exclusive access required — aliasing is UB |
| `Box::from_raw` | HIGH | UAF / double-free if misused (CWE-416) |
| `NonNull::new_unchecked` | HIGH | Null pointer is immediate UB (CWE-476) |
| `CStr::from_ptr` | HIGH | Requires non-null, nul-terminated, valid ptr |
| `ptr::read` / `ptr::write` | HIGH | Bypasses ownership / aliasing rules |
| `.assume_init()` | HIGH | Uninitialized memory UB (CWE-908) |
| `Vec::set_len` | HIGH | Elements must be initialized (CWE-908) |
| Raw pointer dereference | HIGH | Null / dangling pointer (CWE-476) |
| Hardcoded `const` secret / key | HIGH | Credential exposure (CWE-798) |
| `unsafe {}` block | MEDIUM | Opt-out of memory safety |
| `mem::forget` | MEDIUM | Resource leak — skips `Drop` |
| FFI `extern "C"` block | MEDIUM | Cross-boundary invariant violations |
| `.unwrap()` | LOW | Panic on `None` / `Err` (CWE-390) |
| `.expect("...")` | LOW | Panic with message (CWE-390) |
| `as` numeric cast | LOW | Silent truncation (CWE-197) |
| `std::env::var` / `args` | LOW | Attacker-controlled input (CWE-807) |

---

## CI / GitHub Code Scanning Integration

### GitHub Actions

```yaml
name: Security Audit

on: [push, pull_request]

jobs:
  slm-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable

      - name: Cache Kalosm model
        uses: actions/cache@v4
        with:
          path: ~/.cache/kalosm
          key: smollm2-1.7b-v1

      - name: Build slm-audit
        run: cargo build --release

      - name: Run security scan
        run: |
          ./target/release/slm-audit scan ./src \
            --format sarif \
            --min-confidence medium \
            --timeout 120 \
            > results.sarif

      - name: Upload to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### GitLab CI

```yaml
security-audit:
  stage: test
  script:
    - cargo build --release
    - ./target/release/slm-audit scan ./src --format sarif --min-confidence medium > gl-sast-report.sarif
  artifacts:
    reports:
      sast: gl-sast-report.sarif
```

---

## Production Deployment

### System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| RAM | 4 GB | 8 GB |
| Disk (model cache) | 1.5 GB | 3 GB |
| CPU | 4 cores | 8+ cores |
| OS | Linux / macOS / Windows | Linux x86-64 |

### Performance

| File size | Static scan | SLM analysis (SmolLM2-1.7B, CPU) |
|-----------|-------------|--------------------------|
| < 1 KB | < 5 ms | 2–8 s |
| 1–10 KB | < 20 ms | 8–30 s |
| 10–50 KB | < 100 ms | 30–90 s (chunked by function) |
| > 50 KB | < 500 ms | Multiple chunks, processed sequentially |

> **CI gate:** `--timeout 30 --min-confidence high`<br>
> **Thorough audit:** `--timeout 120 --min-confidence low`<br>
> **Fast triage:** `--static-only` (no model needed)

### Air-Gap / Offline Deployment

All inference runs locally via kalosm. No network calls during analysis.

```bash
# Step 1 — on an internet-connected machine, build and warm the cache
cargo build --release
./target/release/slm-audit scan ./dummy.rs  # triggers model download

# Step 2 — copy the binary and model cache to the air-gapped host
scp -r ~/.cache/kalosm airgap-host:~/.cache/kalosm
scp target/release/slm-audit airgap-host:/usr/local/bin/

# Step 3 — run normally on the air-gapped host
slm-audit scan ./classified-project/
```

---

## Features

| Feature | Status |
|---------|--------|
| C, C++, C#/.NET, Rust support | Yes |
| 84 static vulnerability patterns (CWE-mapped) | Yes |
| Local SmolLM2 SLM inference via Kalosm | Yes |
| Function-level chunking for large files | Yes |
| Confidence scoring (LOW / MEDIUM / HIGH) | Yes |
| `--min-confidence` filter | Yes |
| `--static-only` mode (no model download) | Yes |
| Per-file inference timeout (`--timeout`) | Yes |
| Terminal, JSON, SARIF 2.1.0 output | Yes |
| Configurable model presets via `models.toml` | Yes |
| Custom GGUF model support | Yes |
| 45 unit tests | Yes |
| 100% offline — zero external API calls | Yes |

---

## Roadmap

| Item | Priority | Status |
|------|----------|--------|
| SARIF 2.1.0 output | P0 | Done |
| `--min-confidence` filter | P0 | Done |
| Function-level file chunking | P0 | Done |
| Inference timeout (`--timeout`) | P0 | Done |
| 45 unit tests passing | P0 | Done |
| `--static-only` mode | P1 | Done |
| Configurable model presets (SmolLM2, Qwen, Llama) | P1 | Done |
| Parallel file analysis | P1 | Planned |
| `.slm-audit-ignore` suppression file | P1 | Planned |
| GPU acceleration (CUDA / Metal) | P2 | Planned |
| Incremental scan (changed files only) | P2 | Planned |
| VS Code extension | P2 | Planned |
| SmolLM3-3B support (pending kalosm arch compat) | P2 | Research |
| Security-fine-tuned model | P3 | Research |

---

## Contributing

Contributions are welcome.

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/your-feature`
3. Add or update tests for any pattern or feature changes
4. Run `cargo test` — all tests must pass
5. Run `cargo clippy -- -D warnings`
6. Run `cargo fmt -- --check`
7. Open a pull request with a clear description

### Adding Vulnerability Patterns

Patterns live in `src/patterns/<language>.rs`:

```rust
Pattern {
    name: "pattern-id",           // unique kebab-case identifier
    regex: r"your_regex_here",    // use raw string literals
    severity: "HIGH",             // CRITICAL / HIGH / MEDIUM / LOW
    description: "Why this is dangerous and what to use instead.",
},
```

Add a unit test in `src/scanner.rs`:

```rust
#[test]
fn my_pattern_detected() {
    let src = r#"<code that triggers the pattern>"#;
    assert!(has(&scan(src, Language::C), "pattern-id"));
}
```

---

## License

MIT License — see [LICENSE](LICENSE) for full text.

---

<div align="center">

<img src="assets/logo.avif" alt="slm-audit logo" width="80">

Built with [Kalosm](https://github.com/floneum/floneum) &nbsp;·&nbsp; Powered by [SmolLM2](https://huggingface.co/HuggingFaceTB/SmolLM2-1.7B-Instruct) &nbsp;·&nbsp; Written in [Rust](https://www.rust-lang.org)

**[Report an Issue](https://github.com/anubhavg-icpl/slm-l/issues)** &nbsp;·&nbsp; **[anubhavg-icpl](https://github.com/anubhavg-icpl)**

</div>
