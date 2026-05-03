use regex::Regex;

use crate::detector::Language;

pub const CHUNK_CHARS: usize = 6_000;

#[derive(Debug, Clone)]
pub struct Chunk {
    pub start_line: usize,
    pub content: String,
}

pub fn chunk_source(source: &str, lang: Language) -> Vec<Chunk> {
    if source.len() <= CHUNK_CHARS {
        return vec![Chunk { start_line: 1, content: source.to_string() }];
    }

    let boundaries = find_function_starts(source, lang);

    if boundaries.len() > 1 {
        build_chunks_from_boundaries(source, &boundaries)
    } else {
        split_by_lines(source)
    }
}

fn fn_pattern(lang: Language) -> &'static str {
    match lang {
        Language::C | Language::Cpp => {
            r"(?m)^[a-zA-Z_][\w\s\*:<>]*\w\s*\([^;]*\)\s*(const\s*)?(noexcept\s*)?\{"
        }
        Language::DotNet => {
            r"(?m)^\s+(public|private|protected|internal|static|override|virtual|async)\s+[\w<>\[\]]+\s+\w+\s*\("
        }
        Language::Rust => r"(?m)^\s*(pub(\s*\(\s*crate\s*\))?\s+)?(async\s+)?fn\s+\w+",
    }
}

fn find_function_starts(source: &str, lang: Language) -> Vec<usize> {
    let Ok(re) = Regex::new(fn_pattern(lang)) else {
        return Vec::new();
    };

    let mut starts: Vec<usize> = re
        .find_iter(source)
        .map(|m| source[..m.start()].lines().count() + 1)
        .collect();

    starts.dedup();
    starts
}

fn build_chunks_from_boundaries(source: &str, boundaries: &[usize]) -> Vec<Chunk> {
    let lines: Vec<&str> = source.lines().collect();
    let total = lines.len();
    let mut chunks: Vec<Chunk> = Vec::new();
    let mut current_start = *boundaries.first().unwrap_or(&1);
    let mut current_buf = String::new();

    for (i, &boundary) in boundaries.iter().enumerate() {
        let next = boundaries.get(i + 1).copied().unwrap_or(total + 1);
        let seg_end = next.saturating_sub(1).min(total);
        let seg = lines[(boundary - 1)..seg_end].join("\n");

        if current_buf.len() + seg.len() > CHUNK_CHARS && !current_buf.is_empty() {
            chunks.push(Chunk { start_line: current_start, content: current_buf.clone() });
            current_start = boundary;
            current_buf = seg;
        } else {
            if !current_buf.is_empty() {
                current_buf.push('\n');
            } else {
                current_start = boundary;
            }
            current_buf.push_str(&seg);
        }
    }

    if !current_buf.is_empty() {
        chunks.push(Chunk { start_line: current_start, content: current_buf });
    }

    if chunks.is_empty() {
        chunks.push(Chunk { start_line: 1, content: source.to_string() });
    }

    chunks
}

fn split_by_lines(source: &str) -> Vec<Chunk> {
    let mut chunks = Vec::new();
    let mut current_start = 1usize;
    let mut current_buf = String::new();

    for (i, line) in source.lines().enumerate() {
        if current_buf.len() + line.len() + 1 > CHUNK_CHARS && !current_buf.is_empty() {
            chunks.push(Chunk { start_line: current_start, content: current_buf.clone() });
            current_start = i + 1;
            current_buf = line.to_string();
        } else {
            if !current_buf.is_empty() {
                current_buf.push('\n');
            }
            current_buf.push_str(line);
        }
    }

    if !current_buf.is_empty() {
        chunks.push(Chunk { start_line: current_start, content: current_buf });
    }

    chunks
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_file_is_single_chunk() {
        let src = "fn main() {}";
        let chunks = chunk_source(src, Language::Rust);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].start_line, 1);
    }

    #[test]
    fn large_file_splits() {
        let line = "let x = some_func().unwrap();\n";
        let src = line.repeat(300); // ~9 000 chars
        let chunks = chunk_source(&src, Language::Rust);
        assert!(chunks.len() > 1);
        assert!(chunks.iter().all(|c| c.content.len() <= CHUNK_CHARS + 200));
    }
}
