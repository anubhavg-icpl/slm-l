use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    C,
    Cpp,
    DotNet,
    Rust,
}

impl Language {
    pub fn from_path(path: &Path) -> Option<Self> {
        match path.extension()?.to_str()? {
            "c" | "h" => Some(Language::C),
            "cpp" | "cc" | "cxx" | "hpp" | "hxx" => Some(Language::Cpp),
            "cs" => Some(Language::DotNet),
            "rs" => Some(Language::Rust),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Language::C => "C",
            Language::Cpp => "C++",
            Language::DotNet => "C#/.NET",
            Language::Rust => "Rust",
        }
    }
}
