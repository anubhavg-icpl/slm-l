pub mod c;
pub mod cpp;
pub mod dotnet;
pub mod rust_lang;

use crate::detector::Language;

pub struct Pattern {
    pub name: &'static str,
    pub regex: &'static str,
    pub severity: &'static str,
    pub description: &'static str,
}

pub fn for_language(lang: Language) -> &'static [Pattern] {
    match lang {
        Language::C => c::PATTERNS,
        Language::Cpp => cpp::PATTERNS,
        Language::DotNet => dotnet::PATTERNS,
        Language::Rust => rust_lang::PATTERNS,
    }
}
