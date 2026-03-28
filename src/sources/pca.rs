use crate::model::{Record, SourceKind};
use crate::path_extract::{extract_paths, extract_paths_from_bytes};
use crate::sources::util::find_best_filetime;
use crate::registry;
use super::SourceContext;

const PATHS: [&str; 2] = [
    r"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store",
    r"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Persisted",
];

pub fn scan(_ctx: &SourceContext) -> Vec<Record> {
    let mut results = Vec::new();
    for path in PATHS {
        if let Some(key) = registry::open_hkcu(path) {
            for item in key.enum_values().flatten() {
                let (name, value) = item;
                let executed_at = parse_timestamp(&value.bytes);
                let mut added = false;
                if let Some(decoded) = registry::decode_reg_string(&value.bytes) {
                    for path in extract_paths(&decoded) {
                        results.push(Record::from_path(&path, executed_at, SourceKind::PCA));
                        added = true;
                    }
                }
                for path in extract_paths(&name) {
                    results.push(Record::from_path(&path, executed_at, SourceKind::PCA));
                    added = true;
                }
                for path in extract_paths_from_bytes(&value.bytes) {
                    results.push(Record::from_path(&path, executed_at, SourceKind::PCA));
                    added = true;
                }
                if !added && has_allowed_extension(&name) {
                    results.push(Record::from_path(&name, executed_at, SourceKind::PCA));
                }
            }
        }
    }
    results
}

fn parse_timestamp(bytes: &[u8]) -> Option<chrono::DateTime<chrono::Local>> {
    find_best_filetime(bytes)
}

fn has_allowed_extension(text: &str) -> bool {
    let lower = text.to_lowercase();
    lower.ends_with(".exe")
        || lower.ends_with(".dll")
        || lower.ends_with(".jar")
        || lower.ends_with(".rar")
        || lower.ends_with(".zip")
        || lower.ends_with(".bat")
        || lower.ends_with(".cmd")
        || lower.ends_with(".ps1")
}
