use super::SourceContext;
use crate::model::{Record, SourceKind};
use crate::path_extract::{extract_paths, extract_paths_from_bytes};
use crate::registry;
use crate::sources::util::find_best_filetime;

const BASES: [&str; 2] = [
    r"SYSTEM\CurrentControlSet\Services\bam\UserSettings\",
    r"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\",
];

pub fn scan(ctx: &SourceContext) -> Vec<Record> {
    let mut results = Vec::new();
    let Some(sid) = ctx.user_sid.as_ref() else {
        return results;
    };
    for base in BASES {
        let key_path = format!("{base}{sid}");
        if let Some(key) = registry::open_hklm(&key_path) {
            for item in key.enum_values().flatten() {
                let (name, value) = item;
                let executed_at = parse_timestamp(&value.bytes);
                let mut added = false;
                if let Some(decoded) = registry::decode_reg_string(&value.bytes) {
                    for path in extract_paths(&decoded) {
                        results.push(Record::from_path(&path, executed_at, SourceKind::BAM));
                        added = true;
                    }
                }
                for path in extract_paths(&name) {
                    results.push(Record::from_path(&path, executed_at, SourceKind::BAM));
                    added = true;
                }
                for path in extract_paths_from_bytes(&value.bytes) {
                    results.push(Record::from_path(&path, executed_at, SourceKind::BAM));
                    added = true;
                }
                if !added && has_allowed_extension(&name) {
                    results.push(Record::from_path(&name, executed_at, SourceKind::BAM));
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
