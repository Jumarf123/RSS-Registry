use super::SourceContext;
use crate::model::{Record, SourceKind};
use crate::path_extract::{extract_paths, extract_paths_from_bytes};
use crate::registry;
use crate::time::filetime_to_datetime_local;

const PATHS: [&str; 2] = [
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppLaunch",
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched",
];

pub fn scan(_ctx: &SourceContext) -> Vec<Record> {
    let mut results = Vec::new();
    for path in PATHS {
        if let Some(key) = registry::open_hkcu(path) {
            for item in key.enum_values().flatten() {
                let (name, value) = item;
                let executed_at = parse_timestamp(&value.bytes);
                let mut added = false;
                for path in extract_paths(&name) {
                    results.push(Record::from_path(
                        &path,
                        executed_at,
                        SourceKind::FeatureUsage,
                    ));
                    added = true;
                }
                for path in extract_paths_from_bytes(&value.bytes) {
                    results.push(Record::from_path(
                        &path,
                        executed_at,
                        SourceKind::FeatureUsage,
                    ));
                    added = true;
                }
                if !added && has_allowed_extension(&name) {
                    results.push(Record::from_path(
                        &name,
                        executed_at,
                        SourceKind::FeatureUsage,
                    ));
                }
            }
        }
    }
    results
}

fn parse_timestamp(bytes: &[u8]) -> Option<chrono::DateTime<chrono::Local>> {
    if bytes.len() >= 8 {
        let ts = u64::from_le_bytes(bytes[bytes.len() - 8..bytes.len()].try_into().ok()?);
        return filetime_to_datetime_local(ts);
    }
    None
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
