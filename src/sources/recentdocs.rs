use crate::model::{Record, SourceKind};
use crate::path_extract::{extract_allowed_names, extract_paths, extract_paths_from_bytes};
use super::SourceContext;

const ROOT: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs";

pub fn scan(_ctx: &SourceContext) -> Vec<Record> {
    let mut results = Vec::new();
    if let Some(key) = crate::registry::open_hkcu(ROOT) {
        collect_recent_key(&key, &mut results);
        if let Ok(subs) = crate::registry::subkeys(&key) {
            for sub in subs {
                collect_recent_key(&sub, &mut results);
            }
        }
    }
    results
}

fn collect_recent_key(key: &winreg::RegKey, results: &mut Vec<Record>) {
    for item in key.enum_values().flatten() {
        let (name, value) = item;
        if name.eq_ignore_ascii_case("MRUList") {
            continue;
        }
        let mut added = false;
        for path in extract_paths_from_bytes(&value.bytes) {
            results.push(Record::from_path(&path, None, SourceKind::RecentDocs));
            added = true;
        }
        if !added {
            for path in extract_paths(&name) {
                results.push(Record::from_path(&path, None, SourceKind::RecentDocs));
            }
            for s in extract_allowed_names(&value.bytes) {
                results.push(Record::from_path(&s, None, SourceKind::RecentDocs));
            }
        }
    }
}
