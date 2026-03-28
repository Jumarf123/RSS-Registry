use crate::model::{Record, SourceKind};
use crate::path_extract::{
    extract_allowed_names, extract_paths, extract_paths_from_bytes, has_allowed_extension,
    normalize_path_candidate,
};
use crate::registry;
use super::SourceContext;

const ROOT: &str = r"Software\7-Zip";

pub fn scan(_ctx: &SourceContext) -> Vec<Record> {
    let mut results = Vec::new();
    if let Some(key) = registry::open_hkcu(ROOT) {
        walk_key(&key, &mut results, 0);
    }
    results
}

fn walk_key(key: &winreg::RegKey, results: &mut Vec<Record>, depth: usize) {
    if depth > 3 {
        return;
    }
    for item in key.enum_values().flatten() {
        let (name, value) = item;
        let mut added = false;
        if let Some(decoded) = registry::decode_reg_string(&value.bytes) {
            for path in extract_paths(&decoded) {
                results.push(Record::from_path(&path, None, SourceKind::SevenZip));
                added = true;
            }
            if !added && has_allowed_extension(&decoded) {
                let path = normalize_path_candidate(&decoded).unwrap_or(decoded);
                results.push(Record::from_path(&path, None, SourceKind::SevenZip));
                added = true;
            }
        }
        for path in extract_paths_from_bytes(&value.bytes) {
            results.push(Record::from_path(&path, None, SourceKind::SevenZip));
            added = true;
        }
        for path in extract_paths(&name) {
            results.push(Record::from_path(&path, None, SourceKind::SevenZip));
            added = true;
        }
        if !added {
            for s in extract_allowed_names(&value.bytes) {
                results.push(Record::from_path(&s, None, SourceKind::SevenZip));
                added = true;
            }
            if !added && has_allowed_extension(&name) {
                let path = normalize_path_candidate(&name).unwrap_or_else(|| name.clone());
                results.push(Record::from_path(&path, None, SourceKind::SevenZip));
            }
        }
    }
    if let Ok(subs) = registry::subkeys(key) {
        for sub in subs {
            walk_key(&sub, results, depth + 1);
        }
    }
}
