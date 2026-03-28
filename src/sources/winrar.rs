use crate::model::{Record, SourceKind};
use crate::path_extract::{
    extract_allowed_names, extract_paths, extract_paths_from_bytes, has_allowed_extension,
    normalize_path_candidate,
};
use crate::registry;
use super::SourceContext;

const ROOT: &str = r"Software\WinRAR\DialogEditHistory";

pub fn scan(_ctx: &SourceContext) -> Vec<Record> {
    let mut results = Vec::new();
    if let Some(key) = registry::open_hkcu(ROOT) {
        collect_key(&key, &mut results);
        if let Ok(subs) = registry::subkeys(&key) {
            for sub in subs {
                collect_key(&sub, &mut results);
            }
        }
    }
    results
}

fn collect_key(key: &winreg::RegKey, results: &mut Vec<Record>) {
    for item in key.enum_values().flatten() {
        let (name, value) = item;
        let mut added = false;
        if let Some(decoded) = registry::decode_reg_string(&value.bytes) {
            for path in extract_paths(&decoded) {
                results.push(Record::from_path(&path, None, SourceKind::WinRAR));
                added = true;
            }
            if !added && has_allowed_extension(&decoded) {
                let path = normalize_path_candidate(&decoded).unwrap_or(decoded);
                results.push(Record::from_path(&path, None, SourceKind::WinRAR));
                added = true;
            }
        }
        for path in extract_paths_from_bytes(&value.bytes) {
            results.push(Record::from_path(&path, None, SourceKind::WinRAR));
            added = true;
        }
        for path in extract_paths(&name) {
            results.push(Record::from_path(&path, None, SourceKind::WinRAR));
            added = true;
        }
        if !added {
            for s in extract_allowed_names(&value.bytes) {
                results.push(Record::from_path(&s, None, SourceKind::WinRAR));
                added = true;
            }
            if !added && has_allowed_extension(&name) {
                let path = normalize_path_candidate(&name).unwrap_or_else(|| name.clone());
                results.push(Record::from_path(&path, None, SourceKind::WinRAR));
            }
        }
    }
}
