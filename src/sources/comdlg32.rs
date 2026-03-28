use crate::model::{Record, SourceKind};
use crate::path_extract::{extract_allowed_names, extract_paths, extract_paths_from_bytes, has_allowed_extension};
use crate::registry;
use super::SourceContext;

pub fn scan(_ctx: &SourceContext) -> Vec<Record> {
    let mut results = Vec::new();
    let roots = [
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSaveMRU",
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedMRU",
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU",
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU",
    ];
    for root in roots {
        if let Some(key) = registry::open_hkcu(root) {
            collect_key(&key, &mut results);
            if let Ok(subs) = registry::subkeys(&key) {
                for sub in subs {
                    collect_key(&sub, &mut results);
                }
            }
        }
    }
    results
}

fn collect_key(key: &winreg::RegKey, results: &mut Vec<Record>) {
    for item in key.enum_values().flatten() {
        let (name, value) = item;
        if name.eq_ignore_ascii_case("MRUList") || name.eq_ignore_ascii_case("MRUListEx") {
            continue;
        }
        if let Some(decoded) = registry::decode_reg_string(&value.bytes) {
            for path in extract_paths(&decoded) {
                results.push(Record::from_path(&path, None, SourceKind::ComDlg32));
            }
        }
        for path in extract_paths_from_bytes(&value.bytes) {
            results.push(Record::from_path(&path, None, SourceKind::ComDlg32));
        }
        // Some MRU entries store the path inside the value name as well.
        for path in extract_paths(&name) {
            results.push(Record::from_path(&path, None, SourceKind::ComDlg32));
        }
        if has_allowed_extension(&name) {
            results.push(Record::from_path(&name, None, SourceKind::ComDlg32));
        }
        for s in extract_allowed_names(&value.bytes) {
            results.push(Record::from_path(&s, None, SourceKind::ComDlg32));
        }
    }
}
