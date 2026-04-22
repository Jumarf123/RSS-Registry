use super::SourceContext;
use crate::model::{Record, SourceKind};
use crate::path_extract::{extract_paths, extract_paths_from_bytes};
use crate::registry;

const HKCU_KEYS: [&str; 3] = [
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
];

const HKLM_KEYS: [&str; 4] = [
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
];

pub fn scan(_ctx: &SourceContext) -> Vec<Record> {
    let mut results = Vec::new();
    for path in HKCU_KEYS {
        if let Some(key) = registry::open_hkcu(path) {
            collect_values(&key, &mut results);
        }
    }
    for path in HKLM_KEYS {
        if let Some(key) = registry::open_hklm(path) {
            collect_values(&key, &mut results);
        }
    }
    results
}

fn collect_values(key: &winreg::RegKey, results: &mut Vec<Record>) {
    for item in key.enum_values().flatten() {
        let (name, value) = item;
        for path in extract_paths_from_bytes(&value.bytes) {
            results.push(Record::from_path(&path, None, SourceKind::Startup));
        }
        for path in extract_paths(&name) {
            results.push(Record::from_path(&path, None, SourceKind::Startup));
        }
    }
}
