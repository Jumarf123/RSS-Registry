use crate::model::{Record, SourceKind};
use crate::path_extract::extract_paths;
use crate::registry;
use super::SourceContext;

const HKCU_KEYS: [&str; 2] = [
    r"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers",
    r"SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers",
];

const HKLM_KEYS: [&str; 2] = [
    r"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers",
    r"SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers",
];

pub fn scan(_ctx: &SourceContext) -> Vec<Record> {
    let mut results = Vec::new();
    for key_path in HKCU_KEYS {
        if let Some(key) = registry::open_hkcu(key_path) {
            collect_key(&key, &mut results);
        }
    }
    for key_path in HKLM_KEYS {
        if let Some(key) = registry::open_hklm(key_path) {
            collect_key(&key, &mut results);
        }
    }
    results
}

fn collect_key(key: &winreg::RegKey, results: &mut Vec<Record>) {
    for item in key.enum_values().flatten() {
        let (name, _value) = item;
        let mut added = false;
        for path in extract_paths(&name) {
            results.push(Record::from_path(&path, None, SourceKind::AppCompatFlags));
            added = true;
        }
        if !added && has_allowed_extension(&name) {
            results.push(Record::from_path(&name, None, SourceKind::AppCompatFlags));
        }
    }
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
