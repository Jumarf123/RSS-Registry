use super::SourceContext;
use crate::model::{Record, SourceKind};
use crate::path_extract::extract_paths;
use crate::registry;

const PATHS: [&str; 2] = [
    r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
    r"Software\Microsoft\Windows\ShellNoRoam\MUICache",
];

pub fn scan(_ctx: &SourceContext) -> Vec<Record> {
    let mut results = Vec::new();
    for path in PATHS {
        if let Some(key) = registry::open_hkcu(path) {
            for item in key.enum_values().flatten() {
                let (name, _value) = item;
                let mut added = false;
                for path in extract_paths(&name) {
                    results.push(Record::from_path(&path, None, SourceKind::MUICache));
                    added = true;
                }
                if !added && has_allowed_extension(&name) {
                    results.push(Record::from_path(&name, None, SourceKind::MUICache));
                }
            }
        }
    }
    results
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
