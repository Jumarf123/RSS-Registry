use super::SourceContext;
use crate::model::{Record, SourceKind};
use crate::path_extract::{extract_paths, extract_paths_from_bytes};
use crate::registry;

pub fn scan(_ctx: &SourceContext) -> Vec<Record> {
    let mut results = Vec::new();
    if let Some(key) =
        registry::open_hkcu(r"Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths")
    {
        for item in key.enum_values().flatten() {
            let (name, value) = item;
            for path in extract_paths_from_bytes(&value.bytes) {
                results.push(Record::from_path(&path, None, SourceKind::TypedPaths));
            }
            for path in extract_paths(&name) {
                results.push(Record::from_path(&path, None, SourceKind::TypedPaths));
            }
        }
    }
    results
}
