use super::SourceContext;
use crate::model::{Record, SourceKind};
use crate::path_extract::extract_paths;
use crate::registry;
use crate::time::filetime_to_datetime_local;

pub fn scan(_ctx: &SourceContext) -> Vec<Record> {
    let mut results = Vec::new();
    if let Some(root) =
        registry::open_hkcu(r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist")
    {
        if let Ok(subs) = registry::subkeys(&root) {
            for sub in subs {
                if let Ok(count) = sub.open_subkey("Count") {
                    collect_count_key(&count, &mut results);
                }
            }
        }
    }
    results
}

fn collect_count_key(key: &winreg::RegKey, results: &mut Vec<Record>) {
    for item in key.enum_values().flatten() {
        let (name, value) = item;
        let decoded = rot13(&name);
        let executed_at = parse_last_exec(&value.bytes);
        for path in extract_paths(&decoded) {
            results.push(Record::from_path(
                &path,
                executed_at,
                SourceKind::UserAssist,
            ));
        }
    }
}

fn rot13(input: &str) -> String {
    input
        .chars()
        .map(|c| match c {
            'a'..='z' => (((c as u8 - b'a' + 13) % 26) + b'a') as char,
            'A'..='Z' => (((c as u8 - b'A' + 13) % 26) + b'A') as char,
            _ => c,
        })
        .collect()
}

fn parse_last_exec(bytes: &[u8]) -> Option<chrono::DateTime<chrono::Local>> {
    if bytes.len() >= 72 {
        let ts = u64::from_le_bytes(bytes[60..68].try_into().ok()?);
        return filetime_to_datetime_local(ts);
    }
    if bytes.len() >= 16 {
        let ts = u64::from_le_bytes(bytes[8..16].try_into().ok()?);
        return filetime_to_datetime_local(ts);
    }
    None
}
