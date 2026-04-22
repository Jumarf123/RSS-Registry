use std::collections::HashSet;

use super::SourceContext;
use crate::model::{Record, SourceKind};
use crate::path_extract::extract_paths_from_bytes;
use crate::sources::util::find_best_filetime;

const KEY_PATH: &str = r"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache";

pub fn scan(_ctx: &SourceContext) -> Vec<Record> {
    let mut paths: HashSet<String> = HashSet::new();
    let mut results = Vec::new();
    if let Some(key) = crate::registry::open_hklm(KEY_PATH) {
        let key_ts = crate::registry::last_write_time(&key);
        for (_name, bytes) in crate::registry::enum_binary_values(&key) {
            let ts = find_best_filetime(&bytes).or(key_ts);
            for p in extract_paths_from_bytes(&bytes) {
                if paths.insert(p.clone()) {
                    results.push(Record::from_path(&p, ts, SourceKind::ShimCache));
                }
            }
        }
    }
    results
}
