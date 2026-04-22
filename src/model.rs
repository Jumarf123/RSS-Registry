use chrono::{DateTime, Local};
use std::collections::{HashMap, HashSet};
use std::path::Path;

use crate::path_extract;
use crate::time;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SourceKind {
    WinRAR,
    SevenZip,
    ShimCache,
    PCA,
    FeatureUsage,
    Startup,
    BAM,
    AppCompatFlags,
    MUICache,
    UserAssist,
    TypedPaths,
    RecentDocs,
    ComDlg32,
    RunMRU,
}

impl SourceKind {
    pub fn label(&self) -> &'static str {
        match self {
            SourceKind::WinRAR => "WinRAR",
            SourceKind::SevenZip => "7-Zip",
            SourceKind::ShimCache => "ShimCache / AppCompatCache",
            SourceKind::PCA => "PCA / Compatibility Assistant",
            SourceKind::FeatureUsage => "FeatureUsage",
            SourceKind::Startup => "Startup",
            SourceKind::BAM => "BAM",
            SourceKind::AppCompatFlags => "AppCompat Flags",
            SourceKind::MUICache => "MUICache",
            SourceKind::UserAssist => "UserAssist",
            SourceKind::TypedPaths => "TypedPaths",
            SourceKind::RecentDocs => "RecentDocs",
            SourceKind::ComDlg32 => "ComDlg32",
            SourceKind::RunMRU => "RunMRU",
        }
    }
}

pub fn all_sources() -> Vec<SourceKind> {
    vec![
        SourceKind::WinRAR,
        SourceKind::SevenZip,
        SourceKind::ShimCache,
        SourceKind::PCA,
        SourceKind::FeatureUsage,
        SourceKind::Startup,
        SourceKind::BAM,
        SourceKind::AppCompatFlags,
        SourceKind::MUICache,
        SourceKind::UserAssist,
        SourceKind::TypedPaths,
        SourceKind::RecentDocs,
        SourceKind::ComDlg32,
        SourceKind::RunMRU,
    ]
}

#[derive(Debug, Clone)]
pub struct FileTimes {
    pub created: Option<DateTime<Local>>,
    pub modified: Option<DateTime<Local>>,
    pub accessed: Option<DateTime<Local>>,
}

#[derive(Debug, Clone)]
pub struct Record {
    pub file_name: String,
    pub path: String,
    pub deleted: bool,
    pub executed_at: Option<DateTime<Local>>,
    pub file_times: Option<FileTimes>,
    pub sources: HashSet<SourceKind>,
}

impl Record {
    pub fn from_path(path: &str, executed_at: Option<DateTime<Local>>, source: SourceKind) -> Self {
        let normalized = normalize_path(path);
        let exists = Path::new(&normalized).is_file();
        let file_times = if exists {
            time::collect_file_times(&normalized)
        } else {
            None
        };
        let file_name = Path::new(&normalized)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(&normalized)
            .to_string();
        let mut sources = HashSet::new();
        sources.insert(source);
        Record {
            file_name,
            path: normalized,
            deleted: !exists,
            executed_at,
            file_times,
            sources,
        }
    }

    pub fn merge_from(&mut self, other: Record) {
        if !other.deleted {
            self.deleted = false;
            self.file_times = other.file_times.or(self.file_times.take());
        }
        if let Some(exec) = other.executed_at {
            if let Some(curr) = self.executed_at {
                if exec > curr {
                    self.executed_at = Some(exec);
                }
            } else {
                self.executed_at = Some(exec);
            }
        }
        self.sources.extend(other.sources);
    }
}

pub fn dedup_records(records: Vec<Record>) -> Vec<Record> {
    let mut map: HashMap<String, Record> = HashMap::new();
    for rec in records {
        let key = normalize_path(&rec.path).to_lowercase();
        if let Some(existing) = map.get_mut(&key) {
            existing.merge_from(rec);
        } else {
            map.insert(key, rec);
        }
    }
    map.into_values().collect()
}

pub fn normalize_path(path: &str) -> String {
    path_extract::normalize_path(path)
}

pub fn is_not_found_path(path: &str) -> bool {
    !path_extract::has_path_location(path)
}

#[derive(Debug, Clone)]
pub struct ExtensionFilters {
    pub exe: bool,
    pub dll: bool,
    pub jar: bool,
    pub rar: bool,
    pub zip: bool,
    pub bat: bool,
    pub nfp: bool,
}

impl ExtensionFilters {
    pub fn new() -> Self {
        Self {
            exe: true,
            dll: true,
            jar: true,
            rar: true,
            zip: true,
            bat: true,
            nfp: true,
        }
    }

    pub fn is_allowed(&self, path: &str) -> bool {
        if is_not_found_path(path) && !self.nfp {
            return false;
        }

        let lower = path.to_lowercase();
        if lower.ends_with(".exe") {
            return self.exe;
        }
        if lower.ends_with(".dll") {
            return self.dll;
        }
        if lower.ends_with(".jar") {
            return self.jar;
        }
        if lower.ends_with(".rar") {
            return self.rar;
        }
        if lower.ends_with(".zip") {
            return self.zip;
        }
        if lower.ends_with(".bat") {
            return self.bat;
        }
        // .cmd and .ps1 are always allowed (no toggle).
        lower.ends_with(".cmd") || lower.ends_with(".ps1")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nfp_filter_controls_paths_without_locations() {
        let mut filters = ExtensionFilters::new();
        assert!(filters.is_allowed("123.rar"));
        assert!(filters.is_allowed(r"C:\Temp\123.rar"));

        filters.nfp = false;
        assert!(!filters.is_allowed("123.rar"));
        assert!(filters.is_allowed(r"C:\Temp\123.rar"));
    }
}
