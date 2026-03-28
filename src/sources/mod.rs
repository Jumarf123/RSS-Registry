use std::collections::HashSet;

use crate::model::{dedup_records, Record, SourceKind};
use crate::registry;

pub mod appcompat_flags;
pub mod bam;
pub mod comdlg32;
pub mod featureusage;
pub mod muicache;
pub mod pca;
pub mod recentdocs;
pub mod runmru;
pub mod sevenzip;
pub mod shimcache;
pub mod startup;
pub mod typedpaths;
pub mod userassist;
pub mod winrar;
pub mod util;

pub struct SourceContext {
    pub user_sid: Option<String>,
}

impl SourceContext {
    pub fn new() -> Self {
        let user_sid = registry::current_user_sid_string().ok();
        SourceContext { user_sid }
    }
}

pub trait SourceScanner {
    fn kind(&self) -> SourceKind;
    fn scan(&self, ctx: &SourceContext) -> Vec<Record>;
}

struct FuncScanner {
    kind: SourceKind,
    func: fn(&SourceContext) -> Vec<Record>,
}

impl SourceScanner for FuncScanner {
    fn kind(&self) -> SourceKind {
        self.kind
    }

    fn scan(&self, ctx: &SourceContext) -> Vec<Record> {
        (self.func)(ctx)
    }
}

fn scanners() -> Vec<FuncScanner> {
    vec![
        FuncScanner {
            kind: SourceKind::RunMRU,
            func: runmru::scan,
        },
        FuncScanner {
            kind: SourceKind::ComDlg32,
            func: comdlg32::scan,
        },
        FuncScanner {
            kind: SourceKind::RecentDocs,
            func: recentdocs::scan,
        },
        FuncScanner {
            kind: SourceKind::TypedPaths,
            func: typedpaths::scan,
        },
        FuncScanner {
            kind: SourceKind::UserAssist,
            func: userassist::scan,
        },
        FuncScanner {
            kind: SourceKind::MUICache,
            func: muicache::scan,
        },
        FuncScanner {
            kind: SourceKind::AppCompatFlags,
            func: appcompat_flags::scan,
        },
        FuncScanner {
            kind: SourceKind::Startup,
            func: startup::scan,
        },
        FuncScanner {
            kind: SourceKind::FeatureUsage,
            func: featureusage::scan,
        },
        FuncScanner {
            kind: SourceKind::PCA,
            func: pca::scan,
        },
        FuncScanner {
            kind: SourceKind::BAM,
            func: bam::scan,
        },
        FuncScanner {
            kind: SourceKind::ShimCache,
            func: shimcache::scan,
        },
        FuncScanner {
            kind: SourceKind::WinRAR,
            func: winrar::scan,
        },
        FuncScanner {
            kind: SourceKind::SevenZip,
            func: sevenzip::scan,
        },
    ]
}

pub fn scan_selected(selected: &HashSet<SourceKind>) -> Vec<Record> {
    let ctx = SourceContext::new();
    let mut all: Vec<Record> = Vec::new();
    for scanner in scanners() {
        if selected.contains(&scanner.kind()) {
            let result = std::panic::catch_unwind(|| scanner.scan(&ctx));
            if let Ok(records) = result {
                all.extend(records);
            }
        }
    }
    dedup_records(all)
}
