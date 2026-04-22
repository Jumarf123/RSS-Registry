use std::collections::HashSet;

use rss_registry::model::{SourceKind, all_sources};
use rss_registry::sources::{self, SourceContext};
use rss_registry::time;
use std::time::Instant;

fn main() {
    let ctx = SourceContext::new();
    println!("Debug scan (per source):");
    for source in all_sources() {
        let mut selected = HashSet::new();
        selected.insert(source);
        let start = Instant::now();
        let data = run_single(source, &ctx);
        let dur = start.elapsed();
        println!(
            "{:>25}: {:>5} entries | {:>6.2?}",
            source.label(),
            data.len(),
            dur
        );
        for rec in data.iter().take(10) {
            println!(
                "    {} | {} | deleted={} | exec={}",
                rec.file_name,
                rec.path,
                rec.deleted,
                rec.executed_at
                    .map(|d| crate::time::format_datetime(&d))
                    .unwrap_or_else(|| "-".to_string())
            );
        }
    }

    // Combined deduped scan.
    let selected: HashSet<_> = all_sources().into_iter().collect();
    let combined = sources::scan_selected(&selected);
    println!("Combined deduped total: {}", combined.len());
}

fn run_single(kind: SourceKind, ctx: &SourceContext) -> Vec<rss_registry::model::Record> {
    match kind {
        SourceKind::WinRAR => sources::winrar::scan(ctx),
        SourceKind::SevenZip => sources::sevenzip::scan(ctx),
        SourceKind::ShimCache => sources::shimcache::scan(ctx),
        SourceKind::PCA => sources::pca::scan(ctx),
        SourceKind::FeatureUsage => sources::featureusage::scan(ctx),
        SourceKind::Startup => sources::startup::scan(ctx),
        SourceKind::BAM => sources::bam::scan(ctx),
        SourceKind::AppCompatFlags => sources::appcompat_flags::scan(ctx),
        SourceKind::MUICache => sources::muicache::scan(ctx),
        SourceKind::UserAssist => sources::userassist::scan(ctx),
        SourceKind::TypedPaths => sources::typedpaths::scan(ctx),
        SourceKind::RecentDocs => sources::recentdocs::scan(ctx),
        SourceKind::ComDlg32 => sources::comdlg32::scan(ctx),
        SourceKind::RunMRU => sources::runmru::scan(ctx),
    }
}
