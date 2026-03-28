use chrono::{DateTime, Local};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// Seconds between Windows FILETIME epoch (1601-01-01) and Unix epoch.
const WINDOWS_TO_UNIX_EPOCH_DIFF: u64 = 11_644_473_600;

pub fn filetime_to_datetime_local(filetime: u64) -> Option<DateTime<Local>> {
    // FILETIME stores 100-ns ticks since 1601-01-01.
    let ft_duration = Duration::from_nanos(filetime.saturating_mul(100));
    let unix_duration = ft_duration.checked_sub(Duration::from_secs(WINDOWS_TO_UNIX_EPOCH_DIFF))?;
    let system_time = UNIX_EPOCH.checked_add(unix_duration)?;
    Some(DateTime::<Local>::from(system_time))
}

pub fn systemtime_to_local(dt: SystemTime) -> Option<DateTime<Local>> {
    Some(DateTime::<Local>::from(dt))
}

pub fn collect_file_times(path: &str) -> Option<crate::model::FileTimes> {
    let meta = std::fs::metadata(path).ok()?;
    let created = meta.created().ok().and_then(systemtime_to_local);
    let modified = meta.modified().ok().and_then(systemtime_to_local);
    let accessed = meta.accessed().ok().and_then(systemtime_to_local);
    Some(crate::model::FileTimes {
        created,
        modified,
        accessed,
    })
}

pub fn format_datetime(dt: &DateTime<Local>) -> String {
    dt.format("%Y-%m-%d %H:%M:%S").to_string()
}

pub fn format_file_times(ft: &crate::model::FileTimes) -> String {
    let mut parts = Vec::new();
    if let Some(c) = &ft.created {
        parts.push(format!("Created: {}", format_datetime(c)));
    }
    if let Some(m) = &ft.modified {
        parts.push(format!("Modified: {}", format_datetime(m)));
    }
    if let Some(a) = &ft.accessed {
        parts.push(format!("Accessed: {}", format_datetime(a)));
    }
    parts.join(" | ")
}
