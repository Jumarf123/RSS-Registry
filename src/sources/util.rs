use chrono::{DateTime, Datelike, Local};

/// Scan arbitrary bytes for the most plausible FILETIME (little-endian 64-bit).
/// Returns the newest valid timestamp found.
pub fn find_best_filetime(bytes: &[u8]) -> Option<DateTime<Local>> {
    let mut best: Option<DateTime<Local>> = None;
    if bytes.len() < 8 {
        return None;
    }
    for i in 0..=bytes.len() - 8 {
        let candidate = u64::from_le_bytes(bytes[i..i + 8].try_into().unwrap());
        if let Some(dt) = crate::time::filetime_to_datetime_local(candidate) {
            // Filter out bogus/ancient or far future times.
            if dt.year() < 2000 || dt.year() > Local::now().year() + 2 {
                continue;
            }
            if best.map(|b| dt > b).unwrap_or(true) {
                best = Some(dt);
            }
        }
    }
    best
}
