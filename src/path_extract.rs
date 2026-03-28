use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashSet;
use std::env;

const ALLOWED_EXT: [&str; 8] = [".exe", ".dll", ".jar", ".rar", ".zip", ".bat", ".cmd", ".ps1"];

static QUOTED_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r#""([^"]+)""#).unwrap());
static DRIVE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"([A-Za-z]:\\[^"\r\n]*?\.(exe|dll|jar|rar|zip|bat|cmd|ps1))"#).unwrap());
static UNC_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(\\\\[^\s\\]+\\[^\s\\]+\\[^"\r\n]*?\.(exe|dll|jar|rar|zip|bat|cmd|ps1))"#).unwrap());
static ENV_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"%([^%]+)%").unwrap());

pub fn extract_paths(input: &str) -> Vec<String> {
    let cleaned = input.trim_matches(char::from(0)).trim();
    let mut candidates: HashSet<String> = HashSet::new();

    for cap in QUOTED_RE.captures_iter(cleaned) {
        let val = cap.get(1).map(|m| m.as_str()).unwrap_or_default();
        if let Some(p) = normalize_path_candidate(val) {
            candidates.insert(p);
        }
    }
    for cap in DRIVE_RE.captures_iter(cleaned) {
        let val = cap.get(1).map(|m| m.as_str()).unwrap_or_default();
        if let Some(p) = normalize_path_candidate(val) {
            candidates.insert(p);
        }
    }
    for cap in UNC_RE.captures_iter(cleaned) {
        let val = cap.get(1).map(|m| m.as_str()).unwrap_or_default();
        if let Some(p) = normalize_path_candidate(val) {
            candidates.insert(p);
        }
    }

    candidates.into_iter().collect()
}

pub fn extract_paths_from_bytes(bytes: &[u8]) -> Vec<String> {
    let mut seen: HashSet<String> = HashSet::new();

    collect_ascii_segments(bytes, &mut seen);
    collect_wide_segments(bytes, &mut seen);

    seen.into_iter().collect()
}

// Extract just filenames (no path requirement) with allowed extension from mixed byte blobs.
pub fn extract_allowed_names(bytes: &[u8]) -> Vec<String> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut seg = Vec::new();
    for &b in bytes {
        if b == 0 || b == b'\r' || b == b'\n' || !b.is_ascii_graphic() && b != b' ' && b != b'\\' {
            if !seg.is_empty() {
                let s = String::from_utf8_lossy(&seg).to_string();
                if has_allowed_extension(&s) {
                    seen.insert(s);
                }
                seg.clear();
            }
        } else {
            seg.push(b);
        }
    }
    if !seg.is_empty() {
        let s = String::from_utf8_lossy(&seg).to_string();
        if has_allowed_extension(&s) {
            seen.insert(s);
        }
    }

    let mut wseg: Vec<u16> = Vec::new();
    for chunk in bytes.chunks_exact(2) {
        let w = u16::from_le_bytes([chunk[0], chunk[1]]);
        if w == 0 || !is_wide_graphic(w) {
            if !wseg.is_empty() {
                let s = String::from_utf16_lossy(&wseg);
                if has_allowed_extension(&s) {
                    seen.insert(s);
                }
                wseg.clear();
            }
        } else {
            wseg.push(w);
        }
    }
    if !wseg.is_empty() {
        let s = String::from_utf16_lossy(&wseg);
        if has_allowed_extension(&s) {
            seen.insert(s);
        }
    }

    seen.into_iter().collect()
}

fn collect_ascii_segments(bytes: &[u8], seen: &mut HashSet<String>) {
    let mut buf = Vec::new();
    for &b in bytes {
        if b == 0 || b == b'\r' || b == b'\n' || !b.is_ascii_graphic() && b != b' ' && b != b'\\' {
            if !buf.is_empty() {
                if let Some(p) = validate_ascii_segment(&buf) {
                    seen.insert(p);
                }
                buf.clear();
            }
        } else {
            buf.push(b);
        }
    }
    if !buf.is_empty() {
        if let Some(p) = validate_ascii_segment(&buf) {
            seen.insert(p);
        }
    }
}

fn collect_wide_segments(bytes: &[u8], seen: &mut HashSet<String>) {
    let mut seg: Vec<u16> = Vec::new();
    for chunk in bytes.chunks_exact(2) {
        let w = u16::from_le_bytes([chunk[0], chunk[1]]);
        if w == 0 || !is_wide_graphic(w) {
            if !seg.is_empty() {
                if let Some(p) = validate_wide_segment(&seg) {
                    seen.insert(p);
                }
                seg.clear();
            }
        } else {
            seg.push(w);
        }
    }
    if !seg.is_empty() {
        if let Some(p) = validate_wide_segment(&seg) {
            seen.insert(p);
        }
    }
}

fn validate_ascii_segment(seg: &[u8]) -> Option<String> {
    let s = String::from_utf8_lossy(seg).to_string();
    normalize_path_candidate(&s)
}

fn validate_wide_segment(seg: &[u16]) -> Option<String> {
    let s = String::from_utf16_lossy(seg);
    normalize_path_candidate(&s)
}

fn is_wide_graphic(w: u16) -> bool {
    let c = w as u32;
    (0x20..=0x7E).contains(&c) || c == b'\\' as u32 || c == b':' as u32 || c == b'_' as u32
}

pub fn normalize_path_candidate(raw: &str) -> Option<String> {
    let mut s = raw.trim_matches(char::from(0)).trim().to_string();
    if !has_allowed_extension(&s) {
        return None;
    }
    s = expand_env_vars(&s);
    if let Some(stripped) = s.strip_prefix(r"\\??\\") {
        s = stripped.to_string();
    } else if let Some(stripped) = s.strip_prefix(r"\??\") {
        s = stripped.to_string();
    }
    if let Some(stripped) = s.strip_prefix(r"\\?\") {
        s = stripped.to_string();
    }
    if let Some(stripped) = s.strip_prefix(r"UNC\") {
        s = format!(r"\\{}", stripped);
    }
    s = s.replace('/', "\\");

    if !looks_like_path(&s) {
        if let Some(pos) = s.find(":\\") {
            if pos >= 1 {
                let drive = s.as_bytes()[pos - 1] as char;
                if drive.is_ascii_alphabetic() {
                    s = s[(pos - 1)..].to_string();
                }
            }
        } else if let Some(pos) = s.find(r"\\") {
            s = s[pos..].to_string();
        } else {
            return None;
        }
    }
    Some(s)
}

pub fn has_allowed_extension(p: &str) -> bool {
    let lower = p.to_lowercase();
    ALLOWED_EXT.iter().any(|ext| lower.ends_with(ext))
}

fn looks_like_path(p: &str) -> bool {
    if p.starts_with(r"\\") || p.chars().nth(1) == Some(':') {
        return true;
    }
    if let Some(pos) = p.find(":\\") {
        return pos >= 1;
    }
    false
}

fn expand_env_vars(s: &str) -> String {
    ENV_RE
        .replace_all(s, |caps: &regex::Captures| {
            let var = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
            env::var(var).unwrap_or_else(|_| caps[0].to_string())
        })
        .into_owned()
}
