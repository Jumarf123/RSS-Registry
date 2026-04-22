use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashSet;
use std::env;

#[cfg(windows)]
use std::ffi::c_void;
#[cfg(windows)]
use windows::Win32::Foundation::HANDLE;
#[cfg(windows)]
use windows::Win32::Storage::FileSystem::QueryDosDeviceW;
#[cfg(windows)]
use windows::Win32::System::Com::CoTaskMemFree;
#[cfg(windows)]
use windows::Win32::UI::Shell::{KF_FLAG_DEFAULT, SHGetKnownFolderPath};
#[cfg(windows)]
use windows::core::{GUID, PCWSTR};

const ALLOWED_EXT: [&str; 8] = [
    ".exe", ".dll", ".jar", ".rar", ".zip", ".bat", ".cmd", ".ps1",
];

static QUOTED_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r#""([^"]+)""#).unwrap());
static DRIVE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)([A-Z]:\\[^"\r\n]*?\.(exe|dll|jar|rar|zip|bat|cmd|ps1))"#).unwrap()
});
static UNC_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(\\\\[^\s\\]+\\[^\s\\]+\\[^"\r\n]*?\.(exe|dll|jar|rar|zip|bat|cmd|ps1))"#)
        .unwrap()
});
static NT_DEVICE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(\\Device\\[^"\r\n]*?\.(exe|dll|jar|rar|zip|bat|cmd|ps1))"#).unwrap()
});
static KNOWN_FOLDER_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)((?:::)?\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}\\[^"\r\n]*?\.(exe|dll|jar|rar|zip|bat|cmd|ps1))"#,
    )
    .unwrap()
});
static KNOWN_FOLDER_PREFIX_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)^(?:::)?\{([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\}\\?(.*)$"#,
    )
    .unwrap()
});
static ENV_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"%([^%]+)%").unwrap());

#[cfg(windows)]
static DOS_DEVICE_MAPPINGS: Lazy<Vec<(String, String)>> = Lazy::new(|| {
    let mut mappings = Vec::new();
    for letter in b'A'..=b'Z' {
        let drive = format!("{}:", letter as char);
        if let Some(target) = query_dos_device(&drive) {
            mappings.push((target, drive));
        }
    }
    mappings.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
    mappings
});

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
    for cap in NT_DEVICE_RE.captures_iter(cleaned) {
        let val = cap.get(1).map(|m| m.as_str()).unwrap_or_default();
        if let Some(p) = normalize_path_candidate(val) {
            candidates.insert(p);
        }
    }
    for cap in KNOWN_FOLDER_RE.captures_iter(cleaned) {
        let val = cap.get(1).map(|m| m.as_str()).unwrap_or_default();
        if let Some(p) = normalize_path_candidate(val) {
            candidates.insert(p);
        }
    }
    for val in token_candidates(cleaned) {
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

fn token_candidates(s: &str) -> impl Iterator<Item = &str> {
    s.split(|c: char| {
        c.is_whitespace()
            || matches!(
                c,
                '"' | '\'' | '`' | ',' | ';' | '(' | ')' | '[' | ']' | '\r' | '\n' | '\t'
            )
    })
    .filter(|part| !part.is_empty())
}

fn is_wide_graphic(w: u16) -> bool {
    char::from_u32(w as u32)
        .map(|c| !c.is_control())
        .unwrap_or(false)
}

pub fn normalize_path_candidate(raw: &str) -> Option<String> {
    let s = normalize_path(raw);
    if !has_allowed_extension(&s) {
        return None;
    }
    if !has_path_location(&s) && !looks_like_bare_file_name(&s) {
        return None;
    }
    Some(s)
}

pub fn normalize_path(raw: &str) -> String {
    let mut s = trim_outer_noise(raw);
    if s.is_empty() {
        return s;
    }

    s = expand_env_vars(&s);
    s = s.replace('/', "\\");
    s = strip_nt_prefixes(&s);

    if let Some(resolved) = resolve_known_folder_prefix(&s) {
        s = resolved;
    }
    if let Some(resolved) = resolve_system_root_prefix(&s) {
        s = resolved;
    }
    if let Some(resolved) = resolve_nt_device_path(&s) {
        s = resolved;
    }

    s = strip_leading_noise_to_path(&s);
    if let Some(trimmed) = trim_to_allowed_extension(&s) {
        s = trimmed;
    }
    trim_outer_noise(&s)
}

pub fn has_allowed_extension(p: &str) -> bool {
    let lower = p.to_ascii_lowercase();
    ALLOWED_EXT.iter().any(|ext| lower.ends_with(ext))
}

pub fn has_path_location(p: &str) -> bool {
    looks_like_path(p)
}

fn looks_like_path(p: &str) -> bool {
    is_drive_path(p) || p.starts_with(r"\\") || p.starts_with(r"\Device\")
}

fn looks_like_bare_file_name(p: &str) -> bool {
    !p.is_empty()
        && !p.contains('\\')
        && !p.contains('/')
        && !p.contains(':')
        && p.chars().any(|c| c == '.')
        && p.chars().all(|c| {
            !c.is_control() && !matches!(c, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*')
        })
}

fn expand_env_vars(s: &str) -> String {
    ENV_RE
        .replace_all(s, |caps: &regex::Captures| {
            let var = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
            env::var(var).unwrap_or_else(|_| caps[0].to_string())
        })
        .into_owned()
}

fn trim_outer_noise(s: &str) -> String {
    s.trim_matches(char::from(0))
        .trim()
        .trim_matches(|c| matches!(c, '"' | '\'' | '`'))
        .trim()
        .to_string()
}

fn strip_nt_prefixes(s: &str) -> String {
    if let Some(stripped) = s.strip_prefix(r"\\??\\UNC\") {
        return format!(r"\\{}", stripped);
    }
    if let Some(stripped) = s.strip_prefix(r"\??\UNC\") {
        return format!(r"\\{}", stripped);
    }
    if let Some(stripped) = s.strip_prefix(r"\\?\UNC\") {
        return format!(r"\\{}", stripped);
    }
    if let Some(stripped) = s.strip_prefix(r"\\??\\") {
        return stripped.to_string();
    }
    if let Some(stripped) = s.strip_prefix(r"\??\") {
        return stripped.to_string();
    }
    if let Some(stripped) = s.strip_prefix(r"\\?\") {
        return stripped.to_string();
    }
    if let Some(stripped) = s.strip_prefix(r"UNC\") {
        return format!(r"\\{}", stripped);
    }
    s.to_string()
}

fn resolve_known_folder_prefix(s: &str) -> Option<String> {
    let caps = KNOWN_FOLDER_PREFIX_RE.captures(s)?;
    let guid_text = caps.get(1)?.as_str();
    let rest = caps.get(2).map(|m| m.as_str()).unwrap_or_default();
    let base = known_folder_path(guid_text).or_else(|| known_folder_fallback(guid_text))?;
    let mut resolved = base.trim_end_matches('\\').to_string();
    let rest = rest.trim_start_matches('\\');
    if !rest.is_empty() {
        resolved.push('\\');
        resolved.push_str(rest);
    }
    Some(resolved)
}

fn known_folder_fallback(guid_text: &str) -> Option<String> {
    match guid_text.to_ascii_lowercase().as_str() {
        "1ac14e77-02e7-4e5d-b744-2eb1ae5198b7" => {
            env_path("windir", r"C:\Windows").map(|base| join_path(&base, "System32"))
        }
        "d65231b0-b2f1-4857-a4ce-a8e7c6ea7d27" => {
            env_path("windir", r"C:\Windows").map(|base| join_path(&base, "SysWOW64"))
        }
        "6d809377-6af0-444b-8957-a3773f02200e" | "905e63b6-c1bf-494e-b29c-65b732d3d21a" => {
            env_path("ProgramFiles", r"C:\Program Files")
        }
        "7c5a40ef-a0fb-4bfc-874a-c0f2e0b9fa8e" => {
            env_path("ProgramFiles(x86)", r"C:\Program Files (x86)")
        }
        "f38bf404-1d43-42f2-9305-67de0b28fc23" => env_path("windir", r"C:\Windows"),
        "62ab5d82-fdc1-4dc3-a9dd-070d1d495d97" => env_path("ProgramData", r"C:\ProgramData"),
        "0762d272-c50a-4bb0-a382-697dcd729b80" => {
            env_path("SystemDrive", "C:").map(|base| join_path(&base, "Users"))
        }
        "5cd7aee2-2219-4a67-b85d-6c9ce15660cb" => env::var("LOCALAPPDATA")
            .ok()
            .map(|base| join_path(&base, "Programs")),
        _ => None,
    }
}

fn env_path(name: &str, fallback: &str) -> Option<String> {
    Some(env::var(name).unwrap_or_else(|_| fallback.to_string()))
}

fn join_path(base: &str, rest: &str) -> String {
    format!(
        "{}\\{}",
        base.trim_end_matches('\\'),
        rest.trim_start_matches('\\')
    )
}

#[cfg(windows)]
fn known_folder_path(guid_text: &str) -> Option<String> {
    let guid = GUID::from(guid_text);
    unsafe {
        let path = SHGetKnownFolderPath(&guid, KF_FLAG_DEFAULT, HANDLE(0)).ok()?;
        let ptr = path.0;
        let result = path.to_string().ok();
        CoTaskMemFree(Some(ptr as *const c_void));
        result
    }
}

#[cfg(not(windows))]
fn known_folder_path(_guid_text: &str) -> Option<String> {
    None
}

fn resolve_system_root_prefix(s: &str) -> Option<String> {
    let lower = s.to_ascii_lowercase();
    let rest = lower
        .strip_prefix(r"\systemroot\")
        .map(|_| &s[r"\SystemRoot\".len()..])
        .or_else(|| {
            lower
                .strip_prefix(r"systemroot\")
                .map(|_| &s["SystemRoot\\".len()..])
        })?;
    env_path("SystemRoot", r"C:\Windows").map(|base| join_path(&base, rest))
}

#[cfg(windows)]
fn resolve_nt_device_path(s: &str) -> Option<String> {
    for (device, drive) in DOS_DEVICE_MAPPINGS.iter() {
        if starts_with_device_prefix(s, device) {
            let rest = &s[device.len()..];
            return Some(format!("{drive}{rest}"));
        }
    }
    None
}

#[cfg(not(windows))]
fn resolve_nt_device_path(_s: &str) -> Option<String> {
    None
}

fn starts_with_device_prefix(path: &str, device: &str) -> bool {
    if path.len() < device.len() {
        return false;
    }
    let Some((head, rest)) = path.get(..device.len()).zip(path.get(device.len()..)) else {
        return false;
    };
    head.eq_ignore_ascii_case(device) && (rest.is_empty() || rest.starts_with('\\'))
}

fn strip_leading_noise_to_path(s: &str) -> String {
    if is_drive_path(s) || s.starts_with(r"\\") || s.starts_with(r"\Device\") {
        return s.to_string();
    }
    if let Some(pos) = find_drive_path_start(s) {
        return s[pos..].to_string();
    }
    if let Some(pos) = s.find(r"\\") {
        return s[pos..].to_string();
    }
    s.to_string()
}

fn is_drive_path(s: &str) -> bool {
    let bytes = s.as_bytes();
    bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\'
}

fn find_drive_path_start(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    if bytes.len() < 3 {
        return None;
    }
    for i in 0..=(bytes.len() - 3) {
        if bytes[i].is_ascii_alphabetic() && bytes[i + 1] == b':' && bytes[i + 2] == b'\\' {
            return Some(i);
        }
    }
    None
}

fn trim_to_allowed_extension(s: &str) -> Option<String> {
    let lower = s.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    for (i, _) in lower.char_indices() {
        for ext in ALLOWED_EXT {
            if bytes[i..].starts_with(ext.as_bytes()) {
                let end = i + ext.len();
                if s.is_char_boundary(end) && is_extension_boundary(s, end) {
                    return Some(s[..end].to_string());
                }
            }
        }
    }
    None
}

fn is_extension_boundary(s: &str, end: usize) -> bool {
    if end == s.len() {
        return true;
    }
    s[end..]
        .chars()
        .next()
        .map(|c| c.is_whitespace() || matches!(c, '"' | '\'' | '`' | ',' | ';' | ')' | ']'))
        .unwrap_or(true)
}

#[cfg(windows)]
fn query_dos_device(device_name: &str) -> Option<String> {
    let name: Vec<u16> = device_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut buffer = vec![0u16; 1024];
    let len = unsafe { QueryDosDeviceW(PCWSTR(name.as_ptr()), Some(&mut buffer)) };
    if len == 0 {
        return None;
    }
    let end = buffer.iter().position(|c| *c == 0).unwrap_or(len as usize);
    if end == 0 {
        return None;
    }
    Some(String::from_utf16_lossy(&buffer[..end]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_garbage_before_drive_paths() {
        assert_eq!(
            normalize_path_candidate(r"ZC:\Users\jumarf\Desktop\moment\legit\DW20.EXE").unwrap(),
            r"C:\Users\jumarf\Desktop\moment\legit\DW20.EXE"
        );
        assert_eq!(
            normalize_path_candidate(r"fC:\Program Files\AMD\CNext\CNext\PresentMon-x64.exe")
                .unwrap(),
            r"C:\Program Files\AMD\CNext\CNext\PresentMon-x64.exe"
        );
        assert_eq!(
            normalize_path_candidate(r">C:\Windows\system32\svchost.exe").unwrap(),
            r"C:\Windows\system32\svchost.exe"
        );
        assert_eq!(
            normalize_path_candidate(r"`C:\Users\jumarf\AppData\Local\Discord\Update.exe").unwrap(),
            r"C:\Users\jumarf\AppData\Local\Discord\Update.exe"
        );
    }

    #[test]
    fn extracts_uppercase_and_known_folder_paths() {
        let paths = extract_paths(
            r"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe Отсутствует дата Yes ZC:\Users\jumarf\Desktop\moment\legit\DW20.EXE",
        );
        assert!(
            paths
                .iter()
                .any(|p| p.eq_ignore_ascii_case(r"C:\Users\jumarf\Desktop\moment\legit\DW20.EXE"))
        );
        assert!(paths.iter().any(|p| {
            p.to_ascii_lowercase()
                .ends_with(r"\system32\windowspowershell\v1.0\powershell.exe")
        }));
    }

    #[test]
    fn keeps_bare_file_names_without_paths() {
        assert_eq!(normalize_path_candidate("123.rar").unwrap(), "123.rar");
        assert_eq!(
            normalize_path_candidate("example_file.exe Отсутствует дата Yes").unwrap(),
            "example_file.exe"
        );

        let text_paths = extract_paths("123.rar 456.zip C:\\Tools\\tool.exe");
        assert!(text_paths.iter().any(|p| p == "123.rar"));
        assert!(text_paths.iter().any(|p| p == "456.zip"));
        assert!(
            text_paths
                .iter()
                .any(|p| p.eq_ignore_ascii_case(r"C:\Tools\tool.exe"))
        );

        let paths = extract_paths_from_bytes(b"123.rar\0run_me.cmd\0not_a_match.txt\0");
        assert!(paths.iter().any(|p| p == "123.rar"));
        assert!(paths.iter().any(|p| p == "run_me.cmd"));
        assert!(!paths.iter().any(|p| p == "not_a_match.txt"));
    }

    #[test]
    fn resolves_known_folder_guid_prefixes() {
        let system = normalize_path_candidate(
            r"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe Отсутствует дата Yes",
        )
        .unwrap();
        assert!(
            system
                .to_ascii_lowercase()
                .ends_with(r"\system32\windowspowershell\v1.0\powershell.exe")
        );

        let program_files = normalize_path_candidate(
            r"{6D809377-6AF0-444B-8957-A3773F02200E}\Oracle\VirtualBox\VirtualBoxVM.exe",
        )
        .unwrap();
        assert!(!program_files.contains('{'));
        assert!(
            program_files
                .to_ascii_lowercase()
                .ends_with(r"\oracle\virtualbox\virtualboxvm.exe")
        );
    }

    #[cfg(windows)]
    #[test]
    fn maps_current_drive_device_path() {
        let system_root = env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
        let drive = &system_root[..2];
        let device = query_dos_device(drive).expect("system drive must have a DOS device mapping");
        let rest = &system_root[2..];
        let raw = format!(r"{device}{rest}\system32\svchost.exe");
        let expected = format!(r"{drive}{rest}\system32\svchost.exe");
        let normalized = normalize_path_candidate(&raw).unwrap();
        assert!(normalized.eq_ignore_ascii_case(&expected));
    }

    #[cfg(windows)]
    #[test]
    fn builds_mappings_for_all_available_drive_letters() {
        let mapped: HashSet<String> = DOS_DEVICE_MAPPINGS
            .iter()
            .map(|(_, drive)| drive.to_ascii_uppercase())
            .collect();

        for letter in b'A'..=b'Z' {
            let drive = format!("{}:", letter as char);
            if query_dos_device(&drive).is_some() {
                assert!(mapped.contains(&drive));
            }
        }
    }
}
