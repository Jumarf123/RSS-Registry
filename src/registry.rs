use anyhow::{Context, Result, anyhow};
use std::ffi::c_void;
use std::io;

use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, RegType};
use winreg::{HKEY, RegKey};

use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::core::PWSTR;

pub fn open_hkcu(path: &str) -> Option<RegKey> {
    open_key(HKEY_CURRENT_USER, path)
}

pub fn open_hklm(path: &str) -> Option<RegKey> {
    open_key(HKEY_LOCAL_MACHINE, path)
}

pub fn open_key(root: HKEY, path: &str) -> Option<RegKey> {
    RegKey::predef(root)
        .open_subkey_with_flags(path, KEY_READ)
        .ok()
}

pub fn enum_string_values(key: &RegKey) -> Vec<String> {
    let mut out = Vec::new();
    for item in key.enum_values().flatten() {
        let (name, value) = item;
        match value.vtype {
            RegType::REG_SZ | RegType::REG_EXPAND_SZ => {
                if let Ok(mut s) = String::from_utf8(value.bytes.clone()) {
                    if let Some(pos) = s.find('\0') {
                        s.truncate(pos);
                    }
                    if !s.trim().is_empty() {
                        out.push(s);
                    }
                } else if let Ok(s) = key.get_value::<String, _>(&name) {
                    out.push(s);
                }
            }
            _ => {}
        }
    }
    out
}

pub fn enum_binary_values(key: &RegKey) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    for item in key.enum_values().flatten() {
        let (name, value) = item;
        if value.vtype == RegType::REG_BINARY {
            out.push((name, value.bytes));
        }
    }
    out
}

pub fn read_binary_value(key: &RegKey, name: &str) -> Option<Vec<u8>> {
    key.get_raw_value(name).ok().map(|v| v.bytes)
}

pub fn decode_reg_string(bytes: &[u8]) -> Option<String> {
    if bytes.len() >= 2 && bytes.len() % 2 == 0 {
        let words: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|c| *c != 0)
            .collect();
        if !words.is_empty() {
            return Some(String::from_utf16_lossy(&words));
        }
    }
    String::from_utf8(bytes.to_vec()).ok()
}

pub fn subkeys(key: &RegKey) -> io::Result<Vec<RegKey>> {
    let mut res = Vec::new();
    let iter = key.enum_keys();
    for name in iter {
        let name = match name {
            Ok(n) => n,
            Err(_) => continue,
        };
        if let Ok(sub) = key.open_subkey_with_flags(&name, KEY_READ) {
            res.push(sub);
        }
    }
    Ok(res)
}

pub fn last_write_time(key: &RegKey) -> Option<chrono::DateTime<chrono::Local>> {
    key.query_info().ok().and_then(|info| {
        let ft = info.last_write_time;
        let raw = ((ft.dwHighDateTime as u64) << 32) | ft.dwLowDateTime as u64;
        crate::time::filetime_to_datetime_local(raw)
    })
}

pub fn current_user_sid_string() -> Result<String> {
    unsafe {
        let mut token = Default::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)
            .context("OpenProcessToken failed")?;

        let mut len: u32 = 0;
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut len);
        if len == 0 {
            return Err(anyhow!("GetTokenInformation returned zero length"));
        }
        let mut buffer = vec![0u8; len as usize];
        GetTokenInformation(
            token,
            TokenUser,
            Some(buffer.as_mut_ptr() as *mut c_void),
            len,
            &mut len,
        )
        .context("GetTokenInformation data failed")?;
        let token_user = &*(buffer.as_ptr() as *const TOKEN_USER);
        let sid = token_user.User.Sid;
        let mut sid_str: PWSTR = PWSTR::null();
        ConvertSidToStringSidW(sid, &mut sid_str).context("ConvertSidToStringSidW failed")?;
        let sid_string = sid_str
            .to_string()
            .map_err(|e| anyhow!("SID utf16 decode failed: {e}"))?;
        let _ = LocalFree(HLOCAL(sid_str.0 as *mut c_void));
        Ok(sid_string)
    }
}
