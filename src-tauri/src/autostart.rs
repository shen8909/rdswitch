//! Windows 開機排程工作（最高權限）的安全檢查：純函式，不呼叫系統 API，方便測試。
//!
//! - 執行身分：必須是明確的 `DOMAIN\user`（不可為空，不可退回環境變數）。
//! - 執行檔位置：必須在一般使用者無法寫入的系統安裝資料夾（Program Files）之內，
//!   否則任何以該使用者身分執行的程式都能替換執行檔，在下次登入時取得最高權限。

use std::path::{Component, Path, PathBuf};

/// 帳號名稱長度上限（DOMAIN 最長 255 + `\` + 使用者名稱最長 256）。
const MAX_ACCOUNT_LEN: usize = 512;

/// SAM 帳號名稱不允許的字元（另外拒絕所有控制字元）。
const FORBIDDEN_IN_USER: &[char] = &[
    '"', '/', '\\', '[', ']', ':', ';', '|', '=', ',', '+', '*', '?', '<', '>',
];

/// 驗證 `GetUserNameExW(NameSamCompatible)` 的結果：必須是 `DOMAIN\user`，
/// 兩段都不可為空、不含控制字元、引號或其他不允許的字元。
pub fn validate_account(s: &str) -> Option<&str> {
    if s.is_empty() || s.chars().count() > MAX_ACCOUNT_LEN || s.chars().any(char::is_control) {
        return None;
    }
    let (domain, user) = s.split_once('\\')?;
    let bad = |part: &str| {
        part.trim().is_empty() || part != part.trim() || part.contains(FORBIDDEN_IN_USER)
    };
    if bad(domain) || bad(user) {
        return None;
    }
    Some(s)
}

/// 比較用的路徑元件：Windows 路徑不分大小寫。
fn key(c: Component) -> String {
    c.as_os_str().to_string_lossy().to_lowercase()
}

/// `path` 是否位於任一 `roots` 之內（必須是更深的子路徑，不能等於 root 本身）。
/// 兩邊都應該是 `canonicalize` 過的實際路徑，元件逐一比對，避免 `C:\Program Files Evil` 這類字首誤判。
pub fn is_within(path: &Path, roots: &[PathBuf]) -> bool {
    let p: Vec<String> = path.components().map(key).collect();
    roots.iter().any(|root| {
        let r: Vec<String> = root.components().map(key).collect();
        !r.is_empty() && p.len() > r.len() && p[..r.len()] == r[..]
    })
}

/// 把 `canonicalize` 產生的 `\\?\C:\...` 轉回 `C:\...` 給 schtasks 使用。
/// 只接受本機磁碟路徑；UNC 或其他形式回傳 None（排程不應指向網路位置）。
pub fn task_command_path(canonical: &Path) -> Option<String> {
    let s = canonical.to_str()?;
    let rest = s.strip_prefix(r"\\?\")?;
    let b = rest.as_bytes();
    let is_disk = b.len() > 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\';
    (is_disk && !rest.contains('"')).then(|| rest.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_domain_and_user() {
        for ok in [
            r"DESKTOP-AB12\alice",
            r"CORP\bob.smith",
            r"WORKGROUP\使用者",
            r"NT AUTHORITY\a b",
        ] {
            assert_eq!(validate_account(ok), Some(ok), "{ok}");
        }
    }

    #[test]
    fn rejects_empty_or_malformed_accounts() {
        let long = format!(r"D\{}", "a".repeat(600));
        for bad in [
            "",
            "alice",    // 沒有網域
            r"\alice",  // 網域空白
            r"DOMAIN\", // 使用者空白
            r" \alice",
            r"D\ alice", // 前後空白
            r"D\a\b",    // 多一段
            "D\\a\"b",   // 引號會破壞 schtasks 參數
            "D\\a\nb",
            "D\\a\0",
            r"D\a/b",
            r"D\a*",
            long.as_str(),
        ] {
            assert_eq!(validate_account(bad), None, "{bad:?}");
        }
    }

    // 以下兩個測試使用 Windows 路徑語法，只在 Windows 上有意義
    #[cfg(windows)]
    #[test]
    fn within_compares_whole_components_case_insensitively() {
        let roots = [
            PathBuf::from(r"\\?\C:\Program Files"),
            PathBuf::from(r"\\?\C:\Program Files (x86)"),
        ];
        let yes = [
            r"\\?\C:\Program Files\rdswitch\rdswitch.exe",
            r"\\?\c:\program files\rdswitch\rdswitch.exe",
            r"\\?\C:\Program Files (x86)\rdswitch\rdswitch.exe",
        ];
        for p in yes {
            assert!(is_within(Path::new(p), &roots), "{p}");
        }
        let no = [
            r"\\?\C:\Program Files Evil\rdswitch.exe",
            r"\\?\C:\Program Files",
            r"\\?\C:\Users\alice\AppData\Local\rdswitch\rdswitch.exe",
            r"\\?\D:\Program Files\rdswitch\rdswitch.exe",
            r"C:\Program Files\rdswitch\rdswitch.exe", // 未 canonicalize 的形式不相符（fail closed）
        ];
        for p in no {
            assert!(!is_within(Path::new(p), &roots), "{p}");
        }
        assert!(!is_within(Path::new(r"\\?\C:\x"), &[]));
    }

    #[cfg(windows)]
    #[test]
    fn task_command_path_only_accepts_local_disk_paths() {
        assert_eq!(
            task_command_path(Path::new(r"\\?\C:\Program Files\rdswitch\rdswitch.exe")).as_deref(),
            Some(r"C:\Program Files\rdswitch\rdswitch.exe")
        );
        for bad in [
            r"\\?\UNC\server\share\rdswitch.exe",
            r"C:\Program Files\rdswitch.exe",
            r"\\?\C:",
            r#"\\?\C:\a"b.exe"#,
        ] {
            assert_eq!(task_command_path(Path::new(bad)), None, "{bad}");
        }
    }

    /// 開機排程只接受 Program Files 內的安裝位置，因此 Windows 安裝檔必須是 perMachine；
    /// 改回 currentUser（%LOCALAPPDATA%）會讓「開機自動啟動」永遠被拒絕。
    #[test]
    fn windows_installer_installs_per_machine() {
        let cfg: serde_json::Value =
            serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        assert_eq!(
            cfg["bundle"]["windows"]["nsis"]["installMode"],
            "perMachine"
        );
    }
}
