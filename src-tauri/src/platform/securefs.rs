//! 平台相依的「不跟隨 symlink / junction」檔案操作（platform 層的一部分）。
//!
//! 用途：以系統管理員/root 身分把檔案寫進一般使用者可寫的資料夾（備份）時，
//! 防止使用者事先放好 symlink、junction 或同名檔案，把寫入導向系統檔案（M6）。
//!
//! - 資料夾：建立時 0700（Unix）；不得是 symlink/reparse point；Unix 須由目前的有效使用者擁有。
//!   `strict`（以提升權限執行時）另要求整條路徑都沒有 symlink/reparse point。
//! - 檔案：一律 create_new（不覆蓋）且不跟隨最後一段的 symlink；Unix 權限 0600。
//! - 讀取：不跟隨最後一段的 symlink，且必須是一般檔案（避免 FIFO 讓程式卡住）。

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::path::Path;

/// 資料夾通過檢查後的憑證。Windows 上持有不允許刪除/改名的資料夾 handle，
/// 在寫完檔案之前，資料夾（與其上層）無法被換成 junction。
pub struct SecureDir {
    _handle: File,
}

fn unsafe_path(path: &Path, reason: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("unsafe path {}: {reason}", path.display()),
    )
}

/// 最接近的「已存在」上層（含自己）；用於建立資料夾之前先檢查。
fn nearest_existing(dir: &Path) -> Option<&Path> {
    dir.ancestors()
        .find(|p| !p.as_os_str().is_empty() && fs::symlink_metadata(p).is_ok())
}

#[cfg(unix)]
mod imp {
    use super::*;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};

    /// 整條路徑沒有 symlink：解析後的實際路徑與原路徑相同。
    fn no_symlink_in(path: &Path) -> io::Result<()> {
        if fs::canonicalize(path)? != path {
            return Err(unsafe_path(path, "path contains a symlink"));
        }
        Ok(())
    }

    pub fn prepare_private_dir(dir: &Path, strict: bool) -> io::Result<SecureDir> {
        if strict {
            if !dir.is_absolute() {
                return Err(unsafe_path(dir, "not an absolute path"));
            }
            if let Some(p) = nearest_existing(dir) {
                no_symlink_in(p)?; // 先檢查再建立，避免在 symlink 指向的位置建立資料夾
            }
        }
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
        if strict {
            no_symlink_in(dir)?;
        }
        // O_NOFOLLOW：最後一段是 symlink 時開啟失敗（ELOOP）
        let handle = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
            .open(dir)
            .map_err(|e| unsafe_path(dir, &e.to_string()))?;
        let m = handle.metadata()?;
        // SAFETY: geteuid 不接受參數、不會失敗，也沒有副作用。
        let euid = unsafe { libc::geteuid() };
        if !m.is_dir() || m.uid() != euid {
            return Err(unsafe_path(
                dir,
                "not a directory owned by the current user",
            ));
        }
        if m.mode() & 0o077 != 0 {
            // 對已開啟的 handle 做 fchmod，不會被換成 symlink 影響
            handle.set_permissions(fs::Permissions::from_mode(0o700))?;
        }
        Ok(SecureDir { _handle: handle })
    }

    pub fn create_private_file(path: &Path) -> io::Result<File> {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
    }

    pub fn open_no_follow(path: &Path) -> io::Result<File> {
        // O_NONBLOCK：路徑若是 FIFO，開啟時不會卡住（之後檢查種類會拒絕）
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
    }

    pub fn is_link_or_reparse(_m: &fs::Metadata) -> bool {
        false // Unix 由 O_NOFOLLOW 處理；開得起來就不是 symlink
    }
}

#[cfg(windows)]
mod imp {
    use super::*;
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_SHARE_READ: u32 = 0x1;
    const FILE_SHARE_WRITE: u32 = 0x2;

    pub fn is_link_or_reparse(m: &fs::Metadata) -> bool {
        m.file_type().is_symlink() || m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }

    /// 路徑上每一個已存在的層級都不是 reparse point（symlink、junction、掛載點）。
    fn no_reparse_in(path: &Path) -> io::Result<()> {
        for p in path.ancestors().filter(|p| !p.as_os_str().is_empty()) {
            match fs::symlink_metadata(p) {
                Ok(m) if is_link_or_reparse(&m) => {
                    return Err(unsafe_path(p, "symlink or junction"));
                }
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    pub fn prepare_private_dir(dir: &Path, strict: bool) -> io::Result<SecureDir> {
        if strict {
            if !dir.is_absolute() {
                return Err(unsafe_path(dir, "not an absolute path"));
            }
            if let Some(p) = nearest_existing(dir) {
                no_reparse_in(p)?; // 先檢查再建立，避免在 junction 指向的位置建立資料夾
            }
        }
        fs::create_dir_all(dir)?;
        if strict {
            no_reparse_in(dir)?;
        }
        // 不給 FILE_SHARE_DELETE：持有期間資料夾與其上層都無法被改名或刪除（換成 junction）
        let handle = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(dir)?;
        let m = handle.metadata()?;
        if !m.is_dir() || m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(unsafe_path(dir, "not a plain directory"));
        }
        Ok(SecureDir { _handle: handle })
    }

    pub fn create_private_file(path: &Path) -> io::Result<File> {
        // 檔案權限沿用資料夾繼承的 ACL（%APPDATA% 下僅本人、SYSTEM、Administrators）
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
    }

    pub fn open_no_follow(path: &Path) -> io::Result<File> {
        OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
    }
}

/// 確保私有資料夾存在且安全；見模組說明。回傳值必須持有到檔案寫完為止。
pub fn prepare_private_dir(dir: &Path, strict: bool) -> io::Result<SecureDir> {
    imp::prepare_private_dir(dir, strict)
}

/// 建立新的私有檔案：已存在（含 symlink）就失敗，不覆蓋、不跟隨。
pub fn create_private_file(path: &Path) -> io::Result<File> {
    imp::create_private_file(path)
}

/// 讀取一般檔案，不跟隨最後一段的 symlink/junction。不存在時回傳 NotFound。
pub fn read_no_follow(path: &Path) -> io::Result<Vec<u8>> {
    let mut f = imp::open_no_follow(path).map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            e
        } else {
            unsafe_path(path, &e.to_string())
        }
    })?;
    let m = f.metadata()?;
    if imp::is_link_or_reparse(&m) || !m.is_file() {
        return Err(unsafe_path(path, "not a regular file"));
    }
    let mut data = Vec::new();
    f.read_to_end(&mut data)?;
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;

    fn temp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("rds-securefs-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        // 測試用的暫存路徑本身可能含 symlink（例如 macOS 的 /var -> /private/var），先解析
        fs::canonicalize(&d).map(strip_verbatim).unwrap()
    }

    /// Windows 的 canonicalize 會加上 `\\?\`，轉回一般路徑以符合實際使用情境。
    fn strip_verbatim(p: PathBuf) -> PathBuf {
        let s = p.to_string_lossy().to_string();
        match s.strip_prefix(r"\\?\") {
            Some(rest) => PathBuf::from(rest),
            None => p,
        }
    }

    #[test]
    fn creates_dir_and_private_file_without_overwriting() {
        let base = temp_dir("create");
        let dir = base.join("a").join("backups");
        let _g = prepare_private_dir(&dir, true).unwrap();
        let path = dir.join("x.toml");
        create_private_file(&path)
            .unwrap()
            .write_all(b"one")
            .unwrap();
        // 已存在就失敗，不覆蓋
        let e = create_private_file(&path).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&path).unwrap(), b"one");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&dir), 0o700);
            assert_eq!(mode(&path), 0o600);
        }
        drop(_g);
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn read_no_follow_reads_regular_files_and_reports_missing() {
        let base = temp_dir("read");
        let f = base.join("cfg.toml");
        fs::write(&f, "data").unwrap();
        assert_eq!(read_no_follow(&f).unwrap(), b"data");
        let e = read_no_follow(&base.join("missing")).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::NotFound);
        assert!(read_no_follow(&base).is_err(), "資料夾不是一般檔案");
        let _ = fs::remove_dir_all(&base);
    }

    #[cfg(unix)]
    #[test]
    fn unix_symlinks_are_refused() {
        use std::os::unix::fs::symlink;
        let base = temp_dir("unix-link");
        let victim = base.join("victim");
        fs::create_dir_all(&victim).unwrap();
        fs::write(victim.join("secret"), "s").unwrap();
        // 備份資料夾是 symlink
        let link_dir = base.join("backups");
        symlink(&victim, &link_dir).unwrap();
        assert!(prepare_private_dir(&link_dir, false).is_err());
        assert!(prepare_private_dir(&link_dir.join("sub"), true).is_err());
        // 目的檔是預先放好的 symlink：不可寫進它指向的檔案
        let real = base.join("real");
        let _g = prepare_private_dir(&real, true).unwrap();
        symlink(victim.join("secret"), real.join("x.toml")).unwrap();
        assert!(create_private_file(&real.join("x.toml")).is_err());
        assert_eq!(fs::read_to_string(victim.join("secret")).unwrap(), "s");
        // 讀取來源是 symlink：拒絕
        assert!(read_no_follow(&real.join("x.toml")).is_err());
        drop(_g);
        let _ = fs::remove_dir_all(&base);
    }

    /// Windows：junction 不需要系統管理員權限即可建立，用來模擬攻擊。
    #[cfg(windows)]
    #[test]
    fn windows_junctions_are_refused() {
        let base = temp_dir("win-junction");
        let victim = base.join("victim");
        fs::create_dir_all(&victim).unwrap();
        let junction = base.join("backups");
        let status = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&junction)
            .arg(&victim)
            .output()
            .unwrap();
        assert!(status.status.success(), "{status:?}");
        // 最後一段是 junction：嚴格與一般模式都拒絕
        assert!(prepare_private_dir(&junction, false).is_err());
        assert!(prepare_private_dir(&junction, true).is_err());
        // 上層是 junction：嚴格模式拒絕，且不會在 junction 指向的位置建立資料夾
        assert!(prepare_private_dir(&junction.join("sub"), true).is_err());
        assert!(!victim.join("sub").exists());
        // 讀取來源經過 junction 的最後一段：資料夾不是一般檔案，拒絕
        assert!(read_no_follow(&junction).is_err());
        let _ = fs::remove_dir(&junction);
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn strict_mode_requires_an_absolute_path() {
        assert!(prepare_private_dir(Path::new("relative/backups"), true).is_err());
    }
}
