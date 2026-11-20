//! 平台相依的「不跟隨 symlink / junction」檔案操作（platform 層的一部分）。
//!
//! 用途：以系統管理員/root 身分把檔案寫進一般使用者可寫的資料夾（備份）時，
//! 防止使用者事先放好 symlink、junction 或同名檔案，把寫入導向系統檔案（M6）。
//!
//! - 資料夾：建立時 0700（Unix）；不得是 symlink/reparse point；Unix 須由目前的有效使用者擁有。
//!   `strict`（以提升權限執行時）另要求整條路徑都沒有 symlink/reparse point。
//! - 資料夾準備好之後回傳 `SecureDir`，檔案一律「相對於這個已開啟的資料夾」建立，
//!   不再以路徑重新解析（避免「先檢查、後用路徑建檔」的 TOCTOU）：
//!   - Unix：保留資料夾的 fd，以 `openat(dirfd, name, O_CREAT|O_EXCL|O_NOFOLLOW, 0600)` 建檔。
//!     strict 模式下資料夾本身是從 `/` 開始逐層以 `openat(O_NOFOLLOW|O_DIRECTORY)` 走下去
//!     （缺少的層級以 `mkdirat` 0700 建立），路徑上任何一層是 symlink 都會失敗。
//!   - Windows：持有不給 FILE_SHARE_DELETE 的資料夾 handle，持有期間資料夾與其上層都無法被
//!     改名或刪除（有測試驗證），因此以路徑建檔仍會落在同一個資料夾。strict 模式下逐層建立、
//!     逐層確認不是 reparse point，不會在 junction 底下建立任何東西。
//! - 檔案：一律 create_new（不覆蓋）且不跟隨最後一段的 symlink；Unix 權限 0600。
//! - 讀取：不跟隨最後一段的 symlink，且必須是一般檔案（避免 FIFO 讓程式卡住）。
//!
//! 判斷邏輯盡量抽成純函式（`walk_segments`、`dir_check`、`create_checked_chain`、`valid_leaf`），
//! 所有平台都編譯並測試；系統呼叫的薄包裝在各平台的 `imp` 模組。

use std::fs::{self, File};
use std::io::{self, Read};
use std::path::Path;

/// 已通過檢查、且在被丟棄前一直保持開啟的資料夾。檔案只能透過它建立或刪除。
pub struct SecureDir {
    inner: imp::Dir,
}

impl SecureDir {
    /// 在這個資料夾內建立新的私有檔案：已存在（含 symlink）就失敗，不覆蓋、不跟隨。
    /// `name` 必須是單一路徑區段（見 `valid_leaf`）。
    pub fn create_private_file(&self, name: &str) -> io::Result<File> {
        check_leaf(name)?;
        self.inner.create_file(name)
    }

    /// 刪除這個資料夾內的檔案（用於清掉寫到一半的檔案）。
    pub fn remove_file(&self, name: &str) -> io::Result<()> {
        check_leaf(name)?;
        self.inner.remove_file(name)
    }
}

fn unsafe_path(path: &Path, reason: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("unsafe path {}: {reason}", path.display()),
    )
}

/// 檔名必須是單一路徑區段：非空、不是 `.`/`..`、不含路徑分隔字元、`:`（NTFS 資料流）
/// 或控制字元（含 NUL）。白名單以外的一律拒絕。
fn valid_leaf(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name
            .chars()
            .any(|c| c == '/' || c == '\\' || c == ':' || c.is_control())
}

fn check_leaf(name: &str) -> io::Result<()> {
    if valid_leaf(name) {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid file name: {name:?}"),
        ))
    }
}

/// Unix strict 模式：把絕對路徑拆成要從 `/` 逐層開啟的區段。
/// 拒絕相對路徑、根目錄本身、`.`/`..` 與含 NUL 的路徑；重複的 `/` 視為一個（POSIX 語意）。
#[cfg_attr(windows, allow(dead_code))]
fn walk_segments(path: &[u8]) -> Result<Vec<&[u8]>, &'static str> {
    let rest = path.strip_prefix(b"/").ok_or("not an absolute path")?;
    if path.contains(&0) {
        return Err("path contains NUL");
    }
    let segs: Vec<&[u8]> = rest
        .split(|&b| b == b'/')
        .filter(|s| !s.is_empty())
        .collect();
    if segs.iter().any(|s| *s == b"." || *s == b"..") {
        return Err("path contains . or ..");
    }
    if segs.is_empty() {
        return Err("refusing the root directory");
    }
    Ok(segs)
}

/// Unix：已開啟的資料夾是否可用。回傳 Ok(true) 代表需要以 fchmod 收緊成 0700。
#[cfg_attr(windows, allow(dead_code))]
fn dir_check(is_dir: bool, uid: u32, euid: u32, mode: u32) -> Result<bool, &'static str> {
    if !is_dir || uid != euid {
        return Err("not a directory owned by the current user");
    }
    Ok(mode & 0o077 != 0)
}

/// 路徑上某一層的狀態（不跟隨 reparse point 取得）。
#[cfg_attr(unix, allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Node {
    Missing,
    PlainDir,
    /// symlink、junction、掛載點，或不是資料夾。
    Unsafe,
}

/// Windows strict 模式：由上而下逐層處理 `levels`——已存在就確認是一般資料夾；
/// 不存在就建立後再確認。任何一層不安全就立刻停止，不會在它底下建立任何東西。
/// 檔案系統操作由呼叫端注入，方便以假資料測試順序與失敗行為。
#[cfg_attr(unix, allow(dead_code))]
fn create_checked_chain(
    levels: &[&Path],
    stat: &mut dyn FnMut(&Path) -> io::Result<Node>,
    mkdir: &mut dyn FnMut(&Path) -> io::Result<()>,
) -> io::Result<()> {
    for &level in levels {
        let node = match stat(level)? {
            Node::Missing => {
                match mkdir(level) {
                    Ok(()) => {}
                    // 與其他行程同時建立：不信任它，下面重新檢查
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(e) => return Err(e),
                }
                stat(level)?
            }
            n => n,
        };
        if node != Node::PlainDir {
            return Err(unsafe_path(level, "symlink, junction or not a directory"));
        }
    }
    Ok(())
}

#[cfg(unix)]
mod imp {
    use super::*;
    use std::ffi::{CStr, CString};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};

    /// 逐層開啟資料夾用的旗標：不跟隨 symlink、必須是資料夾、exec 時關閉。
    const DIR_FLAGS: libc::c_int =
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    /// 建立備份檔用的旗標：只寫、必須是新檔、不跟隨 symlink、exec 時關閉。
    const FILE_FLAGS: libc::c_int =
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    /// 新檔案的權限。openat 是 C 可變參數函式，mode 必須以 c_uint 傳遞
    /// （macOS 的 mode_t 是 u16，不能直接傳）。
    const FILE_MODE: libc::c_uint = 0o600;
    /// 資料夾權限：mkdirat 用 mode_t（Linux u32、macOS u16），std 的 API 用 u32。
    /// 分開宣告，避免在不同平台出現多餘或縮窄的型別轉換。
    const DIR_MODE: libc::mode_t = 0o700;
    const DIR_PERM: u32 = 0o700;

    pub struct Dir {
        /// 已開啟的資料夾（RAII：丟棄時關閉 fd）。
        fd: OwnedFd,
    }

    fn cstring(bytes: &[u8]) -> io::Result<CString> {
        CString::new(bytes).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in path"))
    }

    /// `openat` 的安全包裝：成功時回傳由 OwnedFd 管理的 fd。
    fn open_at(
        dir: libc::c_int,
        name: &CStr,
        flags: libc::c_int,
        mode: libc::c_uint,
    ) -> io::Result<OwnedFd> {
        // SAFETY: name 是以 NUL 結尾的有效 C 字串，在呼叫期間保持有效；dir 是有效的已開啟 fd
        // 或 AT_FDCWD；mode 以 c_uint 傳給可變參數（符合 C 的整數提升規則）。
        let fd = unsafe { libc::openat(dir, name.as_ptr(), flags, mode) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fd 是 openat 剛回傳、有效且尚未被任何人擁有的 fd，交給 OwnedFd 後由它負責關閉。
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    /// `mkdirat`，已存在視為成功（之後一律以 O_NOFOLLOW 重新開啟並檢查，不信任它）。
    fn mkdir_at(dir: libc::c_int, name: &CStr) -> io::Result<()> {
        // SAFETY: name 是以 NUL 結尾的有效 C 字串；dir 是有效的已開啟 fd。
        if unsafe { libc::mkdirat(dir, name.as_ptr(), DIR_MODE) } == 0 {
            return Ok(());
        }
        let e = io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::EEXIST) {
            Ok(())
        } else {
            Err(e)
        }
    }

    /// strict：從 `/` 逐層以 O_NOFOLLOW|O_DIRECTORY 開啟；缺少的層級以 mkdirat 0700 建立。
    /// 每一層都相對於上一層已開啟的 fd 操作，中途被換成 symlink 也只會讓開啟失敗。
    fn walk_strict(dir: &Path) -> io::Result<OwnedFd> {
        let segs = walk_segments(dir.as_os_str().as_bytes()).map_err(|r| unsafe_path(dir, r))?;
        let mut cur = open_at(libc::AT_FDCWD, c"/", DIR_FLAGS, 0)?;
        for seg in segs {
            let name = cstring(seg)?;
            let parent = cur.as_raw_fd();
            let next = match open_at(parent, &name, DIR_FLAGS, 0) {
                Ok(fd) => fd,
                Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {
                    mkdir_at(parent, &name)?;
                    open_at(parent, &name, DIR_FLAGS, 0)
                        .map_err(|e| unsafe_path(dir, &e.to_string()))?
                }
                // ELOOP / ENOTDIR：這一層是 symlink 或不是資料夾
                Err(e) => return Err(unsafe_path(dir, &e.to_string())),
            };
            cur = next; // 舊的 fd 在這裡被 OwnedFd 關閉
        }
        Ok(cur)
    }

    /// 一般權限：沿用 std 建立資料夾（上層的 symlink 不影響安全性），
    /// 最後一段以 O_NOFOLLOW 開啟，是 symlink 就失敗（ELOOP）。
    fn open_relaxed(dir: &Path) -> io::Result<OwnedFd> {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(DIR_PERM)
            .create(dir)?;
        let f = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
            .open(dir)
            .map_err(|e| unsafe_path(dir, &e.to_string()))?;
        Ok(OwnedFd::from(f))
    }

    pub fn prepare_private_dir(dir: &Path, strict: bool) -> io::Result<SecureDir> {
        let fd = if strict {
            walk_strict(dir)?
        } else {
            open_relaxed(dir)?
        };
        let handle = File::from(fd);
        let m = handle.metadata()?; // fstat：作用在已開啟的 fd
                                    // SAFETY: geteuid 不接受參數、不會失敗，也沒有副作用。
        let euid = unsafe { libc::geteuid() };
        let tighten =
            dir_check(m.is_dir(), m.uid(), euid, m.mode()).map_err(|r| unsafe_path(dir, r))?;
        if tighten {
            // fchmod 作用在已開啟的 fd，不會被路徑上的替換影響
            handle.set_permissions(fs::Permissions::from_mode(DIR_PERM))?;
        }
        Ok(SecureDir {
            inner: Dir {
                fd: OwnedFd::from(handle),
            },
        })
    }

    impl Dir {
        pub fn create_file(&self, name: &str) -> io::Result<File> {
            let name = cstring(name.as_bytes())?;
            open_at(self.fd.as_raw_fd(), &name, FILE_FLAGS, FILE_MODE).map(File::from)
        }

        pub fn remove_file(&self, name: &str) -> io::Result<()> {
            let name = cstring(name.as_bytes())?;
            // SAFETY: name 是以 NUL 結尾的有效 C 字串；fd 由 self 持有，在呼叫期間有效。
            if unsafe { libc::unlinkat(self.fd.as_raw_fd(), name.as_ptr(), 0) } == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        }
    }

    pub fn open_no_follow(path: &Path) -> io::Result<File> {
        // O_NONBLOCK：路徑若是 FIFO，開啟時不會卡住（之後檢查種類會拒絕）
        fs::OpenOptions::new()
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
    use std::path::PathBuf;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_SHARE_READ: u32 = 0x1;
    const FILE_SHARE_WRITE: u32 = 0x2;

    pub struct Dir {
        /// 不給 FILE_SHARE_DELETE 的資料夾 handle：持有期間資料夾與其上層都無法被改名或刪除。
        _handle: File,
        path: PathBuf,
    }

    pub fn is_link_or_reparse(m: &fs::Metadata) -> bool {
        m.file_type().is_symlink() || m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }

    /// 不跟隨 reparse point 取得某一層的狀態。
    fn node_of(p: &Path) -> io::Result<Node> {
        match fs::symlink_metadata(p) {
            Ok(m) if is_link_or_reparse(&m) || !m.is_dir() => Ok(Node::Unsafe),
            Ok(_) => Ok(Node::PlainDir),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Node::Missing),
            Err(e) => Err(e),
        }
    }

    pub fn prepare_private_dir(dir: &Path, strict: bool) -> io::Result<SecureDir> {
        if strict {
            if !dir.is_absolute() {
                return Err(unsafe_path(dir, "not an absolute path"));
            }
            // 由上而下：磁碟根目錄 → ... → dir
            let mut levels: Vec<&Path> = dir
                .ancestors()
                .filter(|p| !p.as_os_str().is_empty())
                .collect();
            levels.reverse();
            create_checked_chain(&levels, &mut node_of, &mut |p| fs::create_dir(p))?;
        } else {
            fs::create_dir_all(dir)?;
        }
        // 不給 FILE_SHARE_DELETE：持有期間資料夾與其上層都無法被改名或刪除（換成 junction）
        let handle = fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(dir)?;
        let m = handle.metadata()?;
        if !m.is_dir() || m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(unsafe_path(dir, "not a plain directory"));
        }
        Ok(SecureDir {
            inner: Dir {
                _handle: handle,
                path: dir.to_path_buf(),
            },
        })
    }

    impl Dir {
        pub fn create_file(&self, name: &str) -> io::Result<File> {
            // 檔案權限沿用資料夾繼承的 ACL（%APPDATA% 下僅本人、SYSTEM、Administrators）
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                .open(self.path.join(name))
        }

        pub fn remove_file(&self, name: &str) -> io::Result<()> {
            fs::remove_file(self.path.join(name))
        }
    }

    pub fn open_no_follow(path: &Path) -> io::Result<File> {
        fs::OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
    }
}

/// 確保私有資料夾存在且安全；見模組說明。回傳值必須持有到檔案寫完為止。
pub fn prepare_private_dir(dir: &Path, strict: bool) -> io::Result<SecureDir> {
    imp::prepare_private_dir(dir, strict)
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
    use std::collections::HashMap;
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
        let d = prepare_private_dir(&dir, true).unwrap();
        d.create_private_file("x.toml")
            .unwrap()
            .write_all(b"one")
            .unwrap();
        // 已存在就失敗，不覆蓋
        let e = d.create_private_file("x.toml").unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::AlreadyExists);
        let path = dir.join("x.toml");
        assert_eq!(fs::read(&path).unwrap(), b"one");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&dir), 0o700);
            assert_eq!(mode(&path), 0o600);
        }
        d.remove_file("x.toml").unwrap();
        assert!(!path.exists());
        drop(d);
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn file_names_must_be_a_single_component() {
        let base = temp_dir("leaf");
        let d = prepare_private_dir(&base.join("b"), true).unwrap();
        for bad in ["", ".", "..", "../x", "a/b", r"a\b", "a:b", "a\0b", "a\nb"] {
            let e = d.create_private_file(bad).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::InvalidInput, "{bad:?}");
            assert!(d.remove_file(bad).is_err(), "{bad:?}");
        }
        assert!(!base.join("x").exists());
        drop(d);
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn valid_leaf_cases() {
        assert!(valid_leaf(
            "1700000000-00000000000000ab-user-RustDesk2.toml"
        ));
        assert!(valid_leaf("中文.toml"));
        for bad in ["", ".", "..", "a/b", r"a\b", "a:b", "a\0", "a\u{7f}"] {
            assert!(!valid_leaf(bad), "{bad:?}");
        }
    }

    #[test]
    fn walk_segments_cases() {
        assert_eq!(
            walk_segments(b"/home/u/.config/rdswitch/backups").unwrap(),
            [&b"home"[..], b"u", b".config", b"rdswitch", b"backups"]
        );
        assert_eq!(walk_segments(b"//a///b/").unwrap(), [&b"a"[..], b"b"]);
        for bad in [
            &b"relative/x"[..],
            b"",
            b"/",
            b"///",
            b"/a/../etc",
            b"/a/./b",
            b"/a\0b",
        ] {
            assert!(walk_segments(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn dir_check_cases() {
        assert_eq!(dir_check(true, 1000, 1000, 0o40700), Ok(false));
        assert_eq!(dir_check(true, 1000, 1000, 0o40755), Ok(true)); // 收緊成 0700
        assert_eq!(dir_check(true, 1000, 1000, 0o40707), Ok(true));
        assert!(dir_check(true, 0, 1000, 0o40700).is_err()); // 不是自己的資料夾
        assert!(dir_check(true, 1000, 0, 0o40700).is_err()); // root 執行時，使用者的資料夾不可用
        assert!(dir_check(false, 1000, 1000, 0o100600).is_err());
    }

    /// 以表格模擬的檔案系統，記錄每一次操作的順序。
    struct FakeTree {
        nodes: HashMap<PathBuf, Node>,
        log: Vec<String>,
        /// 建立這一層之後，把它變成 junction（模擬與攻擊者的競爭）。
        swap_after_mkdir: Option<PathBuf>,
    }

    impl FakeTree {
        fn run(&mut self, levels: &[&str]) -> io::Result<()> {
            let levels: Vec<&Path> = levels.iter().map(Path::new).collect();
            let cell = std::cell::RefCell::new(self);
            create_checked_chain(
                &levels,
                &mut |p| {
                    let mut t = cell.borrow_mut();
                    t.log.push(format!("stat {}", p.display()));
                    Ok(*t.nodes.get(p).unwrap_or(&Node::Missing))
                },
                &mut |p| {
                    let mut t = cell.borrow_mut();
                    t.log.push(format!("mkdir {}", p.display()));
                    let n = if t.swap_after_mkdir.as_deref() == Some(p) {
                        Node::Unsafe
                    } else {
                        Node::PlainDir
                    };
                    t.nodes.insert(p.to_path_buf(), n);
                    Ok(())
                },
            )
        }
    }

    fn tree(existing: &[(&str, Node)]) -> FakeTree {
        FakeTree {
            nodes: existing
                .iter()
                .map(|(p, n)| (PathBuf::from(p), *n))
                .collect(),
            log: vec![],
            swap_after_mkdir: None,
        }
    }

    #[test]
    fn chain_creates_each_level_and_checks_it_before_going_deeper() {
        let mut t = tree(&[("C:/", Node::PlainDir), ("C:/u", Node::PlainDir)]);
        t.run(&["C:/", "C:/u", "C:/u/a", "C:/u/a/b"]).unwrap();
        assert_eq!(
            t.log,
            [
                "stat C:/",
                "stat C:/u",
                "stat C:/u/a",
                "mkdir C:/u/a",
                "stat C:/u/a",
                "stat C:/u/a/b",
                "mkdir C:/u/a/b",
                "stat C:/u/a/b",
            ]
        );
    }

    #[test]
    fn chain_stops_at_a_junction_without_creating_anything_below_it() {
        let mut t = tree(&[("C:/", Node::PlainDir), ("C:/u", Node::Unsafe)]);
        assert!(t.run(&["C:/", "C:/u", "C:/u/a"]).is_err());
        assert!(!t.log.iter().any(|l| l.starts_with("mkdir")), "{:?}", t.log);
        // 剛建立的層級在下一步之前被換成 junction：同樣停止
        let mut t = tree(&[("C:/", Node::PlainDir)]);
        t.swap_after_mkdir = Some(PathBuf::from("C:/a"));
        assert!(t.run(&["C:/", "C:/a", "C:/a/b"]).is_err());
        assert!(!t.log.contains(&"mkdir C:/a/b".to_string()), "{:?}", t.log);
    }

    #[test]
    fn chain_propagates_mkdir_errors() {
        let levels = [Path::new("C:/"), Path::new("C:/x")];
        let r = create_checked_chain(
            &levels,
            &mut |p| {
                Ok(if p == Path::new("C:/") {
                    Node::PlainDir
                } else {
                    Node::Missing
                })
            },
            &mut |_| Err(io::Error::from(io::ErrorKind::PermissionDenied)),
        );
        assert_eq!(r.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
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
        assert!(prepare_private_dir(&link_dir, true).is_err());
        // 上層是 symlink：strict 拒絕，且不會在 symlink 指向的位置建立資料夾
        assert!(prepare_private_dir(&link_dir.join("sub"), true).is_err());
        assert!(!victim.join("sub").exists());
        // 目的檔是預先放好的 symlink：不可寫進它指向的檔案
        let real = base.join("real");
        let d = prepare_private_dir(&real, true).unwrap();
        symlink(victim.join("secret"), real.join("x.toml")).unwrap();
        assert!(d.create_private_file("x.toml").is_err());
        assert_eq!(fs::read_to_string(victim.join("secret")).unwrap(), "s");
        // 讀取來源是 symlink：拒絕
        assert!(read_no_follow(&real.join("x.toml")).is_err());
        drop(d);
        let _ = fs::remove_dir_all(&base);
    }

    /// 取得 SecureDir 之後資料夾被搬走、原位置換成指向別處的 symlink：
    /// 檔案仍建立在原本開啟的資料夾（fd），不會跟著路徑寫到 symlink 指向的位置。
    #[cfg(unix)]
    #[test]
    fn unix_file_is_created_in_the_opened_directory_even_if_the_path_is_swapped() {
        let base = temp_dir("unix-swap");
        let dir = base.join("backups");
        let victim = base.join("victim");
        fs::create_dir_all(&victim).unwrap();
        let d = prepare_private_dir(&dir, true).unwrap();
        fs::rename(&dir, base.join("moved")).unwrap();
        std::os::unix::fs::symlink(&victim, &dir).unwrap();
        d.create_private_file("x.toml").unwrap();
        assert!(base.join("moved").join("x.toml").exists());
        assert!(!victim.join("x.toml").exists());
        drop(d);
        let _ = fs::remove_dir_all(&base);
    }

    /// 既有資料夾權限過寬：以 fchmod 收緊成 0700。
    #[cfg(unix)]
    #[test]
    fn unix_existing_dir_permissions_are_tightened() {
        use std::os::unix::fs::PermissionsExt;
        let base = temp_dir("unix-mode");
        let dir = base.join("backups");
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        for strict in [false, true] {
            let d = prepare_private_dir(&dir, strict).unwrap();
            assert_eq!(
                fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
                0o700
            );
            drop(d);
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        }
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
        assert!(prepare_private_dir(&junction.join("sub").join("deeper"), true).is_err());
        assert!(!victim.join("sub").exists());
        // 讀取來源經過 junction 的最後一段：資料夾不是一般檔案，拒絕
        assert!(read_no_follow(&junction).is_err());
        let _ = fs::remove_dir(&junction);
        let _ = fs::remove_dir_all(&base);
    }

    /// Windows：持有 SecureDir 期間，資料夾本身與它的上層都無法被改名或刪除，
    /// 因此無法在寫入之前把路徑換成 junction。釋放之後就可以改名（確認失敗確實來自 handle）。
    #[cfg(windows)]
    #[test]
    fn windows_held_dir_and_its_parents_cannot_be_renamed() {
        let base = temp_dir("win-hold");
        let parent = base.join("a");
        let dir = parent.join("backups");
        let d = prepare_private_dir(&dir, true).unwrap();
        assert!(
            fs::rename(&parent, base.join("a-moved")).is_err(),
            "上層資料夾在持有期間不可被改名"
        );
        assert!(
            fs::rename(&dir, parent.join("moved")).is_err(),
            "資料夾本身在持有期間不可被改名"
        );
        assert!(fs::remove_dir(&dir).is_err(), "資料夾在持有期間不可被刪除");
        // 仍在原處建立檔案
        d.create_private_file("x.toml").unwrap();
        assert!(dir.join("x.toml").exists());
        drop(d);
        fs::rename(&parent, base.join("a-moved")).expect("釋放後應可改名");
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn strict_mode_requires_an_absolute_path() {
        assert!(prepare_private_dir(Path::new("relative/backups"), true).is_err());
    }
}
