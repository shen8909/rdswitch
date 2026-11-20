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
//!     逐層確認不是 reparse point，不會在 junction 底下建立任何東西。逐層檢查與開啟 handle
//!     之間仍有空窗（上層可能被換成 junction 又換回），因此開啟後再以
//!     GetFinalPathNameByHandleW 取得 handle 的實際路徑，與預期路徑（長檔名、根目錄以同一個
//!     API 解析以處理 subst）正規化後比較，不一致就失敗（`same_win_path`）。
//! - 檔案：一律 create_new（不覆蓋）且不跟隨最後一段的 symlink；Unix 權限 0600。
//! - 讀取：不跟隨最後一段的 symlink，且必須是一般檔案（避免 FIFO 讓程式卡住）。
//!
//! 判斷邏輯盡量抽成純函式（`walk_segments`、`dir_check`、`create_checked_chain`、`valid_leaf`、
//! `split_win_path`、`same_win_path`、`fill_wide`），
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

/// 寬字元路徑的上限（Windows 長路徑約 32,767 字元，再加上 `\\?\UNC\` 等前綴的餘裕）。
#[cfg_attr(unix, allow(dead_code))]
const MAX_WIDE_PATH: usize = 32_800;

/// 以「先試、太小就依回報的長度重試」的方式取得 Win32 寬字串結果
/// （GetFinalPathNameByHandleW、GetLongPathNameW 的共同慣例）。
/// `call` 收到可寫入的緩衝區，回傳 API 的回傳值：
/// 小於緩衝區長度代表成功、為不含結尾 NUL 的字元數；否則為所需大小（含 NUL）。
/// 失敗（API 回傳 0）由 `call` 自行轉成錯誤。重試次數與大小都有上限，超過就失敗。
#[cfg_attr(unix, allow(dead_code))]
fn fill_wide(call: &mut dyn FnMut(&mut [u16]) -> io::Result<u32>) -> io::Result<Vec<u16>> {
    const INITIAL: usize = 260;
    const MAX_TRIES: usize = 4;
    let too_long = || io::Error::new(io::ErrorKind::InvalidData, "path too long");
    let mut cap = INITIAL;
    for _ in 0..MAX_TRIES {
        let mut buf = vec![0u16; cap];
        let n = usize::try_from(call(&mut buf)?).map_err(|_| too_long())?;
        if n < cap {
            buf.truncate(n);
            return Ok(buf);
        }
        // n 是所需大小（含 NUL）；至少要比這次大，避免同樣大小無限重試
        let next = n.max(cap.checked_add(1).ok_or_else(too_long)?);
        if next > MAX_WIDE_PATH {
            return Err(too_long());
        }
        cap = next;
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "path length kept changing",
    ))
}

/// 正規化後的 Windows 絕對路徑：是否為 UNC，以及各個區段（不含分隔字元）。
#[cfg_attr(unix, allow(dead_code))]
#[derive(Debug, PartialEq, Eq)]
struct WinPathParts<'a> {
    unc: bool,
    segs: Vec<&'a [u16]>,
}

#[cfg_attr(unix, allow(dead_code))]
const BACKSLASH: u16 = b'\\' as u16;
#[cfg_attr(unix, allow(dead_code))]
const SLASH: u16 = b'/' as u16;

/// 去掉一個 ASCII 前綴（不分大小寫，只用於 `\\?\UNC\` 這類固定的 ASCII 前綴）。
#[cfg_attr(unix, allow(dead_code))]
fn strip_ascii_prefix<'a>(s: &'a [u16], prefix: &str) -> Option<&'a [u16]> {
    let p = prefix.as_bytes();
    if s.len() < p.len() {
        return None;
    }
    let (head, rest) = s.split_at(p.len());
    head.iter()
        .zip(p)
        .all(|(&c, &b)| u8::try_from(c).is_ok_and(|c| c.eq_ignore_ascii_case(&b)))
        .then_some(rest)
}

/// 把 Windows 絕對路徑拆成可比較的形式；無法確定語意的路徑一律回傳 None（視為不同）。
/// - `\\?\UNC\server\share\…` 與 `\\server\share\…` 視為同一種 UNC 形式；
///   `\\?\C:\…`、`\??\C:\…` 與 `C:\…` 視為同一種磁碟形式。
/// - 非 verbatim 路徑依 Win32 規則：`/` 也是分隔字元、區段結尾的 `.` 與空白會被去掉；
///   verbatim（`\\?\`）路徑則照字面處理。
/// - 重複與結尾的分隔字元忽略；含 `.`、`..`、`\\.\` 裝置路徑、相對路徑或缺少
///   server/share 的 UNC 一律拒絕（不嘗試解析，fail closed）。
/// - 8.3 短檔名、subst、大小寫無法在這裡處理：呼叫端須先把兩邊轉成相同的正規形
///   （長檔名、實際磁碟），大小寫則在比較時處理。
#[cfg_attr(unix, allow(dead_code))]
fn split_win_path(p: &[u16]) -> Option<WinPathParts<'_>> {
    let (unc, verbatim, body) = if let Some(rest) = strip_ascii_prefix(p, r"\\?\UNC\") {
        (true, true, rest)
    } else if let Some(rest) =
        strip_ascii_prefix(p, r"\\?\").or_else(|| strip_ascii_prefix(p, r"\??\"))
    {
        (false, true, rest)
    } else if strip_ascii_prefix(p, r"\\.\").is_some()
        || strip_ascii_prefix(p, r"//./").is_some()
        || strip_ascii_prefix(p, r"//?/").is_some()
    {
        return None; // 裝置路徑：不比較
    } else {
        let is_sep = |c: &u16| *c == BACKSLASH || *c == SLASH;
        match p {
            [a, b, ..] if is_sep(a) && is_sep(b) => (true, false, &p[2..]),
            _ => (false, false, p),
        }
    };
    let is_sep = |c: &u16| *c == BACKSLASH || (!verbatim && *c == SLASH);
    let dot = u16::from(b'.');
    let space = u16::from(b' ');
    let mut segs = Vec::new();
    for seg in body.split(is_sep).filter(|s| !s.is_empty()) {
        if seg.iter().all(|&c| c == dot) {
            return None; // `.`、`..` 等：不解析
        }
        let seg = if verbatim {
            seg
        } else {
            // Win32 會去掉區段結尾的 `.` 與空白；去掉後變成空的區段不接受
            let end = seg.iter().rposition(|&c| c != dot && c != space)?;
            &seg[..=end]
        };
        segs.push(seg);
    }
    let first = segs.first()?;
    if unc {
        if segs.len() < 2 {
            return None; // 至少要有 server 與 share
        }
    } else if !verbatim {
        // 非 verbatim 的非 UNC 路徑必須以 `X:` 開頭（拒絕相對路徑與 `\foo`）
        let drive = matches!(first, [d, c] if *c == u16::from(b':')
            && u8::try_from(*d).is_ok_and(|d| d.is_ascii_alphabetic()));
        let rooted = p.get(2).is_none_or(is_sep);
        if !drive || !rooted {
            return None;
        }
    }
    Some(WinPathParts { unc, segs })
}

/// 兩個 Windows 絕對路徑是否指向同一位置（依 `split_win_path` 的規則正規化後逐段比較）。
/// `eq_ignore_case` 以檔案系統的方式不分大小寫比較單一區段（正式環境用
/// CompareStringOrdinal）。任何一邊無法正規化就回傳 false。
#[cfg_attr(unix, allow(dead_code))]
fn same_win_path(
    expected: &[u16],
    actual: &[u16],
    eq_ignore_case: &dyn Fn(&[u16], &[u16]) -> bool,
) -> bool {
    match (split_win_path(expected), split_win_path(actual)) {
        (Some(a), Some(b)) => {
            a.unc == b.unc
                && a.segs.len() == b.segs.len()
                && a.segs
                    .iter()
                    .zip(&b.segs)
                    .all(|(x, y)| eq_ignore_case(x, y))
        }
        _ => false,
    }
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
    use std::ffi::{c_void, OsString};
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use std::os::windows::io::AsRawHandle;
    use std::path::{Component, PathBuf};

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

    /// 取得路徑資訊的外部資源（Win32 API）。抽成 trait 以便測試注入「開啟後路徑被換掉」的情況。
    pub trait PathQuery {
        /// 已開啟 handle 的實際路徑（GetFinalPathNameByHandleW，長檔名正規形）。
        fn final_path(&self, f: &File) -> io::Result<Vec<u16>>;
        /// 路徑的長檔名形式（GetLongPathNameW；路徑必須存在）。
        fn long_path(&self, p: &Path) -> io::Result<Vec<u16>>;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetFinalPathNameByHandleW(
            file: *mut c_void,
            path: *mut u16,
            cch_path: u32,
            flags: u32,
        ) -> u32;
        fn GetLongPathNameW(short_path: *const u16, long_path: *mut u16, cch_buffer: u32) -> u32;
        fn CompareStringOrdinal(
            s1: *const u16,
            n1: i32,
            s2: *const u16,
            n2: i32,
            ignore_case: i32,
        ) -> i32;
    }

    /// FILE_NAME_NORMALIZED | VOLUME_NAME_DOS（兩者的值都是 0）。
    const FINAL_PATH_FLAGS: u32 = 0;
    const FILE_READ_ATTRIBUTES: u32 = 0x80;
    const CSTR_EQUAL: i32 = 2;

    /// 呼叫端把 API 回傳 0（失敗）轉成錯誤；緩衝區長度轉成 u32 失敗也是錯誤。
    fn api_len(ret: u32) -> io::Result<u32> {
        if ret == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(ret)
        }
    }

    fn buf_len(buf: &[u16]) -> io::Result<u32> {
        u32::try_from(buf.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "buffer too large"))
    }

    /// 正式環境：直接呼叫 Win32。
    pub struct Win32Paths;

    impl PathQuery for Win32Paths {
        fn final_path(&self, f: &File) -> io::Result<Vec<u16>> {
            let handle = f.as_raw_handle();
            fill_wide(&mut |buf| {
                let cch = buf_len(buf)?;
                // SAFETY: handle 屬於仍在借用中的 File（呼叫期間有效）；buf 可寫入 cch 個 u16。
                api_len(unsafe {
                    GetFinalPathNameByHandleW(handle, buf.as_mut_ptr(), cch, FINAL_PATH_FLAGS)
                })
            })
        }

        fn long_path(&self, p: &Path) -> io::Result<Vec<u16>> {
            let mut src: Vec<u16> = p.as_os_str().encode_wide().collect();
            if src.contains(&0) {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "NUL in path"));
            }
            src.push(0);
            fill_wide(&mut |buf| {
                let cch = buf_len(buf)?;
                // SAFETY: src 是以 NUL 結尾的寬字串，在呼叫期間有效；buf 可寫入 cch 個 u16。
                api_len(unsafe { GetLongPathNameW(src.as_ptr(), buf.as_mut_ptr(), cch) })
            })
        }
    }

    /// 以作業系統的大寫表不分大小寫比較（與檔案系統比較檔名的方式一致）。
    /// 長度無法轉換或 API 失敗時視為不同（fail closed）。
    pub fn eq_ignore_case(a: &[u16], b: &[u16]) -> bool {
        let (Ok(na), Ok(nb)) = (i32::try_from(a.len()), i32::try_from(b.len())) else {
            return false;
        };
        // SAFETY: a、b 是有效的切片，長度分別為 na、nb；API 只讀取。
        unsafe { CompareStringOrdinal(a.as_ptr(), na, b.as_ptr(), nb, 1) == CSTR_EQUAL }
    }

    /// 「預期路徑」的正規形：`dir` 先轉成長檔名，根目錄（磁碟或 UNC share）再以
    /// GetFinalPathNameByHandleW 解析（處理 subst 等磁碟代號對應），
    /// 與已開啟 handle 的實際路徑使用同一種 API、同一種正規形。
    fn expected_path(dir: &Path, q: &dyn PathQuery) -> io::Result<Vec<u16>> {
        let long = PathBuf::from(OsString::from_wide(&q.long_path(dir)?));
        let mut root = PathBuf::new();
        let mut rest = Vec::new();
        for c in long.components() {
            match c {
                Component::Prefix(_) | Component::RootDir if rest.is_empty() => root.push(c),
                Component::Normal(s) => rest.push(s),
                _ => return Err(unsafe_path(dir, "unexpected path component")),
            }
        }
        if !root.has_root() {
            return Err(unsafe_path(dir, "not an absolute path"));
        }
        let root_handle = fs::OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(&root)?;
        let mut out = q.final_path(&root_handle)?;
        for s in rest {
            if out.last() != Some(&BACKSLASH) {
                out.push(BACKSLASH);
            }
            out.extend(s.encode_wide());
        }
        Ok(out)
    }

    /// 開啟 handle 之後確認它實際指向預期的路徑：逐層檢查與開啟之間，上層若被換成
    /// junction 又換回，handle 會落在別處，這裡會發現並拒絕（fail closed）。
    pub fn verify_opened_path(dir: &Path, handle: &File, q: &dyn PathQuery) -> io::Result<()> {
        let expected = expected_path(dir, q)?;
        let actual = q.final_path(handle)?;
        if same_win_path(&expected, &actual, &eq_ignore_case) {
            Ok(())
        } else {
            Err(unsafe_path(
                dir,
                &format!(
                    "opened directory resolves to {} instead of {}",
                    String::from_utf16_lossy(&actual),
                    String::from_utf16_lossy(&expected)
                ),
            ))
        }
    }

    pub fn prepare_private_dir(dir: &Path, strict: bool) -> io::Result<SecureDir> {
        prepare_private_dir_with(dir, strict, &Win32Paths)
    }

    /// `prepare_private_dir` 的本體；路徑查詢由呼叫端注入（測試用）。
    pub fn prepare_private_dir_with(
        dir: &Path,
        strict: bool,
        q: &dyn PathQuery,
    ) -> io::Result<SecureDir> {
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
        if strict {
            verify_opened_path(dir, &handle, q)?;
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

    fn w(s: &str) -> Vec<u16> {
        s.encode_utf16().collect()
    }

    /// 測試用的可攜式不分大小寫比較（正式環境在 Windows 用 CompareStringOrdinal）。
    fn fold_eq(a: &[u16], b: &[u16]) -> bool {
        String::from_utf16_lossy(a).to_uppercase() == String::from_utf16_lossy(b).to_uppercase()
    }

    fn same(a: &str, b: &str) -> bool {
        let r = same_win_path(&w(a), &w(b), &fold_eq);
        // 比較必須對稱
        assert_eq!(r, same_win_path(&w(b), &w(a), &fold_eq), "{a:?} vs {b:?}");
        r
    }

    #[test]
    fn same_win_path_accepts_equivalent_forms() {
        for (a, b) in [
            (r"C:\Users\u\AppData", r"C:\Users\u\AppData"),
            // verbatim 前綴
            (r"C:\Users\u\AppData", r"\\?\C:\Users\u\AppData"),
            (r"C:\Users\u", r"\??\C:\Users\u"),
            (r"\\?\C:\x", r"\\?\C:\x"),
            // 大小寫（含磁碟代號與非 ASCII）
            (r"c:\users\U\appdata", r"\\?\C:\Users\u\AppData"),
            (r"C:\ÄÖ\Straße", r"C:\äö\STRAßE"),
            (r"C:\Ωμέγα", r"C:\ΩΜΈΓΑ"),
            // 中文與空白
            (r"C:\Users\王 小明\資料 夾", r"\\?\C:\Users\王 小明\資料 夾"),
            // 尾端與重複的分隔字元、`/`
            (r"C:\a\b\", r"\\?\C:\a\b"),
            (r"C:\a\b\\", r"C:\a\b"),
            (r"C:\a\\b", r"C:\a\b"),
            (r"C:/a/b", r"\\?\C:\a\b"),
            (r"C:\", r"\\?\C:\"),
            (r"C:", r"C:\"),
            // UNC
            (r"\\srv\share\x", r"\\?\UNC\srv\share\x"),
            (r"\\SRV\Share\x\", r"\\?\unc\srv\share\x"),
            (r"//srv/share/x", r"\\?\UNC\srv\share\x"),
            (r"\\srv\share", r"\\?\UNC\srv\share\"),
            // 非 verbatim 路徑：Win32 會去掉區段結尾的 `.` 與空白
            (r"C:\a\b.", r"\\?\C:\a\b"),
            (r"C:\a\b. .\c", r"C:\a\b\c"),
            // Volume GUID（沒有磁碟代號的磁碟區）兩邊相同時
            (
                r"\\?\Volume{0b1c2d3e-0000-0000-0000-100000000000}\x",
                r"\\?\volume{0B1C2D3E-0000-0000-0000-100000000000}\X",
            ),
        ] {
            assert!(same(a, b), "{a:?} vs {b:?}");
        }
    }

    #[test]
    fn same_win_path_rejects_different_or_ambiguous_paths() {
        for (a, b) in [
            (r"C:\a\b", r"C:\a\c"),
            (r"C:\a\b", r"D:\a\b"),
            // 前綴相同但更長或更短
            (r"C:\a\b", r"C:\a\bc"),
            (r"C:\a\b", r"C:\a\b\c"),
            (r"C:\a\b", r"C:\a"),
            (r"C:\a\b", r"C:\ab"),
            (r"\\srv\share\x", r"\\srv\share\x\y"),
            (r"\\srv\share", r"\\srv\shares"),
            // 8.3 短檔名不在這裡展開（呼叫端須先轉成長檔名）
            (r"C:\PROGRA~1\x", r"\\?\C:\Program Files\x"),
            // UNC 與磁碟形式不同
            (r"\\srv\share\x", r"\\?\C:\srv\share\x"),
            (r"\\?\UNC\srv\share", r"\\?\srv\share"),
            // verbatim 路徑照字面：結尾的 `.` 與 `/` 都是名稱的一部分
            (r"\\?\C:\a\b.", r"C:\a\b"),
            (r"\\?\C:\a/b", r"C:\a\b"),
            // `.`、`..` 不解析
            (r"C:\a\..\b", r"C:\b"),
            (r"C:\a\.\b", r"C:\a\b"),
            (r"C:\a\..", r"C:\"),
            (r"C:\a\...", r"C:\a"),
            (r"\\?\C:\a\..\b", r"\\?\C:\a\..\b"),
            // 裝置路徑、相對路徑、沒有磁碟代號的根路徑、空字串、不完整的 UNC
            (r"\\.\C:\a", r"C:\a"),
            (r"\\.\C:\a", r"\\.\C:\a"),
            (r"//./C:/a", r"//./C:/a"),
            (r"a\b", r"a\b"),
            (r"\a\b", r"\a\b"),
            (r"C:a", r"C:a"),
            (r"1:\a", r"1:\a"),
            ("", ""),
            (r"\\srv", r"\\?\UNC\srv"),
            (r"\\?\", r"\\?\"),
            (r"C:\ \x", r"C:\x"),
        ] {
            assert!(!same(a, b), "{a:?} vs {b:?}");
        }
    }

    #[test]
    fn same_win_path_uses_the_injected_comparison() {
        let never = |_: &[u16], _: &[u16]| false;
        assert!(!same_win_path(&w(r"C:\a"), &w(r"C:\a"), &never));
        let exact = |a: &[u16], b: &[u16]| a == b;
        assert!(same_win_path(&w(r"C:\a"), &w(r"\\?\C:\a"), &exact));
        assert!(!same_win_path(&w(r"C:\a"), &w(r"c:\a"), &exact));
    }

    #[test]
    fn split_win_path_keeps_unpaired_surrogates_literal() {
        // NTFS 檔名可以含不成對的 surrogate；照字面比較，不做 lossy 轉換
        let mut a = w(r"C:\x");
        a.push(0xD800);
        let mut b = w(r"\\?\C:\x");
        b.push(0xD800);
        let exact = |x: &[u16], y: &[u16]| x == y;
        assert!(same_win_path(&a, &b, &exact));
        let mut c = w(r"C:\x");
        c.push(0xDC00);
        assert!(!same_win_path(&a, &c, &exact));
    }

    /// 模擬 Win32 的回傳慣例：成功時回傳不含 NUL 的長度，太小時回傳所需大小（含 NUL）。
    fn fake_api(value: &[u16]) -> impl FnMut(&mut [u16]) -> io::Result<u32> + '_ {
        move |buf| {
            if buf.len() > value.len() {
                buf[..value.len()].copy_from_slice(value);
                buf[value.len()] = 0;
                Ok(u32::try_from(value.len()).unwrap())
            } else {
                Ok(u32::try_from(value.len() + 1).unwrap())
            }
        }
    }

    #[test]
    fn fill_wide_retries_with_the_reported_size() {
        let short = w(r"\\?\C:\x");
        assert_eq!(fill_wide(&mut fake_api(&short)).unwrap(), short);
        // 超過初始緩衝區（260）：依回報的大小重試一次
        let long: Vec<u16> = std::iter::repeat_n(u16::from(b'a'), 1000).collect();
        let mut calls = 0;
        let mut api = fake_api(&long);
        let got = fill_wide(&mut |buf| {
            calls += 1;
            api(buf)
        })
        .unwrap();
        assert_eq!(got, long);
        assert_eq!(calls, 2);
        // 剛好等於緩衝區大小的邊界
        for n in [259, 260, 261] {
            let v: Vec<u16> = std::iter::repeat_n(u16::from(b'b'), n).collect();
            assert_eq!(fill_wide(&mut fake_api(&v)).unwrap(), v, "{n}");
        }
    }

    #[test]
    fn fill_wide_fails_closed() {
        // API 失敗：錯誤原樣傳出
        let e =
            fill_wide(&mut |_| Err(io::Error::from(io::ErrorKind::PermissionDenied))).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
        // 回報的大小超過上限
        assert!(fill_wide(&mut |_| Ok(u32::MAX)).is_err());
        let too_big = u32::try_from(MAX_WIDE_PATH + 1).unwrap();
        assert!(fill_wide(&mut |_| Ok(too_big)).is_err());
        // 所需大小一直變大：重試有上限
        let mut calls = 0;
        let r = fill_wide(&mut |buf| {
            calls += 1;
            Ok(u32::try_from(buf.len() * 2).unwrap())
        });
        assert!(r.is_err());
        assert!(calls <= 4, "{calls}");
        // 回報「需要的大小」與目前相同（不合慣例）：不可原地無限重試
        let mut calls = 0;
        let r = fill_wide(&mut |buf| {
            calls += 1;
            Ok(u32::try_from(buf.len()).unwrap())
        });
        assert!(r.is_err());
        assert!(calls <= 4, "{calls}");
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

    /// Windows：以實際的 Win32 API 走一遍 strict 模式，涵蓋容易誤判的合法路徑。
    #[cfg(windows)]
    #[test]
    fn windows_strict_accepts_spaces_unicode_and_case_variants() {
        let base = temp_dir("win-names");
        let dir = base.join("含 空白 的資料夾").join("Backups 備份");
        let d = prepare_private_dir(&dir, true).unwrap();
        d.create_private_file("x.toml").unwrap();
        drop(d);
        // 輸入的大小寫與磁碟上不同（含磁碟代號）
        let upper = PathBuf::from(dir.to_string_lossy().to_uppercase());
        let lower = PathBuf::from(dir.to_string_lossy().to_lowercase());
        for p in [&upper, &lower] {
            prepare_private_dir(p, true).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
        }
        // 尾端分隔字元、`/` 與 verbatim 前綴
        let s = dir.to_string_lossy().to_string();
        for p in [format!(r"{s}\"), s.replace('\\', "/"), format!(r"\\?\{s}")] {
            prepare_private_dir(Path::new(&p), true).unwrap_or_else(|e| panic!("{p}: {e}"));
        }
        let _ = fs::remove_dir_all(&base);
    }

    #[cfg(windows)]
    fn short_path(p: &Path) -> PathBuf {
        use std::os::windows::ffi::{OsStrExt, OsStringExt};
        #[link(name = "kernel32")]
        extern "system" {
            fn GetShortPathNameW(long: *const u16, short: *mut u16, cch: u32) -> u32;
        }
        let mut src: Vec<u16> = p.as_os_str().encode_wide().collect();
        src.push(0);
        let out = fill_wide(&mut |buf| {
            let cch = u32::try_from(buf.len()).unwrap();
            // SAFETY: src 以 NUL 結尾；buf 可寫入 cch 個 u16。
            match unsafe { GetShortPathNameW(src.as_ptr(), buf.as_mut_ptr(), cch) } {
                0 => Err(io::Error::last_os_error()),
                n => Ok(n),
            }
        })
        .unwrap();
        PathBuf::from(std::ffi::OsString::from_wide(&out))
    }

    /// Windows：輸入路徑含 8.3 短檔名時，先展開成長檔名再比較，不可誤判。
    /// 磁碟區若停用 8.3 名稱，短名與長名相同，仍會以長名走一遍。
    #[cfg(windows)]
    #[test]
    fn windows_strict_accepts_short_8dot3_names() {
        let base = temp_dir("win-short");
        let long = base
            .join("Long Folder Name 長檔名")
            .join("another long name");
        fs::create_dir_all(&long).unwrap();
        let short = short_path(&long);
        eprintln!("short form: {}", short.display());
        if short == long {
            eprintln!("8.3 名稱在此磁碟區停用，短檔名情境未實際涵蓋");
        }
        let d = prepare_private_dir(&short.join("backups"), true)
            .unwrap_or_else(|e| panic!("{}: {e}", short.display()));
        d.create_private_file("x.toml").unwrap();
        assert!(long.join("backups").join("x.toml").exists());
        drop(d);
        // %TEMP% 本身也以短檔名形式給出（使用者名稱過長時系統常給 8.3 形式）
        let tmp_short = short_path(&base);
        prepare_private_dir(&tmp_short.join("t"), true)
            .unwrap_or_else(|e| panic!("{}: {e}", tmp_short.display()));
        let _ = fs::remove_dir_all(&base);
    }

    /// 測試結束（含 panic）時一定解除 subst。
    #[cfg(windows)]
    struct SubstGuard(String);

    #[cfg(windows)]
    impl Drop for SubstGuard {
        fn drop(&mut self) {
            let _ = std::process::Command::new("subst")
                .args([self.0.as_str(), "/D"])
                .output();
        }
    }

    /// Windows：以 subst 建立的磁碟代號，實際路徑會解析回原本的磁碟；根目錄以同一個 API
    /// 解析後兩邊一致，不可誤判。
    #[cfg(windows)]
    #[test]
    fn windows_strict_accepts_subst_drives() {
        let base = temp_dir("win-subst");
        let Some(letter) = ('M'..='Y')
            .rev()
            .map(|c| format!("{c}:"))
            .find(|d| !Path::new(&format!(r"{d}\")).exists())
        else {
            panic!("沒有可用的磁碟代號");
        };
        let out = std::process::Command::new("subst")
            .arg(&letter)
            .arg(&base)
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        let _guard = SubstGuard(letter.clone());
        let dir = PathBuf::from(format!(r"{letter}\sub\backups"));
        let d =
            prepare_private_dir(&dir, true).unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
        d.create_private_file("x.toml").unwrap();
        assert!(base.join("sub").join("backups").join("x.toml").exists());
        drop(d);
        // 佐證：subst 磁碟上的 handle 解析回原本的磁碟（因此預期路徑的根目錄必須以同一個 API 解析）
        let f = {
            use std::os::windows::fs::OpenOptionsExt;
            fs::OpenOptions::new()
                .read(true)
                .custom_flags(0x0200_0000) // FILE_FLAG_BACKUP_SEMANTICS
                .open(&dir)
                .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        };
        let real = imp::PathQuery::final_path(&imp::Win32Paths, &f).unwrap();
        let real = String::from_utf16_lossy(&real);
        eprintln!("subst {letter} -> final path {real}");
        assert!(!real.to_uppercase().contains(&letter), "{real}");
        drop(f);
        drop(_guard);
        let _ = fs::remove_dir_all(&base);
    }

    /// 包裝真正的 Win32 查詢；開啟 `target` 的 handle 時改回報另一個路徑或錯誤，
    /// 模擬「逐層檢查後、開啟前上層被換成 junction 又換回」使 handle 落在別處的情況。
    #[cfg(windows)]
    struct SwappedFinalPath {
        target: PathBuf,
        reported: Option<PathBuf>,
    }

    #[cfg(windows)]
    impl imp::PathQuery for SwappedFinalPath {
        fn final_path(&self, f: &File) -> io::Result<Vec<u16>> {
            let real = imp::PathQuery::final_path(&imp::Win32Paths, f)?;
            if !same_win_path(
                &real,
                &w(&self.target.to_string_lossy()),
                &imp::eq_ignore_case,
            ) {
                return Ok(real);
            }
            match &self.reported {
                Some(p) => Ok(w(&p.to_string_lossy())),
                None => Err(io::Error::other(
                    "simulated GetFinalPathNameByHandleW failure",
                )),
            }
        }

        fn long_path(&self, p: &Path) -> io::Result<Vec<u16>> {
            imp::PathQuery::long_path(&imp::Win32Paths, p)
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_strict_refuses_a_handle_that_resolves_elsewhere() {
        let base = temp_dir("win-swapped");
        let dir = base.join("a").join("backups");
        let victim = base.join("victim").join("backups");
        fs::create_dir_all(&victim).unwrap();
        // 實際落在別處（例如 junction 指向的位置）：拒絕
        let q = SwappedFinalPath {
            target: dir.clone(),
            reported: Some(victim.clone()),
        };
        let e = imp::prepare_private_dir_with(&dir, true, &q)
            .err()
            .expect("handle 不在預期路徑時必須失敗");
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied, "{e}");
        assert!(e.to_string().contains("resolves to"), "{e}");
        // 只差在前綴相同但較長的路徑：同樣拒絕
        let q = SwappedFinalPath {
            target: dir.clone(),
            reported: Some(dir.join("x")),
        };
        assert!(imp::prepare_private_dir_with(&dir, true, &q).is_err());
        // 取得實際路徑失敗：fail closed
        let q = SwappedFinalPath {
            target: dir.clone(),
            reported: None,
        };
        assert!(imp::prepare_private_dir_with(&dir, true, &q).is_err());
        // verbatim 形式的同一路徑：接受（確認比較不是靠字串完全相同）
        let q = SwappedFinalPath {
            target: dir.clone(),
            reported: Some(PathBuf::from(format!(r"\\?\{}", dir.display()))),
        };
        imp::prepare_private_dir_with(&dir, true, &q).unwrap();
        // 一般模式（未提權）不做這項檢查
        let q = SwappedFinalPath {
            target: dir.clone(),
            reported: Some(victim.clone()),
        };
        imp::prepare_private_dir_with(&dir, false, &q).unwrap();
        // 正式的查詢：實際路徑與預期一致
        prepare_private_dir(&dir, true).unwrap();
        let _ = fs::remove_dir_all(&base);
    }

    /// Windows：不靠注入，以真正的 junction 重現競爭成功後的結果——handle 是經由上層的
    /// junction 開啟的（落在 junction 指向的位置）。開啟後的路徑檢查必須拒絕它。
    #[cfg(windows)]
    #[test]
    fn windows_handle_opened_through_a_real_junction_is_detected() {
        use std::os::windows::fs::OpenOptionsExt;
        let base = temp_dir("win-junction-handle");
        let victim = base.join("victim");
        fs::create_dir_all(victim.join("sub")).unwrap();
        let junction = base.join("backups");
        let out = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&junction)
            .arg(&victim)
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        let through = junction.join("sub");
        let handle = fs::OpenOptions::new()
            .read(true)
            .custom_flags(0x0200_0000) // FILE_FLAG_BACKUP_SEMANTICS
            .open(&through)
            .unwrap();
        let e = imp::verify_opened_path(&through, &handle, &imp::Win32Paths).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied, "{e}");
        eprintln!("{e}");
        // 對照組：直接開啟真正的位置則通過
        let direct = victim.join("sub");
        let handle2 = fs::OpenOptions::new()
            .read(true)
            .custom_flags(0x0200_0000)
            .open(&direct)
            .unwrap();
        imp::verify_opened_path(&direct, &handle2, &imp::Win32Paths).unwrap();
        drop((handle, handle2));
        let _ = fs::remove_dir(&junction);
        let _ = fs::remove_dir_all(&base);
    }

    #[cfg(windows)]
    #[test]
    fn windows_eq_ignore_case_follows_the_os_table() {
        let eq = |a: &str, b: &str| imp::eq_ignore_case(&w(a), &w(b));
        assert!(eq("AppData", "APPDATA"));
        assert!(eq("äöü", "ÄÖÜ"));
        assert!(eq("σ", "Σ"));
        assert!(eq("資料夾", "資料夾"));
        assert!(!eq("ß", "SS"), "不做多字元展開");
        assert!(!eq("a", "b"));
        assert!(!eq("a", "ab"));
        assert!(eq("", ""));
    }

    #[test]
    fn strict_mode_requires_an_absolute_path() {
        assert!(prepare_private_dir(Path::new("relative/backups"), true).is_err());
    }
}
