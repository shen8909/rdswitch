//! 「要交給 root 執行的程式」是否可信的判斷。
//!
//! 全是純函式：檔案系統的查詢（`stat`、`canonicalize`）由呼叫端注入，
//! 因此在任何平台（含 Windows）都能以假資料測試，實際的 Unix 查詢在 platform.rs。
//!
//! 規則（任何一項不符就拒絕，fail closed）：
//! - 只接受固定白名單位置，不從 PATH 尋找；解析 symlink 後的實際路徑也必須在白名單內。
//! - 執行檔是一般檔案、擁有者為 root、group/other 不可寫、至少有一個執行位元。
//! - 執行檔所在的每一層目錄都是真的目錄、擁有者為 root、group/other 不可寫
//!   （否則可被改名或替換，等同可替換執行檔）。

use std::io;
use std::path::{Path, PathBuf};

/// Linux：提權執行的 rustdesk 只接受這些位置（官方 deb/rpm/AppImage 安裝位置）。
/// macOS 沒有白名單：/Applications 是 root:admin 0775、App 通常屬於使用者本人，
/// 無法滿足「整條路徑由 root 擁有且他人不可寫」，因此 macOS 不以 root 執行 RustDesk。
pub const LINUX_RUSTDESK: &[&str] = &[
    "/usr/bin/rustdesk",
    "/usr/share/rustdesk/rustdesk",
    "/opt/rustdesk/rustdesk",
];

/// 不跟隨 symlink 取得的檔案種類。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    File,
    Dir,
    Symlink,
    Other,
}

/// 判斷所需的最少檔案資訊（相當於 `lstat` 的結果）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeFacts {
    pub kind: NodeKind,
    pub uid: u32,
    pub mode: u32,
}

/// 不可信的原因；呼叫端轉成使用者看得懂的訊息。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Untrusted {
    /// 解析後的實際路徑不在白名單內（例如 symlink 指到別處）。
    NotWhitelisted(PathBuf),
    NotRegularFile(PathBuf),
    NotDirectory(PathBuf),
    NotRootOwned(PathBuf),
    WritableByOthers(PathBuf),
    NotExecutable(PathBuf),
    /// 查詢失敗（權限不足等）；無法確認就視為不可信。
    Unreadable(PathBuf, String),
}

impl Untrusted {
    pub fn path(&self) -> &Path {
        match self {
            Self::NotWhitelisted(p)
            | Self::NotRegularFile(p)
            | Self::NotDirectory(p)
            | Self::NotRootOwned(p)
            | Self::WritableByOthers(p)
            | Self::NotExecutable(p)
            | Self::Unreadable(p, _) => p,
        }
    }

    /// 給使用者看的簡短原因（英文技術描述，放進翻譯字串的 {reason}）。
    pub fn reason(&self) -> String {
        match self {
            Self::NotWhitelisted(_) => "resolved path is not an allowed location".into(),
            Self::NotRegularFile(_) => "not a regular file".into(),
            Self::NotDirectory(_) => "not a directory".into(),
            Self::NotRootOwned(_) => "not owned by root".into(),
            Self::WritableByOthers(_) => "writable by group or others".into(),
            Self::NotExecutable(_) => "not executable".into(),
            Self::Unreadable(_, e) => format!("cannot inspect: {e}"),
        }
    }
}

/// 群組或其他人可寫入的權限位元。
const GROUP_OTHER_WRITE: u32 = 0o022;
/// 任何人可執行的權限位元。
const ANY_EXEC: u32 = 0o111;

fn check_node(path: &Path, f: NodeFacts, want: NodeKind) -> Result<(), Untrusted> {
    let p = || path.to_path_buf();
    if f.kind != want {
        return Err(match want {
            NodeKind::Dir => Untrusted::NotDirectory(p()),
            _ => Untrusted::NotRegularFile(p()),
        });
    }
    if f.uid != 0 {
        return Err(Untrusted::NotRootOwned(p()));
    }
    if f.mode & GROUP_OTHER_WRITE != 0 {
        return Err(Untrusted::WritableByOthers(p()));
    }
    if want == NodeKind::File && f.mode & ANY_EXEC == 0 {
        return Err(Untrusted::NotExecutable(p()));
    }
    Ok(())
}

/// 檢查執行檔本身與它的每一層上層目錄。`path` 必須是已解析 symlink 的絕對路徑，
/// `lstat` 不得跟隨 symlink（路徑中出現 symlink 就會因種類不符而被拒絕）。
pub fn check_root_owned_chain(
    path: &Path,
    lstat: &dyn Fn(&Path) -> io::Result<NodeFacts>,
) -> Result<(), Untrusted> {
    let stat =
        |p: &Path| lstat(p).map_err(|e| Untrusted::Unreadable(p.to_path_buf(), e.to_string()));
    check_node(path, stat(path)?, NodeKind::File)?;
    for dir in path.ancestors().skip(1) {
        if dir.as_os_str().is_empty() {
            break;
        }
        check_node(dir, stat(dir)?, NodeKind::Dir)?;
    }
    Ok(())
}

/// 尋找可信的 RustDesk 執行檔。
/// - 回傳 `Ok(Some(實際路徑))`：找到且通過所有檢查；呼叫端應執行回傳的實際路徑。
/// - 回傳 `Ok(None)`：白名單位置都不存在（沒有安裝）。
/// - 回傳 `Err`：某個位置存在但不可信——直接拒絕，不改試下一個（fail closed）。
pub fn find_trusted_exe(
    candidates: &[&str],
    canonicalize: &dyn Fn(&Path) -> io::Result<PathBuf>,
    lstat: &dyn Fn(&Path) -> io::Result<NodeFacts>,
) -> Result<Option<PathBuf>, Untrusted> {
    for c in candidates {
        let candidate = Path::new(c);
        let real = match canonicalize(candidate) {
            Ok(p) => p,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => {
                return Err(Untrusted::Unreadable(
                    candidate.to_path_buf(),
                    e.to_string(),
                ))
            }
        };
        if !candidates.iter().any(|w| Path::new(w) == real) {
            return Err(Untrusted::NotWhitelisted(real));
        }
        check_root_owned_chain(&real, lstat)?;
        return Ok(Some(real));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const ROOT_DIR: NodeFacts = NodeFacts {
        kind: NodeKind::Dir,
        uid: 0,
        mode: 0o40755,
    };
    const ROOT_EXE: NodeFacts = NodeFacts {
        kind: NodeKind::File,
        uid: 0,
        mode: 0o100755,
    };

    /// 以表格模擬的檔案系統：未列出的路徑視為不存在。
    struct FakeFs {
        nodes: HashMap<PathBuf, NodeFacts>,
        links: HashMap<PathBuf, PathBuf>,
    }

    impl FakeFs {
        /// 預設：/、/usr、/usr/bin、/usr/share、/usr/share/rustdesk、/opt 都是 root 擁有的 0755 目錄。
        fn new() -> Self {
            let mut nodes = HashMap::new();
            for d in [
                "/",
                "/usr",
                "/usr/bin",
                "/usr/share",
                "/usr/share/rustdesk",
                "/opt",
            ] {
                nodes.insert(PathBuf::from(d), ROOT_DIR);
            }
            Self {
                nodes,
                links: HashMap::new(),
            }
        }
        fn set(mut self, p: &str, f: NodeFacts) -> Self {
            self.nodes.insert(PathBuf::from(p), f);
            self
        }
        fn link(mut self, from: &str, to: &str) -> Self {
            self.links.insert(PathBuf::from(from), PathBuf::from(to));
            self
        }
        fn lstat(&self, p: &Path) -> io::Result<NodeFacts> {
            self.nodes
                .get(p)
                .copied()
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
        }
        fn canonicalize(&self, p: &Path) -> io::Result<PathBuf> {
            if let Some(t) = self.links.get(p) {
                return Ok(t.clone());
            }
            self.lstat(p).map(|_| p.to_path_buf())
        }
        fn find(&self) -> Result<Option<PathBuf>, Untrusted> {
            find_trusted_exe(LINUX_RUSTDESK, &|p| self.canonicalize(p), &|p| {
                self.lstat(p)
            })
        }
    }

    #[test]
    fn accepts_root_owned_exe_in_root_owned_dirs() {
        let fs = FakeFs::new().set("/usr/bin/rustdesk", ROOT_EXE);
        assert_eq!(fs.find(), Ok(Some(PathBuf::from("/usr/bin/rustdesk"))));
    }

    #[test]
    fn not_installed_is_none_not_error() {
        assert_eq!(FakeFs::new().find(), Ok(None));
    }

    #[test]
    fn symlink_inside_whitelist_resolves_to_the_real_file() {
        // deb 套件：/usr/bin/rustdesk -> /usr/share/rustdesk/rustdesk
        let fs = FakeFs::new()
            .set("/usr/share/rustdesk/rustdesk", ROOT_EXE)
            .link("/usr/bin/rustdesk", "/usr/share/rustdesk/rustdesk");
        assert_eq!(
            fs.find(),
            Ok(Some(PathBuf::from("/usr/share/rustdesk/rustdesk")))
        );
    }

    #[test]
    fn symlink_pointing_outside_the_whitelist_is_rejected() {
        let fs = FakeFs::new()
            .set("/tmp/evil", ROOT_EXE)
            .link("/usr/bin/rustdesk", "/tmp/evil");
        assert_eq!(
            fs.find(),
            Err(Untrusted::NotWhitelisted(PathBuf::from("/tmp/evil")))
        );
    }

    #[test]
    fn user_owned_or_writable_exe_is_rejected_without_trying_the_next_candidate() {
        let user_owned = NodeFacts {
            uid: 1000,
            ..ROOT_EXE
        };
        let fs = FakeFs::new()
            .set("/usr/bin/rustdesk", user_owned)
            .set("/opt/rustdesk", ROOT_DIR)
            .set("/opt/rustdesk/rustdesk", ROOT_EXE);
        assert_eq!(
            fs.find(),
            Err(Untrusted::NotRootOwned(PathBuf::from("/usr/bin/rustdesk")))
        );
        for mode in [0o100775, 0o100757, 0o100777] {
            let fs = FakeFs::new().set("/usr/bin/rustdesk", NodeFacts { mode, ..ROOT_EXE });
            assert_eq!(
                fs.find(),
                Err(Untrusted::WritableByOthers(PathBuf::from(
                    "/usr/bin/rustdesk"
                ))),
                "{mode:o}"
            );
        }
    }

    #[test]
    fn non_executable_or_non_regular_file_is_rejected() {
        let fs = FakeFs::new().set(
            "/usr/bin/rustdesk",
            NodeFacts {
                mode: 0o100644,
                ..ROOT_EXE
            },
        );
        assert!(matches!(fs.find(), Err(Untrusted::NotExecutable(_))));
        let fs = FakeFs::new().set(
            "/usr/bin/rustdesk",
            NodeFacts {
                kind: NodeKind::Dir,
                ..ROOT_EXE
            },
        );
        assert!(matches!(fs.find(), Err(Untrusted::NotRegularFile(_))));
    }

    #[test]
    fn writable_or_user_owned_parent_directory_is_rejected() {
        // /opt/rustdesk 由一般使用者擁有：可把執行檔改名替換
        let fs = FakeFs::new()
            .set(
                "/opt/rustdesk",
                NodeFacts {
                    uid: 1000,
                    ..ROOT_DIR
                },
            )
            .set("/opt/rustdesk/rustdesk", ROOT_EXE);
        assert_eq!(
            fs.find(),
            Err(Untrusted::NotRootOwned(PathBuf::from("/opt/rustdesk")))
        );
        // /opt 對 group 可寫
        let fs = FakeFs::new()
            .set(
                "/opt",
                NodeFacts {
                    mode: 0o40775,
                    ..ROOT_DIR
                },
            )
            .set("/opt/rustdesk", ROOT_DIR)
            .set("/opt/rustdesk/rustdesk", ROOT_EXE);
        assert_eq!(
            fs.find(),
            Err(Untrusted::WritableByOthers(PathBuf::from("/opt")))
        );
    }

    #[test]
    fn symlinked_parent_directory_is_rejected() {
        // 解析後的路徑中仍出現 symlink（不應發生），lstat 看到的種類不是目錄就拒絕
        let fs = FakeFs::new()
            .set(
                "/opt/rustdesk",
                NodeFacts {
                    kind: NodeKind::Symlink,
                    ..ROOT_DIR
                },
            )
            .set("/opt/rustdesk/rustdesk", ROOT_EXE);
        assert_eq!(
            fs.find(),
            Err(Untrusted::NotDirectory(PathBuf::from("/opt/rustdesk")))
        );
    }

    #[test]
    fn inspection_errors_fail_closed() {
        let denied = |_: &Path| -> io::Result<PathBuf> {
            Err(io::Error::from(io::ErrorKind::PermissionDenied))
        };
        let r = find_trusted_exe(LINUX_RUSTDESK, &denied, &|_| {
            Err(io::Error::from(io::ErrorKind::PermissionDenied))
        });
        assert!(matches!(r, Err(Untrusted::Unreadable(..))));
        // 執行檔可讀，但上層目錄 stat 失敗
        let r = check_root_owned_chain(Path::new("/usr/bin/rustdesk"), &|p| {
            if p == Path::new("/usr/bin/rustdesk") {
                Ok(ROOT_EXE)
            } else {
                Err(io::Error::from(io::ErrorKind::PermissionDenied))
            }
        });
        assert!(matches!(r, Err(Untrusted::Unreadable(..))));
    }

    #[test]
    fn untrusted_reports_path_and_reason() {
        let u = Untrusted::WritableByOthers(PathBuf::from("/opt"));
        assert_eq!(u.path(), Path::new("/opt"));
        assert!(u.reason().contains("writable"));
    }
}
