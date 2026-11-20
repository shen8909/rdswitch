//! 設定檔備份的寫入。
//!
//! 備份資料夾位於使用者可寫的位置，但寫入者可能是系統管理員/root，所以：
//! - 檔名含不可預測的隨機成分（密碼學安全亂數），無法事先放好同名的 symlink 或檔案；
//! - 一律 create_new，已存在就失敗（不覆蓋、不跟隨 symlink/junction）；
//! - 資料夾與檔案的安全檢查交給 `platform::securefs`（作業系統相依的部分）。
//!
//! 時間與亂數由呼叫端注入，方便測試。

use crate::i18n::trf;
use crate::platform::{securefs, CONFIG_NAME};
use std::io::Write;
use std::path::{Path, PathBuf};

/// 備份來源標籤（user / service）只允許小寫英文字母，避免影響檔名。
fn valid_tag(tag: &str) -> bool {
    !tag.is_empty() && tag.len() <= 16 && tag.bytes().all(|b| b.is_ascii_lowercase())
}

/// 備份檔名：`<秒數>-<16 位十六進位亂數>-<標籤>-RustDesk2.toml`。
pub fn file_name(ts: u64, nonce: u64, tag: &str) -> Option<String> {
    valid_tag(tag).then(|| format!("{ts}-{nonce:016x}-{tag}-{CONFIG_NAME}"))
}

/// 由作業系統的密碼學安全亂數來源取得 64 位元亂數。
pub fn os_random_u64() -> Result<u64, String> {
    let mut b = [0u8; 8];
    getrandom::fill(&mut b).map_err(|e| e.to_string())?;
    Ok(u64::from_le_bytes(b))
}

/// 目前時間（Unix 秒數）；時鐘早於 1970 時為 0（只影響檔名排序，不影響唯一性）。
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

/// 備份寫入器。
pub struct Writer<'a> {
    pub dir: &'a Path,
    /// 以系統管理員/root 執行時為 true：整條路徑都不得有 symlink/junction。
    pub strict: bool,
    pub now_secs: &'a dyn Fn() -> u64,
    pub nonce: &'a dyn Fn() -> Result<u64, String>,
}

impl Writer<'_> {
    fn err(&self, path: &Path, e: impl ToString) -> String {
        trf(
            "err.backup_write_failed",
            &[
                ("path", &path.display().to_string()),
                ("err", &e.to_string()),
            ],
        )
    }

    /// 事前檢查：亂數來源可用、備份資料夾存在且安全。用在「之後才能寫備份」的流程，
    /// 讓可預期的失敗發生在變更之前。實際寫入時 `write` 仍會重新檢查。
    pub fn preflight(&self) -> Result<(), String> {
        (self.nonce)()?;
        securefs::prepare_private_dir(self.dir, self.strict)
            .map(|_| ())
            .map_err(|e| self.err(self.dir, e))
    }

    /// 寫入一份新的備份；回傳備份檔路徑。失敗時不留下殘缺的檔案。
    pub fn write(&self, tag: &str, data: &[u8]) -> Result<PathBuf, String> {
        let name = file_name((self.now_secs)(), (self.nonce)()?, tag)
            .ok_or_else(|| self.err(self.dir, "invalid tag"))?;
        let _dir = securefs::prepare_private_dir(self.dir, self.strict)
            .map_err(|e| self.err(self.dir, e))?;
        let path = self.dir.join(name);
        let mut f = securefs::create_private_file(&path).map_err(|e| self.err(&path, e))?;
        if let Err(e) = f.write_all(data).and_then(|()| f.sync_all()) {
            drop(f);
            let _ = std::fs::remove_file(&path); // 只會是剛剛 create_new 建立的檔案
            return Err(self.err(&path, e));
        }
        Ok(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::fs;

    fn temp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("rds-backup-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn file_name_has_random_part_and_rejects_bad_tags() {
        assert_eq!(
            file_name(1700000000, 0xab, "user").unwrap(),
            "1700000000-00000000000000ab-user-RustDesk2.toml"
        );
        for bad in ["", "User", "a/b", "..", "a-b", "x\n", "abcdefghijklmnopq"] {
            assert!(file_name(1, 1, bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn os_random_is_not_constant() {
        let a = os_random_u64().unwrap();
        let b = os_random_u64().unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn writes_unique_backups_in_the_same_second() {
        let dir = temp_dir("unique");
        let w = Writer {
            dir: &dir,
            strict: false,
            now_secs: &|| 42,
            nonce: &os_random_u64,
        };
        let a = w.write("user", b"A").unwrap();
        let b = w.write("user", b"B").unwrap();
        assert_ne!(a, b);
        assert_eq!(fs::read(&a).unwrap(), b"A");
        assert_eq!(fs::read(&b).unwrap(), b"B");
        assert!(a.starts_with(&dir));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn existing_file_with_the_same_name_is_never_overwritten() {
        let dir = temp_dir("collide");
        let w = Writer {
            dir: &dir,
            strict: false,
            now_secs: &|| 1,
            nonce: &|| Ok(7),
        };
        let first = w.write("service", b"original").unwrap();
        assert!(w.write("service", b"attacker").is_err());
        assert_eq!(fs::read(&first).unwrap(), b"original");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn random_source_failure_fails_closed() {
        let dir = temp_dir("rng");
        let calls = Cell::new(0);
        let w = Writer {
            dir: &dir,
            strict: false,
            now_secs: &|| 1,
            nonce: &|| {
                calls.set(calls.get() + 1);
                Err("no entropy".into())
            },
        };
        assert!(w.write("user", b"x").is_err());
        assert!(w.preflight().is_err());
        assert_eq!(calls.get(), 2);
        assert!(!dir.exists(), "亂數失敗時不應建立任何東西");
    }

    #[test]
    fn preflight_creates_the_dir_without_writing_files() {
        let dir = temp_dir("preflight");
        let w = Writer {
            dir: &dir,
            strict: false,
            now_secs: &|| 5,
            nonce: &|| Ok(0xff),
        };
        w.preflight().unwrap();
        assert!(dir.is_dir());
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 0);
        let p = w.write("user", b"x").unwrap();
        assert_eq!(
            p.file_name().unwrap(),
            "5-00000000000000ff-user-RustDesk2.toml"
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
