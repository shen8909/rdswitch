//! Profile 儲存與套用。
//!
//! 套用方式依 RustDesk 的安裝型態而定：
//! - 已安裝為系統服務：執行中的服務行程把設定放在記憶體，只改檔案不會生效
//!   （實測：檔案已改，服務仍連舊伺服器）。必須用 `rustdesk --option`（需系統管理員/root）通知它。
//! - 免安裝/無服務：關閉 GUI -> 備份 -> 原子寫入設定檔 -> 重啟 GUI。

use crate::backup;
use crate::i18n::{tr, trf};
use crate::platform::{self, CONFIG_NAME};
use crate::tomledit::{self, Change};
use crate::validate::{self, Invalid};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

/// 欄位留空 = 回到官方預設。
#[derive(Serialize, Deserialize, Clone, Default, Debug, PartialEq)]
#[serde(default)]
pub struct Profile {
    pub name: String,
    pub server: String, // ID/Rendezvous 伺服器，例如 host:21116
    pub relay: String,
    pub api: String,
    pub key: String, // 公鑰
}

impl Profile {
    fn changes(&self) -> Vec<Change> {
        let opt = |v: &str| (!v.is_empty()).then(|| v.to_string());
        vec![
            Change {
                key: "custom-rendezvous-server",
                value: opt(&self.server),
            },
            Change {
                key: "relay-server",
                value: opt(&self.relay),
            },
            Change {
                key: "api-server",
                value: opt(&self.api),
            },
            Change {
                key: "key",
                value: opt(&self.key),
            },
        ]
    }
}

/// 內建的預設 profile（所有欄位留空 = RustDesk 官方預設），不存檔、不可修改或刪除。
pub const DEFAULT_NAME: &str = "Default";

pub fn is_default_name(name: &str) -> bool {
    name.trim().eq_ignore_ascii_case(DEFAULT_NAME)
}

pub fn default_profile() -> Profile {
    Profile {
        name: DEFAULT_NAME.into(),
        ..Default::default()
    }
}

impl Profile {
    fn is_empty_config(&self) -> bool {
        self.server.is_empty()
            && self.relay.is_empty()
            && self.api.is_empty()
            && self.key.is_empty()
    }
}

/// 欄位格式（白名單）。名稱以外的欄位可為空；套用前與儲存前都要檢查，
/// 因為 profiles.json 可能被其他程式或使用者直接修改。
fn validate_fields(p: &Profile) -> Result<(), String> {
    let msg = |e: Invalid, field: &str| {
        let key = match e {
            Invalid::Name => "err.invalid_name",
            Invalid::HostPort => "err.invalid_hostport",
            Invalid::Url => "err.invalid_url",
            Invalid::Key => "err.invalid_key",
        };
        trf(key, &[("field", field)])
    };
    validate::host_port(&p.server).map_err(|e| msg(e, "server"))?;
    validate::host_port(&p.relay).map_err(|e| msg(e, "relay"))?;
    validate::api_url(&p.api).map_err(|e| msg(e, "api"))?;
    validate::key(&p.key).map_err(|e| msg(e, "key"))
}

/// 儲存前的檢查：名稱與欄位格式；保留名稱 Default；欄位全空等同 Default，沒有存在意義。
fn validate(p: &Profile) -> Result<(), String> {
    validate::name(&p.name).map_err(|_| tr("err.invalid_name"))?;
    validate_fields(p)?;
    if is_default_name(&p.name) {
        return Err(trf("err.default_reserved", &[("name", DEFAULT_NAME)]));
    }
    if p.is_empty_config() {
        return Err(trf("err.empty_config", &[("name", DEFAULT_NAME)]));
    }
    Ok(())
}

fn profiles_path() -> PathBuf {
    platform::app_data_dir().join("profiles.json")
}

fn write_private(path: &Path, data: &str) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    fs::write(path, data).map_err(|e| {
        trf(
            "err.write_failed",
            &[
                ("path", &path.display().to_string()),
                ("err", &e.to_string()),
            ],
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600)); // 含公鑰，僅本人可讀
    }
    Ok(())
}

/// 使用者自訂的 profiles（不含內建的 Default）。
/// 舊版留下的「欄位全空」profile（例如 official）等同 Default，載入時略過。
pub fn load() -> Result<Vec<Profile>, String> {
    Ok(load_raw()?
        .into_iter()
        .filter(|p| !p.is_empty_config() && !is_default_name(&p.name))
        .collect())
}

/// Default 加上所有自訂 profiles。
pub fn all() -> Result<Vec<Profile>, String> {
    let mut v = vec![default_profile()];
    v.extend(load()?);
    Ok(v)
}

fn load_raw() -> Result<Vec<Profile>, String> {
    let raw = match fs::read_to_string(profiles_path()) {
        Ok(s) => s,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => return Err(e.to_string()),
    };
    if let Ok(v) = serde_json::from_str::<Vec<Profile>>(&raw) {
        return Ok(v);
    }
    // 相容舊格式 {名稱: {server,relay,api,key}}
    let legacy: HashMap<String, Profile> = serde_json::from_str(&raw)
        .map_err(|e| trf("err.profiles_format", &[("err", &e.to_string())]))?;
    let mut v: Vec<Profile> = legacy
        .into_iter()
        .map(|(name, p)| Profile { name, ..p })
        .collect();
    v.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(v)
}

fn save(mut ps: Vec<Profile>) -> Result<(), String> {
    ps.sort_by(|a, b| a.name.cmp(&b.name));
    write_private(
        &profiles_path(),
        &serde_json::to_string_pretty(&ps).unwrap(),
    )
}

pub fn find(name: &str) -> Result<Profile, String> {
    all()?
        .into_iter()
        .find(|p| p.name == name)
        .ok_or_else(|| trf("err.not_found", &[("name", name)]))
}

/// 儲存 profile。`old` 為 None 代表新增（名稱不可與現有的重複，避免無聲覆蓋）；
/// 為 Some(原名稱) 代表編輯，名稱可以更改，「我的最愛」會跟著改名。
pub fn save_as(old: Option<&str>, p: Profile) -> Result<(), String> {
    validate(&p)?;
    let mut ps = load()?;
    let exists = |n: &str, ps: &[Profile]| ps.iter().any(|x| x.name == n);
    match old {
        None => {
            if exists(&p.name, &ps) {
                return Err(trf("err.name_exists", &[("name", &p.name)]));
            }
            ps.push(p);
            save(ps)
        }
        Some(old) => {
            if is_default_name(old) {
                return Err(trf("err.default_no_edit", &[("name", DEFAULT_NAME)]));
            }
            let idx = ps
                .iter()
                .position(|x| x.name == old)
                .ok_or_else(|| trf("err.not_found", &[("name", old)]))?;
            if p.name != old && exists(&p.name, &ps) {
                return Err(trf("err.name_exists", &[("name", &p.name)]));
            }
            let new_name = p.name.clone();
            // 先讀最愛：讀不到就整個操作都不做，避免 profile 已改名、最愛卻沒跟上又回報失敗
            let fav_update = if new_name != old {
                renamed_favorite(&load_favorites()?, old, &new_name)
            } else {
                None
            };
            ps[idx] = p;
            save(ps)?;
            if let Some(fav) = fav_update {
                write_favorites(&fav)?;
            }
            Ok(())
        }
    }
}

/// 把最愛清單中的 `old` 改成 `new`；沒有變動時回傳 None。
fn renamed_favorite(fav: &[String], old: &str, new: &str) -> Option<Vec<String>> {
    fav.iter().any(|n| n == old).then(|| {
        fav.iter()
            .map(|n| if n == old { new.to_string() } else { n.clone() })
            .collect()
    })
}

pub fn delete(name: &str) -> Result<(), String> {
    if is_default_name(name) {
        return Err(trf("err.default_no_delete", &[("name", DEFAULT_NAME)]));
    }
    let mut ps = load()?;
    // 先讀最愛：讀不到就不刪除，避免 profile 已刪除卻回報失敗
    let fav = load_favorites()?;
    ps.retain(|p| p.name != name);
    save(ps)?;
    if fav.iter().any(|n| n == name) {
        let rest: Vec<String> = fav.into_iter().filter(|n| n != name).collect();
        write_favorites(&rest)?;
    }
    Ok(())
}

fn write_favorites(fav: &[String]) -> Result<(), String> {
    write_private(
        &favorites_path(),
        &serde_json::to_string_pretty(fav).unwrap(),
    )
}

// ---- 我的最愛（以名稱記錄，Default 也可以加入）----

fn favorites_path() -> PathBuf {
    platform::app_data_dir().join("favorites.json")
}

/// 檔案不存在視為沒有最愛；讀取或解析失敗必須回報，
/// 否則下一次寫入會用殘缺的清單蓋掉原本的檔案（資料遺失）。
pub fn load_favorites() -> Result<Vec<String>, String> {
    parse_favorites(read_optional(&favorites_path())?.as_deref())
}

fn parse_favorites(raw: Option<&str>) -> Result<Vec<String>, String> {
    match raw {
        None => Ok(vec![]),
        Some(s) => serde_json::from_str(s)
            .map_err(|e| trf("err.favorites_format", &[("err", &e.to_string())])),
    }
}

/// 讀取文字檔；不存在回傳 None，其他錯誤往上傳。
fn read_optional(path: &Path) -> Result<Option<String>, String> {
    match fs::read_to_string(path) {
        Ok(s) => Ok(Some(s)),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(trf(
            "err.read_failed",
            &[
                ("path", &path.display().to_string()),
                ("err", &e.to_string()),
            ],
        )),
    }
}

pub fn set_favorite(name: &str, on: bool) -> Result<(), String> {
    let mut fav = load_favorites()?;
    fav.retain(|n| n != name);
    if on {
        if !all()?.iter().any(|p| p.name == name) {
            return Err(trf("err.not_found", &[("name", name)]));
        }
        fav.push(name.to_string());
    }
    write_favorites(&fav)
}

fn user_config() -> PathBuf {
    platform::user_config_dir().join(CONFIG_NAME)
}

/// 目前生效的 ID 伺服器：已安裝服務且有權限時，向執行中的 RustDesk 詢問（設定檔可能與記憶體不一致）。
pub fn current_server() -> String {
    if platform::service_installed() && platform::is_elevated() {
        if let Some(v) = platform::rustdesk_get_option("custom-rendezvous-server") {
            return v;
        }
    }
    fs::read_to_string(user_config())
        .map(|t| tomledit::get_options(&t))
        .unwrap_or_default()
        .remove("custom-rendezvous-server")
        .unwrap_or_default()
}

/// 備份寫入器：備份資料夾位於使用者可寫的位置，以系統管理員/root 執行時採嚴格檢查。
fn with_backup_writer<T>(
    f: impl FnOnce(&backup::Writer) -> Result<T, String>,
) -> Result<T, String> {
    let dir = platform::app_data_dir().join("backups");
    f(&backup::Writer {
        dir: &dir,
        strict: platform::is_elevated(),
        now_secs: &backup::unix_now,
        nonce: &backup::os_random_u64,
    })
}

/// `tag` 區分來源（user/service）。來源不存在就略過；來源是 symlink/junction 時拒絕
/// （以管理員身分讀取使用者可控的連結，會把系統檔案內容複製到使用者看得到的位置）。
fn backup(cfg: &Path, tag: &str) -> Result<(), String> {
    let data = match platform::securefs::read_no_follow(cfg) {
        Ok(d) => d,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(trf(
                "err.backup_failed",
                &[
                    ("path", &cfg.display().to_string()),
                    ("err", &e.to_string()),
                ],
            ))
        }
    };
    with_backup_writer(|w| w.write(tag, &data)).map(|_| ())
}

/// 交給 root 腳本還原擁有者的路徑：上層資料夾先解析成不含 symlink 的實際路徑
/// （腳本會以 `pwd -P` 比對，路徑中有 symlink 就中止）。資料夾不存在時沿用原路徑（腳本會略過）。
fn owner_restore_path(cfg: &Path) -> Result<String, String> {
    let (Some(dir), Some(name)) = (cfg.parent(), cfg.file_name()) else {
        return Err(tr("err.elevate_bad_input"));
    };
    let real = match fs::canonicalize(dir) {
        Ok(d) => d.join(name),
        Err(e) if e.kind() == ErrorKind::NotFound => cfg.to_path_buf(),
        Err(e) => {
            return Err(trf(
                "err.read_failed",
                &[
                    ("path", &dir.display().to_string()),
                    ("err", &e.to_string()),
                ],
            ))
        }
    };
    Ok(real.to_string_lossy().to_string())
}

pub fn apply(p: &Profile) -> Result<(), String> {
    validate_fields(p)?; // 不信任 profiles.json 的內容
    if platform::service_installed() {
        apply_via_cli(p)
    } else {
        apply_via_file(p)
    }
}

/// 已安裝服務：以 `rustdesk --option` 通知執行中的服務，並讀回驗證。
fn apply_via_cli(p: &Profile) -> Result<(), String> {
    let elevated = platform::is_elevated();
    // 不是管理員時：macOS/Linux 可在切換當下跳出系統密碼視窗；Windows 則要求以管理員啟動
    if !elevated && !platform::can_elevate_on_demand() {
        return Err(tr("err.need_admin"));
    }
    let exe = platform::rustdesk_exe()?;
    let now = if elevated {
        backup(&user_config(), "user")?;
        backup(&platform::service_config_dir().join(CONFIG_NAME), "service")?;
        for c in p.changes() {
            platform::rustdesk_set_option(&exe, c.key, c.value.as_deref().unwrap_or(""))?;
        }
        platform::rustdesk_get_option("custom-rendezvous-server")
    } else {
        // 整批設定只問一次密碼。縮小 root 的作用面：root 不寫入任何使用者可寫的位置——
        // 使用者設定檔由本程式以一般權限先備份；服務設定只有 root 讀得到，
        // 由腳本印出後再由本程式寫成備份。以 root 執行 `rustdesk --option` 會把使用者的
        // RustDesk2.toml 寫成 root 擁有，腳本會在安全檢查後把擁有者還給目前使用者。
        backup(&user_config(), "user")?;
        with_backup_writer(|w| w.preflight())?; // 備份資料夾不安全就在變更之前取消
        let changes = p.changes();
        let pairs: Vec<(&str, &str)> = changes
            .iter()
            .map(|c| (c.key, c.value.as_deref().unwrap_or("")))
            .collect();
        let user_cfg = owner_restore_path(&user_config())?;
        let service_cfg = platform::service_config_dir()
            .join(CONFIG_NAME)
            .to_string_lossy()
            .to_string();
        let outcome = platform::rustdesk_set_options_elevated(
            &exe,
            &pairs,
            "custom-rendezvous-server",
            &[&service_cfg],
            &[&user_cfg],
        )?;
        // 走到這裡設定已經生效；備份失敗要明確告知，不可吞掉
        let after = |e: String| trf("err.backup_after_apply", &[("err", &e)]);
        let outcome = outcome.map_err(after)?;
        if let Some(Some(data)) = outcome.dumps.first() {
            with_backup_writer(|w| w.write("service", data)).map_err(after)?;
        }
        outcome.readback
    };
    // 讀回驗證（讀不到就略過，不誤報失敗）
    if let Some(now) = now {
        if now != p.server {
            return Err(trf(
                "err.mismatch",
                &[("now", &now), ("expected", &p.server)],
            ));
        }
    }
    Ok(())
}

/// 離開作用域時一定會重新啟動先前關閉的 GUI（含失敗的提早返回），避免使用者的 RustDesk 被關掉就不再開。
struct GuiRestart {
    stopped: Vec<String>,
    armed: bool,
}

impl GuiRestart {
    fn new(stopped: Vec<String>) -> Self {
        Self {
            stopped,
            armed: true,
        }
    }

    /// 正常流程：重啟並回報結果（呼叫端要讓使用者知道有沒有成功）。
    fn restart(mut self) -> Result<(), String> {
        self.armed = false;
        platform::start_gui(&self.stopped)
    }
}

impl Drop for GuiRestart {
    fn drop(&mut self) {
        if self.armed {
            if let Err(e) = platform::start_gui(&self.stopped) {
                eprintln!("重新啟動 RustDesk 失敗：{e}");
            }
        }
    }
}

/// 免安裝/無服務：關閉 GUI -> 備份 -> 原子寫入 -> 讀回驗證 -> 重新啟動 GUI。
/// GUI 一旦關閉，不論後續成功或失敗都會重新啟動；關不掉就取消，不改設定檔。
fn apply_via_file(p: &Profile) -> Result<(), String> {
    let cfg = user_config();
    // RustDesk 結束時會回寫設定，必須先確實關閉
    let stopped = match platform::stop_gui() {
        Ok(s) => s,
        Err(f) => {
            drop(GuiRestart::new(f.stopped)); // 已被關掉的部分要還原
            return Err(f.message);
        }
    };
    let gui = GuiRestart::new(stopped);
    write_config_file(&cfg, p, |c| backup(c, "user"))?;
    gui.restart()
        .map_err(|e| trf("err.start_gui_failed", &[("err", &e)]))
}

/// 備份 -> 寫暫存檔 -> 取代 -> 讀回驗證。失敗時會清掉暫存檔。
/// `backup_fn` 由呼叫端注入，讓這段邏輯可以在暫存資料夾裡測試。
fn write_config_file(
    cfg: &Path,
    p: &Profile,
    backup_fn: impl FnOnce(&Path) -> Result<(), String>,
) -> Result<(), String> {
    let old = read_optional(cfg)?.unwrap_or_default();
    backup_fn(cfg)?;
    if let Some(dir) = cfg.parent() {
        fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let tmp = cfg.with_extension("toml.tmp");
    let result = fs::write(&tmp, tomledit::set_options(&old, &p.changes()))
        .map_err(|e| {
            trf(
                "err.write_failed",
                &[
                    ("path", &tmp.display().to_string()),
                    ("err", &e.to_string()),
                ],
            )
        })
        .and_then(|()| {
            fs::rename(&tmp, cfg).map_err(|e| {
                trf(
                    "err.replace_failed",
                    &[
                        ("path", &cfg.display().to_string()),
                        ("err", &e.to_string()),
                    ],
                )
            })
        });
    if result.is_err() {
        let _ = fs::remove_file(&tmp); // 不留下殘缺的暫存檔
    }
    result?;
    verify_written(cfg, p)
}

/// 寫入後讀回，確認 ID 伺服器真的是預期的值（與 CLI 路徑的讀回驗證一致）。
fn verify_written(cfg: &Path, p: &Profile) -> Result<(), String> {
    let text = read_optional(cfg)?.unwrap_or_default();
    let now = tomledit::get_options(&text)
        .remove("custom-rendezvous-server")
        .unwrap_or_default();
    if now != p.server {
        return Err(trf(
            "err.mismatch",
            &[("now", &now), ("expected", &p.server)],
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(name: &str, server: &str) -> Profile {
        Profile {
            name: name.into(),
            server: server.into(),
            ..Default::default()
        }
    }

    #[test]
    fn default_is_reserved_and_immutable() {
        assert!(validate(&p("Default", "x:1")).is_err());
        assert!(validate(&p("  default ", "x:1")).is_err()); // 不分大小寫、忽略空白
        assert!(delete("Default").is_err());
        assert!(delete("DEFAULT").is_err());
    }

    #[test]
    fn invalid_fields_are_rejected() {
        let mut bad = p("lab", "192.0.2.1:21116");
        assert!(validate(&bad).is_ok());
        bad.server = "host
relay-server = 'evil'"
            .into();
        assert!(validate(&bad).is_err());
        bad = p("lab", "h:1");
        bad.api = "javascript:alert(1)".into();
        assert!(validate(&bad).is_err());
        bad = p("lab", "h:1");
        bad.key = "k
[x]"
        .into();
        assert!(validate(&bad).is_err());
        assert!(validate(&p(
            "a
b", "h:1"
        ))
        .is_err());
        // apply 與儲存都共用 validate_fields（profiles.json 可能被外部改過）；
        // 這裡直接測驗證函式，避免測試真的去關閉使用者的 RustDesk
        assert!(validate_fields(&p("lab", "bad host")).is_err());
    }

    #[test]
    fn empty_profile_is_rejected() {
        assert!(validate(&p("lab", "")).is_err());
        assert!(validate(&p("lab", "192.0.2.1")).is_ok());
    }

    /// 在暫存資料夾驗證存檔相關行為（不碰真實的使用者資料）。
    #[test]
    fn favorites_and_default_roundtrip() {
        let tmp = std::env::temp_dir().join(format!("rdswitch-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();
        for k in ["APPDATA", "XDG_CONFIG_HOME", "HOME", "USERPROFILE"] {
            std::env::set_var(k, &tmp);
        }
        let names = || {
            all()
                .unwrap()
                .into_iter()
                .map(|p| p.name)
                .collect::<Vec<_>>()
        };

        assert_eq!(names(), ["Default"]); // 一開始只有內建的 Default

        save_as(None, p("lab", "192.0.2.1:21116")).unwrap();
        assert!(save_as(None, p("Default", "x:1")).is_err());
        assert!(save_as(None, p("lab", "192.0.2.9:1")).is_err()); // 新增不可無聲覆蓋同名項目
        assert_eq!(names(), ["Default", "lab"]);

        set_favorite("Default", true).unwrap();
        set_favorite("lab", true).unwrap();
        assert_eq!(load_favorites().unwrap(), ["Default", "lab"]);
        assert!(set_favorite("nope", true).is_err());

        set_favorite("Default", false).unwrap();
        assert_eq!(load_favorites().unwrap(), ["lab"]);

        // 改名：最愛跟著改名、內容保留；不可改成 Default 或與其他項目重名
        save_as(None, p("other", "192.0.2.5:1")).unwrap();
        assert!(save_as(Some("lab"), p("other", "192.0.2.1:21116")).is_err());
        assert!(save_as(Some("lab"), p("default", "192.0.2.1:21116")).is_err());
        assert!(save_as(Some("Default"), p("x", "192.0.2.1:21116")).is_err());
        save_as(Some("lab"), p("實驗室", "192.0.2.1:21116")).unwrap();
        assert_eq!(names(), ["Default", "other", "實驗室"]);
        assert_eq!(load_favorites().unwrap(), ["實驗室"]);
        assert_eq!(find("實驗室").unwrap().server, "192.0.2.1:21116");
        save_as(Some("實驗室"), p("實驗室", "192.0.2.7:1")).unwrap(); // 名稱不變只改內容
        assert_eq!(find("實驗室").unwrap().server, "192.0.2.7:1");
        delete("other").unwrap();
        assert!(find("lab").is_err());

        delete("實驗室").unwrap(); // 刪除 profile 時一併移出最愛
        assert!(load_favorites().unwrap().is_empty());
        assert_eq!(names(), ["Default"]);

        // 舊版遺留的「欄位全空」profile（例如 official）等同 Default，載入時略過
        fs::write(profiles_path(), r#"{"official":{}, "x":{"server":"a:1"}}"#).unwrap();
        assert_eq!(names(), ["Default", "x"]);

        // favorites.json 損毀時，刪除與改名都必須整個不做（不可留下做了一半的變更）
        save_as(None, p("keep", "192.0.2.3:1")).unwrap();
        fs::write(favorites_path(), "{壞掉").unwrap();
        assert!(delete("keep").is_err());
        assert!(find("keep").is_ok());
        assert!(save_as(Some("keep"), p("keep2", "192.0.2.3:1")).is_err());
        assert!(find("keep").is_ok() && find("keep2").is_err());

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn favorite_rename_helper() {
        let fav = vec!["a".to_string(), "b".to_string()];
        assert_eq!(renamed_favorite(&fav, "a", "c").unwrap(), ["c", "b"]);
        assert!(renamed_favorite(&fav, "x", "c").is_none());
    }

    #[test]
    fn favorites_parse_does_not_swallow_errors() {
        assert_eq!(parse_favorites(None).unwrap(), Vec::<String>::new()); // 不存在 = 沒有最愛
        assert_eq!(parse_favorites(Some(r#"["a","b"]"#)).unwrap(), ["a", "b"]);
        assert!(parse_favorites(Some("{壞掉")).is_err()); // 損毀要回報，不可當成空清單
        assert!(parse_favorites(Some(r#"{"a":1}"#)).is_err());
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("rdswitch-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn write_config_file_updates_backs_up_and_verifies() {
        let dir = temp_dir("write-ok");
        let cfg = dir.join(CONFIG_NAME);
        fs::write(
            &cfg,
            "[options]
key = 'old'
",
        )
        .unwrap();
        let mut backed_up = false;
        write_config_file(&cfg, &p("lab", "192.0.2.1:21116"), |c| {
            backed_up = c == cfg;
            Ok(())
        })
        .unwrap();
        assert!(backed_up);
        let o = tomledit::get_options(&fs::read_to_string(&cfg).unwrap());
        assert_eq!(o["custom-rendezvous-server"], "192.0.2.1:21116");
        assert!(!o.contains_key("key")); // 空欄位 = 移除
        assert!(!cfg.with_extension("toml.tmp").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_config_file_aborts_when_backup_fails_and_leaves_file_untouched() {
        let dir = temp_dir("write-bkfail");
        let cfg = dir.join(CONFIG_NAME);
        fs::write(
            &cfg,
            "[options]
key = 'old'
",
        )
        .unwrap();
        let r = write_config_file(&cfg, &p("lab", "h:1"), |_| Err("備份壞了".into()));
        assert_eq!(r.unwrap_err(), "備份壞了");
        assert_eq!(
            fs::read_to_string(&cfg).unwrap(),
            "[options]
key = 'old'
"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_config_file_cleans_tmp_when_replace_fails() {
        let dir = temp_dir("write-replace");
        // 目標是「資料夾」，rename 檔案到資料夾上會失敗
        let cfg = dir.join(CONFIG_NAME);
        fs::create_dir_all(cfg.join("sub")).unwrap();
        let r = write_config_file(&cfg, &p("lab", "h:1"), |_| Ok(()));
        assert!(r.is_err());
        assert!(!cfg.with_extension("toml.tmp").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_written_detects_mismatch() {
        let dir = temp_dir("verify");
        let cfg = dir.join(CONFIG_NAME);
        fs::write(
            &cfg,
            "[options]
custom-rendezvous-server = 'other:1'
",
        )
        .unwrap();
        assert!(verify_written(&cfg, &p("lab", "h:1")).is_err());
        assert!(verify_written(&cfg, &p("lab", "other:1")).is_ok());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn default_profile_is_empty_config() {
        let d = default_profile();
        assert_eq!(d.name, "Default");
        assert!(d.is_empty_config());
    }
}

#[cfg(test)]
mod e2e {
    use super::*;
    use std::time::Duration;

    /// 真實驗證（需以系統管理員/root 執行，且會暫時改動真實的 RustDesk 設定）：
    /// 切到 RDS_E2E_PROFILE 指定的 profile，確認 RustDesk 回報已採用，最後切回原設定。
    #[test]
    #[ignore]
    fn switch_real_profile_and_restore() {
        let name = std::env::var("RDS_E2E_PROFILE").expect("set RDS_E2E_PROFILE");
        let target = find(&name).expect("profile");
        let opts = fs::read_to_string(user_config())
            .map(|t| tomledit::get_options(&t))
            .unwrap_or_default();
        let get = |k: &str| opts.get(k).cloned().unwrap_or_default();
        let orig = Profile {
            name: "orig".into(),
            server: get("custom-rendezvous-server"),
            relay: get("relay-server"),
            api: get("api-server"),
            key: get("key"),
        };

        let r = apply(&target);
        let during = current_server();
        println!("切換後 RustDesk 回報的伺服器：{during}");
        std::thread::sleep(Duration::from_secs(10));
        let back = apply(&orig);
        let after = current_server();
        println!("還原後 RustDesk 回報的伺服器：{after}");

        r.expect("apply target");
        back.expect("restore");
        assert_eq!(during, target.server);
        assert_eq!(after, orig.server);
    }

    /// 需以系統管理員執行：開機自動啟動排程工作的建立/查詢/刪除。
    /// 排程只允許指向 Program Files 內的執行檔；測試執行檔在 target 資料夾，
    /// 因此這裡驗證的是「拒絕建立、且不留下排程工作」，刪除流程照常驗證。
    #[cfg(windows)]
    #[test]
    #[ignore]
    fn autostart_task_roundtrip() {
        assert!(!platform::autostart_enabled(), "測試前不應已存在排程工作");
        assert!(
            platform::set_autostart(true).is_err(),
            "不安全的位置必須拒絕"
        );
        assert!(!platform::autostart_enabled());
        platform::set_autostart(false).expect("delete");
        assert!(!platform::autostart_enabled());
    }
}
