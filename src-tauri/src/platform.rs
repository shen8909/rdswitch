//! 平台設定適配層：所有「作業系統不同」的知識都集中在這個檔案，
//! 其餘模組不得自行判斷作業系統。

use crate::elevate;
use crate::i18n::{tr, trf};
#[cfg(unix)]
use crate::trust;
use std::env;
use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

pub const CONFIG_NAME: &str = "RustDesk2.toml";

/// 建立子行程指令；Windows 下不彈出主控台視窗。
#[allow(unused_mut)]
fn command(program: &str) -> Command {
    let mut c = Command::new(program);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        c.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    c
}

fn env_path(key: &str) -> PathBuf {
    env::var_os(key).map(PathBuf::from).unwrap_or_default()
}

fn home() -> PathBuf {
    let key = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    env_path(key)
}

fn xdg_config() -> PathBuf {
    match env::var_os("XDG_CONFIG_HOME") {
        Some(v) if !v.is_empty() => PathBuf::from(v),
        _ => home().join(".config"),
    }
}

/// 目前使用者的 RustDesk 設定目錄（GUI 使用）。
pub fn user_config_dir() -> PathBuf {
    if cfg!(windows) {
        env_path("APPDATA").join("RustDesk").join("config")
    } else if cfg!(target_os = "macos") {
        home().join("Library/Preferences/com.carriez.RustDesk")
    } else {
        xdg_config().join("rustdesk")
    }
}

/// RustDesk 背景服務的設定目錄（需系統管理員/root 才能寫入）。
pub fn service_config_dir() -> PathBuf {
    if cfg!(windows) {
        let win = env::var_os("SystemRoot")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
        win.join("ServiceProfiles/LocalService/AppData/Roaming/RustDesk/config")
    } else if cfg!(target_os = "macos") {
        PathBuf::from("/var/root/Library/Preferences/com.carriez.RustDesk")
    } else {
        PathBuf::from("/root/.config/rustdesk")
    }
}

/// 本工具自己的資料目錄（profiles、設定、備份）。
pub fn app_data_dir() -> PathBuf {
    if cfg!(windows) {
        env_path("APPDATA").join("rdswitch")
    } else if cfg!(target_os = "macos") {
        home().join("Library/Application Support/rdswitch")
    } else {
        xdg_config().join("rdswitch")
    }
}

/// 系統的顯示語言（語系字串，如 `zh-TW`、`ja-JP`、`en_US.UTF-8`）；偵測不到回傳空字串。
pub fn system_locale() -> String {
    #[cfg(windows)]
    {
        #[link(name = "kernel32")]
        extern "system" {
            fn GetUserDefaultUILanguage() -> u16;
            fn LCIDToLocaleName(locale: u32, name: *mut u16, cch: i32, flags: u32) -> i32;
        }
        let mut buf = [0u16; 85];
        // SAFETY: 兩個都是無副作用的唯讀系統呼叫；buf 長度與傳入的 cch 一致。
        let n = unsafe {
            LCIDToLocaleName(
                GetUserDefaultUILanguage() as u32,
                buf.as_mut_ptr(),
                buf.len() as i32,
                0,
            )
        };
        if n > 1 {
            return String::from_utf16_lossy(&buf[..n as usize - 1]);
        }
        String::new()
    }
    #[cfg(not(windows))]
    {
        #[cfg(target_os = "macos")]
        if let Ok(o) = command("defaults")
            .args(["read", "-g", "AppleLanguages"])
            .output()
        {
            // 輸出形如 ( "zh-Hant-TW", "en-TW" )，取第一個引號內的字串
            let text = String::from_utf8_lossy(&o.stdout).to_string();
            if let Some(first) = text.split('"').nth(1) {
                return first.to_string();
            }
        }
        for k in ["LC_ALL", "LC_MESSAGES", "LANG"] {
            if let Ok(v) = env::var(k) {
                if !v.is_empty() {
                    return v;
                }
            }
        }
        String::new()
    }
}

pub fn is_elevated() -> bool {
    static CACHE: OnceLock<bool> = OnceLock::new();
    *CACHE.get_or_init(|| {
        #[cfg(windows)]
        {
            command("net")
                .arg("session")
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        }
        #[cfg(unix)]
        {
            // 直接問核心，不呼叫外部的 `id`（避免 PATH 被換成假的 id 而誤判權限）
            // SAFETY: geteuid 不接受參數、不會失敗，也沒有副作用。
            unsafe { libc::geteuid() == 0 }
        }
    })
}

/// RustDesk 在 Windows 的實際安裝路徑：優先讀服務登錄的 ImagePath（使用者可能裝在 D: 等非預設位置）。
#[cfg(windows)]
fn windows_rustdesk_exe() -> Option<PathBuf> {
    let out = command("reg")
        .args([
            "query",
            r"HKLM\SYSTEM\CurrentControlSet\Services\RustDesk",
            "/v",
            "ImagePath",
        ])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let line = text.lines().find(|l| l.contains("ImagePath"))?;
    let value = line
        .split("REG_EXPAND_SZ")
        .nth(1)
        .or_else(|| line.split("REG_SZ").nth(1))?
        .trim();
    let path = match value.strip_prefix('"') {
        Some(rest) => rest.split('"').next()?.to_string(),
        None => value.split(" --").next()?.trim().to_string(),
    };
    let p = PathBuf::from(path);
    p.exists().then_some(p)
}

/// 關閉 GUI 時的失敗。即使失敗，`stopped` 仍列出「已經被關掉」的命令列，
/// 讓呼叫端能把它們重新啟動（失敗時還原資源）。
#[derive(Debug)]
pub struct StopFailed {
    pub stopped: Vec<String>,
    pub message: String,
}

/// 等待 GUI 完全結束的上限與輪詢間隔。
const STOP_TIMEOUT: Duration = Duration::from_secs(8);
const STOP_POLL: Duration = Duration::from_millis(200);

/// 解析 `pgrep -xa` 的輸出為 (pid, 命令列)，排除 --service / --server 背景行程。
#[cfg_attr(windows, allow(dead_code))] // Windows 以 PowerShell 查詢，不經過這裡；保留讓所有平台都能測試
fn parse_gui_processes(pgrep_output: &str) -> Vec<(String, String)> {
    pgrep_output
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let (pid, cmd) = line.split_once(' ').unwrap_or((line, ""));
            let is_background = cmd.contains("--service") || cmd.contains("--server");
            (!pid.is_empty() && !is_background).then(|| (pid.to_string(), cmd.to_string()))
        })
        .collect()
}

#[cfg(windows)]
const PS_GUI_FILTER: &str = "$sid = (Get-Process -Id $PID).SessionId; \
    Get-CimInstance Win32_Process -Filter \"Name='rustdesk.exe'\" | \
    Where-Object { $_.SessionId -eq $sid -and $_.CommandLine -and $_.CommandLine -notmatch '--(service|server)' }";

/// 目前執行中的 GUI 命令列（不含 --service / --server）。查詢本身失敗回傳 Err，不可當成「沒有在執行」。
#[cfg(windows)]
fn running_gui() -> Result<Vec<String>, String> {
    let script = format!("{PS_GUI_FILTER} | ForEach-Object {{ $_.CommandLine }}");
    let out = command("powershell")
        .args(["-NoProfile", "-Command", &script])
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect())
}

#[cfg(not(windows))]
fn running_gui() -> Result<Vec<String>, String> {
    let name = if cfg!(target_os = "macos") {
        "RustDesk"
    } else {
        "rustdesk"
    };
    let out = command("pgrep")
        .args(["-xa", name])
        .output()
        .map_err(|e| e.to_string())?;
    // pgrep 找不到行程時結束碼為 1（stdout 為空），屬於正常；其他結束碼才是查詢失敗
    if !out.status.success() && out.status.code() != Some(1) {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    Ok(parse_gui_processes(&String::from_utf8_lossy(&out.stdout))
        .into_iter()
        .map(|(_, cmd)| cmd)
        .collect())
}

/// 關閉 RustDesk GUI（不得動到 --service / --server 背景行程），並確認它真的結束了。
/// 回傳被關閉的 GUI 的命令列；空陣列代表原本就沒有開著（之後不需要重啟）。
/// 無法關閉、或逾時仍在執行時回傳 `StopFailed`：此時不可繼續改設定檔，
/// 否則 RustDesk 結束時會把舊設定寫回去，造成「顯示已切換、實際沒生效」。
pub fn stop_gui() -> Result<Vec<String>, StopFailed> {
    let fail = |stopped: Vec<String>, err: String| StopFailed {
        message: trf("err.stop_gui_failed", &[("err", &err)]),
        stopped,
    };
    let stopped = request_gui_stop().map_err(|(s, e)| fail(s, e))?;
    if stopped.is_empty() {
        return Ok(stopped);
    }
    let deadline = Instant::now() + STOP_TIMEOUT;
    loop {
        match running_gui() {
            Ok(r) if r.is_empty() => return Ok(stopped),
            Ok(_) if Instant::now() < deadline => std::thread::sleep(STOP_POLL),
            Ok(_) => {
                return Err(StopFailed {
                    message: tr("err.stop_gui_timeout"),
                    stopped,
                })
            }
            Err(e) => return Err(fail(stopped, e)),
        }
    }
}

/// 送出關閉要求；回傳實際被要求關閉的命令列。失敗時 Err 內仍帶有已關閉的部分。
#[cfg(windows)]
fn request_gui_stop() -> Result<Vec<String>, (Vec<String>, String)> {
    // 只關閉「本人 session 內、命令列可讀、且不是 --service/--server」的行程。
    // 背景服務跑在 session 0 且命令列對非管理員不可讀，必須明確排除，
    // 否則以管理員身分執行時會誤殺 RustDesk 服務。
    let script = format!(
        "{PS_GUI_FILTER} | ForEach-Object {{ Stop-Process -Id $_.ProcessId -Force -ErrorAction Stop; $_.CommandLine }}"
    );
    let out = command("powershell")
        .args(["-NoProfile", "-Command", &script])
        .output()
        .map_err(|e| (vec![], e.to_string()))?;
    let stopped: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
        return Err((stopped, err));
    }
    Ok(stopped)
}

#[cfg(target_os = "macos")]
fn request_gui_stop() -> Result<Vec<String>, (Vec<String>, String)> {
    if running_gui().map_err(|e| (vec![], e))?.is_empty() {
        return Ok(vec![]);
    }
    let status = command(OSASCRIPT)
        .args(["-e", "tell application \"RustDesk\" to quit"])
        .status()
        .map_err(|e| (vec![], e.to_string()))?;
    if !status.success() {
        return Err((vec![], format!("osascript {status}")));
    }
    Ok(vec![String::new()])
}

#[cfg(all(not(windows), not(target_os = "macos")))]
fn request_gui_stop() -> Result<Vec<String>, (Vec<String>, String)> {
    let out = command("pgrep")
        .args(["-xa", "rustdesk"])
        .output()
        .map_err(|e| (vec![], e.to_string()))?;
    if !out.status.success() && out.status.code() != Some(1) {
        return Err((
            vec![],
            String::from_utf8_lossy(&out.stderr).trim().to_string(),
        ));
    }
    let mut stopped = vec![];
    for (pid, cmd) in parse_gui_processes(&String::from_utf8_lossy(&out.stdout)) {
        let status = command("kill")
            .arg(&pid)
            .status()
            .map_err(|e| (stopped.clone(), e.to_string()))?;
        if !status.success() {
            return Err((stopped, format!("kill {pid}: {status}")));
        }
        stopped.push(cmd);
    }
    Ok(stopped)
}

/// 重新啟動先前被 stop_gui 關閉的 GUI（沿用 --tray 等啟動方式）。啟動失敗要回報，不可吞掉。
pub fn start_gui(stopped: &[String]) -> Result<(), String> {
    if stopped.is_empty() {
        return Ok(());
    }
    let tray = stopped.iter().any(|c| c.contains("--tray"));
    if cfg!(windows) {
        #[cfg(windows)]
        {
            let exe = rustdesk_exe()?;
            let mut c = command(&exe.to_string_lossy());
            if tray {
                c.arg("--tray");
            }
            c.spawn().map_err(|e| e.to_string())?;
        }
        Ok(())
    } else if cfg!(target_os = "macos") {
        let status = command("open")
            .args(["-a", "RustDesk"])
            .status()
            .map_err(|e| e.to_string())?;
        status
            .success()
            .then_some(())
            .ok_or_else(|| format!("open {status}"))
    } else {
        let mut c = command("rustdesk");
        if tray {
            c.arg("--tray");
        }
        c.spawn().map(|_| ()).map_err(|e| e.to_string())
    }
}

/// RustDesk 可執行檔（含 `--option` 命令列介面）。找不到回傳 `err.no_exe`；
/// macOS/Linux 上找到但位置不安全（可能被一般使用者替換）時也回傳錯誤，絕不退回 PATH 搜尋。
pub fn rustdesk_exe() -> Result<PathBuf, String> {
    #[cfg(windows)]
    {
        windows_rustdesk_exe()
            .or_else(|| {
                Some(
                    env_path("ProgramFiles")
                        .join("RustDesk")
                        .join("RustDesk.exe"),
                )
                .filter(|p| p.exists())
            })
            .ok_or_else(|| tr("err.no_exe"))
    }
    #[cfg(unix)]
    {
        let candidates = if cfg!(target_os = "macos") {
            trust::MACOS_RUSTDESK
        } else {
            trust::LINUX_RUSTDESK
        };
        trust::find_trusted_exe(candidates, &unix_realpath, &unix_lstat)
            .map_err(|u| {
                trf(
                    "err.untrusted_exe",
                    &[
                        ("path", &u.path().display().to_string()),
                        ("reason", &u.reason()),
                    ],
                )
            })?
            .ok_or_else(|| tr("err.no_exe"))
    }
}

/// 解析所有 symlink 後的實際路徑（realpath）。
#[cfg(unix)]
fn unix_realpath(p: &std::path::Path) -> std::io::Result<PathBuf> {
    std::fs::canonicalize(p)
}

/// 不跟隨 symlink 取得檔案的種類、擁有者與權限，交給 trust 模組判斷。
#[cfg(unix)]
fn unix_lstat(p: &std::path::Path) -> std::io::Result<trust::NodeFacts> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::symlink_metadata(p)?;
    let ft = m.file_type();
    let kind = if ft.is_symlink() {
        trust::NodeKind::Symlink
    } else if ft.is_file() {
        trust::NodeKind::File
    } else if ft.is_dir() {
        trust::NodeKind::Dir
    } else {
        trust::NodeKind::Other
    };
    Ok(trust::NodeFacts {
        kind,
        uid: m.uid(),
        mode: m.mode(),
    })
}

/// RustDesk 是否安裝為系統服務。已安裝服務時，執行中的服務行程把設定放在記憶體，
/// 只改設定檔不會生效，必須透過 `rustdesk --option`（需系統管理員/root）通知它。
pub fn service_installed() -> bool {
    if cfg!(windows) {
        command("reg")
            .args(["query", r"HKLM\SYSTEM\CurrentControlSet\Services\RustDesk"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    } else if cfg!(target_os = "macos") {
        std::path::Path::new("/Library/LaunchDaemons/com.carriez.RustDesk_service.plist").exists()
    } else {
        [
            "/usr/lib/systemd/system/rustdesk.service",
            "/etc/systemd/system/rustdesk.service",
            "/lib/systemd/system/rustdesk.service",
        ]
        .iter()
        .any(|p| std::path::Path::new(p).exists())
    }
}

const NEED_ADMIN_MSG: &str = "privileges required";

/// 透過 `rustdesk --option <key> <value>` 設定執行中的 RustDesk（空字串 = 清除）。
pub fn rustdesk_set_option(exe: &std::path::Path, key: &str, value: &str) -> Result<(), String> {
    let out = command(&exe.to_string_lossy())
        .args(["--option", key, value])
        .output()
        .map_err(|e| trf("err.run_rustdesk", &[("err", &e.to_string())]))?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    if text.to_lowercase().contains(NEED_ADMIN_MSG) {
        return Err(tr("err.rustdesk_needs_admin"));
    }
    if !out.status.success() {
        return Err(trf(
            "err.option_failed",
            &[("key", key), ("status", &out.status.to_string())],
        ));
    }
    Ok(())
}

/// 目前使用者的 (uid, gid)；Windows 沒有這個概念，回傳 None。
/// 直接問核心，不呼叫外部的 `id`（PATH 上的假 id 可讓 root 腳本把檔案 chown 給別人）。
fn current_uid_gid() -> Option<(u32, u32)> {
    #[cfg(unix)]
    {
        // SAFETY: getuid/getgid 不接受參數、不會失敗，也沒有副作用。
        Some(unsafe { (libc::getuid(), libc::getgid()) })
    }
    #[cfg(windows)]
    {
        None
    }
}

/// 提權用的系統程式一律用絕對路徑，不經 PATH 搜尋（PATH 可被一般使用者改寫）。
const PKEXEC: &str = "/usr/bin/pkexec";
const SH: &str = "/bin/sh";
const OSASCRIPT: &str = "/usr/bin/osascript";

/// 目前不是管理員/root 時，能否在「切換當下」才要求提升權限（跳出系統密碼視窗）。
/// Windows 沒有對應機制（啟動時由 manifest 要求管理員）；macOS 用 osascript，Linux 需要 pkexec。
pub fn can_elevate_on_demand() -> bool {
    if cfg!(windows) {
        false
    } else if cfg!(target_os = "macos") {
        std::path::Path::new(OSASCRIPT).is_file()
    } else {
        std::path::Path::new(PKEXEC).is_file() && std::path::Path::new(SH).is_file()
    }
}

/// 以系統密碼視窗提升權限，一次執行所有 `--option` 設定並讀回 `readback_key` 的值。
/// 整批只問一次密碼；使用者取消會回傳明確的錯誤。回傳 None 代表讀不到值（略過驗證）。
pub fn rustdesk_set_options_elevated(
    exe: &std::path::Path,
    changes: &[(&str, &str)],
    readback_key: &str,
    backups: &[(&str, &str)],
    restore_owner_of: &[&str],
) -> Result<Option<String>, String> {
    if !can_elevate_on_demand() {
        return Err(tr("err.need_admin"));
    }
    let script = elevate::build_script(&elevate::Plan {
        exe: &exe.to_string_lossy(),
        changes,
        readback_key,
        backups,
        owner: current_uid_gid(),
        restore_owner_of,
    })?;
    let out = if cfg!(target_os = "macos") {
        command(OSASCRIPT)
            .args(["-e", &elevate::osascript_arg(&script)])
            .output()
    } else {
        command(PKEXEC).args([SH, "-c", &script]).output()
    }
    .map_err(|e| trf("err.run_rustdesk", &[("err", &e.to_string())]))?;

    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    if !out.status.success() {
        if elevate::is_cancelled(out.status.code(), &stderr) {
            return Err(tr("err.elevate_cancelled"));
        }
        return Err(trf(
            "err.elevate_failed",
            &[("err", stderr.trim()), ("status", &out.status.to_string())],
        ));
    }
    Ok(elevate::parse_readback(&String::from_utf8_lossy(
        &out.stdout,
    )))
}

/// 向執行中的 RustDesk 詢問某個 option 目前的值；讀不到（權限或輸出被吞）回傳 None。
pub fn rustdesk_get_option(key: &str) -> Option<String> {
    let exe = rustdesk_exe().ok()?;
    let out = command(&exe.to_string_lossy())
        .args(["--option", key])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!text.to_lowercase().contains(NEED_ADMIN_MSG) && !text.contains('\n')).then_some(text)
}

// ---- 開機自動啟動 ----
// Windows：本程式要求系統管理員權限，Run 登錄值無法在登入時啟動需提升權限的程式，
// 因此改用「最高權限」的排程工作。其他平台使用 tauri-plugin-autostart。

#[cfg(windows)]
const TASK_NAME: &str = "rdswitch";

#[cfg(windows)]
pub fn autostart_enabled() -> bool {
    command("schtasks")
        .args(["/Query", "/TN", TASK_NAME])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(windows)]
pub fn set_autostart(on: bool) -> Result<(), String> {
    let out = if on {
        let exe = env::current_exe().map_err(|e| e.to_string())?;
        let user = env::var("USERNAME").unwrap_or_default();
        command("schtasks")
            .args([
                "/Create",
                "/TN",
                TASK_NAME,
                "/TR",
                &format!("\"{}\" --minimized", exe.display()),
                "/SC",
                "ONLOGON",
                "/RL",
                "HIGHEST",
                "/RU",
                &user,
                "/IT",
                "/F",
            ])
            .output()
    } else {
        command("schtasks")
            .args(["/Delete", "/TN", TASK_NAME, "/F"])
            .output()
    }
    .map_err(|e| e.to_string())?;
    if out.status.success() || (!on && !autostart_enabled()) {
        Ok(())
    } else {
        Err(trf(
            "err.task_failed",
            &[("err", String::from_utf8_lossy(&out.stderr).trim())],
        ))
    }
}

#[cfg(test)]
mod gui_tests {
    use super::*;

    #[test]
    fn parse_gui_processes_skips_background_and_blank() {
        let out = "101 rustdesk --service\n102 /usr/bin/rustdesk --tray\n\n103 rustdesk --server\n104 rustdesk\n";
        let got = parse_gui_processes(out);
        assert_eq!(
            got,
            [
                ("102".to_string(), "/usr/bin/rustdesk --tray".to_string()),
                ("104".to_string(), "rustdesk".to_string()),
            ]
        );
        assert!(parse_gui_processes("").is_empty());
    }
}
