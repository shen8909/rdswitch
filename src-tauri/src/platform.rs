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

pub mod securefs;

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

/// 解析 macOS `ps -axo pid=,command=` 的輸出：只取執行檔名剛好是 `exe_name` 的行程，
/// 並排除 --service / --server。macOS 的 `pgrep -a` 不會輸出命令列（意思是「含祖先行程」），
/// 所以不能沿用 Linux 的 `pgrep -xa`。
#[cfg_attr(windows, allow(dead_code))]
fn parse_ps_gui_processes(ps_output: &str, exe_name: &str) -> Vec<(String, String)> {
    ps_output
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let (pid, cmd) = line.split_once(char::is_whitespace)?;
            let cmd = cmd.trim();
            let exe = exe_from_command_line(cmd)?;
            let is_target = std::path::Path::new(&exe)
                .file_name()
                .is_some_and(|n| n == exe_name);
            let is_background = cmd.contains("--service") || cmd.contains("--server");
            (is_target && !is_background).then(|| (pid.to_string(), cmd.to_string()))
        })
        .collect()
}

/// 取出命令列的第一個詞（執行檔路徑）；支援以雙引號包住含空白的路徑。
fn exe_from_command_line(cmd: &str) -> Option<String> {
    let cmd = cmd.trim();
    let exe = if let Some(rest) = cmd.strip_prefix('"') {
        rest.split('"').next()?
    } else {
        cmd.split_whitespace().next()?
    };
    (!exe.is_empty()).then(|| exe.to_string())
}

/// 逾時時只把「確定已經結束」的命令列留在清單中：仍在執行的不能再重啟，否則會同時有兩個實例。
fn exited_only(stopped: Vec<String>, still_running: &[String]) -> Vec<String> {
    stopped
        .into_iter()
        .filter(|c| !still_running.contains(c))
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
    if cfg!(target_os = "macos") {
        let out = command("ps")
            .args(["-axo", "pid=,command="])
            .output()
            .map_err(|e| e.to_string())?;
        if !out.status.success() {
            return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
        }
        return Ok(
            parse_ps_gui_processes(&String::from_utf8_lossy(&out.stdout), "RustDesk")
                .into_iter()
                .map(|(_, cmd)| cmd)
                .collect(),
        );
    }
    let name = "rustdesk";
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
            Ok(still) => {
                return Err(StopFailed {
                    message: tr("err.stop_gui_timeout"),
                    stopped: exited_only(stopped, &still),
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
    // 查詢與關閉之間行程可能已自行結束（NoProcessFoundForGivenId）：那正是我們要的結果，不算失敗；
    // 其他錯誤（例如存取被拒）照樣中止。是否真的結束由 stop_gui 的輪詢確認。
    let script = format!(
        "{PS_GUI_FILTER} | ForEach-Object {{ \
         try {{ Stop-Process -Id $_.ProcessId -Force -ErrorAction Stop }} \
         catch {{ if ($_.FullyQualifiedErrorId -notlike 'NoProcessFoundForGivenId*') {{ throw }} }}; \
         $_.CommandLine }}"
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
    let running = running_gui().map_err(|e| (vec![], e))?;
    if running.is_empty() {
        return Ok(vec![]);
    }
    let status = command(OSASCRIPT)
        .args(["-e", "tell application \"RustDesk\" to quit"])
        .status()
        .map_err(|e| (vec![], e.to_string()))?;
    if !status.success() {
        return Err((vec![], format!("osascript {status}")));
    }
    Ok(running)
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
        // kill 失敗時，若該行程其實已經不在了（查詢與關閉之間自行結束），視為成功
        let still_alive = || {
            command("kill")
                .args(["-0", &pid])
                .status()
                .is_ok_and(|s| s.success())
        };
        if !status.success() && still_alive() {
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
            // 優先用原本執行的路徑（免安裝版不在登錄或 Program Files），找不到才退回安裝路徑
            let original = stopped
                .iter()
                .find_map(|c| exe_from_command_line(c))
                .map(PathBuf::from)
                .filter(|p| p.is_file());
            let exe = match original {
                Some(p) => p,
                None => rustdesk_exe()?,
            };
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
/// 整批只問一次密碼；使用者取消會回傳明確的錯誤。`dumps` 是要由 root 讀出、
/// 交回本程式備份的檔案；`restore_owner_of` 是設定後要還給目前使用者的檔案（見 elevate.rs）。
/// 設定已執行但輸出無法解析時回傳 `Ok(Err(..))`，讓呼叫端知道變更已生效。
pub fn rustdesk_set_options_elevated(
    exe: &std::path::Path,
    changes: &[(&str, &str)],
    readback_key: &str,
    dumps: &[&str],
    restore_owner_of: &[&str],
) -> Result<Result<elevate::Outcome, String>, String> {
    if !can_elevate_on_demand() {
        return Err(tr("err.need_admin"));
    }
    let script = elevate::build_script(&elevate::Plan {
        exe: &exe.to_string_lossy(),
        changes,
        readback_key,
        dumps,
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
    Ok(elevate::parse_outcome(
        &String::from_utf8_lossy(&out.stdout),
        dumps.len(),
    ))
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

/// 目前登入者的 `DOMAIN\user`（GetUserNameExW / NameSamCompatible），並以白名單驗證。
/// 不使用環境變數 USERNAME（可被竄改）；取不到或格式不符就回傳錯誤，絕不退回空字串。
#[cfg(windows)]
fn current_account() -> Result<String, String> {
    #[link(name = "secur32")]
    extern "system" {
        fn GetUserNameExW(name_format: u32, name_buffer: *mut u16, n_size: *mut u32) -> u8;
    }
    const NAME_SAM_COMPATIBLE: u32 = 2;
    let fail = |e: &str| trf("err.autostart_no_user", &[("err", e)]);
    let mut buf = [0u16; 1024];
    let mut len = buf.len() as u32;
    // SAFETY: buf 可寫入 len 個 u16；成功時 len 會被設為不含結尾 NUL 的字元數。
    let ok = unsafe { GetUserNameExW(NAME_SAM_COMPATIBLE, buf.as_mut_ptr(), &mut len) };
    if ok == 0 {
        return Err(fail(&std::io::Error::last_os_error().to_string()));
    }
    let name = buf
        .get(..len as usize)
        .ok_or_else(|| fail("length out of range"))?;
    let name = String::from_utf16(name).map_err(|e| fail(&e.to_string()))?;
    crate::autostart::validate_account(&name)
        .map(str::to_string)
        .ok_or_else(|| fail("invalid account name"))
}

/// 一般使用者無法寫入的系統安裝資料夾（Program Files 與 Program Files (x86)），已 canonicalize。
/// 由 SHGetKnownFolderPath 取得（來源是 HKLM），不使用可被使用者改寫的環境變數 ProgramFiles。
#[cfg(windows)]
fn protected_install_roots() -> Result<Vec<PathBuf>, String> {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStringExt;
    #[repr(C)]
    struct Guid(u32, u16, u16, [u8; 8]);
    #[link(name = "shell32")]
    extern "system" {
        fn SHGetKnownFolderPath(
            id: *const Guid,
            flags: u32,
            token: *mut c_void,
            path: *mut *mut u16,
        ) -> i32;
    }
    #[link(name = "ole32")]
    extern "system" {
        fn CoTaskMemFree(pv: *mut c_void);
    }
    const PROGRAM_FILES: Guid = Guid(
        0x905e63b6,
        0xc1bf,
        0x494e,
        [0xb2, 0x9c, 0x65, 0xb7, 0x32, 0xd3, 0xd2, 0x1a],
    );
    const PROGRAM_FILES_X86: Guid = Guid(
        0x7c5a40ef,
        0xa0fb,
        0x4bfc,
        [0x87, 0x4a, 0xc0, 0xf2, 0xe0, 0xb9, 0xfa, 0x8e],
    );
    const MAX_PATH_CHARS: usize = 32_768;

    let mut roots = vec![];
    for id in [&PROGRAM_FILES, &PROGRAM_FILES_X86] {
        let mut p: *mut u16 = std::ptr::null_mut();
        // SAFETY: id 指向有效的 GUID；成功或失敗都必須以 CoTaskMemFree 釋放 p（文件要求）。
        let hr = unsafe { SHGetKnownFolderPath(id, 0, std::ptr::null_mut(), &mut p) };
        let path = if hr >= 0 && !p.is_null() {
            // SAFETY: 成功時 p 是以 NUL 結尾的 UTF-16 字串；以 MAX_PATH_CHARS 為上限避免越界。
            let len = (0..MAX_PATH_CHARS)
                .find(|&i| unsafe { *p.add(i) } == 0)
                .unwrap_or(0);
            let s = unsafe { std::slice::from_raw_parts(p, len) };
            Some(PathBuf::from(std::ffi::OsString::from_wide(s)))
        } else {
            None
        };
        // SAFETY: p 由 SHGetKnownFolderPath 配置（或為 null，CoTaskMemFree 接受 null）。
        unsafe { CoTaskMemFree(p.cast()) };
        let path = path
            .filter(|p| !p.as_os_str().is_empty())
            .ok_or_else(|| format!("SHGetKnownFolderPath failed: {hr:#x}"))?;
        roots.push(std::fs::canonicalize(&path).map_err(|e| e.to_string())?);
    }
    Ok(roots)
}

/// 排程要執行的路徑：本程式必須位於系統安裝資料夾內（一般使用者無法替換執行檔），
/// 否則以最高權限開機執行它等於讓任何使用者層級的程式取得管理員權限。無法判斷時拒絕。
#[cfg(windows)]
fn autostart_command_path() -> Result<String, String> {
    let exe = env::current_exe().map_err(|e| e.to_string())?;
    let unsafe_location = |reason: &str| {
        trf(
            "err.autostart_unsafe_location",
            &[("path", &exe.display().to_string()), ("err", reason)],
        )
    };
    let real = std::fs::canonicalize(&exe).map_err(|e| unsafe_location(&e.to_string()))?;
    let roots = protected_install_roots().map_err(|e| unsafe_location(&e))?;
    if !crate::autostart::is_within(&real, &roots) {
        return Err(unsafe_location("not under Program Files"));
    }
    crate::autostart::task_command_path(&real).ok_or_else(|| unsafe_location("not a local path"))
}

#[cfg(windows)]
pub fn set_autostart(on: bool) -> Result<(), String> {
    let out = if on {
        let exe = autostart_command_path()?;
        let user = current_account()?;
        command("schtasks")
            .args([
                "/Create",
                "/TN",
                TASK_NAME,
                "/TR",
                &format!("\"{exe}\" --minimized"),
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

/// 只讀取系統資訊、不建立排程工作，一般權限即可執行。
#[cfg(all(test, windows))]
mod autostart_tests {
    use super::*;

    #[test]
    fn current_account_is_domain_backslash_user() {
        let a = current_account().unwrap();
        assert!(crate::autostart::validate_account(&a).is_some(), "{a}");
    }

    #[test]
    fn protected_roots_are_program_files() {
        let roots = protected_install_roots().unwrap();
        assert_eq!(roots.len(), 2);
        for r in &roots {
            assert!(r.is_dir(), "{}", r.display());
            assert!(r.to_string_lossy().to_lowercase().contains("program files"));
        }
    }

    /// 測試執行檔在 target 資料夾（一般使用者可寫入），必須拒絕建立排程。
    #[test]
    fn user_writable_location_is_refused() {
        let e = autostart_command_path().unwrap_err();
        assert!(e.contains("Program Files"), "{e}");
    }
}

#[cfg(test)]
mod gui_tests {
    use super::*;

    #[test]
    fn parse_ps_output_matches_exe_name_and_skips_background() {
        let out = "  1 /sbin/launchd\n\
 501 /Applications/RustDesk.app/Contents/MacOS/RustDesk --tray\n\
 502 /Applications/RustDesk.app/Contents/MacOS/RustDesk --server\n\
 503 /Applications/RustDesk.app/Contents/MacOS/service --service\n\
 504 /usr/bin/vim RustDesk\n\
 505 /Applications/RustDesk.app/Contents/MacOS/RustDesk\n";
        let got = parse_ps_gui_processes(out, "RustDesk");
        assert_eq!(
            got,
            [
                (
                    "501".to_string(),
                    "/Applications/RustDesk.app/Contents/MacOS/RustDesk --tray".to_string()
                ),
                (
                    "505".to_string(),
                    "/Applications/RustDesk.app/Contents/MacOS/RustDesk".to_string()
                ),
            ]
        );
        assert!(parse_ps_gui_processes("", "RustDesk").is_empty());
    }

    #[test]
    fn exe_from_command_line_handles_quotes() {
        assert_eq!(
            exe_from_command_line(r#""C:\Tools\rust desk\rustdesk.exe" --tray"#).as_deref(),
            Some(r"C:\Tools\rust desk\rustdesk.exe")
        );
        assert_eq!(
            exe_from_command_line("/usr/bin/rustdesk --tray").as_deref(),
            Some("/usr/bin/rustdesk")
        );
        assert_eq!(exe_from_command_line("   "), None);
        assert_eq!(exe_from_command_line("\"\" x"), None);
    }

    #[test]
    fn exited_only_keeps_just_confirmed_exits() {
        let stopped = vec!["a".to_string(), "b --tray".to_string()];
        assert_eq!(
            exited_only(stopped.clone(), &["b --tray".to_string()]),
            ["a"]
        );
        assert_eq!(exited_only(stopped.clone(), &[]), stopped);
    }

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
