//! 提升權限執行 `rustdesk --option` 的指令組裝與結果解析。
//!
//! 這裡全是純函式、不判斷作業系統、不啟動行程，方便測試；實際呼叫 pkexec 在 platform.rs。
//! （macOS 暫不支援提權切換，見 `platform::ensure_service_switch_supported`。）
//!
//! 安全重點：值會被放進 shell 腳本，由系統以 root 身分執行。
//! 所以要正確跳脫，並且拒絕控制字元與不合法的 option 名稱，不信任任何輸入。
//!
//! root 完全不接觸使用者可控的路徑：
//! - 腳本固定 `HOME`（root 的家目錄）、清除 `XDG_*`，並 `cd /`，root 的 rustdesk 只會讀寫
//!   root 自己的設定（pkexec 本身也會清空環境並把 HOME 設成目標使用者的家目錄，這裡再明確固定一次）。
//! - 腳本中沒有任何寫入、複製、chown 或刪除檔案的指令；唯一的檔案存取是讀取 `dumps`
//!   （root 擁有的服務設定），以 base64 印到 stdout。
//! - 使用者設定檔的備份由本程式在提權前以一般權限完成；服務設定的備份由本程式以一般權限
//!   寫入（見 profiles.rs）。

use crate::i18n::tr;

/// 腳本輸出中，分隔「設定指令的輸出」與「讀回的值」的標記。
pub const MARKER: &str = "__RDSWITCH_READBACK__";

/// 以單引號包住字串給 POSIX shell；字串內的單引號寫成 `'\''`。
pub fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// option 名稱只允許小寫英文字母與連字號（例如 `custom-rendezvous-server`）。
fn valid_key(k: &str) -> bool {
    !k.is_empty() && k.chars().all(|c| c.is_ascii_lowercase() || c == '-')
}

/// 換行、NUL 等控制字元會讓腳本被截斷或夾帶指令，一律拒絕。
fn clean(s: &str) -> bool {
    !s.chars().any(|c| c.is_control())
}

/// 正規化的絕對路徑：以 `/` 開頭、不是根目錄本身、不以 `/` 結尾、
/// 沒有空的區段（`//`）、沒有 `.`/`..`，且不含控制字元。
fn valid_abs_path(p: &str) -> bool {
    let Some(rest) = p.strip_prefix('/') else {
        return false;
    };
    clean(p)
        && !rest.is_empty()
        && rest
            .split('/')
            .all(|seg| !seg.is_empty() && seg != "." && seg != "..")
}

/// 要以管理員身分執行的工作。
pub struct Plan<'a> {
    /// 要執行的 rustdesk（已通過 trust 檢查的絕對路徑）。
    pub exe: &'a str,
    pub changes: &'a [(&'a str, &'a str)],
    pub readback_key: &'a str,
    /// 設定之前由 root 讀出並印到 stdout 的檔案（以 `parse_dump` 取回）；不存在就略過，
    /// 是 symlink 就中止。只應是 root 擁有的路徑（服務設定）。
    pub dumps: &'a [&'a str],
    /// root 的家目錄（Linux 為 `/root`）。腳本把 HOME 固定成它，root 的 rustdesk
    /// 因此只會使用 root 自己的設定檔，不會寫到使用者的家目錄。
    pub root_home: &'a str,
}

/// 安全的 PATH：腳本內的 base64 等指令不受呼叫者環境影響。
pub const SAFE_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";

/// 會改變設定檔位置的環境變數；pkexec 已清空環境，這裡再明確清除一次。
const UNSET_VARS: &str =
    "XDG_CONFIG_HOME XDG_DATA_HOME XDG_CACHE_HOME XDG_STATE_HOME XDG_RUNTIME_DIR";

/// 腳本開頭：失敗即中止、固定 PATH 與 HOME、清除 XDG_*、切到 `/`，並定義讀取用的輔助函式。
///
/// `rds_dump <編號> <路徑>`：路徑是 symlink 就中止；是一般檔案就以 base64 印出（唯讀）。
fn prelude(root_home: &str) -> String {
    format!(
        "set -e; PATH={SAFE_PATH}; export PATH; HOME={}; export HOME; unset {UNSET_VARS}; cd /; {}",
        sh_quote(root_home),
        r#"rds_dump() { if [ -L "$2" ]; then echo "rdswitch: refusing symlink: $2" >&2; exit 1; fi; if [ -f "$2" ]; then echo "__RDSWITCH_DUMP_BEGIN_$1__"; base64 < "$2"; echo "__RDSWITCH_DUMP_END_$1__"; fi; }"#
    )
}

/// 組出要以管理員身分執行的 shell 腳本：印出要備份的檔案、依序設定每個 option，
/// 最後讀回 `readback_key`。任何一步失敗就中止（`set -e`），不會在半套狀態下繼續。
pub fn build_script(plan: &Plan) -> Result<String, String> {
    let bad = || tr("err.elevate_bad_input");
    let (exe, readback_key) = (plan.exe, plan.readback_key);
    if !valid_abs_path(exe) || !valid_abs_path(plan.root_home) || !valid_key(readback_key) {
        return Err(bad());
    }
    let mut parts = vec![prelude(plan.root_home)];
    for (i, src) in plan.dumps.iter().enumerate() {
        if !valid_abs_path(src) {
            return Err(bad());
        }
        parts.push(format!("rds_dump {i} {}", sh_quote(src)));
    }
    for (key, value) in plan.changes {
        if !valid_key(key) || !clean(value) {
            return Err(bad());
        }
        parts.push(format!(
            "{} --option {} {}",
            sh_quote(exe),
            sh_quote(key),
            sh_quote(value)
        ));
    }
    parts.push(format!("echo {MARKER}"));
    parts.push(format!(
        "{} --option {}",
        sh_quote(exe),
        sh_quote(readback_key)
    ));
    Ok(parts.join("; "))
}

/// 提權腳本的結果。
#[derive(Debug, PartialEq)]
pub struct Outcome {
    /// 讀回的值；讀不到為 None（呼叫端略過驗證）。
    pub readback: Option<String>,
    /// 與 `Plan::dumps` 一一對應；None 代表該檔案不存在。
    pub dumps: Vec<Option<Vec<u8>>>,
}

/// 解析腳本輸出。任一個印出的檔案損毀就回傳 Err。
pub fn parse_outcome(output: &str, dump_count: usize) -> Result<Outcome, String> {
    Ok(Outcome {
        readback: parse_readback(output),
        dumps: (0..dump_count)
            .map(|i| parse_dump(output, i))
            .collect::<Result<_, _>>()?,
    })
}

/// 取回 `rds_dump` 印出的第 `index` 個檔案內容。沒有印出（檔案不存在）回傳 Ok(None)；
/// 只有開頭沒有結尾、或 base64 無法解碼時回傳 Err（不可當成「沒有檔案」）。
/// base64 會自動換行（GNU 每 76 字元），解碼前去除所有空白字元（含 `\r`）。
pub fn parse_dump(output: &str, index: usize) -> Result<Option<Vec<u8>>, String> {
    use base64::Engine;
    let begin = format!("__RDSWITCH_DUMP_BEGIN_{index}__");
    let end = format!("__RDSWITCH_DUMP_END_{index}__");
    let Some((_, rest)) = output.split_once(&begin) else {
        return Ok(None);
    };
    let (body, _) = rest
        .split_once(&end)
        .ok_or_else(|| "truncated dump".to_string())?;
    let compact: String = body.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    base64::engine::general_purpose::STANDARD
        .decode(compact)
        .map(Some)
        .map_err(|e| e.to_string())
}

/// 從腳本輸出取出讀回的值。找不到標記、或值不只一行，回傳 None（呼叫端略過驗證，不誤報）。
pub fn parse_readback(output: &str) -> Option<String> {
    let after = output.split_once(MARKER)?.1.trim();
    (!after.contains('\n')).then(|| after.to_string())
}

/// 使用者是否在密碼視窗按了取消（pkexec：結束碼 126 = 未授權或對話框被關閉）。
pub fn is_cancelled(code: Option<i32>) -> bool {
    code == Some(126)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT_HOME: &str = "/root";

    /// 沒有備份的最簡單計畫。
    fn script(exe: &str, changes: &[(&str, &str)], key: &str) -> Result<String, String> {
        build_script(&Plan {
            exe,
            changes,
            readback_key: key,
            dumps: &[],
            root_home: ROOT_HOME,
        })
    }

    fn full_plan<'a>(dumps: &'a [&'a str], root_home: &'a str) -> Result<String, String> {
        build_script(&Plan {
            exe: "/usr/bin/rustdesk",
            changes: &[("relay-server", "x")],
            readback_key: "relay-server",
            dumps,
            root_home,
        })
    }

    #[test]
    fn sh_quote_wraps_and_escapes_single_quotes() {
        assert_eq!(sh_quote("abc"), "'abc'");
        assert_eq!(sh_quote(""), "''");
        assert_eq!(sh_quote("it's"), r"'it'\''s'");
    }

    /// 用真正的 /bin/sh 驗證：不論內容多惡意，都會原封不動地當成「一個參數」。
    #[cfg(unix)]
    #[test]
    fn sh_quote_survives_a_real_shell() {
        let nasty = [
            "plain",
            "a b  c",
            "'; echo INJECTED #",
            "$(echo INJECTED)",
            "`echo INJECTED`",
            "x\" ; echo INJECTED ; \"",
            r"back\slash\\",
            "semi;colon && pipe | amp &",
            "'''",
            "中文 空白",
        ];
        for s in nasty {
            let out = std::process::Command::new("/bin/sh")
                .arg("-c")
                .arg(format!("printf '%s' {}", sh_quote(s)))
                .output()
                .unwrap();
            assert_eq!(String::from_utf8_lossy(&out.stdout), s, "輸入：{s}");
        }
    }

    #[test]
    fn script_sets_each_option_then_reads_back() {
        let s = script(
            "/usr/share/rustdesk/rustdesk",
            &[
                ("custom-rendezvous-server", "203.0.113.5"),
                ("relay-server", ""),
            ],
            "custom-rendezvous-server",
        )
        .unwrap();
        assert!(s.starts_with("set -e; "));
        assert!(s.contains("--option 'custom-rendezvous-server' '203.0.113.5'"));
        assert!(s.contains("--option 'relay-server' ''"));
        assert!(s.ends_with("--option 'custom-rendezvous-server'"));
        assert!(s.contains(&format!("echo {MARKER}")));
    }

    /// HOME 與 PATH 在任何指令之前就被固定，XDG_* 被清除、工作目錄切到 `/`。
    #[test]
    fn script_pins_home_path_and_clears_xdg_before_anything_else() {
        let s = full_plan(&["/root/.config/rustdesk/RustDesk2.toml"], ROOT_HOME).unwrap();
        let head = format!(
            "set -e; PATH={SAFE_PATH}; export PATH; HOME='/root'; export HOME; unset {UNSET_VARS}; cd /; "
        );
        assert!(s.starts_with(&head), "{s}");
        for v in ["XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME"] {
            assert!(UNSET_VARS.split(' ').any(|x| x == v), "{v}");
        }
        // 固定之後才讀檔、執行 rustdesk
        let dump = s.find("rds_dump 0 ").unwrap();
        let option = s.find("--option 'relay-server' 'x'").unwrap();
        assert!(head.len() < dump && dump < option);
    }

    /// root 不寫入、不改擁有者、不複製、不刪除任何檔案：腳本中沒有這類指令或輸出重導向。
    #[test]
    fn script_never_writes_or_chowns_any_path() {
        let s = full_plan(&["/root/.config/rustdesk/RustDesk2.toml"], ROOT_HOME).unwrap();
        for forbidden in [
            "chown", "chmod", "chgrp", "cp ", "mv ", "rm ", "ln ", "tee", "touch", "mkdir",
            "install ", "dd ", "truncate", "find ", "sed ", "rds_own",
        ] {
            assert!(!s.contains(forbidden), "不應出現 {forbidden:?}：{s}");
        }
        // 唯一的「>」是把錯誤訊息導向 stderr；沒有任何寫入檔案的重導向
        assert!(!s.replace(">&2", "").contains('>'), "{s}");
        // 計畫中沒有任何指向使用者家目錄的路徑
        assert!(!s.contains("/home/"), "{s}");
    }

    #[test]
    fn script_rejects_control_characters_and_bad_keys() {
        let exe = "/usr/bin/rustdesk";
        let ok = [("relay-server", "x")];
        assert!(script(exe, &ok, "relay-server").is_ok());
        // 換行 / NUL / 其他控制字元
        for bad in ["a\nb", "a\rb", "a\0b", "a\tb", "a\u{1b}b"] {
            assert!(script(exe, &[("relay-server", bad)], "relay-server").is_err());
            assert!(script(&format!("/usr/bin/{bad}"), &ok, "relay-server").is_err());
        }
        // option 名稱：夾帶指令、大寫、空字串
        for key in ["relay-server; rm -rf /", "Relay", "", "a b", "k'x", "k$(x)"] {
            assert!(script(exe, &[(key, "v")], "relay-server").is_err(), "{key}");
            assert!(script(exe, &ok, key).is_err(), "{key}");
        }
        // 執行檔必須是正規化的絕對路徑
        for bad_exe in [
            "",
            "rustdesk",
            "./rustdesk",
            "/usr/../tmp/x",
            "/usr//bin/x",
            "/",
        ] {
            assert!(script(bad_exe, &ok, "relay-server").is_err(), "{bad_exe:?}");
        }
    }

    #[test]
    fn script_rejects_bad_dump_paths_and_root_home() {
        assert!(full_plan(&["/a"], "/root").is_ok());
        for bad in [
            "",
            "rel/a",
            "/a\n; rm -rf /",
            "/a\0",
            "/a/../etc/shadow",
            "/a/./b",
            "/a//b",
            "/a/",
            "/",
        ] {
            assert!(full_plan(&[bad], "/root").is_err(), "dump {bad:?}");
            assert!(full_plan(&[], bad).is_err(), "home {bad:?}");
        }
    }

    #[test]
    fn valid_abs_path_cases() {
        assert!(valid_abs_path("/root"));
        assert!(valid_abs_path("/a b/it's.toml"));
        assert!(!valid_abs_path("/"));
        assert!(!valid_abs_path("root"));
        assert!(!valid_abs_path("/a/.."));
        assert!(!valid_abs_path("/a\u{7f}"));
    }

    /// 惡意的值放進完整腳本後，用真正的 sh 執行，確認不會執行夾帶的指令。
    #[cfg(unix)]
    #[test]
    fn malicious_value_cannot_inject_a_command_through_the_full_script() {
        let dir = std::env::temp_dir().join(format!("rds-elevate-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let fake = dir.join("fake rustdesk"); // 路徑含空白，同時驗證 exe 的跳脫
        std::fs::write(&fake, "#!/bin/sh\necho \"ARGS:$*\"\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let evidence = dir.join("INJECTED");

        let nasty = format!("x'; touch '{}'; echo '", evidence.display());
        let script = script(
            &fake.to_string_lossy(),
            &[("custom-rendezvous-server", &nasty)],
            "custom-rendezvous-server",
        )
        .unwrap();
        let out = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(&script)
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout).to_string();
        assert!(out.status.success(), "{text}");
        assert!(!evidence.exists(), "夾帶的指令被執行了");
        assert!(text.contains("ARGS:--option custom-rendezvous-server x'; touch"));
        assert!(parse_readback(&text).is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn set_e_stops_after_the_first_failure() {
        // 第一個指令失敗時，後面的指令（含讀回）不應執行
        #[cfg(unix)]
        {
            let s = script(
                "/nonexistent/rustdesk",
                &[("relay-server", "x")],
                "relay-server",
            )
            .unwrap();
            let out = std::process::Command::new("/bin/sh")
                .arg("-c")
                .arg(&s)
                .output()
                .unwrap();
            assert!(!out.status.success());
            assert!(!String::from_utf8_lossy(&out.stdout).contains(MARKER));
        }
    }

    #[test]
    fn dump_parsing() {
        use base64::Engine;
        let data = b"[options]\nkey = 'secret'\n\x00\xff";
        let enc = base64::engine::general_purpose::STANDARD.encode(data);
        // GNU base64 每 76 字元換行；也容忍 \r\n 或單獨的 \r
        let (a, b) = enc.split_at(10);
        let out = format!(
            "noise\r__RDSWITCH_DUMP_BEGIN_0__\r{a}\r\n{b}\r__RDSWITCH_DUMP_END_0__\r{MARKER}\rx"
        );
        assert_eq!(parse_dump(&out, 0).unwrap().unwrap(), data);
        assert_eq!(parse_dump(&out, 1).unwrap(), None); // 沒有印出 = 檔案不存在
        assert!(parse_dump("__RDSWITCH_DUMP_BEGIN_0__\nQUJD", 0).is_err()); // 被截斷
        assert!(parse_dump("__RDSWITCH_DUMP_BEGIN_0__\n@@@\n__RDSWITCH_DUMP_END_0__", 0).is_err());
        // 讀回的值不受備份內容影響
        assert_eq!(parse_readback(&out), Some("x".into()));
    }

    /// 以真正的 /bin/sh 與假的 rustdesk 執行腳本的測試環境（不需要 root）。
    /// root 的家目錄以沙箱內的資料夾代替（`Plan::root_home` 由呼叫端注入）。
    #[cfg(unix)]
    struct ShellSandbox {
        dir: std::path::PathBuf,
        fake: String,
        home: String,
        /// 假的 rustdesk 被執行過就會出現這個檔案（用來確認「中止時沒有做任何變更」）。
        ran: std::path::PathBuf,
    }

    #[cfg(unix)]
    impl ShellSandbox {
        /// 假的 rustdesk 會印出它看到的 HOME、XDG_CONFIG_HOME、PATH 與工作目錄。
        fn new(tag: &str) -> Self {
            use std::os::unix::fs::PermissionsExt;
            let dir = std::env::temp_dir().join(format!("rds-elev-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            // macOS 的暫存資料夾在 /var -> /private/var 之下，先解析成實際路徑
            let dir = std::fs::canonicalize(&dir).unwrap();
            let ran = dir.join("RAN");
            let home = dir.join("root's home"); // 含單引號與空白，同時驗證 HOME 的跳脫
            std::fs::create_dir_all(&home).unwrap();
            let fake = dir.join("fake rustdesk");
            std::fs::write(
                &fake,
                format!(
                    "#!/bin/sh\necho \"ARGS:$*\"\n: > {}\necho \"ENV:HOME=$HOME;XDG=${{XDG_CONFIG_HOME-unset}};PATH=$PATH;PWD=$(pwd)\"\n",
                    sh_quote(&ran.to_string_lossy())
                ),
            )
            .unwrap();
            std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
            Self {
                fake: fake.to_string_lossy().to_string(),
                home: home.to_string_lossy().to_string(),
                dir,
                ran,
            }
        }

        fn path(&self, name: &str) -> String {
            self.dir.join(name).to_string_lossy().to_string()
        }

        /// 以「呼叫者被竄改過」的環境執行，模擬攻擊者控制的 HOME / XDG / PATH。
        fn run(&self, dumps: &[&str]) -> std::process::Output {
            let s = build_script(&Plan {
                exe: &self.fake,
                changes: &[("custom-rendezvous-server", "203.0.113.5")],
                readback_key: "custom-rendezvous-server",
                dumps,
                root_home: &self.home,
            })
            .unwrap();
            std::process::Command::new("/bin/sh")
                .arg("-c")
                .arg(&s)
                .env("HOME", self.path("attacker-home"))
                .env("XDG_CONFIG_HOME", self.path("attacker-xdg"))
                .env("PATH", self.path("attacker-bin"))
                .current_dir(&self.dir)
                .output()
                .unwrap()
        }
    }

    #[cfg(unix)]
    impl Drop for ShellSandbox {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// 正常流程：服務設定被印出供本程式備份、不存在的檔案不會讓腳本失敗；
    /// rustdesk 看到的 HOME 是注入的 root 家目錄、XDG_CONFIG_HOME 被清除、PATH 被固定、
    /// 工作目錄是 `/`——不論呼叫者的環境被改成什麼。
    #[cfg(unix)]
    #[test]
    fn real_shell_pins_environment_and_dumps_service_config() {
        let sb = ShellSandbox::new("ok");
        let svc = sb.path("service.toml");
        std::fs::write(&svc, b"[options]\nk = 'v'\n\x00\xff").unwrap();
        let missing = sb.path("missing.toml");

        let out = sb.run(&[&svc, &missing]);
        let text = String::from_utf8_lossy(&out.stdout).to_string();
        assert!(
            out.status.success(),
            "{text}{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            parse_dump(&text, 0).unwrap().unwrap(),
            b"[options]\nk = 'v'\n\x00\xff"
        );
        assert_eq!(parse_dump(&text, 1).unwrap(), None);
        let want = format!("ENV:HOME={};XDG=unset;PATH={SAFE_PATH};PWD=/", sb.home);
        assert!(text.contains(&want), "{text}");
        assert!(!text.contains("attacker"), "{text}");
        assert!(sb.ran.exists());
        // root 沒有在任何地方建立檔案（只有假的 rustdesk 自己的 RAN 標記）
        let mut names: Vec<_> = std::fs::read_dir(&sb.dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        names.sort();
        assert_eq!(
            names,
            ["RAN", "fake rustdesk", "root's home", "service.toml"]
        );
        assert_eq!(std::fs::read_dir(&sb.home).unwrap().count(), 0);
    }

    /// 要印出的服務設定是 symlink：中止，不把連結目標的內容印給一般權限的程式。
    #[cfg(unix)]
    #[test]
    fn real_shell_symlinked_dump_source_aborts() {
        let sb = ShellSandbox::new("dumplink");
        std::fs::write(sb.path("secret"), "secret").unwrap();
        std::os::unix::fs::symlink(sb.dir.join("secret"), sb.dir.join("svc.toml")).unwrap();
        let out = sb.run(&[&sb.path("svc.toml")]);
        assert!(!out.status.success());
        assert!(!String::from_utf8_lossy(&out.stdout).contains("c2VjcmV0")); // "secret" 的 base64
        assert!(!sb.ran.exists());
    }

    #[test]
    fn readback_parsing() {
        assert_eq!(
            parse_readback(&format!("noise\n{MARKER}\n203.0.113.5\n")),
            Some("203.0.113.5".into())
        );
        // 清除成預設值：標記後面是空的
        assert_eq!(parse_readback(&format!("{MARKER}\n")), Some(String::new()));
        // 沒有標記、或值有多行：不驗證
        assert_eq!(parse_readback("203.0.113.5"), None);
        assert_eq!(parse_readback(&format!("{MARKER}\na\nb\n")), None);
    }

    #[test]
    fn cancel_detection() {
        assert!(is_cancelled(Some(126)));
        // 127：驗證失敗或無法執行，不是「取消」，必須當成失敗回報
        assert!(!is_cancelled(Some(127)));
        assert!(!is_cancelled(Some(1)));
        assert!(!is_cancelled(None));
    }
}
