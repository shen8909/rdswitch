//! 提升權限執行 `rustdesk --option` 的指令組裝與結果解析。
//!
//! 這裡全是純函式、不判斷作業系統、不啟動行程，方便測試；實際呼叫 osascript / pkexec 在 platform.rs。
//!
//! 安全重點：值會被放進 shell 腳本，再（macOS）放進 AppleScript 字串，由系統以管理員身分執行。
//! 所以每一層都要正確跳脫，並且拒絕控制字元與不合法的 option 名稱，不信任任何輸入。
//!
//! root 對使用者可寫路徑的作用面盡量縮小：不複製檔案到使用者的位置（備份由本程式以一般權限寫入），
//! 唯一的寫入是 `chown -h`，且前後都檢查路徑沒有 symlink、檔案不是硬連結（見 `prelude`）。

use crate::i18n::tr;

/// 腳本輸出中，分隔「設定指令的輸出」與「讀回的值」的標記。
pub const MARKER: &str = "__RDSWITCH_READBACK__";

/// 以單引號包住字串給 POSIX shell；字串內的單引號寫成 `'\''`。
pub fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// 產生 AppleScript 字串常值（含外層雙引號）：跳脫反斜線與雙引號。
pub fn applescript_quote(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', r"\\").replace('"', "\\\""))
}

/// option 名稱只允許小寫英文字母與連字號（例如 `custom-rendezvous-server`）。
fn valid_key(k: &str) -> bool {
    !k.is_empty() && k.chars().all(|c| c.is_ascii_lowercase() || c == '-')
}

/// 換行、NUL 等控制字元會讓腳本被截斷或夾帶指令，一律拒絕。
fn clean(s: &str) -> bool {
    !s.chars().any(|c| c.is_control())
}

/// 要以管理員身分執行的工作。
///
/// 縮小 root 的作用面：root 不再把檔案複製到使用者可寫的位置。
/// - 使用者設定檔的備份由本程式在提權前以一般權限完成。
/// - 服務設定（只有 root 讀得到）由腳本以 base64 印到 stdout，本程式以一般權限寫成備份。
/// - root 對使用者路徑唯一的寫入動作是把設定檔的擁有者還給使用者（見 `restore_owner_of`）。
pub struct Plan<'a> {
    pub exe: &'a str,
    pub changes: &'a [(&'a str, &'a str)],
    pub readback_key: &'a str,
    /// 設定之前由 root 讀出並印到 stdout 的檔案（以 `parse_dump` 取回）；不存在就略過，
    /// 是 symlink 就中止。
    pub dumps: &'a [&'a str],
    /// 以 root 執行 `rustdesk --option` 會把使用者家目錄下的設定檔寫成 root 擁有；
    /// 給定 (uid, gid) 時，腳本會把 `restore_owner_of` 的檔案還給這個使用者。
    pub owner: Option<(u32, u32)>,
    /// 必須是不含 symlink 的絕對路徑（呼叫端先 canonicalize 上層資料夾）。
    pub restore_owner_of: &'a [&'a str],
}

/// 安全的 PATH：腳本內的 cp/find/chown/base64 不受呼叫者環境影響。
const SAFE_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";

/// 把絕對路徑拆成 (上層資料夾, 檔名)。拒絕相對路徑、`.`/`..`、重複或結尾的斜線，
/// 以及以 `-` 開頭的檔名，讓腳本中的 `pwd -P` 比對有意義、指令不會把檔名當成選項。
fn split_abs(path: &str) -> Option<(&str, &str)> {
    if !path.starts_with('/') || path.ends_with('/') || path.contains("//") {
        return None;
    }
    if path.split('/').any(|seg| seg == "." || seg == "..") {
        return None;
    }
    let (dir, name) = path.rsplit_once('/')?;
    let dir = if dir.is_empty() { "/" } else { dir };
    (!name.is_empty() && !name.starts_with('-')).then_some((dir, name))
}

/// 腳本開頭：失敗即中止、固定 PATH，並定義兩個輔助函式。
///
/// `rds_own <資料夾> <檔名> check|chown`：
///   進入「實際路徑與給定路徑相同（沒有 symlink）且由使用者擁有」的資料夾後，
///   確認檔案不是 symlink、是一般檔案且只有一個硬連結（不是指向系統檔案的硬連結），
///   `chown` 模式再以 `chown -h` 改擁有者（-h：即使在檢查後被換成 symlink 也只改連結本身）。
///   資料夾不存在就略過；任何檢查不符就中止整個腳本（fail closed）。
/// `rds_dump <編號> <路徑>`：路徑是 symlink 就中止；是一般檔案就以 base64 印出。
fn prelude(owner: Option<(u32, u32)>) -> String {
    let own = owner
        .map(|(u, g)| {
            format!(
                r#"rds_own() {{ [ -e "$1" ] || [ -L "$1" ] || return 0; ( cd -P -- "$1" || exit 1; [ "$(pwd -P)" = "$1" ] || {{ echo "rdswitch: unsafe directory: $1" >&2; exit 1; }}; [ -n "$(find . -prune -type d -user {u})" ] || {{ echo "rdswitch: directory not owned by the user: $1" >&2; exit 1; }}; if [ -L "./$2" ]; then echo "rdswitch: refusing symlink: $1/$2" >&2; exit 1; fi; [ -e "./$2" ] || exit 0; [ -n "$(find "./$2" -prune -type f -links 1)" ] || {{ echo "rdswitch: refusing non-regular or hard-linked file: $1/$2" >&2; exit 1; }}; if [ "$3" = chown ]; then chown -h {u}:{g} "./$2"; fi ); }}; "#
            )
        })
        .unwrap_or_default();
    format!(
        "set -e; PATH={SAFE_PATH}; export PATH; {own}{}",
        r#"rds_dump() { if [ -L "$2" ]; then echo "rdswitch: refusing symlink: $2" >&2; exit 1; fi; if [ -f "$2" ]; then echo "__RDSWITCH_DUMP_BEGIN_$1__"; base64 < "$2"; echo "__RDSWITCH_DUMP_END_$1__"; fi; }"#
    )
}

/// 組出要以管理員身分執行的 shell 腳本：檢查使用者設定檔的路徑、印出要備份的檔案、
/// 依序設定每個 option、再次檢查並還原檔案擁有者，最後讀回 `readback_key`。
/// 任何一步失敗就中止（`set -e`），不會在半套狀態下繼續。
pub fn build_script(plan: &Plan) -> Result<String, String> {
    let bad = || tr("err.elevate_bad_input");
    let (exe, readback_key) = (plan.exe, plan.readback_key);
    if !clean(exe) || exe.is_empty() || !valid_key(readback_key) {
        return Err(bad());
    }
    let mut owned = vec![];
    if plan.owner.is_some() {
        for f in plan.restore_owner_of {
            let (dir, name) = split_abs(f).filter(|_| clean(f)).ok_or_else(bad)?;
            owned.push(format!("{} {}", sh_quote(dir), sh_quote(name)));
        }
    }
    let mut parts = vec![prelude(plan.owner)];
    // 先檢查：路徑不安全時，在做任何變更之前就中止
    parts.extend(owned.iter().map(|o| format!("rds_own {o} check")));
    for (i, src) in plan.dumps.iter().enumerate() {
        if !src.starts_with('/') || !clean(src) {
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
    parts.extend(owned.iter().map(|o| format!("rds_own {o} chown")));
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
/// macOS 的 `do shell script` 會把換行改成 `\r`，解碼前去除所有空白字元。
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

/// macOS：`osascript -e` 的參數，會跳出系統密碼視窗。
pub fn osascript_arg(script: &str) -> String {
    format!(
        "do shell script {} with administrator privileges",
        applescript_quote(script)
    )
}

/// 從腳本輸出取出讀回的值。找不到標記、或值不只一行，回傳 None（呼叫端略過驗證，不誤報）。
pub fn parse_readback(output: &str) -> Option<String> {
    let after = output.split_once(MARKER)?.1.trim();
    (!after.contains('\n')).then(|| after.to_string())
}

/// 使用者是否在密碼視窗按了取消（macOS：錯誤碼 -128；pkexec：結束碼 126 = 對話框被關閉）。
pub fn is_cancelled(code: Option<i32>, stderr: &str) -> bool {
    let s = stderr.to_lowercase();
    code == Some(126) || s.contains("(-128)") || s.contains("user canceled")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 沒有備份、沒有還原擁有者的最簡單計畫。
    fn script(exe: &str, changes: &[(&str, &str)], key: &str) -> Result<String, String> {
        build_script(&Plan {
            exe,
            changes,
            readback_key: key,
            dumps: &[],
            owner: None,
            restore_owner_of: &[],
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
    fn applescript_quote_escapes_backslash_and_quote() {
        assert_eq!(applescript_quote("abc"), "\"abc\"");
        assert_eq!(applescript_quote("a\"b"), "\"a\\\"b\"");
        assert_eq!(applescript_quote(r"a\b"), r#""a\\b""#);
        // 先處理反斜線再處理引號：  \"  必須變成  \\\"
        assert_eq!(applescript_quote("\\\""), r#""\\\"""#);
    }

    #[test]
    fn script_sets_each_option_then_reads_back() {
        let s = script(
            "/Applications/RustDesk.app/Contents/MacOS/RustDesk",
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

    #[test]
    fn script_rejects_control_characters_and_bad_keys() {
        let exe = "/usr/bin/rustdesk";
        let ok = [("relay-server", "x")];
        assert!(script(exe, &ok, "relay-server").is_ok());
        // 換行 / NUL / 其他控制字元
        for bad in ["a\nb", "a\rb", "a\0b", "a\tb", "a\u{1b}b"] {
            assert!(script(exe, &[("relay-server", bad)], "relay-server").is_err());
            assert!(script(bad, &ok, "relay-server").is_err());
        }
        // option 名稱：夾帶指令、大寫、空字串
        for key in ["relay-server; rm -rf /", "Relay", "", "a b", "k'x", "k$(x)"] {
            assert!(script(exe, &[(key, "v")], "relay-server").is_err(), "{key}");
            assert!(script(exe, &ok, key).is_err(), "{key}");
        }
        assert!(script("", &ok, "relay-server").is_err());
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

    fn owner_plan<'a>(dumps: &'a [&'a str], files: &'a [&'a str]) -> Result<String, String> {
        build_script(&Plan {
            exe: "/usr/bin/rustdesk",
            changes: &[("relay-server", "x")],
            readback_key: "relay-server",
            dumps,
            owner: Some((501, 20)),
            restore_owner_of: files,
        })
    }

    #[test]
    fn script_checks_and_dumps_first_then_restores_owner_before_the_readback() {
        let s = owner_plan(
            &["/root/.config/rustdesk/RustDesk2.toml"],
            &["/home/u/.config/rustdesk/RustDesk2.toml"],
        )
        .unwrap();
        let target = "'/home/u/.config/rustdesk' 'RustDesk2.toml'";
        let check = s.find(&format!("rds_own {target} check")).unwrap();
        let dump = s
            .find("rds_dump 0 '/root/.config/rustdesk/RustDesk2.toml'")
            .unwrap();
        let option = s.find("--option 'relay-server' 'x'").unwrap();
        let restore = s.find(&format!("rds_own {target} chown")).unwrap();
        let marker = s.find(&format!("echo {MARKER}")).unwrap();
        assert!(
            check < dump && dump < option && option < restore && restore < marker,
            "{s}"
        );
        // 固定 PATH、chown 不跟隨 symlink、拒絕 symlink 與硬連結、比對實際路徑
        assert!(s.starts_with("set -e; PATH=/usr/bin:/bin:/usr/sbin:/sbin; export PATH; "));
        assert!(s.contains("chown -h 501:20 \"./$2\""));
        assert!(s.contains("if [ -L \"./$2\" ]"));
        assert!(s.contains("-type f -links 1"));
        assert!(s.contains("cd -P -- \"$1\""));
        assert!(s.contains("-type d -user 501"));
        // root 不再把任何檔案複製到使用者可寫的位置
        assert!(!s.contains("cp "), "{s}");
    }

    #[test]
    fn script_without_owner_does_not_touch_user_files() {
        let s = build_script(&Plan {
            exe: "/usr/bin/rustdesk",
            changes: &[("relay-server", "x")],
            readback_key: "relay-server",
            dumps: &[],
            owner: None,
            restore_owner_of: &["/home/u/x.toml"],
        })
        .unwrap();
        assert!(!s.contains("rds_own"), "{s}");
        assert!(!s.contains("chown"), "{s}");
    }

    #[test]
    fn script_rejects_bad_dump_and_owner_paths() {
        assert!(owner_plan(&["/a"], &["/c/d"]).is_ok());
        assert!(owner_plan(&["/a"], &["/d"]).is_ok()); // 根目錄下的檔案
        for bad_dump in ["", "rel/a", "/a\n; rm -rf /", "/a\0"] {
            assert!(owner_plan(&[bad_dump], &[]).is_err(), "{bad_dump:?}");
        }
        for bad in [
            "",
            "relative/x",
            "/c\u{0}",
            "/c/../etc/shadow",
            "/c/./x",
            "/c//x",
            "/c/x/",
            "/",
            "/c/-rf",
            "/c/x\n",
        ] {
            assert!(owner_plan(&[], &[bad]).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn split_abs_cases() {
        assert_eq!(split_abs("/a/b/c.toml"), Some(("/a/b", "c.toml")));
        assert_eq!(split_abs("/c.toml"), Some(("/", "c.toml")));
        assert_eq!(split_abs("/a b/it's.toml"), Some(("/a b", "it's.toml")));
        assert_eq!(split_abs("a/b"), None);
        assert_eq!(split_abs("/a/.."), None);
        assert_eq!(split_abs("/a/-x"), None);
    }

    #[test]
    fn dump_parsing() {
        use base64::Engine;
        let data = b"[options]\nkey = 'secret'\n\x00\xff";
        let enc = base64::engine::general_purpose::STANDARD.encode(data);
        // GNU base64 每 76 字元換行；macOS do shell script 把 \n 改成 \r
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

    /// 以真正的 /bin/sh 與假的 rustdesk 執行腳本的測試環境（不需要 root：chown 成自己的 uid/gid）。
    #[cfg(unix)]
    struct ShellSandbox {
        dir: std::path::PathBuf,
        fake: String,
        /// 假的 rustdesk 被執行過就會出現這個檔案（用來確認「中止時沒有做任何變更」）。
        ran: std::path::PathBuf,
    }

    #[cfg(unix)]
    impl ShellSandbox {
        /// `extra`：假的 rustdesk 每次執行時額外跑的 shell 指令（模擬執行期間的攻擊）。
        fn new(tag: &str, extra: &str) -> Self {
            use std::os::unix::fs::PermissionsExt;
            let dir = std::env::temp_dir().join(format!("rds-elev-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            // macOS 的暫存資料夾在 /var -> /private/var 之下；腳本要求不含 symlink 的路徑
            let dir = std::fs::canonicalize(&dir).unwrap();
            let ran = dir.join("RAN");
            let fake = dir.join("fake rustdesk");
            std::fs::write(
                &fake,
                format!(
                    "#!/bin/sh\necho \"ARGS:$*\"\n: > {}\n{extra}\n",
                    sh_quote(&ran.to_string_lossy())
                ),
            )
            .unwrap();
            std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
            Self {
                fake: fake.to_string_lossy().to_string(),
                dir,
                ran,
            }
        }

        fn path(&self, name: &str) -> String {
            self.dir.join(name).to_string_lossy().to_string()
        }

        fn run(&self, dumps: &[&str], files: &[&str]) -> std::process::Output {
            // SAFETY: getuid/getgid 不接受參數、不會失敗，也沒有副作用。
            let owner = unsafe { (libc::getuid(), libc::getgid()) };
            let s = build_script(&Plan {
                exe: &self.fake,
                changes: &[("custom-rendezvous-server", "203.0.113.5")],
                readback_key: "custom-rendezvous-server",
                dumps,
                owner: Some(owner),
                restore_owner_of: files,
            })
            .unwrap();
            std::process::Command::new("/bin/sh")
                .arg("-c")
                .arg(&s)
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

    /// 正常流程：服務設定被印出供本程式備份、含空白與單引號的路徑也能處理、
    /// 檔案不存在不會讓腳本失敗、擁有者還原成功。
    #[cfg(unix)]
    #[test]
    fn real_shell_dump_and_owner_restore() {
        let sb = ShellSandbox::new("ok", "");
        std::fs::create_dir_all(sb.dir.join("it's dir")).unwrap();
        let cfg = sb.path("it's dir/cfg.toml");
        std::fs::write(&cfg, "user").unwrap();
        let svc = sb.path("service.toml");
        std::fs::write(&svc, b"[options]\nk = 'v'\n\x00\xff").unwrap();
        let (missing_dump, missing_cfg) = (sb.path("missing.toml"), sb.path("nope/cfg.toml"));

        let out = sb.run(&[&svc, &missing_dump], &[&cfg, &missing_cfg]);
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
        assert!(parse_readback(&text).is_some());
        assert_eq!(std::fs::read_to_string(&cfg).unwrap(), "user");
    }

    /// 攻擊：使用者設定檔被換成指向系統檔案的 symlink。必須在任何變更之前中止，且不動到目標。
    #[cfg(unix)]
    #[test]
    fn real_shell_symlinked_config_aborts_before_any_change() {
        use std::os::unix::fs::MetadataExt;
        let sb = ShellSandbox::new("symlink", "");
        let victim = sb.path("victim");
        std::fs::write(&victim, "victim").unwrap();
        let before = std::fs::metadata(&victim).unwrap();
        std::fs::create_dir_all(sb.dir.join("cfgdir")).unwrap();
        let cfg = sb.path("cfgdir/RustDesk2.toml");
        std::os::unix::fs::symlink(&victim, &cfg).unwrap();

        let out = sb.run(&[], &[&cfg]);
        assert!(!out.status.success());
        assert!(String::from_utf8_lossy(&out.stderr).contains("refusing symlink"));
        assert!(!sb.ran.exists(), "中止前不可執行 rustdesk --option");
        assert!(!String::from_utf8_lossy(&out.stdout).contains(MARKER));
        let after = std::fs::metadata(&victim).unwrap();
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "victim");
        assert_eq!(
            (after.uid(), after.gid(), after.mode()),
            (before.uid(), before.gid(), before.mode())
        );
        // 符號連結本身也沒有被替換
        assert!(std::fs::symlink_metadata(&cfg)
            .unwrap()
            .file_type()
            .is_symlink());
    }

    /// 攻擊：設定檔所在的資料夾被換成 symlink（指向系統資料夾）。
    #[cfg(unix)]
    #[test]
    fn real_shell_symlinked_directory_aborts() {
        let sb = ShellSandbox::new("dirlink", "");
        std::fs::create_dir_all(sb.dir.join("real")).unwrap();
        std::fs::write(sb.dir.join("real/RustDesk2.toml"), "x").unwrap();
        std::os::unix::fs::symlink(sb.dir.join("real"), sb.dir.join("link")).unwrap();
        let out = sb.run(&[], &[&sb.path("link/RustDesk2.toml")]);
        assert!(!out.status.success());
        assert!(String::from_utf8_lossy(&out.stderr).contains("unsafe directory"));
        assert!(!sb.ran.exists());
    }

    /// 攻擊：設定檔是指向系統檔案的硬連結（chown 會改到系統檔案本身）。
    #[cfg(unix)]
    #[test]
    fn real_shell_hardlinked_config_aborts() {
        let sb = ShellSandbox::new("hardlink", "");
        let victim = sb.path("victim");
        std::fs::write(&victim, "victim").unwrap();
        std::fs::create_dir_all(sb.dir.join("cfgdir")).unwrap();
        let cfg = sb.path("cfgdir/RustDesk2.toml");
        std::fs::hard_link(&victim, &cfg).unwrap();
        let out = sb.run(&[], &[&cfg]);
        assert!(!out.status.success());
        assert!(String::from_utf8_lossy(&out.stderr).contains("hard-linked"));
        assert!(!sb.ran.exists());
    }

    /// 攻擊：在 rustdesk 執行期間（檢查之後）才把設定檔換成 symlink。chown 前的再次檢查必須中止。
    #[cfg(unix)]
    #[test]
    fn real_shell_symlink_swapped_in_after_the_first_check_aborts_before_chown() {
        // 假的 rustdesk 執行時把設定檔換成指向 victim 的 symlink（路徑相對於假程式所在的資料夾）
        let swap = r#"d=$(dirname "$0"); rm -f "$d/cfgdir/RustDesk2.toml"; ln -s "$d/victim" "$d/cfgdir/RustDesk2.toml""#;
        let sb = ShellSandbox::new("swap", swap);
        std::fs::write(sb.path("victim"), "victim").unwrap();
        std::fs::create_dir_all(sb.dir.join("cfgdir")).unwrap();
        let cfg = sb.path("cfgdir/RustDesk2.toml");
        std::fs::write(&cfg, "user").unwrap();
        let out = sb.run(&[], &[&cfg]);
        assert!(sb.ran.exists(), "第一次檢查應該通過");
        assert!(!out.status.success());
        assert!(String::from_utf8_lossy(&out.stderr).contains("refusing symlink"));
        assert!(!String::from_utf8_lossy(&out.stdout).contains(MARKER));
        assert_eq!(
            std::fs::read_to_string(sb.path("victim")).unwrap(),
            "victim"
        );
    }

    /// 要印出的服務設定是 symlink：中止，不把連結目標的內容印給一般權限的程式。
    #[cfg(unix)]
    #[test]
    fn real_shell_symlinked_dump_source_aborts() {
        let sb = ShellSandbox::new("dumplink", "");
        std::fs::write(sb.path("secret"), "secret").unwrap();
        std::os::unix::fs::symlink(sb.dir.join("secret"), sb.dir.join("svc.toml")).unwrap();
        let out = sb.run(&[&sb.path("svc.toml")], &[]);
        assert!(!out.status.success());
        assert!(!String::from_utf8_lossy(&out.stdout).contains("c2VjcmV0")); // "secret" 的 base64
        assert!(!sb.ran.exists());
    }

    #[test]
    fn osascript_arg_embeds_the_quoted_script() {
        let a = osascript_arg("set -e; echo \"hi\"");
        assert_eq!(
            a,
            "do shell script \"set -e; echo \\\"hi\\\"\" with administrator privileges"
        );
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
        assert!(is_cancelled(
            Some(1),
            "execution error: User canceled. (-128)"
        ));
        assert!(is_cancelled(Some(126), ""));
        assert!(!is_cancelled(
            Some(1),
            "execution error: not allowed (-60007)"
        ));
        assert!(!is_cancelled(
            Some(127),
            "Error executing command as another user"
        ));
    }
}
