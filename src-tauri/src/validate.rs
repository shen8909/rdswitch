//! 欄位格式驗證（純函式，白名單）。
//!
//! 信任邊界：使用者輸入、貼上的設定字串與 profiles.json 內容一律視為不可信，
//! 在寫入 RustDesk 設定檔、或交給 `rustdesk --option` 之前都要通過這裡。
//! 空字串代表「回到官方預設」，一律合法，是否允許全空由呼叫端決定。

use std::net::Ipv6Addr;

/// 每個欄位的長度上限（以 Unicode 字元數計）。
pub const MAX_LEN: usize = 256;
const MAX_NAME_LEN: usize = 64;

/// 驗證失敗的欄位種類，由呼叫端對應成可翻譯的訊息。
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Invalid {
    Name,
    HostPort,
    Url,
    Key,
}

fn within(s: &str, max: usize) -> bool {
    s.chars().count() <= max
}

/// profile 名稱：非空、長度受限、不含控制字元（含換行與 NUL）。
pub fn name(s: &str) -> Result<(), Invalid> {
    let ok = !s.is_empty() && within(s, MAX_NAME_LEN) && !s.chars().any(char::is_control);
    ok.then_some(()).ok_or(Invalid::Name)
}

fn valid_port(p: &str) -> bool {
    !p.is_empty()
        && p.len() <= 5
        && p.bytes().all(|b| b.is_ascii_digit())
        && p.parse::<u32>().is_ok_and(|n| (1..=65535).contains(&n))
}

fn valid_hostname(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= 253
        && h.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

/// `host`、`host:port`、`ipv4:port`、`[ipv6]:port` 或單獨的 `ipv6`。空字串合法。
pub fn host_port(s: &str) -> Result<(), Invalid> {
    if s.is_empty() {
        return Ok(());
    }
    let ok = within(s, MAX_LEN) && {
        if let Some(rest) = s.strip_prefix('[') {
            // [ipv6] 或 [ipv6]:port
            rest.split_once(']').is_some_and(|(addr, tail)| {
                addr.parse::<Ipv6Addr>().is_ok()
                    && (tail.is_empty() || tail.strip_prefix(':').is_some_and(valid_port))
            })
        } else if s.parse::<Ipv6Addr>().is_ok() {
            true // 沒有埠號的 IPv6 位址
        } else {
            match s.split_once(':') {
                None => valid_hostname(s),
                Some((host, port)) => valid_hostname(host) && valid_port(port),
            }
        }
    };
    ok.then_some(()).ok_or(Invalid::HostPort)
}

/// API 伺服器：只接受 http(s) URL，且只含可見 ASCII 字元（不含空白、控制字元、引號）。空字串合法。
pub fn api_url(s: &str) -> Result<(), Invalid> {
    if s.is_empty() {
        return Ok(());
    }
    let rest = s
        .strip_prefix("https://")
        .or_else(|| s.strip_prefix("http://"));
    let ok = within(s, MAX_LEN)
        && rest.is_some_and(|r| !r.is_empty())
        && s.bytes()
            .all(|b| b.is_ascii_graphic() && !matches!(b, b'"' | b'\'' | b'\\' | b'<' | b'>'));
    ok.then_some(()).ok_or(Invalid::Url)
}

/// 公鑰：base64（標準或 URL-safe）字元集。空字串合法。
pub fn key(s: &str) -> Result<(), Invalid> {
    let ok = within(s, MAX_LEN)
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'-' | b'_'));
    ok.then_some(()).ok_or(Invalid::Key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_rules() {
        assert!(name("lab").is_ok());
        assert!(name("實驗室 1").is_ok());
        assert_eq!(name(""), Err(Invalid::Name));
        assert_eq!(name("a\nb"), Err(Invalid::Name));
        assert_eq!(name("a\0b"), Err(Invalid::Name));
        assert_eq!(name("a\tb"), Err(Invalid::Name));
        assert_eq!(name(&"x".repeat(65)), Err(Invalid::Name));
        assert!(name(&"x".repeat(64)).is_ok());
    }

    #[test]
    fn host_port_accepts_valid() {
        for ok in [
            "",
            "rs.example.com",
            "rs.example.com:21116",
            "192.0.2.1",
            "192.0.2.1:21116",
            "my_host-1.lan:1",
            "[2001:db8::1]:21116",
            "[2001:db8::1]",
            "2001:db8::1",
            "localhost:65535",
        ] {
            assert!(host_port(ok).is_ok(), "{ok}");
        }
    }

    #[test]
    fn host_port_rejects_invalid() {
        for bad in [
            "host:0",
            "host:65536",
            "host:abc",
            "host:",
            ":21116",
            "ho st",
            "host\n",
            "host\r:1",
            "host'x",
            "-bad.example.com",
            "a..b",
            "host:1:2",
            "[2001:db8::1",
            "[nothex]:1",
            "[2001:db8::1]x",
            "http://host",
            "host/path",
            "ホスト",
        ] {
            assert_eq!(host_port(bad), Err(Invalid::HostPort), "{bad}");
        }
        assert_eq!(
            host_port(&format!("{}.com", "a".repeat(260))),
            Err(Invalid::HostPort)
        );
    }

    #[test]
    fn api_url_rules() {
        assert!(api_url("").is_ok());
        assert!(api_url("https://api.example.com").is_ok());
        assert!(api_url("http://192.0.2.1:21114/path?x=1").is_ok());
        for bad in [
            "ftp://x",
            "example.com",
            "https://",
            "https://a b",
            "https://a\nb",
            "https://a'b",
            "javascript:alert(1)",
            "https://é.com",
        ] {
            assert_eq!(api_url(bad), Err(Invalid::Url), "{bad}");
        }
    }

    #[test]
    fn key_rules() {
        assert!(key("").is_ok());
        assert!(key("AbC+/=_-0123").is_ok());
        for bad in ["a b", "a\nb", "a'b", "key\u{0}", "金鑰"] {
            assert_eq!(key(bad), Err(Invalid::Key), "{bad}");
        }
        assert_eq!(key(&"a".repeat(257)), Err(Invalid::Key));
    }
}
