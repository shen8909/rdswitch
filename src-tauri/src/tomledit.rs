//! 最小化的 TOML `[options]` 編輯器：只改動目標 key，保留其他內容與順序。

use regex::Regex;
use std::collections::HashMap;
use std::sync::OnceLock;

/// `value` 為 None 代表移除該 key。
pub struct Change {
    pub key: &'static str,
    pub value: Option<String>,
}

fn header_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"^\s*\[.*\]\s*$").unwrap())
}

fn key_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"^\s*([A-Za-z0-9_.-]+)\s*=").unwrap())
}

fn value_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r#"^\s*([A-Za-z0-9_.-]+)\s*=\s*(?:'([^']*)'|"((?:[^"\\]|\\.)*)")"#).unwrap()
    })
}

/// TOML literal string（單引號）不允許控制字元（Tab 除外）與單引號本身；
/// 其餘情況改用 basic string，並依規範跳脫所有控制字元，避免寫出不合法的 TOML。
fn quote(v: &str) -> String {
    let needs_escape = |c: char| c == '\'' || (c.is_control() && c != '\t');
    if !v.chars().any(needs_escape) {
        return format!("'{v}'");
    }
    let mut out = String::with_capacity(v.len() + 2);
    out.push('"');
    for c in v.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04X}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars();
    while let Some(c) = it.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match it.next() {
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some('u') => {
                let hex: String = it.by_ref().take(4).collect();
                match u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32) {
                    Some(ch) => out.push(ch),
                    None => {
                        out.push_str("\\u");
                        out.push_str(&hex);
                    }
                }
            }
            Some(o) => out.push(o),
            None => out.push('\\'),
        }
    }
    out
}

fn split_lines(text: &str) -> Vec<String> {
    let t = text.replace("\r\n", "\n");
    let t = t.strip_suffix('\n').unwrap_or(&t);
    if t.is_empty() {
        vec![]
    } else {
        t.split('\n').map(String::from).collect()
    }
}

/// 回傳 `[options]` 標頭所在行與區段結束行（不含）。
fn options_range(lines: &[String]) -> Option<(usize, usize)> {
    let start = lines.iter().position(|l| l.trim() == "[options]")?;
    let end = (start + 1..lines.len())
        .find(|&i| header_re().is_match(&lines[i]))
        .unwrap_or(lines.len());
    Some((start, end))
}

pub fn get_options(text: &str) -> HashMap<String, String> {
    let lines = split_lines(text);
    let mut res = HashMap::new();
    if let Some((s, e)) = options_range(&lines) {
        for l in &lines[s + 1..e] {
            if let Some(m) = value_re().captures(l) {
                let v = match (m.get(2), m.get(3)) {
                    (Some(a), _) => a.as_str().to_string(),
                    (_, Some(b)) => unescape(b.as_str()),
                    _ => continue,
                };
                res.insert(m[1].to_string(), v);
            }
        }
    }
    res
}

pub fn set_options(text: &str, changes: &[Change]) -> String {
    let mut lines = split_lines(text);
    let (s, e) = match options_range(&lines) {
        Some(r) => r,
        None => {
            if lines.last().is_some_and(|l| !l.trim().is_empty()) {
                lines.push(String::new());
            }
            lines.push("[options]".into());
            (lines.len() - 1, lines.len())
        }
    };

    let mut pending: HashMap<&str, &Option<String>> =
        changes.iter().map(|c| (c.key, &c.value)).collect();
    let mut section: Vec<String> = Vec::new();
    for l in &lines[s + 1..e] {
        if let Some(m) = key_re().captures(l) {
            if let Some(v) = pending.remove(&m[1]) {
                if let Some(v) = v {
                    section.push(format!("{} = {}", &m[1], quote(v)));
                }
                continue;
            }
        }
        section.push(l.clone());
    }
    let mut trailing = Vec::new();
    while section.last().is_some_and(|l| l.trim().is_empty()) {
        trailing.push(section.pop().unwrap());
    }
    for c in changes {
        if let Some(Some(v)) = pending.get(c.key) {
            section.push(format!("{} = {}", c.key, quote(v)));
        }
    }
    section.extend(trailing);

    let mut out: Vec<String> = lines[..=s].to_vec();
    out.extend(section);
    out.extend_from_slice(&lines[e..]);
    out.join("\n") + "\n"
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "rendezvous_server = '198.51.100.2:21116'\nserial = 0\n\n[options]\n\
custom-rendezvous-server = '192.0.2.10:21116'\nkey = 'abc'\naccess-mode = 'full'\n\n[other]\nx = 1\n";

    fn ch(key: &'static str, v: Option<&str>) -> Change {
        Change {
            key,
            value: v.map(String::from),
        }
    }

    #[test]
    fn replace_add_remove() {
        let out = set_options(
            SAMPLE,
            &[
                ch("custom-rendezvous-server", Some("h:21116")),
                ch("key", None),
                ch("api-server", Some("http://a")),
            ],
        );
        let o = get_options(&out);
        assert_eq!(o["custom-rendezvous-server"], "h:21116");
        assert_eq!(o["api-server"], "http://a");
        assert_eq!(o["access-mode"], "full");
        assert!(!o.contains_key("key"));
        assert!(out.ends_with("[other]\nx = 1\n"), "{out}");
        assert!(out.starts_with("rendezvous_server = '198.51.100.2:21116'\nserial = 0\n"));
    }

    #[test]
    fn no_options_section() {
        let o = get_options(&set_options("serial = 0\n", &[ch("key", Some("k"))]));
        assert_eq!(o.len(), 1);
        assert_eq!(o["key"], "k");
    }

    #[test]
    fn quote_roundtrip() {
        let o = get_options(&set_options("", &[ch("key", Some("it's"))]));
        assert_eq!(o["key"], "it's");
    }

    #[test]
    fn control_chars_are_escaped_and_roundtrip() {
        for v in [
            "a\nb",
            "a\r\nb",
            "a\0b",
            "tab\there",
            "\u{7f}",
            "q\"uote\\back",
            "it's\u{1}",
        ] {
            let out = set_options("", &[ch("key", Some(v))]);
            // 寫出的值不可含有原始的控制字元（Tab 在 literal string 內合法）
            let line = out.lines().find(|l| l.starts_with("key")).unwrap();
            assert!(
                !line.chars().any(|c| c.is_control() && c != '\t'),
                "{v:?} -> {line:?}"
            );
            assert_eq!(get_options(&out)["key"], v, "{v:?}");
        }
        // 一般字串仍使用 literal string，保持與 RustDesk 慣例一致
        assert!(set_options("", &[ch("key", Some("abc"))]).contains("key = 'abc'"));
    }

    #[test]
    fn crlf_input() {
        let o = get_options(&set_options(
            "[options]\r\nkey = 'a'\r\n",
            &[ch("key", Some("b"))],
        ));
        assert_eq!(o["key"], "b");
    }
}
