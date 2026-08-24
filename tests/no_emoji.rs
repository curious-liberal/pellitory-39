//! No-emoji assertion over GUI source files.
//!
//! The project enforces a strict no-emoji policy (decision D8). The CLI
//! is checked by `tests/e2e_encrypt.sh` (test 12). This test checks the
//! GUI source files for emoji codepoints.
//!
//! Box-drawing characters (U+2500–U+257F, e.g. `──`) are intentionally
//! excluded — they are the project's existing section-divider style and
//! are not emoji.

use std::fs;

/// Return true if a `char` is an emoji codepoint.
///
/// Checked ranges (matching the CLI's perl assertion in
/// `tests/e2e_encrypt.sh`):
/// - U+1F000–U+1FAFF: emoji supplemental
/// - U+2600–U+27BF: misc symbols + dingbats
/// - U+2190–U+21FF: arrows
/// - U+2B00–U+2BFF: misc symbols arrows
///
/// Box-drawing (U+2500–U+257F) is excluded — `──` is existing style.
fn is_emoji(c: char) -> bool {
    let cp = c as u32;
    (0x1F000..=0x1FAFF).contains(&cp)
        || (0x2600..=0x27BF).contains(&cp)
        || (0x2190..=0x21FF).contains(&cp)
        || (0x2B00..=0x2BFF).contains(&cp)
}

/// Scan a source file for emoji codepoints and return the first hit
/// (line number + the char) if found.
fn scan_for_emoji(path: &str) -> Option<(usize, char)> {
    let src = fs::read_to_string(path).expect("source file should be readable");
    for (lineno, line) in src.lines().enumerate() {
        for c in line.chars() {
            if is_emoji(c) {
                return Some((lineno + 1, c));
            }
        }
    }
    None
}

#[test]
fn no_emoji_in_gui_source() {
    for path in &["src/gui.rs", "src/gui_support.rs"] {
        if let Some((lineno, c)) = scan_for_emoji(path) {
            panic!(
                "{path}:{lineno}: found emoji codepoint U+{:04X} ({}) \
                 — no emoji allowed in GUI source (decision D8)",
                c as u32,
                c
            );
        }
    }
}
