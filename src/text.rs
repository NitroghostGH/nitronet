//! Making untrusted text safe to show in a terminal.
//!
//! Process names (/proc/<pid>/comm), cgroup names, host names from reverse
//! lookups and the like can be set by other users or other machines, and may
//! contain escape sequences. Printed as-is to a terminal, those could move
//! the cursor, hide lines, or set the window title. The TUI is protected by
//! ratatui, which drops control characters, but plain-text output (`--once`,
//! `--scan`) is not, so names are cleaned where they enter the program.

/// Replaces control characters (C0, DEL, C1) and invisible formatting
/// characters (zero-width and bidirectional overrides) with '?'.
pub fn clean(s: &str) -> String {
    if !s.chars().any(unsafe_char) {
        return s.to_string();
    }
    s.chars()
        .map(|c| if unsafe_char(c) { '?' } else { c })
        .collect()
}

fn unsafe_char(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{200b}'..='\u{200f}'
                | '\u{2028}'..='\u{202e}'
                | '\u{2060}'..='\u{2069}'
                | '\u{feff}'
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removes_escapes_and_invisible_characters() {
        assert_eq!(clean("firefox"), "firefox");
        assert_eq!(clean("naïve café ✓"), "naïve café ✓");
        assert_eq!(clean("x\u{1b}]0;t\u{7}y"), "x?]0;t?y");
        assert_eq!(clean("a\u{9b}2Jb"), "a?2Jb"); // C1 CSI
        assert_eq!(clean("a\u{7f}b\tc\nd"), "a?b?c?d");
        assert_eq!(clean("evil\u{202e}gpj.exe"), "evil?gpj.exe");
        assert_eq!(clean("zero\u{200b}width"), "zero?width");
    }
}
