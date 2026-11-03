//! The `/` filter: every word must match, and `!word` excludes.

use crate::packet::find_ignore_case;

/// A parsed filter. Words are lowercase.
#[derive(Default, Debug)]
pub struct Query {
    pub want: Vec<String>,
    pub avoid: Vec<String>,
}

/// What a query found so far in something made of several parts (a
/// conversation's packets): which wanted words, and whether any excluded one.
#[derive(Clone, Debug)]
pub struct Found {
    want: Vec<bool>,
    avoided: bool,
}

impl Query {
    pub fn parse(filter: &str) -> Self {
        let mut q = Self::default();
        for w in filter.to_lowercase().split_whitespace() {
            match w.strip_prefix('!') {
                Some("") => {}
                Some(not) => q.avoid.push(not.to_string()),
                None => q.want.push(w.to_string()),
            }
        }
        q
    }

    pub fn is_empty(&self) -> bool {
        self.want.is_empty() && self.avoid.is_empty()
    }

    /// Whether `fields` and `bytes` together match.
    pub fn matches(&self, fields: &[&str], bytes: &[u8]) -> bool {
        if self.is_empty() {
            return true;
        }
        let mut f = self.found();
        self.scan(&mut f, fields, bytes);
        self.passes(&f)
    }

    pub fn found(&self) -> Found {
        Found {
            want: vec![false; self.want.len()],
            avoided: false,
        }
    }

    /// Adds what `fields` and `bytes` contain to `f`.
    pub fn scan(&self, f: &mut Found, fields: &[&str], bytes: &[u8]) {
        let hit = |w: &str| {
            fields.iter().any(|field| contains(field, w))
                || find_ignore_case(bytes, w.as_bytes()).is_some()
        };
        for (seen, w) in f.want.iter_mut().zip(&self.want) {
            *seen = *seen || hit(w);
        }
        f.avoided = f.avoided || self.avoid.iter().any(|w| hit(w));
    }

    /// Every wanted word was found, and no excluded one.
    pub fn passes(&self, f: &Found) -> bool {
        !f.avoided && f.want.iter().all(|s| *s)
    }
}

/// Whether `field` contains `word` (already lowercase), ignoring case. Plain
/// ASCII is compared in place, without making a lowercase copy.
fn contains(field: &str, word: &str) -> bool {
    if field.is_ascii() {
        find_ignore_case(field.as_bytes(), word.as_bytes()).is_some()
    } else {
        field.to_lowercase().contains(word)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn words_and_exclusions() {
        let q = Query::parse("Fire !Socket !");
        assert_eq!((q.want.len(), q.avoid.len()), (1, 1));
        assert!(q.matches(&["firefox", "443"], b""));
        assert!(!q.matches(&["firefox", "Socket Thread"], b""));
        assert!(!q.matches(&["curl"], b"firefox"[..0].as_ref()));
        assert!(q.matches(&["x"], b"..FIREfox.."));
        assert!(Query::parse("ÉTÉ").matches(&["été"], b""));
        assert!(Query::parse("  ").matches(&[], b""));
    }

    #[test]
    fn parts_add_up() {
        // A conversation matches "get !secret" only if some packet has "get"
        // and none has "secret".
        let q = Query::parse("get !secret");
        let mut f = q.found();
        q.scan(&mut f, &["tcp"], b"GET / HTTP/1.1");
        assert!(q.passes(&f));
        q.scan(&mut f, &["tcp"], b"password=secret");
        assert!(!q.passes(&f));
    }
}
