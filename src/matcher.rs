pub struct Matcher {
    pattern: Vec<u8>,
    state: usize,
}

impl Matcher {
    pub fn new(pattern: &str) -> Self {
        Self {
            pattern: pattern.as_bytes().to_vec(),
            state: 0,
        }
    }

    pub fn feed(&mut self, data: &[u8]) -> bool {
        if self.pattern.is_empty() {
            return false;
        }
        for &byte in data {
            if self.state < self.pattern.len() && self.pattern[self.state] == byte {
                self.state += 1;
            } else {
                self.state = 0;
                if !self.pattern.is_empty() && self.pattern[0] == byte {
                    self.state = 1;
                }
            }
            if self.state == self.pattern.len() {
                return true;
            }
        }
        false
    }

    pub fn reset(&mut self) {
        self.state = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_match() {
        let mut m = Matcher::new("assword:");
        assert!(m.feed(b"Password:"));
    }

    #[test]
    fn match_across_buffers() {
        let mut m = Matcher::new("assword:");
        assert!(!m.feed(b"Pass"));
        assert!(m.feed(b"word:"));
    }

    #[test]
    fn no_match() {
        let mut m = Matcher::new("assword:");
        assert!(!m.feed(b"something else entirely"));
    }

    #[test]
    fn match_after_partial_mismatch() {
        let mut m = Matcher::new("abc");
        assert!(m.feed(b"ababc"));
    }

    #[test]
    fn no_match_partial_only() {
        let mut m = Matcher::new("abcd");
        assert!(!m.feed(b"abcx"));
    }

    #[test]
    fn match_at_start() {
        let mut m = Matcher::new("hello");
        assert!(m.feed(b"hello world"));
    }

    #[test]
    fn match_at_end() {
        let mut m = Matcher::new("world");
        assert!(m.feed(b"hello world"));
    }

    #[test]
    fn match_in_middle() {
        let mut m = Matcher::new("assword:");
        assert!(m.feed(b"user@host's password: "));
    }

    #[test]
    fn reset_clears_state() {
        let mut m = Matcher::new("assword:");
        m.feed(b"asswo");
        m.reset();
        assert!(!m.feed(b"rd:"));
    }

    #[test]
    fn split_single_char_boundary() {
        let mut m = Matcher::new("assword:");
        assert!(!m.feed(b"assword"));
        assert!(m.feed(b":"));
    }

    #[test]
    fn host_key_match() {
        let mut m = Matcher::new("The authenticity of host ");
        assert!(m.feed(b"The authenticity of host 'example.com' can't be established."));
    }

    #[test]
    fn host_key_changed_match() {
        let mut m = Matcher::new("differs from the key for the IP address");
        assert!(m.feed(b"WARNING: the RSA host key differs from the key for the IP address"));
    }

    #[test]
    fn empty_pattern_never_matches() {
        let mut m = Matcher::new("");
        assert!(!m.feed(b"anything"));
    }
}
