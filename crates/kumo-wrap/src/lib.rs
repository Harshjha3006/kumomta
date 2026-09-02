use bstr::{BStr, ByteVec};
use std::sync::atomic::{AtomicBool, Ordering};

pub const SOFT_WIDTH: usize = 75;
pub const HARD_WIDTH: usize = 900;

static SOFT_WRAP_ENABLED: AtomicBool = AtomicBool::new(true);

/// Controls whether `wrap`/`wrap_bytes` fold long header values at
/// `SOFT_WIDTH` for readability. This is process-wide, intended to be
/// set once via Lua config (`kumo.set_header_soft_wrap_enabled`).
/// The hard-wrap safety net (`HARD_WIDTH`) that keeps a single
/// unbreakable token from producing an SMTP-illegal line always stays
/// active regardless of this setting.
pub fn set_soft_wrap_enabled(enabled: bool) {
    SOFT_WRAP_ENABLED.store(enabled, Ordering::Relaxed);
}

fn soft_wrap_enabled() -> bool {
    SOFT_WRAP_ENABLED.load(Ordering::Relaxed)
}

fn soft_width() -> usize {
    if soft_wrap_enabled() {
        SOFT_WIDTH
    } else {
        // wrap_impl only ever consults hard_width once a line has
        // already exceeded soft_width, so usize::MAX here would
        // disable the hard-wrap safety net too. Using HARD_WIDTH
        // keeps whitespace-separated content on one line (no
        // readability folding) while still forcing a break, at a
        // word boundary when possible, once a line would otherwise
        // exceed the SMTP-safe length.
        HARD_WIDTH
    }
}

pub fn wrap(value: &str) -> String {
    String::from_utf8(wrap_impl(value, soft_width(), HARD_WIDTH)).expect("utf8-in, utf8-out")
}

pub fn wrap_bytes(value: impl AsRef<BStr>) -> Vec<u8> {
    wrap_impl(value, soft_width(), HARD_WIDTH)
}

/// We can't use textwrap::fill here because it will prefer to break
/// a line rather than finding stuff that fits.  We use a simple
/// algorithm that tries to fill up to the desired width, allowing
/// for overflow if there is a word that is too long to fit in
/// the header, but breaking after a hard limit threshold.
pub fn wrap_impl(value: impl AsRef<BStr>, soft_width: usize, hard_width: usize) -> Vec<u8> {
    let value: &BStr = value.as_ref();
    let mut result: Vec<u8> = vec![];
    let mut line: Vec<u8> = vec![];

    for word in value.split(|&b| b.is_ascii_whitespace()) {
        if word.is_empty() {
            continue;
        }
        if line.len() + word.len() < soft_width {
            if !line.is_empty() {
                line.push(b' ');
            }
            line.push_str(word);
            continue;
        }

        // Need to wrap.

        // Accumulate line so far, if any
        if !line.is_empty() {
            if !result.is_empty() {
                // There's an existing line, start a new one, indented
                result.push(b'\t');
            }
            result.push_str(&line);
            result.push_str("\r\n");
            line.clear();
        }

        // build out a line from the characters of this one
        if word.len() <= hard_width {
            line.push_str(word);
        } else {
            for &c in word.iter() {
                line.push(c);
                if line.len() >= hard_width {
                    if !result.is_empty() {
                        result.push(b'\t');
                    }
                    result.push_str(&line);
                    result.push_str("\r\n");
                    line.clear();
                    continue;
                }
            }
        }
    }

    if !line.is_empty() {
        if !result.is_empty() {
            result.push(b'\t');
        }
        result.push_str(&line);
    }

    result
}

#[cfg(test)]
mod test {
    use super::*;

    /// Restores the global soft-wrap toggle to its default (enabled)
    /// state when dropped, so a panic mid-test can't leak state into
    /// other tests in this binary.
    struct SoftWrapGuard;

    impl Drop for SoftWrapGuard {
        fn drop(&mut self) {
            set_soft_wrap_enabled(true);
        }
    }

    // Both properties live in one test because `set_soft_wrap_enabled`
    // is process-wide global state; splitting them risks a race with
    // cargo's default parallel test threads.
    #[test]
    fn soft_wrap_toggle() {
        let _guard = SoftWrapGuard;

        let words = "word ".repeat(20);
        let words = words.trim();
        assert!(words.len() > SOFT_WIDTH, "fixture must exceed SOFT_WIDTH");

        set_soft_wrap_enabled(false);
        k9::assert_equal!(wrap(words), words);
        k9::assert_equal!(wrap_bytes(words), words.as_bytes().to_vec());

        let long_word = "a".repeat(HARD_WIDTH + 100);
        let wrapped = wrap(&long_word);
        assert!(
            wrapped.contains("\r\n\t"),
            "expected hard-wrap fold even with soft wrap disabled, got: {wrapped}"
        );

        set_soft_wrap_enabled(true);
        assert!(
            wrap(words).contains("\r\n\t"),
            "expected soft wrap to resume once re-enabled"
        );
    }

    #[test]
    fn wrapping() {
        for (input, expect) in [
            ("foo", "foo"),
            ("hi there", "hi there"),
            ("hello world", "hello\r\n\tworld"),
            ("hello world ", "hello\r\n\tworld"),
            (
                "hello world foo bar baz woot woot",
                "hello\r\n\tworld foo\r\n\tbar baz\r\n\twoot woot",
            ),
            (
                "hi there breakmepleaseIamtoolong",
                "hi there\r\n\tbreakmepleaseIa\r\n\tmtoolong",
            ),
        ] {
            let wrapped = wrap_impl(input, 10, 15);
            k9::assert_equal!(
                wrapped,
                expect.as_bytes(),
                "input: '{input}' should produce '{expect}'"
            );
        }
    }
}
