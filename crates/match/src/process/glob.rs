//! Компактный glob: `*` и `**` (любая цепочка, включая `/`), `?`, `[a-z]`, `[!a]`.

/// Разобранный шаблон.
#[derive(Debug, Clone)]
pub(super) struct Glob {
    tokens: Vec<Token>,
}

#[derive(Debug, Clone)]
enum Token {
    Lit(char),
    One,
    Star,
    // `**/`: ноль или больше каталогов.
    Dirs,
    Class {
        negate: bool,
        items: Vec<(char, char)>,
    },
}

impl Glob {
    /// Разбирает шаблон; ошибка — незакрытый класс.
    pub(super) fn new(pattern: &str) -> Result<Self, String> {
        let mut tokens = Vec::new();
        let mut chars = pattern.chars().peekable();
        let mut at_segment_start = true;

        while let Some(c) = chars.next() {
            let token = match c {
                '*' => {
                    while chars.next_if_eq(&'*').is_some() {}
                    if at_segment_start && chars.next_if_eq(&'/').is_some() {
                        Token::Dirs
                    } else {
                        Token::Star
                    }
                }
                '?' => Token::One,
                '[' => parse_class(&mut chars)?,
                c => Token::Lit(c),
            };
            at_segment_start = matches!(c, '/');
            tokens.push(token);
        }
        Ok(Self { tokens })
    }

    /// Подходит ли строка целиком.
    pub(super) fn is_match(&self, text: &str) -> bool {
        matches(&self.tokens, text)
    }
}

fn parse_class(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> Result<Token, String> {
    let negate = chars.next_if(|c| matches!(c, '!' | '^')).is_some();
    let mut items = Vec::new();
    let mut first = true;
    loop {
        let lo = match chars.next() {
            Some(']') if !first => return Ok(Token::Class { negate, items }),
            Some(c) => c,
            None => return Err("незакрытый класс `[`".into()),
        };
        first = false;
        let mut look = chars.clone();
        if look.next() == Some('-') && look.peek().is_some_and(|&c| c != ']') {
            chars.next();
            let hi = chars.next().unwrap_or(lo);
            items.push((lo, hi));
        } else {
            items.push((lo, lo));
        }
    }
}

/// Проход по множеству достижимых позиций: O(шаблон × текст), без перебора с возвратом.
fn matches(tokens: &[Token], text: &str) -> bool {
    let mut reach = vec![false; text.len() + 1];
    let mut next = vec![false; text.len() + 1];
    reach[0] = true;
    for token in tokens {
        next.fill(false);
        step(token, text, &reach, &mut next);
        std::mem::swap(&mut reach, &mut next);
        if !reach.contains(&true) {
            return false;
        }
    }
    reach[text.len()]
}

fn step(token: &Token, text: &str, reach: &[bool], next: &mut [bool]) {
    match token {
        Token::Star => {
            let Some(first) = reach.iter().position(|&r| r) else {
                return;
            };
            for i in (first..=text.len()).filter(|&i| text.is_char_boundary(i)) {
                next[i] = true;
            }
        }
        Token::Dirs => {
            let mut open = false;
            for (i, &r) in reach.iter().enumerate() {
                next[i] |= r || (open && text.as_bytes()[i - 1] == b'/');
                open |= r;
            }
        }
        _ => {
            for (i, c) in text.char_indices().filter(|&(i, _)| reach[i]) {
                if accepts(token, c) {
                    next[i + c.len_utf8()] = true;
                }
            }
        }
    }
}

fn accepts(token: &Token, c: char) -> bool {
    match token {
        Token::Lit(l) => *l == c,
        Token::One => true,
        Token::Class { negate, items } => {
            items.iter().any(|&(lo, hi)| (lo..=hi).contains(&c)) != *negate
        }
        Token::Star | Token::Dirs => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is(pattern: &str, text: &str) -> bool {
        Glob::new(pattern).expect("разбирается").is_match(text)
    }

    #[test]
    fn star_crosses_separators() {
        assert!(is("c:/games/*.exe", "c:/games/a/b.exe"));
        assert!(is("*", ""));
        assert!(!is("c:/games/*.exe", "c:/games/a.txt"));
    }

    #[test]
    fn double_star_dir_matches_zero_or_more() {
        assert!(is("c:/g/**/*.exe", "c:/g/a.exe"));
        assert!(is("c:/g/**/*.exe", "c:/g/a/b/c.exe"));
        assert!(!is("c:/g/**/*.exe", "c:/h/a.exe"));
        assert!(is("/opt/**", "/opt/a/b"));
    }

    #[test]
    fn many_stars_do_not_backtrack_exponentially() {
        let text = format!("c:/{}c.exe", "a".repeat(400));
        assert!(!is("c:/**/*a*a*a*a*a*a*a*a*b.exe", &text));
        assert!(is("c:/**/*a*a*a*a*a*a*a*a*c.exe", &text));
    }

    #[test]
    fn question_matches_one_char() {
        assert!(is("a?c", "abc"));
        assert!(!is("a?c", "ac"));
        assert!(is("?", "ы"));
    }

    #[test]
    fn classes() {
        assert!(is("v[0-9].exe", "v7.exe"));
        assert!(!is("v[0-9].exe", "va.exe"));
        assert!(is("v[!0-9]", "va"));
        assert!(!is("v[!0-9]", "v1"));
        assert!(is("[]a]", "]"));
        assert!(is("[a-]", "-"));
    }

    #[test]
    fn unclosed_class_is_an_error() {
        assert!(Glob::new("a[bc").is_err());
        assert!(Glob::new("a[").is_err());
    }
}
