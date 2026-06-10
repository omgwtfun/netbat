//! Tokenizer and recursive-descent parser for JunOS hierarchical config format.
//!
//! A [`Statement`] has a `keyword` (the first token), `args` (tokens that
//! follow before `{` or `;`), and `children` (`None` for leaf statements
//! ending in `;`, `Some(..)` for `{ ... }` blocks).
//!
//! Bracket notation `application [ junos-http junos-https ];` is flattened so
//! the bracketed items are appended to `args` and `children` stays `None`.

/// A parsed JunOS statement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Statement {
    pub keyword: String,
    pub args: Vec<String>,
    pub children: Option<Vec<Statement>>,
}

const STRUCTURAL: [char; 5] = ['{', '}', '[', ']', ';'];

fn is_structural(s: &str) -> bool {
    s.len() == 1 && STRUCTURAL.contains(&s.chars().next().unwrap())
}

/// Convert JunOS config text to a flat list of tokens.
pub fn tokenize(text: &str) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();
    let mut tokens: Vec<String> = Vec::new();
    let mut i = 0;

    while i < n {
        let c = chars[i];

        if c.is_whitespace() {
            i += 1;
            continue;
        }

        // Single-line comment
        if c == '#' {
            while i < n && chars[i] != '\n' {
                i += 1;
            }
            continue;
        }

        // Block comment
        if c == '/' && i + 1 < n && chars[i + 1] == '*' {
            i += 2;
            while i + 1 < n && !(chars[i] == '*' && chars[i + 1] == '/') {
                i += 1;
            }
            i = if i + 1 < n { i + 2 } else { n };
            continue;
        }

        // Structural single-char tokens
        if STRUCTURAL.contains(&c) {
            tokens.push(c.to_string());
            i += 1;
            continue;
        }

        // Double-quoted string — content without the surrounding quotes
        if c == '"' {
            i += 1;
            let mut s = String::new();
            while i < n && chars[i] != '"' {
                if chars[i] == '\\' && i + 1 < n {
                    i += 1;
                }
                s.push(chars[i]);
                i += 1;
            }
            tokens.push(s);
            i += 1; // skip closing "
            continue;
        }

        // Bare word (identifier, IP, etc.)
        let start = i;
        while i < n && !chars[i].is_whitespace() && !STRUCTURAL.contains(&chars[i]) {
            i += 1;
        }
        if i > start {
            tokens.push(chars[start..i].iter().collect());
        }
    }

    tokens
}

struct Parser<'a> {
    tokens: &'a [String],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn parse_block(&mut self) -> Vec<Statement> {
        let mut stmts = Vec::new();
        while self.pos < self.tokens.len() && self.tokens[self.pos] != "}" {
            if let Some(stmt) = self.parse_statement() {
                stmts.push(stmt);
            } else {
                break;
            }
        }
        stmts
    }

    fn parse_statement(&mut self) -> Option<Statement> {
        if self.pos >= self.tokens.len() {
            return None;
        }

        let keyword = self.tokens[self.pos].clone();
        self.pos += 1;

        let mut args: Vec<String> = Vec::new();
        while self.pos < self.tokens.len() && !is_structural(&self.tokens[self.pos]) {
            args.push(self.tokens[self.pos].clone());
            self.pos += 1;
        }

        if self.pos >= self.tokens.len() {
            return Some(Statement {
                keyword,
                args,
                children: None,
            });
        }

        match self.tokens[self.pos].as_str() {
            ";" => {
                self.pos += 1;
                Some(Statement {
                    keyword,
                    args,
                    children: None,
                })
            }
            // Bracket notation: key [ v1 v2 v3 ];
            "[" => {
                self.pos += 1;
                while self.pos < self.tokens.len() && self.tokens[self.pos] != "]" {
                    args.push(self.tokens[self.pos].clone());
                    self.pos += 1;
                }
                if self.pos < self.tokens.len() {
                    self.pos += 1; // skip ]
                }
                if self.pos < self.tokens.len() && self.tokens[self.pos] == ";" {
                    self.pos += 1;
                }
                Some(Statement {
                    keyword,
                    args,
                    children: None,
                })
            }
            // Block: key args* { ... }
            "{" => {
                self.pos += 1;
                let children = self.parse_block();
                if self.pos < self.tokens.len() && self.tokens[self.pos] == "}" {
                    self.pos += 1;
                }
                Some(Statement {
                    keyword,
                    args,
                    children: Some(children),
                })
            }
            _ => Some(Statement {
                keyword,
                args,
                children: None,
            }),
        }
    }
}

/// Parse a flat token list into a list of [`Statement`]s.
pub fn parse(tokens: &[String]) -> Vec<Statement> {
    let mut parser = Parser { tokens, pos: 0 };
    parser.parse_block()
}

/// Parse JunOS hierarchical config text and return a [`Statement`] list.
pub fn parse_config(text: &str) -> Vec<Statement> {
    parse(&tokenize(text))
}
