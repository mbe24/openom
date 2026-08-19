//! A hand-rolled JSON [`Codec`] — no serde, on purpose: it **rejects duplicate object keys** (which
//! `serde_json` silently last-writer-wins) and **rejects floats** (no canonical archive form), and
//! it never panics on arbitrary input (bounds-checked, depth-limited).

use crate::{Codec, CodecError, ValueTree};
use std::collections::HashSet;

/// The JSON codec. `max_depth` bounds nesting so hostile input can't overflow the stack.
pub struct JsonCodec {
    pub max_depth: usize,
}

impl Default for JsonCodec {
    fn default() -> Self {
        JsonCodec { max_depth: 128 }
    }
}

impl Codec for JsonCodec {
    fn parse(&self, bytes: &[u8]) -> Result<ValueTree, CodecError> {
        let mut p = Parser {
            b: bytes,
            pos: 0,
            max_depth: self.max_depth,
        };
        p.ws();
        let v = p.value(0)?;
        p.ws();
        if p.pos != p.b.len() {
            return Err(CodecError::Malformed {
                pos: p.pos,
                what: "trailing bytes after value",
            });
        }
        Ok(v)
    }

    fn emit(&self, value: &ValueTree) -> Result<Vec<u8>, CodecError> {
        let mut out = Vec::new();
        emit_value(value, &mut out)?;
        Ok(out)
    }
}

struct Parser<'a> {
    b: &'a [u8],
    pos: usize,
    max_depth: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.pos).copied()
    }

    fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn lit(&mut self, s: &[u8], val: ValueTree) -> Result<ValueTree, CodecError> {
        if self.b[self.pos..].starts_with(s) {
            self.pos += s.len();
            Ok(val)
        } else {
            Err(CodecError::Malformed {
                pos: self.pos,
                what: "invalid literal",
            })
        }
    }

    fn value(&mut self, depth: usize) -> Result<ValueTree, CodecError> {
        if depth > self.max_depth {
            return Err(CodecError::TooDeep);
        }
        match self.peek() {
            None => Err(CodecError::Malformed {
                pos: self.pos,
                what: "unexpected end of input",
            }),
            Some(b'n') => self.lit(b"null", ValueTree::Null),
            Some(b't') => self.lit(b"true", ValueTree::Bool(true)),
            Some(b'f') => self.lit(b"false", ValueTree::Bool(false)),
            Some(b'"') => Ok(ValueTree::Str(self.string()?)),
            Some(b'[') => self.array(depth),
            Some(b'{') => self.object(depth),
            Some(c) if c == b'-' || c.is_ascii_digit() => self.number(),
            Some(_) => Err(CodecError::Malformed {
                pos: self.pos,
                what: "unexpected byte",
            }),
        }
    }

    fn number(&mut self) -> Result<ValueTree, CodecError> {
        let start = self.pos;
        let mut is_float = false;
        while let Some(c) = self.peek() {
            match c {
                b'0'..=b'9' | b'-' | b'+' => self.pos += 1,
                b'.' | b'e' | b'E' => {
                    is_float = true;
                    self.pos += 1;
                }
                _ => break,
            }
        }
        let tok = &self.b[start..self.pos];
        if is_float {
            return Err(CodecError::FloatNotRepresentable);
        }
        let s = std::str::from_utf8(tok).map_err(|_| CodecError::Malformed {
            pos: start,
            what: "number",
        })?;
        if let Some(stripped) = s.strip_prefix('-') {
            // Negative: i64. (`-` alone or `-<huge>` → out of range.)
            let _ = stripped;
            s.parse::<i64>()
                .map(ValueTree::Int)
                .map_err(|_| CodecError::NumberOutOfRange)
        } else {
            s.parse::<u64>()
                .map(ValueTree::Uint)
                .map_err(|_| CodecError::NumberOutOfRange)
        }
    }

    fn string(&mut self) -> Result<String, CodecError> {
        debug_assert_eq!(self.peek(), Some(b'"'));
        self.pos += 1;
        let mut out: Vec<u8> = Vec::new();
        loop {
            let c = self.peek().ok_or(CodecError::Malformed {
                pos: self.pos,
                what: "unterminated string",
            })?;
            self.pos += 1;
            match c {
                b'"' => break,
                b'\\' => {
                    let e = self.peek().ok_or(CodecError::Malformed {
                        pos: self.pos,
                        what: "bad escape",
                    })?;
                    self.pos += 1;
                    match e {
                        b'"' => out.push(b'"'),
                        b'\\' => out.push(b'\\'),
                        b'/' => out.push(b'/'),
                        b'b' => out.push(0x08),
                        b'f' => out.push(0x0c),
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'u' => {
                            let ch = self.unicode_escape()?;
                            let mut buf = [0u8; 4];
                            out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                        }
                        _ => {
                            return Err(CodecError::Malformed {
                                pos: self.pos,
                                what: "bad escape",
                            })
                        }
                    }
                }
                0x00..=0x1f => {
                    return Err(CodecError::Malformed {
                        pos: self.pos,
                        what: "control char in string",
                    })
                }
                _ => out.push(c),
            }
        }
        String::from_utf8(out).map_err(|_| CodecError::Malformed {
            pos: self.pos,
            what: "invalid utf-8 in string",
        })
    }

    fn hex4(&mut self) -> Result<u16, CodecError> {
        let s = self
            .b
            .get(self.pos..self.pos + 4)
            .ok_or(CodecError::Malformed {
                pos: self.pos,
                what: "short \\u escape",
            })?;
        let s = std::str::from_utf8(s).map_err(|_| CodecError::Malformed {
            pos: self.pos,
            what: "\\u escape",
        })?;
        let v = u16::from_str_radix(s, 16).map_err(|_| CodecError::Malformed {
            pos: self.pos,
            what: "\\u hex",
        })?;
        self.pos += 4;
        Ok(v)
    }

    fn unicode_escape(&mut self) -> Result<char, CodecError> {
        let hi = self.hex4()?;
        if (0xD800..=0xDBFF).contains(&hi) {
            // High surrogate — must be followed by \uLOW.
            if self.b.get(self.pos) != Some(&b'\\') || self.b.get(self.pos + 1) != Some(&b'u') {
                return Err(CodecError::Malformed {
                    pos: self.pos,
                    what: "lone high surrogate",
                });
            }
            self.pos += 2;
            let lo = self.hex4()?;
            if !(0xDC00..=0xDFFF).contains(&lo) {
                return Err(CodecError::Malformed {
                    pos: self.pos,
                    what: "bad low surrogate",
                });
            }
            let c = 0x10000 + ((hi as u32 - 0xD800) << 10) + (lo as u32 - 0xDC00);
            char::from_u32(c).ok_or(CodecError::Malformed {
                pos: self.pos,
                what: "bad surrogate pair",
            })
        } else if (0xDC00..=0xDFFF).contains(&hi) {
            Err(CodecError::Malformed {
                pos: self.pos,
                what: "lone low surrogate",
            })
        } else {
            char::from_u32(hi as u32).ok_or(CodecError::Malformed {
                pos: self.pos,
                what: "bad \\u",
            })
        }
    }

    fn array(&mut self, depth: usize) -> Result<ValueTree, CodecError> {
        self.pos += 1; // [
        let mut items = Vec::new();
        self.ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(ValueTree::Seq(items));
        }
        loop {
            self.ws();
            items.push(self.value(depth + 1)?);
            self.ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(ValueTree::Seq(items));
                }
                _ => {
                    return Err(CodecError::Malformed {
                        pos: self.pos,
                        what: "expected ',' or ']'",
                    })
                }
            }
        }
    }

    fn object(&mut self, depth: usize) -> Result<ValueTree, CodecError> {
        self.pos += 1; // {
        let mut entries: Vec<(String, ValueTree)> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        self.ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(ValueTree::Map(entries));
        }
        loop {
            self.ws();
            if self.peek() != Some(b'"') {
                return Err(CodecError::Malformed {
                    pos: self.pos,
                    what: "expected object key",
                });
            }
            let key = self.string()?;
            if !seen.insert(key.clone()) {
                return Err(CodecError::DuplicateKey(key));
            }
            self.ws();
            if self.peek() != Some(b':') {
                return Err(CodecError::Malformed {
                    pos: self.pos,
                    what: "expected ':'",
                });
            }
            self.pos += 1;
            self.ws();
            let val = self.value(depth + 1)?;
            entries.push((key, val));
            self.ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(ValueTree::Map(entries));
                }
                _ => {
                    return Err(CodecError::Malformed {
                        pos: self.pos,
                        what: "expected ',' or '}'",
                    })
                }
            }
        }
    }
}

// ---- emit ----

fn emit_string(s: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for c in s.chars() {
        match c {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            '\u{08}' => out.extend_from_slice(b"\\b"),
            '\u{0c}' => out.extend_from_slice(b"\\f"),
            c if (c as u32) < 0x20 => {
                out.extend_from_slice(format!("\\u{:04x}", c as u32).as_bytes())
            }
            c => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out.push(b'"');
}

fn emit_value(v: &ValueTree, out: &mut Vec<u8>) -> Result<(), CodecError> {
    match v {
        ValueTree::Null => out.extend_from_slice(b"null"),
        ValueTree::Bool(true) => out.extend_from_slice(b"true"),
        ValueTree::Bool(false) => out.extend_from_slice(b"false"),
        ValueTree::Int(n) => out.extend_from_slice(n.to_string().as_bytes()),
        ValueTree::Uint(n) => out.extend_from_slice(n.to_string().as_bytes()),
        ValueTree::Str(s) => emit_string(s, out),
        ValueTree::Bytes(_) => {
            return Err(CodecError::Unrepresentable("raw bytes have no JSON form"))
        }
        ValueTree::Seq(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                emit_value(item, out)?;
            }
            out.push(b']');
        }
        ValueTree::Map(entries) => {
            out.push(b'{');
            for (i, (k, val)) in entries.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                emit_string(k, out);
                out.push(b':');
                emit_value(val, out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}
