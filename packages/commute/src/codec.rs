//! Deterministic binary encoding for a run of [`Op`]s — the unit both a **snapshot** (all ops) and
//! a **delta** (ops after a version) serialize to. "Deterministic" is load-bearing: the same logical
//! op run always yields the same bytes, so two converged replicas produce byte-identical snapshots
//! (the convergence oracle) and these bytes are a stable sealed-archive substrate.
//!
//! The format is a bespoke length-prefixed TLV (no floats, fixed-width big-endian integers, explicit
//! lengths) rather than a serde/CBOR dependency — it keeps `commute` zero-dependency and gives full
//! control over canonical form. A leading `LAYOUT_VERSION` byte lets the format evolve; the encoding
//! lives behind these functions, so switching to canonical CBOR later is a localized change.
//!
//! The decoder is **hostile-input-safe**: it never panics, never over-allocates on a forged length
//! prefix (every length is checked against the remaining buffer, in `u64` space so a 32-bit `usize`
//! target — wasm — can't truncate the check), and rejects malformed input with a typed error.

use crate::{Op, OpIntent, ReplicaId, Stamp, Value};

/// The encoding version — bumped only on a real format change, with a migration.
pub const LAYOUT_VERSION: u8 = 1;

/// Why decoding failed. Never a panic — arbitrary bytes always fail cleanly.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DecodeError {
    /// The buffer ended mid-value.
    Truncated,
    /// A length prefix exceeds the remaining input (forged/corrupt).
    LengthOverrun,
    /// An unknown discriminant tag (value kind, op kind).
    BadTag,
    /// The layout version isn't one this build understands.
    BadLayout,
    /// A `Text` field wasn't valid UTF-8.
    BadUtf8,
    /// Trailing bytes after a complete decode.
    TrailingBytes,
}

// ---- writer (infallible; determinism is in the fixed widths + explicit lengths) ----

fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn put_len(out: &mut Vec<u8>, b: &[u8]) {
    put_u64(out, b.len() as u64);
    out.extend_from_slice(b);
}

fn put_stamp(out: &mut Vec<u8>, s: &Stamp) {
    put_u64(out, s.lamport);
    out.extend_from_slice(&s.replica);
}

fn put_value(out: &mut Vec<u8>, v: &Value) {
    match v {
        Value::Null => out.push(0),
        Value::Bool(b) => {
            out.push(1);
            out.push(*b as u8);
        }
        Value::I64(n) => {
            out.push(2);
            out.extend_from_slice(&n.to_be_bytes());
        }
        Value::U64(n) => {
            out.push(3);
            put_u64(out, *n);
        }
        Value::Bytes(b) => {
            out.push(4);
            put_len(out, b);
        }
        Value::Text(s) => {
            out.push(5);
            put_len(out, s.as_bytes());
        }
    }
}

fn put_intent(out: &mut Vec<u8>, i: &OpIntent) {
    match i {
        OpIntent::SetRegister { cell, value } => {
            out.push(0);
            put_len(out, cell);
            put_value(out, value);
        }
        OpIntent::AddElement { cell, elem, value } => {
            out.push(1);
            put_len(out, cell);
            put_len(out, elem);
            put_value(out, value);
        }
        OpIntent::RemoveElement { cell, elem } => {
            out.push(2);
            put_len(out, cell);
            put_len(out, elem);
        }
    }
}

/// Encode a run of ops. The caller supplies them in a canonical order (see `Doc::ops_since`), so the
/// bytes are canonical.
pub fn encode_ops(ops: &[Op]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 8 + ops.len() * 24);
    out.push(LAYOUT_VERSION);
    put_u64(&mut out, ops.len() as u64);
    for op in ops {
        put_stamp(&mut out, &op.stamp);
        put_intent(&mut out, &op.intent);
    }
    out
}

// ---- reader (fallible, bounds-checked) ----

struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn remaining(&self) -> usize {
        self.b.len() - self.pos
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if n > self.remaining() {
            return Err(DecodeError::Truncated);
        }
        let s = &self.b[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }

    fn u64(&mut self) -> Result<u64, DecodeError> {
        let s = self.take(8)?;
        Ok(u64::from_be_bytes(s.try_into().expect("took 8")))
    }

    fn i64(&mut self) -> Result<i64, DecodeError> {
        let s = self.take(8)?;
        Ok(i64::from_be_bytes(s.try_into().expect("took 8")))
    }

    /// A length-prefixed byte run. The length is validated against the remaining input in `u64`
    /// space FIRST, so a huge forged prefix errors instead of allocating (and can't truncate on a
    /// 32-bit `usize` target).
    fn len_bytes(&mut self) -> Result<Vec<u8>, DecodeError> {
        let n = self.u64()?;
        if n > self.remaining() as u64 {
            return Err(DecodeError::LengthOverrun);
        }
        Ok(self.take(n as usize)?.to_vec())
    }

    fn replica(&mut self) -> Result<ReplicaId, DecodeError> {
        let s = self.take(16)?;
        Ok(s.try_into().expect("took 16"))
    }

    fn stamp(&mut self) -> Result<Stamp, DecodeError> {
        Ok(Stamp {
            lamport: self.u64()?,
            replica: self.replica()?,
        })
    }

    fn value(&mut self) -> Result<Value, DecodeError> {
        Ok(match self.u8()? {
            0 => Value::Null,
            1 => Value::Bool(self.u8()? != 0),
            2 => Value::I64(self.i64()?),
            3 => Value::U64(self.u64()?),
            4 => Value::Bytes(self.len_bytes()?),
            5 => {
                Value::Text(String::from_utf8(self.len_bytes()?).map_err(|_| DecodeError::BadUtf8)?)
            }
            _ => return Err(DecodeError::BadTag),
        })
    }

    fn intent(&mut self) -> Result<OpIntent, DecodeError> {
        Ok(match self.u8()? {
            0 => OpIntent::SetRegister {
                cell: self.len_bytes()?,
                value: self.value()?,
            },
            1 => OpIntent::AddElement {
                cell: self.len_bytes()?,
                elem: self.len_bytes()?,
                value: self.value()?,
            },
            2 => OpIntent::RemoveElement {
                cell: self.len_bytes()?,
                elem: self.len_bytes()?,
            },
            _ => return Err(DecodeError::BadTag),
        })
    }
}

/// Decode a run of ops. Never panics on arbitrary input.
pub fn decode_ops(bytes: &[u8]) -> Result<Vec<Op>, DecodeError> {
    let mut r = Reader { b: bytes, pos: 0 };
    if r.u8()? != LAYOUT_VERSION {
        return Err(DecodeError::BadLayout);
    }
    let count = r.u64()?;
    // Guard against a forged count: each op is at least 25 bytes (stamp 24 + 1 tag), so a count
    // beyond that can't be honest — reject before reserving.
    if count > r.remaining() as u64 {
        return Err(DecodeError::LengthOverrun);
    }
    let mut ops = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let stamp = r.stamp()?;
        let intent = r.intent()?;
        ops.push(Op { stamp, intent });
    }
    if r.remaining() != 0 {
        return Err(DecodeError::TrailingBytes);
    }
    Ok(ops)
}
