//! Deterministic, hostile-input-safe encoding of a [`Proposal`] — the bytes sealed as a
//! `KIND_PROPOSAL` bundle. A length-prefixed TLV with a leading layout-version byte, mirroring the
//! `commute` codec's discipline (fixed-width big-endian counts, explicit lengths checked against the
//! remaining buffer, a typed error on any malformed input — never a panic).

use crate::{Pedigree, Proposal, TreeOp};
use commute::ReplicaId;

const LAYOUT: u8 = 1;

/// Why decoding a proposal failed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProposalError {
    Truncated,
    LengthOverrun,
    BadTag,
    BadLayout,
    BadUtf8,
    TrailingBytes,
}

// ---- writer ----

fn put_u64(o: &mut Vec<u8>, v: u64) {
    o.extend_from_slice(&v.to_be_bytes());
}
fn put_bytes(o: &mut Vec<u8>, b: &[u8]) {
    o.extend_from_slice(&(b.len() as u32).to_be_bytes());
    o.extend_from_slice(b);
}
fn put_opt(o: &mut Vec<u8>, s: &Option<String>) {
    match s {
        Some(x) => {
            o.push(1);
            put_bytes(o, x.as_bytes());
        }
        None => o.push(0),
    }
}

fn put_opt_bytes(o: &mut Vec<u8>, b: &Option<Vec<u8>>) {
    match b {
        Some(x) => {
            o.push(1);
            put_bytes(o, x);
        }
        None => o.push(0),
    }
}

fn put_op(o: &mut Vec<u8>, op: &TreeOp) {
    match op {
        TreeOp::AddPerson { id } => {
            o.push(0);
            put_bytes(o, id);
        }
        TreeOp::RemovePerson { id } => {
            o.push(1);
            put_bytes(o, id);
        }
        TreeOp::AddClaim { subject, field, claim, value, source } => {
            o.push(2);
            put_bytes(o, subject);
            put_bytes(o, field.as_bytes());
            put_bytes(o, claim);
            put_bytes(o, value.as_bytes());
            put_opt(o, source);
        }
        TreeOp::SetPreferredClaim { subject, field, claim } => {
            o.push(3);
            put_bytes(o, subject);
            put_bytes(o, field.as_bytes());
            put_bytes(o, claim);
        }
        TreeOp::RetractClaim { subject, field, claim } => {
            o.push(4);
            put_bytes(o, subject);
            put_bytes(o, field.as_bytes());
            put_bytes(o, claim);
        }
        TreeOp::AddFamily { id } => {
            o.push(5);
            put_bytes(o, id);
        }
        TreeOp::RemoveFamily { id } => {
            o.push(6);
            put_bytes(o, id);
        }
        TreeOp::LinkChild { family, person, pedi } => {
            o.push(7);
            put_bytes(o, family);
            put_bytes(o, person);
            o.push(pedi.tag() as u8);
        }
        TreeOp::UnlinkChild { family, person } => {
            o.push(8);
            put_bytes(o, family);
            put_bytes(o, person);
        }
        TreeOp::MoveChild { person, from, to, pedi } => {
            o.push(9);
            put_bytes(o, person);
            put_bytes(o, from);
            put_bytes(o, to);
            o.push(pedi.tag() as u8);
        }
        TreeOp::LinkSpouse { family, person } => {
            o.push(10);
            put_bytes(o, family);
            put_bytes(o, person);
        }
        TreeOp::UnlinkSpouse { family, person } => {
            o.push(11);
            put_bytes(o, family);
            put_bytes(o, person);
        }
        // Tags 12/13 (the retired AttachMedia/DetachMedia) are permanently reserved — never re-used.
        TreeOp::AddName { subject, name } => {
            o.push(14);
            put_bytes(o, subject);
            put_bytes(o, name);
        }
        TreeOp::RemoveName { subject, name } => {
            o.push(15);
            put_bytes(o, subject);
            put_bytes(o, name);
        }
        TreeOp::SetPrimaryName { subject, name } => {
            o.push(16);
            put_bytes(o, subject);
            put_bytes(o, name);
        }
        TreeOp::AddEvent { subject, event } => {
            o.push(17);
            put_bytes(o, subject);
            put_bytes(o, event);
        }
        TreeOp::RemoveEvent { subject, event } => {
            o.push(18);
            put_bytes(o, subject);
            put_bytes(o, event);
        }
        TreeOp::AddSource { source } => {
            o.push(19);
            put_bytes(o, source);
        }
        TreeOp::RemoveSource { source } => {
            o.push(20);
            put_bytes(o, source);
        }
        TreeOp::Cite { subject, field, source, claim } => {
            o.push(21);
            put_bytes(o, subject);
            put_bytes(o, field.as_bytes());
            put_bytes(o, source);
            put_opt_bytes(o, claim);
        }
        TreeOp::Uncite { subject, field, source } => {
            o.push(22);
            put_bytes(o, subject);
            put_bytes(o, field.as_bytes());
            put_bytes(o, source);
        }
        TreeOp::AddMediaRecord { media } => {
            o.push(23);
            put_bytes(o, media);
        }
        TreeOp::RemoveMediaRecord { media } => {
            o.push(24);
            put_bytes(o, media);
        }
        TreeOp::AddMediaLink { subject, link, media } => {
            o.push(25);
            put_bytes(o, subject);
            put_bytes(o, link);
            put_bytes(o, media);
        }
        TreeOp::RemoveMediaLink { subject, link } => {
            o.push(26);
            put_bytes(o, subject);
            put_bytes(o, link);
        }
    }
}

/// Encode a proposal: `base` version vector, then the op bundle. Canonical (the base is walked in
/// its `BTreeMap` order).
pub fn encode(p: &Proposal) -> Vec<u8> {
    let mut o = vec![LAYOUT];
    put_u64(&mut o, p.base.len() as u64);
    for (replica, lamport) in &p.base {
        o.extend_from_slice(replica);
        put_u64(&mut o, *lamport);
    }
    put_u64(&mut o, p.ops.len() as u64);
    for op in &p.ops {
        put_op(&mut o, op);
    }
    o
}

// ---- reader (bounds-checked) ----

struct R<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> R<'a> {
    fn remaining(&self) -> usize {
        self.b.len() - self.pos
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], ProposalError> {
        if n > self.remaining() {
            return Err(ProposalError::Truncated);
        }
        let s = &self.b[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, ProposalError> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32, ProposalError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().expect("4")))
    }
    fn u64(&mut self) -> Result<u64, ProposalError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().expect("8")))
    }
    fn bytes(&mut self) -> Result<Vec<u8>, ProposalError> {
        // u32 length fits usize on every target, so this check can't truncate.
        let n = self.u32()? as usize;
        Ok(self.take(n)?.to_vec())
    }
    fn string(&mut self) -> Result<String, ProposalError> {
        String::from_utf8(self.bytes()?).map_err(|_| ProposalError::BadUtf8)
    }
    fn opt_string(&mut self) -> Result<Option<String>, ProposalError> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.string()?)),
            _ => Err(ProposalError::BadTag),
        }
    }
    fn opt_bytes(&mut self) -> Result<Option<Vec<u8>>, ProposalError> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.bytes()?)),
            _ => Err(ProposalError::BadTag),
        }
    }
    fn replica(&mut self) -> Result<ReplicaId, ProposalError> {
        Ok(self.take(16)?.try_into().expect("16"))
    }
    fn pedi(&mut self) -> Result<Pedigree, ProposalError> {
        Ok(Pedigree::from_tag(self.u8()? as i64))
    }
    fn op(&mut self) -> Result<TreeOp, ProposalError> {
        Ok(match self.u8()? {
            0 => TreeOp::AddPerson { id: self.bytes()? },
            1 => TreeOp::RemovePerson { id: self.bytes()? },
            2 => TreeOp::AddClaim { subject: self.bytes()?, field: self.string()?, claim: self.bytes()?, value: self.string()?, source: self.opt_string()? },
            3 => TreeOp::SetPreferredClaim { subject: self.bytes()?, field: self.string()?, claim: self.bytes()? },
            4 => TreeOp::RetractClaim { subject: self.bytes()?, field: self.string()?, claim: self.bytes()? },
            5 => TreeOp::AddFamily { id: self.bytes()? },
            6 => TreeOp::RemoveFamily { id: self.bytes()? },
            7 => TreeOp::LinkChild { family: self.bytes()?, person: self.bytes()?, pedi: self.pedi()? },
            8 => TreeOp::UnlinkChild { family: self.bytes()?, person: self.bytes()? },
            9 => TreeOp::MoveChild { person: self.bytes()?, from: self.bytes()?, to: self.bytes()?, pedi: self.pedi()? },
            10 => TreeOp::LinkSpouse { family: self.bytes()?, person: self.bytes()? },
            11 => TreeOp::UnlinkSpouse { family: self.bytes()?, person: self.bytes()? },
            // 12/13 = retired AttachMedia/DetachMedia — reserved, decode as BadTag.
            14 => TreeOp::AddName { subject: self.bytes()?, name: self.bytes()? },
            15 => TreeOp::RemoveName { subject: self.bytes()?, name: self.bytes()? },
            16 => TreeOp::SetPrimaryName { subject: self.bytes()?, name: self.bytes()? },
            17 => TreeOp::AddEvent { subject: self.bytes()?, event: self.bytes()? },
            18 => TreeOp::RemoveEvent { subject: self.bytes()?, event: self.bytes()? },
            19 => TreeOp::AddSource { source: self.bytes()? },
            20 => TreeOp::RemoveSource { source: self.bytes()? },
            21 => TreeOp::Cite { subject: self.bytes()?, field: self.string()?, source: self.bytes()?, claim: self.opt_bytes()? },
            22 => TreeOp::Uncite { subject: self.bytes()?, field: self.string()?, source: self.bytes()? },
            23 => TreeOp::AddMediaRecord { media: self.bytes()? },
            24 => TreeOp::RemoveMediaRecord { media: self.bytes()? },
            25 => TreeOp::AddMediaLink { subject: self.bytes()?, link: self.bytes()?, media: self.bytes()? },
            26 => TreeOp::RemoveMediaLink { subject: self.bytes()?, link: self.bytes()? },
            _ => return Err(ProposalError::BadTag),
        })
    }
}

/// Decode a proposal. Never panics on arbitrary bytes.
pub fn decode(bytes: &[u8]) -> Result<Proposal, ProposalError> {
    let mut r = R { b: bytes, pos: 0 };
    if r.u8()? != LAYOUT {
        return Err(ProposalError::BadLayout);
    }
    let base_len = r.u64()?;
    // Each base entry is 24 bytes; a count beyond the buffer can't be honest.
    if base_len > r.remaining() as u64 {
        return Err(ProposalError::LengthOverrun);
    }
    let mut base = commute::VersionVector::new();
    for _ in 0..base_len {
        let replica = r.replica()?;
        base.insert(replica, r.u64()?);
    }
    let ops_len = r.u64()?;
    if ops_len > r.remaining() as u64 {
        return Err(ProposalError::LengthOverrun);
    }
    let mut ops = Vec::with_capacity(ops_len as usize);
    for _ in 0..ops_len {
        ops.push(r.op()?);
    }
    if r.remaining() != 0 {
        return Err(ProposalError::TrailingBytes);
    }
    Ok(Proposal { base, ops })
}
