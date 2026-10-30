use std::{mem, ops};

use o3::alloc;

use crate::conn::wire::{crypto::fragment, ingress::frames::sources};
use crate::{conn, wire::frame};

mod prepared;
mod scratch;

pub(in crate::conn) use prepared::Prepared;
use scratch::Kind;
pub(in crate::conn) use scratch::{Access, Scratch, Step};

struct Input<'a> {
    offset: u64,
    bytes: &'a [u8],
    source: usize,
}

struct State {
    /// Native TLS owns message fragments; this cursor only orders CRYPTO bytes.
    next: u64,
    parts: Option<fragment::Fragment>,
}

pub(in crate::conn) struct Spaces([State; 3]);

pub(in crate::conn::wire) struct Cursor<'a> {
    next: &'a mut u64,
    parts: Option<&'a mut fragment::Fragment>,
}

pub(in crate::conn) enum Failure {
    Connection(conn::Error),
    Allocation(alloc::Exhausted),
}

pub(in crate::conn::wire) fn accept(
    chunk: sources::Crypto<'_, '_, '_>,
    consume: impl for<'message> FnMut(&'message [u8]) -> Result<(), conn::Error>,
) -> Result<(), conn::Error> {
    let (mut cursor, step, body) = chunk.into_parts();
    cursor.accept(step.step.kind, body.as_ref(), consume)
}

impl<'a> Input<'a> {
    fn new(
        next: u64,
        offset: u64,
        source: ops::Range<usize>,
        body: &'a [u8],
    ) -> Result<Option<Self>, conn::Error> {
        let Some(data) = body.get(source.clone()) else {
            return Err(conn::Error::CryptoBufferExceeded);
        };
        let end = State::end(offset, data.len())?;
        if data.is_empty() || end <= next {
            return Ok(None);
        }
        let skip = next.saturating_sub(offset) as usize;
        let Some(bytes) = data.get(skip..) else {
            return Err(conn::Error::CryptoBufferExceeded);
        };
        Ok(Some(Self {
            offset: offset.max(next),
            bytes,
            source: source
                .start
                .checked_add(skip)
                .ok_or(conn::Error::CryptoBufferExceeded)?,
        }))
    }
}

impl State {
    const fn new() -> Self {
        Self {
            next: 0,
            parts: None,
        }
    }

    fn prepare<'state, 'rows, 'id: 'rows>(
        &'state mut self,
        frames: impl IntoIterator<Item = (u64, ops::Range<usize>, &'rows mut Step<'id>)>,
        body: &[u8],
        scratch: &mut Scratch,
    ) -> Result<Cursor<'state>, Failure> {
        scratch.clear();
        let mut frames = frames.into_iter();
        let mut next = self.next;
        if let Some(parts) = self.parts.as_ref() {
            let mut shadow = parts
                .shadow(&mut scratch.spans)
                .ok_or(Failure::Connection(conn::Error::CryptoBufferExceeded))?;
            for (offset, source, step) in frames {
                Self::plan_one(&mut next, &mut shadow, offset, source, body, step)
                    .map_err(Failure::Connection)?;
            }
        } else {
            while let Some((offset, source, step)) = frames.next() {
                let input =
                    Input::new(next, offset, source.clone(), body).map_err(Failure::Connection)?;
                let Some(input) = input else {
                    step.kind = Kind::Ignore;
                    continue;
                };
                if input.offset == next {
                    let len = input.bytes.len();
                    step.kind = Kind::Direct {
                        start: input.source,
                        len: len as u32,
                    };
                    next = next
                        .checked_add(len as u64)
                        .ok_or(Failure::Connection(conn::Error::CryptoBufferExceeded))?;
                    continue;
                }

                let parts = fragment::Fragment::try_new(self.next).map_err(Failure::Allocation)?;
                {
                    let mut shadow = fragment::Shadow::new(self.next, &mut scratch.spans);
                    Self::plan_one(&mut next, &mut shadow, offset, source, body, step)
                        .map_err(Failure::Connection)?;
                    for (offset, source, step) in frames {
                        Self::plan_one(&mut next, &mut shadow, offset, source, body, step)
                            .map_err(Failure::Connection)?;
                    }
                }
                self.parts = Some(parts);
                break;
            }
        }
        Ok(Cursor {
            next: &mut self.next,
            parts: self.parts.as_mut(),
        })
    }

    fn plan_one(
        next: &mut u64,
        shadow: &mut fragment::Shadow<'_>,
        offset: u64,
        source: ops::Range<usize>,
        body: &[u8],
        step: &mut Step<'_>,
    ) -> Result<(), conn::Error> {
        let Some(input) = Input::new(*next, offset, source, body)? else {
            step.kind = Kind::Ignore;
            return Ok(());
        };
        let start = input.source;
        if shadow.first().is_none() && input.offset == *next {
            let len = input.bytes.len();
            *next = next
                .checked_add(len as u64)
                .ok_or(conn::Error::CryptoBufferExceeded)?;
            shadow.reset(*next)?;
            step.kind = Kind::Reset {
                start,
                len: len as u32,
            };
            return Ok(());
        }
        let insert = shadow.stage(input.offset, input.bytes.len())?;
        let position = shadow.position(*next)?;
        let drain = shadow.first().filter(|span| span.start() == position);
        if let Some(span) = drain {
            *next = next
                .checked_add((span.end() - span.start()) as u64)
                .ok_or(conn::Error::CryptoBufferExceeded)?;
            shadow.consume(span.end())?;
        }
        let reset = shadow.first().is_none();
        if reset {
            shadow.reset(*next)?;
        }
        step.kind = Kind::Buffered {
            start,
            insert,
            drain,
            reset,
        };
        Ok(())
    }

    fn discard(&mut self) {
        self.next = 0;
        self.parts = None;
    }

    fn end(offset: u64, len: usize) -> Result<u64, conn::Error> {
        if len > fragment::MAX {
            return Err(conn::Error::CryptoBufferExceeded);
        }
        offset
            .checked_add(len as u64)
            .ok_or(conn::Error::CryptoBufferExceeded)
    }
}

impl Cursor<'_> {
    /// A consumer error after native TLS mutation is terminal. Successful bytes
    /// retain this cursor even when a later frame prevents the packet ACK.
    fn accept(
        &mut self,
        step: Kind,
        body: &[u8],
        mut consume: impl for<'message> FnMut(&'message [u8]) -> Result<(), conn::Error>,
    ) -> Result<(), conn::Error> {
        match step {
            Kind::Ignore => return Ok(()),
            Kind::Direct { start, len } => {
                Self::direct(self.next, body, start, len, &mut consume)?;
            }
            Kind::Reset { start, len } => {
                Self::direct(self.next, body, start, len, &mut consume)?;
                let Some(parts) = self.parts.as_mut() else {
                    return Err(conn::Error::CryptoBufferExceeded);
                };
                parts.reset(*self.next);
            }
            Kind::Buffered {
                start,
                insert,
                drain,
                reset,
            } => {
                let Some(parts) = self.parts.as_mut() else {
                    return Err(conn::Error::CryptoBufferExceeded);
                };
                parts.apply(insert, start, body)?;
                if let Some(span) = drain {
                    consume(parts.bytes(span).ok_or(conn::Error::CryptoBufferExceeded)?)?;
                    let consumed = span
                        .end()
                        .checked_sub(span.start())
                        .ok_or(conn::Error::CryptoBufferExceeded)?;
                    *self.next = self
                        .next
                        .checked_add(consumed as u64)
                        .ok_or(conn::Error::CryptoBufferExceeded)?;
                    parts.consume(span)?;
                }
                if reset {
                    parts.reset(*self.next);
                }
            }
        }
        Ok(())
    }

    fn direct(
        next: &mut u64,
        body: &[u8],
        start: usize,
        len: u32,
        consume: &mut impl for<'message> FnMut(&'message [u8]) -> Result<(), conn::Error>,
    ) -> Result<(), conn::Error> {
        if len == 0 {
            return Ok(());
        }
        let Some(end) = start.checked_add(len as usize) else {
            return Err(conn::Error::CryptoBufferExceeded);
        };
        let Some(bytes) = body.get(start..end) else {
            return Err(conn::Error::CryptoBufferExceeded);
        };
        consume(bytes)?;
        *next = next
            .checked_add(len as u64)
            .ok_or(conn::Error::CryptoBufferExceeded)?;
        Ok(())
    }
}

impl Spaces {
    pub(in crate::conn) const fn new() -> Self {
        Self([const { State::new() }; 3])
    }

    pub(in crate::conn::wire) fn prepare<'a, 'rows, 'id: 'rows>(
        &'a mut self,
        epoch: conn::Epoch,
        frames: impl IntoIterator<Item = (u64, ops::Range<usize>, &'rows mut Step<'id>)>,
        body: &frame::Body<'_, 'id>,
        scratch: &mut Scratch,
    ) -> Result<Prepared<'a, 'id>, Failure> {
        let state = epoch
            .bind_mut(&mut self.0)
            .prepare(frames, body.as_ref(), scratch)?;
        Ok(Prepared::new(state, body))
    }

    pub(in crate::conn) fn discard(&mut self, epoch: conn::Epoch) {
        epoch.bind_mut(&mut self.0).discard();
    }
}

const _: () = assert!(mem::size_of::<State>() == 2 * mem::size_of::<usize>());
const _: () = assert!(mem::size_of::<Spaces>() == 3 * mem::size_of::<State>());
const _: () = assert!(mem::size_of::<Scratch>() == 3 * mem::size_of::<usize>());
