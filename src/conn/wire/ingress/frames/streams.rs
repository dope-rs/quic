use crate::errors::detail;
use o3::mem::slice::Ext as _;
use std::{iter, ops};

use crate::conn;
use crate::conn::stream::event::queue;
use crate::conn::stream::state::receive::recv::map::{scope, views};
use crate::conn::wire::ingress::frames::{self, sources};
use crate::stream;
use crate::wire::ranges::inserts;

pub(super) struct Streams<'a, 'id, 'table, 'body, B: stream::Recv> {
    scope: scope::Batch<'a, 'id, 'table, 'body, B>,
}

impl<'a, 'id, 'table, 'body, B: stream::Recv> Streams<'a, 'id, 'table, 'body, B> {
    pub(super) fn try_new<S: sources::Backing<B>>(
        scope: scope::Preparation<'a, 'id, 'table, B>,
        ready: &sources::Prepared<'_, 'body, '_, '_, '_, '_, '_, '_, '_, '_, B, S>,
        segs: &mut Vec<ops::Range<u64>>,
        parts: &mut Vec<inserts::Part>,
    ) -> Result<Self, detail::Streams> {
        let mut order = ready.order();
        let mut prior = None;
        let scope = scope
            .prepare_all(
                ready.source(),
                |index| {
                    let id = ready.id(*index);
                    if prior == Some(id) {
                        return Ok(None);
                    }
                    prior = Some(id);
                    let (indices, rest) = order.split_while(|index| ready.id(*index) == id);
                    order = rest;
                    let mut input = indices.iter().map(|index| {
                        ready
                            .entry(*index)
                            .try_stream()
                            .map(|stream| stream.map(|stream| (*index, stream)))
                            .map_err(|error| detail::Stream::Backing {
                                frame: index.get(),
                                error,
                            })
                    });
                    let first = input
                        .find_map(Result::transpose)
                        .transpose()
                        .map_err(|error| detail::Scope::Prepare { id, error })?;
                    Ok(first.map(|first| {
                        let key = first.1.key();
                        (key, id, iter::once(Ok(Some(first))).chain(input))
                    }))
                },
                |source, target| {
                    let source = source.map(|entry| {
                        let Some((frame, stream)) = entry? else {
                            return Ok(None);
                        };
                        stream
                            .take()
                            .map(Some)
                            .map_err(|error| detail::Stream::Backing {
                                frame: frame.get(),
                                error,
                            })
                    });
                    views::Input::try_collect(target, segs, parts, source)
                },
            )
            .map_err(detail::Streams::Receiver)?;
        Ok(Self { scope })
    }

    pub(super) fn try_apply(
        self,
        permit: &frames::CommitPermit<'_>,
        events: &mut queue::Permit<'_>,
    ) -> Result<(), detail::Streams> {
        use o3::depot::arena::linked::Batch as _;
        scope::Input::new(self.scope, permit, events)
            .try_apply()
            .map_err(detail::Streams::Slots)?;
        Ok(())
    }
}

const _: () = assert!(conn::MAX_FRAMES_PER_PACKET <= u8::MAX as usize + 1);
