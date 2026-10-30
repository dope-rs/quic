use std::{net, time};

use crate::conn;
use crate::conn::output::control;
use crate::conn::wire::path;
use crate::conn::wire::path::address::state;
use crate::proto::recovery::numbers;
use crate::wire::packet::cid;

#[derive(Clone, Copy)]
pub(in crate::conn) struct Output<'a> {
    path: &'a path::State,
}

impl<'a> Output<'a> {
    pub(in crate::conn::wire::path) const fn new(path: &'a path::State) -> Self {
        Self { path }
    }

    pub(in crate::conn) fn deadline(&self) -> Option<time::Instant> {
        self.path
            .address
            .candidate
            .and_then(state::Candidate::deadline)
    }

    pub(in crate::conn) fn is_retry_due(&self, now: time::Instant) -> bool {
        self.path
            .address
            .candidate
            .is_some_and(|item| item.is_retry_due(now))
    }

    pub(in crate::conn) fn permit(
        &self,
        control: &control::Pending,
        ceiling: usize,
        packet: &numbers::Packet,
    ) -> path::OutputPermit {
        control
            .probe()
            .find_path(control, |path| self.try_path(path, ceiling, packet))
            .unwrap_or(path::OutputPermit {
                route: path::OutputRoute::ACTIVE,
                ceiling,
            })
    }

    fn try_path(
        &self,
        path: path::Key,
        mut ceiling: usize,
        packet: &numbers::Packet,
    ) -> Option<path::OutputPermit> {
        let observed = self.path.address.get(path)?;
        if Some(observed.address) != self.path.address.active {
            let auth = u128::from(observed.received) * 3;
            let spent = u128::from(observed.sent);
            let room = auth
                .saturating_sub(spent)
                .min(u128::from(u64::MAX - observed.sent));
            let room = u64::try_from(room).ok()?;
            let room = room.min(usize::MAX as u64) as usize;
            ceiling = ceiling.min(room);
        }
        let route = path::OutputRoute { path: Some(path) };
        let minimum = 1usize
            .saturating_add(self.cid(route).len())
            .saturating_add(usize::from(packet.encoded_len()))
            .saturating_add(9)
            .saturating_add(conn::TAG_LEN);
        (ceiling >= minimum).then_some(path::OutputPermit { route, ceiling })
    }

    pub(in crate::conn) fn target(
        &self,
        route: path::OutputRoute,
    ) -> Option<Option<net::SocketAddr>> {
        match route.path() {
            Some(path) => self
                .path
                .address
                .get(path)
                .map(|observed| Some(observed.address)),
            None => Some(None),
        }
    }

    pub(in crate::conn) fn cid(&self, route: path::OutputRoute) -> cid::Ref<'a> {
        let spare = route.path().is_some_and(|path| {
            self.path
                .address
                .candidate
                .is_some_and(|item| item.path() == path)
        });
        if spare && let Some(cid) = self.path.peer.spare() {
            return cid.as_ref_id();
        }
        self.path.peer.id().as_ref_id()
    }

    pub(in crate::conn) fn has_output(&self, control: &control::Pending) -> bool {
        control.probe().has_output(control)
    }
}
