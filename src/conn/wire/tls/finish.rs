use o3::buffer;
use std::time;

use crate::{
    conn::{
        self, output,
        wire::{path, tls},
    },
    proto::param,
    stream,
    wire::stream::Initiator,
};
use conn::stream::State;
use output::control;

/// Connection fields consumed by a successful handshake transition.
pub(in crate::conn) struct Finish<'a, B: stream::Recv, D: buffer::raw::Segment> {
    pub(in crate::conn) egress: &'a mut output::Egress,
    pub(in crate::conn) control: &'a mut control::Pending,
    pub(in crate::conn) completion: tls::Completion<'a>,
    pub(in crate::conn) path: &'a mut path::State,
    pub(in crate::conn) streams: &'a mut State<B, D>,
    pub(in crate::conn) params: &'a mut Option<param::Set>,
    pub(in crate::conn) local: Initiator,
}

struct Peer(param::Set);

impl Peer {
    fn try_new(
        peer: param::Set,
        path: &path::State,
        saved: Option<&param::Set>,
        local: Initiator,
        early: bool,
    ) -> Result<Self, conn::Error> {
        let fail = || conn::Error::TransportParameterMismatch;
        let id = peer.identity();
        let want = path.origin.peer_first_scid.as_ref().ok_or_else(fail)?;
        let got = id.initial().ok_or_else(fail)?;
        if got != want {
            return Err(fail());
        }

        match local {
            Initiator::Client => {
                if id.original() != Some(&path.origin.original_dcid) {
                    return Err(fail());
                }
                if id.retry() != path.origin.retry_source_cid.as_ref() {
                    return Err(fail());
                }
                if id.has_address() && got.is_empty() {
                    return Err(fail());
                }
                if early && let Some(saved) = saved {
                    Self::try_early(&peer, saved)?;
                }
            }
            Initiator::Server => {
                if id.original().is_some()
                    || id.retry().is_some()
                    || id.reset().is_some()
                    || id.has_address()
                {
                    return Err(fail());
                }
            }
        }
        Ok(Self(peer))
    }

    fn into_inner(self) -> param::Set {
        self.0
    }

    fn try_early(new: &param::Set, saved: &param::Set) -> Result<(), conn::Error> {
        let new_id = new.identity();
        let old_id = saved.identity();
        let new = new.flow();
        let old = saved.flow();
        if new_id.cid_limit() < old_id.cid_limit()
            || new.initial_data() < old.initial_data()
            || new.local_bidi() < old.local_bidi()
            || new.remote_bidi() < old.remote_bidi()
            || new.stream_uni() < old.stream_uni()
            || new.bidi_count() < old.bidi_count()
            || new.uni_count() < old.uni_count()
        {
            return Err(conn::Error::TransportParameterMismatch);
        }
        if let Some(old) = old.datagram()
            && new.datagram().unwrap_or(0) < old
        {
            return Err(conn::Error::ProtocolViolation);
        }
        Ok(())
    }
}

impl<B: stream::Recv, D: buffer::raw::Segment> Finish<'_, B, D> {
    pub(in crate::conn) fn apply(self) -> Result<(), conn::Error> {
        let raw = param::Codec::decode(
            self.completion
                .params
                .ok_or(conn::Error::TransportParameterMismatch)?,
        )?;
        let peer = Peer::try_new(
            raw,
            self.path,
            self.params.as_ref(),
            self.local,
            self.completion.early,
        )?
        .into_inner();
        let id = peer.identity();
        let flow = peer.flow();
        let timing = peer.timing();

        self.completion.keys.activate();

        if matches!(self.local, Initiator::Client)
            && let Some(token) = id.reset()
        {
            self.path.peer.set_token(token);
        }
        let early = self.completion.early;
        let mut counts = [flow.bidi_count(), flow.uni_count()];
        let transmit = &mut self.streams.transmit;
        if early {
            for (count, previous) in counts.iter_mut().zip(self.streams.local_initiated.peer_max) {
                *count = (*count).max(previous);
            }
            transmit
                .peer
                .data_credit
                .raise(flow.initial_data(), self.control);
        } else {
            transmit
                .peer
                .data_credit
                .replace(flow.initial_data(), self.control);
        }
        transmit.set_credit(&peer, self.local, early, self.control)?;
        self.streams.local_initiated.peer_max = counts;
        self.egress
            .cc
            .set_peer_max(flow.udp_max())
            .ok_or_else(|| conn::Error::TransportParameterMismatch)?;
        self.egress.recovery.peer_max_ack_delay =
            time::Duration::from_millis(u64::from(timing.ack_ms()));
        let cids = self.path.local.issue_cids(id.cid_limit());
        *self.params = Some(peer);
        self.egress.lifecycle.state = conn::State::Established;
        if matches!(self.local, Initiator::Server) {
            self.egress.lifecycle.handshake_confirmed = true;
        }
        self.egress.derived.establish(self.local, cids);
        Ok(())
    }
}
