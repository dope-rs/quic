use o3::buffer;
use std::time;

use crate::conn::stream::{State, Streams, state::streams};
use crate::conn::wire::tls::ciphers::Update;
use crate::conn::{self, output};
use crate::security::crypto;
use crate::{stream, wire::varint};
use output::{control, transmit::Admission};

pub(super) struct Stage<'a, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment> {
    conn: &'a mut conn::Machine<DOMAIN, B, D>,
}

pub(super) enum Outcome {
    Ready(Option<(time::Duration, time::Duration)>),
    Closed,
}

impl<'a, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment> Stage<'a, DOMAIN, B, D> {
    pub(super) fn new(conn: &'a mut conn::Machine<DOMAIN, B, D>) -> Self {
        Self { conn }
    }

    pub(super) fn snapshot(&mut self, work: usize) -> Result<(), control::Admission> {
        let local = self.conn.streams.local();
        let Streams {
            state:
                State {
                    transmit,
                    local_initiated: admit,
                    ..
                },
            ..
        } = &mut self.conn.streams;
        transmit.snapshot(&mut self.conn.control, work, |id| {
            admit.allows(streams::Relative::new(id, local))
        })
    }

    pub(super) fn try_one_rtt(
        &mut self,
        now: time::Instant,
    ) -> Result<Outcome, Admission<crypto::Dimensions>> {
        if self.conn.egress.lifecycle.state == conn::State::Closed {
            return Ok(Outcome::Closed);
        }
        let keys = &self.conn.handshake.keys;
        let spaces = &self.conn.egress.recovery.spaces;
        let initial =
            keys.long.initial().is_some() && conn::Epoch::Initial.bind(spaces).is_exhausted();
        let hs =
            keys.long.handshake().is_some() && conn::Epoch::Handshake.bind(spaces).is_exhausted();
        let app = (keys.long.early().is_some() || keys.has_write())
            && conn::Epoch::Application.bind(spaces).is_exhausted();
        if initial || hs || app {
            self.conn.egress.lifecycle.state = conn::State::Closed;
            return Ok(Outcome::Closed);
        }
        if self.conn.handshake.keys.long.is_exhausted() {
            if !self.conn.handshake.keys.has_write() {
                self.conn.egress.lifecycle.state = conn::State::Closed;
                return Ok(Outcome::Closed);
            }
            let _ = self.conn.queue_close(output::PendingClose::transport(
                conn::AEAD_LIMIT_REACHED,
                varint::VarInt::ZERO,
            ));
        }
        if !self.conn.handshake.keys.has_write() {
            return Ok(Outcome::Ready(None));
        }
        let admitted = self.conn.try_pto()?;
        if self.conn.is_closing() {
            return Ok(Outcome::Ready(Some(admitted)));
        }
        let pto = admitted.1;
        let done = self.conn.egress.lifecycle.handshake_confirmed;
        match self.conn.handshake.keys.prepare(done, now, pto) {
            Ok(()) => Ok(Outcome::Ready(Some(admitted))),
            Err(Update::Timing(error)) => Err(Admission::Timing(self.conn.fail_timing(error))),
            Err(Update::Dimensions(error)) => {
                let _ = self.conn.queue_close(output::PendingClose::transport(
                    conn::INTERNAL_ERROR,
                    varint::VarInt::ZERO,
                ));
                Err(Admission::Protection(error))
            }
            Err(error @ (Update::AeadLimitReached | Update::Key)) => {
                let code = if matches!(error, Update::AeadLimitReached) {
                    conn::AEAD_LIMIT_REACHED
                } else {
                    conn::KEY_UPDATE_ERROR
                };
                let _ = self
                    .conn
                    .queue_close(output::PendingClose::transport(code, varint::VarInt::ZERO));
                Ok(Outcome::Ready(Some(admitted)))
            }
            Err(Update::UnexpectedEpoch) => {
                let _ = self.conn.queue_close(output::PendingClose::transport(
                    conn::INTERNAL_ERROR,
                    varint::VarInt::ZERO,
                ));
                Ok(Outcome::Ready(Some(admitted)))
            }
        }
    }
}
