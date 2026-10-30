pub mod datagram;
pub mod replay;

use crate::common::peer;
use dope_quic::conn::life::options::Options;
use dope_quic::conn::output::transmit;
use dope_quic::conn::wire::ingress::events;
use dope_quic::conn::{self, stream};
use dope_quic::errors::Code;
use dope_quic::errors::detail::Diagnostic;
use dope_quic::stream::{Capacity, release, send::admit};
use dope_quic::wire::stream::Id;
use o3::buffer::hold::evidence;
use peer::Bind as _;
use peer::Pair;
use peer::ReceiveId;
use peer::Scope as _;
use peer::SendId;
use peer::Setup;
use std::time::{Duration, Instant};

/// Established peers and one stream bound to its receiving connection.
pub struct Receive<F> {
    pub pair: Pair,
    pub stream: SendId,
    pub peer: ReceiveId,
    pub at: Instant,
    observe: F,
}

#[derive(Debug)]
pub enum Error {
    Deadline(Instant, Duration),
    Setup(Setup),
    Stream(stream::Error),
    Output(transmit::Error),
}

impl<F: FnMut(&rustls::Error)> Receive<F> {
    pub fn try_new(observe: F) -> Result<Self, Error> {
        let mut pair = Pair::try_default().map_err(Error::Setup)?;
        let stream = pair
            .client
            .send_streams()
            .open_uni()
            .map_err(Error::Stream)?;
        let peer = stream.bind(&pair.server).map_err(Error::Stream)?;
        let at = Instant::now();
        let delay = Duration::from_secs(4);
        Ok(Self {
            pair,
            stream,
            peer,
            at: at.checked_add(delay).ok_or(Error::Deadline(at, delay))?,
            observe,
        })
    }

    pub fn try_send(&mut self, bytes: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
        self.pair
            .client
            .send_streams()
            .send(self.stream, bytes)
            .map_err(Error::Stream)?;
        self.try_flush()
    }

    pub fn try_flush(&mut self) -> Result<Vec<Vec<u8>>, Error> {
        let delay = Duration::from_millis(1);
        self.at = self
            .at
            .checked_add(delay)
            .ok_or(Error::Deadline(self.at, delay))?;
        let (packets, result) = self
            .pair
            .client
            .with_scope(|mut scope| scope.output().send(self.at));
        result.map_err(Error::Output)?;
        Ok(packets)
    }

    pub fn try_open(&mut self) -> Result<(), stream::Error> {
        let stream = self.pair.client.send_streams().open_uni()?;
        let peer = stream.bind(&self.pair.server)?;
        self.stream = stream;
        self.peer = peer;
        Ok(())
    }

    pub fn deliver(&mut self, packets: &mut [Vec<u8>]) -> Result<(), conn::Error> {
        for packet in packets {
            self.pair.server.with_scope(|mut scope| {
                scope
                    .input(&mut self.pair.work)
                    .recv_packet(packet, self.at, &mut self.observe)
            })?;
        }
        Ok(())
    }
}

pub struct Rejected<F> {
    pub error: Option<Capacity>,
    pub id: Option<Id>,
    pub observed: usize,
    pub unexpected: Option<Diagnostic>,
    observe: F,
}

impl<F: FnMut(&rustls::Error)> Rejected<F> {
    pub fn new(observe: F) -> Self {
        Self {
            error: None,
            id: None,
            observed: 0,
            unexpected: None,
            observe,
        }
    }
}

impl<F> release::Sink for Rejected<F> {
    type Mode = evidence::Off;

    fn release(&mut self, proof: evidence::Off, _: admit::Source, _: release::Cause) {
        let evidence::Off = proof;
    }
}

impl<F: FnMut(&rustls::Error)> events::Sink for Rejected<F> {
    type Observer<'a>
        = &'a mut Self
    where
        Self: 'a;

    fn certificate(&mut self, cause: &rustls::Error) {
        (self.observe)(cause)
    }

    fn observer(&mut self) -> Option<Self::Observer<'_>> {
        Some(self)
    }
}

impl<F> events::Observe for &mut Rejected<F> {
    fn observe(self, detail: &Diagnostic) {
        use dope_quic::errors::detail::{Diagnostic, Scope, Stream, Streams};
        use dope_quic::wire::ranges;
        self.observed += 1;
        match detail {
            Diagnostic::Streams(Streams::Receiver(Scope::Prepare {
                id,
                error: Stream::Range(ranges::Error::Capacity(cause)),
            })) => {
                self.error.get_or_insert(*cause);
                self.id.get_or_insert(*id);
            }
            other => {
                self.unexpected.get_or_insert_with(|| other.clone());
            }
        }
    }
}

pub const MIXED_STREAM: &[u8] = b"mixed stream";
pub const REVERSE_STREAM: &[u8] = b"reverse stream";

pub fn try_options(events: usize) -> Result<Options, Setup> {
    peer::Config::new(1 << 20, 1 << 20, 0, 2)
        .try_build()?
        .into_builder()
        .streams(|streams| streams.local_bidi(0).local_uni(2).events(events))
        .try_build()
        .map_err(Setup::Options)
}

pub fn try_queue(client: &mut conn::Connection) -> Result<(SendId, SendId), stream::Error> {
    let data = client.send_streams().open_uni()?;
    let reset = client.send_streams().open_uni()?;
    client.send_streams().send(data, MIXED_STREAM)?;
    client.send_streams().finish(data)?;
    client.send_streams().reset(reset, Code::from_u8(0x51))?;
    Ok((data, reset))
}
