use crate::common::{
    peer,
    suite::peers::packet::{CID, Error, Session},
};
use dope_quic::conn::{self, life::accept, life::options::Options};
use dope_quic::proto::param;
use dope_quic::wire::{frame, packet::cid, varint::VarInt};
use dope_tls::config;
use o3::{alloc::VecExt, buffer::storage};
use std::time::Instant;

pub struct Pair {
    pub peer: Session,
    pub server: conn::Connection,
    pub work: conn::Workspace,
}

impl Pair {
    pub fn try_new(
        parts: usize,
        now: Instant,
        check: impl FnMut(&rustls::Error),
    ) -> Result<Self, Error> {
        use peer::Setup;

        let params = param::Set::builder()
            .initial_data(4096)
            .stream_uni(2048)
            .uni_count(3)
            .try_build()
            .map_err(Setup::Params)
            .map_err(Error::Setup)?;
        Self::try_params(parts, params, now, check)
    }

    pub fn try_params(
        parts: usize,
        params: param::Set,
        now: Instant,
        check: impl FnMut(&rustls::Error),
    ) -> Result<Self, Error> {
        use peer::Setup;

        let options = Options::builder()
            .transport(|net| net.params(params))
            .streams(|streams| streams.recv_parts(parts).local_uni(3))
            .try_build()
            .map_err(Setup::Options)
            .map_err(Error::Setup)?;
        Self::try_options(options, now, check)
    }

    pub fn try_options(
        options: Options,
        now: Instant,
        mut check: impl FnMut(&rustls::Error),
    ) -> Result<Self, Error> {
        use peer::Setup;

        let (signing, key) = peer::raw(0x60)
            .map_err(Setup::Identity)
            .map_err(Error::Setup)?;
        let config = config::raw::Identity::client(key).map_err(Error::Tls)?;
        let mut peer = Session::try_new(config, options.params())?;
        let config = signing.server().map_err(Error::Tls)?;
        let auth = accept::Authority::new(config, options)
            .map_err(Setup::Authority)
            .map_err(Error::Setup)?;
        let cid = cid::Id::try_from(CID).map_err(Error::Id)?;
        let mut server = auth
            .accept::<storage::Shared>(accept::Ids::initial(cid, cid, cid))
            .map_err(Setup::Accept)
            .map_err(Error::Setup)?;
        let mut work = conn::Workspace::try_new().map_err(Error::Allocation)?;
        let mut initial = peer.initial()?;
        server
            .with_scope(|mut scope| {
                scope
                    .input(&mut work)
                    .recv_packet(&mut initial, now, &mut check)
            })
            .map_err(|error| Error::Setup(Setup::Server(peer::Transfer::Input(error))))?;
        let (outgoing, result) = server.with_scope(|mut scope| scope.output().send(now));
        result
            .map_err(peer::Transfer::Output)
            .map_err(Setup::Server)
            .map_err(Error::Setup)?;
        let mut packets = Vec::try_new(outgoing.len()).map_err(Error::Allocation)?;
        for packet in outgoing {
            if let Some(packet) = peer.receive(&packet)? {
                packets.push(packet);
            }
        }
        let mut finish = peer.finish(None)?;
        server
            .with_scope(|mut scope| {
                scope
                    .input(&mut work)
                    .recv_packet(&mut finish, now, &mut check)
            })
            .map_err(|error| Error::Setup(Setup::Server(peer::Transfer::Input(error))))?;
        if !server.view().lifecycle().is_ready() {
            return Err(Error::State(server.view().lifecycle().state()));
        }
        let mut pair = Self { peer, server, work };
        let _ = pair.consume(packets, now)?;
        Ok(pair)
    }

    pub fn receive(&mut self, frames: &[u8], now: Instant) -> Result<(), Error> {
        let mut packet = self.peer.packet(frames)?;
        self.server
            .with_scope(|mut scope| {
                scope
                    .input(&mut self.work)
                    .recv_packet(&mut packet, now, |_| {})
            })
            .map_err(|error| Error::Setup(peer::Setup::Server(peer::Transfer::Input(error))))
    }

    pub fn retired(&mut self, now: Instant) -> Result<Vec<u64>, Error> {
        let (packets, result) = self.server.with_scope(|mut scope| scope.output().send(now));
        result
            .map_err(peer::Transfer::Output)
            .map_err(peer::Setup::Server)
            .map_err(Error::Setup)?;
        self.consume(packets, now)
    }

    fn consume(&mut self, packets: Vec<Vec<u8>>, now: Instant) -> Result<Vec<u64>, Error> {
        let mut retired = Vec::new();
        for packet in packets {
            let Some(mut packet) = self.peer.receive(&packet)? else {
                continue;
            };
            let (number, data) = self.peer.open(&mut packet)?;
            let mut ack = false;
            for frame in frame::Frame::decode_all(&data).map_err(Error::Frame)? {
                match frame.view() {
                    frame::View::RetireConnectionId {
                        sequence_number: seq,
                    } => {
                        VecExt::try_reserve(&mut retired, 1).map_err(Error::Allocation)?;
                        retired.push(seq.get());
                        ack = true;
                    }
                    frame::View::Padding
                    | frame::View::Ack { .. }
                    | frame::View::ConnectionClose { .. } => {}
                    _ => ack = true,
                }
            }
            if ack {
                let number = VarInt::try_from(number).map_err(Error::VarInt)?;
                let mut ack = Vec::new();
                frame::Borrowed::ack(number, VarInt::ZERO, VarInt::ZERO, &[])
                    .map_err(|error| Error::Frame(error.into()))?
                    .encode(&mut ack)
                    .map_err(Error::Allocation)?;
                self.receive(&ack, now)?;
            }
        }
        Ok(retired)
    }
}
