use crate::common::{
    peer::{self, Initial, Setup, Transfer, sealer::Raw},
    suite::peers::packet::{CID, Error, Session, bytes, wire::Wire},
};
use dope_quic::{
    conn,
    wire::{frame, packet::cid, varint::VarInt},
};
use dope_tls::config;
use o3::alloc::{self, VecExt};
use o3::buffer::write::Sink as _;
use rustls::{
    ClientConfig, ServerConfig, Side,
    client::{ClientSessionMemoryCache, Resumption},
    quic,
    server::ServerSessionMemoryCache,
};
use std::{mem, sync::Arc, time::Instant};

pub fn empty(out: &mut Vec<u8>, id: VarInt) -> Result<(), alloc::Error> {
    out.write_slices([id.pack().as_ref(), &[0]])
}

pub fn is_reserved(id: u64) -> bool {
    id >= 27 && (id - 27).is_multiple_of(31)
}

pub fn push(out: &mut Vec<u8>, id: VarInt, value: &[u8]) -> Result<(), Error> {
    let length = VarInt::try_from(value.len() as u64).map_err(Error::VarInt)?;
    out.write_slices([id.pack().as_ref(), length.pack().as_ref(), value])
        .map_err(Error::Allocation)
}

pub fn preferred(cid_len: u8) -> [u8; 62] {
    let mut value = [0; 62];
    value[..4].copy_from_slice(&[127, 0, 0, 1]);
    value[4..6].copy_from_slice(&443u16.to_be_bytes());
    value[24] = cid_len;
    value[25..].fill(0x59);
    value
}

pub fn configs() -> Result<(ClientConfig, ServerConfig, Arc<ClientSessionMemoryCache>), Error> {
    let (identity, key) = peer::raw(0x65).map_err(Error::Tls)?;
    let mut client = config::raw::Identity::client(key).map_err(Error::Tls)?;
    let cache = Arc::new(ClientSessionMemoryCache::new(16));
    client.enable_early_data = true;
    client.resumption = Resumption::store(cache.clone());
    let mut server = identity.server().map_err(Error::Tls)?;
    server.send_tls13_tickets = 2;
    server.max_early_data_size = u32::MAX;
    server.session_storage = ServerSessionMemoryCache::new(8);
    Ok((client, server, cache))
}

pub struct Server {
    peer: Session,
    initial: Raw,
}

impl Server {
    pub fn try_new(
        config: Arc<ServerConfig>,
        local: cid::Id,
        encoded: Vec<u8>,
    ) -> Result<Self, Error> {
        let tls = quic::ServerConnection::new(config, quic::Version::V1, encoded)
            .map_err(dope_tls::Error::Tls)
            .map_err(Error::Tls)?;
        Ok(Self {
            peer: Session {
                tls: tls.into(),
                wire: Wire::default(),
                initial: Raw::initial(&CID, Side::Client, 0).map_err(Error::Key)?,
                local,
                target: cid::Id::try_from(CID).map_err(Error::Id)?,
                offsets: [0; 2],
                number: 0,
            },
            initial: Raw::initial(&CID, Side::Server, 0).map_err(Error::Key)?,
        })
    }

    pub fn exchange(
        &mut self,
        client: &mut conn::Connection,
        work: &mut conn::Workspace,
        now: Instant,
    ) -> Result<(), Error> {
        let now = client.view().recovery().send_at(now);
        let (packets, result) = client.with_scope(|mut scope| scope.output().send(now));
        result
            .map_err(Transfer::Output)
            .map_err(Setup::Client)
            .map_err(Error::Setup)?;
        for packet in packets {
            let _ = self.receive(&packet)?;
        }
        for mut packet in self.send()? {
            client
                .with_scope(|mut scope| scope.input(work).recv_packet(&mut packet, now, |_| {}))
                .map_err(|error| Error::Setup(Setup::Client(Transfer::Input(error))))?;
        }
        Ok(())
    }

    pub fn receive(&mut self, packet: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        self.peer.receive(packet)
    }

    pub fn packet(&mut self, frames: &[u8]) -> Result<Vec<u8>, Error> {
        self.peer.packet(frames)
    }

    pub fn send(&mut self) -> Result<Vec<Vec<u8>>, Error> {
        let mut packets = Vec::try_new(3).map_err(Error::Allocation)?;
        let initial = mem::take(&mut self.peer.wire.output[0]);
        if !initial.is_empty() {
            let frame = bytes::crypto(VarInt::ZERO, &initial)?;
            packets.push(
                Initial::new(self.peer.target.as_slice(), self.peer.local.as_slice(), 0)
                    .seal_with(&frame, &mut self.initial)
                    .map_err(Error::Wire)?,
            );
        }
        let flight = mem::take(&mut self.peer.wire.output[1]);
        if !flight.is_empty() {
            packets.push(self.peer.handshake(&flight)?);
        }
        let tickets = mem::take(&mut self.peer.wire.output[2]);
        if !tickets.is_empty() {
            let mut frames = bytes::crypto(VarInt::ZERO, &tickets)?;
            frames
                .write_slice(&[frame::TYPE_HANDSHAKE_DONE])
                .map_err(Error::Allocation)?;
            packets.push(self.peer.packet(&frames)?);
        }
        Ok(packets)
    }
}
