use crate::common::peer::Transfer;
use crate::common::suite::peers::{self, Authority};
use dope_quic::conn::{self, scope::Access};
use o3::buffer::storage;
use std::time::Instant;

pub fn authority() -> Result<Authority, peers::Error> {
    Authority::params()
        .and_then(Authority::options)
        .and_then(Authority::try_new)
}

pub fn finish(
    server: &mut Access<'_, 0, Vec<u8>, false, storage::Shared>,
    client: &mut Access<'_, 0, Vec<u8>, false, storage::Shared>,
    work: &mut conn::Workspace,
    now: Instant,
) -> Result<(), Transfer> {
    for _ in 0..3 {
        let (packets, result) = server.output().send(now);
        result.map_err(Transfer::Output)?;
        for mut packet in packets {
            client
                .input(work)
                .recv_packet(&mut packet, now, |_| {})
                .map_err(Transfer::Input)?;
        }
        let (packets, result) = client.output().send(now);
        result.map_err(Transfer::Output)?;
        for mut packet in packets {
            server
                .input(work)
                .recv_packet(&mut packet, now, |_| {})
                .map_err(Transfer::Input)?;
        }
    }
    Ok(())
}
