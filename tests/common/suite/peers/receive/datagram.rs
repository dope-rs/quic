use crate::common::peer::{Pair, Receiver as _, Setup};
use dope_quic::conn::{self, life::options::Options, output::transmit};
use dope_quic::errors::SendFailure;
use dope_quic::{proto::param, wire::packet::cid};
use std::{
    mem,
    time::{Duration, Instant},
};

fn random(seed: &mut u64) -> u32 {
    *seed = seed
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    (*seed >> 33) as u32
}

#[derive(Debug)]
pub enum Error {
    Deadline(Instant, Duration),
    Timing(conn::Timing),
    Setup(Setup),
    Send(SendFailure<Vec<u8>>),
    Output(transmit::Error),
}

fn try_options() -> Result<Options, Setup> {
    let params = param::Set::builder()
        .idle_ms(60_000)
        .datagram(Some(65535))
        .try_build()
        .map_err(Setup::Params)?;
    Options::builder()
        .transport(|net| net.params(params))
        .datagrams(|dgrams| dgrams.pending(4096))
        .try_build()
        .map_err(Setup::Options)
}

pub fn try_pair() -> Result<Pair, Setup> {
    let cid = cid::Id::try_from([0x88; 8]).map_err(Setup::Id)?;
    let mut pair = Pair::try_with(try_options()?, try_options()?, cid)?;
    let now = Instant::now();
    for _ in 0..6 {
        pair.exchange(now, 1)?;
        if pair.client.view().lifecycle().is_ready() && pair.server.view().lifecycle().is_ready() {
            break;
        }
    }
    pair.try_ready()?;
    Ok(pair)
}

pub fn try_settle(pair: &mut Pair, start: Instant) -> Result<Instant, Setup> {
    let mut now = start;
    for turn in 0..32 {
        let delay = Duration::from_millis(turn * 10);
        now = start
            .checked_add(delay)
            .ok_or(Setup::Deadline(start, delay))?;
        pair.exchange(now, 1)?;
    }
    Ok(now)
}

pub fn try_burst(client: &mut conn::Connection) -> Result<(), SendFailure<Vec<u8>>> {
    for i in 0..1000usize {
        let mut payload = vec![0_u8; 1000];
        payload[..mem::size_of::<usize>()].copy_from_slice(&i.to_ne_bytes());
        client.with_scope(|mut scope| scope.datagrams().try_send(payload))?;
    }
    Ok(())
}

pub fn try_drain(loss: u32, n: usize) -> Result<(usize, usize, Duration), Error> {
    let Pair {
        mut client,
        mut server,
        mut work,
    } = try_pair().map_err(Error::Setup)?;
    let mut rng = 0xDEAD_BEEF_CAFE_BABE;

    for i in 0..n {
        client
            .with_scope(|mut scope| {
                scope
                    .datagrams()
                    .try_send(format!("dg-{i:06}").into_bytes())
            })
            .map_err(Error::Send)?;
    }

    let t0 = Instant::now();
    let mut now = t0;
    let mut received = 0usize;
    let mut steps = 0usize;
    let max_iter = 50_000usize;
    let delay = Duration::from_micros(100);

    while received < n && steps < max_iter {
        let (packets, result) = client.with_scope(|mut scope| scope.output().send(now));
        result.map_err(Error::Output)?;
        for mut pkt in packets {
            if random(&mut rng) % 1_000_000 >= loss {
                server
                    .receive(&mut work, &mut pkt, now)
                    .map_err(Setup::Server)
                    .map_err(Error::Setup)?;
            }
        }
        while server
            .with_scope(|mut scope| scope.datagrams().recv())
            .is_some()
        {
            received += 1;
        }
        let (packets, result) = server.with_scope(|mut scope| scope.output().send(now));
        result.map_err(Error::Output)?;
        for mut pkt in packets {
            if random(&mut rng) % 1_000_000 >= loss {
                client
                    .receive(&mut work, &mut pkt, now)
                    .map_err(Setup::Client)
                    .map_err(Error::Setup)?;
            }
        }

        client
            .with_scope(|mut scope| scope.recovery().try_loss(now))
            .map_err(Error::Timing)?;
        server
            .with_scope(|mut scope| scope.recovery().try_loss(now))
            .map_err(Error::Timing)?;

        steps += 1;
        now = now.checked_add(delay).ok_or(Error::Deadline(now, delay))?;
    }

    Ok((received, steps, now - t0))
}
