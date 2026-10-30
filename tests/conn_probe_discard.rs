pub mod common;

use common::runtime::{
    Error,
    reap::{CID, CLIENT, Capture, Pair, SERVER},
};
use dope_quic::{
    conn::{Epoch, life::options::Options},
    runtime::mux::builder::{Builder, Plan},
};
use std::{
    pin::Pin,
    time::{Duration, Instant},
};

#[test]
fn discard_stops_probe() -> Result<(), Error> {
    let Pair {
        mut server,
        srv_log,
        key,
        params,
        ..
    } = Capture::build_pair(30_000)?;
    let capture = Capture::default();
    let cli_log = capture.events.clone();
    let limits = Plan::try_new(1, 1, 1 << 20).expect("one packet output limit");
    let mut client = Builder::client(capture)
        .limits(limits)
        .build()
        .expect("client router");
    let now = Instant::now();
    let handle = Capture::connect(
        &mut client,
        SERVER,
        key,
        Options::try_from(params).map_err(Error::Options)?,
        CID.to_vec(),
        now,
    )?;
    Capture::relay_once(&mut client, &mut server, CLIENT, now)?;
    Capture::relay_once(&mut server, &mut client, SERVER, now)?;
    for _ in 0..4 {
        Capture::relay_once(&mut client, &mut server, CLIENT, now)?;
        if server
            .sole()
            .and_then(|handle| server.conn(handle))
            .is_some_and(|conn| conn.view().lifecycle().is_ready())
        {
            break;
        }
    }
    assert!(
        server
            .sole()
            .and_then(|handle| server.conn(handle))
            .is_some_and(|conn| conn.view().lifecycle().is_ready())
    );
    let confirm = Capture::output(&mut server, now).map_err(Error::Output)?;
    assert!(!confirm.is_empty());

    let conn = client.conn(handle).expect("retained client");
    assert!(conn.view().lifecycle().is_ready());
    assert!(!conn.view().lifecycle().is_confirmed());
    assert_eq!(conn.view().recovery().unacked(Epoch::Initial), 0);
    let pending = conn.view().recovery().unacked(Epoch::Handshake);
    assert!(pending > 0);
    let probe_at =
        conn.view().recovery().next_timer().expect("handshake PTO") + Duration::from_nanos(1);
    let probe = Capture::output(&mut client, probe_at).map_err(Error::Output)?;
    assert_eq!(
        probe
            .iter()
            .map(|flight| flight.packet_count().get())
            .sum::<usize>(),
        1
    );
    assert_eq!(
        client
            .conn(handle)
            .expect("retained client")
            .view()
            .recovery()
            .unacked(Epoch::Handshake),
        pending + 1
    );

    for mut flight in confirm {
        for packet in flight.segments_mut() {
            Capture::receive(&mut client, SERVER, packet, probe_at)?;
        }
        Pin::new(&mut server).output().recycle(flight);
    }
    let conn = client.conn(handle).expect("retained client");
    assert!(conn.view().lifecycle().is_confirmed());
    assert!(conn.view().lifecycle().is_ready());
    assert_eq!(conn.view().recovery().unacked(Epoch::Handshake), 0);
    for _ in 0..4 {
        let flights = Capture::output(&mut client, probe_at).map_err(Error::Output)?;
        if flights.is_empty() {
            break;
        }
        for flight in flights {
            Pin::new(&mut client).output().recycle(flight);
        }
    }
    assert!(
        Pin::new(&mut client)
            .observe(probe_at, |turn| turn.deadline())
            .is_none_or(|due| due > probe_at),
        "discarded handshake probes must not retain immediate mux work"
    );
    assert_eq!(
        Capture::drive(&mut client, probe_at).map_err(Error::Output)?,
        0
    );
    assert!(cli_log.borrow().closed.is_empty());
    assert!(srv_log.borrow().closed.is_empty());
    Ok(())
}
