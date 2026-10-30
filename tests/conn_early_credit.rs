pub mod common;
use common::runtime::reap::{CLIENT, Capture, Credit};
use common::suite::peers;
use common::suite::peers::Error;
use dope_quic::conn;
use dope_quic::conn::life::options::Options;
use dope_quic::runtime::routing;
use dope_quic::wire::packet::cid;
use dope_quic::{proto::param, runtime::mux::builder::Builder};
use std::{pin::Pin, time::Instant};

#[test]
fn early_control_credit() {
    let params = param::Set::builder()
        .idle_ms(0)
        .initial_data(4)
        .local_bidi(4)
        .remote_bidi(4)
        .bidi_count(1)
        .try_build()
        .expect("four-byte receive credit");
    let auth = peers::Authority::try_new(Options::try_from(params).expect("server options"));
    auth.as_ref()
        .map_err(Error::cause)
        .expect("early-data authority");
    let auth = auth.ok().expect("admitted authority");
    auth.first(&peers::CID)
        .as_ref()
        .map_err(Error::cause)
        .expect("cached Plain ticket");
    let client = auth.resume(
        cid::Id::try_from([0x69; 8]).expect("initial CID"),
        cid::Id::try_from([0x6a; 8]).expect("client CID"),
        routing::Plain,
    );
    client
        .as_ref()
        .map_err(Error::cause)
        .expect("resumed client");
    let mut client = client.ok().expect("admitted client");
    let mut server = Builder::server(Capture::default(), auth.server)
        .build()
        .expect("early-data router");
    let now = Instant::now();
    let (stream, packets) = client.with_scope(|mut scope| {
        let stream = scope
            .streams()
            .send()
            .open_bidi()
            .expect("cached stream credit");
        scope
            .streams()
            .send()
            .send(stream.send(), b"lane")
            .expect("four early bytes");
        let id = stream.id();
        let (packets, send_result) = scope.output().send(now);
        send_result.expect("early flight");
        (id, packets)
    });
    assert!(
        packets
            .iter()
            .any(|packet| packet.first().is_some_and(|byte| byte & 0xf0 == 0xd0))
    );
    for mut packet in packets {
        Capture::receive(&mut server, CLIENT, &mut packet, now).expect("early ingress");
    }
    let handle = server.sole().expect("unvalidated early-data owner");
    let mut raw = [0u8; 1200];
    let cid = server
        .conn(handle)
        .expect("server")
        .view()
        .path()
        .local_cids()
        .values()
        .next()
        .expect("routable server CID");
    assert_eq!(cid.len(), 8);
    raw[1..9].copy_from_slice(cid);
    let credit =
        Credit::exhaust(&mut server, handle, &mut raw, now).expect("finite amplification fixture");
    assert_eq!(credit.deadline, None);
    assert!(credit.blocked < raw.len());
    assert_eq!(credit.probes, [1, 1]);
    assert!(credit.sent <= 3 * credit.received);
    assert!((1..29).contains(&(3 * credit.received - credit.sent)));
    let now = credit.now;
    let conn = server.conn(handle).expect("server");
    assert_eq!(conn.view().path().received(), credit.received);
    assert_eq!(conn.view().recovery().next_timer(), None);
    assert!(!conn.view().lifecycle().is_ready());
    assert!(!conn.view().path().is_valid());
    Capture::with_conn(&mut server, handle, now, |mut scope| {
        let peer = scope
            .streams()
            .view()
            .resolve_recv(stream)
            .expect("early stream");
        let mut got = Vec::new();
        assert_eq!(scope.streams().receive().recv(peer, &mut got), Ok(4));
        assert_eq!(got, b"lane");
    })
    .expect("release early receive credit");
    assert!(
        Capture::output(&mut server, now)
            .expect("materialize flow control")
            .is_empty()
    );
    assert_eq!(
        server
            .conn(handle)
            .expect("server")
            .view()
            .recovery()
            .next_timer(),
        None
    );
    let due = Pin::new(&mut server).observe(now, |turn| turn.deadline());
    assert!(
        due.is_none_or(|due| due > now),
        "blocked control at {now:?}, due {due:?}"
    );
    assert_eq!(
        Capture::drive(&mut server, now).expect("blocked control turn"),
        0
    );
    Capture::receive(&mut server, CLIENT, &mut raw, now).expect("raw ingress credit");
    let conn = server.conn(handle).expect("server");
    assert_eq!(conn.view().path().received(), credit.received + 1200);
    let pto = conn
        .view()
        .recovery()
        .next_timer()
        .expect("retained future PTO");
    let unacked = conn.view().recovery().unacked(conn::Epoch::Application);
    let due = Pin::new(&mut server)
        .observe(now, |turn| turn.deadline())
        .expect("retained flow control becomes runnable");
    assert!(
        now.max(due) < pto,
        "flow control resumes before another PTO can arm"
    );
    let output = Capture::output(&mut server, now.max(due)).expect("protected flow control output");
    assert!(!output.is_empty());
    let sent = output
        .iter()
        .map(|flight| flight.payload().len() as u64)
        .sum::<u64>();
    assert!(sent < 1200);
    assert!(credit.sent + sent <= 3 * (credit.received + 1200));
    assert!(
        server
            .conn(handle)
            .expect("server")
            .view()
            .recovery()
            .unacked(conn::Epoch::Application)
            > unacked
    );
    assert!(
        !server
            .conn(handle)
            .expect("server")
            .view()
            .path()
            .is_valid()
    );
}
