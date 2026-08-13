use std::env;
use std::hint::black_box;
use std::time::{Duration, Instant};

use dope_quic::conn::server;
use dope_quic::conn::session::Connection;
use dope_quic::conn::{self, datagram::CongestionControl, packet::Batch};
use dope_quic::transport_params;
use shin::crypto::sig::SigningKey;

const SEED: [u8; 32] = [0x5a; 32];
const CID: [u8; 8] = [0x42; 8];
const PAYLOAD: usize = 256;
const CONNECTIONS: usize = 3;
const CONTROL_BURST: usize = 8;
const DEFAULT_GROUPS: usize = 128;

struct Pair {
    client: Connection,
    _server: server::Connection,
}

impl Pair {
    fn established() -> Self {
        let signing = SigningKey::from_seed(&SEED).expect("seed");
        let server_pubkey = *signing.pubkey().expect("public key");
        let mut server = dope_quic::conn::setup::Server::accept(
            CID.to_vec(),
            CID.to_vec(),
            CID.to_vec(),
            signing,
            config(),
        )
        .expect("server configuration");
        let mut client = dope_quic::conn::setup::Client::connect(
            CID.to_vec(),
            CID.to_vec(),
            server_pubkey,
            config(),
        )
        .expect("client configuration");
        let mut workspace = conn::ReceiveWorkspace::new();
        for _ in 0..32 {
            let now = Instant::now();
            let mut client_packets = client.transmit().send(now);
            for packet in &mut client_packets {
                server
                    .recv_packet(&mut workspace, packet, now)
                    .expect("server receive");
            }
            let mut server_packets = server.transmit().send(now);
            for packet in &mut server_packets {
                client
                    .recv_packet(&mut workspace, packet, now)
                    .expect("client receive");
            }
            if client.status().is_established()
                && server.status().is_established()
                && client_packets.is_empty()
                && server_packets.is_empty()
            {
                return Self {
                    client,
                    _server: server,
                };
            }
        }
        panic!("handshake did not quiesce");
    }
}

fn config() -> conn::config::Options {
    conn::config::Options {
        transport_params: transport_params::Params {
            max_idle_timeout_ms: 30_000,
            max_datagram_frame_size: Some(65_535),
            initial_max_data: 1 << 20,
            initial_max_stream_data_bidi_local: 1 << 20,
            initial_max_stream_data_bidi_remote: 1 << 20,
            initial_max_streams_bidi: 1,
            ..transport_params::Params::default()
        },
        datagram_congestion_control: CongestionControl::Uncongested,
        pending_datagrams_capacity: 8_192,
        ..conn::config::Options::default()
    }
}

fn groups() -> usize {
    env::var("FIRST_FLUSH_GROUPS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(DEFAULT_GROUPS)
}

fn percentile(values: &mut [Duration], percentile: usize) -> Duration {
    values.sort_unstable();
    let last = values.len() - 1;
    values[last.saturating_mul(percentile) / 100]
}

fn print_distribution(name: &str, mut values: Vec<Duration>) {
    let p50 = percentile(&mut values, 50);
    let p90 = percentile(&mut values, 90);
    let p99 = percentile(&mut values, 99);
    println!("{name}: p50={p50:?} p90={p90:?} p99={p99:?}");
}

fn emit_one(connection: &mut Connection, batch: &mut Batch, min_bytes: usize) -> Duration {
    let started = Instant::now();
    connection
        .transmit()
        .send_batch(batch, Instant::now(), 1, 1_200);
    let elapsed = started.elapsed();
    assert_eq!(batch.packets(), 1);
    assert!(batch.byte_len() >= min_bytes);
    elapsed
}

fn arm_control_probe(connection: &mut Connection, batch: &mut Batch, token: u64) {
    connection.send_path_challenge(token.to_ne_bytes());
    connection
        .transmit()
        .send_batch(batch, Instant::now(), 1, 1_200);
    assert_eq!(batch.packets(), 1);
    let deadline = connection
        .status()
        .next_timer()
        .expect("control packet timer");
    conn::recovery::Loss::new(connection).check_loss(deadline);
}

fn main() {
    let groups = groups();
    assert!(groups != 0);

    let mut batch = Batch::default();
    let mut warmup = Pair::established();
    warmup
        .client
        .datagrams()
        .try_send(vec![0; PAYLOAD])
        .expect("warmup queue");
    let _ = emit_one(&mut warmup.client, &mut batch, PAYLOAD);

    let mut first = std::array::from_fn::<_, CONNECTIONS, _>(|_| Vec::with_capacity(groups));
    let mut second = std::array::from_fn::<_, CONNECTIONS, _>(|_| Vec::with_capacity(groups));
    let mut stream = std::array::from_fn::<_, CONNECTIONS, _>(|_| Vec::with_capacity(groups));
    let mut control = std::array::from_fn::<_, CONNECTIONS, _>(|_| Vec::with_capacity(groups));
    let mut control_burst =
        std::array::from_fn::<_, CONNECTIONS, _>(|_| Vec::with_capacity(groups));
    let mut probe = std::array::from_fn::<_, CONNECTIONS, _>(|_| Vec::with_capacity(groups));
    let mut construct = Vec::with_capacity(groups);
    let signing = SigningKey::from_seed(&SEED).expect("seed");
    let server_pubkey = *signing.pubkey().expect("public key");

    for _ in 0..groups {
        let started = Instant::now();
        let client = dope_quic::conn::setup::Client::<0>::connect(
            CID.to_vec(),
            CID.to_vec(),
            server_pubkey,
            config(),
        )
        .expect("client configuration");
        construct.push(started.elapsed());
        black_box(&client);
        drop(client);
        let mut pairs = std::array::from_fn::<_, CONNECTIONS, _>(|_| Pair::established());
        for pair in &mut pairs {
            pair.client
                .datagrams()
                .try_send(vec![0; PAYLOAD])
                .expect("first queue");
        }
        for (position, pair) in pairs.iter_mut().enumerate() {
            first[position].push(emit_one(&mut pair.client, &mut batch, PAYLOAD));
        }
        for pair in &mut pairs {
            pair.client
                .datagrams()
                .try_send(vec![0; PAYLOAD])
                .expect("second queue");
        }
        for (position, pair) in pairs.iter_mut().enumerate() {
            second[position].push(emit_one(&mut pair.client, &mut batch, PAYLOAD));
        }
        for pair in &mut pairs {
            let stream_id = pair.client.streams().open_bidi().expect("stream credit");
            pair.client
                .streams()
                .send(stream_id, &[0; PAYLOAD])
                .expect("stream payload");
        }
        for (position, pair) in pairs.iter_mut().enumerate() {
            stream[position].push(emit_one(&mut pair.client, &mut batch, PAYLOAD));
        }
        for (position, pair) in pairs.iter_mut().enumerate() {
            pair.client
                .send_path_challenge((position as u64).to_ne_bytes());
        }
        for (position, pair) in pairs.iter_mut().enumerate() {
            control[position].push(emit_one(&mut pair.client, &mut batch, 1));
        }
        for (position, pair) in pairs.iter_mut().enumerate() {
            for item in 0..CONTROL_BURST {
                pair.client.send_path_challenge(
                    ((groups as u64) << 32 | (position * CONTROL_BURST + item) as u64)
                        .to_ne_bytes(),
                );
            }
        }
        for (position, pair) in pairs.iter_mut().enumerate() {
            control_burst[position].push(emit_one(&mut pair.client, &mut batch, 1));
        }
        for (position, pair) in pairs.iter_mut().enumerate() {
            arm_control_probe(
                &mut pair.client,
                &mut batch,
                (groups as u64) << 32 | 1 << 31 | position as u64,
            );
            probe[position].push(emit_one(&mut pair.client, &mut batch, 1));
        }
    }

    println!("# production-shaped QUIC first flush ({groups} x {CONNECTIONS} connections)");
    print_distribution("construct/client", construct);
    for position in 0..CONNECTIONS {
        print_distribution(
            &format!("first/position-{position}"),
            std::mem::take(&mut first[position]),
        );
        print_distribution(
            &format!("second/position-{position}"),
            std::mem::take(&mut second[position]),
        );
        print_distribution(
            &format!("stream/position-{position}"),
            std::mem::take(&mut stream[position]),
        );
        print_distribution(
            &format!("control/position-{position}"),
            std::mem::take(&mut control[position]),
        );
        print_distribution(
            &format!("control-burst/position-{position}"),
            std::mem::take(&mut control_burst[position]),
        );
        print_distribution(
            &format!("probe/position-{position}"),
            std::mem::take(&mut probe[position]),
        );
    }
}
