pub mod peer;
use std::{hint, process, time};

use conn::{output::transmit, wire::packet};
use dope_quic::{conn, errors};
use peer::Config;
use peer::Pair;
use peer::Receiver as _;

enum Error {
    Setup(peer::Setup),
    Queue(errors::SendFailure<Vec<u8>>),
    Output(transmit::Error),
    Input(peer::Transfer),
    Emission { actual: usize },
    Growth { before: usize, after: usize },
}

struct Journal {
    pair: Pair,
    now: time::Instant,
    output: packet::Batch,
    wires: Vec<Vec<u8>>,
}

impl Journal {
    fn new() -> Result<Self, Error> {
        Ok(Self {
            pair: Pair::try_default().map_err(Error::Setup)?,
            now: time::Instant::now() + time::Duration::from_secs(1),
            output: packet::Batch::default(),
            wires: Vec::new(),
        })
    }

    fn send(&mut self, count: usize) -> Result<(), Error> {
        for _ in 0..count {
            self.now += time::Duration::from_millis(1);
            self.pair
                .client
                .with_scope(|mut scope| scope.datagrams().try_send(vec![0]))
                .map_err(Error::Queue)?;
            self.emit()?;
        }
        Ok(())
    }

    fn emit(&mut self) -> Result<(), Error> {
        self.pair
            .client
            .with_scope(|mut scope| {
                scope
                    .output()
                    .send_batch(&mut self.output, self.now, 1, 1200)
            })
            .map_err(Error::Output)?;
        let actual = self.output.packets();
        if actual != 1 {
            return Err(Error::Emission { actual });
        }
        for wire in self.output.iter() {
            self.wires.push(wire.to_vec());
        }
        Ok(())
    }

    fn grow(&mut self) -> Result<(), Error> {
        let before = self.pair.client.view().journal().packet_bytes;
        self.send(1)?;
        let after = self.pair.client.view().journal().packet_bytes;
        if after <= before {
            return Err(Error::Growth { before, after });
        }
        Ok(())
    }

    fn ack(&mut self, start: usize, count: usize) -> Result<(), Error> {
        let Pair {
            server,
            client,
            work,
        } = &mut self.pair;
        for wire in &mut self.wires[start..start + count] {
            server.receive(work, wire, self.now).map_err(Error::Input)?;
        }
        self.now += time::Duration::from_millis(30);
        client
            .receive_from(work, server, self.now)
            .map_err(Error::Input)?;
        Ok(())
    }
}

fn measure(
    name: &str,
    prepare: impl Fn(&mut Journal) -> Result<(), Error>,
    run: impl Fn(&mut Journal) -> Result<(), Error>,
) -> Result<(), Error> {
    let mut elapsed = time::Duration::ZERO;
    let mut backing = (0, 0);
    for _ in 0..64 {
        let mut journal = Journal::new()?;
        prepare(&mut journal)?;
        let before = journal.pair.client.view().journal().packet_bytes;
        let start = time::Instant::now();
        run(&mut journal)?;
        elapsed += start.elapsed();
        let after = hint::black_box(journal.pair.client.view().journal().packet_bytes);
        backing = (before, after);
    }
    println!(
        "{name}: {} ns/op (64 samples), packet backing {} -> {} bytes",
        elapsed.as_nanos() / 64,
        backing.0,
        backing.1
    );
    Ok(())
}

fn run() -> Result<(), Error> {
    measure("ack_back_retire", |j| j.send(64), |j| j.ack(0, 64))?;
    measure("loss_front_retire", |j| j.send(64), |j| j.ack(63, 1))?;
    measure("retain_unacked", |j| j.send(64), |j| j.ack(0, 1))?;
    measure(
        "wrapped_ack_lookup",
        |j| {
            j.send(64)?;
            j.ack(0, 32)?;
            j.send(32)
        },
        |j| j.ack(32, 32),
    )?;
    measure(
        "cold_initial_packet",
        |j| {
            j.pair = Pair::try_open(
                Config::default().try_build().map_err(Error::Setup)?,
                Config::default().try_build().map_err(Error::Setup)?,
            )
            .map_err(Error::Setup)?;
            Ok(())
        },
        Journal::emit,
    )?;
    measure(
        "wrapped_growth",
        |j| {
            j.send(64)?;
            j.ack(0, 32)?;
            j.send(32)
        },
        Journal::grow,
    )?;
    measure("linear_growth", |j| j.send(64), Journal::grow)?;
    measure(
        "short_wrapped_growth",
        |j| {
            j.send(64)?;
            j.ack(0, 63)?;
            j.send(63)
        },
        Journal::grow,
    )?;
    Ok(())
}

fn main() -> process::ExitCode {
    match run() {
        Ok(()) => process::ExitCode::SUCCESS,
        Err(error) => {
            match error {
                Error::Setup(cause) => eprintln!("journal setup failed: {cause:?}"),
                Error::Queue(cause) => eprintln!("datagram queue failed: {cause:?}"),
                Error::Output(cause) => eprintln!("packet output failed: {cause:?}"),
                Error::Input(cause) => eprintln!("packet input failed: {cause:?}"),
                Error::Emission { actual } => {
                    eprintln!("expected one emitted packet, observed {actual}")
                }
                Error::Growth { before, after } => {
                    eprintln!("expected journal growth, observed {before} -> {after} bytes")
                }
            }
            process::ExitCode::FAILURE
        }
    }
}
