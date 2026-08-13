use std::net::SocketAddr;
use std::pin::Pin;
use std::time::Instant;

use dope::core::driver::{self, schedule};
use dope::manifold::datagram::{self, Socket};

use crate::conn;
use crate::endpoint::EndpointBuffer;
use crate::mux::drive::{DriveOps as _, OutputOps as _};
use crate::mux::output::State as _;
use crate::mux::{self, Outgoing, PooledMux};
use crate::stream::ReceiveBuffer;

pub(super) struct Runtime<
    'd,
    'tls,
    H: mux::Handler<ID, B>,
    P: conn::server::Policy,
    const ID: u8,
    B: ReceiveBuffer,
> {
    pub(super) mux: PooledMux<'tls, H, P, ID, B>,
    flush_blocked: bool,
    prefer_output: bool,
    stopping: bool,
    driver: std::marker::PhantomData<&'d ()>,
}

impl<'d, 'tls, H: mux::Handler<ID, B>, P: conn::server::Policy, const ID: u8, B: ReceiveBuffer>
    Runtime<'d, 'tls, H, P, ID, B>
{
    pub(super) fn new(mux: PooledMux<'tls, H, P, ID, B>) -> Self {
        Self {
            mux,
            flush_blocked: false,
            prefer_output: true,
            stopping: false,
            driver: std::marker::PhantomData,
        }
    }
}

impl<'d, 'tls, const ID: u8, H, P, B> datagram::Handler<'d, ID> for Runtime<'d, 'tls, H, P, ID, B>
where
    H: mux::Handler<ID, B>,
    P: conn::server::Policy,
    B: EndpointBuffer<'d>,
{
    fn packet<'turn>(
        &mut self,
        addr: SocketAddr,
        packet: datagram::packet::Packet<'turn, 'd>,
        socket: Pin<&'turn mut Socket<'d, ID>>,
        now: Instant,
    ) {
        let len = packet.as_ref().len();
        let received = B::receive_packet(&mut self.mux, addr, packet, socket, now);
        if let Err(error) = received {
            self.mux.handler_mut().packet_error(addr, &error, len);
        }
    }

    fn recycle(&mut self, payload: Vec<u8>) {
        self.mux.recycle_packet(payload);
    }

    fn pre_park<'turn>(
        &mut self,
        mut socket: Pin<&mut Socket<'d, ID>>,
        now: Instant,
        work: driver::schedule::Application<'turn, 'd>,
    ) {
        if self.stopping {
            while !self.mux.shutdown_complete() {
                let Some(permit) = work.permit() else {
                    return;
                };
                self.mux.lifecycle().step(permit);
            }
            return;
        }
        self.flush_blocked = false;
        loop {
            let output = !self.mux.output().is_empty() && !self.flush_blocked;
            let drive = self.mux.has_drive_work(now);
            if !output && !drive {
                break;
            }
            let Some(permit) = work.permit() else {
                break;
            };
            let send = output && (!drive || self.prefer_output);
            if output && drive {
                self.prefer_output = !self.prefer_output;
            }
            if send {
                self.flush_blocked = !queue_one(socket.as_mut(), &mut self.mux, permit);
            } else {
                self.mux.drive_one(permit, now);
            }
        }
    }

    fn progress(&self, region: &o3::cell::region::Token<'d>) -> schedule::Progress<'d> {
        if self.stopping {
            return if self.mux.shutdown_complete() {
                schedule::Progress::Quiescent
            } else {
                schedule::Progress::Runnable
            };
        }
        let mut progress = schedule::Progress::Quiescent;
        if self.mux.has_buffered_output() && !self.flush_blocked {
            progress = progress.reduce(schedule::Progress::Runnable);
        }
        if self.mux.has_drive_work(Instant::now()) {
            progress = progress.reduce(schedule::Progress::Runnable);
        }
        if let Some(deadline) = self.mux.next_deadline(Instant::now()) {
            progress = progress.reduce(schedule::Progress::until(region, deadline));
        }
        progress
    }

    fn shutdown(&mut self) {
        self.stopping = true;
        self.mux.lifecycle().begin();
    }
}

fn queue_one<'turn, 'd, 'tls, const ID: u8, H, P, B>(
    mut socket: Pin<&mut Socket<'d, ID>>,
    mux: &mut PooledMux<'tls, H, P, ID, B>,
    _permit: driver::schedule::ApplicationPermit<'turn, 'd>,
) -> bool
where
    H: mux::Handler<ID, B>,
    P: conn::server::Policy,
    B: ReceiveBuffer,
{
    let Some(item) = mux.output().pop() else {
        return true;
    };
    match item {
        Outgoing::Plain(addr, payload) => {
            if let Err(payload) = socket.as_mut().queue_to(payload, addr) {
                let _ = mux.output().push_front(Outgoing::Plain(addr, payload));
                return false;
            }
        }
        Outgoing::Suffix(addr, payload) => {
            if let Err(payload) = socket.as_mut().queue_suffix(payload, addr) {
                let _ = mux.output().push_front(Outgoing::Suffix(addr, payload));
                return false;
            }
        }
        Outgoing::Batch(addr, payload, segment_size) => {
            if let Err(payload) = socket.as_mut().queue_gso(payload, segment_size, addr) {
                let _ = mux
                    .output()
                    .push_front(Outgoing::Batch(addr, payload, segment_size));
                return false;
            }
        }
    }
    true
}
