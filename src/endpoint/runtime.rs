use std::net;
use std::pin;
use std::time;

use dope::core::driver::{self, schedule};
use dope::manifold::datagram;

use crate::conn;
use crate::endpoint;
use crate::mux;
use crate::mux::drive::{DriveOps as _, OutputOps as _};
use crate::mux::output::State as _;
use crate::stream;

pub(super) struct Runtime<
    'd,
    'tls,
    H: mux::Handler<ID, B>,
    P: conn::server::Policy,
    const ID: u8,
    B: stream::ReceiveBuffer,
> {
    pub(super) mux: mux::PooledRouter<'tls, H, P, ID, B>,
    flush_blocked: bool,
    prefer_output: bool,
    stopping: bool,
    driver: std::marker::PhantomData<&'d ()>,
}

impl<
    'd,
    'tls,
    H: mux::Handler<ID, B>,
    P: conn::server::Policy,
    const ID: u8,
    B: stream::ReceiveBuffer,
> Runtime<'d, 'tls, H, P, ID, B>
{
    pub(super) fn new(mux: mux::PooledRouter<'tls, H, P, ID, B>) -> Self {
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
    B: endpoint::Storage<'d>,
{
    fn packet<'turn>(
        &mut self,
        addr: net::SocketAddr,
        packet: datagram::packet::Packet<'turn, 'd>,
        socket: pin::Pin<&'turn mut datagram::Socket<'d, ID>>,
        now: time::Instant,
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
        mut socket: pin::Pin<&mut datagram::Socket<'d, ID>>,
        now: time::Instant,
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
        if self.mux.has_drive_work(time::Instant::now()) {
            progress = progress.reduce(schedule::Progress::Runnable);
        }
        if let Some(deadline) = self.mux.next_deadline(time::Instant::now()) {
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
    mut socket: pin::Pin<&mut datagram::Socket<'d, ID>>,
    mux: &mut mux::PooledRouter<'tls, H, P, ID, B>,
    _permit: driver::schedule::ApplicationPermit<'turn, 'd>,
) -> bool
where
    H: mux::Handler<ID, B>,
    P: conn::server::Policy,
    B: stream::ReceiveBuffer,
{
    let Some(item) = mux.output().pop() else {
        return true;
    };
    match item {
        crate::mux::Outgoing::Plain(addr, payload) => {
            if let Err(payload) = socket.as_mut().queue_to(payload, addr) {
                let _ = mux
                    .output()
                    .push_front(crate::mux::Outgoing::Plain(addr, payload));
                return false;
            }
        }
        crate::mux::Outgoing::Suffix(addr, payload) => {
            if let Err(payload) = socket.as_mut().queue_suffix(payload, addr) {
                let _ = mux
                    .output()
                    .push_front(crate::mux::Outgoing::Suffix(addr, payload));
                return false;
            }
        }
        crate::mux::Outgoing::Batch(addr, payload, segment_size) => {
            if let Err(payload) = socket.as_mut().queue_gso(payload, segment_size, addr) {
                let _ = mux.output().push_front(crate::mux::Outgoing::Batch(
                    addr,
                    payload,
                    segment_size,
                ));
                return false;
            }
        }
    }
    true
}
